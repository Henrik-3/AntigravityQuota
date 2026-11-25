import './setup';
import {describe, it, afterEach} from 'node:test';
import * as assert from 'node:assert';
import * as http from 'node:http';
import {ProcessFinder} from '../core/process_finder';

type RouteHandler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

describe('ProcessFinder - HTTP hub and GetUserStatus fallback', () => {
	const servers: http.Server[] = [];

	afterEach(async () => {
		await Promise.all(
			servers.splice(0).map(
				server =>
					new Promise<void>(resolve => {
						server.close(() => resolve());
					})
			)
		);
	});

	/**
	 * Start a local HTTP mock server on an ephemeral loopback port.
	 */
	async function start_mock_server(handler: RouteHandler): Promise<number> {
		const server = http.createServer(handler);
		servers.push(server);
		await new Promise<void>(resolve => {
			server.listen(0, '127.0.0.1', () => resolve());
		});
		const address = server.address();
		assert.ok(address && typeof address === 'object', 'Server address must be available');
		return address.port;
	}

	it('should detect HTTP hub port via GetUnleashData and return use_tls=false', async () => {
		const requested_paths: string[] = [];
		const port = await start_mock_server((req, res) => {
			requested_paths.push(req.url ?? '');
			res.writeHead(200, {'Content-Type': 'application/json'});
			res.end(JSON.stringify({}));
		});

		const finder = new ProcessFinder();
		const result = await (finder as any).find_working_port([port], 'test-csrf', true);

		assert.deepStrictEqual(result, {port, use_tls: false});
		assert.deepStrictEqual(requested_paths, ['/exa.language_server_pb.LanguageServerService/GetUnleashData']);
	});

	it('should fallback to GetUserStatus when GetUnleashData returns 404', async () => {
		const requested_paths: string[] = [];
		const port = await start_mock_server((req, res) => {
			requested_paths.push(req.url ?? '');
			if (req.url === '/exa.language_server_pb.LanguageServerService/GetUnleashData') {
				res.writeHead(404);
				res.end('Not Found');
				return;
			}
			if (req.url === '/exa.language_server_pb.LanguageServerService/GetUserStatus') {
				res.writeHead(200, {'Content-Type': 'application/json'});
				res.end(JSON.stringify({userStatus: {}}));
				return;
			}
			res.writeHead(404);
			res.end();
		});

		const finder = new ProcessFinder();
		const result = await (finder as any).find_working_port([port], 'test-csrf', true);

		assert.deepStrictEqual(result, {port, use_tls: false});
		assert.deepStrictEqual(requested_paths, [
			'/exa.language_server_pb.LanguageServerService/GetUnleashData',
			'/exa.language_server_pb.LanguageServerService/GetUserStatus',
		]);
	});

	it('should reject GetUserStatus fallback when userStatus is missing or invalid', async () => {
		const port = await start_mock_server((req, res) => {
			if (req.url === '/exa.language_server_pb.LanguageServerService/GetUnleashData') {
				res.writeHead(404);
				res.end();
				return;
			}
			res.writeHead(200, {'Content-Type': 'application/json'});
			res.end(JSON.stringify({userStatus: null}));
		});

		const finder = new ProcessFinder();
		const result = await (finder as any).find_working_port([port], 'test-csrf', true);

		assert.strictEqual(result, null);
	});

	it('should not fallback to GetUserStatus when GetUnleashData returns non-404 error', async () => {
		const requested_paths: string[] = [];
		const port = await start_mock_server((req, res) => {
			requested_paths.push(req.url ?? '');
			res.writeHead(500);
			res.end('Internal Server Error');
		});

		const finder = new ProcessFinder();
		const result = await (finder as any).find_working_port([port], 'test-csrf', true);

		assert.strictEqual(result, null);
		assert.ok(
			!requested_paths.includes('/exa.language_server_pb.LanguageServerService/GetUserStatus'),
			'GetUserStatus should not be probed on non-404 status'
		);
	});
});
