/**
 * Process Finder Service
 */

import {exec} from 'child_process';
import {promisify} from 'util';
import * as https from 'https';
import {WindowsStrategy, UnixStrategy, platform_strategy} from './platform_strategies';
import * as process from 'process';
import * as vscode from 'vscode';
import {logger} from '../utils/logger';

const exec_async = promisify(exec);

export interface process_info {
	extension_port: number;
	connect_port: number;
	csrf_token: string;
}

const LOG_CAT = 'ProcessFinder';

export class ProcessFinder {
	private strategy: platform_strategy;
	private process_name: string;

	constructor() {
		logger.debug(LOG_CAT, `Initializing ProcessFinder for platform: ${process.platform}, arch: ${process.arch}`);

		if (process.platform === 'win32') {
			this.strategy = new WindowsStrategy();
			this.process_name = 'language_server_windows_x64.exe';
		} else if (process.platform === 'darwin') {
			this.strategy = new UnixStrategy('darwin');
			this.process_name = `language_server_macos${process.arch === 'arm64' ? '_arm' : ''}`;
		} else {
			this.strategy = new UnixStrategy('linux');
			this.process_name = `language_server_linux${process.arch === 'arm64' ? '_arm' : '_x64'}`;
		}

		logger.info(LOG_CAT, `Target process name: ${this.process_name}`);
	}

	async detect_process_info(max_retries: number = 1): Promise<process_info | null> {
		logger.section(LOG_CAT, `Starting process detection (max_retries: ${max_retries})`);
		const timer = logger.time_start('detect_process_info');

		for (let i = 0; i < max_retries; i++) {
			logger.debug(LOG_CAT, `Attempt ${i + 1}/${max_retries}`);

			try {
				const cmd = this.strategy.get_process_list_command(this.process_name);
				logger.debug(LOG_CAT, `Executing process list command:\n${cmd}`);

				const {stdout, stderr} = await exec_async(cmd);

				if (stderr) {
					logger.warn(LOG_CAT, `Command stderr output: ${stderr}`);
				}

				logger.debug(LOG_CAT, `Raw stdout (${stdout.length} chars):\n${stdout}`);

				const info = this.strategy.parse_process_info(stdout);

				if (info) {
					logger.info(LOG_CAT, `Process info parsed successfully:`, {
						pid: info.pid,
						extension_port: info.extension_port,
						csrf_token: `${info.csrf_token.substring(0, 8)}...`,
					});

					logger.debug(LOG_CAT, `Getting listening ports for PID: ${info.pid}`);
					const ports = await this.get_listening_ports(info.pid);

					logger.debug(LOG_CAT, `Found ${ports.length} listening port(s): [${ports.join(', ')}]`);

					if (ports.length > 0) {
						logger.debug(LOG_CAT, `Testing ports to find working endpoint...`);
						const valid_port = await this.find_working_port(ports, info.csrf_token);

						if (valid_port) {
							logger.info(LOG_CAT, `SUCCESS: Valid port found: ${valid_port}`);
							timer();
							return {
								extension_port: info.extension_port,
								connect_port: valid_port,
								csrf_token: info.csrf_token,
							};
						} else {
							logger.warn(LOG_CAT, `No ports responded successfully to health check`);
						}
					} else {
						logger.warn(LOG_CAT, `No listening ports found for PID ${info.pid}`);
					}
				} else {
					logger.warn(LOG_CAT, `Failed to parse process info from command output`);
				}
			} catch (e: any) {
				logger.error(LOG_CAT, `Attempt ${i + 1} failed with error:`, {
					message: e.message,
					code: e.code,
					killed: e.killed,
					signal: e.signal,
				});

				if (e.stderr) {
					logger.error(LOG_CAT, `Command stderr: ${e.stderr}`);
				}
			}

			if (i < max_retries - 1) {
				logger.debug(LOG_CAT, `Waiting 100ms before retry...`);
				await new Promise(r => setTimeout(r, 100));
			}
		}

		logger.error(LOG_CAT, `Process detection failed after ${max_retries} attempt(s)`);
		timer();
		return null;
	}

	private async get_listening_ports(pid: number): Promise<number[]> {
		try {
			const cmd = this.strategy.get_port_list_command(pid);
			logger.debug(LOG_CAT, `Port list command:\n${cmd}`);

			const {stdout, stderr} = await exec_async(cmd);

			if (stderr) {
				logger.warn(LOG_CAT, `Port list stderr: ${stderr}`);
			}

			logger.debug(LOG_CAT, `Port list stdout (${stdout.length} chars):\n${stdout.substring(0, 500)}${stdout.length > 500 ? '...(truncated)' : ''}`);

			const ports = this.strategy.parse_listening_ports(stdout, pid);
			logger.debug(LOG_CAT, `Parsed ports: [${ports.join(', ')}]`);

			return ports;
		} catch (e: any) {
			logger.error(LOG_CAT, `Failed to get listening ports:`, {
				message: e.message,
				code: e.code,
			});
			return [];
		}
	}

	private async find_working_port(ports: number[], csrf_token: string): Promise<number | null> {
		for (const port of ports) {
			logger.debug(LOG_CAT, `Testing port ${port}...`);
			const is_working = await this.test_port(port, csrf_token);

			if (is_working) {
				logger.info(LOG_CAT, `Port ${port} is working`);
				return port;
			} else {
				logger.debug(LOG_CAT, `Port ${port} did not respond`);
			}
		}
		return null;
	}

	private test_port(port: number, csrf_token: string): Promise<boolean> {
		return new Promise(resolve => {
			const options = {
				hostname: '127.0.0.1',
				port,
				path: '/exa.language_server_pb.LanguageServerService/GetUnleashData',
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-Codeium-Csrf-Token': csrf_token,
					'Connect-Protocol-Version': '1',
				},
				rejectUnauthorized: false,
				timeout: 5000,
			};

			logger.debug(LOG_CAT, `HTTP request to https://127.0.0.1:${port}${options.path}`);

			const req = https.request(options, res => {
				logger.debug(LOG_CAT, `Response from port ${port}: status=${res.statusCode}`);

				let body = '';
				res.on('data', chunk => (body += chunk));
				res.on('end', () => {
					if (res.statusCode === 200) {
						try {
							JSON.parse(body);
							resolve(true);
						} catch {
							logger.debug(LOG_CAT, `Port ${port} responded with 200 but body is not valid JSON`);
							resolve(false);
						}
					} else {
						resolve(false);
					}
				});
			});

			req.on('error', (err: any) => {
				logger.debug(LOG_CAT, `Port ${port} connection error: ${err.code || err.message}`);
				resolve(false);
			});

			req.on('timeout', () => {
				logger.debug(LOG_CAT, `Port ${port} connection timeout`);
				req.destroy();
				resolve(false);
			});

			req.write(JSON.stringify({wrapper_data: {}}));
			req.end();
		});
	}
}
