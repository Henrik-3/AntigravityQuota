import './setup';
import {describe, it} from 'node:test';
import * as assert from 'node:assert';
import {WindowsStrategy, UnixStrategy} from '../core/platform_strategies';

describe('WindowsStrategy', () => {
	it('should generate process list command with multiple process names for PowerShell', () => {
		const strategy = new WindowsStrategy();
		strategy.set_use_powershell(true);

		const cmd = strategy.get_process_list_command(['agy.exe', 'language_server_windows_x64.exe']);
		assert.ok(cmd.includes("name='agy.exe' or name='language_server_windows_x64.exe'"));
		assert.ok(cmd.includes('Get-CimInstance'));
	});

	it('should generate process list command for WMIC fallback', () => {
		const strategy = new WindowsStrategy();
		strategy.set_use_powershell(false);

		const cmd = strategy.get_process_list_command(['agy.exe', 'language_server_windows_x64.exe']);
		assert.ok(cmd.includes("name='agy.exe' or name='language_server_windows_x64.exe'"));
		assert.ok(cmd.includes('wmic process where'));
	});

	it('should return null on empty stdout without throwing JSON parse error', () => {
		const strategy = new WindowsStrategy();
		const result = strategy.parse_process_info('');
		assert.strictEqual(result, null);

		const whitespaceResult = strategy.parse_process_info('   \r\n   ');
		assert.strictEqual(whitespaceResult, null);
	});

	it('should parse modern agy.exe process info with --hub-port and --app_data_dir=', () => {
		const strategy = new WindowsStrategy();
		const mockOutput = JSON.stringify({
			ProcessId: 6200,
			CommandLine:
				'C:\\Users\\test\\.gemini\\bin\\agy.exe --hub --hub-port=60742 --app_data_dir=antigravity --csrf_token=87d11f7e-aafb-4cbf-adbd-e54f366ff5ea --add-dir=e:\\work',
		});

		const result = strategy.parse_process_info(mockOutput);
		assert.notStrictEqual(result, null);
		assert.strictEqual(result?.length, 1);
		assert.strictEqual(result?.[0].pid, 6200);
		assert.strictEqual(result?.[0].extension_port, 60742);
		assert.strictEqual(result?.[0].csrf_token, '87d11f7e-aafb-4cbf-adbd-e54f366ff5ea');
	});

	it('should parse legacy language_server process info with space-separated flags', () => {
		const strategy = new WindowsStrategy();
		const mockOutput = JSON.stringify({
			ProcessId: 1234,
			CommandLine:
				'C:\\Users\\test\\.antigravity\\language_server_windows_x64.exe --extension_server_port 50000 --app_data_dir antigravity --csrf_token 11112222-3333-4444-5555-666677778888',
		});

		const result = strategy.parse_process_info(mockOutput);
		assert.notStrictEqual(result, null);
		assert.strictEqual(result?.length, 1);
		assert.strictEqual(result?.[0].pid, 1234);
		assert.strictEqual(result?.[0].extension_port, 50000);
		assert.strictEqual(result?.[0].csrf_token, '11112222-3333-4444-5555-666677778888');
	});

	it('should filter candidate array, skip tokenless processes, and return all valid Antigravity candidates', () => {
		const strategy = new WindowsStrategy();
		const mockOutput = JSON.stringify([
			{
				ProcessId: 100,
				CommandLine: 'C:\\Other\\unrelated.exe --some-flag',
			},
			{
				ProcessId: 5000,
				// Tokenless Antigravity process should be skipped
				CommandLine: 'agy.exe --hub --hub-port=60700 --app_data_dir=antigravity',
			},
			{
				ProcessId: 6200,
				CommandLine: 'agy.exe --hub --hub-port=60742 --app_data_dir=antigravity --csrf_token=test-token-1234',
			},
			{
				ProcessId: 7000,
				CommandLine: 'language_server_windows_x64.exe --extension_server_port 50000 --app_data_dir antigravity --csrf_token=legacy-token-5678',
			},
		]);

		const result = strategy.parse_process_info(mockOutput);
		assert.notStrictEqual(result, null);
		assert.strictEqual(result?.length, 2);
		assert.strictEqual(result?.[0].pid, 6200);
		assert.strictEqual(result?.[0].extension_port, 60742);
		assert.strictEqual(result?.[0].csrf_token, 'test-token-1234');
		assert.strictEqual(result?.[1].pid, 7000);
		assert.strictEqual(result?.[1].extension_port, 50000);
		assert.strictEqual(result?.[1].csrf_token, 'legacy-token-5678');
	});
});

describe('UnixStrategy', () => {
	it('should generate process list command with regex pattern including language_server', () => {
		const macStrategy = new UnixStrategy('darwin');
		const macCmd = macStrategy.get_process_list_command(['agy', 'language_server', 'language_server_macos_arm']);
		assert.ok(macCmd.includes('pgrep -fl "(agy|language_server|language_server_macos_arm)"'));

		const linuxStrategy = new UnixStrategy('linux');
		const linuxCmd = linuxStrategy.get_process_list_command(['agy', 'language_server', 'language_server_linux_x64']);
		assert.ok(linuxCmd.includes('pgrep -af "(agy|language_server|language_server_linux_x64)"'));
	});

	it('should parse modern agy process line with --hub-port and --csrf_token', () => {
		const strategy = new UnixStrategy('darwin');
		const stdout = '6200 /path/to/agy --hub --hub-port=60742 --app_data_dir=antigravity --csrf_token=mac-token-5678\n';

		const result = strategy.parse_process_info(stdout);
		assert.notStrictEqual(result, null);
		assert.strictEqual(result?.length, 1);
		assert.strictEqual(result?.[0].pid, 6200);
		assert.strictEqual(result?.[0].extension_port, 60742);
		assert.strictEqual(result?.[0].csrf_token, 'mac-token-5678');
	});

	it('should parse macOS language_server binary without platform suffix (Antigravity IDE 2.6.0+)', () => {
		const strategy = new UnixStrategy('darwin');
		const stdout = '4321 /Applications/Antigravity.app/Contents/Resources/bin/language_server --extension_server_port 50001 --app_data_dir /Users/test/Library/Application Support/antigravity --csrf_token mac-token-arm-123\n';

		const result = strategy.parse_process_info(stdout);
		assert.notStrictEqual(result, null);
		assert.strictEqual(result?.length, 1);
		assert.strictEqual(result?.[0].pid, 4321);
		assert.strictEqual(result?.[0].extension_port, 50001);
		assert.strictEqual(result?.[0].csrf_token, 'mac-token-arm-123');
	});

	it('should parse legacy language_server line with --extension_server_port', () => {
		const strategy = new UnixStrategy('linux');
		const stdout = '1234 /path/to/language_server_linux_x64 --extension_server_port=50000 --app_data_dir antigravity --csrf_token=linux-token-9999\n';

		const result = strategy.parse_process_info(stdout);
		assert.notStrictEqual(result, null);
		assert.strictEqual(result?.length, 1);
		assert.strictEqual(result?.[0].pid, 1234);
		assert.strictEqual(result?.[0].extension_port, 50000);
		assert.strictEqual(result?.[0].csrf_token, 'linux-token-9999');
	});

	it('should return multiple valid candidates and skip tokenless lines', () => {
		const strategy = new UnixStrategy('darwin');
		const stdout = [
			'100 /usr/bin/unrelated',
			'5000 /path/to/agy --hub --hub-port=60700 --app_data_dir=antigravity',
			'6200 /path/to/agy --hub --hub-port=60742 --app_data_dir=antigravity --csrf_token=mac-token-1',
			'7000 /path/to/language_server --extension_server_port=50000 --app_data_dir antigravity --csrf_token=mac-token-2',
		].join('\n');

		const result = strategy.parse_process_info(stdout);
		assert.notStrictEqual(result, null);
		assert.strictEqual(result?.length, 2);
		assert.strictEqual(result?.[0].pid, 6200);
		assert.strictEqual(result?.[0].csrf_token, 'mac-token-1');
		assert.strictEqual(result?.[1].pid, 7000);
		assert.strictEqual(result?.[1].csrf_token, 'mac-token-2');
	});
});
