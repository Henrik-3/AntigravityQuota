import {logger} from '../utils/logger';

export interface platform_strategy {
	get_process_list_command(process_name: string): string;
	parse_process_info(stdout: string): {pid: number; extension_port: number; csrf_token: string} | null;
	get_port_list_command(pid: number): string;
	parse_listening_ports(stdout: string, pid: number): number[];
	get_error_messages(): {process_not_found: string; command_not_available: string; requirements: string[]};
}

export class WindowsStrategy implements platform_strategy {
	private use_powershell: boolean = true;

	set_use_powershell(use: boolean) {
		this.use_powershell = use;
	}

	is_using_powershell(): boolean {
		return this.use_powershell;
	}

	/**
	 * Determine if a command line belongs to an Antigravity process.
	 * Checks for --app_data_dir antigravity parameter or antigravity in the path.
	 */
	private is_antigravity_process(command_line: string): boolean {
		const lower_cmd = command_line.toLowerCase();

		if (/--app_data_dir\s+antigravity\b/i.test(command_line)) {
			logger.debug('WindowsStrategy', `Process identified as Antigravity (--app_data_dir match)`);
			return true;
		}

		if (lower_cmd.includes('\\antigravity\\') || lower_cmd.includes('/antigravity/')) {
			logger.debug('WindowsStrategy', `Process identified as Antigravity (path match)`);
			return true;
		}

		logger.debug('WindowsStrategy', `Process is NOT Antigravity`);
		return false;
	}

	get_process_list_command(process_name: string): string {
		if (this.use_powershell) {
			return `powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"name='${process_name}'\\" | Select-Object ProcessId,CommandLine | ConvertTo-Json"`;
		}
		return `wmic process where "name='${process_name}'" get ProcessId,CommandLine /format:list`;
	}

	parse_process_info(stdout: string): {pid: number; extension_port: number; csrf_token: string} | null {
		logger.debug('WindowsStrategy', `Parsing process info (using PowerShell: ${this.use_powershell})`);

		if (this.use_powershell || stdout.trim().startsWith('{') || stdout.trim().startsWith('[')) {
			logger.debug('WindowsStrategy', `Detected JSON output, parsing...`);

			try {
				let data = JSON.parse(stdout.trim());

				if (Array.isArray(data)) {
					logger.debug('WindowsStrategy', `JSON is an array with ${data.length} element(s)`);

					if (data.length === 0) {
						logger.warn('WindowsStrategy', `Empty process array - no language_server processes found`);
						return null;
					}

					const total_count = data.length;

					for (let i = 0; i < data.length; i++) {
						const item = data[i];
						logger.debug('WindowsStrategy', `Process ${i + 1}/${total_count}: PID=${item.ProcessId}`);
						logger.debug('WindowsStrategy', `  CommandLine: ${item.CommandLine ? item.CommandLine.substring(0, 200) + '...' : '(empty)'}`);
					}

					const antigravity_processes = data.filter((item: any) => item.CommandLine && this.is_antigravity_process(item.CommandLine));

					logger.info('WindowsStrategy', `Found ${total_count} language_server process(es), ${antigravity_processes.length} belong to Antigravity`);

					if (antigravity_processes.length === 0) {
						logger.warn('WindowsStrategy', `No Antigravity process found among ${total_count} language_server process(es)`);
						logger.debug('WindowsStrategy', `Hint: Looking for processes with '--app_data_dir antigravity' or '\\antigravity\\' in path`);
						return null;
					}

					if (total_count > 1) {
						logger.info(
							'WindowsStrategy',
							`Selected Antigravity process PID: ${antigravity_processes[0].ProcessId} (first match of ${antigravity_processes.length})`
						);
					}
					data = antigravity_processes[0];
				} else {
					logger.debug('WindowsStrategy', `JSON is a single object (PID: ${data.ProcessId})`);
					logger.debug('WindowsStrategy', `CommandLine: ${data.CommandLine ? data.CommandLine.substring(0, 200) + '...' : '(empty)'}`);

					if (!data.CommandLine || !this.is_antigravity_process(data.CommandLine)) {
						logger.warn('WindowsStrategy', `Single process found but not Antigravity, skipping`);
						return null;
					}
					logger.info('WindowsStrategy', `Found 1 Antigravity process, PID: ${data.ProcessId}`);
				}

				const command_line = data.CommandLine || '';
				const pid = data.ProcessId;

				if (!pid) {
					logger.error('WindowsStrategy', `No PID found in process data`);
					return null;
				}

				const port_match = command_line.match(/--extension_server_port[=\s]+(\d+)/);
				const token_match = command_line.match(/--csrf_token[=\s]+([a-f0-9\-]+)/i);

				logger.debug(
					'WindowsStrategy',
					`Regex matches: extension_port=${port_match ? port_match[1] : 'NOT FOUND'}, csrf_token=${token_match ? 'FOUND' : 'NOT FOUND'}`
				);

				if (!token_match || !token_match[1]) {
					logger.error('WindowsStrategy', `CSRF token not found in command line`);
					logger.debug('WindowsStrategy', `Full command line: ${command_line}`);
					return null;
				}

				const extension_port = port_match && port_match[1] ? parseInt(port_match[1], 10) : 0;
				const csrf_token = token_match[1];

				logger.debug('WindowsStrategy', `Extracted: PID=${pid}, extension_port=${extension_port}, csrf_token=${csrf_token.substring(0, 8)}...`);

				return {pid, extension_port, csrf_token};
			} catch (e: any) {
				logger.error('WindowsStrategy', `JSON parse error: ${e.message}`);
				logger.debug('WindowsStrategy', `Raw stdout (first 500 chars): ${stdout.substring(0, 500)}`);
			}
		}
		const blocks = stdout.split(/\n\s*\n/).filter(block => block.trim().length > 0);

		logger.debug('WindowsStrategy', `Fallback: Processing WMIC output with ${blocks.length} block(s)`);

		const candidates: Array<{pid: number; extension_port: number; csrf_token: string}> = [];

		for (const block of blocks) {
			const pid_match = block.match(/ProcessId=(\d+)/);
			const command_line_match = block.match(/CommandLine=(.+)/);

			if (!pid_match || !command_line_match) {
				logger.debug('WindowsStrategy', `WMIC block skipped: missing PID or CommandLine`);
				continue;
			}

			const command_line = command_line_match[1].trim();
			logger.debug('WindowsStrategy', `WMIC: Checking PID ${pid_match[1]}`);

			if (!this.is_antigravity_process(command_line)) {
				continue;
			}

			const port_match = command_line.match(/--extension_server_port[=\s]+(\d+)/);
			const token_match = command_line.match(/--csrf_token[=\s]+([a-f0-9\-]+)/i);

			if (!token_match || !token_match[1]) {
				logger.debug('WindowsStrategy', `WMIC: PID ${pid_match[1]} has no CSRF token, skipping`);
				continue;
			}

			const pid = parseInt(pid_match[1], 10);
			const extension_port = port_match && port_match[1] ? parseInt(port_match[1], 10) : 0;
			const csrf_token = token_match[1];

			logger.debug('WindowsStrategy', `WMIC: Found candidate PID=${pid}, extension_port=${extension_port}`);
			candidates.push({pid, extension_port, csrf_token});
		}

		if (candidates.length === 0) {
			logger.warn('WindowsStrategy', `WMIC: No Antigravity process found`);
			return null;
		}

		logger.info('WindowsStrategy', `WMIC: Found ${candidates.length} Antigravity process(es), using PID: ${candidates[0].pid}`);
		return candidates[0];
	}

	get_port_list_command(pid: number): string {
		if (this.use_powershell) {
			return `powershell -NoProfile -Command "Get-NetTCPConnection -OwningProcess ${pid} -State Listen | Select-Object -ExpandProperty LocalPort | ConvertTo-Json"`;
		}
		return `netstat -ano | findstr "${pid}"`;
	}

	parse_listening_ports(stdout: string, pid: number): number[] {
		const ports: number[] = [];
		if (this.use_powershell) {
			try {
				const data = JSON.parse(stdout.trim());
				if (Array.isArray(data)) {
					for (const port of data) {
						if (typeof port === 'number' && !ports.includes(port)) {
							ports.push(port);
						}
					}
				} else if (typeof data === 'number') {
					ports.push(data);
				}
			} catch (e) {
				// Fallback or ignore parse errors (e.g. empty output)
			}
			return ports.sort((a, b) => a - b);
		}

		const port_regex = new RegExp(`(?:127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::1?\\]):(\\d+)\\s+(?:0\\.0\\.0\\.0:0|\\[::\\]:0|\\*:\\*).*?\\s+${pid}$`, 'gim');
		let match;

		while ((match = port_regex.exec(stdout)) !== null) {
			const port = parseInt(match[1], 10);
			if (!ports.includes(port)) {
				ports.push(port);
			}
		}

		return ports.sort((a, b) => a - b);
	}

	get_error_messages() {
		return {
			process_not_found: this.use_powershell ? 'language_server process not found' : 'language_server process not found',
			command_not_available: this.use_powershell
				? 'PowerShell command failed; please check system permissions'
				: 'wmic/PowerShell command unavailable; please check the system environment',
			requirements: [
				'Antigravity is running',
				'language_server_windows_x64.exe process is running',
				this.use_powershell
					? 'The system has permission to run PowerShell commands (Get-CimInstance, Get-NetTCPConnection)'
					: 'The system has permission to run wmic/PowerShell and netstat commands (auto-fallback supported)',
			],
		};
	}
}

export class UnixStrategy implements platform_strategy {
	private platform: string;
	constructor(platform: string) {
		this.platform = platform;
	}

	get_process_list_command(process_name: string): string {
		if (this.platform === 'darwin') {
			return `pgrep -fl ${process_name}`;
		}
		return `pgrep -af ${process_name}`;
	}

	parse_process_info(stdout: string): {pid: number; extension_port: number; csrf_token: string} | null {
		const lines = stdout.split('\n');
		for (const line of lines) {
			if (line.includes('--extension_server_port')) {
				const parts = line.trim().split(/\s+/);
				const pid = parseInt(parts[0], 10);
				const cmd = line.substring(parts[0].length).trim();

				const port_match = cmd.match(/--extension_server_port[=\s]+(\d+)/);
				const token_match = cmd.match(/--csrf_token[=\s]+([a-zA-Z0-9\-]+)/);

				return {
					pid,
					extension_port: port_match ? parseInt(port_match[1], 10) : 0,
					csrf_token: token_match ? token_match[1] : '',
				};
			}
		}
		return null;
	}

	get_port_list_command(pid: number): string {
		if (this.platform === 'darwin') {
			return `lsof -nP -a -iTCP -sTCP:LISTEN -p ${pid}`;
		}
		return `ss -tlnp 2>/dev/null | grep "pid=${pid}" || lsof -nP -a -iTCP -sTCP:LISTEN -p ${pid} 2>/dev/null`;
	}

	parse_listening_ports(stdout: string, pid: number): number[] {
		const ports: number[] = [];
		const lsof_regex = new RegExp(`^\\S+\\s+${pid}\\s+.*?(?:TCP|UDP)\\s+(?:\\*|[\\d.]+|\\[[\\da-f:]+\\]):(\\d+)\\s+\\(LISTEN\\)`, 'gim');

		if (this.platform === 'darwin') {
			let match;
			while ((match = lsof_regex.exec(stdout)) !== null) {
				const port = parseInt(match[1], 10);
				if (!ports.includes(port)) {
					ports.push(port);
				}
			}
		} else {
			const ss_regex = new RegExp(`LISTEN\\s+\\d+\\s+\\d+\\s+(?:\\*|[\\d.]+|\\[[\\da-f:]*\\]):(\\d+).*?users:.*?,pid=${pid},`, 'gi');
			let match;
			while ((match = ss_regex.exec(stdout)) !== null) {
				const port = parseInt(match[1], 10);
				if (!ports.includes(port)) {
					ports.push(port);
				}
			}

			if (ports.length === 0) {
				while ((match = lsof_regex.exec(stdout)) !== null) {
					const port = parseInt(match[1], 10);
					if (!ports.includes(port)) {
						ports.push(port);
					}
				}
			}
		}

		return ports.sort((a, b) => a - b);
	}

	get_error_messages() {
		return {
			process_not_found: 'Process not found',
			command_not_available: 'Command check failed',
			requirements: ['lsof or netstat'],
		};
	}
}
