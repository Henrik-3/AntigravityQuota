import {logger} from '../utils/logger';

export interface process_candidate {
	pid: number;
	extension_port: number;
	csrf_token: string;
}

export interface platform_strategy {
	get_process_list_command(process_name: string | string[]): string;
	parse_process_info(stdout: string): process_candidate[] | null;
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
	 * Checks for --app_data_dir parameter, antigravity in the path, or agy --hub.
	 */
	private is_antigravity_process(command_line: string): boolean {
		const lower_cmd = command_line.toLowerCase();

		// Match --app_data_dir parameter containing antigravity
		if (/--app_data_dir[=\s]+[^\s]*antigravity/i.test(command_line)) {
			logger.debug('WindowsStrategy', `Process identified as Antigravity (--app_data_dir match)`);
			return true;
		}

		// Match path containing antigravity
		if (lower_cmd.includes('antigravity')) {
			logger.debug('WindowsStrategy', `Process identified as Antigravity (path match)`);
			return true;
		}

		// Match agy process with --hub flag
		if (lower_cmd.includes('agy') && lower_cmd.includes('--hub')) {
			logger.debug('WindowsStrategy', `Process identified as Antigravity (agy --hub match)`);
			return true;
		}

		logger.debug('WindowsStrategy', `Process is NOT Antigravity`);
		return false;
	}

	get_process_list_command(process_name: string | string[]): string {
		const names = Array.isArray(process_name) ? process_name : [process_name];
		const filter = names.map(n => `name='${n}'`).join(' or ');

		if (this.use_powershell) {
			return `powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"${filter}\\" | Select-Object ProcessId,CommandLine | ConvertTo-Json"`;
		}
		return `wmic process where "${filter}" get ProcessId,CommandLine /format:list`;
	}

	parse_process_info(stdout: string): process_candidate[] | null {
		logger.debug('WindowsStrategy', `Parsing process info (using PowerShell: ${this.use_powershell})`);

		const trimmed = stdout.trim();
		if (!trimmed) {
			logger.debug('WindowsStrategy', `Process list stdout is empty`);
			return null;
		}

		const candidates: process_candidate[] = [];

		if (this.use_powershell || trimmed.startsWith('{') || trimmed.startsWith('[')) {
			logger.debug('WindowsStrategy', `Detected JSON output, parsing...`);

			try {
				const data = JSON.parse(trimmed);
				const items = Array.isArray(data) ? data : [data];

				if (items.length === 0) {
					logger.warn('WindowsStrategy', `Empty process array - no target processes found`);
					return null;
				}

				for (let i = 0; i < items.length; i++) {
					const item = items[i];
					const pid = item.ProcessId;
					const command_line = item.CommandLine || '';

					logger.debug('WindowsStrategy', `Process ${i + 1}/${items.length}: PID=${pid}`);
					logger.debug('WindowsStrategy', `  CommandLine: ${command_line ? command_line.substring(0, 200) + '...' : '(empty)'}`);

					if (!pid || !command_line) {
						continue;
					}

					if (!this.is_antigravity_process(command_line)) {
						continue;
					}

					const port_match = command_line.match(/--(?:extension_server_port|hub-port)[=\s]+(\d+)/i);
					const token_match = command_line.match(/--csrf_token[=\s]+([a-zA-Z0-9-]+)/i);

					if (!token_match || !token_match[1]) {
						logger.debug('WindowsStrategy', `PID ${pid} has no valid CSRF token, skipping`);
						continue;
					}

					const extension_port = port_match && port_match[1] ? parseInt(port_match[1], 10) : 0;
					const csrf_token = token_match[1];

					logger.debug('WindowsStrategy', `Extracted: PID=${pid}, extension_port=${extension_port}, csrf_token=${csrf_token.substring(0, 8)}...`);

					candidates.push({pid, extension_port, csrf_token});
				}

				if (candidates.length === 0) {
					logger.warn('WindowsStrategy', `No valid Antigravity candidate found in JSON`);
					return null;
				}

				logger.info('WindowsStrategy', `Found ${candidates.length} valid Antigravity candidate(s) in JSON`);
				return candidates;
			} catch (e: any) {
				logger.error('WindowsStrategy', `JSON parse error: ${e.message}`);
				logger.debug('WindowsStrategy', `Raw stdout (first 500 chars): ${stdout.substring(0, 500)}`);
			}
		}

		// WMIC fallback parsing
		const blocks = stdout.split(/\n\s*\n/).filter(block => block.trim().length > 0);
		logger.debug('WindowsStrategy', `Fallback: Processing WMIC output with ${blocks.length} block(s)`);

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

			const port_match = command_line.match(/--(?:extension_server_port|hub-port)[=\s]+(\d+)/i);
			const token_match = command_line.match(/--csrf_token[=\s]+([a-zA-Z0-9-]+)/i);

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

		logger.info('WindowsStrategy', `WMIC: Found ${candidates.length} Antigravity candidate(s)`);
		return candidates;
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
			process_not_found: 'Antigravity process not found (agy / language_server)',
			command_not_available: this.use_powershell
				? 'PowerShell command failed; please check system permissions'
				: 'wmic/PowerShell command unavailable; please check the system environment',
			requirements: [
				'Antigravity is running',
				'agy.exe or language_server process is running',
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

	get_process_list_command(process_name: string | string[]): string {
		const names = Array.isArray(process_name) ? process_name : [process_name];
		const pattern = names.length > 1 ? `(${names.join('|')})` : names[0];

		// LC_ALL=C avoids pgrep aborting on invalid UTF-8 in unrelated process args (macOS Sequoia+).
		if (this.platform === 'darwin') {
			return `LC_ALL=C pgrep -fl "${pattern}"`;
		}
		return `LC_ALL=C pgrep -af "${pattern}"`;
	}

	/**
	 * Determine if a command line belongs to an Antigravity process.
	 * Checks for --app_data_dir parameter, antigravity in the path, or agy --hub.
	 */
	private is_antigravity_process(command_line: string): boolean {
		const lower_cmd = command_line.toLowerCase();

		// Match --app_data_dir parameter containing antigravity
		if (/--app_data_dir[=\s]+[^\s]*antigravity/i.test(command_line)) {
			logger.debug('UnixStrategy', `Process identified as Antigravity (--app_data_dir match)`);
			return true;
		}

		// Match path containing antigravity (e.g. /Applications/Antigravity.app/... or \antigravity\)
		if (lower_cmd.includes('antigravity')) {
			logger.debug('UnixStrategy', `Process identified as Antigravity (path match)`);
			return true;
		}

		// Match agy process with --hub flag
		if (lower_cmd.includes('agy') && lower_cmd.includes('--hub')) {
			logger.debug('UnixStrategy', `Process identified as Antigravity (agy --hub match)`);
			return true;
		}

		logger.debug('UnixStrategy', `Process is NOT Antigravity`);
		return false;
	}

	parse_process_info(stdout: string): process_candidate[] | null {
		const lines = stdout.split('\n').filter(line => line.trim().length > 0);
		const candidates: process_candidate[] = [];

		for (const line of lines) {
			// Relax check: legacy used --extension_server_port, new agy uses --csrf_token or --hub-port
			if (!line.includes('--extension_server_port') && !line.includes('--hub-port') && !line.includes('--csrf_token')) {
				continue;
			}

			const parts = line.trim().split(/\s+/);
			const pid = parseInt(parts[0], 10);
			const cmd = line.substring(parts[0].length).trim();

			if (!this.is_antigravity_process(cmd)) {
				continue;
			}

			const port_match = cmd.match(/--(?:extension_server_port|hub-port)[=\s]+(\d+)/i);
			const token_match = cmd.match(/--csrf_token[=\s]+([a-zA-Z0-9-]+)/i);

			if (!token_match?.[1]) {
				logger.debug('UnixStrategy', `PID ${pid} has no CSRF token, skipping`);
				continue;
			}

			candidates.push({
				pid,
				extension_port: port_match ? parseInt(port_match[1], 10) : 0,
				csrf_token: token_match[1],
			});
		}

		if (candidates.length === 0) {
			logger.warn('UnixStrategy', 'No Antigravity language_server process found');
			return null;
		}

		logger.info('UnixStrategy', `Found ${candidates.length} Antigravity candidate(s)`);
		return candidates;
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
			process_not_found: 'Antigravity process not found (agy / language_server)',
			command_not_available: 'Command check failed',
			requirements: ['Antigravity is running', 'lsof, ss, or netstat available'],
		};
	}
}
