import { logger } from '../utils/logger';

// New candidate_info interface for multi-candidate support
export interface candidate_info {
	pid: number;
	extension_port: number; // May be 0 if unparsed
	csrf_token: string;     // May be "" if unparsed
	command_line: string;   // May be "" if null/truncated
}

export interface platform_strategy {
	// New: Returns tiered commands for discovery
	get_process_list_commands(process_name: string): { name: string; command: string }[];
	// Changed: Returns array of candidates, MUST include PID even if args are missing
	parse_process_info(stdout: string): candidate_info[];
	// New: For targeted PID re-query (macOS/Windows truncation)
	get_full_command_line_command(pid: number): string | null;
	parse_command_line(pid: number, full_args: string): candidate_info | null;
	// Existing (unchanged)
	get_port_list_command(pid: number): string;
	parse_listening_ports(stdout: string, pid: number): number[];
	get_error_messages(): { process_not_found: string; command_not_available: string; requirements: string[] };
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

	get_process_list_commands(process_name: string): { name: string; command: string }[] {
		// Windows: Single tier (no user-based filtering needed like Unix)
		if (this.use_powershell) {
			return [
				{
					name: 'PowerShell',
					command: `powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"name='${process_name}'\\" | Select-Object ProcessId,CommandLine | ConvertTo-Json"`,
				},
			];
		}
		return [
			{
				name: 'WMIC',
				command: `wmic process where "name='${process_name}'" get ProcessId,CommandLine /format:list`,
			},
		];
	}

	parse_process_info(stdout: string): candidate_info[] {
		const candidates: candidate_info[] = [];
		logger.debug('WindowsStrategy', `Parsing process info (using PowerShell: ${this.use_powershell})`);

		if (this.use_powershell || stdout.trim().startsWith('{') || stdout.trim().startsWith('[')) {
			logger.debug('WindowsStrategy', `Detected JSON output, parsing...`);

			try {
				let data = JSON.parse(stdout.trim());

				if (!Array.isArray(data)) {
					data = [data];
				}

				logger.debug('WindowsStrategy', `JSON has ${data.length} element(s)`);

				for (const item of data) {
					if (!item.ProcessId) {
						continue;
					}

					const pid = item.ProcessId;
					const command_line = item.CommandLine || '';

					// Check if this is an Antigravity process (if command line is available)
					if (command_line && !this.is_antigravity_process(command_line)) {
						continue;
					}

					// Extract port and token if available
					const port_match = command_line.match(/--extension_server_port[=\s]+(\d+)/);
					const token_match = command_line.match(/--csrf_token[=\s]+([a-f0-9\-]+)/i);

					candidates.push({
						pid,
						extension_port: port_match ? parseInt(port_match[1], 10) : 0,
						csrf_token: token_match ? token_match[1] : '',
						command_line,
					});

					logger.debug('WindowsStrategy', `Added candidate: PID=${pid}, token=${token_match ? 'FOUND' : 'MISSING'}, cmdline=${command_line ? 'present' : 'empty'}`);
				}
			} catch (e: any) {
				logger.error('WindowsStrategy', `JSON parse error: ${e.message}`);
				logger.debug('WindowsStrategy', `Raw stdout (first 500 chars): ${stdout.substring(0, 500)}`);
			}
		} else {
			// WMIC fallback parsing
			const blocks = stdout.split(/\n\s*\n/).filter(block => block.trim().length > 0);
			logger.debug('WindowsStrategy', `Fallback: Processing WMIC output with ${blocks.length} block(s)`);

			for (const block of blocks) {
				const pid_match = block.match(/ProcessId=(\d+)/);
				const command_line_match = block.match(/CommandLine=(.+)/);

				if (!pid_match) {
					continue;
				}

				const pid = parseInt(pid_match[1], 10);
				const command_line = command_line_match ? command_line_match[1].trim() : '';

				if (command_line && !this.is_antigravity_process(command_line)) {
					continue;
				}

				const port_match = command_line.match(/--extension_server_port[=\s]+(\d+)/);
				const token_match = command_line.match(/--csrf_token[=\s]+([a-f0-9\-]+)/i);

				candidates.push({
					pid,
					extension_port: port_match ? parseInt(port_match[1], 10) : 0,
					csrf_token: token_match ? token_match[1] : '',
					command_line,
				});

				logger.debug('WindowsStrategy', `WMIC: Added candidate PID=${pid}`);
			}
		}

		logger.info('WindowsStrategy', `Found ${candidates.length} Antigravity candidate(s)`);
		return candidates;
	}

	get_full_command_line_command(pid: number): string | null {
		// PowerShell re-query for specific PID
		return `powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"ProcessId = ${pid}\\" | Select-Object -ExpandProperty CommandLine"`;
	}

	parse_command_line(pid: number, full_args: string): candidate_info | null {
		if (!full_args || full_args.trim() === '') {
			return null;
		}

		const command_line = full_args.trim();
		const port_match = command_line.match(/--extension_server_port[=\s]+(\d+)/);
		const token_match = command_line.match(/--csrf_token[=\s]+([a-f0-9\-]+)/i);

		if (!token_match) {
			return null;
		}

		return {
			pid,
			extension_port: port_match ? parseInt(port_match[1], 10) : 0,
			csrf_token: token_match[1],
			command_line,
		};
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

	get_process_list_commands(process_name: string): { name: string; command: string }[] {
		// Tiered discovery: Tier 1 (current user), Tier 2 (global)
		if (this.platform === 'darwin') {
			return [
				{ name: 'User (macOS)', command: `pgrep -u $(id -u) -fl ${process_name}` },
				{ name: 'Global (macOS)', command: `pgrep -fl ${process_name}` },
			];
		}
		return [
			{ name: 'User (Linux)', command: `pgrep -u $(id -u) -af ${process_name}` },
			{ name: 'Global (Linux)', command: `pgrep -af ${process_name}` },
		];
	}

	parse_process_info(stdout: string): candidate_info[] {
		const candidates: candidate_info[] = [];
		const lines = stdout.split('\n');

		for (const line of lines) {
			if (!line.trim()) {
				continue;
			}

			const parts = line.trim().split(/\s+/);
			const pid = parseInt(parts[0], 10);

			if (isNaN(pid)) {
				continue;
			}

			const cmd = line.substring(parts[0].length).trim();

			// Extract port and token if available
			const port_match = cmd.match(/--extension_server_port[=\s]+(\d+)/);
			const token_match = cmd.match(/--csrf_token[=\s]+([a-zA-Z0-9\-]+)/);

			// Return ALL PIDs, even if token is missing (crucial for macOS truncation)
			candidates.push({
				pid,
				extension_port: port_match ? parseInt(port_match[1], 10) : 0,
				csrf_token: token_match ? token_match[1] : '',
				command_line: cmd,
			});

			logger.debug('UnixStrategy', `Added candidate: PID=${pid}, token=${token_match ? 'FOUND' : 'MISSING'}`);
		}

		logger.info('UnixStrategy', `Found ${candidates.length} candidate(s)`);
		return candidates;
	}

	get_full_command_line_command(pid: number): string | null {
		// ps -ww gives full command line on macOS/Linux
		return `ps -ww -p ${pid} -o args=`;
	}

	parse_command_line(pid: number, full_args: string): candidate_info | null {
		if (!full_args || full_args.trim() === '') {
			return null;
		}

		const command_line = full_args.trim();
		const port_match = command_line.match(/--extension_server_port[=\s]+(\d+)/);
		const token_match = command_line.match(/--csrf_token[=\s]+([a-zA-Z0-9\-]+)/);

		if (!token_match) {
			return null;
		}

		return {
			pid,
			extension_port: port_match ? parseInt(port_match[1], 10) : 0,
			csrf_token: token_match[1],
			command_line,
		};
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
