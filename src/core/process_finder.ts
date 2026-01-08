/**
 * Process Finder Service
 * Refactored for multi-candidate, tiered discovery with workspace-aware prioritization
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as https from 'https';
import * as fs from 'fs';
import { WindowsStrategy, UnixStrategy, platform_strategy, candidate_info } from './platform_strategies';
import * as process from 'process';
import * as vscode from 'vscode';
import { logger } from '../utils/logger';

const exec_async = promisify(exec);

export interface process_info {
	extension_port: number;
	connect_port: number;
	csrf_token: string;
}

const LOG_CAT = 'ProcessFinder';

// Windows null CommandLine re-query budget (global per detection cycle)
const NULL_REQUERY_BUDGET = 3;

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

		const checked_pids = new Set<number>();
		let null_requery_remaining = NULL_REQUERY_BUDGET;

		// Get workspace paths for prioritization
		const workspace_paths = this.get_workspace_paths();
		const target_folder = this.get_target_folder();

		logger.debug(LOG_CAT, `Target folder: ${target_folder?.uri.fsPath ?? 'none'}`);
		logger.debug(LOG_CAT, `Workspace folders: ${workspace_paths.length}`);

		// Get tiered commands
		const commands = this.strategy.get_process_list_commands(this.process_name);
		logger.debug(LOG_CAT, `Discovery tiers: ${commands.map(c => c.name).join(', ')}`);

		for (let retry = 0; retry < max_retries; retry++) {
			if (retry > 0) {
				logger.debug(LOG_CAT, `Retry ${retry + 1}/${max_retries}`);
				await new Promise(r => setTimeout(r, 100));
			}

			for (const { name: tier_name, command } of commands) {
				logger.debug(LOG_CAT, `Tier: ${tier_name}`);
				logger.debug(LOG_CAT, `Executing: ${command}`);

				let stdout = '';
				try {
					const result = await exec_async(command);
					stdout = result.stdout;
					if (result.stderr) {
						logger.warn(LOG_CAT, `Command stderr: ${result.stderr}`);
					}
				} catch (e: any) {
					// Semantic error handling: pgrep exit code 1 = no matches (not an error)
					if (e.code === 1 && e.signal === null && (!e.stderr || e.stderr === '')) {
						logger.debug(LOG_CAT, `Tier ${tier_name}: No matches (exit code 1)`);
						continue;
					}
					logger.error(LOG_CAT, `Tier ${tier_name} failed:`, { code: e.code, message: e.message });
					continue;
				}

				logger.debug(LOG_CAT, `Raw stdout (${stdout.length} chars):\n${stdout.substring(0, 500)}${stdout.length > 500 ? '...' : ''}`);

				// Parse candidates
				let candidates = this.strategy.parse_process_info(stdout);
				logger.debug(LOG_CAT, `Parsed ${candidates.length} candidate(s)`);

				// Deduplicate against checked_pids
				candidates = candidates.filter(c => !checked_pids.has(c.pid));
				logger.debug(LOG_CAT, `After dedup: ${candidates.length} candidate(s)`);

				if (candidates.length === 0) {
					continue;
				}

				// Re-query candidates with missing tokens
				const resolve_result = await this.resolve_missing_tokens(candidates, null_requery_remaining);
				candidates = resolve_result.candidates;

				// Update null_requery_remaining based on how many null CommandLine candidates were actually re-queried
				null_requery_remaining = Math.max(0, null_requery_remaining - resolve_result.null_requeried);

				// Filter out candidates still missing tokens
				candidates = candidates.filter(c => c.csrf_token !== '');
				logger.debug(LOG_CAT, `After token filter: ${candidates.length} candidate(s)`);

				if (candidates.length === 0) {
					continue;
				}

				// Prioritize candidates
				candidates = this.prioritize_candidates(candidates, target_folder, workspace_paths);

				// Health check candidates in order
				for (const candidate of candidates) {
					logger.debug(LOG_CAT, `Testing candidate PID=${candidate.pid}`);
					checked_pids.add(candidate.pid);

					const ports = await this.get_listening_ports(candidate.pid);
					logger.debug(LOG_CAT, `Found ${ports.length} listening port(s): [${ports.join(', ')}]`);

					if (ports.length === 0) {
						logger.warn(LOG_CAT, `No listening ports for PID ${candidate.pid}`);
						continue;
					}

					const valid_port = await this.find_working_port(ports, candidate.csrf_token);
					if (valid_port) {
						logger.info(LOG_CAT, `SUCCESS: Valid port found: ${valid_port} for PID ${candidate.pid}`);
						timer();
						return {
							extension_port: candidate.extension_port,
							connect_port: valid_port,
							csrf_token: candidate.csrf_token,
						};
					} else {
						logger.warn(LOG_CAT, `No working port for PID ${candidate.pid}`);
					}
				}
			}
		}

		logger.error(LOG_CAT, `Process detection failed after ${max_retries} attempt(s)`);
		timer();
		return null;
	}

	private async resolve_missing_tokens(candidates: candidate_info[], null_budget: number): Promise<{ candidates: candidate_info[]; null_requeried: number }> {
		const resolved: candidate_info[] = [];
		let null_used = 0;

		// Sort by PID descending for deterministic null-origin selection
		const sorted = [...candidates].sort((a, b) => b.pid - a.pid);

		for (const candidate of sorted) {
			if (candidate.csrf_token !== '') {
				resolved.push(candidate);
				continue;
			}

			// Candidate needs re-query
			const is_null_origin = candidate.command_line === '';

			// Check budget for null-origin candidates
			if (is_null_origin && null_used >= null_budget) {
				logger.debug(LOG_CAT, `Skipping PID ${candidate.pid} (null-origin budget exhausted)`);
				continue;
			}

			const requery_cmd = this.strategy.get_full_command_line_command(candidate.pid);
			if (!requery_cmd) {
				resolved.push(candidate);
				continue;
			}

			logger.debug(LOG_CAT, `Re-querying PID ${candidate.pid}: ${requery_cmd}`);

			// Count null-origin re-query BEFORE the attempt (to enforce budget globally)
			if (is_null_origin) {
				null_used++;
			}

			try {
				const { stdout } = await exec_async(requery_cmd);
				const updated = this.strategy.parse_command_line(candidate.pid, stdout);

				if (updated && updated.csrf_token !== '') {
					logger.debug(LOG_CAT, `Re-query success for PID ${candidate.pid}`);
					resolved.push(updated);
				} else {
					logger.debug(LOG_CAT, `Re-query failed for PID ${candidate.pid} (no token)`);
					// Don't add to resolved - candidate is invalid
				}
			} catch (e: any) {
				logger.debug(LOG_CAT, `Re-query error for PID ${candidate.pid}: ${e.message}`);
				// Don't add to resolved - candidate may belong to another user
			}
		}

		return { candidates: resolved, null_requeried: null_used };
	}

	private get_workspace_paths(): { fsPath: string; realPath: string; workspace_id: string; realPath_id: string }[] {
		const folders = vscode.workspace.workspaceFolders || [];
		const result: { fsPath: string; realPath: string; workspace_id: string; realPath_id: string }[] = [];

		for (const folder of folders) {
			if (folder.uri.scheme !== 'file') {
				continue;
			}

			const fsPath = folder.uri.fsPath;
			let realPath = fsPath;

			try {
				realPath = fs.realpathSync(fsPath);
			} catch {
				// Fall back to original path
			}

			result.push({
				fsPath,
				realPath,
				workspace_id: this.derive_workspace_id(fsPath),
				realPath_id: this.derive_workspace_id(realPath),
			});
		}

		return result;
	}

	private get_target_folder(): vscode.WorkspaceFolder | undefined {
		// Use active editor's workspace folder if available
		const editor = vscode.window.activeTextEditor;
		if (editor) {
			const folder = vscode.workspace.getWorkspaceFolder(editor.document.uri);
			if (folder) {
				return folder;
			}
		}
		// Fallback to first workspace folder
		return vscode.workspace.workspaceFolders?.[0];
	}

	private derive_workspace_id(fsPath: string): string {
		// Note: Leading "/" on Unix becomes "_", so /home/foo → file__home_foo (double underscore is intentional)
		let normalized = fsPath.replace(/[/\\:]/g, '_');
		if (process.platform === 'win32') {
			normalized = normalized.toLowerCase();
		}
		return 'file_' + normalized;
	}

	private prioritize_candidates(
		candidates: candidate_info[],
		target_folder: vscode.WorkspaceFolder | undefined,
		workspace_paths: { fsPath: string; realPath: string; workspace_id: string; realPath_id: string }[]
	): candidate_info[] {
		// Get target folder paths (if any)
		let target_paths: string[] = [];
		let target_ids: string[] = [];

		if (target_folder && target_folder.uri.scheme === 'file') {
			const fsPath = target_folder.uri.fsPath;
			let realPath = fsPath;
			try {
				realPath = fs.realpathSync(fsPath);
			} catch {
				// Fall back to original
			}
			target_paths = [fsPath, realPath];
			target_ids = [this.derive_workspace_id(fsPath), this.derive_workspace_id(realPath)];
		}

		// Compute all workspace paths and IDs
		const all_paths = workspace_paths.flatMap(w => [w.fsPath, w.realPath]);
		const all_ids = workspace_paths.flatMap(w => [w.workspace_id, w.realPath_id]);

		// Helper for path matching (case-insensitive on Windows)
		const pathIncludes = (cmd: string, path: string): boolean => {
			if (process.platform === 'win32') {
				return cmd.toLowerCase().includes(path.toLowerCase());
			}
			return cmd.includes(path);
		};

		// Score and sort candidates
		const scored = candidates.map(candidate => {
			let weight = 0;

			// Weight 100: Matches target folder
			if (target_paths.some(p => pathIncludes(candidate.command_line, p))) {
				weight = 100;
			}
			// Weight 50: Matches any workspace folder
			else if (all_paths.some(p => pathIncludes(candidate.command_line, p))) {
				weight = 50;
			}
			// Weight 10: Matches any workspace_id (also case-insensitive on Windows)
			else if (all_ids.some(id => pathIncludes(candidate.command_line, id))) {
				weight = 10;
			}

			return { candidate, weight };
		});

		// Sort by weight descending, then PID descending
		scored.sort((a, b) => {
			if (b.weight !== a.weight) {
				return b.weight - a.weight;
			}
			return b.candidate.pid - a.candidate.pid;
		});

		logger.debug(LOG_CAT, `Prioritized candidates: ${scored.map(s => `PID=${s.candidate.pid}(w=${s.weight})`).join(', ')}`);

		return scored.map(s => s.candidate);
	}

	private async get_listening_ports(pid: number): Promise<number[]> {
		try {
			const cmd = this.strategy.get_port_list_command(pid);
			logger.debug(LOG_CAT, `Port list command:\n${cmd}`);

			const { stdout, stderr } = await exec_async(cmd);

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

			req.write(JSON.stringify({ wrapper_data: {} }));
			req.end();
		});
	}
}
