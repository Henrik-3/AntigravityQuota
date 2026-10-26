/**
 * Status Bar UI Manager
 */

import * as vscode from 'vscode';
import {quota_snapshot, model_quota_info, quota_group_info, display_mode} from '../utils/types';
import {ConfigManager} from '../core/config_manager';

/** Mapping of model labels to short abbreviations for status bar display */
const MODEL_ABBREVIATIONS: Record<string, string> = {
	'Gemini 3.5 Flash (Low)': 'G3.5F(L)',
	'Gemini 3.5 Flash (Medium)': 'G3.5F(M)',
	'Gemini 3.5 Flash (High)': 'G3.5F(H)',
	'Gemini 3.1 Pro (High)': 'G3.1P(H)',
	'Gemini 3.1 Pro (Low)': 'G3.1P(L)',
	'Gemini 3 Pro (High)': 'G3P(H)',
	'Gemini 3 Pro (Low)': 'G3P(L)',
	'Gemini 3 Flash': 'G3F',
	'Claude Sonnet 4.6 (Thinking)': 'Claude S4.6T',
	'Claude Opus 4.6 (Thinking)': 'Claude O4.6T',
	'Claude Sonnet 4.5': 'Claude S4.5',
	'Claude Sonnet 4.5 (Thinking)': 'Claude S4.5T',
	'Claude Opus 4.5 (Thinking)': 'Claude O4.5T',
	'GPT-OSS 120B (Medium)': 'GPT-OSS (M)',
};

/** Get short abbreviation for a model label */
export function get_abbreviation(label: string): string {
	if (MODEL_ABBREVIATIONS[label]) {
		return MODEL_ABBREVIATIONS[label];
	}
	// Fallback: generate abbreviation from first letters of words + numbers
	return label
		.split(/[\s\-_()]+/)
		.filter(Boolean)
		.map(word => {
			const match = word.match(/^([A-Za-z]?)(.*)$/);
			if (match) {
				return match[1].toUpperCase() + (word.match(/\d+/) || [''])[0];
			}
			return word[0]?.toUpperCase() || '';
		})
		.join('')
		.slice(0, 5);
}

/** Get short label for a quota group */
export function get_group_short_name(group_name: string): string {
	const lower = group_name.toLowerCase();
	if (lower.includes('gemini')) return 'Gemini';
	if (lower.includes('claude') && lower.includes('gpt')) return 'Claude/GPT';
	if (lower.includes('claude')) return 'Claude';
	if (lower.includes('gpt')) return 'GPT';
	return group_name.split(/\s+/)[0] || group_name;
}

/** Format a single quota group into status bar string */
export function format_group_status(group: quota_group_info): string {
	const short_name = get_group_short_name(group.display_name);
	const bucket_parts: string[] = [];

	let min_pct: number | undefined;
	let has_exhausted = false;

	for (const b of group.buckets) {
		const pct = b.remaining_percentage;
		if (b.is_exhausted) has_exhausted = true;
		if (pct !== undefined) {
			if (min_pct === undefined || pct < min_pct) {
				min_pct = pct;
			}
		}

		const pct_str = pct !== undefined ? `${pct.toFixed(0)}%` : 'N/A';
		const window_label = b.window === 'weekly' ? '1w' : b.window;
		bucket_parts.push(`${window_label}: ${pct_str}`);
	}

	const icon = has_exhausted ? '$(error)' : min_pct !== undefined && min_pct < 20 ? '$(warning)' : '$(check)';
	return `${icon} ${short_name} [${bucket_parts.join(' | ')}]`;
}

/**
 * Escape regular expression special characters
 * @param str Input string
 * @returns Escaped regex string
 */
function escape_regex(str: string): string {
	return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Check if a quota group is pinned for status bar display
 */
export function is_group_pinned(group_name: string, pinned_groups: string[]): boolean {
	if (!pinned_groups || pinned_groups.length === 0) {
		return true;
	}
	const short_name = get_group_short_name(group_name).toLowerCase();
	const full_name = group_name.toLowerCase();
	return pinned_groups.some(p => {
		const target = p.toLowerCase();
		if (target === short_name || target === full_name) {
			return true;
		}
		// Word-boundary matching (e.g. 'GPT' or 'Claude' matches 'Claude and GPT models' or 'Claude/GPT')
		const regex = new RegExp(`(^|[\\s/\\-_,.])${escape_regex(target)}($|[\\s/\\-_,.])`, 'i');
		return regex.test(full_name) || regex.test(short_name);
	});
}

/** Draw a progress bar string */
export function draw_progress_bar(percentage: number): string {
	const total = 10;
	const filled = Math.round((percentage / 100) * total);
	const empty = Math.max(0, total - filled);
	return '▓'.repeat(Math.max(0, filled)) + '░'.repeat(empty);
}

export class StatusBarManager {
	private item: vscode.StatusBarItem;
	private last_snapshot: quota_snapshot | undefined;
	private config_manager = new ConfigManager();

	constructor() {
		this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
		this.item.command = 'agq.show_menu';
		this.item.text = '$(rocket) AGQ';
		this.item.show();
	}

	show_loading() {
		this.item.text = '$(sync~spin) AGQ';
		this.item.show();
	}

	show_error(msg: string) {
		this.item.text = '$(error) AGQ';
		this.item.tooltip = msg;
		this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
		this.item.show();
	}

	update(snapshot: quota_snapshot, show_credits: boolean, mode?: display_mode) {
		this.last_snapshot = snapshot;

		const resolved_config = this.config_manager.get_config();
		const current_mode: display_mode = mode ?? resolved_config.display_mode ?? 'models';
		const pinned = this.get_pinned_models();
		const parts: string[] = [];
		const has_groups = !!(snapshot.groups && snapshot.groups.length > 0);

		// 1. Group limits
		if ((current_mode === 'groups' || current_mode === 'both') && has_groups) {
			const pinned_groups = this.get_pinned_groups();
			for (const group of snapshot.groups!) {
				if (is_group_pinned(group.display_name, pinned_groups)) {
					parts.push(format_group_status(group));
				}
			}
		}

		// 2. Individual pinned models
		// Fall back to models in 'groups' mode only if quota group data itself is unavailable or empty.
		if (current_mode === 'models' || current_mode === 'both' || (current_mode === 'groups' && !has_groups)) {
			const pinned_models = snapshot.models
				.filter(m => pinned.includes(m.model_id))
				.sort((a, b) => a.label.localeCompare(b.label));

			for (const m of pinned_models) {
				const pct = m.remaining_percentage !== undefined ? `${m.remaining_percentage.toFixed(0)}%` : 'N/A';
				const status_icon = m.is_exhausted
					? '$(error)'
					: m.remaining_percentage !== undefined && m.remaining_percentage < 20
					? '$(warning)'
					: '$(check)';
				const abbrev = get_abbreviation(m.label);
				parts.push(`${status_icon} ${abbrev}: ${pct}`);
			}
		}

		if (parts.length === 0) {
			this.item.text = '$(rocket) AGQ';
		} else {
			this.item.text = parts.join('  ');
		}

		this.item.backgroundColor = undefined;
		this.item.tooltip = 'Click to view Antigravity Quota details';
		this.item.show();
	}

	/**
	 * Re-render status bar using the cached quota snapshot
	 * @param show_credits Whether to show prompt credits
	 * @param mode Display mode (models, groups, or both)
	 */
	refresh_cached_snapshot(show_credits: boolean, mode?: display_mode) {
		if (this.last_snapshot) {
			this.update(this.last_snapshot, show_credits, mode);
		}
	}

	show_menu() {
		const pick = vscode.window.createQuickPick();
		pick.title = 'Antigravity Quota';
		pick.placeholder = 'Click a model to toggle its visibility in the status bar';
		pick.matchOnDescription = false;
		pick.matchOnDetail = false;
		pick.canSelectMany = false;

		pick.items = this.build_menu_items();

		let currentActiveItem: vscode.QuickPickItem | undefined;

		pick.onDidChangeActive(items => {
			currentActiveItem = items[0];
		});

		pick.onDidAccept(async () => {
			if (currentActiveItem && 'group_name' in currentActiveItem) {
				await this.toggle_pinned_group(
					(currentActiveItem as any).group_name,
					(currentActiveItem as any).group_display_name
				);
				pick.items = this.build_menu_items();
				if (this.last_snapshot) {
					const cfg = this.config_manager.get_config();
					this.update(
						this.last_snapshot,
						cfg.show_prompt_credits ?? false,
						cfg.display_mode
					);
				}
			} else if (currentActiveItem && 'model_id' in currentActiveItem) {
				await this.toggle_pinned_model((currentActiveItem as any).model_id);
				pick.items = this.build_menu_items();
				if (this.last_snapshot) {
					const cfg = this.config_manager.get_config();
					this.update(
						this.last_snapshot,
						cfg.show_prompt_credits ?? false,
						cfg.display_mode
					);
				}
			}
		});

		pick.onDidHide(() => {
			pick.dispose();
		});

		pick.show();
	}

	private get_pinned_models(): string[] {
		const config = vscode.workspace.getConfiguration('agq');
		return config.get<string[]>('pinnedModels') || [];
	}

	/**
	 * Get list of pinned quota group identifiers from configuration
	 * @returns Array of pinned group names or keys
	 */
	private get_pinned_groups(): string[] {
		const config = vscode.workspace.getConfiguration('agq');
		return config.get<string[]>('pinnedGroups') || [];
	}

	/**
	 * Toggle pin status for a quota group in global configuration
	 * @param group_key Short key or identifier of the group
	 * @param group_display_name Full display name of the group
	 */
	private async toggle_pinned_group(group_key: string, group_display_name?: string): Promise<void> {
		const config = vscode.workspace.getConfiguration('agq');
		let pinned = [...(config.get<string[]>('pinnedGroups') || [])];
		const all_groups = (this.last_snapshot?.groups || []).map(g => get_group_short_name(g.display_name));
		const display_name = group_display_name || group_key;

		if (pinned.length === 0) {
			pinned = all_groups.filter(g => g.toLowerCase() !== group_key.toLowerCase());
			if (pinned.length === 0) {
				pinned = ['none'];
			}
		} else {
			const remaining = pinned.filter(p => !is_group_pinned(display_name, [p]));
			if (remaining.length !== pinned.length) {
				pinned = remaining;
				if (pinned.length === 0) {
					pinned = ['none'];
				}
			} else {
				pinned = pinned.filter(p => p.toLowerCase() !== 'none');
				pinned.push(group_key);
			}
		}

		await config.update('pinnedGroups', pinned, vscode.ConfigurationTarget.Global);
	}

	private async toggle_pinned_model(model_id: string): Promise<void> {
		const config = vscode.workspace.getConfiguration('agq');
		const pinned = [...(config.get<string[]>('pinnedModels') || [])];

		const index = pinned.indexOf(model_id);
		if (index >= 0) {
			pinned.splice(index, 1);
		} else {
			pinned.push(model_id);
		}

		await config.update('pinnedModels', pinned, vscode.ConfigurationTarget.Global);
	}

	public build_menu_items(): vscode.QuickPickItem[] {
		const items: vscode.QuickPickItem[] = [];
		const snapshot = this.last_snapshot;
		const pinned = this.get_pinned_models();

		// Section: Shared Quota Groups
		if (snapshot?.groups && snapshot.groups.length > 0) {
			items.push({label: 'Quota Groups (Toggle Pin)', kind: vscode.QuickPickItemKind.Separator});
			const pinned_groups = this.get_pinned_groups();

			for (const group of snapshot.groups) {
				const short_name = get_group_short_name(group.display_name);
				const is_pinned = is_group_pinned(group.display_name, pinned_groups);
				const selection_icon = is_pinned ? '$(check)' : '$(circle-outline)';

				let has_exhausted = false;
				let min_pct: number | undefined;

				for (const b of group.buckets) {
					if (b.is_exhausted) has_exhausted = true;
					if (b.remaining_percentage !== undefined) {
						if (min_pct === undefined || b.remaining_percentage < min_pct) {
							min_pct = b.remaining_percentage;
						}
					}
				}

				const status_icon = has_exhausted
					? '$(error)'
					: min_pct !== undefined && min_pct < 20
					? '$(warning)'
					: '';

				// Parent Header Item with Checkmark
				const parent_item: vscode.QuickPickItem & {group_name?: string; group_display_name?: string} = {
					label: `${selection_icon} ${status_icon ? status_icon + ' ' : ''}${group.display_name}`,
				};
				parent_item.group_name = short_name;
				parent_item.group_display_name = group.display_name;
				items.push(parent_item);

				// Child Bucket Items (Indented, vertical progress bars)
				for (const bucket of group.buckets) {
					const pct = bucket.remaining_percentage;
					const pct_display = pct !== undefined ? `${pct.toFixed(1)}%` : 'N/A';
					const bar = pct !== undefined ? draw_progress_bar(pct) : '░'.repeat(10);
					const window_label = bucket.window === 'weekly' ? 'Weekly' : bucket.window === '5h' ? '5-Hour' : bucket.display_name;

					const child_item: vscode.QuickPickItem & {group_name?: string; group_display_name?: string} = {
						label: `      ${window_label}: ${bar} ${pct_display}`,
						description: `Resets in: ${bucket.time_until_reset_formatted}`,
					};
					child_item.group_name = short_name;
					child_item.group_display_name = group.display_name;
					items.push(child_item);
				}
			}
		}

		// Section: Individual Models
		items.push({label: 'Model Quotas (Toggle Pin)', kind: vscode.QuickPickItemKind.Separator});

		if (snapshot && snapshot.models.length > 0) {
			for (const m of snapshot.models) {
				const pct = m.remaining_percentage;
				const pct_display = pct !== undefined ? `${pct.toFixed(1)}%` : 'N/A';
				const bar = pct !== undefined ? draw_progress_bar(pct) : '░'.repeat(10);
				const is_pinned = pinned.includes(m.model_id);

				const selection_icon = is_pinned ? '$(check)' : '$(circle-outline)';
				const status_icon = m.is_exhausted ? '$(error)' : pct !== undefined && pct < 20 ? '$(warning)' : '';

				const item: vscode.QuickPickItem & {model_id?: string} = {
					label: `${selection_icon} ${status_icon ? status_icon + ' ' : ''}${m.label}`,
					description: `${bar} ${pct_display}`,
					detail: `    Resets in: ${m.time_until_reset_formatted}`,
				};

				(item as any).model_id = m.model_id;
				items.push(item);
			}
		} else {
			items.push({
				label: '$(info) No model data',
				description: 'Waiting for quota info...',
			});
		}

		return items;
	}

	dispose() {
		this.item.dispose();
	}
}
