/**
 * Status Bar UI Manager
 */

import * as vscode from 'vscode';
import {quota_snapshot, model_quota_info} from '../utils/types';

/** Mapping of model labels to short abbreviations for status bar display */
const MODEL_ABBREVIATIONS: Record<string, string> = {
	'Gemini 3 Pro (High)': 'Gemini 3 Pro (H)',
	'Gemini 3 Pro (Low)': 'Gemini 3 Pro (L)',
	'Gemini 3 Flash': 'Gemini 3 Flash',
	'Claude Sonnet 4.5': 'Claude S4.5',
	'Claude Sonnet 4.5 (Thinking)': 'Claude S4.5T',
	'Claude Opus 4.5 (Thinking)': 'Claude O4.5T',
	'GPT-OSS 120B (Medium)': 'GPT-OSS (M)',
};

/** Get short abbreviation for a model label */
function get_abbreviation(label: string): string {
	if (MODEL_ABBREVIATIONS[label]) {
		return MODEL_ABBREVIATIONS[label];
	}
	// Fallback: generate abbreviation from first letters of words + numbers
	return label
		.split(/[\s\-_()]+/)
		.filter(Boolean)
		.map(word => {
			// If word contains numbers, keep them
			const match = word.match(/^([A-Za-z]?)(.*)$/);
			if (match) {
				return match[1].toUpperCase() + (word.match(/\d+/) || [''])[0];
			}
			return word[0]?.toUpperCase() || '';
		})
		.join('')
		.slice(0, 5);
}

export class StatusBarManager {
	private item: vscode.StatusBarItem;
	private last_snapshot: quota_snapshot | undefined;

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

	update(snapshot: quota_snapshot, show_credits: boolean) {
		this.last_snapshot = snapshot;

		const pinned = this.get_pinned_models();
		const parts: string[] = [];

		/*if (show_credits && snapshot.prompt_credits) {
			const pc = snapshot.prompt_credits;
			const icon = pc.remaining_percentage > 20 ? '$(check)' : '$(warning)';
			parts.push(`${icon} Credits: ${pc.available}/${pc.monthly}`);
		}*/

		// Filter models to only show pinned ones
		const pinned_models = snapshot.models.filter(m => pinned.includes(m.model_id));

		if (pinned_models.length === 0 && !show_credits) {
			// Show default text if nothing is pinned
			this.item.text = '$(rocket) AGQ';
		} else {
			for (const m of pinned_models) {
				const pct = m.remaining_percentage !== undefined ? `${m.remaining_percentage.toFixed(0)}%` : 'N/A';
				const status_icon = m.is_exhausted ? '$(error)' : m.remaining_percentage !== undefined && m.remaining_percentage < 20 ? '$(warning)' : '$(check)';
				const abbrev = get_abbreviation(m.label);
				parts.push(`${status_icon} ${abbrev}: ${pct}`);
			}

			this.item.text = parts.length > 0 ? parts.join('  ') : '$(rocket) AGQ';
		}

		this.item.backgroundColor = undefined;
		this.item.tooltip = 'Click to view Antigravity Quota details';
		this.item.show();
	}

	show_menu() {
		const pick = vscode.window.createQuickPick();
		pick.title = 'Antigravity Quota';
		pick.placeholder = 'Click a model to toggle its visibility in the status bar';
		pick.matchOnDescription = false;
		pick.matchOnDetail = false;
		pick.canSelectMany = false;

		pick.items = this.build_menu_items();

		// Track the currently active (hovered/highlighted) item
		let currentActiveItem: vscode.QuickPickItem | undefined;

		// Capture the active item immediately when it changes (on hover/keyboard)
		pick.onDidChangeActive(items => {
			currentActiveItem = items[0];
		});

		// Action the tracked item when user accepts (click/Enter)
		pick.onDidAccept(async () => {
			if (currentActiveItem && 'model_id' in currentActiveItem) {
				await this.toggle_pinned_model((currentActiveItem as any).model_id);
				// Refresh the menu items to reflect the change
				pick.items = this.build_menu_items();
				// Update status bar immediately if we have a snapshot
				if (this.last_snapshot) {
					const config = vscode.workspace.getConfiguration('agq');
					this.update(this.last_snapshot, !!config.get('showPromptCredits'));
				}
			} else if (currentActiveItem && (currentActiveItem as any).action === 'reconnect') {
				vscode.commands.executeCommand('agq.reconnect');
				pick.hide();
			} else if (currentActiveItem && (currentActiveItem as any).action === 'settings') {
				vscode.commands.executeCommand('workbench.action.openSettings', 'agq');
				pick.hide();
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

	private build_menu_items(): vscode.QuickPickItem[] {
		const items: vscode.QuickPickItem[] = [];
		const snapshot = this.last_snapshot;
		const pinned = this.get_pinned_models();

		items.push({label: 'Model Quotas', kind: vscode.QuickPickItemKind.Separator});

		if (snapshot && snapshot.models.length > 0) {
			for (const m of snapshot.models) {
				const pct = m.remaining_percentage ?? 0;
				const bar = this.draw_progress_bar(pct);
				const is_pinned = pinned.includes(m.model_id);

				// Use checkmark to show if model is selected for status bar
				const selection_icon = is_pinned ? '$(check)' : '$(circle-outline)';
				// Show quota status separately
				const status_icon = m.is_exhausted ? '$(error)' : pct < 20 ? '$(warning)' : '';

				const item: vscode.QuickPickItem & {model_id?: string} = {
					label: `${selection_icon} ${status_icon ? status_icon + ' ' : ''}${m.label}`,
					description: `${bar} ${pct.toFixed(1)}%`,
					detail: `    Resets in: ${m.time_until_reset_formatted}`,
				};

				// Attach model_id for click handling
				(item as any).model_id = m.model_id;
				items.push(item);
			}
		} else {
			items.push({
				label: '$(info) No model data',
				description: 'Waiting for quota info...',
			});
		}

		// Commented out until used (if ever)
		/*if (snapshot?.prompt_credits) {
			const pc = snapshot.prompt_credits;
			const bar = this.draw_progress_bar(pc.remaining_percentage);

			items.push({label: '', kind: vscode.QuickPickItemKind.Separator});
			items.push({label: 'Prompt Credits (Not activly used)', kind: vscode.QuickPickItemKind.Separator});
			items.push({
				label: `$(credit-card) ${pc.available.toLocaleString()} / ${pc.monthly.toLocaleString()}`,
				description: `${bar} ${pc.remaining_percentage.toFixed(1)}%`,
			});
		}*/

		// Add Refresh and Settings
		items.push({label: 'Actions', kind: vscode.QuickPickItemKind.Separator});
		
		items.push({
			label: '$(sync) Retry Connection',
			description: 'Force search for Antigravity process',
			action: 'reconnect'
		} as any);

		return items;
	}

	private draw_progress_bar(percentage: number): string {
		const total = 10;
		const filled = Math.round((percentage / 100) * total);
		const empty = total - filled;
		return '▓'.repeat(filled) + '░'.repeat(empty);
	}

	dispose() {
		this.item.dispose();
	}
}
