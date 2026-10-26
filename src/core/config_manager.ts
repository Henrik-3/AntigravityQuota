/**
 * Config Manager Service
 */

import * as vscode from 'vscode';
import {config_options, display_mode} from '../utils/types';

export class ConfigManager {
	private readonly config_key = 'agq';
	private readonly legacy_config_key = 'agQuota';

	/**
	 * Resolve configuration value by prioritizing explicit `agq` setting,
	 * then explicit legacy `agQuota` setting, then manifest defaults.
	 * @param key Configuration key name
	 * @param default_value Default fallback value
	 * @returns Resolved configuration value
	 */
	private resolve_value<T>(key: string, default_value: T): T {
		const config = vscode.workspace.getConfiguration(this.config_key);
		const legacy_config = vscode.workspace.getConfiguration(this.legacy_config_key);

		const inspected = config.inspect<T>(key);
		const has_explicit_agq =
			inspected &&
			(inspected.globalValue !== undefined ||
				inspected.workspaceValue !== undefined ||
				inspected.workspaceFolderValue !== undefined);
		if (has_explicit_agq) {
			return config.get<T>(key, default_value);
		}

		const legacy_inspected = legacy_config.inspect<T>(key);
		const has_explicit_legacy =
			legacy_inspected &&
			(legacy_inspected.globalValue !== undefined ||
				legacy_inspected.workspaceValue !== undefined ||
				legacy_inspected.workspaceFolderValue !== undefined);
		if (has_explicit_legacy) {
			return legacy_config.get<T>(key, default_value);
		}

		return config.get<T>(key, default_value);
	}

	/**
	 * Get full config
	 */
	get_config(): config_options {
		const enabled = this.resolve_value<boolean>('enabled', true);
		const polling_interval_sec = this.resolve_value<number>('pollingInterval', 120);
		const show_prompt_credits = this.resolve_value<boolean>('showPromptCredits', false);
		const display_mode = this.resolve_value<display_mode>('displayMode', 'models');

		return {
			enabled,
			polling_interval: Math.max(30, polling_interval_sec) * 1000,
			show_prompt_credits,
			display_mode,
		};
	}

	/**
	 * Listen to config changes
	 */
	on_config_change(callback: (config: config_options) => void): vscode.Disposable {
		return vscode.workspace.onDidChangeConfiguration(event => {
			if (event.affectsConfiguration(this.config_key) || event.affectsConfiguration(this.legacy_config_key)) {
				callback(this.get_config());
			}
		});
	}
}
