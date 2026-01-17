/**
 * Antigravity Quota Watcher - Main Entry
 */

import * as vscode from 'vscode';
import {ConfigManager} from './core/config_manager';
import {ProcessFinder} from './core/process_finder';
import {QuotaManager} from './core/quota_manager';
import {StatusBarManager} from './ui/status_bar';
import {logger} from './utils/logger';

let config_manager: ConfigManager;
let process_finder: ProcessFinder;
let quota_manager: QuotaManager;
let status_bar: StatusBarManager;
let is_initialized = false;

export async function activate(context: vscode.ExtensionContext) {
	logger.init(context);
	logger.section('Extension', 'Antigravity Quota Activating');
	logger.info('Extension', `VS Code Version: ${vscode.version}`);
	logger.info('Extension', `Extension activating at: ${new Date().toISOString()}`);

	config_manager = new ConfigManager();
	process_finder = new ProcessFinder();
	quota_manager = new QuotaManager();
	status_bar = new StatusBarManager();

	context.subscriptions.push(status_bar);

	const config = config_manager.get_config();
	logger.debug('Extension', 'Initial config:', config);

	// Register Commands
	context.subscriptions.push(
		vscode.commands.registerCommand('agq.refresh', () => {
			logger.info('Extension', 'Manual refresh triggered');
			vscode.window.showInformationMessage('Refreshing Quota...');
			quota_manager.fetch_quota();
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('agq.show_menu', () => {
			logger.debug('Extension', 'Show menu triggered');
			status_bar.show_menu();
		})
	);

	// Manual activation command
	context.subscriptions.push(
		vscode.commands.registerCommand('agq.activate', async () => {
			logger.info('Extension', 'Manual activation triggered');
			if (!is_initialized) {
				await initialize_extension();
			} else {
				vscode.window.showInformationMessage('AGQ is already active');
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('agq.reconnect', async () => {
			logger.info('Extension', 'Reconnect triggered');
			vscode.window.showInformationMessage('Reconnecting to Antigravity process...');
			is_initialized = false;
			quota_manager.stop_polling();
			status_bar.show_loading();
			await initialize_extension();
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('agq.show_logs', () => {
			logger.info('Extension', 'Opening debug log panel');
			logger.show();
			vscode.window.showInformationMessage('Debug log panel opened');
		})
	);

	// Setup Quota Manager Callbacks
	quota_manager.on_update(snapshot => {
		const current_config = config_manager.get_config();
		logger.debug('Extension', 'Quota update received:', {
			models_count: snapshot.models?.length ?? 0,
			prompt_credits: snapshot.prompt_credits,
			timestamp: snapshot.timestamp,
		});
		status_bar.update(snapshot, current_config.show_prompt_credits ?? false);
	});

	quota_manager.on_error(err => {
		logger.error('Extension', `Quota error: ${err.message}`);
		status_bar.show_error(err.message);
	});

	// Initialize extension asynchronously (non-blocking)
	// This prevents blocking VS Code startup
	logger.debug('Extension', 'Starting async initialization...');
	initialize_extension().catch(err => {
		logger.error('Extension', 'Failed to initialize AG Quota Watcher:', err);
	});

	// Handle Config Changes
	context.subscriptions.push(
		config_manager.on_config_change(new_config => {
			logger.info('Extension', 'Config changed:', new_config);
			if (new_config.enabled) {
				quota_manager.start_polling(new_config.polling_interval);
			} else {
				quota_manager.stop_polling();
			}
		})
	);

	logger.info('Extension', 'Extension activation complete');
}

async function initialize_extension() {
	if (is_initialized) {
		logger.debug('Extension', 'Already initialized, skipping');
		return;
	}

	logger.section('Extension', 'Initializing Extension');
	const timer = logger.time_start('initialize_extension');

	const config = config_manager.get_config();
	status_bar.show_loading();

	try {
		logger.info('Extension', 'Detecting Antigravity process...');
		const process_info = await process_finder.detect_process_info(5);

		if (process_info) {
			logger.info('Extension', 'Process found successfully', {
				extension_port: process_info.extension_port,
				connect_port: process_info.connect_port,
				csrf_token: process_info.csrf_token.substring(0, 8) + '...',
			});

			quota_manager.init(process_info.connect_port, process_info.csrf_token);

			if (config.enabled) {
				logger.debug('Extension', `Starting polling with interval: ${config.polling_interval}ms`);
				quota_manager.start_polling(config.polling_interval);
			}
			is_initialized = true;
			logger.info('Extension', 'Initialization successful');
		} else {
			logger.error('Extension', 'Antigravity process not found');
			logger.info('Extension', 'Troubleshooting tips:');
			logger.info('Extension', '   1. Make sure Antigravity extension is installed and enabled');
			logger.info('Extension', '   2. Check if the language_server process is running');
			logger.info('Extension', '   3. Try reloading VS Code');
			logger.info('Extension', '   4. Open "Output" panel and select "Antigravity Quota" for detailed logs');

			status_bar.show_error('Antigravity process not found');
			vscode.window.showErrorMessage('Could not find Antigravity process. Is it running? Use "AGQ: Show Debug Log" to see details.', 'Show Logs').then(action => {
				if (action === 'Show Logs') {
					logger.show();
				}
			});
		}
	} catch (e: any) {
		logger.error('Extension', 'Detection failed with exception:', {
			message: e.message,
			stack: e.stack,
		});
		status_bar.show_error('Detection failed');
	}

	timer();
}

export function deactivate() {
	logger.info('Extension', 'Extension deactivating');
	quota_manager?.stop_polling();
	status_bar?.dispose();
}
