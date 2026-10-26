// Minimal in-memory mock for 'vscode' in unit test environment
// eslint-disable-next-line @typescript-eslint/no-var-requires
const Module = require('module');
const originalResolveFilename = Module._resolveFilename;

let configStore: Record<string, any> = {};

export function setMockConfig(key: string, value: any) {
	configStore[key] = value;
}

export function getMockConfig(key: string) {
	return configStore[key];
}

export function resetMockConfig() {
	configStore = {};
}

const mockVscode = {
	StatusBarAlignment: { Left: 1, Right: 2 },
	QuickPickItemKind: { Separator: -1, Default: 0 },
	ConfigurationTarget: { Global: 1, Workspace: 2, WorkspaceFolder: 3 },
	ThemeColor: class ThemeColor {
		constructor(public id: string) {}
	},
	window: {
		createStatusBarItem: () => ({
			show: () => {},
			dispose: () => {},
			text: '',
			tooltip: '',
			backgroundColor: undefined,
			command: '',
		}),
		createOutputChannel: () => ({
			appendLine: () => {},
			show: () => {},
		}),
		createQuickPick: () => ({
			show: () => {},
			dispose: () => {},
			onDidChangeActive: () => {},
			onDidAccept: () => {},
			onDidHide: () => {},
			items: [],
		}),
	},
	workspace: {
		getConfiguration: (section?: string) => ({
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			get: (key: string, defaultValue: any) => {
				const fullKey = section ? `${section}.${key}` : key;
				return fullKey in configStore ? configStore[fullKey] : defaultValue;
			},
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			inspect: (key: string) => {
				const fullKey = section ? `${section}.${key}` : key;
				const hasVal = fullKey in configStore;
				return {
					key,
					defaultValue: undefined,
					globalValue: hasVal ? configStore[fullKey] : undefined,
					workspaceValue: undefined,
					workspaceFolderValue: undefined,
				};
			},
			update: async (key: string, value: any) => {
				const fullKey = section ? `${section}.${key}` : key;
				configStore[fullKey] = value;
			},
		}),
		onDidChangeConfiguration: () => ({ dispose: () => {} }),
	},
	commands: {
		registerCommand: () => ({ dispose: () => {} }),
	},
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
Module._resolveFilename = function (request: string, parent: any, isMain: boolean, options: any) {
	if (request === 'vscode') {
		return 'vscode';
	}
	return originalResolveFilename.call(this, request, parent, isMain, options);
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
require.cache['vscode'] = {
	id: 'vscode',
	filename: 'vscode',
	loaded: true,
	exports: mockVscode,
} as any;
