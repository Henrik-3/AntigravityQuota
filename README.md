# Antigravity Quota Watcher

A lightweight VS Code extension that monitors your Antigravity AI model usage quota and displays it in the status bar.

<img src="assets/modal.png" alt="drawing" width="500"/>
<img src="assets/taskbar.png" alt="drawing" width="500"/>

## Installation (Github)

1. Download the latest `.vsix` from the [Releases](https://github.com/Henrik-3/AntigravityQuota/releases/latest)
2. In VS Code: `Extensions` → `...` → `Install from VSIX...`
3. Restart VS Code / Antigravity

## Installation (Open VSX/Antigravity)

1. Open Antigravity
2. Open the Extensions view (`Ctrl+Shift+X`)
3. Search for "Antigravity Quota (AGQ)"
4. Click `Install`

## Features

### Real-Time Quota Monitoring

- **Automatic detection** – Finds Antigravity's language server process, port, and auth token without manual setup
- **Background polling** – Periodically fetches quota data to keep the status bar up-to-date
- **Multi-model support** – Tracks quota usage for all available AI models (Gemini, Claude, GPT, etc.)

### Status Bar Integration

- Displays quota info directly in the VS Code status bar
- Visual indicators:
    - `$(check)` – Quota healthy (>20%)
    - `$(warning)` – Quota low (<20%)
    - `$(error)` – Quota exhausted
- Click to open the interactive quota menu

### Pinned Models

- Pin your favorite models to the status bar for quick visibility
- Toggle pinning from the interactive menu
- When no models are pinned, displays "AGQ" as default

### Interactive Quota Menu

- View all models with progress bars and percentages
- See time until quota reset for each model
- View prompt credits (available/monthly)
- Toggle model visibility directly from the menu

### Cross-Platform Support

- **Windows** – Full support using `wmic` for process detection
- **macOS** – Unix-based detection strategy
- **Linux** – Unix-based detection strategy

## Commands

| Command            | Description                 |
| ------------------ | --------------------------- |
| `AGQ: Refresh Now` | Manually refresh quota data |

## Configuration

Configure via VS Code Settings (`Ctrl+,`) under **AGQ**:

| Setting               | Default | Description                                 |
| --------------------- | ------- | ------------------------------------------- |
| `agq.enabled`         | `true`  | Enable/disable quota monitoring             |
| `agq.pollingInterval` | `120`   | Polling interval in seconds (min: 30s)      |
| `agq.pinnedModels`    | `[]`    | Array of model IDs to display in status bar |

## Building from Source

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Package VSIX
npm run node:vsix:package
```

For Bun users:

```bash
bun run bun:vsix:package
```

## Development

```bash
# Watch mode for development
npm run watch

# Lint
npm run lint
```

## How It Works

1. **Process Detection** – Scans for Antigravity's language server process and extracts connection parameters
2. **Port Discovery** – Tests listening ports to find the correct API endpoint
3. **Quota Fetching** – Calls `GetUserStatus` API to retrieve model quotas and prompt credits
4. **UI Updates** – Parses the response and updates the status bar with formatted quota info

## Disclaimer

This extension was created by me and Gemini 3 Pro between some Rainbow Six Siege Games, therefore please do not expect the highest code quality in this repo (yet).
Some parts of the code (and especially the knowledge of how this process works) are based on the [Antigravity Quota Watcher](https://github.com/wusimpl/AntigravityQuotaWatcher) project. Feel free to check it out and leave a star on their repo if you find this useful.

This project isn't endorsed by Google and doesn't reflect the views or opinions of Google or anyone officially involved in producing or managing Google/AntiGravity properties

## License

[MIT License](LICENSE)
