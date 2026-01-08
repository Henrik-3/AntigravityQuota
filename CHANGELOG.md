# CHANGELOG

## 1.2.0 (2026-01-08)

### Fixed
- **Multi-user environment support**: Fixed process detection failing on shared Linux servers where multiple users run language_server processes. The extension now correctly identifies processes belonging to the current user.
- **macOS argument truncation**: Fixed token extraction failing when `pgrep -fl` returns truncated command lines. Now performs targeted `ps -ww` re-queries to resolve full arguments.
- **Windows CommandLine null handling**: Improved handling of processes with null/missing CommandLine in WMI output.

### Added
- **Tiered discovery**: Implements user-first, then global process search for better accuracy.
- **Workspace-aware prioritization**: Prioritizes language server processes matching the current VS Code workspace.
- **Multi-candidate iteration**: Tests multiple matching processes until finding a working one, instead of failing on the first candidate.

### Changed
- Refactored `platform_strategy` interface to support multi-tiered commands and multi-candidate parsing.
- Refactored `ProcessFinder` for robust error handling and semantic exit code classification.

## 1.1.0 (2025-12-20)

- Add absolute date and time to quota reset information (locale-aware)
- Add notice/mention of the source project
- Fix macOS port detection logic by using AND semantics in `lsof`
- Improve port validation to prevent false positives from unrelated local services
- Add PID verification for all discovered listening ports

## 1.0.7 (2025-12-17)

- Added naming scheme for Gemini 3 Flash
