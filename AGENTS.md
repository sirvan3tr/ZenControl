# Repository Guidelines

## Project Structure & Module Organization
- `src/ZenControl.go` is the main Go program (CLI encrypt/decrypt workflow).
- `example apps/` contains small Go examples (not part of the core build).
- `macOS Exec/` and `Windows Exec/` hold prebuilt binaries and a sample `files.db`.
- The app expects a SQLite database named `files.db` in the current working directory.

## Build, Test, and Development Commands
- `go build -o ZenControl ./src/ZenControl.go` builds a local binary in the repo root.
- `go run ./src/ZenControl.go encrypt` runs the encrypt flow from source.
- `go run ./src/ZenControl.go decrypt` runs the decrypt flow from source.
- Prebuilt binaries:
  - macOS: `./macOS\ Exec/ZenControl encrypt`
  - Windows: `Windows Exec\\ZenControl.exe encrypt`

Note: there is no `go.mod` in this repo; builds rely on a GOPATH setup or a locally initialized module.

## Coding Style & Naming Conventions
- Follow standard Go formatting (`gofmt`); use tabs for indentation.
- Prefer `camelCase` for local variables and `CamelCase` for exported names.
- Keep CLI strings and file paths explicit; avoid hidden defaults.

## Testing Guidelines
- No automated tests are present today.
- If adding tests, use Go’s standard tooling: `go test ./...`.
- Name test files `*_test.go` and prefer table-driven tests where practical.

## Commit & Pull Request Guidelines
- Recent commit messages are short and imperative (e.g., “restructure, added windows shortcuts with args”).
- Keep commits focused; summarize behavior changes in the first line.
- PRs should include:
  - A brief summary and testing notes.
  - Any changes to CLI usage or database schema.
  - Screenshots are not required for this CLI tool.

## Security & Configuration Tips
- `files.db` stores `id, filename, filedir, status`; ensure `filedir` includes a trailing slash/backslash.
- The app deletes the original file after encrypting; test with backups.
- The time gate is based on local system time (defaults to 19:00); document changes clearly.
