# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Falco plugin for monitoring OpenClaw AI assistant logs and detecting 7 categories of security threats in real-time. Built with the Falco Plugin SDK for Go (`plugin-sdk-go`). The plugin tails multiple log files (JSONL + plaintext), parses entries, runs security pattern detection, and delivers events to Falco via GOB-encoded batches.

## Build & Development Commands

```bash
make build          # Build shared library (.so on Linux, .dylib on macOS)
make test           # Run all tests: go test ./... -v
make test-coverage  # Tests with coverage report for pkg/
make lint           # golangci-lint run (requires golangci-lint installed)
make vet            # go vet ./...
make verify         # Build + verify binary is valid ELF shared object
make clean          # Remove build artifacts
```

Run a single test:
```bash
go test ./pkg/parser/ -v -run TestName
```

**Build requires CGO_ENABLED=1** and uses `-buildmode=c-shared` to produce a shared library. Cross-compilation from macOS to Linux is not possible with CGO — use the Dockerfile or a Linux machine.

## Architecture

### Two-layer design

1. **Plugin layer** (`cmd/plugin-sdk/plugin.go`) — Implements the Falco plugin SDK interfaces:
   - `Info()` / `Init()` / `InitSchema()` — plugin metadata and config
   - `Open()` / `Close()` — instance lifecycle, starts fsnotify file watchers
   - `NextBatch()` — delivers GOB-encoded events to Falco
   - `Fields()` / `Extract()` — defines and extracts the 13 `openclaw.*` fields
   - Background goroutine (`readLoop`) tails log files and sends parsed events to a buffered channel

2. **Parser layer** (`pkg/parser/`) — Pure Go, no Falco dependency, fully testable:
   - `parser.go` — `Parser` struct, auto-detects JSON vs plaintext format, produces `LogEntry` structs
   - `regex_simple.go` — `SimpleSecurityDetector` with string-matching threat detection (no regex, ReDoS-safe). Detects 7 threat categories.
   - `config.go` — Parser configuration struct

### Data flow

```
Log files → fsnotify watcher → readLoop goroutine → Parser.Parse()
→ LogEntry (with SecurityThreat) → OpenclawEvent → buffered channel
→ NextBatch() → GOB encode → Falco
```

### Key type mapping

`LogEntry` (parser output) maps to `OpenclawEvent` (plugin event) — these are deliberately separate structs (marked C-001 in code).

## Critical Constraints (P-codes in comments)

- **P002**: `-buildmode=c-shared` is required — without it Falco cannot load the plugin
- **P004**: `Headers` map must always be initialized with `make()` to prevent nil map panics during GOB encoding
- **P008**: `load_plugins: [openclaw]` is required in falco.yaml — without it the plugin is silently ignored
- **P010**: Every field in `Fields()` must have a corresponding case in `Extract()`, and vice versa
- **P014**: Log files are seeked to end on open — only new entries are processed

## Falco Configuration

Three config files for different environments:
- `falco.yaml` — Production Linux install
- `falco-local.yaml` — Local macOS development (uses .dylib path)
- `falco-docker.yaml` — Docker container (uses mounted /openclaw-logs/)

Rules are in `rules/openclaw_rules.yaml`. All rules must have `source: openclaw`. Do not use `evt.type` in plugin rules (P005).

## Testing

Tests live in `pkg/parser/parser_test.go`. Test fixture data is in `test/fixtures/sample_logs/` and security pattern test cases are in `test/e2e/patterns/categories/` (one JSON file per threat category).

## Linting

Uses golangci-lint with gosec, govet, errcheck, staticcheck, unused, ineffassign, gocritic, and prealloc. gosec rule G304 (taint input file paths) is excluded since log file paths are expected user input.
