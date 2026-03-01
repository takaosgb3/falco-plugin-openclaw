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
make e2e            # Run E2E Level 1 + Level 2 tests
make e2e-all        # Run all E2E levels + Allure report
make e2e-deploy-local # Deploy local test results to GitHub Pages
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

### Unit Tests

Parser unit tests in `pkg/parser/parser_test.go` (95.9% coverage). Test fixture data in `test/fixtures/sample_logs/`.

```bash
make test              # Run all unit tests
make test-coverage     # Tests with coverage report
```

### E2E Tests (3 levels)

| Level | Description | Falco Required | Location |
|-------|-------------|----------------|----------|
| Level 1 | Pattern coverage tests | No | `test/e2e/e2e_pattern_test.go` |
| Level 2 | Plugin pipeline tests | No | `cmd/plugin-sdk/plugin_test.go` |
| Level 3 | Falco integration tests | Yes | `e2e/scripts/` |

Test pattern data: `test/e2e/patterns/categories/` (11 JSON files, 56 patterns total).

```bash
make e2e               # Level 1 + Level 2 (no Falco)
make e2e-pattern       # Level 1 only
make e2e-pipeline      # Level 2 only (requires CGO_ENABLED=1)
make e2e-native        # Level 3 on macOS (requires local Falco)
make e2e-ci            # Level 3 on Linux CI
make e2e-all           # All levels + Allure report
make e2e-report        # Generate Allure report from Level 3 results
make e2e-deploy-local  # Deploy local test results to GitHub Pages
```

See `e2e/README.md` for detailed E2E test documentation.

### Key E2E Constraints

- **Level 2 requires CGO_ENABLED=1** because plugin-sdk-go has C dependencies
- **Falco 0.43.0 fires only 1 rule per event** (first matching rule in file order)
- **Escape rule has no tool condition** — fires on args patterns regardless of tool value
- **Parser truncation vs Falco**: `DetectThreat()` truncates args >10240B, but `Extract()` returns full args to Falco

## Linting

Uses golangci-lint with gosec, govet, errcheck, staticcheck, unused, ineffassign, gocritic, and prealloc. gosec rule G304 (taint input file paths) is excluded since log file paths are expected user input.
