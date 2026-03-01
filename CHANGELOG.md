# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive E2E test suite with 3 levels (pattern, pipeline, Falco integration)
- 56 test patterns across 11 categories (7 threat + benign + edge cases + composite + plaintext)
- Level 3 integration test scripts (inject_patterns.sh, batch_analyzer.py)
- Allure report generation for visual test results
- E2E CI workflow (.github/workflows/e2e-test.yml)
- Makefile E2E targets (e2e, e2e-pattern, e2e-pipeline, e2e-ci, e2e-native, e2e-all)
- E2E test documentation (e2e/README.md)

## [0.1.0] - 2026-02-27

### Added
- Initial release of the Falco OpenClaw plugin
- Real-time monitoring of 3 log files simultaneously (JSONL + plaintext)
- Auto-detection of JSON and plaintext log formats
- 7 security threat detection categories:
  - Dangerous Command Execution (rm -rf, chmod 777, fork bombs, etc.)
  - Data Exfiltration Attempts (curl/wget + sensitive files)
  - Agent Runaway Behavior (infinite loops, excessive retries)
  - Workspace Escape Attempts (access to /etc/passwd, /proc/, path traversal)
  - Suspicious Configuration Changes (disable_auth, bypass, insecure)
  - Unauthorized Model Changes (model field in config_change events)
  - Shell Injection in Non-Shell Tools (shell metacharacters in read/write/edit)
- 13 extractable fields (`openclaw.type`, `openclaw.tool`, `openclaw.args`, etc.)
- Map field support (`openclaw.headers[key]`)
- String-matching based detection (no regex, ReDoS-safe)
- Input size limit (10KB) for security detection
- fsnotify-based file watching with seek-to-end (new entries only)
- Buffered event channel with overflow handling
- GOB-encoded event serialization
- 7 Falco detection rules with lists and macros
- Multi-stage Docker build (golang:1.22-bookworm + falcosecurity/falco-no-driver:0.39.2)
- CI pipeline with tests, vet, lint, build, and binary verification
- Release workflow with manual trigger and SHA256 checksums
- Debug mode via `FALCO_OPENCLAW_DEBUG=true` environment variable
- Test coverage at 95.9% for parser package
- 3 Falco configuration variants (production, local macOS, Docker)
