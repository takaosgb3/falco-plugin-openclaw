# Falco OpenClaw Plugin

[![CI](https://github.com/takaosgb3/falco-plugin-openclaw/actions/workflows/ci.yml/badge.svg)](https://github.com/takaosgb3/falco-plugin-openclaw/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22-00ADD8.svg)](https://go.dev/)

A Falco plugin for monitoring OpenClaw AI assistant logs and detecting security threats in real-time.

[日本語版 README はこちら](README_ja.md)

## Features

- Real-time monitoring of multiple log files (JSONL + plaintext)
- Auto-detection of JSON and plaintext log formats
- 7 security threat detection categories
- String-matching based detection (no regex, ReDoS-safe)
- Debug mode via environment variable

## Security Rules

| Rule | Description | Priority |
|------|-------------|----------|
| Dangerous Command | Detects dangerous shell commands (rm -rf, chmod 777, fork bombs) | CRITICAL |
| Data Exfiltration | Detects sensitive data exfiltration via network tools | CRITICAL |
| Agent Runaway | Detects infinite loops and excessive retries | WARNING |
| Workspace Escape | Detects access to files outside the workspace | WARNING |
| Suspicious Config | Detects suspicious configuration changes | WARNING |
| Shell Injection | Detects shell metacharacters in non-shell tools | WARNING |
| Unauthorized Model | Detects unauthorized AI model changes | NOTICE |

## Quick Start

### Requirements

- Falco 0.36.0+
- Linux
- Go 1.22+ (for building from source only)

### Installation

```bash
# Download plugin binary
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/libopenclaw-plugin-linux-amd64.so

# Copy to Falco plugins directory
sudo cp libopenclaw-plugin-linux-amd64.so /usr/share/falco/plugins/libopenclaw-plugin.so

# Download and copy rules
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/openclaw_rules.yaml
sudo cp openclaw_rules.yaml /etc/falco/rules.d/
```

### Configuration

Add to your `falco.yaml`:

```yaml
plugins:
  - name: openclaw
    library_path: /usr/share/falco/plugins/libopenclaw-plugin.so
    init_config: |
      {
        "log_paths": [
          "~/.openclaw/logs/agent.jsonl",
          "~/.openclaw/logs/tools.jsonl",
          "~/.openclaw/logs/system.log"
        ]
      }

load_plugins: [openclaw]

rules_files:
  - /etc/falco/rules.d/openclaw_rules.yaml

stdout_output:
  enabled: true

outputs:
  rate: 0
  max_burst: 0
```

> **Important**: `load_plugins: [openclaw]` is required. Without it, the plugin is silently ignored.

### Running

```bash
sudo falco -c /etc/falco/falco.yaml --disable-source syscall
```

## Plugin Fields

| Field | Type | Description |
|-------|------|-------------|
| `openclaw.type` | string | Event type (tool_call, message, config_change, system) |
| `openclaw.tool` | string | Tool name (bash, read, write, etc.) |
| `openclaw.args` | string | Tool arguments |
| `openclaw.session_id` | string | Session identifier |
| `openclaw.timestamp` | string | Event timestamp (RFC3339) |
| `openclaw.source_file` | string | Source log file name |
| `openclaw.user_message` | string | User message content |
| `openclaw.model` | string | AI model name |
| `openclaw.config_path` | string | Configuration file path |
| `openclaw.suspicious` | string | Security threat type detected |
| `openclaw.log_path` | string | Log file path |
| `openclaw.raw` | string | Raw log line |
| `openclaw.headers[key]` | string | Extra metadata by key |

## Building from Source

```bash
git clone https://github.com/takaosgb3/falco-plugin-openclaw.git
cd falco-plugin-openclaw

make build          # Development build
make build-release  # Optimized release build
make test           # Run tests
make verify         # Verify binary
```

See [BUILD.md](BUILD.md) for detailed instructions.

## E2E Testing

The plugin includes a comprehensive E2E test suite with three levels:

| Level | Description | Falco Required | Command |
|-------|-------------|----------------|---------|
| Level 1 | Pattern coverage tests (Go) | No | `make e2e-pattern` |
| Level 2 | Plugin pipeline tests (Go) | No | `make e2e-pipeline` |
| Level 3 | Falco integration tests | Yes | `make e2e-native` |

```bash
# Run Level 1 + Level 2 (no Falco needed)
make e2e

# Run all levels + Allure report (requires Falco)
make e2e-all
```

56 test patterns cover 11 categories including edge cases, composite threats, and benign patterns. See [e2e/README.md](e2e/README.md) for full details.

## Docker

```bash
docker build -t falco-openclaw .
docker run --rm -v ~/.openclaw/logs:/openclaw-logs/logs:ro falco-openclaw
```

## Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Guide](docs/configuration.md)
- [Build Instructions](BUILD.md)
- [E2E Test Guide](e2e/README.md)
- [Changelog](CHANGELOG.md)

## Debug Mode

```bash
export FALCO_OPENCLAW_DEBUG=true
```

## License

[Apache-2.0](LICENSE)
