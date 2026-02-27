# Falco OpenClaw Plugin

A Falco plugin for monitoring OpenClaw AI assistant logs and detecting security threats in real-time.

## Features

- Real-time monitoring of 3 log files simultaneously (JSONL + plaintext)
- Security threat detection:
  - Dangerous Command Execution
  - Data Exfiltration Attempts
  - Agent Runaway Behavior
  - Workspace Escape Attempts
  - Suspicious Configuration Changes
  - Unauthorized Model Changes
  - Shell Injection in Non-Shell Tools
- JSON and plaintext log format support
- URL decoding support (up to 3 levels)
- Customizable Falco rules

## Requirements

- Falco 0.36.0+
- Go 1.22+ (for building from source)
- Linux (for running the plugin)

## Quick Start

### Installation

```bash
# Download the plugin binary
wget https://github.com/takaos/falco-openclaw-plugin/releases/latest/download/libopenclaw-plugin-linux-amd64.so

# Copy to Falco plugins directory
sudo cp libopenclaw-plugin-linux-amd64.so /usr/share/falco/plugins/libopenclaw-plugin.so

# Copy rules
sudo cp rules/openclaw_rules.yaml /etc/falco/rules.d/
```

### Configuration

Add to your `falco.yaml`:

```yaml
plugins:
  - name: openclaw
    library_path: /usr/share/falco/plugins/libopenclaw-plugin.so
    init_config: |
      {"log_paths": ["~/.openclaw/logs/agent.jsonl", "~/.openclaw/logs/tools.jsonl", "~/.openclaw/logs/system.log"]}

load_plugins: [openclaw]

rules_files:
  - /etc/falco/rules.d/openclaw_rules.yaml

stdout_output:
  enabled: true
  rate: 0
  max_burst: 0
```

### Running

```bash
# Run Falco with the plugin (plugin-only mode)
sudo falco -c /etc/falco/falco.yaml --disable-source syscall
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/takaos/falco-openclaw-plugin.git
cd falco-openclaw-plugin

# Build (Linux only)
make build

# Run tests
make test

# Verify the binary
make verify
```

## Security Rules

| Rule | Description | Priority |
|------|-------------|----------|
| Dangerous Command | Detects dangerous shell commands (rm -rf, chmod 777, etc.) | CRITICAL |
| Data Exfiltration | Detects sensitive data being sent via network tools | CRITICAL |
| Agent Runaway | Detects infinite loops and excessive retries | WARNING |
| Workspace Escape | Detects access to files outside the workspace | WARNING |
| Suspicious Config | Detects suspicious configuration changes | WARNING |
| Unauthorized Model | Detects unauthorized AI model changes | NOTICE |
| Shell Injection | Detects shell metacharacters in non-shell tools | WARNING |

## Plugin Fields

| Field | Type | Description |
|-------|------|-------------|
| `openclaw.type` | string | Event type (tool_call, message, config_change, system) |
| `openclaw.tool` | string | Tool name (bash, read, write, etc.) |
| `openclaw.args` | string | Tool arguments |
| `openclaw.session_id` | string | Session identifier |
| `openclaw.timestamp` | string | Event timestamp |
| `openclaw.source_file` | string | Source log file name |
| `openclaw.user_message` | string | User message content |
| `openclaw.model` | string | AI model name |
| `openclaw.config_path` | string | Configuration file path |
| `openclaw.suspicious` | string | Security threat type detected |
| `openclaw.log_path` | string | Log file path |
| `openclaw.raw` | string | Raw log line |
| `openclaw.headers[key]` | string | Extra metadata |

## Debug Mode

Enable debug logging:

```bash
export FALCO_OPENCLAW_DEBUG=true
```

## License

Apache-2.0
