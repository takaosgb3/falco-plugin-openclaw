# Configuration Guide

## Plugin Configuration (`init_config`)

The plugin is configured via the `init_config` field in Falco's `falco.yaml`.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log_paths` | `[]string` | `["~/.openclaw/logs/agent.jsonl", "~/.openclaw/logs/tools.jsonl", "~/.openclaw/logs/system.log"]` | Log file paths to monitor |
| `event_buffer_size` | `int` | `1000` | Event channel buffer size (1-100000) |

### Example Configuration

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
        ],
        "event_buffer_size": 1000
      }
```

### Log Path Configuration

- Paths support `~` expansion (expanded to user home directory)
- Parent directories are created automatically if they don't exist
- Files are created if they don't exist
- The plugin seeks to the end of each file on startup (only new entries are processed)

### Buffer Size Tuning

The `event_buffer_size` controls how many events can be queued before dropping:

- **Default (1000)**: Suitable for most deployments
- **Higher values**: Use for high-throughput environments to prevent event drops
- **Range**: 1–100000 (values outside this range default to 1000)

When the buffer is full, new events are dropped and a warning is logged every 100 drops.

## Falco Output Configuration

To prevent alert suppression, disable rate limiting:

```yaml
outputs:
  rate: 0        # No rate limiting
  max_burst: 0   # No burst limiting
```

## Debug Mode

Enable debug logging with an environment variable:

```bash
export FALCO_OPENCLAW_DEBUG=true
```

Debug logs are prefixed with `[openclaw-debug]` and include:
- Plugin initialization details
- File watch events
- Parse errors
- GOB encoding errors
- Dropped event counts

## macOS-Specific Notes

On macOS (Falco 0.43.0), the following differences apply:

- **Do NOT include `outputs:` section** (`rate`/`max_burst`). It causes a schema validation error in Falco 0.43.0.
- **Use `json_output: true`** for structured output.
- **Required flags**: `--disable-source syscall -U` (see [Installation Guide](installation.md#4-run-falco-1)).

Example macOS config (`falco-local.yaml`):

```yaml
plugins:
  - name: openclaw
    library_path: ./libopenclaw-plugin-darwin-arm64.dylib
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
  - ./rules/openclaw_rules.yaml

stdout_output:
  enabled: true

json_output: true
```

## Configuration Variants

This repository includes 3 configuration files:

| File | Use Case |
|------|----------|
| `falco.yaml` | Production Linux deployment |
| `falco-local.yaml` | Local macOS development (uses `.dylib`) |
| `falco-docker.yaml` | Docker container (mounted `/openclaw-logs/`) |

---

# 設定ガイド（日本語）

## プラグイン設定 (`init_config`)

| オプション | 型 | デフォルト | 説明 |
|-----------|------|---------|------|
| `log_paths` | `[]string` | 上記参照 | 監視するログファイルパス |
| `event_buffer_size` | `int` | `1000` | イベントチャネルのバッファサイズ (1-100000) |

### ログパス設定
- `~` はホームディレクトリに展開されます
- 親ディレクトリは自動的に作成されます
- 起動時にファイル末尾にシークします（新しいエントリのみ処理）

### バッファサイズの調整
- デフォルト (1000) は大部分の環境に適しています
- 高スループット環境ではより大きな値を使用してください
- バッファが満杯の場合、イベントはドロップされます

## デバッグモード

```bash
export FALCO_OPENCLAW_DEBUG=true
```

デバッグログは `[openclaw-debug]` プレフィックスで出力されます。

## macOS 固有の注意事項

macOS（Falco 0.43.0）では以下の違いがあります:

- **`outputs:` セクションは含めない**: `rate`/`max_burst` は Falco 0.43.0 でスキーマ検証エラーになります
- **`json_output: true`** を使用してください
- **必須フラグ**: `--disable-source syscall -U`（詳細は[インストールガイド](installation.md)を参照）
