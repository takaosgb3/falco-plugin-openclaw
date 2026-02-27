# Falco OpenClaw Plugin

[![CI](https://github.com/takaosgb3/falco-plugin-openclaw/actions/workflows/ci.yml/badge.svg)](https://github.com/takaosgb3/falco-plugin-openclaw/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22-00ADD8.svg)](https://go.dev/)

A Falco plugin for monitoring OpenClaw AI assistant logs and detecting security threats in real-time.

OpenClaw AI アシスタントのログをリアルタイム監視し、セキュリティ脅威を検出する Falco プラグインです。

## Features / 機能

- Real-time monitoring of multiple log files (JSONL + plaintext) / 複数ログファイルのリアルタイム監視
- Auto-detection of JSON and plaintext log formats / JSON・プレーンテキスト形式の自動検出
- 7 security threat detection categories / 7種類のセキュリティ脅威検出
- String-matching based detection (no regex, ReDoS-safe) / 文字列マッチングベースの検出（正規表現不使用、ReDoS安全）
- Debug mode via environment variable / 環境変数によるデバッグモード

## Security Rules / セキュリティルール

| Rule | Description / 説明 | Priority |
|------|---------------------|----------|
| Dangerous Command | Detects dangerous shell commands (rm -rf, chmod 777, fork bombs) / 危険なシェルコマンドの検出 | CRITICAL |
| Data Exfiltration | Detects sensitive data exfiltration via network tools / ネットワークツールによる機密データ流出の検出 | CRITICAL |
| Agent Runaway | Detects infinite loops and excessive retries / 無限ループ・過剰リトライの検出 | WARNING |
| Workspace Escape | Detects access to files outside the workspace / ワークスペース外ファイルアクセスの検出 | WARNING |
| Suspicious Config | Detects suspicious configuration changes / 不審な設定変更の検出 | WARNING |
| Unauthorized Model | Detects unauthorized AI model changes / 不正な AI モデル変更の検出 | NOTICE |
| Shell Injection | Detects shell metacharacters in non-shell tools / 非シェルツールでのシェルインジェクションの検出 | WARNING |

## Quick Start / クイックスタート

### Requirements / 要件

- Falco 0.36.0+
- Linux (for running the plugin / プラグイン実行用)
- Go 1.22+ (for building from source / ソースからビルドする場合のみ)

### Installation / インストール

```bash
# Download plugin binary / プラグインバイナリをダウンロード
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/libopenclaw-plugin-linux-amd64.so

# Copy to Falco plugins directory / Falco プラグインディレクトリにコピー
sudo cp libopenclaw-plugin-linux-amd64.so /usr/share/falco/plugins/libopenclaw-plugin.so

# Copy rules / ルールをコピー
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/openclaw_rules.yaml
sudo cp openclaw_rules.yaml /etc/falco/rules.d/
```

### Configuration / 設定

Add to your `falco.yaml` / `falco.yaml` に追加:

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

> **Important / 重要**: `load_plugins: [openclaw]` is required. Without it, the plugin is silently ignored. / `load_plugins: [openclaw]` は必須です。これがないとプラグインは無視されます。

### Running / 実行

```bash
sudo falco -c /etc/falco/falco.yaml --disable-source syscall
```

## Plugin Fields / プラグインフィールド

| Field | Type | Description / 説明 |
|-------|------|---------------------|
| `openclaw.type` | string | Event type (tool_call, message, config_change, system) / イベントタイプ |
| `openclaw.tool` | string | Tool name (bash, read, write, etc.) / ツール名 |
| `openclaw.args` | string | Tool arguments / ツール引数 |
| `openclaw.session_id` | string | Session identifier / セッションID |
| `openclaw.timestamp` | string | Event timestamp (RFC3339) / タイムスタンプ |
| `openclaw.source_file` | string | Source log file name / ソースログファイル名 |
| `openclaw.user_message` | string | User message content / ユーザメッセージ |
| `openclaw.model` | string | AI model name / AI モデル名 |
| `openclaw.config_path` | string | Configuration file path / 設定ファイルパス |
| `openclaw.suspicious` | string | Security threat type detected / 検出されたセキュリティ脅威タイプ |
| `openclaw.log_path` | string | Log file path / ログファイルパス |
| `openclaw.raw` | string | Raw log line / 生ログ行 |
| `openclaw.headers[key]` | string | Extra metadata by key / キーによる追加メタデータ |

## Building from Source / ソースからのビルド

```bash
git clone https://github.com/takaosgb3/falco-plugin-openclaw.git
cd falco-plugin-openclaw

make build          # Development build / 開発ビルド
make build-release  # Optimized release build / リリースビルド
make test           # Run tests / テスト実行
make verify         # Verify binary / バイナリ検証
```

See [BUILD.md](BUILD.md) for detailed instructions. / 詳細は [BUILD.md](BUILD.md) を参照してください。

## Docker

```bash
docker build -t falco-openclaw .
docker run --rm -v ~/.openclaw/logs:/openclaw-logs/logs:ro falco-openclaw
```

## Documentation / ドキュメント

- [Installation Guide / インストールガイド](docs/installation.md)
- [Configuration Guide / 設定ガイド](docs/configuration.md)
- [Build Instructions / ビルド手順](BUILD.md)
- [Changelog / 変更履歴](CHANGELOG.md)

## Debug Mode / デバッグモード

```bash
export FALCO_OPENCLAW_DEBUG=true
```

## License / ライセンス

[Apache-2.0](LICENSE)
