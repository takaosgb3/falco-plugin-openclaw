# Falco OpenClaw Plugin

[![CI](https://github.com/takaosgb3/falco-plugin-openclaw/actions/workflows/ci.yml/badge.svg)](https://github.com/takaosgb3/falco-plugin-openclaw/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22-00ADD8.svg)](https://go.dev/)

OpenClaw AI アシスタントのログをリアルタイム監視し、セキュリティ脅威を検出する Falco プラグインです。

[English README](README.md)

## 機能

- 複数ログファイル（JSONL + プレーンテキスト）のリアルタイム監視
- JSON・プレーンテキスト形式の自動検出
- 7種類のセキュリティ脅威検出
- 文字列マッチングベースの検出（正規表現不使用、ReDoS安全）
- 環境変数によるデバッグモード

## セキュリティルール

| ルール | 説明 | 優先度 |
|--------|------|--------|
| Dangerous Command | 危険なシェルコマンドの検出（rm -rf, chmod 777, fork bomb 等） | CRITICAL |
| Data Exfiltration | ネットワークツールによる機密データ流出の検出 | CRITICAL |
| Agent Runaway | 無限ループ・過剰リトライの検出 | WARNING |
| Workspace Escape | ワークスペース外ファイルアクセスの検出 | WARNING |
| Suspicious Config | 不審な設定変更の検出 | WARNING |
| Shell Injection | 非シェルツールでのシェルインジェクションの検出 | WARNING |
| Unauthorized Model | 不正な AI モデル変更の検出 | NOTICE |

## クイックスタート

### 要件

- Falco 0.36.0+
- Linux (amd64) または macOS (ARM64)
- Go 1.22+（ソースからビルドする場合のみ）

### インストール

**Linux (amd64)**

```bash
# プラグインバイナリをダウンロード
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/libopenclaw-plugin-linux-amd64.so

# Falco プラグインディレクトリにコピー
sudo cp libopenclaw-plugin-linux-amd64.so /usr/share/falco/plugins/libopenclaw-plugin.so

# ルールをダウンロードしてコピー
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/openclaw_rules.yaml
sudo cp openclaw_rules.yaml /etc/falco/rules.d/
```

**macOS (ARM64)**

```bash
# プラグインバイナリをダウンロード
curl -LO https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/libopenclaw-plugin-darwin-arm64.dylib

# ルールをダウンロード
curl -LO https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/openclaw_rules.yaml
```

> **注意**: macOS では Falco 0.43.0 を `MINIMAL_BUILD=ON` でソースビルドする必要があります。詳細は [BUILD.md](BUILD.md) を参照してください。

### 設定

`falco.yaml` に追加:

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

> **重要**: `load_plugins: [openclaw]` は必須です。これがないとプラグインは無視されます。

### 実行

```bash
sudo falco -c /etc/falco/falco.yaml --disable-source syscall
```

## プラグインフィールド

| フィールド | タイプ | 説明 |
|------------|--------|------|
| `openclaw.type` | string | イベントタイプ（tool_call, message, config_change, system） |
| `openclaw.tool` | string | ツール名（bash, read, write 等） |
| `openclaw.args` | string | ツール引数 |
| `openclaw.session_id` | string | セッションID |
| `openclaw.timestamp` | string | タイムスタンプ（RFC3339） |
| `openclaw.source_file` | string | ソースログファイル名 |
| `openclaw.user_message` | string | ユーザメッセージ |
| `openclaw.model` | string | AI モデル名 |
| `openclaw.config_path` | string | 設定ファイルパス |
| `openclaw.suspicious` | string | 検出されたセキュリティ脅威タイプ |
| `openclaw.log_path` | string | ログファイルパス |
| `openclaw.raw` | string | 生ログ行 |
| `openclaw.headers[key]` | string | キーによる追加メタデータ |

## ソースからのビルド

```bash
git clone https://github.com/takaosgb3/falco-plugin-openclaw.git
cd falco-plugin-openclaw

make build          # 開発ビルド
make build-release  # リリースビルド
make test           # テスト実行
make verify         # バイナリ検証
```

詳細は [BUILD.md](BUILD.md) を参照してください。

## E2E テスト

プラグインには3つのレベルで構成される包括的なE2Eテストスイートが含まれています：

| レベル | 説明 | Falco必要 | コマンド |
|--------|------|-----------|---------|
| レベル1 | パターンカバレッジテスト (Go) | 不要 | `make e2e-pattern` |
| レベル2 | プラグインパイプラインテスト (Go) | 不要 | `make e2e-pipeline` |
| レベル3 | Falco統合テスト | 必要 | `make e2e-native` |

```bash
# レベル1 + レベル2を実行（Falco不要）
make e2e

# 全レベル + Allureレポート（Falco必要）
make e2e-all

# ローカルのテスト結果を GitHub Pages にデプロイ
make e2e-deploy-local
```

56のテストパターンが11カテゴリ（エッジケース、複合脅威、良性パターンを含む）をカバーします。テスト結果は [GitHub Pages の Allure レポート](https://takaosgb3.github.io/falco-plugin-openclaw/) で確認できます。詳細は [e2e/README.md](e2e/README.md) を参照してください。

## Docker

```bash
docker build -t falco-openclaw .
docker run --rm -v ~/.openclaw/logs:/openclaw-logs/logs:ro falco-openclaw
```

## ドキュメント

- [インストールガイド](docs/installation.md)
- [設定ガイド](docs/configuration.md)
- [ビルド手順](BUILD.md)
- [E2Eテストガイド](e2e/README.md)
- [変更履歴](CHANGELOG.md)

## デバッグモード

```bash
export FALCO_OPENCLAW_DEBUG=true
```

## ライセンス

[Apache-2.0](LICENSE)
