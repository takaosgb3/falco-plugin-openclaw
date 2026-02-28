# E2E Tests / E2Eテスト

[English](#english) | [日本語](#japanese)

---

<a id="english"></a>

## Overview

End-to-end test suite for the OpenClaw Falco plugin. Tests are organized in three levels:

| Level | Description | Falco Required | Command |
|-------|-------------|----------------|---------|
| Level 1 | Pattern coverage tests (Go) | No | `make e2e-pattern` |
| Level 2 | Plugin pipeline tests (Go) | No | `make e2e-pipeline` |
| Level 3 | Falco integration tests | Yes | `make e2e-ci` or `make e2e-native` |

## Prerequisites

- **Go 1.22+** — for Level 1 & 2 tests
- **Python 3.8+** — for Level 3 analysis scripts
- **jq** — for pattern injection
- **Falco 0.43.0** — for Level 3 only (Linux: apt install, macOS: build from source)
- **Allure CLI** — for report generation (`brew install allure` on macOS)

## Quick Start

```bash
# Run Level 1 + Level 2 (no Falco needed)
make e2e

# Run all levels + Allure report (requires Falco)
make e2e-all
```

## Test Levels

### Level 1: Pattern Tests

Tests pattern detection logic directly via the parser, covering all 7 threat categories plus edge cases.

```bash
make e2e-pattern
# or: go test ./test/e2e/ -v -race -run TestPattern
```

### Level 2: Pipeline Tests

Tests the full plugin pipeline (Init → Open → Write → NextBatch → Extract) without Falco.

```bash
make e2e-pipeline
# or: go test ./cmd/plugin-sdk/ -v -race -run TestPipeline
```

### Level 3: Falco Integration

Injects test patterns into a log file, runs Falco with the plugin, and analyzes alert output.

**Linux CI:**
```bash
make e2e-ci
```

**macOS Native** (requires Falco built from source):
```bash
make e2e-native
```

**Dry run** (no Falco, shows what would be injected):
```bash
bash e2e/scripts/inject_patterns.sh --dry-run -v
```

## Allure Report

Generate and view the visual test report:

```bash
# Install Python dependencies
pip install -r e2e/allure/requirements.txt

# Generate report data (after Level 3 completes)
make e2e-report

# Open report in browser
make e2e-serve
```

## Directory Structure

```
e2e/
├── scripts/
│   ├── inject_patterns.sh    # Pattern injection + Falco execution
│   └── batch_analyzer.py     # Result analysis
├── allure/
│   ├── conftest.py            # pytest configuration
│   ├── test_e2e_wrapper.py    # Allure report wrapper
│   └── requirements.txt       # Python dependencies
├── results/                   # Generated (gitignored)
│   ├── falco-output.log
│   ├── test-ids.json
│   ├── test-results.json
│   ├── summary.json
│   └── falco-ci.yaml
└── README.md
test/e2e/
├── e2e_pattern_test.go        # Level 1 Go tests
└── patterns/categories/       # Test pattern data (JSON)
cmd/plugin-sdk/
└── plugin_test.go             # Level 2 Go tests
```

## Troubleshooting

- **Falco shows no alerts**: Make sure to use `-U` flag (unbuffered output)
- **macOS build errors**: CGO_ENABLED=1 is required; cross-compile from macOS to Linux is not supported
- **fsnotify timing**: Level 2 tests use `time.Sleep` between write and read to account for fsnotify event propagation
- **Falco startup timeout**: Increase with `-t` flag: `inject_patterns.sh -t 60 ...`

---

<a id="japanese"></a>

## 概要

OpenClaw Falcoプラグインのエンドツーエンドテストスイートです。テストは3つのレベルで構成されています：

| レベル | 説明 | Falco必要 | コマンド |
|--------|------|-----------|---------|
| レベル1 | パターンカバレッジテスト (Go) | 不要 | `make e2e-pattern` |
| レベル2 | プラグインパイプラインテスト (Go) | 不要 | `make e2e-pipeline` |
| レベル3 | Falco統合テスト | 必要 | `make e2e-ci` or `make e2e-native` |

## 前提条件

- **Go 1.22+** — レベル1・2テスト用
- **Python 3.8+** — レベル3分析スクリプト用
- **jq** — パターン注入用
- **Falco 0.43.0** — レベル3のみ（Linux: apt install、macOS: ソースからビルド）
- **Allure CLI** — レポート生成用（macOS: `brew install allure`）

## クイックスタート

```bash
# レベル1 + レベル2を実行（Falco不要）
make e2e

# 全レベル + Allureレポート（Falco必要）
make e2e-all
```

## テストレベル

### レベル1: パターンテスト

パーサーを直接テストし、7つの脅威カテゴリとエッジケースをカバーします。

```bash
make e2e-pattern
```

### レベル2: パイプラインテスト

Falcoなしでプラグインの全パイプライン（Init → Open → Write → NextBatch → Extract）をテストします。

```bash
make e2e-pipeline
```

### レベル3: Falco統合テスト

テストパターンをログファイルに注入し、プラグインと共にFalcoを実行し、アラート出力を分析します。

**macOSネイティブ**（ソースからビルドしたFalcoが必要）:
```bash
make e2e-native
```

## Allureレポート

```bash
# Python依存インストール
pip install -r e2e/allure/requirements.txt

# レポートデータ生成（レベル3完了後）
make e2e-report

# ブラウザでレポート表示
make e2e-serve
```

## トラブルシューティング

- **Falcoのアラートが表示されない**: `-U` フラグ（バッファなし出力）を使用してください
- **macOSビルドエラー**: CGO_ENABLED=1が必要です
- **Falco起動タイムアウト**: `-t` フラグで増加: `inject_patterns.sh -t 60 ...`
