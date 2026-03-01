# Building from Source

## Prerequisites

- **Go 1.22+** ([https://go.dev/dl/](https://go.dev/dl/))
- **CGO enabled** (required for `-buildmode=c-shared`)
- **GCC** or compatible C compiler
- **Linux** (for production `.so` builds) or **macOS** (for local `.dylib` development)
- **golangci-lint** (optional, for linting): `go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.59.1`

## Build Commands

```bash
# Development build (includes debug symbols)
make build

# Optimized release build (stripped, smaller binary)
make build-release

# Run tests
make test

# Run tests with coverage report
make test-coverage

# Run linter
make lint

# Run static analysis
make vet

# Build + verify binary format
make verify

# Release package (build-release + verify + checksums)
make package

# Clean build artifacts
make clean

# E2E tests (Level 1 + Level 2, no Falco needed)
make e2e

# E2E Level 3 integration test (requires Falco)
make e2e-native     # macOS
make e2e-ci         # Linux CI

# All E2E levels + Allure report
make e2e-all

# Deploy local test results to GitHub Pages
make e2e-deploy-local
```

## Cross-Compilation Note

The plugin must be built as a **C shared library** (`-buildmode=c-shared`), which requires CGO. This means:

- **Linux → Linux**: Works directly
- **macOS → macOS**: Produces `.dylib` (also available as a release artifact via CI)
- **macOS → Linux**: **Not possible** with CGO. Use Docker or a Linux machine.

## Docker Build

Build a Linux binary from any platform using Docker:

```bash
docker build -t falco-openclaw .
```

The multi-stage Dockerfile:
1. Builds the plugin as a Linux `.so` in `golang:1.22-bookworm`
2. Packages it with `falcosecurity/falco-no-driver:0.39.2`

## Binary Verification

After building, verify the binary is a valid ELF shared object:

```bash
make verify
# Expected output: "OK: Valid ELF shared object"
```

On macOS, `make build` produces a `.dylib` (Mach-O), which is expected for local development but **cannot be used with Falco on Linux**.

---

# ビルド手順（日本語）

## 前提条件

- **Go 1.22+** ([https://go.dev/dl/](https://go.dev/dl/))
- **CGO 有効**（`-buildmode=c-shared` に必要）
- **GCC** または互換 C コンパイラ
- **Linux**（本番用 `.so` ビルド）または **macOS**（ローカル開発用 `.dylib`）

## ビルドコマンド

```bash
make build          # 開発ビルド（デバッグ情報あり）
make build-release  # リリースビルド（最適化・ストリップ済み）
make test           # テスト実行
make test-coverage  # カバレッジ付きテスト
make lint           # リンター実行
make verify         # バイナリ形式の検証
make package        # リリースパッケージ作成
make e2e            # E2Eテスト（レベル1+2、Falco不要）
make e2e-native     # E2Eレベル3統合テスト（macOS、Falco必要）
make e2e-ci         # E2Eレベル3統合テスト（Linux CI）
make e2e-all        # 全E2Eレベル + Allureレポート
make e2e-deploy-local # ローカルのテスト結果をGitHub Pagesにデプロイ
```

## クロスコンパイルの注意

プラグインは C 共有ライブラリとしてビルドする必要があり、CGO が必要です。macOS から Linux バイナリを直接クロスコンパイルすることはできません。Docker またはLinux マシンを使用してください。
