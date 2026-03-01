# Installation Guide

## Requirements

- **Falco 0.36.0+** (Linux) or **Falco 0.43.0** (macOS, built from source)
- **Linux (amd64)** or **macOS (ARM64)**
- **Go 1.22+** (for building from source only)

## Linux Installation

### 1. Download

Download the latest release from [GitHub Releases](https://github.com/takaosgb3/falco-plugin-openclaw/releases):

```bash
# Download plugin binary
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/libopenclaw-plugin-linux-amd64.so

# Download rules
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/openclaw_rules.yaml

# Verify checksums
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/checksums.sha256
sha256sum -c checksums.sha256
```

### 2. Install Files

```bash
# Copy plugin to Falco plugins directory
sudo cp libopenclaw-plugin-linux-amd64.so /usr/share/falco/plugins/libopenclaw-plugin.so

# Copy rules
sudo cp openclaw_rules.yaml /etc/falco/rules.d/
```

### 3. Configure Falco

Add the following to `/etc/falco/falco.yaml`:

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

### 4. Run Falco

```bash
sudo falco -c /etc/falco/falco.yaml --disable-source syscall
```

## macOS Installation (ARM64)

macOS does not have an official Falco package. You need to build Falco from source with `MINIMAL_BUILD=ON` (no syscall driver). The plugin binary is available as a pre-built release artifact.

### 1. Build Falco from Source

```bash
# Prerequisites
brew install cmake

# Clone and build Falco 0.43.0
git clone --branch 0.43.0 --depth 1 https://github.com/falcosecurity/falco.git /tmp/falco-build
cd /tmp/falco-build
mkdir build && cd build
cmake -DMINIMAL_BUILD=ON -DUSE_BUNDLED_DEPS=ON -DCMAKE_BUILD_TYPE=Release ..
make -j$(sysctl -n hw.ncpu)

# Verify
./userspace/falco/falco --version
```

### 2. Download Plugin and Rules

```bash
curl -LO https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/libopenclaw-plugin-darwin-arm64.dylib
curl -LO https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/openclaw_rules.yaml
```

### 3. Configure Falco

Create `falco-local.yaml`:

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
  - ./openclaw_rules.yaml

stdout_output:
  enabled: true

json_output: true
```

> **Note**: Do NOT include `outputs:` section (`rate`/`max_burst`). Falco 0.43.0 rejects this with a schema validation error.

### 4. Run Falco

Both flags are **required** on macOS:

```bash
/tmp/falco-build/build/userspace/falco/falco \
  -c falco-local.yaml \
  --disable-source syscall \
  -U
```

| Flag | Purpose |
|------|---------|
| `--disable-source syscall` | macOS has no syscall driver (no eBPF) |
| `-U` | Unbuffered stdout. Without this, alerts are not displayed |

### macOS Troubleshooting

- **No alerts shown**: Ensure you are using the `-U` flag
- **Schema validation error on `outputs:`**: Remove the `outputs:` section from your config
- **Build errors**: Ensure `cmake`, Xcode command line tools, and a C++ compiler are available

## Docker Installation

```bash
# Build the Docker image
docker build -t falco-openclaw .

# Run with mounted log directory
docker run --rm \
  -v ~/.openclaw/logs:/openclaw-logs/logs:ro \
  falco-openclaw
```

## Build from Source

See [BUILD.md](../BUILD.md) for instructions.

---

# インストールガイド（日本語）

## 要件

- **Falco 0.36.0+**（Linux）または **Falco 0.43.0**（macOS、ソースビルド）
- **Linux (amd64)** または **macOS (ARM64)**
- **Go 1.22+**（ソースからビルドする場合のみ）

## Linux インストール

### 1. ダウンロード

[GitHub Releases](https://github.com/takaosgb3/falco-plugin-openclaw/releases) から最新版をダウンロード:

```bash
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/libopenclaw-plugin-linux-amd64.so
wget https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/openclaw_rules.yaml
```

### 2. ファイル配置

```bash
sudo cp libopenclaw-plugin-linux-amd64.so /usr/share/falco/plugins/libopenclaw-plugin.so
sudo cp openclaw_rules.yaml /etc/falco/rules.d/
```

### 3. Falco 設定

`/etc/falco/falco.yaml` に設定を追加してください（上記 Linux セクション参照）。
`load_plugins: [openclaw]` は必須です（これがないとプラグインは無視されます）。

### 4. 実行

```bash
sudo falco -c /etc/falco/falco.yaml --disable-source syscall
```

## macOS インストール (ARM64)

macOS には公式の Falco パッケージがないため、`MINIMAL_BUILD=ON` でソースからビルドする必要があります。プラグインバイナリはリリースからダウンロードできます。

### 1. Falco をソースからビルド

```bash
# 前提: cmake がインストール済み
brew install cmake

# Falco 0.43.0 をビルド
git clone --branch 0.43.0 --depth 1 https://github.com/falcosecurity/falco.git /tmp/falco-build
cd /tmp/falco-build
mkdir build && cd build
cmake -DMINIMAL_BUILD=ON -DUSE_BUNDLED_DEPS=ON -DCMAKE_BUILD_TYPE=Release ..
make -j$(sysctl -n hw.ncpu)
```

### 2. プラグインとルールをダウンロード

```bash
curl -LO https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/libopenclaw-plugin-darwin-arm64.dylib
curl -LO https://github.com/takaosgb3/falco-plugin-openclaw/releases/latest/download/openclaw_rules.yaml
```

### 3. Falco 設定

`falco-local.yaml` を作成してください（上記 macOS セクション参照）。

> **注意**: `outputs:` セクション（`rate`/`max_burst`）は含めないでください。Falco 0.43.0 ではスキーマ検証エラーになります。

### 4. 実行

macOS では以下の2つのフラグが**必須**です:

```bash
/tmp/falco-build/build/userspace/falco/falco \
  -c falco-local.yaml \
  --disable-source syscall \
  -U
```

| フラグ | 目的 |
|--------|------|
| `--disable-source syscall` | macOS には syscall ドライバがないため無効化が必要 |
| `-U` | stdout 出力のバッファリングを無効化。なしではアラートが表示されない |

### macOS トラブルシューティング

- **アラートが表示されない**: `-U` フラグを使用しているか確認してください
- **`outputs:` のスキーマ検証エラー**: 設定ファイルから `outputs:` セクションを削除してください
- **ビルドエラー**: `cmake`、Xcode コマンドラインツール、C++ コンパイラが必要です

## Docker インストール

```bash
docker build -t falco-openclaw .
docker run --rm -v ~/.openclaw/logs:/openclaw-logs/logs:ro falco-openclaw
```
