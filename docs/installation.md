# Installation Guide

## Binary Installation

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

## Build from Source

See [BUILD.md](../BUILD.md) for instructions.

## Docker Installation

```bash
# Build the Docker image
docker build -t falco-openclaw .

# Run with mounted log directory
docker run --rm \
  -v ~/.openclaw/logs:/openclaw-logs/logs:ro \
  falco-openclaw
```

## Requirements

- **Falco 0.36.0+**
- **Linux** (for running the plugin)
- **Go 1.22+** (for building from source only)

---

# インストールガイド（日本語）

## バイナリインストール

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

`/etc/falco/falco.yaml` に上記の設定を追加してください。
`load_plugins: [openclaw]` は必須です（これがないとプラグインは無視されます）。

### 4. 実行

```bash
sudo falco -c /etc/falco/falco.yaml --disable-source syscall
```

## Docker インストール

```bash
docker build -t falco-openclaw .
docker run --rm -v ~/.openclaw/logs:/openclaw-logs/logs:ro falco-openclaw
```
