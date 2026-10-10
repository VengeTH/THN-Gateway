# Installation, Build & Environment Setup

This document provides instructions for compiling, installing, configuring filesystem permissions, and verifying **THN Gateway** binaries on an Ubuntu Server host.

---

## 1. Prerequisites & Host Dependencies

### 1.1 Operating System & Kernel
- **Ubuntu Server**: 22.04 LTS or 24.04 LTS (x86_64).
- **Linux Kernel**: 6.8+ recommended (minimum 5.15+ with netfilter support).
- **Kernel Modules Required**: `nf_tables`, `nft_compat`, `nft_nat`, `nft_masq`, `sch_cake` (for shaping).

### 1.2 Required System Packages
Verify and install host utilities:
```bash
sudo apt update
sudo apt install -y build-essential git nftables iproute2 jq curl systemd-resolved
```

### 1.3 Go Toolchain
THN Gateway is developed in Go (minimum version 1.23, target version 1.26 in `go.mod`):
```bash
# Check current Go version
go version

# If Go is not installed or older than 1.23, install via official tarball:
curl -fsSL https://go.dev/dl/go1.23.6.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## 2. Compiling the Binaries

The repository provides two primary entry points:
- `cmd/thn`: The unified command-line tool, transaction engine, and preflight validator.
- `cmd/thnd`: The background daemon providing local management APIs and telemetry aggregation.

### 2.1 Build on Target Host (`heedful-dev`)
From the repository root (`~/THN-Gateway`):

```bash
cd ~/THN-Gateway

# Run unit tests before compiling
go test ./...

# Build thn CLI
go build -ldflags="-s -w" -o thn ./cmd/thn

# Build thnd daemon
go build -ldflags="-s -w" -o thnd ./cmd/thnd
```

### 2.2 Cross-Compilation (from Development Laptop)
If developing remotely on Windows or macOS:
```bash
# PowerShell / Linux / macOS cross-compile for Ubuntu x86_64
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o thn-linux-amd64 ./cmd/thn
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o thnd-linux-amd64 ./cmd/thnd

# Transfer to heedful-dev
scp thn-linux-amd64 heedful-dev:~/THN-Gateway/thn
```

---

## 3. Filesystem Hierarchy & Directory Layout

THN Gateway uses standard Linux FHS locations:

| Directory | Purpose | Recommended Permissions | Owner |
|---|---|---|---|
| `/usr/local/bin/` | Binary executable location | `0755` | `root:root` |
| `/etc/thn/` | System configuration (`config.yaml`) | `0755` (dir), `0644` (file) | `root:root` |
| `/var/lib/thn/` | Persistent state (`state.db`, journal) | `0700` (dir), `0600` (file) | `root:root` |
| `/run/thn/` | Runtime IPC sockets (`thn.sock`) | `0750` | `root:root` |

### Create Required Directories:
```bash
sudo mkdir -p /etc/thn
sudo mkdir -p /var/lib/thn
sudo mkdir -p /run/thn
sudo chmod 0755 /etc/thn
sudo chmod 0700 /var/lib/thn
sudo chmod 0750 /run/thn
```

---

## 4. Binary Installation & Backup Strategy

Before replacing an active binary, always archive the existing working copy:

```bash
# 1. Archive previous binary if it exists
if [ -f /usr/local/bin/thn ]; then
    sudo cp /usr/local/bin/thn /usr/local/bin/thn.bak-$(date +%Y%m%d-%H%M%S)
fi

# 2. Install the newly compiled binary
sudo install -m 0755 thn /usr/local/bin/thn

# 3. Verify executable path and permissions
which thn
thn --version 2>&1 || thn activation status
```

---

## 5. Setting up the Initial Configuration

Copy the validated hardware lab configuration into `/etc/thn/config.yaml`:

```bash
# 1. Back up existing configuration if present
if [ -f /etc/thn/config.yaml ]; then
    sudo cp /etc/thn/config.yaml /etc/thn/config.yaml.bak-$(date +%Y%m%d-%H%M%S)
fi

# 2. Copy the physical lab configuration
sudo cp configs/physical_dell_lab.yaml /etc/thn/config.yaml
sudo chmod 0644 /etc/thn/config.yaml

# 3. Test static validation
thn validate /etc/thn/config.yaml
```

Expected output:
```
Result: PASS (0 error, X warning, Y info)
```

---

## 6. Systemd Daemon Service Configuration (`thnd.service`)

If you choose to run the background daemon for local telemetry and management APIs:

### 6.1 Create Service Unit: `/etc/systemd/system/thnd.service`
```ini
[Unit]
Description=THN Gateway Management Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/thnd --config /etc/thn/config.yaml
Restart=on-failure
RestartSec=5s
ProtectSystem=full
ProtectHome=read-only
RuntimeDirectory=thn
StateDirectory=thn
ConfigurationDirectory=thn

[Install]
WantedBy=multi-user.target
```

### 6.2 Enable and Start Daemon:
```bash
sudo systemctl daemon-reload
sudo systemctl enable thnd.service
sudo systemctl start thnd.service
sudo systemctl status thnd.service
```
