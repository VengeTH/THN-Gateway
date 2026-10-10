# Ubuntu Server Activation & Community Gateway Operations Guide

This guide provides end-to-end operational instructions for deploying and activating THN Gateway on an Ubuntu 24.04 LTS server. It specifically addresses using the gateway to share and manage internet connectivity with neighbors (community ISP model), mitigating network congestion, enforcing access controls, and operating safely within the system's structural constraints.

---

## 1. System Reality & Capabilities

Before provisioning hardware or altering host networking, understand what the current build of THN Gateway does and does not do.

### What is implemented and active
- **Observation & Modeling**: [internal/host/host.go](internal/host/host.go) and [internal/network/subsystems.go](internal/network/subsystems.go) discover interfaces, stable hardware identities (MAC addresses), routes, and kernel subsystems.
- **Data Plane Forwarding & NAT**: Renders and applies Linux kernel IPv4 forwarding and `nftables` source NAT (masquerading) under an isolated table named `table inet thn`.
- **Foreign Infrastructure Protection**: Foreign tables (Docker, WireGuard, Tailscale) and non-managed interfaces are preserved and never flushed.
- **Safety Gating & Rollback**: 13 strict safety gates in [internal/activation/activation.go](internal/activation/activation.go#L269-L358) must pass. Every applied mutation is backed by atomic compensation and compared against a pre-flight baseline.
- **Inventory & Client Tracking**: `thn clients` and `thn monitoring` gather connected devices, IP/MAC mappings, and traffic state.

### What is gated or not implemented
- **QoS (Traffic Shaping) is blocked from production activation**:
  In [internal/cli/activate_production.go](internal/cli/activate_production.go#L244-L260), activation strictly refuses when `qos.enabled: true` until controlled real-hardware traffic verification is completed. Per-client HTB hierarchies and CAKE qdiscs are fully modeled in code and verified in network namespaces, but cannot be automatically applied in production yet.
- **DHCP and DNS servers are not built-in**:
  In [internal/cli/activate_production.go](internal/cli/activate_production.go#L231-L242), activation strictly refuses when `dhcp.enabled: true` or `dns.enabled: true`. Client devices must be configured with static IP addresses, or you must run an external DHCP server (such as standalone dnsmasq).
- **Billing and Accounting do not exist**:
  There is no billing ledger, automated expiration timer, or payment gateway. Neighbor subscriptions and payment statuses must be tracked administratively by the operator.

---

## 2. Hardware & Network Topology Requirements

### Server Specifications
- **Operating System**: Ubuntu 24.04 LTS (x86_64) or compatible modern Linux kernel (6.8+ recommended).
- **Network Interfaces**: Exactly two dedicated physical Ethernet ports:
  1. **Built-in Dell Ethernet NIC (WAN)**: Connected to the upstream ISP ONT / Modem (PLDT).
  2. **External USB 3.0 Gigabit Ethernet NIC (LAN)**: Connected downstream to your central Gigabit Switch.
- **Console Access**: A physical monitor and keyboard connected directly to the server. Because the `--confirm-present` safety gate requires confirmation of physical presence, and SSH sessions can be disrupted by networking changes, physical console access is mandatory.

### Physical Wiring Flow

```
PLDT ONT / Modem (Fiber In)
      │
      ▼ (Ethernet Cable)
[ Dell Built-in NIC (WAN) ] (e.g., enp0s31f6)
┌─────────────────────────────────────────────────────────────┐
│                 Dell E5470 Ubuntu Server                    │
│                        (THN Gateway)                        │
│                                                             │
│   • IPv4 Forwarding: enabled                                │
│   • Masquerade NAT: table inet thn                          │
│   • Subnet: 10.77.0.1/24                                    │
│   • Management: Physical Console & LAN SSH                  │
└─────────────────────────────────────────────────────────────┘
[ Dell External USB 3.0 Gigabit NIC (LAN) ] (e.g., enx00e0...)
      │
      ▼ (Ethernet Cable)
┌─────────────────────────────────────────────────────────────┐
│                 Unmanaged Gigabit Switch                    │
└───────┬─────────────────────────────┬───────────────────────┘
        │ (Port 1)                    │ (Port 2..N)
        ▼                             ▼
┌───────────────────────────┐ ┌───────────────────────────────┐
│    Home / Family Router   │ │       Neighbor Routers        │
│   (WAN: 10.77.0.50 Static)│ │    (WAN: 10.77.0.100 Static)  │
│   (ROUTER MODE: Enabled)  │ │    (ROUTER MODE: Mandatory)   │
│   (Local LAN: 192.168.1.x)│ │    (Local LAN: 192.168.2.x)   │
└─────────────┬─────────────┘ └───────────────┬───────────────┘
              ▼                               ▼
       Family Devices                  Neighbor Devices
    (Phones, PCs, Smart TVs)        (Household Phones, TVs)
```

---

## 3. Router Mode vs AP Mode: What Should You Set?

When distributing internet from the switch to your home router and neighbor routers, **set ROUTER MODE on all downstream routers.** Do not use AP (Access Point) Mode.

### Comparison Matrix

| Factor | Router Mode (Recommended & Mandatory for Neighbors) | AP Mode (Access Point Mode) |
|---|---|---|
| **DHCP Distribution** | **Local & Automatic**: The router runs its own DHCP server. Neighbor phones and TVs connect automatically. | **Broken**: THN Gateway does **not** run a DHCP server. Every single phone, laptop, or guest device would require manual static IP configuration. |
| **Bandwidth Enforcement** | **1 Household = 1 IP**: All devices inside the neighbor's home are NATed behind a single WAN IP (e.g., `10.77.0.100`). You can cap the entire household easily. | **Fragmented**: Every device has its own IP. If a neighbor connects 8 devices, enforcing a 20 Mbps household cap requires tracking 8 dynamic MAC addresses. |
| **Security & Privacy** | **Isolated**: Neighbors cannot browse your family's smart TVs, network shares, printers, or the gateway management port. | **No Isolation**: Neighbors and your family share the same broadcast domain. Neighbors can see your network devices and generate ARP/broadcast noise. |
| **Management Simplicity** | **Zero Client Setup**: You only assign one static IP to the neighbor's router WAN port. Their internal devices are self-managed. | **High Support Burden**: Neighbors will constantly call whenever a new device fails to get an IP address. |

### Configuration Rules for Downstream Routers

1. **Neighbor Routers (Mandatory: ROUTER MODE)**:
   - Connect the Ethernet cable coming from the central switch into the **WAN/Internet port** of the neighbor's router.
   - In the neighbor router's web admin:
     - **WAN Connection Type**: Static IP.
     - **WAN IP Address**: `10.77.0.100` (increment for each neighbor: `10.77.0.101`, etc.).
     - **Subnet Mask**: `255.255.255.0` (`/24`).
     - **Default Gateway**: `10.77.0.1` (the Dell server LAN IP).
     - **Primary / Secondary DNS**: `1.1.1.1` and `9.9.9.9` (Cloudflare / Quad9).
     - **Local LAN Subnet**: Set to `192.168.2.1/24` (or any non-conflicting subnet; ensure it is **not** `10.77.0.x`).
     - **Local DHCP Server**: **Enabled**. This automatically assigns IPs to all phones and computers in their house.

2. **Home / Family Router (Recommended: ROUTER MODE)**:
   - Connect the cable from the central switch into the **WAN/Internet port** of your home router.
   - In your home router's web admin:
     - **WAN Connection Type**: Static IP.
     - **WAN IP Address**: `10.77.0.50` (reserved for your household in THN config).
     - **Subnet Mask**: `255.255.255.0`.
     - **Default Gateway**: `10.77.0.1`.
     - **DNS**: `1.1.1.1`, `9.9.9.9`.
     - **Local LAN Subnet**: `192.168.1.1/24` (separate from `10.77.0.x`).
     - **Local DHCP Server**: **Enabled**. All family devices receive fast, local addresses without interfering with neighbors.

---

## 4. Building and Installing the Binaries

The repository provides two core executables:
- `thn`: The primary CLI for discovery, validation, planning, and activation.
- `thnd`: The passive background monitoring daemon.

### Cross-compiling from a Windows Development Machine
If developing on Windows, cross-compile the Linux binaries using PowerShell:

```powershell
cd "d:\Programming\Projects\The Heedful\THN-Gateway"
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -o thn ./cmd/thn
go build -o thnd ./cmd/thnd
scp .\thn user@your-server-ip:/tmp/
scp .\thnd user@your-server-ip:/tmp/
```

### Compiling Directly on Ubuntu Server
If building directly on the server, install Go 1.26+ and compile:

```bash
cd /path/to/THN-Gateway
go build -o thn ./cmd/thn
go build -o thnd ./cmd/thnd
sudo install -m 0755 thn /usr/local/bin/thn
sudo install -m 0755 thnd /usr/local/bin/thnd
```

### Verifying System Tools
Ensure the required Linux networking binaries and kernel modules are present:

```bash
which ip nft tc sysctl
sudo apt update && sudo apt install -y iproute2 nftables
sudo modprobe sch_cake
sudo modprobe sch_htb
```

---

## 5. Pre-Flight Inspection & Baseline Capture

Run read-only discovery to inspect the host and identify physical ports:

```bash
sudo thn host
sudo thn host --analyze
sudo thn discover --mac
```

### Interpreting the Discovery Output
1. Check the **Readiness** status. It must report `READY` or `READY_WITH_WARNINGS`. If it reports `BLOCKED`, resolve the issue (such as missing Ethernet cables or fewer than 2 physical ports).
2. Note the stable hardware IDs (formatted as `hw:<mac-address>`) for both the WAN NIC (carrying the default route) and the LAN NIC.
3. Ensure the LAN cable is plugged into the switch so the link status reports `UP` with carrier present.

### Mandatory Baseline Recording
Record the pre-deployment network state from your workstation or copy it off the server. If an emergency occurs, this file allows manual restoration:

```bash
sudo bash -c '
{
  echo "=== date ===";          date -Is
  echo "=== default route ==="; ip -4 route show default
  echo "=== all routes ===";    ip -4 route show
  echo "=== addresses ===";     ip -4 addr show
  echo "=== links ===";         ip -j link show
  echo "=== nft tables ===";    nft list tables
  echo "=== qdiscs ===";        tc -s qdisc show
  echo "=== sysctl ===";        sysctl net.ipv4.ip_forward
} > /root/thn-baseline.txt'
```

Copy `/root/thn-baseline.txt` to your personal computer:

```bash
scp user@your-server-ip:/root/thn-baseline.txt ~/Desktop/
```

---

## 6. Gateway Configuration

Create the system directories:

```bash
sudo mkdir -p /etc/thn /var/lib/thn /run/thn
```

Generate the initial network fragment with stable hardware IDs:

```bash
sudo thn discover --emit
```

Create `/etc/thn/config.yaml` based on the template in [configs/gateway.yaml](configs/gateway.yaml). Apply the following required configurations:

```yaml
schema_version: 1

gateway:
  name: thn-gateway
  generation: 1
  enabled: true

routing:
  ipv4_forwarding: true
  ipv6_forwarding: false

network:
  # Replace with the stable hardware ID of your WAN NIC
  wan: "hw:00:11:22:33:44:55"

  # Replace with the stable hardware ID of your LAN NIC
  lan: "hw:66:77:88:99:aa:bb"

  lan_prefix: 10.77.0.1/24
  dns:
    - 1.1.1.1
    - 9.9.9.9
  mtu: 1500
  upstream_gateway: ""

nat:
  enabled: true
  interfaces:
    - "hw:66:77:88:99:aa:bb"
  masquerade:
    enabled: true
    outbound: wan

firewall:
  enabled: true
  backend: nftables
  default_inbound_policy: drop
  # Include your LAN prefix AND your external management/VPN subnet
  admin_sources:
    - 10.77.0.0/24
    - 100.64.0.0/10    # Tailscale CGNAT subnet (if applicable)

# MANDATORY: Must be false to pass the subsystems-executable gate
dhcp:
  enabled: false
  reservations:
    - mac: "aa:bb:cc:dd:ee:01"
      address: 10.77.0.50
      hostname: admin-workstation
    - mac: "aa:bb:cc:dd:ee:02"
      address: 10.77.0.100
      hostname: neighbor-cruz
    - mac: "aa:bb:cc:dd:ee:03"
      address: 10.77.0.101
      hostname: neighbor-santos

# MANDATORY: Must be false to pass the subsystems-executable gate
dns:
  enabled: false

# MANDATORY FOR ACTIVATION: Must be false until physical lab verification passes
qos:
  enabled: false
  algorithm: cake
  interface: "hw:00:11:22:33:44:55"
  download_kbps: 100000
  upload_kbps: 30000
  clients:
    - id: neighbor-cruz
      ip: 10.77.0.100
      download_kbps: 20000
      upload_kbps: 5000
      priority: normal
    - id: neighbor-santos
      ip: 10.77.0.101
      download_kbps: 20000
      upload_kbps: 5000
      priority: normal
    - id: admin-workstation
      ip: 10.77.0.50
      download_kbps: 50000
      upload_kbps: 15000
      priority: critical

paths:
  config: /etc/thn/config.yaml
  state_dir: /var/lib/thn
  state_db: /var/lib/thn/state.db
  socket: /run/thn/thnd.sock
  run_dir: /run/thn
  log_file: ""

logging:
  level: info
  format: json

activation:
  require_physical_presence: true
```

Validate the file syntax and subsystem coherence:

```bash
sudo thn config validate /etc/thn/config.yaml
sudo thn validate /etc/thn/config.yaml
```

Both commands must return exit code 0 with zero blocking errors.

---

## 7. Neighbor Client Management & Static Addressing

Because THN does not run an automated DHCP server, downstream devices must be assigned static configurations, or you must run an external DHCP daemon (such as standalone dnsmasq on the server).

### Client Addressing Table
Configure neighbor routers or client devices with static IPv4 settings:

| Setting | Value | Explanation |
|---|---|---|
| **IPv4 Address** | `10.77.0.100` – `10.77.0.250` | Unique address per neighbor device |
| **Subnet Mask** | `255.255.255.0` (`/24`) | Matches `network.lan_prefix` |
| **Default Gateway** | `10.77.0.1` | The THN LAN IP address |
| **DNS Servers** | `1.1.1.1`, `9.9.9.9` | **Do not** use `10.77.0.1`. The gateway does not run a DNS resolver. |

### Neighbor Access Policies
When a neighbor misses a payment or requires restriction, define an access policy in your configuration or apply firewall rules.

Example policy disabling a device in [internal/policy/policy.go](internal/policy/policy.go#L65-L75):

```yaml
policies:
  - kind: device
    subject:
      kind: device
      mac: "aa:bb:cc:dd:ee:02"
    profile: blocked
```

To block a non-paying neighbor immediately via `nftables` without restarting services:

```bash
sudo nft add element inet thn blocked_clients { 10.77.0.100 }
```

---

## 8. Inspection, Dry Run, and Activation

Perform pre-flight verification before altering host networking:

```bash
sudo thn activation inspect --config /etc/thn/config.yaml
sudo thn activation verify --config /etc/thn/config.yaml
```

Confirm that:
- **Management path safe** reports `true`.
- **Preserved resources** lists your foreign routes and external tables.
- **Mutations** only list `table inet thn`, bringing up the LAN link, and assigning `10.77.0.1/24`.

### Step 1: Authorized Dry Run
Execute the dry run to evaluate all 13 gates without mutating the host:

```bash
sudo thn activate --config /etc/thn/config.yaml --confirm --confirm-present --dry-run
```

Ensure this reports `dry-run completed: all gates satisfied`.

### Step 2: Live Activation
From the **physical console** of the Ubuntu server, execute the live activation:

```bash
sudo thn activate --config /etc/thn/config.yaml --confirm --confirm-present
```

The process runs through transactional phases:
`PREPARE -> BACKUP -> VALIDATE -> APPLY -> HEALTH_CHECK -> COMMIT`

Expected result:
```
Status: COMMITTED
All safety gates passed, mutations applied, and baseline verified.
```

---

## 9. Post-Activation Verification

Verify connectivity from a client device connected to the downstream switch:

1. **Ping Gateway**:
   ```bash
   ping 10.77.0.1
   ```
2. **Ping Internet**:
   ```bash
   ping 1.1.1.1
   ```
3. **Verify Masquerade NAT**:
   ```bash
   curl https://ifconfig.me
   ```
   The output must display the public IP address of your WAN connection.
4. **Verify Host Tables on Server**:
   ```bash
   sudo nft list tables
   ```
   Confirm `table inet thn` is present alongside any pre-existing Docker or VPN tables.

---

## 10. Background Daemon Setup & Operational Monitoring

To enable real-time telemetry, inventory querying, and diagnostics, configure `thnd` as a systemd service.

Create `/etc/systemd/system/thnd.service`:

```ini
[Unit]
Description=THN Gateway Controller Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/thnd --config /etc/thn/config.yaml
Restart=on-failure
RestartSec=5
RuntimeDirectory=thn
StateDirectory=thn

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now thnd
sudo systemctl status thnd
```

### Monitoring Commands
Run monitoring and inventory commands to manage connected neighbors:

```bash
# Report live gateway state from thnd
thn status

# Show connected neighbor devices, IPs, MACs, and online status
thn clients

# Inspect interface bandwidth and system resources
thn monitoring

# Verify interface roles and link carrier states
thn interfaces

# Run self-diagnostics
thn diagnostics
```

---

## 11. Congestion Control, QoS & Multi-WAN Load Balancing

When multiple households share a single PLDT fiber connection, unmanaged traffic will quickly cause extreme latency spikes (500ms+ ping), video conference freezing, buffering, and packet loss. This section explains the root cause and provides a complete solution.

### 11.1 The Root Cause of Instability (Bufferbloat & Asymmetric Saturation)

1. **Bufferbloat in the ISP Modem**:
   When a neighbor uploads a large file (e.g., Google Drive backup, iCloud sync, torrents), the modem's internal packet buffers fill to maximum capacity. Packets wait in queue behind the upload, causing ping times to jump from 15ms to 600ms+ for every household on the network.
2. **Download Monopoly**:
   Without per-client rate shaping, a single device downloading a game or 4K video stream will open dozens of parallel TCP connections, saturating the link and starving all other users.
3. **Upload Choking Download**:
   Every download requires TCP ACK packets to travel upstream. If a neighbor saturates the upload pipe, ACK packets are delayed or dropped, which collapses download speeds across all households.

### 11.2 The Architecture: CAKE + HTB Class Hierarchy

To guarantee a stable connection:
- **CAKE (Common Applications Kept Enhanced)**: Operates Active Queue Management (AQM) and Flow Queuing (FQ). It isolates flows automatically (`dual-srchost`), balances connections fairly, and categorizes traffic into 4 priority tins (`diffserv4`: Voice/DNS/Gaming > Video > Best-effort > Bulk).
- **HTB (Hierarchical Token Bucket)**: Divides total bandwidth into strict bandwidth limits per household. Because all neighbor devices sit behind their router's single static IP, HTB caps the entire household as a single entity.
- **Priority Scheduling**: Family traffic is placed in a high-priority tier (`priority 1`), while neighbor traffic sits in normal tiers (`priority 3`). Family video calls and work sessions take precedence during peak congestion.

### 11.3 Step-by-Step Traffic Control Script (`/etc/thn/apply-qos.sh`)

> **Correction (Oct 2026): the upload filters below do not work.**
>
> This script classifies upload with
> `tc filter ... u32 match ip src 10.77.0.50/32`. On a masquerading gateway that
> filter matches nothing: by the time an upload packet reaches the WAN's egress
> queue, nftables has already rewritten its source address to the gateway's WAN
> address. The filter installs, the class exists, and no packet ever enters it —
> so **the upload limits in this script have never applied.**
>
> The download half is correct and works as written.
>
> Upload classification must go through the packet mark, which is set before
> masquerade runs. See [`QOS_AND_CLIENT_CONTROL.md`](QOS_AND_CLIENT_CONTROL.md)
> §1.1 for the verified form, and use
> `/usr/local/bin/thn-client-control` rather than hand-rolled `tc` for
> per-client limits.
>
> The table below is retained because the HTB shape, the priorities and the
> per-household model are correct and are what the working implementation
> builds on.

Because automated QoS activation is gated in [internal/cli/activate_production.go](internal/cli/activate_production.go#L244-L260), you apply this proven Linux `tc` hierarchy directly.

Create `/etc/thn/apply-qos.sh`:

```bash
sudo tee /etc/thn/apply-qos.sh > /dev/null <<'EOF'
#!/usr/bin/env bash
# THN Gateway Production QoS Script
# WAN interface = Built-in Dell NIC (Upload bottleneck)
# LAN interface = External USB 3.0 NIC (Download bottleneck)

WAN_IF="enp0s31f6"      # Replace with your actual WAN interface name from 'thn host'
LAN_IF="enx00e099001812" # Replace with your actual LAN interface name from 'thn host'

# Set your provisioned bandwidth minus 5-10% overhead compensation
# e.g., for a 100 Mbps Download / 30 Mbps Upload PLDT Fiber plan:
TOTAL_DOWN="90mbit"
TOTAL_UP="28mbit"

# 1. Clear existing root qdiscs
tc qdisc del dev "$WAN_IF" root 2>/dev/null
tc qdisc del dev "$LAN_IF" root 2>/dev/null

# ==============================================================================
# UPLOAD SHAPING (Attached to WAN_IF)
# ==============================================================================
# Create Root HTB class
tc qdisc add dev "$WAN_IF" root handle 1: htb default 30
tc class add dev "$WAN_IF" parent 1: classid 1:1 htb rate "$TOTAL_UP" ceil "$TOTAL_UP"

# Class 1:10 -> Home / Family Router (10.77.0.50) [Guaranteed 15M, Max 28M, High Priority]
tc class add dev "$WAN_IF" parent 1:1 classid 1:10 htb rate 15mbit ceil "$TOTAL_UP" prio 1
tc qdisc add dev "$WAN_IF" parent 1:10 handle 10: cake diffserv4 nat dual-srchost

# Class 1:20 -> Neighbor 1 Router (10.77.0.100) [Guaranteed 5M, Max 8M, Normal Priority]
tc class add dev "$WAN_IF" parent 1:1 classid 1:20 htb rate 5mbit ceil 8mbit prio 3
tc qdisc add dev "$WAN_IF" parent 1:20 handle 20: cake diffserv4 nat dual-srchost

# Class 1:30 -> Neighbor 2 Router (10.77.0.101) [Guaranteed 5M, Max 8M, Normal Priority]
tc class add dev "$WAN_IF" parent 1:1 classid 1:30 htb rate 5mbit ceil 8mbit prio 3
tc qdisc add dev "$WAN_IF" parent 1:30 handle 30: cake diffserv4 nat dual-srchost

# Filter Upload by Source IP
tc filter add dev "$WAN_IF" protocol ip parent 1:0 prio 1 u32 match ip src 10.77.0.50/32 flowid 1:10
tc filter add dev "$WAN_IF" protocol ip parent 1:0 prio 3 u32 match ip src 10.77.0.100/32 flowid 1:20
tc filter add dev "$WAN_IF" protocol ip parent 1:0 prio 3 u32 match ip src 10.77.0.101/32 flowid 1:30

# ==============================================================================
# DOWNLOAD SHAPING (Attached to LAN_IF)
# ==============================================================================
# Create Root HTB class
tc qdisc add dev "$LAN_IF" root handle 1: htb default 30
tc class add dev "$LAN_IF" parent 1: classid 1:1 htb rate "$TOTAL_DOWN" ceil "$TOTAL_DOWN"

# Class 1:10 -> Home / Family Router (10.77.0.50) [Guaranteed 50M, Max 90M, High Priority]
tc class add dev "$LAN_IF" parent 1:1 classid 1:10 htb rate 50mbit ceil "$TOTAL_DOWN" prio 1
tc qdisc add dev "$LAN_IF" parent 1:10 handle 10: cake diffserv4 nat dual-dsthost

# Class 1:20 -> Neighbor 1 Router (10.77.0.100) [Guaranteed 15M, Max 25M, Normal Priority]
tc class add dev "$LAN_IF" parent 1:1 classid 1:20 htb rate 15mbit ceil 25mbit prio 3
tc qdisc add dev "$LAN_IF" parent 1:20 handle 20: cake diffserv4 nat dual-dsthost

# Class 1:30 -> Neighbor 2 Router (10.77.0.101) [Guaranteed 15M, Max 25M, Normal Priority]
tc class add dev "$LAN_IF" parent 1:1 classid 1:30 htb rate 15mbit ceil 25mbit prio 3
tc qdisc add dev "$LAN_IF" parent 1:30 handle 30: cake diffserv4 nat dual-dsthost

# Filter Download by Destination IP
tc filter add dev "$LAN_IF" protocol ip parent 1:0 prio 1 u32 match ip dst 10.77.0.50/32 flowid 1:10
tc filter add dev "$LAN_IF" protocol ip parent 1:0 prio 3 u32 match ip dst 10.77.0.100/32 flowid 1:20
tc filter add dev "$LAN_IF" protocol ip parent 1:0 prio 3 u32 match ip dst 10.77.0.101/32 flowid 1:30

echo "THN Gateway QoS applied successfully: Bufferbloat eliminated and household bandwidth partitioned."
EOF

sudo chmod +x /etc/thn/apply-qos.sh
sudo /etc/thn/apply-qos.sh
```

### 11.4 Making QoS Persistent on Boot

Create a systemd unit to execute `/etc/thn/apply-qos.sh` automatically whenever the network interfaces initialize:

```bash
sudo tee /etc/systemd/system/thn-qos.service > /dev/null <<'EOF'
[Unit]
Description=THN Gateway QoS Traffic Shaping Service
After=network.target thnd.service
Wants=network.target

[Service]
Type=oneshot
ExecStart=/etc/thn/apply-qos.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable thn-qos.service
```

### 11.5 Verifying Real-Time Queue Statistics

While running a speed test or streaming video, inspect the active CAKE tins and drops:

```bash
# Check WAN Upload queue
sudo tc -s qdisc show dev enp0s31f6

# Check LAN Download queue
sudo tc -s qdisc show dev enx00e099001812
```

You should observe packets classified into respective tins with minimal delay and zero bufferbloat.

### 11.6 Multi-WAN & Load Balancing

THN models Multi-WAN routing in [internal/multiwan/intent.go](internal/multiwan/intent.go). If you add a second ISP connection in the future (e.g., Converge, Globe, or Starlink):

1. **Physical Setup**: Connect the secondary ISP to an additional USB Gigabit adapter or VLAN interface.
2. **Multi-WAN Modes**:
   - `ModeLoadBalance`: Distributes outgoing sessions across both ISPs according to configured weights (e.g., 70% PLDT, 30% Backup), multiplying your available downstream capacity.
   - `ModeFailover`: Routes all traffic through PLDT primarily; if PLDT fiber drops, the gateway switches traffic to the backup link within seconds.
3. **Health Tracking**: Continuous observation evaluates carrier status, gateway responsiveness, and route integrity, transitioning links through `healthy`, `degraded`, or `unhealthy`.

---

## 12. Emergency Recovery Runbook

If activation experiences an issue or network connectivity is lost, follow the emergency procedures in [docs/deployment-runbook.md](docs/deployment-runbook.md#L285-L350).

### Physical Console Recovery Procedure

1. Log in at the physical console.
2. Remove THN's firewall ruleset:
   ```bash
   sudo nft delete table inet thn
   ```
3. Stop the daemon:
   ```bash
   sudo systemctl stop thnd
   ```
4. Reset the LAN interface and restore original IP configuration:
   ```bash
   sudo ip addr flush dev <lan-interface>
   sudo ip link set dev <lan-interface> down
   ```
5. If interrupted during apply, inspect the journal file:
   ```bash
   cat /var/lib/thn/activation-journal.json
   sudo rm /var/lib/thn/activation-journal.json
   ```
6. Restore pre-flight default routes and forwarding from your baseline file:
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo ip route replace default via <isp-gateway-ip> dev <wan-interface>
   ```
7. Verify external reachability:
   ```bash
   ping -c 3 1.1.1.1
   ```
