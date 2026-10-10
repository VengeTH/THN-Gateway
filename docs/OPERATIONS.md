# Day-2 Operations, Monitoring & Maintenance Guide

This document provides ongoing operational procedures, telemetry queries, client inventory monitoring, log inspection, and configuration lifecycle workflows for an active **THN Gateway** deployment.

---

## 1. Routine Health & Telemetry Checks

THN provides built-in read-only commands for inspecting the health and telemetry of the gateway:

### 1.1 Consolidated Gateway Monitoring (`thn monitoring`)
Reports interface states, rx/tx counters, packet error rates, and system uptime:
```bash
thn monitoring
```

### 1.2 System Diagnostics (`thn diagnostics`)
Assesses system subsystems, kernel capabilities, routing coherence, and table presence:
```bash
thn diagnostics
```

### 1.3 Live Daemon Status (`thn status`)
When `thnd` is running as a systemd service, query live state:
```bash
thn status
```

### 1.4 Client Inventory (`thn clients`)
Reports all connected devices observed on the LAN subnet (`10.77.0.0/24`), their MAC addresses, and assigned IP addresses:
```bash
thn clients
```

#### Understanding the Client Output:
- Because downstream devices are in **ROUTER MODE**, you should see distinct entries for the WAN interface of each downstream router:
  - `10.77.0.50`: Family Router (NAT gateway for all internal family devices).
  - `10.77.0.100`: Neighbor 1 Router (NAT gateway for neighbor household).
  - `10.77.0.101`: Neighbor 2 Router.
- Individual client phones and televisions will **not** appear here; their traffic is aggregated behind their respective household router IP.

---

## 2. Log Analysis & Audit Trails

### 2.1 THN Daemon Logs
Inspect background daemon events:
```bash
sudo journalctl -u thnd.service -n 100 -f
```

### 2.2 Host DHCP & DNS Logs (`dnsmasq`)
Monitor DHCP lease allocations, lease renewals, and DNS queries:
```bash
sudo journalctl -u dnsmasq.service -n 100 -f
```
To view active DHCP leases on the host:
```bash
cat /var/lib/misc/dnsmasq.leases
```

### 2.3 Kernel Packet Drop & Firewall Logs
If dropped packets or connection tracking errors occur:
```bash
sudo dmesg -T | grep -iE '(nft|drop|spoof|reject)'
```

### 2.4 THN Audit & Event History (`thn events`)
Inspect recorded gateway lifecycle events:
```bash
thn events
```

---

## 3. Safe Configuration Change Lifecycle

Whenever modifying `/etc/thn/config.yaml` (e.g., adding an approved adapter, modifying firewall rules, or bumping gateway generation):

```
┌─────────────────────────────────┐
│ 1. Edit Configuration           │
│    sudo nano /etc/thn/config.yaml
└────────────────┬────────────────┘
                 ▼
┌─────────────────────────────────┐
│ 2. Validate Schema & Live Host  │
│    thn validate --live /etc/thn/config.yaml
└────────────────┬────────────────┘
                 ▼
┌─────────────────────────────────┐
│ 3. Inspect Plan & Explain Diff  │
│    thn plan --explain /etc/thn/config.yaml
└────────────────┬────────────────┘
                 ▼
┌─────────────────────────────────┐
│ 4. Run Preflight Dry-Run        │
│    sudo thn activate --config /etc/thn/config.yaml \
│         --confirm --confirm-present --dry-run
└────────────────┬────────────────┘
                 ▼
┌─────────────────────────────────┐
│ 5. Execute Live Activation      │
│    sudo thn activate --config /etc/thn/config.yaml \
│         --confirm --confirm-present
└─────────────────────────────────┘
```

**Rule:** Never execute step 5 unless steps 2, 3, and 4 pass cleanly without errors.

---

## 4. Hardware & Interface Maintenance

### 4.1 USB Ethernet Adapter Health Check
Check link speed and duplex on the USB adapter:
```bash
ethtool enx00e099001812
```
Look for:
- `Speed: 100Mb/s`
- `Duplex: Full`
- `Link detected: yes`

If `Speed: 10Mb/s` or `Duplex: Half` is detected, the physical cable is degraded or the USB port suffered an electrical negotiation fault. Reseat the cable and USB adapter.

### 4.2 Carrier Drop Detection
Check interface error counters:
```bash
ip -s link show enx00e099001812
```
Verify `errors`, `dropped`, and `carrier` counters are not rapidly incrementing.

### 4.3 Database Maintenance
The state database lives at `/var/lib/thn/state.db`. Verify SQLite integrity:
```bash
sudo sqlite3 /var/lib/thn/state.db "PRAGMA integrity_check;"
```
Expected output: `ok`.
