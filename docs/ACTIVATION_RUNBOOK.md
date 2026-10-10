# THN Gateway Activation Runbook (Authoritative Procedure)

This is the **mandatory, step-by-step physical activation runbook** for THN Gateway on `heedful-dev`.

> **SAFETY MANDATE:**
> The `heedful-dev` server is currently forwarding live network traffic for connected devices. Never skip baseline captures, never guess interface selectors, and never perform live activation over an unverified remote SSH connection without physical console access standing by.

---

## 1. Prerequisites & Physical Access Verification

Before executing any commands:

- [ ] **Physical Console Access**: You are sitting directly in front of the server with a physical monitor and keyboard connected. If an unexpected firewall rule or network disruption drops your SSH session, the physical console is your guaranteed recovery path.
- [ ] **Out-of-band Management Active**: Verify Tailscale is active (`tailscale status`) and connected over Wi-Fi (`wlp2s0`).
- [ ] **Backup Laptop Ready**: Keep a separate laptop connected to Tailscale or Wi-Fi to capture the baseline text files.

---

## 2. Step 1: Capture Pre-Activation Host Baseline

Run this read-only diagnostic capture on the server. Save the output to a persistent baseline file:

```bash
mkdir -p ~/thn-baselines
BASELINE_FILE=~/thn-baselines/baseline-$(date +%Y%m%d-%H%M%S).txt

{
  echo "=== 1. HOST IDENTIFICATION ==="
  hostname; uname -a; uptime
  
  echo "=== 2. THN REPO STATUS & COMMIT ==="
  cd ~/THN-Gateway && git status -s && git rev-parse HEAD
  
  echo "=== 3. NETWORK INTERFACES & OPERSTATE ==="
  ip -d link show
  
  echo "=== 4. IP ADDRESSES ==="
  ip addr show
  
  echo "=== 5. ROUTING TABLES ==="
  ip -4 route show
  ip -4 route show table all
  
  echo "=== 6. IP FORWARDING SYSCTL ==="
  sysctl net.ipv4.ip_forward
  
  echo "=== 7. NFTABLES RULES & TABLES ==="
  sudo nft list tables
  sudo nft list ruleset
  
  echo "=== 8. UFW STATUS ==="
  sudo ufw status numbered
  
  echo "=== 9. TC QDISCS & SHAPING ==="
  tc -s qdisc show
  
  echo "=== 10. ACTIVE NETWORKING SERVICES ==="
  systemctl status --no-pager dnsmasq thn-gateway-restore.service systemd-networkd
  
  echo "=== 11. DNS RESOLVER ==="
  cat /etc/resolv.conf
  
  echo "=== 12. TAILSCALE STATUS ==="
  tailscale status
} | tee "$BASELINE_FILE"

echo "Baseline successfully saved to: $BASELINE_FILE"
```

---

## 3. Step 2: Back Up Configuration, State & Host Rules

Create an immutable backup archive of existing network configurations:

```bash
BACKUP_DIR=~/thn-backups/backup-$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR"

# Back up THN configuration and state database
[ -f /etc/thn/config.yaml ] && sudo cp /etc/thn/config.yaml "$BACKUP_DIR/"
[ -f /var/lib/thn/state.db ] && sudo cp /var/lib/thn/state.db "$BACKUP_DIR/"

# Back up systemd network and sysctl
[ -f /etc/systemd/network/20-thn-lan.network ] && cp /etc/systemd/network/20-thn-lan.network "$BACKUP_DIR/"
[ -f /etc/sysctl.d/90-thn-gateway.conf ] && cp /etc/sysctl.d/90-thn-gateway.conf "$BACKUP_DIR/"

# Back up host dnsmasq and gateway restore scripts
[ -f /etc/dnsmasq.d/thn-gateway.conf ] && cp /etc/dnsmasq.d/thn-gateway.conf "$BACKUP_DIR/"
[ -f /etc/thn-gateway/thn_gateway.nft ] && sudo cp /etc/thn-gateway/thn_gateway.nft "$BACKUP_DIR/"
[ -f /usr/local/sbin/thn-gateway-restore ] && cp /usr/local/sbin/thn-gateway-restore "$BACKUP_DIR/"

echo "Configuration assets backed up to: $BACKUP_DIR"
```

---

## 4. Step 3: Discover Hardware & Verify Interface Selectors

Run `thn discover` to observe what the kernel currently reports and confirm stable hardware IDs:

```bash
thn discover
```

### Checkpoint:
Verify that:
- WAN interface (`enp0s31f6`) has stable ID `hw:7c6170fd7f34317a`, speed `1000 Mbps`, state `UP`.
- LAN interface (`enx00e099001812`) has stable ID `hw:2c886f45ad0cb12f`, speed `100 Mbps`, state `UP`.

If either selector is different, **STOP**. Update `/etc/thn/config.yaml` to match the exact ID reported by `thn discover`.

---

## 5. Step 4: Validate Configuration

Perform static and live configuration validation:

```bash
# 1. Static schema validation
thn validate /etc/thn/config.yaml

# 2. Live validation against host interfaces
thn validate --live /etc/thn/config.yaml
```

### Expected Output:
- Result: `PASS (0 error, ...)`
- Notice the explicit warning:
  `DEVELOPMENT MODE: a Fast Ethernet LAN adapter has been approved by name. LAN throughput is capped at 100 Mbps...`
- **STOP CONDITION:** If any `error` finding is printed, do not proceed. Fix the error in `/etc/thn/config.yaml`.

---

## 6. Step 5: Evaluate Activation Safety Gates

Check the status of all 13 safety gates without initiating changes:

```bash
thn readiness /etc/thn/config.yaml
```

And check detailed activation status:
```bash
thn activation status
```

### Checkpoint:
In `thn readiness`:
- `lan-identified` must report `ok` with the note:
  `role lan is filled by enx00e099001812 (identity hw:2c886f45ad0cb12f) under an EXPLICIT DEVELOPMENT OVERRIDE...`
- The `!! DEVELOPMENT OVERRIDE ACTIVE` banner is displayed.
- The only blocked gate in readiness mode must be `physical-presence` (because readiness runs read-only without the presence flag).

---

## 7. Step 6: Inspect Proposed Mutations (Read-Only)

Examine the exact commands, nftables rules, and sysctls THN plans to execute:

```bash
thn activation inspect --config /etc/thn/config.yaml
```

To see the operation plan and compensating rollback steps:
```bash
thn plan --explain /etc/thn/config.yaml
```

### Checkpoint:
Verify that:
- Proposed mutations affect only `table inet thn`, bringing up the LAN interface, and setting `net.ipv4.ip_forward = 1`.
- No operations target `table ip thn_gateway`, `ufw`, `tailscale`, or `wlp2s0`.
- Rollback operations correspond 1-to-1 with compensating actions.

---

## 8. Step 7: Execute Authorized Dry-Run

Run the fully authorized preflight dry run with both required confirmation flags:

```bash
sudo thn activate --config /etc/thn/config.yaml --confirm --confirm-present --dry-run
```

### Expected Output:
```
thn activate: dry run completed: all gates satisfied.

All activation safety gates satisfied.
Authorization and physical presence confirmed.
Nothing was changed (dry run).

!! DEVELOPMENT OVERRIDE ACTIVE
   gate "lan-identified" passed only because an operator-approved
   development exception applied to this host.

   LAN throughput is limited to Fast Ethernet (100 Mbps).
   This configuration is NOT approved for production
   deployment. Restore production policy with:
     activation.development.allow_fast_ethernet_lan: false

Ready for live activation:
  thn activate --config /etc/thn/config.yaml --confirm --confirm-present

Current network remains untouched.
```

**STOP CONDITION:** If the output reports `activation refused` or lists any blocking gates, **do not proceed to Step 8**. Refer to [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) to diagnose the blocking gate.

---

## 9. Step 8: Live Activation Execution

> **POINT OF EXECUTION:**
> This step executes the 6-phase transaction (`PREPARE -> BACKUP -> VALIDATE -> APPLY -> HEALTH_CHECK -> COMMIT`).

From the server console, run:

```bash
sudo thn activate --config /etc/thn/config.yaml --confirm --confirm-present
```

### Expected Output:
```
Production activation
─────────────────────
Plan:       plan-...
Journal:    /var/lib/thn/activation-journal.json
Phases:     prepare -> backup -> validate -> apply -> health-check -> commit

Applied (X):
  + [sysctl] net.ipv4.ip_forward = 1
  + [link] enx00e099001812 up
  + [addr] 10.77.0.1/24 on enx00e099001812
  + [nft] apply table inet thn

Result: COMMITTED

  [ok] forwarding           net.ipv4.ip_forward=1 observed
  [ok] table-installed      table inet thn exists and contains base chains
  [ok] lan-carrier          enx00e099001812 carrier detected

The gateway is serving as planned. Post-activation verification is
in docs/deployment-runbook.md; it does not depend on THN.

!! WARNING: Activated under DEVELOPMENT OVERRIDE (Fast Ethernet LAN, 100 Mbps max)
   This host is NOT approved for production deployment.
   Restore production policy by installing a Gigabit USB adapter and setting:
     activation.development.allow_fast_ethernet_lan: false
```

---

## 10. Step 9: Post-Activation Verification Checklist

Immediately verify the health of all systems:

### 10.1 Remote Administration Path Survival
```bash
# Verify Tailscale connectivity
tailscale status

# Verify SSH listening on port 22
sudo ss -tulpn | grep :22
```

### 10.2 Table Isolation & nftables Verification
```bash
# Verify table inet thn is active
sudo nft list table inet thn

# Verify table ip thn_gateway was NOT destroyed
sudo nft list table ip thn_gateway

# Verify foreign tables (ufw, tailscale) survive
sudo nft list tables
```

### 10.3 DHCP & DNS Service Verification
```bash
# Verify dnsmasq is active and listening on port 53 and port 67
systemctl is-active dnsmasq
sudo ss -ulpn | grep -E ':(53|67)'
```

### 10.4 Downstream LAN Client Connectivity
From a connected client behind the central switch (e.g., `10.77.0.143` or household router):
1. Ping the gateway IP:
   ```bash
   ping -c 4 10.77.0.1
   ```
2. Test DNS resolution:
   ```bash
   dig @10.77.0.1 google.com
   ```
3. Test internet connectivity (NAT forwarding):
   ```bash
   curl -I https://1.1.1.1
   curl -I https://www.google.com
   ```
4. Verify bandwidth cap:
   Run a speed test. Download/upload should cap at ~90–94 Mbps due to the Fast Ethernet adapter line rate.

---

## 11. Step 10: Abort & Emergency Rollback

If any post-activation verification check fails (e.g., clients lose internet access, or remote management is disrupted):

1. **Check Transaction Journal**:
   ```bash
   sudo cat /var/lib/thn/activation-journal.json
   ```
2. **Remove `table inet thn`**:
   ```bash
   sudo nft delete table inet thn
   ```
3. **Re-run the Host Restore Service**:
   ```bash
   sudo systemctl restart thn-gateway-restore.service
   ```
4. Consult [docs/ROLLBACK_AND_RECOVERY.md](docs/ROLLBACK_AND_RECOVERY.md) for full recovery procedures.
