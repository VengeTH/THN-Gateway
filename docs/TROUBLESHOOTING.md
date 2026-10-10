# Diagnostic & Troubleshooting Guide

This guide provides targeted diagnostic procedures, root cause analysis, and remediation steps for issues encountered when configuring, activating, or operating **THN Gateway**.

---

## 1. Activation Issues

### 1.1 Gate Blocked: `lan-identified` (100 Mbps Adapter Rejected)

- **Symptom**: `thn activate` or `thn readiness` fails with:
  ```
  Blocking gates (1):
    [x] lan-identified   interface enx00e099001812 operates at 100 Mbps; production LAN requires a Gigabit Ethernet interface (>= 1000 Mbps)...
  ```
- **Likely Cause**: The LAN adapter operates below 1000 Mbps, and the development override is not enabled or does not name this adapter's exact stable ID.
- **Diagnostic Commands**:
  ```bash
  thn discover | grep -A 5 -i lan
  grep -A 5 "development:" /etc/thn/config.yaml
  ```
- **Remediation**:
  Ensure `/etc/thn/config.yaml` contains both the opt-in flag and the exact hardware identity:
  ```yaml
  activation:
    require_physical_presence: true
    development:
      allow_fast_ethernet_lan: true
      approved_fast_ethernet_lan:
        - hw:2c886f45ad0cb12f
  ```
  Re-test with `thn readiness /etc/thn/config.yaml`.

---

### 1.2 Gate Blocked: `physical-presence`

- **Symptom**: `thn activate --confirm` refuses with:
  ```
  Blocking gates (1):
    [x] physical-presence   physical presence at the device must be confirmed
  ```
- **Likely Cause**: Missing `--confirm-present` flag. THN enforces this gate to prevent remote root SSH sessions from inadvertently altering edge network state without console access.
- **Remediation**:
  Ensure you are standing beside the machine at the console, and provide both flags:
  ```bash
  sudo thn activate --confirm --confirm-present
  ```

---

### 1.3 Gate Blocked: `subsystems-executable` (QoS, DHCP, or DNS Enabled)

- **Symptom**: `thn readiness` reports `subsystems-executable` blocked:
  ```
  [x] subsystems-executable   subsystems requested in configuration are not executable in this build: qos
  ```
- **Likely Cause**: `qos.enabled: true`, `dhcp.enabled: true`, or `dns.enabled: true` in `/etc/thn/config.yaml`.
- **Remediation**:
  Set those subsystems to `false` in `/etc/thn/config.yaml`. These roles are handled externally on this host (CAKE via `thn-gateway-restore.service`, and DHCP/DNS via `dnsmasq`).

---

### 1.4 Refusal: `RECOVERY_REQUIRED` (Transaction Interrupted)

- **Symptom**: `thn activate` refuses with:
  ```
  Reason:
    RECOVERY_REQUIRED — an earlier transaction was interrupted.
    Plan        plan-xyz
    Last state  apply
  ```
- **Likely Cause**: A previous activation was interrupted mid-flight (crash, power loss, or terminal disconnect). The transaction journal `/var/lib/thn/activation-journal.json` marks the transaction uncompleted.
- **Diagnostic Commands**:
  ```bash
  sudo cat /var/lib/thn/activation-journal.json | jq .
  ```
- **Remediation**:
  1. Inspect the host against your baseline to verify which operations applied.
  2. If the host is in a clean state, remove the stale journal file:
     ```bash
     sudo rm /var/lib/thn/activation-journal.json
     ```
  3. Re-run `thn activation inspect` and preflight dry-run before activating again.

---

## 2. Client Connectivity & Forwarding Issues

### 2.1 Downstream Client Does Not Receive a DHCP Lease

- **Symptom**: Downstream laptop or router WAN port shows `Link up`, but receives no IP address (or self-assigns `169.254.x.x`).
- **Diagnostic Commands**:
  ```bash
  # Check if dnsmasq is running
  sudo systemctl status dnsmasq

  # Check if dnsmasq is listening on UDP port 67
  sudo ss -ulpn | grep :67

  # Check live dnsmasq lease logs
  sudo journalctl -u dnsmasq -n 50 --no-pager
  ```
- **Likely Cause**:
  1. `dnsmasq` service is crashed or stopped.
  2. `dnsmasq` is listening on the wrong interface.
  3. Physical switch or Ethernet patch cable disconnected.
- **Remediation**:
  ```bash
  # Verify dnsmasq configuration references enx00e099001812
  cat /etc/dnsmasq.d/thn-gateway.conf

  # Restart dnsmasq
  sudo systemctl restart dnsmasq
  ```

---

### 2.2 Client Cannot Resolve DNS Names (Websites Fail by Name, Work by IP)

- **Symptom**: Client can `ping 1.1.1.1` successfully, but `ping google.com` fails with `Name resolution failure`.
- **Diagnostic Commands**:
  ```bash
  # From client:
  dig @10.77.0.1 google.com

  # From host:
  sudo ss -tulpn | grep :53
  cat /etc/resolv.conf
  ```
- **Likely Cause**: `dnsmasq` DNS service is not answering queries on `10.77.0.1:53`, or upstream forwarders (`1.1.1.1`, `9.9.9.9`) are unreachable.
- **Remediation**:
  Check `/etc/dnsmasq.d/thn-gateway.conf`. Ensure `listen-address=10.77.0.1` and `server=1.1.1.1` are active. Restart `dnsmasq`.

---

### 2.3 Client Can Ping Gateway (`10.77.0.1`), but Cannot Access the Internet

- **Symptom**: Client pings `10.77.0.1` with 0% packet loss. Client cannot ping `1.1.1.1` or reach web pages.
- **Diagnostic Commands**:
  ```bash
  # 1. Check kernel forwarding
  sysctl net.ipv4.ip_forward

  # 2. Check default gateway on WAN
  ip -4 route show default

  # 3. Check nftables forward chain counters
  sudo nft list chain inet thn forward

  # 4. Check nftables masquerade NAT rule
  sudo nft list chain inet thn postrouting
  ```
- **Likely Cause**:
  1. `net.ipv4.ip_forward` is `0`.
  2. Masquerade NAT is missing or bound to the wrong WAN interface name.
  3. The upstream ISP router (`192.168.1.1`) has dropped the host's WAN link.
- **Remediation**:
  ```bash
  # Ensure IP forwarding is enabled
  sudo sysctl -w net.ipv4.ip_forward=1

  # Verify default route exists via enp0s31f6
  ip route show default
  # Should show: default via 192.168.1.1 dev enp0s31f6

  # Check if WAN can reach internet directly
  ping -I enp0s31f6 -c 3 1.1.1.1
  ```

---

## 3. Remote Access & Firewall Lockout Issues

### 3.1 Tailscale or Remote SSH Drops During Activation

- **Symptom**: You trigger an operation and the remote SSH session freezes or terminates.
- **Likely Cause**: The firewall policy dropped the incoming management connection or modified the routing table on `wlp2s0` / `tailscale0`.
- **Remediation (via Physical Console)**:
  1. Log into the server using the physical keyboard and monitor.
  2. Inspect running nftables tables:
     ```bash
     sudo nft list tables
     ```
  3. If `table inet thn` was loaded with an unintended rule:
     ```bash
     sudo nft delete table inet thn
     ```
  4. Verify SSH is listening and Tailscale is connected:
     ```bash
     sudo systemctl status ssh
     tailscale status
     ```
  5. Your remote SSH and Tailscale connectivity will immediately recover.

---

### 3.2 UFW vs nftables Conflicts

- **Symptom**: `table inet thn` is installed, but packets are rejected by UFW.
- **Diagnostic Commands**:
  ```bash
  sudo ufw status verbose
  sudo nft list table inet ufw
  ```
- **Explanation**: In Ubuntu, UFW inserts chains into `table inet ufw`. Both `table inet ufw` and `table inet thn` evaluate packets. If either drops the packet, it is dropped.
- **Remediation**:
  Ensure UFW allows routed traffic and administration:
  ```bash
  sudo ufw allow 22/tcp
  sudo ufw default allow routed
  ```
