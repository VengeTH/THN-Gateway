# Rollback, State Recovery & Disaster Procedures

This document defines the safe, non-destructive rollback mechanisms and manual recovery procedures for **THN Gateway** on `heedful-dev`.

---

## 1. Safety Golden Rules

When recovering from any gateway fault or unexpected state:

> **CRITICAL RECOVERY RULES:**
> 1. **NEVER run `nft flush ruleset`**: This flushes all tables across all families, destroying Tailscale, UFW, Docker, and `ip thn_gateway` in one blow and causing total remote management lockout.
> 2. **NEVER run `iptables -F`**: Same risk as above.
> 3. **NEVER reboot the server as a first resort**: A reboot with an unverified network configuration or disabled restore service can lock you out permanently.
> 4. **Always use targeted deletion**: Target only the specific table owned by THN: `nft delete table inet thn`.

---

## 2. Automatic Execution-Level Rollback

THN's 6-phase transaction executor includes built-in automated rollback:

```
[Phase 4: APPLY]
   Operation 1: sysctl net.ipv4.ip_forward = 1  (Success)
   Operation 2: ip link set enx... up           (Success)
   Operation 3: ip addr add 10.77.0.1/24 dev... (Success)
   Operation 4: nft -f table_inet_thn.nft        (FAILS!)
                        │
                        ▼ (AUTOMATIC FAILURE TRIGGER)
[Compensating Rollback in Reverse Order]
   Compensate 3: ip addr del 10.77.0.1/24 dev... (Executed)
   Compensate 2: ip link set enx... down         (Executed)
   Compensate 1: restore original sysctl value   (Executed)
                        │
                        ▼
[Baseline Comparison]
   Compare live host against pre-apply snapshot.
   - If match: Final State = ROLLED_BACK (host restored to exact baseline).
   - If mismatch: Final State = DEGRADED (manual recovery required).
```

### When Automatic Rollback Triggers:
1. An individual driver operation fails during the `APPLY` phase.
2. An active health check probe fails during the `HEALTH_CHECK` phase (e.g., carrier loss or missing table).
3. The context is cancelled (timeout or process interrupt).

---

## 3. Manual Recovery from `RECOVERY_REQUIRED`

If an activation process crashed or was terminated mid-transaction, THN locks itself into `RECOVERY_REQUIRED`:

```
Reason:
  RECOVERY_REQUIRED — an earlier transaction was interrupted.
  Plan        plan-c32...
  Last state  apply
  Started     2026-10-10T12:00:00Z
```

### Recovery Procedure:

1. **Inspect the Transaction Journal**:
   ```bash
   sudo cat /var/lib/thn/activation-journal.json | jq .
   ```
   Note the `applied_ops` array to see exactly which steps were executed before the crash.

2. **Check the Live Host Against Your Pre-Flight Baseline**:
   ```bash
   # Compare nftables tables
   sudo nft list tables
   
   # Compare addresses
   ip addr show dev enx00e099001812
   ```

3. **Revert Any Partial Changes**:
   If `table inet thn` was partially loaded:
   ```bash
   sudo nft delete table inet thn
   ```

4. **Clear the Stale Journal**:
   Once you have verified the host is in a clean baseline state:
   ```bash
   sudo rm /var/lib/thn/activation-journal.json
   ```

5. **Verify Activation Gating**:
   ```bash
   thn activation status
   ```
   `Can Apply` should return to `true` and `State` should return to `DEVELOPMENT`.

---

## 4. Restoring the Host-Managed Gateway (`ip thn_gateway`)

The `heedful-dev` host has an independent gateway service configured outside of THN:
- `/etc/thn-gateway/thn_gateway.nft` (defines `table ip thn_gateway`)
- `/usr/local/sbin/thn-gateway-restore`
- `thn-gateway-restore.service`

If THN activation fails or needs to be completely undone, restore the host-managed baseline:

```bash
# 1. Remove THN's managed table
sudo nft delete table inet thn 2>/dev/null || true

# 2. Re-apply the host gateway restore script
sudo /usr/local/sbin/thn-gateway-restore

# 3. Restart the restore systemd service
sudo systemctl restart thn-gateway-restore.service

# 4. Verify the host gateway table is active
sudo nft list table ip thn_gateway

# 5. Verify dnsmasq is serving DHCP/DNS
sudo systemctl restart dnsmasq.service
```

---

## 5. Emergency Physical Console Runbook (Complete Lockout)

If you lose remote SSH and Tailscale connectivity:

1. **Walk to the Server**: Log in via the physical keyboard and monitor.
2. **Remove THN Table**:
   ```bash
   sudo nft delete table inet thn
   ```
3. **Check Network Links**:
   ```bash
   ip link set enp0s31f6 up
   ip link set wlp2s0 up
   ```
4. **Restart Networking & Management Services**:
   ```bash
   sudo systemctl restart systemd-networkd
   sudo systemctl restart tailscaled
   sudo systemctl restart ssh
   ```
5. **Verify Tailscale IP**:
   ```bash
   tailscale ip -4
   ```
   Confirm `100.65.7.40` is responsive.
