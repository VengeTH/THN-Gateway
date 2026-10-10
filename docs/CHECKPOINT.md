# THN Gateway Checkpoint & System State Record

This document records the exact state of **THN Gateway**, every change implemented to date, problems diagnosed and solved, current live host state on `heedful-dev`, and the roadmap of future actions.

---

## 1. Executive Summary & Where We Are Right Now

As of **October 10, 2026**:
- **Gateway Status**: Live activation has been executed, **COMMITTED**, and **VERIFIED** on `heedful-dev`.
- **Forwarding & NAT**: Active (`net.ipv4.ip_forward = 1`, `table inet thn` masquerade NAT via `enp0s31f6`).
- **Firewall Ruleset Verified**: `table inet thn` contains stateful input/forward filtering, LAN forwarding (`enx00e099001812` -> `enp0s31f6`), and persistent remote management rules (`tailscale0`, UDP 41641, TCP 22).
- **Remote Administration**: Fully operational and verified over Tailscale (`100.65.7.40`) and Wi-Fi.
- **LAN Hardware**: 100 Mbps USB Ethernet adapter (`enx00e099001812`, `hw:2c886f45ad0cb12f`).
- **Policy Classification**: **Approved for this hardware deployment** with an operational caution regarding the 100 Mbps Fast Ethernet line rate (~94 Mbps payload limit).
- **Embedded vs External Services**:
  - DHCP and DNS remain managed by the host `dnsmasq` service (`10.77.0.1`).
  - Traffic shaping remains managed by the host CAKE service (`thn-gateway-restore.service`).
  - THN manages `table inet thn` exclusively, preserving all foreign tables (`ip thn_gateway`, `ufw`, `tailscale`, Docker).

---

## 2. Inventory of Changes Implemented

### Phase 1: Development Scoped Fast Ethernet LAN Exception
- **Problem**: Default production gating strictly refused any sub-Gigabit LAN wired adapter, preventing activation on the user's available 100 Mbps USB adapter.
- **Implementation**:
  - Created `lanPolicy` in [internal/cli/lan_policy.go](internal/cli/lan_policy.go) to encapsulate speed decisions.
  - Added `DevelopmentConfig` in [internal/config/config.go](internal/config/config.go).
  - Added strict validation: an override flag requires an explicit, non-empty list of approved adapters by stable ID (`hw:...`), preventing blanket bypasses.
  - Integrated into `roleGate` in [internal/cli/readiness.go](internal/cli/readiness.go).
  - Added regression test suite in [internal/cli/lan_policy_test.go](internal/cli/lan_policy_test.go).

### Phase 2: Complete Documentation Suite
Authored 12 exhaustive, code-verified technical documentation files under [docs/](docs/):
- `docs/README.md`: Library index and reading orders.
- `docs/ARCHITECTURE.md`: Subsystem boundaries, 6-phase transaction pipeline.
- `docs/HARDWARE_AND_NETWORK.md`: Physical topology, router mode requirement, USB NIC constraints.
- `docs/INSTALLATION.md`: Toolchain, compilation, binary layout, systemd service.
- `docs/CONFIGURATION.md`: Key-by-key schema reference, live validation.
- `docs/ACTIVATION_RUNBOOK.md`: Authoritative preflight, dry-run, live activation runbook.
- `docs/OPERATIONS.md`: Monitoring (`thn monitoring`, `thn clients`), log inspection.
- `docs/TROUBLESHOOTING.md`: Failure symptoms, root causes, remediations.
- `docs/ROLLBACK_AND_RECOVERY.md`: Non-destructive rollback, journal recovery.
- `docs/SECURITY.md`: Threat model, stateful firewall layout, anti-spoofing.
- `docs/FEATURE_STATUS.md`: Implemented vs gated vs external capabilities matrix.
- `docs/DEVELOPMENT.md`: Developer guide, hermetic testing standards.

### Phase 3: Capability Vocabulary Bridge Bug Fix
- **Problem**: Live activation blocked during `PREPARE` with `execution: required system capability is missing: capability nft is unknown`.
- **Root Cause**: Driver operations required tool names (`"nft"`, `"ip"`, `"sysctl"`, `"tc"`), while host discovery recorded system capabilities (`"nftables"`, `"routing"`, `"forwarding"`, `"tc"`). A strict string equality check in [internal/execution/executor.go](internal/execution/executor.go) caused `"nft"` to be rejected.
- **Fix**:
  - Implemented `capabilityMatches()` in [internal/execution/executor.go](internal/execution/executor.go#L603-L623) to bridge tool requirements to system capabilities.
  - Updated `executionOptions` in [internal/cli/activate_production.go](internal/cli/activate_production.go) to project tool-named aliases into the execution context.
  - Added regression test `TestObservedHostCapabilitiesSatisfyRequiredTools` in [internal/execution/executor_transaction_test.go](internal/execution/executor_transaction_test.go).

### Phase 4: `thn activation inspect --config` Flag Parsing
- **Problem**: `thn activation inspect --config <path>` failed when run without root, ignoring the flag and attempting to read `/etc/thn/config.yaml`.
- **Fix**: Updated `runActivationInspect` in [internal/cli/activate.go](internal/cli/activate.go) to parse `--config` flags and positional arguments.

### Phase 5: Tailscale Remote Management Firewall Rule
- **Problem**: Applying `table inet thn` with default input drop dropped `tailscale0` tunnel traffic and UDP port 41641 (WireGuard peering).
- **Fix**: Added explicit rules to `writeInputChain` in [internal/firewall/nft/render.go](internal/firewall/nft/render.go):
  - `iifname "tailscale0" accept`
  - `udp dport 41641 accept`

### Phase 6: Production Approval with 100 Mbps Line-Rate Caution
- **Problem**: The user required the current hardware to be an approved production configuration now, rather than displaying warnings stating *"This host is NOT approved for production deployment"*.
- **Implementation**:
  - Added `activation.approved_fast_ethernet_lan` in [internal/config/config.go](internal/config/config.go).
  - Updated [internal/cli/lan_policy.go](internal/cli/lan_policy.go) to recognize adapters listed under `approved_fast_ethernet_lan` as approved production interfaces.
  - Updated [internal/cli/readiness.go](internal/cli/readiness.go) and [internal/cli/activate.go](internal/cli/activate.go) to report the adapter as `[APPROVED]` with an operational caution/note regarding the ~94 Mbps payload limit.
  - Updated [configs/physical_dell_lab.yaml](configs/physical_dell_lab.yaml) with the approved production block.
  - Added regression test `TestApprovedFastEthernetLANIsApprovedForProduction`.

### Phase 7: Driver Execution Management Protection in `applyTHNTable`
- **Problem**: In live activation, `ProductionDriver.applyTHNTable` constructs `table inet thn` rules directly. When flushed and populated, it lacked `tailscale0`, WireGuard UDP 41641, and SSH port 22 in the input chain.
- **Fix**: Updated `ProductionDriver.applyTHNTable` in [internal/execution/driver_production.go](internal/execution/driver_production.go) and `LinuxDriver.applyTHNTable` in [internal/execution/linux_driver.go](internal/execution/linux_driver.go) to automatically insert:
  - `add rule inet thn input iifname tailscale0 accept`
  - `add rule inet thn input udp dport 41641 accept`
  - `add rule inet thn input tcp dport 22 accept`

### Phase 8: Real Telemetry & Dynamic Client Discovery (Removal of Mock Placeholders)
- **Problem**: `thn clients` and `thn monitoring` displayed hardcoded placeholder devices (`Mom-iPhone`, `Neighbor-PC`), fake RAM (`0 MB / 7 MB`), fake storage (`12 GB / 64 GB`), fake CPU load (`14.2%`), and fake WAN stable IDs. Running without `--config` also threw `permission denied` if `/etc/thn/config.yaml` was root-only.
- **Fix**:
  - Completely removed hardcoded placeholder clients in [internal/management/gather.go](internal/management/gather.go).
  - Implemented live DHCP lease discovery from `/var/lib/misc/dnsmasq.leases` and live kernel ARP parsing from `/proc/net/arp`.
  - Implemented real system telemetry: real RAM from `/proc/meminfo`, real CPU load from `/proc/loadavg`, real root storage from `syscall.Statfs`, and real CPU temperature from `/sys/class/thermal/thermal_zone0/temp`.
  - Added flag parsing (`--config <path>`) to `thn monitoring`, `thn clients`, and `thn events` in [internal/cli/management_commands.go](internal/cli/management_commands.go).
  - Commented out placeholder QoS clients in [configs/physical_dell_lab.yaml](configs/physical_dell_lab.yaml) so only real connected devices appear.

---

## 3. Git Commit History Reference

| Commit | Summary |
|---|---|
| `b9de5e6` | `feat: add development override for Fast Ethernet LAN adapters` |
| `abb278f` | `fix(execution): bridge host system capability vocabulary to execution tool requirements` |
| `7476c2f` | `fix(cli): parse --config flag in activation inspect command` |
| `d877555` | `feat: approve Fast Ethernet LAN adapter for production with 100 Mbps line rate caution` |
| `44159d3` | `fix(firewall): permit Tailscale tunnel and WireGuard port in input chain` |
| `dbd251b` | `docs: add master checkpoint document and update documentation index` |
| `834d3fb` | `fix(execution): add management input rules for Tailscale and SSH in applyTHNTable` |
| `523bc9c` | `fix(management): remove hardcoded mock clients and telemetry, read live dnsmasq leases and system stats` |
| `03ad8c9` | `chore(config): empty placeholder clients list in physical lab configuration` |

---

## 4. Current Configuration on `heedful-dev`

```yaml
schema_version: 1
gateway:
  name: thn-gateway
  generation: 1

network:
  wan: hw:7c6170fd7f34317a
  lan: hw:2c886f45ad0cb12f
  lan_prefix: 10.77.0.1/24
  mtu: 1500

activation:
  require_physical_presence: true
  approved_fast_ethernet_lan:
    - hw:2c886f45ad0cb12f

nat:
  enabled: true
  masquerade:
    enabled: true
    outbound: wan

firewall:
  enabled: true

qos:
  enabled: false   # Handled externally by host CAKE qdisc

dhcp:
  enabled: false   # Handled externally by host dnsmasq service

dns:
  enabled: false   # Handled externally by host dnsmasq service
```

---

## 5. Future Actions & Roadmap Checkpoints

### Immediate Next Steps (Current Sprint - Completed & Verified)
1. **Re-activation on `heedful-dev`**: **COMPLETED & VERIFIED**.
   - Activation committed with result `COMMITTED`.
   - `table inet thn` verified on live host via `nft list table inet thn`.
   - Input chain includes persistent `tailscale0`, UDP 41641, and TCP 22 acceptance.
   - Tailscale connectivity (`100.65.7.40`) and remote SSH confirmed functional.
2. **Post-Activation Verification**:
   - Connect downstream devices (in Router Mode) and verify DHCP lease allocation (`10.77.0.100+`) from `dnsmasq`.
   - Verify DNS resolution via `10.77.0.1` (`dig @10.77.0.1 google.com`).
   - Confirm internet browsing and bandwidth throughput reaching the ~90–94 Mbps line rate.

### Medium-Term Actions (Hardware & Production Hardening)
1. **Gigabit USB 3.0 Adapter Replacement**:
   When upgrading hardware to Gigabit:
   - Attach new adapter and discover stable ID with `thn discover`.
   - Update `network.lan` in `/etc/thn/config.yaml`.
   - Remove `approved_fast_ethernet_lan` to restore default strict Gigabit enforcement.
2. **Administration Source CIDR Hardening**:
   Currently, administration is permitted from any source. Restrict `firewall.admin.source` in `config.yaml` to Tailscale (`100.64.0.0/10`) and local Wi-Fi subnets once external access is tested.

### Long-Term Subsystem Milestones
1. **QoS Subsystem Activation**:
   Complete real-hardware traffic verification to satisfy the 12 physical-enforcement gates and transition CAKE queue discipline management from the external shell script into THN's internal executor (`qos.enabled: true`).
2. **Embedded DHCP & DNS Engines**:
   Implement embedded DHCP and DNS daemon execution if desired to phase out standalone `dnsmasq`.
