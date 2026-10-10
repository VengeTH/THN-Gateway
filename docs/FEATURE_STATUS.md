# Feature Implementation & Subsystem Status Matrix

This document provides a realistic, code-verified audit of the capabilities in **THN Gateway**.

> **CORE PRINCIPLE:**
> Never document a feature as working solely because the configuration validator accepts its keys. This document distinguishes what is verified in the execution engine versus what exists only as configuration intent or is blocked by production gates.

---

## 1. Subsystem Capability Matrix

| Subsystem / Capability | Implementation Status | Backing Code Location | Operational Reality on `heedful-dev` |
|---|---|---|---|
| **Host & Hardware Discovery** | **Implemented & Tested** | `internal/host/` | Discovers interfaces, speeds, carrier states, and stable IDs (`hw:...`). |
| **Stable Hardware Identities** | **Implemented & Tested** | `internal/host/host.go` | Hash derived from MAC and kind; survives reboots and device renames. |
| **Configuration Engine & Validation** | **Implemented & Tested** | `internal/config/` | Strict schema validation, CIDR checks, and role collision detection. |
| **13 Production Safety Gates** | **Implemented & Tested** | `internal/activation/` | Fail-closed evaluation in `EvaluateProduction()`. |
| **Development Fast Ethernet Override** | **Implemented & Tested** | `internal/cli/lan_policy.go` | Opt-in override permitting named 100 Mbps LAN adapter for lab use. |
| **6-Phase Transactional Executor** | **Implemented & Tested** | `internal/execution/` | `PREPARE -> BACKUP -> VALIDATE -> APPLY -> HEALTH_CHECK -> COMMIT`. |
| **Automatic Atomic Rollback** | **Implemented & Tested** | `internal/execution/executor.go` | Reverses applied operations in reverse order if apply or health check fails. |
| **Crash Recovery Journaling** | **Implemented & Tested** | `internal/execution/journal.go` | `/var/lib/thn/activation-journal.json` tracks in-flight transactions. |
| **nftables Forwarding & NAT** | **Implemented & Tested** | `internal/firewall/nft/` | Renders and applies `table inet thn` (masquerade, drop by default). |
| **Foreign Table Protection** | **Implemented & Tested** | `internal/execution/` | Preserves `table ip thn_gateway`, `ufw`, `tailscale`, and Docker. |
| **Physical Presence Gating** | **Implemented & Tested** | `internal/activation/` | Enforces `--confirm-present` alongside `--confirm`. |
| **Client Inventory Tracking** | **Implemented & Tested** | `internal/cli/` | `thn clients` reports observed MACs and IP mappings. |
| **QoS / Traffic Shaping (THN Internal)** | **Modeled; Gated from Production** | `internal/qos/`, `internal/cli/activate_production.go` | Fully modeled and tested in netns, but **blocked from production activation** by safety gates. External CAKE is used. |
| **DHCP Server (Embedded)** | **Configuration Intent Only** | `internal/dhcp/`, `internal/cli/activate_production.go` | Modeled and planned in memory; **not implemented in execution layer**. Activation blocks if enabled. External `dnsmasq` is used. |
| **DNS Resolver (Embedded)** | **Configuration Intent Only** | `internal/dns/`, `internal/cli/activate_production.go` | Modeled and planned in memory; **not implemented in execution layer**. Activation blocks if enabled. External `dnsmasq` is used. |
| **Multi-WAN Routing** | **Partial (Single-WAN active)** | `internal/multiwan/` | Single-WAN default is active. Policy-based multi-uplink routing requires verified routing table operations. |
| **Billing & Accounting** | **Not Implemented** | N/A | No billing ledger, automated expiration timers, or payment gateways exist. |
| **Captive Portal / Vouchers** | **Not Implemented** | N/A | No splash page, voucher generation, or radius captive portal engine exists. |

---

## 2. Subsystems Managed Externally on This Host

To ensure stable gateway operations on `heedful-dev`, three responsibilities are delegated to host-native services:

### 2.1 DHCP Lease Allocation (`dnsmasq`)
- **Status in THN**: `dhcp.enabled: false`. If set to `true`, the `subsystems-executable` gate refuses activation.
- **Host Reality**: The host-managed `dnsmasq` service (`/etc/dnsmasq.d/thn-gateway.conf`) listens on `10.77.0.1:67` and distributes dynamic IPv4 leases (`10.77.0.100`–`10.77.0.250`).

### 2.2 Local DNS Resolution (`dnsmasq`)
- **Status in THN**: `dns.enabled: false`. If set to `true`, the `subsystems-executable` gate refuses activation.
- **Host Reality**: `dnsmasq` listens on `10.77.0.1:53` and forwards queries upstream to `1.1.1.1` and `9.9.9.9`.

### 2.3 Traffic Shaping & Bufferbloat Mitigation (CAKE)
- **Status in THN**: `qos.enabled: false`. THN's internal QoS applier is locked until real-hardware multi-tenant validation criteria are signed off.
- **Host Reality**: The host script `/usr/local/sbin/thn-gateway-restore` and `thn-gateway-restore.service` install a CAKE qdisc on the uplink to eliminate bufferbloat independently of THN.
