# THN Gateway Architecture & System Boundaries

This document defines the architectural design, execution pipeline, state management, and isolation boundaries of **THN Gateway**.

---

## 1. Architectural Overview & Design Philosophy

THN Gateway is designed as a **fail-closed, transactional network appliance controller** for Linux systems. Rather than running a long-lived, opaque daemon that continuously rewrites host configuration, THN uses an explicit, staged transaction engine:

```mermaid
flowchart TD
    Config[Configuration /etc/thn/config.yaml] --> Load[Config Loader & Validator]
    Host[Host Observation rtnetlink / sysfs] --> Observe[Hardware & Subsystem Discovery]

    Load --> Gates[13 Activation Safety Gates]
    Observe --> Gates

    Gates -->|All Satisfied| Plan[Planner: Desired vs Observed Diff]
    Gates -->|Any Blocked| Refusal[Strict Activation Refusal: Network Untouched]

    Plan --> Preconditions[Precondition Validation]
    Preconditions --> Executor[6-Phase Transactional Executor]

    subgraph Execution Transaction
        Phase1[1. PREPARE: Digests & Auth] --> Phase2[2. BACKUP: Baseline Capture]
        Phase2 --> Phase3[3. VALIDATE: Syntactic Ruleset Check]
        Phase3 --> Phase4[4. APPLY: Atomic Driver Execution]
        Phase4 --> Phase5[5. HEALTH_CHECK: Verification Probes]
        Phase5 -->|Pass| Phase6[6. COMMIT: Transaction Journal Recorded]
        Phase5 -->|Fail| Rollback[Atomic Rollback: Compensating Ops]
    end

    Executor --> Execution Transaction
```

### Key Engineering Principles
- **Separation of Modeling and Execution**: The system can fully model, diff, simulate, and validate network state in pure memory without requiring root privileges or touching the kernel.
- **Explicit Operator Authorization**: Production activation requires physical presence confirmation (`--confirm-present`) and deliberate authorization (`--confirm`). No convenience flag (such as `--yes`) can bypass these checks.
- **Fail-Closed Execution**: If any assumption, digest, or capability check fails during the transaction, the engine halts immediately and executes compensating rollback operations.
- **Strict Table Isolation**: THN only creates and mutates its own isolated nftables table (`table inet thn`). It never executes broad flushes (`nft flush ruleset`).

---

## 2. Command Tiers & Privilege Separation

The CLI commands are categorized into three distinct execution tiers (see `internal/cli/commands.go`):

| Tier | Characteristics | Root Required? | Modifies Network? | Example Commands |
|---|---|---|---|---|
| **`pure`** | Runs entirely in-process; models state, parses documents, performs calculations, or checks syntax. | No | No | `thn validate`, `thn plan`, `thn firewall render`, `thn readiness`, `thn discover` |
| **`live`** | Queries host subsystems or reads telemetry through read-only inspection. | No (read-only) | No | `thn status`, `thn diagnostics`, `thn monitoring` |
| **`destructive`** | Applies state changes to the host kernel; requires confirmation flags and root execution. | Yes (`sudo`) | Yes (managed table only) | `thn activate --confirm --confirm-present` |

---

## 3. Subsystem Architecture

### 3.1 Host Discovery (`internal/host`)
- Reads interface definitions, MAC addresses, link states, MTU, carrier speed, and driver information directly from `/sys/class/net/` and `rtnetlink`.
- Assigns **stable hardware identities** (`hw:<sha256(kind+mac)>[:16]`). An interface's stable ID never changes even if systemd or the kernel renames the network device (e.g., between `enx00e0...` and `eth1`).
- Identifies kernel capabilities (`cap:routing`, `cap:nat`, `cap:qos`, `cap:firewall`).

### 3.2 Configuration Engine (`internal/config`)
- Loads `/etc/thn/config.yaml` or user-specified path.
- Enforces structural validation, schema versioning, CIDR prefix sanity, and role consistency.
- Enforces development override constraints: an active development flag requires an explicit, non-empty list of approved interface identities.

### 3.3 Safety Gating (`internal/activation`)
Before any activation plan is executed, 13 safety gates are evaluated by `EvaluateProduction`:

1. `plan-validated`: Plan exists, is fresh, and contains zero blocking preconditions.
2. `config-valid`: Configuration file passes all structural schema validations.
3. `capabilities-observed`: Required kernel capabilities (routing, NAT, packet filtering) are directly observed, not merely inferred.
4. `digests-fresh`: Plan digests (observed, desired, assignment) match current live state.
5. `management-safety`: The proposed change will not sever SSH, Tailscale, or the local management path.
6. `subsystems-executable`: All requested subsystems have executable drivers in this build (enforces that `dhcp`, `dns`, and `qos` are disabled).
7. `recoverable`: Automatic compensating rollback operations are computed and available.
8. `physical-presence`: Physical presence has been confirmed by the operator.
9. `wan-present`: WAN interface is identified, physically attached, and capable.
10. `lan-identified`: LAN interface is identified, attached, and meets link speed criteria (Gigabit in production, or explicitly approved Fast Ethernet under development override).
11. `no-role-conflicts`: WAN, LAN, and Management roles are mapped to distinct physical interfaces.
12. `host-readiness`: Operating system platform and kernel version meet gateway prerequisites.
13. `apply-capable`: The build and driver support execution (`CanApply() == true`).

### 3.4 6-Phase Transactional Executor (`internal/execution`)
When activation is authorized, `Executor.ExecutePlan` runs through six sequential phases:

1. **`PREPARE`**: Checks transaction journal for prior crashes, validates input digests, and verifies management safety.
2. **`BACKUP`**: Captures a pre-execution baseline snapshot of the host state (sysctl, interface states, addresses, existing qdiscs).
3. **`VALIDATE`**: Validates structured operations syntactically before touching the host.
4. **`APPLY`**: Executes individual driver operations sequentially. Each applied operation is appended to the transaction journal.
5. **`HEALTH_CHECK`**: Runs active health verification probes (verifying `net.ipv4.ip_forward`, checking table existence, confirming carrier state).
6. **`COMMIT`**: Marks the transaction complete in `/var/lib/thn/activation-journal.json`.

If any operation in Phase 4 fails, or if health verification in Phase 5 fails, the engine transitions immediately to **Rollback**, applying compensating operations in reverse order.

---

## 4. Host & Network Isolation Model

THN Gateway operates alongside existing host services. Understanding these boundaries prevents accidental disruption:

```
┌────────────────────────────────────────────────────────────────────────┐
│                              Linux Kernel                              │
│                                                                        │
│  Sysctl: net.ipv4.ip_forward = 1                                       │
│                                                                        │
│  ┌─────────────────────────┐        ┌───────────────────────────────┐  │
│  │     nftables Engine     │        │          Traffic Shaping      │  │
│  │                         │        │                               │  │
│  │  table inet thn         │        │  External CAKE qdisc          │  │
│  │  (Managed by THN)       │        │  (Managed by Host Service)    │  │
│  │                         │        │                               │  │
│  │  table ip thn_gateway   │        │  THN Internal QoS             │  │
│  │  (Host Gateway Table)   │        │  (Disabled in config)         │  │
│  │                         │        └───────────────────────────────┘  │
│  │  table inet ufw         │                                           │
│  │  (Host UFW Service)     │        ┌───────────────────────────────┐  │
│  │                         │        │        DHCP & DNS Services    │  │
│  │  table ip tailscale     │        │                               │  │
│  │  (Tailscale VPN)        │        │  dnsmasq (Host Service)       │  │
│  └─────────────────────────┘        │  Port 53 (DNS), Port 67 (DHCP)│  │
│                                     │                               │  │
│                                     │  THN DHCP & DNS               │  │
│                                     │  (Disabled in config)         │  │
│                                     └───────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Table Isolation
- **`table inet thn` (THN Gateway)**: Created and managed exclusively by THN. Contains base chains `input`, `forward`, `prerouting`, and `postrouting`.
- **`table ip thn_gateway` (Host Gateway Restore)**: Managed by `/usr/local/sbin/thn-gateway-restore` and systemd. Operates in the `ip` family (IPv4-only), separate from THN's `inet` family table.
- **`table inet ufw` (Host UFW)**: Host firewall rules for local service access. Preserved by THN.
- **Foreign Tables**: Tailscale, WireGuard, Docker, and bridge tables are detected and preserved. THN never executes `nft flush ruleset`.

### Service Boundaries (DHCP, DNS, QoS)
- **DHCP & DNS**: THN Gateway does **not** run embedded DHCP or DNS daemon servers. In `/etc/thn/config.yaml`, `dhcp.enabled: false` and `dns.enabled: false` are mandatory. The host runs `dnsmasq` (`/etc/dnsmasq.d/thn-gateway.conf`) to serve DHCP leases (`10.77.0.100-250`) and DNS lookups on `10.77.0.1`.
- **Traffic Shaping (QoS)**: THN's internal QoS subsystem is gated from production activation (`qos.enabled: false`). External CAKE traffic shaping is applied independently by the host service `/usr/local/sbin/thn-gateway-restore`.

---

## 5. State & Data Storage Locations

| Path | Purpose | Format | Permissions |
|---|---|---|---|
| `/etc/thn/config.yaml` | Primary gateway configuration | YAML | `0644 root:root` |
| `/var/lib/thn/state.db` | Local state database (interface bindings, inventory) | SQLite | `0600 root:root` |
| `/var/lib/thn/activation-journal.json` | Active or last execution transaction journal | JSON | `0600 root:root` |
| `/run/thn/thn.sock` | Daemon IPC socket (when `thnd` is running) | UNIX domain socket | `0660 root:root` |
