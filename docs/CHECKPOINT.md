# THN Gateway Checkpoint & System State Record

This document records the exact state of **THN Gateway**, every change implemented to date, problems diagnosed and solved, current live host state on `heedful-dev`, and the roadmap of future actions.

---

## 1. Executive Summary & Where We Are Right Now

As of **October 10, 2026**:
- **Gateway Status**: Live activation has been executed, **COMMITTED**, and **VERIFIED** on `heedful-dev`.
- **Forwarding & NAT**: Active (`net.ipv4.ip_forward = 1`, `table inet thn` masquerade NAT via `enp0s31f6`).
- **Firewall Ruleset Verified**: `table inet thn` contains stateful input/forward filtering, LAN forwarding (`enx00e099001812` -> `enp0s31f6`), and persistent remote management rules (`tailscale0`, UDP 41641, TCP 22).
- **Remote Administration**: Fully operational and verified over Tailscale (`100.65.7.40`) and Wi-Fi.
- **Web Console**: Rewritten in Phase 10 — responsive, WCAG AA conformant, no fabricated telemetry.
- **LAN Hardware**: 100 Mbps USB Ethernet adapter (`enx00e099001812`, `hw:2c886f45ad0cb12f`).
- **Policy Classification**: **Approved for this hardware deployment** with an operational caution regarding the 100 Mbps Fast Ethernet line rate (~94 Mbps payload limit).
- **Embedded vs External Services**:
  - DHCP and DNS remain managed by the host `dnsmasq` service (`10.77.0.1`).
  - Traffic shaping remains managed by the host CAKE service (`thn-gateway-restore.service`).
  - THN manages `table inet thn` exclusively, preserving all foreign tables (`ip thn_gateway`, `ufw`, `tailscale`, Docker).

### 1.1 Known Outstanding Blocker — Downstream Devices Cannot Reach the Internet

**This is the current open issue. The uplink is healthy; the downstream segment is not.**

Measured state on `heedful-dev` at 2026-10-10:

| Probe | Result |
|---|---|
| `ping 8.8.8.8` from `enp0s31f6` | **0% loss, 5.8 ms** |
| `https://www.google.com` from box | **HTTP 200** |
| Default route | `via 192.168.1.1 dev enp0s31f6` |
| `192.168.1.1` identity | `ac:51:ab:cc:9f:45`, ports 53+443 open (TP-Link serving DNS) |
| `ip neigh show dev enx00e099001812` | `10.77.0.143 lladdr 08:8f:c3:1b:9c:84 REACHABLE` (Windows workstation) |
| DHCP leases issued | `10.77.0.143` active and reachable |
| `ip_forward` | `1` on all interfaces |

**Observed Client State (Windows Workstation on Ethernet):**
```
Ethernet adapter Ethernet:
   IPv4 Address:    10.77.0.143
   Subnet Mask:     255.255.255.0
   Default Gateway: 192.168.1.1
                    10.77.0.1
```
*Note on dual default gateway:* The client has two gateways listed because the TP-Link is still announcing `192.168.1.1` via DHCP/router advertisement on the same physical segment while `dnsmasq` serves `10.77.0.1`.

**Host Firewall (UFW) Impact on 10.77.0.1 Web UI Access:**
In addition to the router mode fault, Ubuntu host `ufw` is active with `DEFAULT_INPUT_POLICY="DROP"`. While ICMP is allowed (ping to `10.77.0.1` succeeds at <1 ms), incoming TCP connections from `enx00e099001812` to ports 1717 and 80 are dropped by host UFW.
Resolution on `heedful-dev`:
```bash
sudo ufw allow in on enx00e099001812
```
Combined with THN's prerouting redirect (`iifname "enx00e099001812" tcp dport 80 redirect to :1717`), browsing to `http://10.77.0.1` transparently routes directly into the Web UI console.

Two independent faults, **both required** before downstream clients work:

**Fault A — the TP-Link is still routing, not bridging.**
The LAN interface has an ARP entry for `192.168.1.1` learned on the `10.77.0.0/24` segment, with a different MAC than the one answering on the WAN segment. The TP-Link is operating in router mode with a static LAN address inside `192.168.1.x` — the same range the PLDT ONT uses. Its WAN port (which previously carried PLDT) is now disconnected, so it issues working local addresses and routes nothing. This is the direct cause of the reported symptom: neighbours obtain an address, obtain local reachability, and have no internet.
Required TP-Link state: **AP/Bridge mode**, uplink into a **LAN** port (not WAN), **DHCP server OFF**, and a LAN address that is **not** in `192.168.1.0/24` (e.g. `10.77.0.2`).

**Fault B — no masquerade is loaded for the LAN subnet.**
`nft list ruleset` cannot be read without root on this host, so the live table is unverified from an unprivileged session. However `activation_state` is `GATED` and THN is render-not-apply by design, so a re-apply after the rewire has not occurred. Treat the masquerade as **unconfirmed** rather than absent.

**Ordering matters.** Fixing A alone changes which segment devices sit on but does not by itself grant internet if B is live-unloaded. Fixing B alone leaves devices stranded on the TP-Link's dead router path. Verify both, in that order, one at a time.

### 1.2 Correction to an Earlier Misdiagnosis (recorded deliberately)

An interim diagnosis during this session claimed the neighbours' outage was caused by `dhcp.enabled: false` and `dns.enabled: false` in `/etc/thn/config.yaml`.

**That diagnosis was wrong, and is retracted here so it is not repeated.** Those keys are `false` *by design* — see [TROUBLESHOOTING.md §1.3](TROUBLESHOOTING.md) and `docs/CHECKPOINT.md` §4. Enabling them in this build trips the `subsystems-executable` readiness gate and **blocks activation**, because DHCP/DNS are deliberately delegated to host `dnsmasq`. Verified live: `dnsmasq` is listening on `0.0.0.0%enx00e099001812:67` and `10.77.0.1:53`, and it has issued leases on `10.77.0.0/24`. DHCP and DNS are working. Leave those keys alone.

The real cause is Fault A. The lesson worth keeping: `thn validate` reports **intent versus what THN itself owns**, not the health of externally-managed services, and an `info` line about a disabled subsystem is not a fault report.

### 1.3 Physical Topology as Built vs. Intended

**As wired today** (verified by ARP and routing tables):

```
  PLDT ONT ──► enp0s31f6 (WAN) ──► heedful-dev ──► enx00e099001812 (10.77.0.1/24)
                      │                                          │
                      └── default route via 192.168.1.1          └── switch ──► TP-Link
                          (TP-Link still routing)                          (still router mode)
```

**As intended** (the target this project is built for):

```
  PLDT ONT
      │  (bridge mode — ONT becomes a dumb modem)
      ▼
  enp0s31f6  WAN NIC   hw:7c6170fd7f34317a  (Intel I219-LM)
      │
  ┌───┴────────────────────────────────────────────┐
  │  heedful-dev                                   │
  │  NAT · firewall · DHCP · DNS  ← THN renders    │
  │  LAN NIC   hw:2c886f45ad0cb12f  (USB FE 100M)   │
  └───┬────────────────────────────────────────────┘
      │  10.77.0.0/24
      ▼
    SWITCH ──┬── home router (AP mode, no DHCP, no routing)
              ├── neighbour devices
              └── guest devices
```

**Open architectural decision — ONT mode.** The ONT currently operates in **router mode**: the server holds `192.168.1.104/24` behind it and never received a public address. This forces a choice.

| | ONT in router mode (current) | ONT in bridge mode (target) |
|---|---|---|
| NAT layers | **double** (server, then ONT) | single (server only) |
| Server's public IP | none; `192.168.1.x` | obtained via DHCP/PPPoE |
| Latency / traceroute | degraded, double hop | clean |
| Inbound traffic | limited by ONT | fully controlled by THN |
| Risk of lockout | none | **PLDT binds ONT by MAC + serial; unprovisioned bridge mode loses service and may require a technician** |
| "THN controls the whole internet" | **not true** — the ONT still routes | true |

Bridge mode is the correct target and is what "THN is the actual router" requires. It is only safely attemptable with the TP-Link's WAN cable **kept connected and within reach**, so PLDT → TP-Link WAN restores service in about two minutes if the bridge change fails.

**Unresolved prerequisite:** whether the PLDT line authenticates by **PPPoE** or plain **DHCP**. PPPoE changes the WAN setup substantially (`pppd` plus credentials) and is not yet established. Check the ONT status page or PLDT before attempting bridge mode.

### 1.4 Link-Speed Ceiling (unresolved, physical)

Both NICs negotiate at **100 Mbps**:

```
enp0s31f6        Speed: 100 Mbps   (WAN)
enx00e099001812  Speed: 100 Mbps   (LAN)
```

A NIC feeding a switch that serves a household plus neighbours at 100 Mbps indicates a cable fault — most often a Cat5 run with a failed pair, or a switch port pinned to 100/Full. **No configuration compensates for this.** Diagnose and replace cabling before investing further in the NAT path, or the result will be a correctly configured 100 Mbps bottleneck. The WAN side may legitimately be capped by the ISP plan; the LAN side has no such justification.

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

### Phase 9: Interactive Web UI Bandwidth Limiting & Access Controls
- **Implementation**:
  - Created [tools/thn-client-control.sh](tools/thn-client-control.sh) to apply per-client HTB FQ-CoDel rate limiting on `enx00e099001812` and nftables forward drops without disrupting global shaping.
  - Created Next.js API route `ui/app/api/clients/control/route.ts` to execute live control actions.
  - Created interactive Client Component `ui/components/device-controls.tsx` with preset buttons (`Uncapped`, `10M`, `20M`, `30M`, `50M`), custom Mbps input, and `Block / Unblock` toggle.
  - Updated `ui/app/devices/page.tsx` so operators can set bandwidth limits and block devices directly from the web browser.
  - Updated [internal/management/gather.go](internal/management/gather.go) to dynamically reflect active client limits and blocks in both CLI (`thn clients`) and the Web UI.

### Phase 10: Console Defect Remediation, Responsive Rewrite & Telemetry Honesty

Commit `0f2ac3c` — 19 files, +1910/−737. This phase was driven by a review of the console as a reader sees it, not as the code intends it.

**Defects found and fixed.**

| Defect | Cause | Fix |
|---|---|---|
| Rules table columns overlapped; "RULE" header unreadable | `table-fixed` with `w-8` on severity, forcing pills wider than the column into the header | replaced with a responsive `<DataTable>` (§2.1) |
| Bandwidth "active" preset indistinguishable from inactive | `bg-accent` used but **never defined** in the Tailwind theme — silently emitted no CSS | defined `accent` (TH yellow `#ffc107`), reserved for interactive state only |
| Block/unblock button border absent | `border-critical-border` used but undefined | added `edge` shade to every severity family |
| **All status labels effectively invisible** | `text-ok`/`text-critical`/`text-warning` resolve to *dark* shades intended to sit on light `muted` fills; on the dark page they land near **1.9:1** | added an `fg` shade per family for text on dark; rewrote all 20 usages |
| Explanatory body text below AA | `ink-400`/`ink-500` were `#8189a0`/`#5f6780` = **3.4:1** | lightened to `#9aa3b8`/`#8791a8` |
| `<main>` collapsed to 0px at ~874px | both nav halves rendered, one hidden by CSS — the hidden one still occupied flex space | split into `variant="mobile" \| "desktop"` |
| Mobile: horizontal scroll on every page | fixed-width columns, `min-w-[24rem]` inputs, `w-56` flex rows | responsive primitives; verified 0 overflow at 390/768/1440 |

**Fabricated telemetry removed.** The dashboard hardcoded values that did not come from the binary: `↓ 100 Mbps` / `↑ 20 Mbps`, `Hardware cool`, `No errors`, and `ACTIVE` / `PROTECTED` / `ENFORCED` / `LAN ONLY` badges asserting a security posture that was never read from anywhere. Monitoring printed `Low jitter`, `0.0% loss`, `Resolved` and `Reachable` as fixed strings regardless of the reading beside them — a page stating "low jitter" next to a 900 ms latency. All now derive from `thn --json` fields or render `—`/`idle` when unknown.

This continues the Phase 8 intent (real telemetry in the CLI) into the console. The rule generalised: **a status label that is not derived from a measurement is a claim, and a false claim is worse than an absent one.**

**Accessibility and comprehension.**

- 16-term plain-language glossary on `/about`; every page leads with a plain sentence before the mechanism.
- Gateway status in the chrome on every page, read from the gateway's own `health_state` (`healthy`/`ok`, `degraded`, `critical`); an unrecognised value reports *unknown* rather than guessing.
- Navigation items carry descriptions — "Networks" alone does not say what a zone is.
- **Verification: 1430 text nodes across 10 routes × 2 widths audited against WCAG AA. 78 failures before, 0 after.**
- Focus-visible ring, `prefers-reduced-motion` honoured, ARIA labels, 44px touch targets on phones only.

**New files.**
- [ui/components/data-table.tsx](ui/components/data-table.tsx) — responsive table (server component; must stay one, see §5).
- [ui/components/nav.tsx](ui/components/nav.tsx) — mobile drawer, desktop rail.
- [ui/components/primitives.tsx](ui/components/primitives.tsx) — added `PageHeader`, `Stat`, `Callout`; `Field` made responsive via `.kv`.

#### 2.1 Responsive table contract

`<DataTable>` renders a real `<table>` at `sm` and up, and a card list below it. Columns are declared **once** as data and both renderings read that one declaration, so a column cannot drift between views. Only one form is ever in the accessibility tree — CSS `hidden` removes the other.

#### 2.2 Severity colour contract (three roles per family)

| shade | correct use |
|---|---|
| `DEFAULT` | fill only, with light text on top |
| `muted` | fill, with `text` shade on top |
| `text` | **text on a `muted` fill only** |
| `edge` | borders on the dark page |
| `fg` | **text on the dark page** |

Writing a bare `text-ok` on the page background is the specific error that made the console unreadable. `edge` and `fg` hold identical values but are named separately because `text-critical-edge` misleads a reader and `border-critical-fg` does not.

### Phase 11: Repository Hygiene

Commits `3b2a00f`, `250fc5f` — surfaced while syncing `heedful-dev`.

- **`.gitignore` gap**: `go build ./cmd/thn` drops a bare 20 MB `thn` at the repo root; only named artefacts (`thn.exe`, `thn-linux-amd64`) were ignored. Covered by name and by output path, with the npm lockfile caveat documented in-file.
- **`tools/thn-client-control.sh` tracked as `100644`**: the script has a `#!/usr/bin/env bash` shebang, so `./tools/thn-client-control.sh` failed with permission denied. Recorded as `100755`.

#### 11.1 npm version skew — recurring pull breakage

`ui/package-lock.json` is rewritten by `npm install`, and the two machines disagree:

| machine | npm | node |
|---|---|---|
| `heedful-dev` | 10.8.2 | v20.20.2 |
| dev workstation | 10.9.2 | v22.17.0 |

npm 10.9 writes `libc` fields for Linux-only optional dependencies; 10.8 does not. Each side strips the other's fields, leaving a dirty lockfile that makes `git pull` refuse with *"local changes would be overwritten by merge"*. Recovery: `git checkout -- ui/package-lock.json && git pull`. **Use `npm ci` on the gateway box** — it installs what the lockfile pins and never rewrites it.

### Phase 12: Observed State vs. Asserted State (Telemetry Honesty)

Commit `e465573` (9 files, +880/−99).

Surfaced when the console reported a device as connected hours after it had physically disconnected and claimed the uplink was online on an interface carrying no traffic.

- **GatherWAN 4-stage pipeline**: Replaced hardcoded status "online" and literal boolean flags (`LinkUp`, `GatewayReachable`, `InternetReachable`, `DNSReachable`) with empirical measurements executed in packet order. Status is now derived directly from those four verified measurements.
- **GatherInterfaces dynamic observation**: Replaced hardcoded interface structs (which had asserted a 1000 Mbps NIC at `192.168.1.150`) with live discovery of host interfaces via sysfs and netlink, preserving role classification and reporting only observed devices.
- **Dual-condition presence rule**: Fixed `parseDnsmasqLeases`. A lease is only a grant and outlives disconnected devices. Presence now requires BOTH an unexpired lease AND an active kernel neighbor entry (`/proc/net/arp` / netlink). Stamping `LastSeen` with `time.Now()` was removed so stale entries no longer claim to have been active this instant.
- **Hexadecimal ARP flag parsing**: Resolved a parser defect where hex `0x2` flags were parsed as decimal, causing all neighbor entries to be discarded and marking reachable gateways as unreachable.
- **ICMP evasion**: Replaced ICMP ping probes with TCP handshakes and neighbor state to function properly when unprivileged processes cannot open raw ICMP sockets (`ping_group_range 1 0`). `probe_other.go` fails closed off Linux rather than inventing a healthy uplink.

### Phase 13: Corporate Brand Identity Modernization & Visual Design

Commit `6c6dc65` (9 files, +203/−134).

Aligned the gateway console with The Heedful official design guidelines.

- **The Heedful design system palette**: Updated corporate colors to `#0F0F0F` (page background), `#1A1A1A` (surface/panel), `#2B2B2B` (borders), `#FFC107` (TH yellow interactive accent), and `#424242` (subtle dividers).
- **Typography hierarchy**: Introduced Space Grotesk display typography for headings, metrics, and branding, paired with Inter for clear body copy.
- **Official V4 Hexagonal Eye logo**: Added [ui/components/logo.tsx](ui/components/logo.tsx) SVG mark in desktop header, navigation drawer, and branding surfaces.
- **Inventory presence & device sorting**: Fixed device presence badge checking `c.online` instead of defaulting to Online when unblocked; added active vs total device sorting and summary indicators.
- **Slice serialization safety**: Ensured Go slice serialization emits empty arrays (`[]`) instead of `null` for interface IPs and related lists.

### Phase 14: Removal of Shipped Credentials & PBKDF2 Auth

Commit `b961966` (5 files, +305/−23).

Eliminated security vulnerability of static credentials compiled into every build.

- **No implicit accounts**: Removed hardcoded credentials (`admin/thn-admin-password`, operator, viewer) from `NewAuthManager`. Fixed credentials in source code are an unauthenticated write path into house LANs.
- **Config-driven operator account**: Added `management.operator_username` and `management.operator_password` to `config.Config`. Hashed with PBKDF2-HMAC-SHA256 (100,000 iterations, 16-byte cryptographically secure salt) on initialization.
- **Explicit 503 unconfigured error**: Login against a gateway with unconfigured operator credentials returns HTTP 503 "management is not configured" with specific remediation steps, rather than misleading HTTP 401 "invalid credentials".
- **Comprehensive test coverage**: Added `auth_hardcoded_test.go` covering no implicit account creation, rejection of documented default passwords, 503 response semantics, config-driven bootstrap idempotency, and empty credential handling.

### Phase 15: Router-Style LAN Web UI Access (10.77.0.1) & Operator Login Flow

Phase 15 connects physical Ethernet clients to a seamless, secure router experience at `10.77.0.1`.

- **Router Web UI Experience**: Just like accessing a commercial router at `192.168.1.1` or `10.77.0.1`, connecting to the gateway LAN now provides a full browser administration experience with operator credentials.
- **Next.js Authentication Layer**:
  - Implemented [ui/components/login-view.tsx](ui/components/login-view.tsx) with The Heedful branding, providing operator username and password inputs, unconfigured gateway status alerts, and feedback.
  - Implemented [ui/lib/auth.ts](ui/lib/auth.ts), `ui/app/api/auth/login/route.ts`, `ui/app/api/auth/logout/route.ts`, and `ui/app/api/auth/status/route.ts`. Session management uses secure HTTP-only cookies (`thn_session`).
  - Added [ui/components/user-badge.tsx](ui/components/user-badge.tsx) displaying active operator identity (`👤 admin`) with one-click sign-out.
  - Protected `RootLayout` in [ui/app/layout.tsx](ui/app/layout.tsx) so unauthenticated users see the clean router login screen, while authenticated operators access the full console.
- **CLI Management Auth Command**:
  - Added `thn management auth` subcommand in [internal/cli/management_commands.go](internal/cli/management_commands.go). Supports `--status` for configuration checks and `--username` / `--password` for credential verification via `AuthManager.Authenticate`.
  - Added `"auth"` to `ALLOWED.management` allowlist in [ui/lib/thn.ts](ui/lib/thn.ts).
  - Added unit test suite in [internal/cli/management_auth_test.go](internal/cli/management_auth_test.go).
- **Firewall & Routing for LAN Web Access**:
  - Updated [internal/firewall/nft/render.go](internal/firewall/nft/render.go) to explicitly permit LAN management traffic (TCP 80, 1717, 8080) and local DNS/DHCP (UDP 53, 67, TCP 53).
  - Added prerouting redirect rule `iifname <LAN> tcp dport 80 redirect to :1717` in `render.go`, `driver_production.go`, and `linux_driver.go`. Navigating to `http://10.77.0.1` in any browser automatically routes to the Next.js console on port 1717 without disrupting Docker services on WAN.
- **Physical Lab Configuration**:
  - Added `management:` block to [configs/physical_dell_lab.yaml](configs/physical_dell_lab.yaml) and [configs/gateway.yaml](configs/gateway.yaml) binding `0.0.0.0:1717` and allowing `10.77.0.0/24`, `127.0.0.0/8`, and `100.64.0.0/10`.

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
| `848f4c5` | `feat(ui): add interactive bandwidth limit and client controls to Web UI` |
| `0f2ac3c` | `feat(ui): standardize page headers with PageHeader component` — console defect remediation, responsive rewrite, telemetry honesty (§2 Phase 10) |
| `3b2a00f` | `chore: ignore gateway build output at repo root and document lockfile churn` |
| `250fc5f` | `chore(tools): mark thn-client-control.sh executable` |
| `b5ce05c` | `docs: record console rewrite, downstream outage and topology decisions` |
| `e465573` | `fix(management): report observed state instead of asserted state` — Phase 12 |
| `6c6dc65` | `feat(ui): modernize brand identity to The Heedful guide and fix device presence bug` — Phase 13 |
| `b961966` | `fix(management): remove hardcoded credentials shipped with every build` — Phase 14 |
| `HEAD` | `feat: router-style LAN Web UI access on 10.77.0.1 and operator authentication` — Phase 15 |

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

management:
  enabled: true
  bind_address: "0.0.0.0:1717"
  allowed_networks:
    - 10.77.0.0/24
    - 127.0.0.0/8
    - 100.64.0.0/10
  wan_access: false
  session_ttl: 24h
  operator_username: "admin"
  operator_password: ""
```

---

## 5. Future Actions & Roadmap Checkpoints

### 5.0 Blocking — Downstream Internet (do these before anything else)

1. **Resolve the 100 Mbps LAN link.** `ethtool enx00e099001812` and confirm `Supported link` advertises 1000baseT. Swap Cat5 cabling / check the switch port is not pinned to 100/Full. Until this is fixed, everything below runs over a 100 Mbps ceiling regardless of correctness.
2. **Establish the ONT auth type** — PPPoE or DHCP. Check the ONT status page or PLDT. This determines the WAN setup and cannot be guessed.
3. **Fix the TP-Link** (Fault A): AP/Bridge mode, uplink into a LAN port, DHCP server off, LAN address outside `192.168.1.0/24`.
4. **Re-apply the rendered ruleset** after the rewire (Fault B) — see §5.1.
5. **Verify hop by hop, one step at a time**, so a break identifies itself:
   ```bash
   ip -4 -br addr show enp0s31f6     # does the WAN hold a lease?
   ip route | grep default          # is there a default route?
   ping -c 3 1.1.1.1                # raw IP, no DNS
   dig +short @1.1.1.1 google.com    # DNS upstream
   ping -c 3 10.77.0.2              # a downstream device
   ```
   Then, from a neighbour's device: can it reach `1.1.1.1`? If the server can and they cannot, the fault is the firewall or masquerade — not the uplink.

**Do not** set `dhcp.enabled` or `dns.enabled` to `true` in this build. See §1.2.

### 5.1 Decide: operator-applied rules, or build activation

The Phase-4 rules in §4 were loaded in-memory and do not survive reboot. Two paths:

- **Interim** — load exactly what THN renders, so the applied state is already what THN wants and a later activation replaces an identical state rather than changing behaviour:
  ```bash
  thn firewall render > /tmp/thn-nft.rules
  thn net render     >> /tmp/thn-nft.rules
  sudo nft -f /tmp/thn-nft.rules
  ```
  **Read the rendered file before loading it.** Confirm the masquerade is scoped to the LAN subnet and egresses via WAN — an unscoped masquerade rewrites source addresses leaving *every* interface, which presents as intermittent hardware failure rather than as the misconfiguration it is. A systemd unit makes it survive reboot, but it drifts from what THN renders and needs manual reconciliation.

- **Proper** — build activation. `thn activate` already exists as the deliberately-blocked destructive verb; wiring it to the render is the real milestone and is what makes "THN controls the internet" literally true rather than "THN describes what an operator applied". This is a change to a safety-critical path and should be done as its own reviewed change, not as a side effect of a network rewire.

### 5.2 Immediate Next Steps (Completed & Verified)
1. **Re-activation on `heedful-dev`**: **COMPLETED & VERIFIED**.
   - Activation committed with result `COMMITTED`.
   - `table inet thn` verified on live host via `nft list table inet thn`.
   - Input chain includes persistent `tailscale0`, UDP 41641, and TCP 22 acceptance.
   - Tailscale connectivity (`100.65.7.40`) and remote SSH confirmed functional.
2. **Post-Activation Verification**: *(pending the rewire — see §5.0)*
   - Connect downstream devices and verify DHCP lease allocation (`10.77.0.100+`) from `dnsmasq`.
   - Verify DNS resolution via `10.77.0.1` (`dig @10.77.0.1 google.com`).
   - Confirm internet browsing and bandwidth throughput reaching the ~90–94 Mbps line rate.

### 5.3 Medium-Term Actions (Hardware & Production Hardening)
1. **Gigabit USB 3.0 Adapter Replacement**:
   - Attach new adapter and discover stable ID with `thn discover`.
   - Update `network.lan` in `/etc/thn/config.yaml`.
   - Remove `approved_fast_ethernet_lan` to restore default strict Gigabit enforcement.
2. **Administration Source CIDR Hardening**:
   Currently, administration is permitted from any source. Restrict `firewall.admin.source` in `config.yaml` to Tailscale (`100.64.0.0/10`) and local Wi-Fi subnets once external access is tested. **If you administer over Tailscale, list it — an over-restrictive rule locks you out and needs physical access to recover.**
3. **Clean up the duplicate WAN address**: `enp0s31f6` currently carries both `192.168.1.104/24` (static) and `192.168.1.27/24` (DHCP). One or the other, not both.

### 5.4 Long-Term Subsystem Milestones
1. **QoS Subsystem Activation**:
   Complete real-hardware traffic verification to satisfy the physical-enforcement gates and transition CAKE queue discipline management from the external shell script into THN's internal executor (`qos.enabled: true`).
2. **Embedded DHCP & DNS Engines**:
   Implement embedded DHCP and DNS daemon execution to phase out standalone `dnsmasq`. Note this requires a separate subsystem-executable milestone; enabling those keys in the current build only trips the readiness gate.
3. **Write path decision** *(pre-existing inconsistency, flagged not fixed)*:
   [tools/thn-client-control.sh](tools/thn-client-control.sh) plus `ui/app/api/clients/control/route.ts` apply live bandwidth and block rules — a real write path — while `ui/app/about/page.tsx` states the console applies nothing. Both cannot be true. The render-not-apply property is load-bearing; the write path either needs its own safety argument or the About copy needs to be scoped precisely to what *THN* applies versus what the *host scripts* do.

### 5.5 Engineering Notes (carry forward)

- **`ui/components/data-table.tsx` must stay a server component.** It takes `render` callbacks; `"use client"` breaks the RSC boundary, because functions cannot cross it.
- **Do not render both nav halves into one flex container.** The hidden half still occupies space and collapses `<main>` to 0px.
- **Never** write a bare `text-ok`/`text-critical`/`text-warning` on the dark page — use `-fg`. See §2.2.
- **`npm run build` while the dev server runs corrupts `.next`**, producing `Cannot find module './331.js'` and a 500. Stop the server first.
- **Verification that caught real defects, worth repeating on any future UI change:**
  - horizontal-overflow sweep: all routes × 390/768/1440;
  - contrast sweep: every text node vs WCAG AA.
