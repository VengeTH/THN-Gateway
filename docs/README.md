# THN Gateway Documentation Library

Welcome to the authoritative technical documentation for **THN Gateway**. This library covers end-to-end design, installation, configuration, physical activation, operations, recovery, and security for running THN Gateway on Linux systems (specifically targeting Ubuntu Server).

---

## 1. Documentation Index & Recommended Reading Order

Select your reading path depending on your immediate objective:

### Path A: Physical Deployment & Immediate Operations (Fastest Path to Activation)
If your primary goal is to safely inspect, dry-run, and activate THN Gateway on your current host:

1. [docs/HARDWARE_AND_NETWORK.md](docs/HARDWARE_AND_NETWORK.md) — Review physical topology, interface mappings, and the 100 Mbps Fast Ethernet constraints.
2. [docs/FEATURE_STATUS.md](docs/FEATURE_STATUS.md) — Understand which features are active versus externally managed (`dnsmasq` for DHCP/DNS, external CAKE).
3. [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — Set up and validate `/etc/thn/config.yaml` with the development override.
4. [docs/ACTIVATION_RUNBOOK.md](docs/ACTIVATION_RUNBOOK.md) — **Authoritative step-by-step activation guide**: baseline capture, inspection, dry-run, live activation, and verification.
5. [docs/ROLLBACK_AND_RECOVERY.md](docs/ROLLBACK_AND_RECOVERY.md) — Keep open as emergency reference if any health check fails.

### Path B: System Administrator & Day-2 Operations
If you need to administer, monitor, and troubleshoot an active gateway:

1. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Structural boundaries, nftables table isolation, and transaction engine.
2. [docs/OPERATIONS.md](docs/OPERATIONS.md) — Day-2 monitoring, client inventory, logging, and safe maintenance.
3. [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — Scenario-based diagnostics and remediation procedures.
4. [docs/SECURITY.md](docs/SECURITY.md) — Threat model, administrative access boundaries, and anti-spoofing rules.

### Path C: Software Engineering & Development
If you are developing new subsystems, writing tests, or extending CLI commands:

1. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — Core pipeline (`observe -> model -> plan -> validate -> apply -> health-check -> commit`).
2. [docs/INSTALLATION.md](docs/INSTALLATION.md) — Build toolchain, Go requirements, and binary packaging.
3. [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — Hermetic testing standards, simulated hardware, and gating policies.
4. [docs/FEATURE_STATUS.md](docs/FEATURE_STATUS.md) — Detailed implementation status matrix across all subsystems.

---

## 2. Document Map

| Document | Purpose & Scope | Target Audience |
|---|---|---|
| [docs/README.md](docs/README.md) | Navigation index, reading paths, and documentation conventions. | All |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architectural subsystems, transaction pipeline, and isolation model. | Engineers & Admins |
| [docs/HARDWARE_AND_NETWORK.md](docs/HARDWARE_AND_NETWORK.md) | Physical topology, MAC identity discovery, and USB NIC constraints. | Network Engineers |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Prerequisites, Go compilation, binary installation, and directories. | SysAdmins |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Configuration schema, development overrides, and live validation. | Operators |
| [docs/ACTIVATION_RUNBOOK.md](docs/ACTIVATION_RUNBOOK.md) | Exact numbered runbook: preflight, dry-run, live activation, verification. | Operators (Physical Console) |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Monitoring commands, log analysis, client tracking, and routines. | Operators |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Specific failure symptoms, root causes, diagnostic steps, and fixes. | Operators & Support |
| [docs/ROLLBACK_AND_RECOVERY.md](docs/ROLLBACK_AND_RECOVERY.md) | Atomic rollbacks, journal recovery, and host restoration. | Operators |
| [docs/SECURITY.md](docs/SECURITY.md) | Security model, firewall rule layout, management safety, and risks. | Security Architects |
| [docs/FEATURE_STATUS.md](docs/FEATURE_STATUS.md) | Implemented vs planned features, production blockers, and manual roles. | All |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Test suites, test conventions, adding gates, and policy workflows. | Developers |

---

## 3. Core Safety Tenets

Every procedure documented in this library adheres to three fundamental engineering invariants:

1. **Read-Only Inspection First**: All commands without explicit `--confirm` flags are pure, in-process, or read-only queries. They will not mutate kernel tables, drop packets, or change interface states.
2. **Table & Resource Isolation**: THN Gateway manages its own dedicated `table inet thn`. It strictly preserves foreign tables (`ip thn_gateway`, UFW, Tailscale, Docker), external routes, and independent services (`dnsmasq`).
3. **Fail-Closed Execution**: If any safety check, digest verification, physical presence requirement, or rollback readiness check is ambiguous or failing, activation halts immediately. The current network remains completely untouched.
