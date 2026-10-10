# Developer Guide, Testing Standards & Architecture Workflows

This document defines coding conventions, hermetic testing standards, architectural workflows, and test execution procedures for contributing to **THN Gateway**.

---

## 1. Development Environment & Toolchain

- **Language**: Go 1.23+ (target `go 1.26.0` in `go.mod`).
- **Standard Library First**: External dependencies are strictly minimized (primarily `gopkg.in/yaml.v3` for parsing and modernc SQLite drivers).
- **No CGO Required**: Builds without CGO dependencies (`CGO_ENABLED=0` compatible for cross-compilation).

---

## 2. Repository Structure

```
cmd/
  thn/             # Unified CLI entry point
  thnd/            # Background daemon entry point
configs/
  gateway.yaml     # Production baseline template
  physical_dell_lab.yaml # Validated Dell lab configuration
docs/              # Complete documentation library
internal/
  acceptance/      # System acceptance criteria and validation probes
  activation/      # 13 Production safety gates and gating results
  appliance/       # Hardware slot model and manifest verification
  cli/             # CLI command handlers, dispatch table, and UI output
  config/          # Configuration models, YAML loaders, and schema validation
  desired/         # Desired state synthesis from configuration
  diff/            # Diff computation between desired and observed state
  execution/       # 6-Phase Transactional Executor, drivers, and journal
  firewall/        # nftables ruleset renderer and stateful policy models
  host/            # rtnetlink discovery, MAC hashing, and capability probing
  planner/         # Plan generation, step dependencies, and digest calculation
  qos/             # Traffic shaping hierarchies and CAKE/HTB algorithms
  rollback/        # Configuration history and generational rollback planning
tools/             # Diagnostic scripts and migration utilities
```

---

## 3. Testing Standards & Execution Commands

### 3.1 Running the Full Test Suite
All unit and regression tests must pass cleanly before submitting any changes:

```bash
# Run all tests without caching
go test -count=1 ./...
```

### 3.2 Running Targeted Subsystem Tests
When working on specific components:

```bash
# Test CLI commands and preflight gates
go test -v ./internal/cli

# Test safety gate definitions and evaluation
go test -v ./internal/activation

# Test configuration parsing and schema validation
go test -v ./internal/config

# Test 6-phase execution engine and drivers
go test -v ./internal/execution

# Test nftables rendering and rule ordering
go test -v ./internal/firewall/nft
```

### 3.3 Running LAN Policy & Development Override Tests
To verify the 100 Mbps Fast Ethernet development override and its containment:

```bash
go test -v ./internal/cli -run "Test.*(FastEthernet|LAN|Gigabit|Override)"
```

---

## 4. Architectural Invariants for Code Changes

When modifying code or adding features, observe the following rules:

### 4.1 Fail-Closed Defaults
Every struct zero-value must represent the **safest, most restrictive production policy**:
- A zero `lanPolicy` denies every sub-Gigabit adapter.
- A zero `GateResult` reports `AllSatisfied: false`.
- A zero `ProductionDriver` returns `CanApply() == false`.

### 4.2 Hermetic Testing (No Live Host Assumptions)
- Tests must never require root privileges, modify the host routing table, or open sockets to real external networks.
- Use simulated host snapshots (`host.FromSnapshot`) and `simIfaceWithSpeed()` to construct deterministic test topologies.
- Use mock command runners (`NewMockCommandRunner()`) to assert on exact shell commands rendered by execution drivers.

### 4.3 Scoped Approvals, Never Blanket Bypasses
- When creating overrides for testing (such as the Fast Ethernet LAN override), **never create a blanket flag** that bypasses checks across the entire system.
- Overrides must be keyed to an explicit, operator-provided identifier (e.g., stable hardware ID `hw:...`).
- An override flag without an accompanying approval list must fail schema validation.

---

## 5. How to Revert the Development Override for Production

When the dedicated USB 3.0 Gigabit Ethernet adapter is plugged into the server:

1. Update `/etc/thn/config.yaml`:
   ```yaml
   network:
     lan: hw:<new-gigabit-adapter-id>

   activation:
     require_physical_presence: true
     # Remove the development block entirely, or set:
     development:
       allow_fast_ethernet_lan: false
       approved_fast_ethernet_lan: []
   ```
2. Verify production policy re-engages:
   ```bash
   thn validate /etc/thn/config.yaml
   thn readiness /etc/thn/config.yaml
   ```
   Notice that the `!! DEVELOPMENT OVERRIDE ACTIVE` banner disappears.
3. If an unapproved 100 Mbps adapter is ever re-attached to LAN, `lan-identified` will immediately block activation as required by production policy.
