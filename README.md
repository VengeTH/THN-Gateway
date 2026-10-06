# THN — The Heedful Network

**THN Gateway** is the gateway component: configuration, planning and
inspection for a Linux gateway, built so that it **cannot change host
networking** in its current state.

THN Gateway is developed remotely against a real machine that is unattended.
The risk that matters is not a bug — it is a well-meaning command run from a
laptop 100 km away that reconfigures a machine nobody can reach. That risk is
therefore removed structurally rather than avoided by convention.

## What this build can and cannot do

| | Stages |
|---|---|
| **Implemented** | `observe` · `model` · `plan` · `validate` · `simulate` |
| **Not implemented** | `apply` · `health-check` · `commit` · `rollback` |

`apply` is absent from this build's *shipped* path, not disabled. There is no
flag, environment variable or configuration key that enables production
activation, because there is no code that could.

The one apply path that does exist is confined to a disposable Linux lab, and
cannot be reached from `thn activate`:

| Driver | `CanApply()` | Where it can run |
|---|---|---|
| `ProductionDriver` | `false`, permanently | nowhere — refuses every mutation |
| `LinuxDriver` | only after `VerifyLabEnvironment` | a disposable lab that declares itself one, by marker file, hostname, MAC and interface checks |

`internal/execution` is exercised against real packets inside network
namespaces by `internal/lab`, and by hand in a lab VM — see
[docs/disposable-lab.md](./docs/disposable-lab.md). Nothing in that path can
reach a physical gateway.

## Commands

```
thn validate [path] [--live] [--config <path>] [--json]
thn plan     [path] [--explain] [--config <path>] [--json]
thn config   show [--desired] [path]
thn schema   [--mutating]
thn status   [--local]
thn diagnostics [--local]
thn host     [--requires <n>] [--mac] [--config <path>] [--json]
thn activate        # always refuses
```

### Tiers

Commands are grouped by what they need, and the grouping is a safety property:

| Tier | Commands | Requires |
|---|---|---|
| `pure` | `validate`, `plan`, `config`, `schema` | nothing — no daemon, no root, no network |
| `live` | `status`, `diagnostics` | `thnd` (or `--local`) |
| `destructive` | `activate` | refused in this build |

The pure commands are safe to run unattended, in CI, or against a production
gateway. They work with `thnd` stopped and the network unplugged:

```sh
thn validate configs/gateway.yaml    # CI gate
thn plan     configs/gateway.yaml    # what would change
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | the operation found problems |
| 2 | usage error |
| 3 | the daemon could not be reached |

## Host observation (`thn host`)

`thn host` describes a real Linux machine and reports whether it could be a
gateway. It observes; it never changes anything.

```
$ thn host
THN Host
════════

Platform
────────
  Ubuntu 24.04.1 LTS
  kernel 6.8.0-45-generic
  amd64
  hostname thn-gateway

Network state
──────────────
  IPv4 forwarding    enabled
  default route      via 203.0.113.1 dev wan0 (dhcp)
  nftables           available
    table ip filter (unmanaged)
  tc                 available
    qdisc cake 8001 on wan0
  DNS                systemd-resolved
    nameservers 127.0.0.53
    /etc/resolv.conf is a systemd-resolved stub; ...

Capabilities
─────────────
  routing             available    observed
  nftables            available    observed
  tc                  available    observed
  cake                unavailable  unknown

Readiness
─────────
  STATUS: READY_WITH_WARNINGS
```

`--json` emits the same model for automation. `--requires <n>` sets how many
physical ports the intended topology needs (default 2), and changes the
readiness verdict accordingly: the same host can be reported ready at
`--requires 1` and blocked at `--requires 3`. `thn host --help` lists every
option.

### What is observed

| Area | Observed |
|---|---|
| Platform | OS, distribution, version, codename, kernel release, architecture |
| Interfaces | stable identity, kernel name, kind, admin/operational state, carrier, MTU, MAC, addresses, link speed, wireless mode, master relationship |
| Addresses | IPv4 and IPv6, prefix, scope, owning interface |
| Routes | destination, gateway, output interface, protocol, scope, metric |
| Forwarding | `net.ipv4.ip_forward`, and whether it could be read at all |
| nftables | whether it is installed and answerable, the tables present, and which are THN's |
| Traffic control | whether `tc` is installed and answerable, and the disciplines attached |
| DNS | resolver mechanism, upstream nameservers, and whether the file is authoritative |

Interfaces keep their stable identity — derived from the hardware address,
where one exists — so a NIC that moves slots or is renamed is still the same
NIC. Kernel names are observations, never identities.

### Unmanaged infrastructure is left alone

A production gateway usually runs Docker, Tailscale, application services or
its own firewall. THN records all of it and touches none of it:

```json
{
  "family": "ip",
  "name": "docker-forward",
  "chains": ["DOCKER-FORWARD"],
  "thn_owned": false
}
```

Unknown is never treated as broken, as removable, or as managed. Discovery
does not clean up.

### Capabilities and confidence

Every capability carries how firmly it was determined, and the three states are
not interchangeable:

| Confidence | Meaning |
|---|---|
| `observed` | THN asked the host and the host answered |
| `inferred` | THN concluded it from the platform, without a probe |
| `unknown` | THN could not tell, and says so |

An **inferred** capability does not satisfy a hard gate, and an **unknown** one
is never treated as supported. `nftables` on Linux is a statement about a great
many kernels, not about this machine — so on a host whose `nft` binary is
missing, THN reports firewall support as unavailable, not as "available,
probably".

This is why CAKE is usually `unknown` even on a host with `tc` installed:
`sch_cake` is a kernel module, and the only non-mutating evidence that it
works is a CAKE discipline already attached. THN fails closed rather than
guessing.

### Readiness

Readiness is a read-only verdict with three outcomes:

| Status | Meaning |
|---|---|
| `READY` | nothing blocks, and nothing is uncertain |
| `READY_WITH_WARNINGS` | nothing blocks; some facts could not be confirmed |
| `BLOCKED` | something prevents gateway operation |

```
BLOCKED
  1 physical interface(s) observed, but the requested topology needs 2

WARN
  capability cake is unknown, not observed

NOTE
  this host carries 4 virtual interface(s) and 2 nftables table(s) that THN
  does not own; they are recorded as observed and left untouched
```

Blocking conditions are deliberately narrow: too few ports, an unresolved or
conflicting role, forwarding off or unreadable, or a required subsystem that
cannot be used. Uncertainty warns instead of blocking, because a host THN
understands less is not a host an operator can use less. Foreign infrastructure
is a **note**, not a warning — Docker bridges are normal, and treating them as
a problem would invite an operator to delete working infrastructure.

## Why it cannot change networking

Three independent layers. Any one alone would be a convention; all three must be
defeated to mutate the host.

**1. A command allowlist.** `internal/guard` is the only place permitted to call
`os/exec`. Every invocation is validated against a read-only allowlist before a
process is created. `ip`, `nft`, `tc` and `sysctl -n` are permitted for inspection
only; `ip addr add`, `nft flush ruleset`, `tc qdisc replace` and `sysctl -w` are
not on it, and unknown input is denied.

```go
guard.Check("ip", "-j", "addr", "show")   // nil
guard.Check("ip", "addr", "add", "10.77.0.1/24", "dev", "eth0")
// guard: host network mutation forbidden
```

**2. A repository-wide test.** `TestRepoContainsNoUnguardedExec` parses every Go
file in the module and fails the build if any `exec.Command` call site names a
binary outside the allowlist. Adding an apply path means deleting a visible test.

**3. An activation state machine with no exit.** `internal/activation` defines the
lifecycle, and its `Applier` interface has exactly one implementation:
`Disabled`, which refuses. There is no constructor that accepts a working one,
and no transition out of `PREPARED`.

Plans render the commands they *would* run, as text, for review. Rendering a
command is not the same as running it, and nothing crosses that line.

## How planning works

```
config ──▶ desired ──┐
                    ├──▶ diff ──▶ planner ──▶ plan + simulation
observed host ───────┘
```

**Desired state** is configuration resolved: no defaults, no optional fields, and
`unknown` modelled explicitly so "not attached" stays distinct from "not wanted".

**The diff** classifies every difference, because the three kinds need different
responses:

| Kind | Meaning |
|---|---|
| `pending` | desired state undetermined, or host unobservable — nothing to do yet |
| `drift` | the host differs from the intent |
| `blocked` | cannot be reconciled as configured; the fix is on the host or in the config |

Pending never blocks convergence. Collapsing pending into drift is the classic
mistake: it produces a plan that configures an interface that does not exist.

Each change carries a risk rating (`none` → `critical`) so `thn plan` leads with
the dangerous ones.

**The plan** orders steps into phases, because network operations have real
dependencies — a firewall applied before the addressing it depends on exists
locks the operator out:

1. `addressing` — LAN address and link state
2. `forwarding` — kernel forwarding
3. `services` — NAT, firewall, QoS
4. `housekeeping` — resolvers

Plan IDs are content-addressed, so regenerating an unchanged plan yields the same
ID and two plans can be compared.

## Current state

Running against a host with no THN-managed interfaces, which is the expected
state during remote development:

```
$ thn plan configs/gateway.yaml
plan b8f3eb58b429e03f generation 1: 0 step(s), 4 pending, 0 blocked [NOT READY]
Activation: BLOCKED (no apply path in this build)

  KIND      RISK      FIELD                        REASON
  pending   none      wan.interface                interface not attached to this host
  pending   none      firewall.enabled             host inspection unavailable on this platform
```

Everything is reported as *pending* rather than drift, because nothing has been
observed. A tool that reports "nothing to do" when it simply could not look is
worse than useless on a remote device.

## Layout

```
cmd/thn/              CLI entry point
internal/
  guard/              exec allowlist + repo-wide AST enforcement
  config/             layered configuration loading
  schema/             versioned schema, field catalogue, typo suggestions
  desired/            normalised target state
  validation/         static (CI) and live policy engine
  diff/               observed vs desired, risk classification
  planner/            phased plan generation and simulation
  activation/         state machine; Disabled applier
  network/            read-only host inspection (links, routes, sysctls,
                        nftables, tc, DNS, platform)
    host/               observed device model, capability confidence, readiness
    firewall/           read-only nftables/tc inspection
      execution/          transactions, drivers, rollback, lab authorization
      netns/              isolated network namespaces for tests that need a kernel
      lab/                M6.2 disposable gateway topology and live end-to-end suite
      recovery/           rollback planning (no execution)
  state/              SQLite store, owned exclusively by thnd
  logging/            slog to journal + durable events
  cli/                command dispatch and tiers
configs/gateway.yaml  example configuration
tools/                repository maintenance scripts
```

## Validating against a real host

`thn host` is read-only, but THN has never been run against a production
machine — the development host is not Linux. To validate M7.0 observation on
a real gateway, run these yourself. Every one of them only reads:

```sh
# platform
cat /etc/os-release
uname -r
uname -m

# interfaces and addresses
ip -j -d link show
ip -j addr show

# routes
ip -j route show

# forwarding
sysctl -n net.ipv4.ip_forward

# nftables (list only — never flush, never delete)
nft -j list tables

# traffic control (show only)
tc -j qdisc show

# DNS
cat /etc/resolv.conf
ls -l /etc/resolv.conf

# then, and still read-only:
thn host
thn host --json
```

Compare against what `thn host` reported. Differences are expected on some
axes and worth reporting either way — particularly if THN classifies an
interface as physical that you expected to be virtual, or reports a capability
you know to be present as `unknown`.

## Building

```sh
go test ./...

# static Linux binary, no CGO, ~4 MB
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags '-s -w' -o bin/thn ./cmd/thn
```

`modernc.org/sqlite` is used rather than `mattn/go-sqlite3` so the build is
CGO-free and cross-compiles cleanly to the gateway.

## Planned deployment

```
/usr/local/bin/thnd            daemon
/etc/systemd/system/thnd.service
/run/thn/thnd.sock             Unix socket
/var/lib/thn/state.db          SQLite, owned only by thnd
journalctl -u thnd
```

`thn` never opens the state database. It talks to `thnd` over the socket, so
there is structurally a single writer and no SQLite locking question to answer.
