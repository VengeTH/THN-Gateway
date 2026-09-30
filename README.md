# THN Gateway

Configuration, planning and inspection for a Linux gateway, built so that it
**cannot change host networking** in its current state.

THN is developed remotely against a real Dell that is unattended. The risk that
matters is not a bug — it is a well-meaning command run from a laptop 100 km
away that reconfigures a machine nobody can reach. That risk is therefore
removed structurally rather than avoided by convention.

## What this build can and cannot do

| | Stages |
|---|---|
| **Implemented** | `observe` · `model` · `plan` · `validate` · `simulate` |
| **Not implemented** | `apply` · `health-check` · `commit` · `rollback` |

`apply` is absent, not disabled. There is no flag, environment variable or
configuration key that enables it, because there is no code that could.

## Commands

```
thn validate [path] [--live] [--config <path>] [--json]
thn plan     [path] [--explain] [--config <path>] [--json]
thn config   show [--desired] [path]
thn schema   [--mutating]
thn status   [--local]
thn diagnostics [--local]
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
  network/            read-only host inspection
  firewall/           read-only nftables/tc inspection
  recovery/           rollback planning (no execution)
  state/              SQLite store, owned exclusively by thnd
  logging/            slog to journal + durable events
  cli/                command dispatch and tiers
configs/gateway.yaml  example configuration
tools/                repository maintenance scripts
```

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
