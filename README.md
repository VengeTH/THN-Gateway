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
thn host     [--analyze] [--debug] [--requires <n>] [--mac] [--config <path>] [--json]
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
`--requires 1` and blocked at `--requires 3`. `--analyze` adds the hardware
suitability analysis described below. `thn host --help` lists every option.

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

## Hardware suitability (`thn host --analyze`)

Observation answers *what exists on this host*. Suitability answers the next
question: *given what exists, what could this host reasonably be used for as a
gateway?* It is an explanation, not a configuration, and not a decision.

```
$ thn host --analyze
Hardware suitability
─────────────────────
  3 physical port(s): 2 Ethernet, 1 wireless
  default routes: 1 via enp0s31f6
  virtual infrastructure: br-7a3f1c2d, tailscale0, veth9f3c1a@if12 (recorded, not modified)

  enp0s31f6  [physical Ethernet]
      current:  in use, carries the default route, addressed
      link:    1000 Mbps
         + the host reports this as real hardware
         + Ethernet link kind
         + a carrier is present
         + 1000 Mbps observed
         + an IPv4 address is assigned
         + an observed default route uses this interface
      WAN    strong candidate observed
         ! currently in use: the interface carries observed addresses or routes
      LAN    limited candidate observed
         ! an observed default route currently uses this interface; using it
           for a downstream network would change the host's current path
      MGMT   candidate        observed

  enx00e099001812  [physical Ethernet]
      current:  idle
      link:    speed unknown (the host reported none); this is not a
               measurement of zero
      WAN    limited candidate observed
         ! no carrier is present, so the link is not currently connected
      LAN    candidate        observed
         ! no carrier is present, so the link is not currently connected

  Gateway profiles
  ────────────────

  Two-port wired gateway
    POSSIBLE
    + 2 physical Ethernet interfaces observed
    WAN    candidate: enp0s31f6
    LAN    candidate: enx00e099001812
    ! the WAN candidate enp0s31f6 is currently in use
    ! the LAN candidate enx00e099001812 is idle and has no carrier

  Suitability is not assignment: no role was given to any interface.
```

`thn host` without `--analyze` prints exactly what it printed before M7.1.
The flag changes no verdict and no exit code.

### Observed ≠ suitable ≠ assigned ≠ activated

THN keeps four states apart, and M7.1 owns exactly one arrow between them:

```
OBSERVED ──▶ SUITABLE ──▶ ASSIGNED ──▶ ACTIVATED
 (M7.0)      (M7.1)       (later)      (later)
```

| State | Means | Set by |
|---|---|---|
| **Observed** | THN queried the host and the host answered | `thn host` |
| **Suitable** | this link could reasonably serve that role, on stated evidence | `thn host --analyze` |
| **Assigned** | an operator explicitly gave the interface that role | `thn interface assign`, in configuration |
| **Activated** | the configuration was applied to the host | not implemented; `apply` is absent from this build |

Collapsing any two of these produces a failure that looks correct while it
happens. An interface carrying the default route looks like an uplink — but
"looks like" is not "has been told to be", and only the operator decides. So
the analysis reports:

```
enp0s31f6
  current:  in use, carries the default route   ← what the host is doing now
  WAN:     strong candidate                      ← what it could reasonably be
```

and never a third line naming a role it has given. `RoleAssignments()` is
empty after analysis, the device is byte-for-byte unchanged, and the readiness
verdict does not move — each of those is a test.

### Suitability classifications

| Classification | Meaning |
|---|---|
| `strong_candidate` | the observed evidence is the shape that role normally has |
| `candidate` | plausible for the role, nothing observed arguing against it |
| `limited_candidate` | the right kind of hardware, but something observed restricts it — no carrier, a bridge relationship, a medium that cannot carry the role conventionally |
| `unsuitable` | something observed rules it out: virtual infrastructure, loopback, enslaved, or a mode that carries no gateway traffic |
| `unknown` | THN could not classify it. Never rounded down to `unsuitable` |

A disconnected Ethernet port is a `limited_candidate`, not an unsuitable one.
Plugging the cable in is the normal order of operations, and refusing to offer
the port until it is plugged in would make the tool useless for exactly the
setup it exists for.

**Occupancy is not a classification.** It is a separate `current` state —
`idle`, `in use`, `enslaved`, or `virtual infrastructure` — because the
interface carrying the default route is usually the *best* uplink evidence on
the machine. Folding "busy" into the suitability scale would report a real
gateway's best uplink as its worst, which is how a tool talks an operator out
of the correct configuration.

### What counts as evidence, and what does not

Every classification carries the observations it rests on, and a verdict with
no evidence attached cannot be answered for. There is no opaque score — the
question an operator asks is "why?", and a number does not answer it.

Rules the analysis is written against, each with a test that defeats the
shortcut:

| Shortcut | Why it fails |
|---|---|
| Interface name | `eth0` and `docker0` are both names, and they are opposite ends of the question |
| Address range | `192.168.x.x` is as likely to be a Docker bridge as a NIC |
| Carrier alone | a Docker bridge with carrier is not a physical port |
| Speed alone | a 10 Gbps veth is not a better gateway port than a 1 Gbps NIC |
| Position in a list | "the first NIC is the uplink" is a guess, and on a laptop it is a wrong one |
| Unreported speed | `speed: 0` is an absence of a measurement, never reported as `0 Mbps` |
| Unobserved wireless mode | a radio is not an access point unless the host said it was |

Evidence is reported at `observed` confidence and is never silently upgraded.
Suitability is built entirely from observed facts, so it is `observed`; a host
THN could not inspect produces `unknown` throughout rather than a verdict
nobody reached.

### Gateway profiles

Three shapes, always reported whether or not they fit, because "not a
multi-interface host" and "three ports would be possible here and you are one
short" are different answers:

| Profile | Requires | Verdict |
|---|---|---|
| Single-interface host | exactly 1 physical port | `POSSIBLE` / `NOT POSSIBLE` |
| Two-port wired gateway | 2+ **physical Ethernet** ports | `POSSIBLE` / `NOT POSSIBLE` |
| Multi-interface gateway | 3+ physical ports | `POSSIBLE` / `NOT POSSIBLE` |

A Wi-Fi radio is hardware and it is not a wired port, so the two-port profile
counts Ethernet specifically — otherwise a host with one NIC and one adapter
would report itself as a wired gateway.

The verdict is `POSSIBLE` or `NOT POSSIBLE`, never `READY`. A hardware shape
being present says nothing about whether DHCP, DNS, VLAN, firewall, shaping or
AP capability works, and a readiness verdict here would be a claim about
capabilities this analysis has no standing to make.

`NOT POSSIBLE` is always specific about what was counted and never generalises
to a verdict on the machine. A host with no Ethernet ports may have a perfectly
good wireless uplink; "not a two-port wired gateway" is not "unusable", and
collapsing the two is the generalisation an operator would quote back at THN
when it is wrong about a machine they can see.

### Existing infrastructure is described, never judged

Docker bridges, container veths, Tailscale tunnels, WireGuard links and
bridges on a host all get read out, explained by kind, and left alone:

```
veth9f3c1a@if12  [virtual infrastructure]
    WAN/LAN/MGMT  unsuitable    observed
    x a container endpoint attached to br-7a3f1c2d is virtual infrastructure
      and does not outlive its container
```

They are recorded, counted, and reported in gateway-profile constraints, so an
operator sees them. They are never a warning, never a fault, and never a
suggestion to remove them. Two default routes are reported the same way — as a
fact about the host, not an error. A machine with a wired and a wireless uplink
is a laptop, and a report that called it broken would be teaching the operator
to distrust everything else it says.

### JSON

`--analyze --json` adds a `hardware` key alongside the existing observation
model. It is structured, not prose — every field a consumer needs is a value:

```json
{
  "hardware": {
    "physical_ethernet": 2,
    "physical_wireless": 1,
    "default_route_count": 1,
    "default_route_ifaces": ["enp0s31f6"],
    "assignment_made": false,
    "network_untouched": true,
    "is_readiness_verdict": false,
    "interfaces": [
      {
        "system_name": "enp0s31f6",
        "class": "physical-wired",
        "speed_known": true,
        "speed_mbps": 1000,
        "current": { "state": "occupied", "default_route": true, "addressed": true },
        "suitability": {
          "wan": {
            "classification": "strong_candidate",
            "confidence": "observed",
            "candidate": true,
            "evidence": [{ "code": "default-route", "detail": "...", "confidence": "observed" }],
            "blockers": [],
            "limitations": ["currently in use: the interface carries observed addresses or routes"]
          }
        }
      }
    ],
    "profiles": [
      { "id": "two-port-wired", "verdict": "POSSIBLE",
        "candidates": { "wan": "enp0s31f6", "lan": "enx00e099001812" } }
    ]
  }
}
```

The key is `candidates`, never `roles` — a consumer reading a key called
`roles` will reasonably assume THN decided something. `speed_mbps` is omitted
entirely when the host reported no speed, and `speed_known` says so, so a zero
is never mistaken for a measurement.

## Diagnosing an unknown

An `unknown` with no reason is the least useful thing a diagnostic tool can
report, so every one of THN's carries the stage that produced it.

```sh
thn host --analyze --debug
```

`--debug` writes to **stderr** only. stdout is the report, and under `--json`
it is a document a machine parses — so a diagnostic line printed there would
corrupt the output for every consumer that is not a person at a terminal. JSON
is byte-identical with and without the flag, and two tests enforce that.

```
probes       7 run, 2 did not reach a conclusion
  [ok]  nftables/list-tables stage=classify outcome=no_evidence tool=nft args="-j list tables" count=4
       the query succeeded
  [!!] traffic-control/qdisc-show stage=execute outcome=execution_failed tool=tc args="-j qdisc show" exit=1
       the tool ran but did not succeed
       cause: tc: exit 1: RTNETLINK answers: Operation not permitted
  [---] wireless/nl80211-modes stage=not-started outcome=not_checked
       this probe was never run, so nothing is known about wireless
```

The marker separates three things that look alike in a long output: `ok` ran
and concluded, `!!` ran and failed, `---` never ran. Only `ok` says anything
about the host.

### Why the outcomes are kept apart

They are not a severity scale. Each is a different operator action:

| Outcome | Means | What to do |
|---|---|---|
| `not_checked` | nobody looked | a THN-side gap; usually a missing source |
| `tool_unavailable` | the binary or file was not found | install the package |
| `execution_failed` | found, and running it failed | usually privilege |
| `parse_failed` | it ran and said something THN does not understand | THN is behind the tool's output format |
| `unexpected_output` | it parsed, but not into the expected shape | THN is behind the tool's output format |
| `no_evidence` | success — the probe worked and found nothing | nothing; this is an answer |
| `evidence` | success | nothing |

The last two are both success, and that pair is the one most often collapsed.
"No CAKE discipline is attached" is a working probe reporting a fact; "THN
could not check" is a gap in THN's knowledge. Merging them produces either a
false alarm on every healthy host or false confidence on every unhealthy one.

`not_checked` is listed under "did not reach a conclusion" deliberately. A
probe that never ran has established nothing about the host, so reporting it
under failures is correct rather than pedantic — and it is invisible
everywhere else, because a probe that never ran produces no error, no
diagnostic and no log line.

### Two parse failures that were previously silent

`tc -j qdisc show` and `nft -j list tables` used to return an empty result on
malformed output and say nothing. Since an empty result is also what a host
with nothing configured prints, a `tc` that had started emitting a new format
was reported — confidently — as a host that needs no queue shaping.

Both parsers now return an error naming the tool and the expected shape, and
`QuerySucceeded` is false on a parse failure rather than true over unparsed
output.

### Unknowables in the analysis

M7.1 reaches unknowns of its own — a link speed no driver reported, a wireless
mode the host did not state. Each names the probe that explains it:

```
unknowns     1, each with its cause
  enx00e099001812  link-speed  the link speed was not reported, so throughput
                    is unknown and is not estimated
        [ok] link-speed/sysfs-speed stage=classify outcome=no_evidence
             path=/sys/class/net/enx00e099001812/speed
             the kernel reported no link speed for this interface
             cause: unparseable or negative speed attribute: -1
```

The same data is in `--analyze --json` under `hardware.unknowns`, with the
probe as a structured object rather than a sentence. A speed attribute reading
`-1` is a kernel declining to answer; a missing one is a link with no
ethtool backing. Both are "unknown speed" and they are not the same thing.

### What is not recorded

Full command output. An nftables ruleset, a `resolv.conf`, a routing table:
these are operator configuration, and a debug log that dumps them by default is
a log that ends up pasted into a bug report. Probes carry counts, outcomes
and causes, truncated to one line and 200 characters. Redaction is applied in
one constructor rather than left to each caller, because every caller would
get it wrong eventually.

### Unknown is not one thing

A capability reported `unknown` has one of three causes, and telling them
apart is the difference between a diagnostic and a shrug:

| Cause | Example | Correct response |
|---|---|---|
| the probe failed | `nft` installed, query refused with EPERM | fix privilege, or run as the right user |
| no evidence exists | CAKE, with nothing to attach a discipline without mutating | accept it; it is honestly unknowable |
| nobody looked | no probe exists for this capability | a gap in THN, worth reporting |

`thn host --debug` prints each one with the probe behind it:

```
capabilities 4 of 17 are not fully established; each with its source
  firewall            unavailable  unknown   source=nftables
      nft is installed but the ruleset could not be read: exit 1: Operation not permitted
        [!!] nftables/list-tables stage=execute outcome=execution_failed tool=nft exit=1
             the tool ran and did not succeed
             cause: nft: exit 1: netlink: cache initialization failed: Operation not permitted
```

A **confirmed absence** is not one of these. If `nft` is definitively not
installed, THN has *established* that, and reports
`nftables: unavailable / observed` — absence is evidence, not a gap. Scoring
it as `unknown` would make a minimal host indistinguishable from one nobody
examined.

### A tool that ran is never scored as absent

`guard.Exec` embeds a command's stderr in its error string, so the error text
cannot distinguish "the binary is missing" from "the binary ran and said
something". Messages like `Cannot find device "eth0"` — which `ip` prints when
an interface vanishes mid-read — would otherwise be read as "not installed".

The discriminator is structural: `guard.Exec` returns an output only when a
process was actually created. That is a fact about what happened, available
without reading a byte of the tool's output.

Getting this wrong cuts in the dangerous direction. A confirmed absence is
scored `observed`, so a misclassified error would have produced
`nftables: unavailable / observed` on a host where nft was installed and
working — a confidently wrong answer in the column that gates activation.

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

**4. An analysis layer that cannot speak.** M7.1's suitability engine is a pure
function from an observed `Device` to an explanation. It imports no `os/exec`,
does not reach `internal/guard`, runs no command of its own, and takes no
parameter through which a role could be returned. `TestM71AnalysisHasNoExecutionOrObservationPath`
scans its source for all of those, and the point is structural: adding a probe
"just to check one more thing" would be a second observation path — and a
second chance to mutate a live gateway — so it has to be a deliberate act that
breaks a visible test.

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
    host/               observed device model, capability confidence, readiness,
                        and the M7.1 hardware suitability analyzer (pure)
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
thn host --analyze
thn host --analyze --json
```

Compare against what `thn host` reported. Differences are expected on some
axes and worth reporting either way — particularly if THN classifies an
interface as physical that you expected to be virtual, or reports a capability
you know to be present as `unknown`.

### Validating M7.1 hardware suitability

`--analyze` is read-only and derives everything from the snapshot `thn host`
already collected, so the same comparison applies. Worth checking specifically:

```sh
# the uplink should be a strong WAN candidate and the spare port a LAN
# candidate — with no carrier and, if the driver reports none, unknown speed
thn host --analyze

# machine-readable; check the structured fields, not the prose
thn host --analyze --json | jq '.hardware | {
  ethernet: .physical_ethernet,
  defaults: .default_route_count,
  assigned: .assignment_made,
  untouched: .network_untouched
}'

# per-interface verdicts
thn host --analyze --json | jq '.hardware.interfaces[]
  | {name: .system_name, class: .class, speed: .speed_known,
     wan: .suitability.wan.classification,
     lan: .suitability.lan.classification}'

# when something reads unexpected, ask why — stderr, so --json stays valid
thn host --analyze --debug

# which probes did not reach a conclusion, and where they stopped
thn host --analyze --json | jq '.hardware.unknowns[]
  | {subject, question, stage: .probe.stage, outcome: .probe.outcome,
     reason: .probe.reason}'
```

What a correct report looks like on a host with one wired uplink, one unused
Ethernet port, and a Wi-Fi adapter:

| Interface | Expected |
|---|---|
| the port carrying the default route | `strong candidate` for WAN, `current` = in use |
| the unused Ethernet port | `candidate` for LAN, limitation "no carrier", speed unknown unless reported |
| the Wi-Fi adapter in client mode | plausible WAN candidate; **not** a normal wired LAN port; AP capability not inferred |
| Docker bridges, veths, Tailscale | `unsuitable`, named by kind, left alone |
| the virtual tunnel | `unsuitable`, including when it carries a default route |

If any of those differ, the most likely cause is in the observation layer
rather than the analysis — `ip -j -d link show` above is the command to
compare against, and `thn host` prints each interface's kind and physicality
directly.

Do **not** bring an interface down, change an address or route, flush
nftables, restart networking, or stop Docker or Tailscale to make a test
pass. The host is a live server and has to stay reachable. A disagreement is
information about the code, not about the machine.

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
