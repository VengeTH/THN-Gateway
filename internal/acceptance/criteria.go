// Package acceptance decides whether a gateway may be called successful.
//
// # What this is for
//
// Seventeen criteria. Every one of them is a thing that, if it silently broke,
// would take out somebody's work: a database, a tunnel somebody is reaching
// through, a model server, the uplink itself.
//
// The package exists because a checklist on a wiki does not hold anyone to
// anything, and because the question "did the change break the box" has to be
// answerable by a machine at three in the morning when nobody is awake to
// remember that Docker was on it.
//
// # The distinction that shapes everything
//
// Four of the seventeen are not checks. They are procedures.
//
//	Gateway survives reboot
//	Gateway configuration survives reboot
//	Rollback works
//	Gateway can recover from failed configuration
//
// None of these can be evaluated by looking at the host. They are claims about
// what happened across a lifecycle: that the machine came back, that the
// configuration came back, that a revert worked, that a bad configuration was
// recovered from. A tool that inspects a running gateway and reports those four
// as passed is inventing an observation it did not make.
//
// So they are classified as lifecycle criteria, they require evidence recorded
// during an actual cycle, and absent that evidence they report `NotAttempted`.
// Not "pass". Not "assume". Not attempted.
//
// That refusal is the most valuable thing in this package. Everything else here
// could be fudged by writing a lenient check; this cannot, because it declines
// to produce an answer at all.
//
// # Verdict arithmetic
//
// A gateway is successful when every criterion is `Pass`. `Unknowable` is not
// `Pass`. `NotAttempted` is not `Pass`. A criterion that could not be checked
// is a gap in the evidence, and a gap in the evidence about whether the gateway
// is safe to leave alone is exactly the thing that must not be rounded in the
// gateway's favour.
//
// # What "remains healthy" means
//
// It is relative. "PostgreSQL remains healthy" is a claim about change, not
// about a standard: the thing to compare against is what was reachable before.
// A gateway that never ran PostgreSQL cannot violate this criterion, and a
// gateway where PostgreSQL was already down must not be reported as having
// broken it. Hence Baseline.
//
// # What a probe can and cannot show
//
// The probe layer reads /proc and the filesystem. That proves something is bound
// to a port; it does not prove the service behind the port answers correctly. A
// database in an infinite recovery loop still holds its port.
//
// So these criteria are reachability criteria, and they are labelled as such.
// Where a criterion needs more than reachability it says so rather than
// passing on weaker evidence.
package acceptance

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Class is how a criterion is evaluated.
type Class string

const (
	// ClassState is evaluated from one observation of the host.
	//
	// "Is the uplink up" is answerable now, by looking.
	ClassState Class = "state"

	// ClassBaseline is evaluated by comparing an observation against a recorded
	// prior one.
	//
	// "PostgreSQL remains healthy" means "was reachable, still is".
	ClassBaseline Class = "baseline"

	// ClassLifecycle requires evidence from an actual reboot or rollback.
	//
	// These cannot be evaluated by inspection, and this package does not try.
	ClassLifecycle Class = "lifecycle"
)

// Verdict is a criterion's outcome.
type Verdict string

const (
	// VerdictPass means the criterion is satisfied.
	VerdictPass Verdict = "pass"

	// VerdictFail means the criterion is definitely not satisfied.
	VerdictFail Verdict = "fail"

	// VerdictUnknowable means the check could not be run.
	//
	// Not a soft pass. A criterion nobody could check is a criterion with no
	// evidence behind it, and "no evidence" and "working" are different
	// sentences.
	VerdictUnknowable Verdict = "unknowable"

	// VerdictNotAttempted means the criterion requires a lifecycle event that
	// has not been recorded.
	//
	// Distinct from VerdictUnknowable because it names the reason: not that the
	// check was impossible, but that the thing being checked — a reboot, a
	// rollback — has not happened.
	VerdictNotAttempted Verdict = "not-attempted"
)

// Passed reports whether a verdict is a pass.
func (v Verdict) Passed() bool { return v == VerdictPass }

// Criterion is one line of the acceptance test.
type Criterion struct {
	// ID is the stable identifier.
	ID string `json:"id"`

	// Title is the short name as an operator writes it.
	Title string `json:"title"`

	// Class is how it is evaluated.
	Class Class `json:"class"`

	// WhatItProves is one sentence, because a criterion nobody can explain is a
	// criterion nobody can act on when it fails.
	WhatItProves string `json:"what_it_proves"`

	// Needs names what must exist for the check to mean anything.
	//
	// Stated per criterion rather than assumed, because the failure mode is
	// specific: a check for a service this machine does not run has to report
	// "not configured", not "failed", and the difference is whether the operator
	// goes looking for a real fault.
	Needs []string `json:"needs,omitempty"`
}

// Criteria is the acceptance test.
func Criteria() []Criterion {
	return []Criterion{
		{
			ID: "wan-works", Title: "WAN works", Class: ClassState,
			WhatItProves: "There is a default route through an interface that is present and up, " +
				"so traffic leaving this host has somewhere to go.",
		},
		{
			ID: "lan-works", Title: "LAN works", Class: ClassState,
			WhatItProves: "The downstream interface exists, is up, and holds the address the " +
				"configuration asked for.",
			Needs: []string{"a configured LAN interface"},
		},
		{
			ID: "dhcp-works", Title: "DHCP works", Class: ClassState,
			WhatItProves: "A DHCP configuration is rendered and the lease file it names is " +
				"readable, so a server has somewhere to record what it handed out.",
		},
		{
			ID: "dns-works", Title: "DNS works", Class: ClassState,
			WhatItProves: "Something is listening on the DNS port and resolvers are " +
				"configured, so clients on the LAN can resolve names.",
		},
		{
			ID: "nat-works", Title: "NAT works", Class: ClassState,
			WhatItProves: "Forwarding is enabled and a masquerade rule is present in the live " +
				"ruleset, so LAN clients get a source address the internet accepts.",
		},
		{
			ID: "firewall-works", Title: "Firewall works", Class: ClassState,
			WhatItProves: "A ruleset is loaded with THN's table present and chains carrying a " +
				"policy, so traffic is actually being filtered rather than merely configured.",
		},
		{
			ID: "qos-works", Title: "QoS works", Class: ClassState,
			WhatItProves: "A queue discipline is attached to the uplink, so shaping is " +
				"configured on the interface it affects.",
			Needs: []string{"QoS enabled in the configuration"},
		},
		{
			ID: "tailscale-works", Title: "Tailscale management works", Class: ClassState,
			WhatItProves: "The Tailscale interface is present, so the gateway can be reached " +
				"without depending on the WAN being up.",
			Needs: []string{"Tailscale installed and joined"},
		},
		{
			ID: "ssh-works", Title: "SSH works", Class: ClassState,
			WhatItProves: "Something is listening on the SSH port, so there is a way in that " +
				"does not depend on the management tunnel.",
		},
		{
			ID: "apps-reachable", Title: "Existing applications remain reachable", Class: ClassBaseline,
			WhatItProves: "Everything that was reachable before the change still is. This is " +
				"the criterion that catches a firewall change that silently cut somebody off.",
		},
		{
			ID: "docker-healthy", Title: "Docker remains healthy", Class: ClassBaseline,
			WhatItProves: "The Docker daemon is present and reachable, as it was before.",
			Needs:        []string{"Docker running on this host"},
		},
		{
			ID: "postgres-healthy", Title: "PostgreSQL remains healthy", Class: ClassBaseline,
			WhatItProves: "Something holds the PostgreSQL port, as it did before.",
			Needs:        []string{"PostgreSQL running on this host"},
		},
		{
			ID: "cloudflare-healthy", Title: "Cloudflare Tunnel remains healthy", Class: ClassBaseline,
			WhatItProves: "An outbound tunnel connection is held, as it was before.",
			Needs:        []string{"cloudflared running on this host"},
		},
		{
			ID: "ollama-healthy", Title: "Ollama remains healthy", Class: ClassBaseline,
			WhatItProves: "Something holds the Ollama port, as it did before.",
			Needs:        []string{"Ollama running on this host"},
		},

		// ---- lifecycle. Not evaluable by looking. ----
		//
		// Each of these states a fact about an event. None can be established
		// from a single observation, and this package declines to pretend
		// otherwise.

		{
			ID: "survives-reboot", Title: "Gateway survives reboot", Class: ClassLifecycle,
			WhatItProves: "The machine came back after a reboot and this gateway was still " +
				"running. Requires a recorded post-reboot observation; an appliance " +
				"that will not boot cannot report on itself.",
			Needs: []string{"a recorded reboot cycle"},
		},
		{
			ID: "config-survives-reboot", Title: "Gateway configuration survives reboot", Class: ClassLifecycle,
			WhatItProves: "The configuration present after a reboot is byte-identical to the " +
				"one before it, so nothing regenerates or truncates it behind the operator's back.",
			Needs: []string{"a recorded reboot cycle"},
		},
		{
			ID: "rollback-works", Title: "Rollback works", Class: ClassLifecycle,
			WhatItProves: "A configuration was actually reverted and the host returned to the " +
				"earlier state. Requires a performed rollback, not an available one.",
			Needs: []string{"a performed rollback"},
		},
		{
			ID: "recovers-from-failed-config", Title: "Gateway can recover from failed configuration",
			Class: ClassLifecycle,
			WhatItProves: "A deliberately broken configuration was applied, the gateway did " +
				"not stay broken, and the previous configuration was restored.",
			Needs: []string{"a performed recovery from a failed configuration"},
		},
	}
}

// CriterionByID finds a criterion.
func CriterionByID(id string) (Criterion, bool) {
	for _, c := range Criteria() {
		if c.ID == id {
			return c, true
		}
	}
	return Criterion{}, false
}

// Result is one criterion's outcome in a run.
type Result struct {
	// Criterion is what was checked.
	Criterion Criterion `json:"criterion"`

	// Verdict is the outcome.
	Verdict Verdict `json:"verdict"`

	// Detail is the evidence, in a sentence.
	Detail string `json:"detail"`

	// Observed is what was actually seen, for a failure an operator needs to
	// diagnose.
	Observed string `json:"observed,omitempty"`
}

// Report is a whole acceptance run.
type Report struct {
	// Gateway is whose gateway this is.
	Gateway string `json:"gateway"`

	// At is when the run happened.
	At time.Time `json:"at"`

	// Results are the criteria, worst first.
	Results []Result `json:"results"`

	// BaselineAt is when the baseline was captured, when there is one.
	BaselineAt time.Time `json:"baseline_at,omitempty"`

	// Summary counts outcomes.
	Summary Summary `json:"summary"`
}

// Summary counts outcomes.
type Summary struct {
	Pass         int `json:"pass"`
	Fail         int `json:"fail"`
	Unknowable   int `json:"unknowable"`
	NotAttempted int `json:"not_attempted"`
	Total        int `json:"total"`
}

// Successful reports whether the gateway may be called successful.
//
// Every criterion must pass. Unknowable and NotAttempted do not round in the
// gateway's favour, because both mean the same thing operationally: nobody
// knows, and the gateway is about to be left alone.
func (r Report) Successful() bool {
	return r.Summary.Fail == 0 &&
		r.Summary.Unknowable == 0 &&
		r.Summary.NotAttempted == 0 &&
		r.Summary.Pass == r.Summary.Total &&
		r.Summary.Total > 0
}

// Blocking returns the criteria that stopped success, in report order.
func (r Report) Blocking() []Result {
	var out []Result
	for _, res := range r.Results {
		if !res.Verdict.Passed() {
			out = append(out, res)
		}
	}
	return out
}

// add appends a result and recounts.
func (r *Report) add(res Result) {
	r.Results = append(r.Results, res)
	r.recount()
}

func (r *Report) recount() {
	r.Summary = Summary{Total: len(r.Results)}
	for _, res := range r.Results {
		switch res.Verdict {
		case VerdictPass:
			r.Summary.Pass++
		case VerdictFail:
			r.Summary.Fail++
		case VerdictUnknowable:
			r.Summary.Unknowable++
		case VerdictNotAttempted:
			r.Summary.NotAttempted++
		}
	}
}

// sortResults puts the worst first, because a report read top-down should start
// with what is broken.
func (r *Report) sortResults() {
	sort.SliceStable(r.Results, func(i, j int) bool {
		ri, rj := verdictRank(r.Results[i].Verdict), verdictRank(r.Results[j].Verdict)
		if ri != rj {
			return ri < rj
		}
		return r.Results[i].Criterion.ID < r.Results[j].Criterion.ID
	})
}

func verdictRank(v Verdict) int {
	switch v {
	case VerdictFail:
		return 0
	case VerdictUnknowable:
		return 1
	case VerdictNotAttempted:
		return 2
	default:
		return 3
	}
}

// Evidence is what a run actually saw.
//
// It is a struct rather than a map because the set of things worth observing is
// known, and a map would let a caller add a key that no criterion reads — which
// is how a check ends up recording evidence it never looked at.
type Evidence struct {
	// Interfaces present on the host.
	Interfaces []string

	// DefaultRouteInterface is the interface the default route leaves through.
	DefaultRouteInterface string

	// DefaultRoutePresent reports whether there is a default route at all.
	DefaultRoutePresent bool

	// WANUp reports the uplink's link state.
	WANUp bool

	// LANConfigured is the LAN interface the configuration names.
	LANConfigured string

	// LANUp reports the LAN interface's link state.
	LANUp bool

	// LANAddressPresent reports whether the configured LAN address is bound.
	LANAddressPresent bool

	// DHCPLeaseFileReadable reports whether the lease file could be read.
	DHCPLeaseFileReadable bool

	// DHCPLeaseCount is how many leases it holds.
	DHCPLeaseCount int

	// ResolversConfigured is how many upstream resolvers are set.
	ResolversConfigured int

	// ForwardingEnabled reports whether IPv4 forwarding is on.
	ForwardingEnabled bool

	// MasqueradePresent reports whether NAT is in the live ruleset.
	MasqueradePresent bool

	// FirewallLoaded reports whether a ruleset is loaded.
	FirewallLoaded bool

	// FirewallTablePresent reports whether THN's table is in it.
	FirewallTablePresent bool

	// FirewallChainCount is how many chains the ruleset has.
	FirewallChainCount int

	// QoSPresent reports whether a queue discipline is on the uplink.
	QoSPresent bool

	// QoSAlgorithm is which one.
	QoSAlgorithm string

	// ListeningPorts is every TCP port with a socket in LISTEN.
	ListeningPorts []int

	// TunnelEstablished reports whether an outbound tunnel connection is held.
	TunnelEstablished bool

	// HostSupported reports whether this host could be inspected at all.
	HostSupported bool
}

// Baseline is what was reachable before a change.
//
// Without this, "PostgreSQL remains healthy" has no meaning: it would either
// fail on a host that never ran PostgreSQL, or pass on a host where it was
// already broken. Both are wrong, and the second is worse because it reports a
// success nobody checked.
type Baseline struct {
	// Gateway is whose baseline this is.
	Gateway string `json:"gateway"`

	// CapturedAt is when it was taken.
	CapturedAt time.Time `json:"captured_at"`

	// ListeningPorts is the set of ports that were listening.
	ListeningPorts []int `json:"listening_ports"`

	// TunnelEstablished records the tunnel state at capture time.
	TunnelEstablished bool `json:"tunnel_established"`

	// Interfaces present at capture time.
	Interfaces []string `json:"interfaces"`
}

// Capture records a baseline from evidence.
func Capture(gateway string, e Evidence, at time.Time) Baseline {
	ports := append([]int(nil), e.ListeningPorts...)
	sort.Ints(ports)

	return Baseline{
		Gateway:           gateway,
		CapturedAt:        at.UTC(),
		ListeningPorts:    ports,
		TunnelEstablished: e.TunnelEstablished,
		Interfaces:        append([]string(nil), e.Interfaces...),
	}
}

// wasListening reports whether a port was reachable before.
func (b Baseline) wasListening(port int) bool {
	for _, p := range b.ListeningPorts {
		if p == port {
			return true
		}
	}
	return false
}

// Render formats a report for a terminal.
//
// The headline is the verdict, and it is stated in words rather than as a
// colour or an icon, because this report gets read on a console over a serial
// link at three in the morning.
func Render(r Report) string {
	var sb strings.Builder

	verdict := "NOT SUCCESSFUL"
	if r.Successful() {
		verdict = "SUCCESSFUL"
	}

	fmt.Fprintf(&sb, "Acceptance: %s\n", verdict)
	fmt.Fprintf(&sb, "Gateway:    %s\n", r.Gateway)
	fmt.Fprintf(&sb, "Run at:     %s\n", r.At.Format(time.RFC3339))
	if !r.BaselineAt.IsZero() {
		fmt.Fprintf(&sb, "Baseline:   %s\n", r.BaselineAt.Format(time.RFC3339))
	}
	fmt.Fprintf(&sb, "\n%d of %d criteria pass; %d fail, %d unknowable, %d not attempted.\n",
		r.Summary.Pass, r.Summary.Total,
		r.Summary.Fail, r.Summary.Unknowable, r.Summary.NotAttempted)

	if !r.Successful() {
		sb.WriteString("\nThis gateway may not be called successful.\n")
	}

	sb.WriteString("\n" + strings.Repeat("-", 72) + "\n")

	for _, res := range r.Results {
		fmt.Fprintf(&sb, "[%-12s] %s\n", res.Verdict, res.Criterion.Title)
		fmt.Fprintf(&sb, "               %s\n", res.Detail)
		if res.Observed != "" {
			fmt.Fprintf(&sb, "               observed: %s\n", res.Observed)
		}
	}

	if !r.Successful() {
		sb.WriteString("\n" + strings.Repeat("-", 72) + "\n")
		sb.WriteString("Not successful because:\n\n")
		for _, res := range r.Blocking() {
			switch res.Criterion.Class {
			case ClassLifecycle:
				fmt.Fprintf(&sb, "  %s — %s\n", res.Criterion.ID, res.Detail)
			default:
				fmt.Fprintf(&sb, "  %s — %s\n", res.Criterion.ID, res.ObservedOrDetail())
			}
		}
	}

	return sb.String()
}

// ObservedOrDetail prefers the observed value, falling back to the detail.
func (r Result) ObservedOrDetail() string {
	if r.Observed != "" {
		return r.Observed
	}
	return r.Detail
}
