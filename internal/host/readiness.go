package host

// Read-only evaluation of whether an observed host could be a gateway.
//
// # What this decides, and what it does not
//
// This file answers one question: given what has been observed about this
// machine, is there anything that would prevent it from becoming a gateway?
//
// It does not answer "how do I change it", and it cannot. Every function here
// is pure: it reads a Device and returns a verdict. There is no command, no
// file write, and no path to the executor — the package does not import it,
// and adding that import would be the review event at which this file's whole
// reason for existing would come up.
//
// # Three verdicts, because two are not enough
//
//	Ready                 nothing blocks it
//	ReadyWithWarnings     nothing blocks it, but something is uncertain
//	Blocked               something prevents it, and more configuration
//	                      will not fix it
//
// The third verdict is the one that earns its keep. "This host has one NIC"
// and "THN could not determine whether this kernel has CAKE" are both
// "something is wrong", and an operator responds to them completely
// differently: one needs a different machine or a different topology, the
// other needs a probe. Collapsing them into a single "NOT READY" throws away
// the only part of the answer that tells the operator what to do next.
//
// # Blocking is narrow on purpose
//
// Only conditions that genuinely prevent gateway operation block. Every
// uncertainty is a warning.
//
// The reasoning: readiness is reported to a human deciding what to do next.
// A warning they cannot act on is noise; a block they cannot act on is worse.
// So the bar for blocking is "an operator could not proceed with this host",
// and everything softer than that is surfaced as a warning with the reason
// attached. Uncertain capabilities warn. Unresolved role assignments block,
// because an operator cannot configure a gateway whose LAN is unassigned.

import (
	"fmt"
	"sort"
)

// ReadinessStatus is the verdict of a readiness evaluation.
type ReadinessStatus string

const (
	// ReadyStatus means nothing was found that would prevent gateway
	// operation.
	ReadyStatus ReadinessStatus = "READY"

	// ReadyWithWarningsStatus means nothing blocks, but at least one fact is
	// uncertain. It is not a softer "ready": it is "ready, and here is what
	// THN could not confirm".
	ReadyWithWarningsStatus ReadinessStatus = "READY_WITH_WARNINGS"

	// BlockedStatus means something prevents gateway operation, and more
	// configuration will not fix it.
	BlockedStatus ReadinessStatus = "BLOCKED"
)

// Severity distinguishes a condition that blocks from one that only warns.
type Severity string

const (
	// SeverityBlocking prevents gateway operation.
	SeverityBlocking Severity = "blocking"

	// SeverityWarning is worth knowing but does not prevent anything.
	SeverityWarning Severity = "warning"

	// SeverityInfo is a recorded observation that changes no verdict.
	//
	// It exists because "not blocking" and "worth mentioning" are not the
	// same as "a gap in what THN knows". Foreign infrastructure — a Docker
	// bridge, someone else's nftables table — is a fact about the host that
	// THN has established and is happy with. Counting it as a warning would
	// mean no real production host could ever report plain READY, because a
	// real host almost always has a container network on it.
	SeverityInfo Severity = "info"
)

// ReadinessFinding is one thing readiness has to say about the host.
//
// It reuses the Problem shape this package already defines rather than
// introducing a parallel one. The fields overlap deliberately: Code carries a
// stable machine-readable reason, and Candidates lets the same finding drive
// both a sentence on a terminal and a list in a UI without the two
// disagreeing about which interfaces were suggested.
type ReadinessFinding struct {
	// Severity is blocking or warning.
	Severity Severity `json:"severity"`

	// Code is a stable machine-readable reason.
	//
	//	no-physical-interfaces    the host has no physical NIC at all
	//	insufficient-interfaces   fewer NICs than the topology needs
	//	role-unresolved           a configured role matched no interface
	//	role-conflict             two roles or two selectors collide
	//	forwarding-unavailable    IPv4 forwarding is off
	//	forwarding-undetermined   the forwarding setting could not be read
	//	nftables-unavailable      nftables cannot be used here
	//	tc-unavailable            traffic control cannot be used here
	//	capability-unknown        a capability could not be determined
	//	capability-inferred       a capability rests on an inference
	//	unmanaged-infrastructure  this host carries resources THN does not own
	Code string `json:"code"`

	// Subject names what the finding is about, e.g. "LAN" or "nftables".
	Subject string `json:"subject"`

	// Message is the human sentence explaining the verdict.
	Message string `json:"message"`

	// Candidates are the interfaces that could resolve the finding.
	Candidates []string `json:"candidates,omitempty"`

	// Confidence is the capability confidence this finding rests on, for
	// capability findings.
	Confidence Confidence `json:"confidence,omitempty"`
}

// Readiness is the outcome of evaluating an observed host.
type Readiness struct {
	// Status is the verdict.
	Status ReadinessStatus `json:"status"`

	// Summary is a one-line human explanation of the verdict.
	Summary string `json:"summary"`

	// Findings are everything readiness has to report, blocking first.
	Findings []ReadinessFinding `json:"findings"`

	// Fact lines are the observed facts the verdict rests on, already
	// rendered. They are included so that a reader sees what was checked
	// and not only what was wrong — "2 physical interfaces, forwarding
	// available" is as much a part of the answer as "CAKE unknown".
	Facts []string `json:"facts"`

	// UncertainCapabilities are the capabilities that are not observed,
	// sorted by name.
	UncertainCapabilities []Capability `json:"uncertain_capabilities,omitempty"`

	// Blocked reports whether Status is Blocked.
	Blocked bool `json:"blocked"`
}

// ReadinessRequest describes the topology readiness is being asked about.
type ReadinessRequest struct {
	// RequiredInterfaces is how many assignable physical interfaces the
	// intended topology needs.
	//
	// Zero means "at least one", which is the most a readiness check can
	// demand without knowing the topology. The canonical two-port gateway
	// asks for two.
	RequiredInterfaces int

	// Resolutions maps each configured role to its resolution, so that
	// unresolved and conflicting assignments are reported.
	//
	// Optional: a host observed before anything has been configured has no
	// assignments, and readiness must work without them rather than
	// demanding a configuration document just to answer a question about
	// the hardware.
	Resolutions map[Role]Resolution
}

// EvaluateReadiness reports whether an observed host could be a gateway.
//
// Pure and total: it never returns an error, and it never mutates anything.
func EvaluateReadiness(d *Device, req ReadinessRequest) Readiness {
	r := Readiness{Facts: []string{}, Findings: []ReadinessFinding{}}

	if d == nil || !d.Supported {
		r.Blocked = true
		r.Status = BlockedStatus
		r.Summary = "host inspection is not available on this machine, so nothing could be observed"
		r.Findings = append(r.Findings, ReadinessFinding{
			Severity: SeverityBlocking,
			Code:     "inspection-unavailable",
			Subject:  "host",
			Message:  "THN cannot inspect this host, so it cannot assess it for gateway operation",
		})
		return r
	}

	r.Facts = observedFacts(d)
	evaluateInterfaces(d, req, &r)
	evaluateRoles(req, &r)
	evaluateForwarding(d, &r)
	evaluateSubsystems(d, &r)
	evaluateConfidence(d, &r)
	evaluateUnmanaged(d, &r)

	// Deterministic order: blocking, then warnings, then informational; then
	// by code, then by subject. Two runs over the same host must produce
	// byte-identical output, because a readiness report that reorders itself
	// between runs cannot be diffed or compared against a previous run.
	sort.SliceStable(r.Findings, func(a, b int) bool {
		fa, fb := r.Findings[a], r.Findings[b]
		if fa.Severity != fb.Severity {
			return severityRank(fa.Severity) > severityRank(fb.Severity)
		}
		if fa.Code != fb.Code {
			return fa.Code < fb.Code
		}
		return fa.Subject < fb.Subject
	})

	r.Status, r.Summary, r.Blocked = summarise(&r)
	r.UncertainCapabilities = d.UncertainCapabilities()
	return r
}

// observedFacts renders the facts a verdict rests on.
//
// These are deliberately the positive findings, not just the problems. An
// operator reading "CAKE unknown" needs to know that everything else checked
// out, and a report listing only warnings makes that impossible to tell.
func observedFacts(d *Device) []string {
	facts := []string{
		fmt.Sprintf("physical interfaces: %d", len(d.PhysicalInterfaces())),
		fmt.Sprintf("assignable interfaces: %d", len(d.RoleCandidates())),
	}
	if d.System.PrettyName != "" || d.System.Name != "" {
		facts = append(facts, fmt.Sprintf("platform: %s", d.System.Describe()))
	}
	if d.System.Kernel != "" {
		facts = append(facts, fmt.Sprintf("kernel: %s", d.System.Kernel))
	}

	switch {
	case !d.ForwardingKnown:
		facts = append(facts, "IPv4 forwarding: unknown")
	case d.ForwardingEnabled:
		facts = append(facts, "IPv4 forwarding: enabled")
	default:
		facts = append(facts, "IPv4 forwarding: disabled")
	}

	facts = append(facts,
		"nftables: "+subsystemWord(d.NFTables.Checked, d.NFTables.QuerySucceeded, d.NFTables.Available),
		"tc: "+subsystemWord(d.TrafficControl.Checked, d.TrafficControl.QuerySucceeded, d.TrafficControl.Available),
	)
	return facts
}

// subsystemWord renders a probed/unprobed subsystem as one word.
func subsystemWord(checked, succeeded, available bool) string {
	switch {
	case !checked:
		return "not probed"
	case succeeded:
		return "available"
	case available:
		return "installed, not queryable"
	default:
		return "unavailable"
	}
}

// evaluateInterfaces checks that the host has enough ports for the topology.
func evaluateInterfaces(d *Device, req ReadinessRequest, r *Readiness) {
	physical := d.PhysicalInterfaces()

	// No physical NIC at all is a different failure from too few, and the
	// difference is what the operator does about it: one means the wrong
	// machine or a VM with no passed-through adapter, the other means this
	// host is a client rather than a gateway.
	if len(physical) == 0 {
		r.Findings = append(r.Findings, ReadinessFinding{
			Severity: SeverityBlocking,
			Code:     "no-physical-interfaces",
			Subject:  "interfaces",
			Message: "no physical network interface was observed on this host; " +
				"a gateway needs at least one real network port",
			Candidates: d.SystemNames(),
		})
		return
	}

	required := req.RequiredInterfaces
	if required < 1 {
		required = 1
	}
	if len(physical) >= required {
		return
	}

	r.Findings = append(r.Findings, ReadinessFinding{
		Severity: SeverityBlocking,
		Code:     "insufficient-interfaces",
		Subject:  "interfaces",
		Message: fmt.Sprintf("%d physical interface(s) observed, but the requested "+
			"topology needs %d; this host cannot be a %d-port gateway",
			len(physical), required, required),
		Candidates: interfaceNames(physical),
	})
}

// evaluateRoles reports unresolved and conflicting role assignments.
func evaluateRoles(req ReadinessRequest, r *Readiness) {
	roles := make([]Role, 0, len(req.Resolutions))
	for role := range req.Resolutions {
		roles = append(roles, role)
	}
	// Sorted so that a host with two unresolved roles always reports them in
	// the same order.
	sort.Slice(roles, func(a, b int) bool { return roles[a] < roles[b] })

	for _, role := range roles {
		res := req.Resolutions[role]
		for _, p := range res.Problems {
			r.Findings = append(r.Findings, ReadinessFinding{
				Severity: SeverityBlocking,
				Code:     "role-" + p.Code,
				Subject:  string(role),
				Message: fmt.Sprintf("role %s is unresolved: %s",
					role, p.Message),
				Candidates: p.Candidates,
			})
		}
	}
}

// evaluateForwarding checks the one setting a gateway cannot work without.
//
// An unreadable sysctl and a disabled one are separate findings with separate
// codes. They look identical on the model — forwarding is off — and they call
// for opposite responses: one is a THN privilege problem, the other is a host
// that needs a setting changed.
func evaluateForwarding(d *Device, r *Readiness) {
	if !d.ForwardingKnown {
		r.Findings = append(r.Findings, ReadinessFinding{
			Severity:   SeverityBlocking,
			Code:       "forwarding-undetermined",
			Subject:    "forwarding",
			Message:    "net.ipv4.ip_forward could not be read; THN will not assume a gateway can forward when it could not confirm the setting",
			Confidence: ConfidenceUnknown,
		})
		return
	}
	if d.ForwardingEnabled {
		return
	}
	r.Findings = append(r.Findings, ReadinessFinding{
		Severity:   SeverityBlocking,
		Code:       "forwarding-unavailable",
		Subject:    "forwarding",
		Message:    "net.ipv4.ip_forward is disabled; a gateway must forward IPv4 between its interfaces",
		Confidence: ConfidenceObserved,
	})
}

// evaluateSubsystems reports the two facilities the M6.x apply path needs.
func evaluateSubsystems(d *Device, r *Readiness) {
	if d.NFTables.Checked && !d.NFTables.QuerySucceeded {
		r.Findings = append(r.Findings, ReadinessFinding{
			Severity:   SeverityBlocking,
			Code:       "nftables-unavailable",
			Subject:    "nftables",
			Message:    nftablesReason(d),
			Confidence: d.nftConfidence(),
		})
	}
	if d.TrafficControl.Checked && !d.TrafficControl.QuerySucceeded {
		r.Findings = append(r.Findings, ReadinessFinding{
			Severity:   SeverityBlocking,
			Code:       "tc-unavailable",
			Subject:    "tc",
			Message:    tcReason(d.TrafficControl),
			Confidence: tcConfidence(d.TrafficControl),
		})
	}
}

// nftablesReason explains why nftables could not be used.
func nftablesReason(d *Device) string {
	if d.NFTables.Reason != "" {
		return d.NFTables.Reason
	}
	return "nftables could not be queried on this host"
}

// structuralInference reports a capability whose inference is permanent.
//
// # Why these three are exempt
//
// NAT, DHCP and DNS are served in userspace by software THN would run, not
// by the kernel. THN will never probe them, so on every host, forever, they
// are inferred — and an inference that can never become an observation is not
// information about THAT host, it is a fixed fact about how THN works.
//
// Warning about them would mean three permanent warnings on every report,
// which is worse than no warning at all: an operator learns to ignore the
// warning list, and then misses the one that mattered. The capability table
// still shows them as inferred, with their reason, so nothing is hidden —
// only the repetitive part is suppressed.
//
// This is the difference between "THN does not know" and "THN does not need
// to know". Only the first is worth interrupting a report for.
func structuralInference(c Capability) bool {
	switch c {
	case CapNAT, CapDHCP, CapDNS:
		return true
	default:
		return false
	}
}

// evaluateConfidence surfaces the capabilities that are uncertain about THIS
// host.
//
// A warning, never a block. THN not being able to tell whether a kernel
// supports CAKE is a gap in THN's knowledge, not a defect in the host, and
// treating it as a blocker would mean a host THN understands least is the one
// an operator is least able to use.
//
// Every genuinely uncertain capability warns, including CAKE on a host that
// simply has no CAKE attached — because "tc is installed but this kernel's
// CAKE support is unknown" is exactly the thing an operator configuring QoS
// needs to be told before they rely on it.
func evaluateConfidence(d *Device, r *Readiness) {
	for _, c := range d.UncertainCapabilities() {
		if structuralInference(c) {
			continue
		}
		s, _ := d.Capabilities[c]
		r.Findings = append(r.Findings, ReadinessFinding{
			Severity:   SeverityWarning,
			Code:       "capability-" + string(s.Confidence),
			Subject:    string(c),
			Message:    fmt.Sprintf("capability %s is %s, not observed", c, s.Confidence),
			Confidence: s.Confidence,
		})
	}
}

// evaluateUnmanaged notes infrastructure THN does not own.
//
// Recorded as information, never as a problem. Docker, Tailscale and host
// firewalls are normal on a real gateway, and a readiness report that treats
// their presence as a warning invites an operator to delete working
// infrastructure. It is also the reason plain READY is still reachable on a
// real host: a host with a Docker bridge is READY, not READY_WITH_WARNINGS.
func evaluateUnmanaged(d *Device, r *Readiness) {
	tables := 0
	for _, t := range d.NFTables.Tables {
		if !t.IsTHNTable() {
			tables++
		}
	}
	virtual := 0
	for _, i := range d.Interfaces {
		if i.Virtual {
			virtual++
		}
	}
	if tables == 0 && virtual == 0 {
		return
	}
	r.Findings = append(r.Findings, ReadinessFinding{
		Severity: SeverityInfo,
		Code:     "unmanaged-infrastructure",
		Subject:  "host",
		Message: fmt.Sprintf("this host carries %d virtual interface(s) and %d "+
			"nftables table(s) that THN does not own; they are recorded as "+
			"observed and left untouched", virtual, tables),
	})
}

// summarise turns the findings into a verdict.
//
// The rule is that any blocking finding blocks, and any warning without a
// block produces READY_WITH_WARNINGS. Informational findings count toward
// neither: they are observations THN is content with, not gaps in what it
// knows, and letting them lower the verdict would make the top verdict
// unreachable on any real host that runs containers.
//
// The summary sentence names the count rather than the detail, because the
// detail is in the findings and a summary that repeats it produces a report
// nobody reads to the end.
func summarise(r *Readiness) (ReadinessStatus, string, bool) {
	blocking, warning := 0, 0
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityBlocking:
			blocking++
		case SeverityWarning:
			warning++
		}
	}

	switch {
	case blocking > 0:
		return BlockedStatus,
			fmt.Sprintf("%d condition(s) would prevent gateway operation", blocking),
			true
	case warning > 0:
		return ReadyWithWarningsStatus,
			fmt.Sprintf("no blocking conditions, but %d fact(s) are uncertain", warning),
			false
	default:
		return ReadyStatus, "nothing was found that would prevent gateway operation", false
	}
}

// Blocking returns only the findings that block.
func (r Readiness) Blocking() []ReadinessFinding { return r.bySeverity(SeverityBlocking) }

// Warnings returns only the findings that warn.
func (r Readiness) Warnings() []ReadinessFinding { return r.bySeverity(SeverityWarning) }

// Notes returns only the informational findings.
func (r Readiness) Notes() []ReadinessFinding { return r.bySeverity(SeverityInfo) }

func (r Readiness) bySeverity(s Severity) []ReadinessFinding {
	var out []ReadinessFinding
	for _, f := range r.Findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

// severityRank orders severities for display: blocking first, info last.
func severityRank(s Severity) int {
	switch s {
	case SeverityBlocking:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// HasCode reports whether any finding carries the given code.
func (r Readiness) HasCode(code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// interfaceNames renders interface system names for a candidate list.
func interfaceNames(in []Interface) []string {
	out := make([]string, 0, len(in))
	for _, i := range in {
		out = append(out, i.SystemName)
	}
	sort.Strings(out)
	return out
}
