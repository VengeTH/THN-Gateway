// Package planner turns a diff into an ordered, reviewable plan.
//
// # What a plan is
//
// A plan is a document. It contains the steps that would be carried out, the
// commands each step would run rendered as text, the ordering constraints
// between them, and a simulation of the outcome. Producing one reads
// configuration and an observation; it changes nothing.
//
// The rendered commands are documentation for the operator, not an execution
// list. Nothing in this package executes them, and nothing outside this
// package can: internal/guard would refuse the invocations anyway, because
// every one of them is state-changing.
//
// # Ordering
//
// Steps are grouped into phases, because the order of network operations is
// not arbitrary. Enabling a firewall before the addressing it depends on
// exists locks the operator out. Enabling forwarding before NAT leaves the
// host routing traffic it cannot translate. The phase order encodes that
// dependency explicitly so an operator can see why step 4 happens before
// step 2 would.
//
//	Phase 1  addressing   establish the LAN address and link state
//	Phase 2  forwarding   enable kernel forwarding
//	Phase 3  services     NAT, firewall, QoS
//	Phase 4  housekeeping resolvers
package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/qos"
)

// Action classifies the reconciliation operation on a resource.
type Action string

const (
	// ActionNoop means the observed state already matches desired state.
	ActionNoop Action = "NOOP"
	// ActionCreate means the desired state does not exist on the host.
	ActionCreate Action = "CREATE"
	// ActionUpdate means the resource exists but differs from intent.
	ActionUpdate Action = "UPDATE"
	// ActionDelete means an explicitly managed resource should be removed.
	ActionDelete Action = "DELETE"
	// ActionConflict means declarations conflict.
	ActionConflict Action = "CONFLICT"
	// ActionBlocked means prerequisites cannot be satisfied.
	ActionBlocked Action = "BLOCKED"
)

// Phase groups steps that must run together, in order.
type Phase struct {
	// Number is the one-based execution order.
	Number int `json:"number"`
	// Name identifies the phase.
	Name string `json:"name"`
	// Purpose explains why this phase happens where it does.
	Purpose string `json:"purpose"`
}

// phases is the fixed ordering. It is a declared table rather than something
// computed, because the ordering is a safety decision that should be
// reviewable at a glance.
var phases = []Phase{
	{Number: 1, Name: "addressing", Purpose: "establish the LAN address and link state, since every later phase depends on the LAN existing"},
	{Number: 2, Name: "forwarding", Purpose: "enable kernel forwarding, required before any traffic can be routed"},
	{Number: 3, Name: "services", Purpose: "apply NAT, firewall and shaping, which translate and filter the traffic forwarding will carry"},
	{Number: 4, Name: "housekeeping", Purpose: "apply resolvers, which affect name resolution rather than connectivity"},
	{Number: 5, Name: "service-intent", Purpose: "describe the DHCP and DNS behaviour requested, which this build does not yet apply"},
}

// Phases returns a copy of the phase table.
//
// It is exported so that the CLI can render the same ordering the planner
// used, rather than hard-coding phase names and risking the two disagreeing.
func Phases() []Phase {
	out := make([]Phase, len(phases))
	copy(out, phases)
	return out
}

// phasesTable returns a copy of the phase table.
func phasesTable() []Phase { return Phases() }

// RollbackInfo provides metadata needed to revert a step.
type RollbackInfo struct {
	// Target is the affected subsystem or setting.
	Target string `json:"target"`
	// PreviousState is the observed prior value.
	PreviousState string `json:"previous_state,omitempty"`
	// RestoreCommands are the shell commands that would reinstate previous state.
	RestoreCommands []string `json:"restore_commands,omitempty"`
	// Reversibility classifies how completely the step can be undone.
	Reversibility string `json:"reversibility"`
	// RequiresOperator reports whether operator intervention is needed.
	RequiresOperator bool `json:"requires_operator"`
}

// Step is one unit of work in a plan.
type Step struct {
	// ID is the change ID this step resolves.
	ID string `json:"id"`
	// Action is the reconciliation operation (CREATE, UPDATE, DELETE, NOOP).
	Action Action `json:"action"`
	// Target is the resource identifier being acted on.
	Target string `json:"target,omitempty"`
	// Phase is the phase number this step belongs to.
	Phase int `json:"phase"`
	// PhaseName is the phase's name.
	PhaseName string `json:"phase_name"`
	// Subsystem is the affected subsystem.
	Subsystem string `json:"subsystem"`
	// Field is the affected setting.
	Field string `json:"field"`
	// Risk is the change's risk classification.
	Risk diff.Risk `json:"risk"`
	// Summary is a one-line description.
	Summary string `json:"summary"`
	// Reason explains why the change is needed.
	Reason string `json:"reason"`
	// Current is the observed value.
	Current string `json:"current,omitempty"`
	// Desired is the target value.
	Desired string `json:"desired,omitempty"`
	// Commands are the shell commands this step would run, rendered as text
	// for the operator to read. Nothing here executes them.
	Commands []string `json:"commands,omitempty"`
	// RequiresRoot marks a step that would need elevated privilege.
	RequiresRoot bool `json:"requires_root"`
	// Disruptive marks a step that would interrupt connectivity.
	Disruptive bool `json:"disruptive"`
	// Reversible records whether the change could be undone.
	Reversible string `json:"reversible"`
	// Rollback carries recovery metadata for this step.
	Rollback *RollbackInfo `json:"rollback,omitempty"`
}

// Inputs holds content-addressed digests of the inputs the plan was derived from.
type Inputs struct {
	// ObservedDigest is the digest of observed host state.
	ObservedDigest string `json:"observed_digest"`
	// DesiredDigest is the digest of desired state.
	DesiredDigest string `json:"desired_digest"`
	// AssignmentDigest is the digest of role assignments.
	AssignmentDigest string `json:"assignment_digest"`
	// ConfigDigest is the digest of configuration.
	ConfigDigest string `json:"config_digest,omitempty"`
}

// Precondition is an explicit assertion that must hold before a plan can execute.
type Precondition struct {
	// ID is a stable identifier.
	ID string `json:"id"`
	// Description explains what is checked.
	Description string `json:"description"`
	// Expected describes the expected value or condition.
	Expected string `json:"expected"`
	// Satisfied reports whether the condition holds.
	Satisfied bool `json:"satisfied"`
	// Reason explains why it is not satisfied, when unsatisfied.
	Reason string `json:"reason,omitempty"`
}

// TransactionPhaseSummary describes one stage in a dry-run transaction.
type TransactionPhaseSummary struct {
	Phase   string `json:"phase"`
	Purpose string `json:"purpose"`
	Detail  string `json:"detail"`
}

// Transaction models the dry-run execution transaction lifecycle.
type Transaction struct {
	DryRun  bool                      `json:"dry_run"`
	Phases  []TransactionPhaseSummary `json:"phases"`
	Explain string                    `json:"explain"`
}

// VerificationCheck is one post-apply health check.
type VerificationCheck struct {
	Target      string `json:"target"`
	Check       string `json:"check"`
	Expectation string `json:"expectation"`
}

// Verification aggregates all post-apply verification checks.
type Verification struct {
	Checks []VerificationCheck `json:"checks"`
}

// Plan is a complete, reviewable description of intended work.
type Plan struct {
	// ID is a content-addressed identifier, so regenerating an identical plan
	// yields an identical ID and two plans can be compared.
	ID string `json:"id"`
	// GeneratedAt is when the plan was produced.
	GeneratedAt time.Time `json:"generated_at"`
	// Generation is the configuration generation this plan targets.
	Generation uint64 `json:"generation"`
	// Source describes where the configuration came from.
	Source string `json:"source"`
	// Live reports whether the plan was built against an observed host.
	Live bool `json:"live"`
	// Inputs holds content digests of the inputs.
	Inputs Inputs `json:"inputs"`
	// Preconditions are the conditions that must hold before execution.
	Preconditions []Precondition `json:"preconditions"`
	// Steps are the actionable changes, in phase order.
	Steps []Step `json:"steps"`
	// Blocked lists changes that cannot proceed.
	Blocked []diff.Change `json:"blocked,omitempty"`
	// Pending lists changes that are not yet determined.
	Pending []diff.Change `json:"pending,omitempty"`
	// ManagedResources lists the resources explicitly managed by THN.
	ManagedResources []string `json:"managed_resources,omitempty"`
	// UnmanagedResources lists observed resources deliberately not modified by THN.
	UnmanagedResources []string `json:"unmanaged_resources,omitempty"`
	// Transaction describes the dry-run transaction lifecycle.
	Transaction Transaction `json:"transaction"`
	// Verification describes post-apply verification checks.
	Verification Verification `json:"verification"`
	// Simulation describes the outcome without performing it.
	Simulation Simulation `json:"simulation"`
	// Ready reports whether the plan is complete and internally consistent.
	Ready bool `json:"ready"`
	// Summary is a one-line description.
	Summary string `json:"summary"`
}

// Simulation describes what applying the plan would do.
type Simulation struct {
	// Headline is the single most important consequence.
	Headline string `json:"headline"`
	// WouldApply lists the steps that would take effect.
	WouldApply []string `json:"would_apply,omitempty"`
	// AlreadySatisfied lists changes the host already matches.
	AlreadySatisfied []string `json:"already_satisfied,omitempty"`
	// Pending lists changes that could not be evaluated.
	Pending []string `json:"pending,omitempty"`
	// Blocked lists changes that cannot proceed.
	Blocked []string `json:"blocked,omitempty"`
	// Consequences describes the resulting behaviour.
	Consequences []string `json:"consequences,omitempty"`
	// Disruptions describes connectivity interruptions that would occur.
	Disruptions []string `json:"disruptions,omitempty"`
	// OutOfOrder lists steps that would violate a dependency.
	OutOfOrder []string `json:"out_of_order,omitempty"`
}

// Options configures plan generation.
type Options struct {
	// Generation is the configuration generation.
	Generation uint64
	// Source describes where the configuration was read from.
	Source string
	// Live reports whether an observed host was available.
	Live bool
	// Now overrides the timestamp, for deterministic tests.
	Now time.Time

	// Observed is the observed host state.
	Observed diff.Observed
	// Desired is the desired network state.
	Desired desired.State
	// Assignments are the role assignments.
	Assignments []host.Assignment
	// ConfigDigest is an optional explicit configuration digest.
	ConfigDigest string
	// Device is the observed host device.
	Device *host.Device
}

// Build produces a plan from a diff.
//
// The diff is the only input describing what needs to change; the planner does
// not re-compare observed against desired. Keeping comparison in one place is
// what guarantees that `thn plan` and `thn status` cannot disagree about what
// the differences are.
func Build(d diff.Result, opts Options) *Plan {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	obsDigest := ComputeObservedDigest(opts.Observed)
	desDigest := ComputeDesiredDigest(opts.Desired)
	assignDigest := ComputeAssignmentDigest(opts.Assignments)

	p := &Plan{
		GeneratedAt: now,
		Generation:  opts.Generation,
		Source:      opts.Source,
		Live:        opts.Live,
		Inputs: Inputs{
			ObservedDigest:   obsDigest,
			DesiredDigest:    desDigest,
			AssignmentDigest: assignDigest,
			ConfigDigest:     opts.ConfigDigest,
		},
	}

	// Only drift becomes an actionable step. Pending is outstanding work and
	// blocked is unresolvable; neither is something a plan should try to do.
	for _, c := range d.ByKind(diff.KindDrift) {
		step := stepFor(c)
		if step == nil {
			continue
		}
		p.Steps = append(p.Steps, *step)
	}
	p.Blocked = d.ByKind(diff.KindBlocked)
	p.Pending = d.ByKind(diff.KindPending)

	// DHCP and DNS intent is appended as DESCRIBED state, not as drift.
	//
	// These steps come from the document, not from a comparison against the
	// host: THN does not observe a DHCP or DNS service, so there is no
	// observed-vs-desired comparison to make and no drift to report. Adding
	// them here is what lets `thn plan` answer "what would this machine hand
	// out, and to whom" without pretending it can already do it.
	//
	// They carry no commands on purpose. A step whose Commands field contained
	// "systemctl enable dnsmasq" would assert that an implementation exists,
	// and nothing in this build starts or configures a service. The step says
	// the behaviour is desired and is not yet applied, which is the truth.
	p.Steps = append(p.Steps, serviceIntentSteps(opts.Desired, opts.Device)...)

	p.ManagedResources, p.UnmanagedResources = identifyResources(opts)
	p.Preconditions = buildPreconditions(opts, d, p.Inputs)
	p.Transaction = buildTransaction(p.Steps, p.Blocked, opts.Generation)
	p.Verification = buildVerification(opts.Desired, p.Steps)

	p.order()
	p.simulate()
	p.Ready = p.checkReady()

	// The ID is derived before the summary is rendered, because the summary
	// embeds it.
	p.ID = deriveID(p)
	p.Summary = p.summarise()
	return p
}

// ComputeObservedDigest computes a deterministic SHA-256 digest of observed host state.
func ComputeObservedDigest(obs diff.Observed) string {
	h := sha256.New()
	fmt.Fprintf(h, "supported=%t;host=%s;", obs.Supported, obs.HostName)
	fmt.Fprintf(h, "wan=%t:%s:%t;", obs.WANPresent, obs.WANName, obs.WANUp)
	fmt.Fprintf(h, "lan=%t:%s:%t;", obs.LANPresent, obs.LANName, obs.LANUp)
	sortAddrs := append([]string(nil), obs.LANAddresses...)
	sort.Strings(sortAddrs)
	fmt.Fprintf(h, "lan_addrs=%s;", strings.Join(sortAddrs, ","))
	fmt.Fprintf(h, "gw=%t:%s;", obs.HasDefaultRoute, obs.DefaultGateway)
	fmt.Fprintf(h, "fwd=%t:%t;", obs.IPv4ForwardingKnown, obs.IPv4Forwarding)
	fmt.Fprintf(h, "fw=%t:%d;", obs.FirewallActive, obs.FirewallRuleCount)
	fmt.Fprintf(h, "qos=%t:%s;", obs.QoSActive, obs.QoSAlgorithm)
	sortRes := append([]string(nil), obs.Resolvers...)
	sort.Strings(sortRes)
	fmt.Fprintf(h, "res=%t:%s;", obs.ResolversKnown, strings.Join(sortRes, ","))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ComputeDesiredDigest computes a deterministic SHA-256 digest of desired state.
func ComputeDesiredDigest(des desired.State) string {
	h := sha256.New()
	fmt.Fprintf(h, "gen=%d;name=%s;schema=%d;", des.Generation, des.Name, des.SchemaVersion)
	// The intent and the stable identities are part of the desired state, so
	// they are part of its digest. Leaving them out would let two documents
	// that differ only in whether a gateway was requested — or only in which
	// link the LAN selector referred to — produce the same desired digest
	// and therefore the same plan ID.
	fmt.Fprintf(h, "intent=%t:%s:%s;", des.Intent.Enabled, des.Intent.WANSelector, des.Intent.LANSelector)
	fmt.Fprintf(h, "wan=%t:%s:%s:%s:%d:%t;", des.WAN.Present, des.WAN.Name, des.WAN.StableID, des.WAN.Role, des.WAN.MTU, des.WAN.Up)
	sortAddrs := append([]string(nil), des.LAN.Addresses...)
	sort.Strings(sortAddrs)
	fmt.Fprintf(h, "lan=%t:%s:%s:%s:%d:%t:%s;", des.LAN.Present, des.LAN.Name, des.LAN.StableID, des.LAN.Role, des.LAN.MTU, des.LAN.Up, strings.Join(sortAddrs, ","))
	fmt.Fprintf(h, "addr=%t:%s:%t:%t;", des.Addressing.UpstreamPresent, des.Addressing.DefaultGateway, des.Addressing.IPv4Forwarding, des.Addressing.IPv6Forwarding)
	sortNAT := append([]string(nil), des.NAT.Interfaces...)
	sort.Strings(sortNAT)
	fmt.Fprintf(h, "nat=%t:%t:%s;", des.NAT.Enabled, des.NAT.Resolved, strings.Join(sortNAT, ","))
	fmt.Fprintf(h, "fw=%t:%s:%s:%t:%t;", des.Firewall.Enabled, des.Firewall.Backend, des.Firewall.DefaultInboundPolicy, des.Firewall.AllowEstablished, des.Firewall.AllowLoopback)
	fmt.Fprintf(h, "qos=%t:%t:%s:%s:%d:%d;",
		des.QoS.Enabled, des.QoS.Resolved, des.QoS.Algorithm,
		des.QoS.Interface, des.QoS.DownloadKbps, des.QoS.UploadKbps)

	// M7.4 extends the QoS content address with the role, the stable identity
	// and the overhead compensation.
	//
	// Each is asked-for information rather than an observation, which is the
	// rule this function follows throughout: the desired digest must be the
	// same on two machines given the same document. A rate, an algorithm and
	// a link are all choices someone made.
	//
	// Capability and the observed qdiscs are deliberately ABSENT. Both describe
	// the host rather than the request, and including them would mean a plan
	// generated on a machine with CAKE had a different identity from the same
	// plan generated on a machine without — which would break content
	// addressing for the one class of information where it is least useful.
	// They belong to the observed digest, and they are rendered into the QoS
	// plan step where an operator can act on them.
	fmt.Fprintf(h, "qosrole=%s:%s:%d;",
		des.QoS.Role, des.QoS.StableID, des.QoS.OverheadPercent)
	for _, c := range des.QoS.Clients {
		fmt.Fprintf(h, "qosclient=%s:%s:%d:%d:%d:%d:%s:%t;",
			c.ID, c.IP, c.DownloadKbps, c.UploadKbps, c.MinDownloadKbps, c.MinUploadKbps, c.Priority, c.Disabled)
	}
	sortDNS := append([]string(nil), des.DNS.Servers...)
	sort.Strings(sortDNS)
	fmt.Fprintf(h, "dns=%t:%s;", des.DNS.Present, strings.Join(sortDNS, ","))

	// The DNS SERVICE is content-addressed separately from the host's own
	// resolver set, because they are separate decisions. Without this, a
	// document that turned the service on, moved its listen address or
	// changed its upstream resolvers would produce the same desired digest
	// and therefore the same plan ID as one that did not.
	//
	// Every collection is sorted, so two documents listing the same
	// resolvers in a different order describe the same machine and must not
	// produce two different digests.
	svc := des.DNS.Service
	sortSvcUpstream := append([]string(nil), svc.Upstream...)
	sort.Strings(sortSvcUpstream)
	fmt.Fprintf(h, "dnssvc=%t:%s:%s:%s:%s:%t:%s:%s;",
		svc.Enabled, svc.LANSelector, svc.Interface, svc.StableID,
		svc.ListenAddress, svc.Resolved, strings.Join(sortSvcUpstream, ","),
		svc.LocalDomain)
	// The upstream source is part of the identity: a document that resolves
	// the same resolver set through dns.upstream and one that does so through
	// network.dns are different documents, and the milestone's whole point is
	// that the difference is visible rather than silently absorbed.
	fmt.Fprintf(h, "dnssrc=%s;", svc.UpstreamSource)

	// DHCP intent is content-addressed too: changing a pool, the advertised
	// router, the lease time or whether DHCP is wanted at all all change what
	// clients would be given, so all of it changes the digest.
	//
	// Ranges keep declaration order. Reordering two disjoint pools describes
	// the same set of addresses, but the order is the operator's written
	// intent and sorting would hide an edit that is otherwise invisible.
	d := des.DHCP
	fmt.Fprintf(h, "dhcp=%t:%s:%s:%s:%s:%s:%s:%t:%t:%s;",
		d.Enabled, d.LANSelector, d.Interface, d.StableID,
		d.Subnet, d.Router, strings.Join(d.Ranges, ","),
		d.Authoritative, d.Resolved, d.LeaseTime)
	sortAdvDNS := append([]string(nil), d.AdvertisedDNS...)
	sort.Strings(sortAdvDNS)
	fmt.Fprintf(h, "dhcpdns=%s;dhcpdomain=%s;", strings.Join(sortAdvDNS, ","), d.Domain)

	// Multi-WAN intent is content-addressed too: mode, members, weights,
	// priorities and health policy change routing and failover behavior,
	// so all of it changes the digest.
	mw := des.MultiWAN
	fmt.Fprintf(h, "mwan=%t:%t:%s:%s;", mw.Enabled, mw.Resolved, mw.Mode, mw.Policy)
	fmt.Fprintf(h, "mwanhc=%s:%d:%d;", mw.HealthCheck.Target, mw.HealthCheck.Interval, mw.HealthCheck.Timeout)
	for _, m := range mw.Members {
		fmt.Fprintf(h, "mwanm=%s:%s:%s:%d:%d:%t:%s;",
			m.ID, m.Interface, m.StableID, m.Weight, m.Priority, m.Enabled, m.Gateway)
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ComputeAssignmentDigest computes a deterministic SHA-256 digest of role assignments.
func ComputeAssignmentDigest(assignments []host.Assignment) string {
	h := sha256.New()
	sorted := append([]host.Assignment(nil), assignments...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Role != sorted[j].Role {
			return sorted[i].Role < sorted[j].Role
		}
		return sorted[i].Selector < sorted[j].Selector
	})
	for _, a := range sorted {
		fmt.Fprintf(h, "%s=%s;", a.Role, a.Selector)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// identifyResources categorises resources into managed vs unmanaged.
func identifyResources(opts Options) ([]string, []string) {
	var managed []string
	var unmanaged []string

	if opts.Desired.WAN.Present && opts.Desired.WAN.Name != "" {
		managed = append(managed, fmt.Sprintf("interface:%s (role:wan)", opts.Desired.WAN.Name))
	}
	if opts.Desired.LAN.Present && opts.Desired.LAN.Name != "" {
		managed = append(managed, fmt.Sprintf("interface:%s (role:lan)", opts.Desired.LAN.Name))
		for _, addr := range opts.Desired.LAN.Addresses {
			managed = append(managed, fmt.Sprintf("address:%s dev %s", addr, opts.Desired.LAN.Name))
		}
	}
	if opts.Desired.Addressing.UpstreamPresent && opts.Desired.Addressing.DefaultGateway != "" {
		managed = append(managed, fmt.Sprintf("route:default via %s", opts.Desired.Addressing.DefaultGateway))
	}
	if opts.Desired.Addressing.IPv4Forwarding {
		managed = append(managed, "sysctl:net.ipv4.ip_forward")
	}
	if opts.Desired.Firewall.Enabled {
		managed = append(managed, "nftables:table inet thn")
	}
	if opts.Desired.NAT.Enabled {
		managed = append(managed, "nftables:nat masquerade")
	}

	if opts.Device != nil {
		for _, iface := range opts.Device.Interfaces {
			if iface.Role == host.RoleWAN || iface.Role == host.RoleLAN {
				continue
			}
			unmanaged = append(unmanaged, fmt.Sprintf("interface:%s (kind:%s)", iface.SystemName, iface.Kind))
		}
	}

	sort.Strings(managed)
	sort.Strings(unmanaged)
	return managed, unmanaged
}

// buildPreconditions constructs the explicit preconditions for a plan.
func buildPreconditions(opts Options, d diff.Result, inputs Inputs) []Precondition {
	var pre []Precondition

	pre = append(pre, Precondition{
		ID:          "observed-state-fresh",
		Description: "observed host state matches plan generation state",
		Expected:    inputs.ObservedDigest,
		Satisfied:   true,
	})

	pre = append(pre, Precondition{
		ID:          "desired-state-aligned",
		Description: "desired network configuration matches plan target",
		Expected:    inputs.DesiredDigest,
		Satisfied:   true,
	})

	if opts.Desired.WAN.Present {
		wanSatisfied := opts.Observed.WANPresent
		wanReason := ""
		if !wanSatisfied {
			wanReason = "WAN interface is not resolved or present on host"
		}
		pre = append(pre, Precondition{
			ID:          "wan-role-resolved",
			Description: "WAN logical role is bound and interface is present",
			Expected:    "resolved",
			Satisfied:   wanSatisfied,
			Reason:      wanReason,
		})
	}

	if opts.Desired.LAN.Present {
		lanSatisfied := opts.Observed.LANPresent
		lanReason := ""
		if !lanSatisfied {
			lanReason = "LAN interface is not resolved or present on host"
		}
		pre = append(pre, Precondition{
			ID:          "lan-role-resolved",
			Description: "LAN logical role is bound and interface is present",
			Expected:    "resolved",
			Satisfied:   lanSatisfied,
			Reason:      lanReason,
		})
	}

	noBlocked := len(d.ByKind(diff.KindBlocked)) == 0
	blockedReason := ""
	if !noBlocked {
		blockedReason = fmt.Sprintf("%d blocking change(s) detected", len(d.ByKind(diff.KindBlocked)))
	}
	pre = append(pre, Precondition{
		ID:          "no-blocking-conflicts",
		Description: "no blocking configuration or identity conflicts exist",
		Expected:    "clean",
		Satisfied:   noBlocked,
		Reason:      blockedReason,
	})

	return pre
}

// ValidatePreconditions re-evaluates a plan's preconditions against current live observation.
func (p *Plan) ValidatePreconditions(currentObs diff.Observed, currentDes desired.State) (bool, []Precondition) {
	currentObsDigest := ComputeObservedDigest(currentObs)
	currentDesDigest := ComputeDesiredDigest(currentDes)

	out := make([]Precondition, len(p.Preconditions))
	allSatisfied := true

	for i, prec := range p.Preconditions {
		out[i] = prec
		switch prec.ID {
		case "observed-state-fresh":
			if currentObsDigest != p.Inputs.ObservedDigest {
				out[i].Satisfied = false
				out[i].Reason = fmt.Sprintf("host state changed (digest %s != expected %s); plan is stale",
					currentObsDigest, p.Inputs.ObservedDigest)
				allSatisfied = false
			}
		case "desired-state-aligned":
			if currentDesDigest != p.Inputs.DesiredDigest {
				out[i].Satisfied = false
				out[i].Reason = fmt.Sprintf("desired configuration changed (digest %s != expected %s); plan is stale",
					currentDesDigest, p.Inputs.DesiredDigest)
				allSatisfied = false
			}
		case "wan-role-resolved":
			if !currentObs.WANPresent {
				out[i].Satisfied = false
				out[i].Reason = "WAN interface is not present"
				allSatisfied = false
			}
		case "lan-role-resolved":
			if !currentObs.LANPresent {
				out[i].Satisfied = false
				out[i].Reason = "LAN interface is not present"
				allSatisfied = false
			}
		default:
			if !out[i].Satisfied {
				allSatisfied = false
			}
		}
	}

	return allSatisfied, out
}

// buildTransaction constructs the dry-run transaction stage breakdown.
func buildTransaction(steps []Step, blocked []diff.Change, gen uint64) Transaction {
	phases := []TransactionPhaseSummary{
		{
			Phase:   "PREPARE",
			Purpose: "verify preconditions, link states and state freshness",
			Detail:  "ensure expected hardware identities, kernel modules and capabilities are available",
		},
		{
			Phase:   "BACKUP",
			Purpose: "capture current network state for rollback",
			Detail:  "record current IP addresses, default routes, sysctl values and active firewall rules",
		},
		{
			Phase:   "VALIDATE",
			Purpose: "validate rendered command sequences against dependency graph",
			Detail:  fmt.Sprintf("check %d operations across 4 execution phases", len(steps)),
		},
		{
			Phase:   "APPLY",
			Purpose: "describe planned configuration steps without mutating host",
			Detail:  fmt.Sprintf("model %d operations for configuration generation %d", len(steps), gen),
		},
		{
			Phase:   "HEALTH_CHECK",
			Purpose: "describe post-apply verification checks",
			Detail:  "verify interface carrier, address assignment, IPv4 forwarding and firewall reachability",
		},
		{
			Phase:   "COMMIT",
			Purpose: "describe final transaction persistence",
			Detail:  fmt.Sprintf("record generation %d into state store after all checks succeed", gen),
		},
	}

	explain := "This is a dry-run transaction plan. No operations will be executed on this host."
	if len(blocked) > 0 {
		explain = fmt.Sprintf("This transaction is BLOCKED: %d unresolvable issue(s) prevent execution.", len(blocked))
	}

	return Transaction{
		DryRun:  true,
		Phases:  phases,
		Explain: explain,
	}
}

// buildVerification constructs the expected post-apply verification checks.
func buildVerification(des desired.State, steps []Step) Verification {
	var checks []VerificationCheck

	if des.LAN.Present && des.LAN.Name != "" {
		checks = append(checks, VerificationCheck{
			Target:      des.LAN.Name,
			Check:       "link_carrier",
			Expectation: "interface administrative state is UP",
		})
		for _, addr := range des.LAN.Addresses {
			checks = append(checks, VerificationCheck{
				Target:      des.LAN.Name,
				Check:       "address_assigned",
				Expectation: fmt.Sprintf("interface %s carries CIDR %s", des.LAN.Name, addr),
			})
		}
	}

	if des.Addressing.IPv4Forwarding {
		checks = append(checks, VerificationCheck{
			Target:      "sysctl:net.ipv4.ip_forward",
			Check:       "kernel_forwarding",
			Expectation: "net.ipv4.ip_forward equals 1",
		})
	}

	if des.Firewall.Enabled {
		checks = append(checks, VerificationCheck{
			Target:      "nftables:table inet thn",
			Check:       "firewall_active",
			Expectation: "table inet thn is active with default policy " + des.Firewall.DefaultInboundPolicy,
		})
	}

	if des.NAT.Enabled && des.NAT.Resolved {
		checks = append(checks, VerificationCheck{
			Target:      "nftables:masquerade",
			Check:       "nat_masquerade",
			Expectation: fmt.Sprintf("masquerade rule active for %s", strings.Join(des.NAT.Interfaces, ", ")),
		})
	}

	return Verification{Checks: checks}
}

// stepFor builds a step from a drift change, or nil when the change carries
// no actionable work.
func stepFor(c diff.Change) *Step {
	phase := phaseFor(c.Subsystem)

	s := &Step{
		ID:           c.ID,
		Action:       actionFor(c),
		Target:       targetFor(c),
		Phase:        phase.Number,
		PhaseName:    phase.Name,
		Subsystem:    c.Subsystem,
		Field:        c.Field,
		Risk:         c.Risk,
		Summary:      summaryFor(c),
		Reason:       c.Reason,
		Current:      c.Current,
		Desired:      c.Desired,
		RequiresRoot: true,
		Reversible:   reversibilityFor(c),
		Rollback:     rollbackFor(c),
	}

	s.Commands = commandsFor(c)
	s.Disruptive = isDisruptive(c)

	return s
}

// actionFor determines the reconciliation Action for a diff change.
func actionFor(c diff.Change) Action {
	switch c.ID {
	case "lan-address-add", "default-route-add", "firewall-absent", "qos-absent":
		return ActionCreate
	case "lan-address-remove":
		return ActionDelete
	case "wan-link-state", "lan-link-state", "default-route-gateway", "ip-forwarding",
		"firewall-empty", "qos-algorithm", "qos-rate", "qos-policy", "resolvers":
		return ActionUpdate
	case "wan-name-mismatch", "lan-name-mismatch":
		return ActionConflict
	default:
		if c.Kind == diff.KindBlocked {
			return ActionBlocked
		}
		if c.Current == "" || c.Current == "(none)" || c.Current == "(no default route)" {
			return ActionCreate
		}
		return ActionUpdate
	}
}

// targetFor identifies the target resource from a change.
func targetFor(c diff.Change) string {
	switch c.Subsystem {
	case "address", "link":
		return c.Field
	case "route":
		return "route:default"
	case "sysctl":
		return "sysctl:net.ipv4.ip_forward"
	case "nftables":
		return "nftables:table inet thn"
	case "qdisc":
		return "qdisc:" + qosDevice(c.Desired)
	default:
		return c.Field
	}
}

// rollbackFor constructs recovery metadata for a change.
func rollbackFor(c diff.Change) *RollbackInfo {
	rb := &RollbackInfo{
		Target:        c.Field,
		PreviousState: c.Current,
		Reversibility: reversibilityFor(c),
	}

	switch c.ID {
	case "lan-address-add":
		if c.Desired != "" && !strings.Contains(c.Desired, "(none)") {
			rb.RestoreCommands = []string{fmt.Sprintf("ip addr del %s dev %s", c.Desired, lanNameFromChange(c))}
		}
	case "lan-address-remove":
		for _, addr := range splitList(c.Current) {
			rb.RestoreCommands = append(rb.RestoreCommands, fmt.Sprintf("ip addr add %s dev %s", addr, lanNameFromChange(c)))
		}
	case "wan-link-state", "lan-link-state":
		if c.Current != "" && c.Current != "(none)" {
			rb.RestoreCommands = []string{fmt.Sprintf("ip link set %s %s", interfaceFromField(c.Field), c.Current)}
		}
	case "default-route-add":
		rb.RestoreCommands = []string{"ip route del default"}
	case "default-route-gateway":
		if c.Current != "" && c.Current != "(no default route)" {
			rb.RestoreCommands = []string{fmt.Sprintf("ip route replace default via %s", c.Current)}
		} else {
			rb.RestoreCommands = []string{"ip route del default"}
		}
	case "ip-forwarding":
		if c.Current == "disabled" || c.Current == "0" || c.Current == "false" {
			rb.RestoreCommands = []string{"sysctl -w net.ipv4.ip_forward=0"}
		} else {
			rb.RestoreCommands = []string{"sysctl -w net.ipv4.ip_forward=1"}
		}
	case "firewall-absent", "firewall-empty":
		rb.RestoreCommands = []string{"nft delete table inet thn"}
		rb.Reversibility = "reversible"
	case "qos-absent":
		device := qosDevice(c.Desired)
		if device != "" {
			rb.RestoreCommands = []string{fmt.Sprintf("tc qdisc del dev %s root", device)}
		}
	case "qos-algorithm", "qos-rate", "qos-policy":
		device := qosDevice(c.Desired)
		if device != "" && c.Current != "" {
			rb.RestoreCommands = []string{fmt.Sprintf("tc qdisc replace dev %s root %s", device, c.Current)}
		}
	case "resolvers":
		if c.Current != "" && c.Current != "(none)" {
			rb.RestoreCommands = []string{fmt.Sprintf("# restore previous resolvers %s", c.Current)}
		}
	}

	return rb
}

// phaseFor maps a subsystem onto its phase.
func phaseFor(subsystem string) Phase {
	switch subsystem {
	case "address", "link":
		return phasesTable()[0]
	case "sysctl":
		return phasesTable()[1]
	case "nftables", "qdisc":
		return phasesTable()[2]
	case "dhcp", "dns":
		return phasesTable()[4]
	default:
		return phasesTable()[3]
	}
}

// serviceIntentSteps describes the requested DHCP and DNS behaviour.
//
// # Why these are steps rather than drift
//
// Every other step in a plan answers "the host differs from what was asked
// for". These answer "what was asked for" on its own. THN observes
// interfaces, addresses, routes, forwarding and firewall rules; it does not
// observe a running DHCP or DNS service, so there is no observed value to
// compare against and no drift to synthesise. Emitting them keeps `thn plan`
// able to show the whole intent in one place.
//
// # Why they carry no commands
//
// A step normally renders the commands that would enact it. These do not,
// and that absence is deliberate rather than an omission: this build does not
// start, configure or install a DHCP or DNS service, so rendering
// "systemctl enable dnsmasq" would describe an implementation that does not
// exist. The step instead says the behaviour is desired and is not yet
// applied, which is both true and checkable.
//
// The identity used in Target is the stable interface ID where one is known,
// so a plan generated after a NIC moves slots still refers to the same link.
func serviceIntentSteps(des desired.State, dev *host.Device) []Step {
	var out []Step

	if des.DHCP.Enabled {
		out = append(out, dhcpIntentStep(des.DHCP))
	}
	if des.DNS.Service.Enabled {
		out = append(out, dnsServiceIntentStep(des.DNS.Service))
	}
	if des.QoS.Enabled {
		out = append(out, qosIntentStep(des.QoS, dev))
	}
	if des.MultiWAN.Enabled || len(des.MultiWAN.Members) > 1 {
		out = append(out, multiWANIntentStep(des.MultiWAN, dev))
	}

	return out
}

// qosIntentStep describes the requested shaping policy.
//
// # Why capability is read here and not from desired state
//
// Capability is an OBSERVED fact about this host, not something the operator
// asked for, so it is read from the device rather than carried in
// desired.State. Putting it in the desired state would make the desired digest
// depend on which machine produced it, and two identical configurations on two
// different hosts would stop being the same machine — which is exactly the
// property the digest exists to preserve.
//
// The same reasoning keeps observed qdiscs out of it. They describe the host,
// not the request, and they already belong to the observed digest.
//
// # Why this is separate from qdisc drift
//
// internal/diff already compares the observed qdisc against the desired one and
// emits qos-absent or qos-algorithm when they differ. Those changes describe
// drift: the host does not match the document.
//
// This step describes the document itself, and it exists for the case the diff
// cannot express. When CAKE capability is unknown the desired policy is
// perfectly coherent and there is nothing to compare against — the host has
// not been asked and must not be. Without this step a plan would show no QoS at
// all in that state, and an operator would conclude THN had ignored their
// configuration.
//
// # Why it carries no commands
//
// There is no production QoS applier. A step rendering "tc qdisc replace …"
// would assert an implementation this build does not have, exactly as
// systemctl enable dnsmasq would in M7.3. The step states the policy and, when
// the capability is unresolved, says which prerequisite is outstanding.
func qosIntentStep(d desired.QoS, dev *host.Device) Step {
	phase := phasesTable()[4]

	cap := qos.CakeCapability(dev)
	observed := observedQdiscKinds(dev)

	summary := fmt.Sprintf("shape the %s with %s at %d/%d kbit/s",
		orNoneLabel(d.Role, d.Interface), orNoneLabel(d.Algorithm, "(no algorithm)"),
		d.DownloadKbps, d.UploadKbps)

	reason := "the document asks for traffic shaping on the uplink; " +
		"no qdisc is attached, changed or removed by this build"

	// An unresolved capability is reported on the step rather than only in the
	// findings, because the plan is where an operator asks "what is left to
	// do?" and the honest answer is "confirm the kernel provides this".
	switch string(cap.State) {
	case string(qos.CapabilityUnknown):
		reason = "the document asks for traffic shaping, but THN does not have sufficient " +
			"evidence that " + orNoneLabel(d.Algorithm, "this algorithm") + " can be used here; " +
			"no network mutation was performed to find out"
	case string(qos.CapabilityUnavailable):
		reason = "the document asks for traffic shaping, but THN has evidence that " +
			orNoneLabel(d.Algorithm, "this algorithm") + " cannot be used on this host"
	}

	target := serviceTarget(d.Role, d.Interface, d.StableID)
	if target == "" {
		target = "qos:" + orNoneLabel(d.Role, "wan")
	}

	return Step{
		ID:           "qos-intent",
		Action:       qosAction(d.Algorithm, observed),
		Target:       target,
		Phase:        phase.Number,
		PhaseName:    phase.Name,
		Subsystem:    "qos",
		Field:        "qos.enabled",
		Risk:         diff.RiskNone,
		Summary:      summary,
		Reason:       reason,
		Current:      currentQdiscText(observed),
		Desired:      qosDesiredText(d, cap),
		Commands:     nil,
		RequiresRoot: false,
		Disruptive:   false,
		Reversible:   "not-applied",
	}
}

// observedQdiscKinds lists the disciplines currently attached.
//
// Pure observation. Nothing here is adopted or removed: THN reads qdiscs and
// reports them, and ownership is a separate question this milestone
// deliberately does not answer.
func observedQdiscKinds(dev *host.Device) []string {
	if dev == nil {
		return nil
	}
	out := make([]string, 0, len(dev.TrafficControl.Qdiscs))
	for _, q := range dev.TrafficControl.Qdiscs {
		if q.Kind != "" {
			out = append(out, q.Kind)
		}
	}
	sort.Strings(out)
	return out
}

// qosAction classifies the step as a no-op or an update.
//
// A host already carrying the requested discipline is a NOOP: the desired state
// is satisfied, and reporting it as work to do would teach operators to ignore
// the plan. Anything else is an UPDATE, because the document asks for a policy
// the host does not currently have.
//
// The observed disciplines are observation only. THN does not adopt them, so
// "fq_codel is attached" is never a reason to claim the job is done.
func qosAction(algorithm string, observed []string) Action {
	if len(observed) == 1 && strings.EqualFold(observed[0], algorithm) {
		return ActionNoop
	}
	return ActionUpdate
}

// currentQdiscText renders what is attached now.
func currentQdiscText(observed []string) string {
	if len(observed) == 0 {
		return "(no queue discipline observed)"
	}
	return strings.Join(observed, ", ") + " (observed, not adopted by THN)"
}

// qosDesiredText renders the desired shaping policy for a step.
func qosDesiredText(d desired.QoS, cap qos.Evidence) string {
	parts := []string{
		"enabled",
		"algorithm=" + orNoneLabel(d.Algorithm, "(none)"),
		"role=" + orNoneLabel(d.Role, "(unset)"),
	}
	if d.DownloadKbps > 0 || d.UploadKbps > 0 {
		parts = append(parts, fmt.Sprintf("download=%dkbit/s upload=%dkbit/s", d.DownloadKbps, d.UploadKbps))
	}
	if len(d.Clients) > 0 {
		parts = append(parts, fmt.Sprintf("clients=%d", len(d.Clients)))
	}
	// The capability verdict is rendered into the step because it is the
	// prerequisite an operator has to resolve. It is deliberately not in the
	// desired digest: it describes this host, not the request.
	parts = append(parts, "capability="+string(cap.State))
	return strings.Join(parts, " ")
}

// orNoneLabel renders an empty string as an explicit label.
func orNoneLabel(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// dhcpIntentStep describes the requested DHCP behaviour.
func dhcpIntentStep(d desired.DHCP) Step {
	phase := phasesTable()[4]

	summary := "serve addresses on the LAN"
	if len(d.Ranges) > 0 {
		summary += " from " + strings.Join(d.Ranges, ", ")
	}

	reason := "the document asks for DHCP on the LAN; no address service is started or configured by this build"
	if !d.Resolved {
		reason = "the document asks for DHCP but the LAN or its address pool is not yet determined, so no pool can be planned"
	}

	target := serviceTarget(d.LANSelector, d.Interface, d.StableID)
	if target == "" {
		target = "dhcp:lan"
	}

	return Step{
		ID:        "dhcp-intent",
		Action:    ActionCreate,
		Target:    target,
		Phase:     phase.Number,
		PhaseName: phase.Name,
		Subsystem: "dhcp",
		Field:     "dhcp.enabled",
		Risk:      diff.RiskNone,
		Summary:   summary,
		Reason:    reason,
		Current:   "(no DHCP service is applied by this build)",
		Desired:   dhcpDesiredText(d),
		// Deliberately empty. See the function comment.
		Commands:     nil,
		RequiresRoot: false,
		Disruptive:   false,
		Reversible:   "not-applied",
	}
}

// dnsServiceIntentStep describes the requested DNS behaviour.
func dnsServiceIntentStep(s desired.DNSService) Step {
	phase := phasesTable()[4]

	summary := "serve DNS on the LAN"
	if len(s.Upstream) > 0 {
		summary += " forwarding to " + strings.Join(s.Upstream, ", ")
	}

	reason := "the document asks for a DNS service on the LAN; no resolver is started or configured by this build"
	if !s.Resolved {
		reason = "the document asks for DNS but the LAN or its listen address is not yet determined, so no resolver can be planned"
	}

	target := serviceTarget(s.LANSelector, s.Interface, s.StableID)
	if target == "" {
		target = "dns:lan"
	}

	return Step{
		ID:           "dns-service-intent",
		Action:       ActionCreate,
		Target:       target,
		Phase:        phase.Number,
		PhaseName:    phase.Name,
		Subsystem:    "dns",
		Field:        "dns.enabled",
		Risk:         diff.RiskNone,
		Summary:      summary,
		Reason:       reason,
		Current:      "(no DNS service is applied by this build)",
		Desired:      dnsDesiredText(s),
		Commands:     nil,
		RequiresRoot: false,
		Disruptive:   false,
		Reversible:   "not-applied",
	}
}

// multiWANIntentStep describes the requested multi-WAN routing and balancing policy.
//
// Like DHCP, DNS and QoS, it carries NO shell or network mutation commands:
// this build does not touch ip rule, ip route, or nftables. It states the
// requested mode, priorities, weights and consequences without faking an applier.
func multiWANIntentStep(m desired.MultiWAN, dev *host.Device) Step {
	phase := phasesTable()[4]

	mode := m.Mode
	if mode == "" {
		mode = "single"
	}

	summary := fmt.Sprintf("route Internet traffic via %d WAN uplink(s) in %s mode",
		len(m.Members), mode)

	reason := "the document asks for multi-WAN routing; " +
		"no routing table, ip rule, or nftables state is modified by this build"
	if !m.Resolved {
		reason = "the document asks for multi-WAN routing, but one or more WAN members have not yet been resolved against this host"
	}

	var desiredParts []string
	desiredParts = append(desiredParts, "mode="+mode, "policy="+m.Policy)
	for _, mem := range m.Members {
		desiredParts = append(desiredParts, fmt.Sprintf("%s:%s(p=%d,w=%d,en=%t)",
			mem.ID, orNoneLabel(mem.Interface, mem.StableID), mem.Priority, mem.Weight, mem.Enabled))
	}

	return Step{
		ID:           "multi-wan-intent",
		Action:       multiWANAction(m, dev),
		Target:       "routing:multi-wan",
		Phase:        phase.Number,
		PhaseName:    phase.Name,
		Subsystem:    "routing",
		Field:        "multi_wan.mode",
		Risk:         diff.RiskNone,
		Summary:      summary,
		Reason:       reason,
		Current:      currentWANText(m, dev),
		Desired:      strings.Join(desiredParts, " "),
		Commands:     nil,
		RequiresRoot: false,
		Disruptive:   false,
		Reversible:   "not-applied",
	}
}

// multiWANAction classifies the multi-WAN planning step action.
func multiWANAction(m desired.MultiWAN, dev *host.Device) Action {
	if dev == nil || len(dev.Routes) == 0 {
		return ActionCreate
	}
	if m.Mode == "single" && len(m.Members) == 1 {
		for _, r := range dev.Routes {
			if (r.Destination == "default" || r.Destination == "0.0.0.0/0") &&
				r.Interface != "" && (r.Interface == m.Members[0].Interface || r.Interface == m.Members[0].StableID) {
				return ActionNoop
			}
		}
	}
	return ActionUpdate
}

// currentWANText renders the current observed default WAN routing state.
func currentWANText(m desired.MultiWAN, dev *host.Device) string {
	if dev == nil || len(dev.Routes) == 0 {
		return "(no default WAN route observed)"
	}
	var defRoutes []string
	for _, r := range dev.Routes {
		if r.Destination == "default" || r.Destination == "0.0.0.0/0" {
			defRoutes = append(defRoutes, fmt.Sprintf("via %s dev %s", r.Gateway, r.Interface))
		}
	}
	if len(defRoutes) == 0 {
		return "(no default WAN route observed)"
	}
	return strings.Join(defRoutes, ", ") + " (observed, not managed by multi-WAN)"
}

// serviceTarget builds a stable identity for a service step.
//
// The stable ID is preferred over the kernel name so that a plan generated
// before and after a NIC moves slots refers to the same link. Falls back to
// the selector, which is what the document actually wrote.
func serviceTarget(selector, iface, stableID string) string {
	switch {
	case stableID != "":
		return stableID
	case selector != "":
		return selector
	default:
		return iface
	}
}

// dhcpDesiredText renders the desired DHCP state for a step's Desired field.
func dhcpDesiredText(d desired.DHCP) string {
	parts := []string{"enabled"}
	if d.Subnet != "" {
		parts = append(parts, "lan="+d.Subnet)
	}
	if len(d.Ranges) > 0 {
		parts = append(parts, "range="+strings.Join(d.Ranges, ","))
	}
	if d.Router != "" {
		parts = append(parts, "router="+d.Router)
	}
	return strings.Join(parts, " ")
}

// dnsDesiredText renders the desired DNS state for a step's Desired field.
func dnsDesiredText(s desired.DNSService) string {
	parts := []string{"enabled"}
	if s.ListenAddress != "" {
		parts = append(parts, "listen="+s.ListenAddress)
	}
	if len(s.Upstream) > 0 {
		parts = append(parts, "upstream="+strings.Join(s.Upstream, ","))
	}
	if s.UpstreamSource != "" {
		parts = append(parts, "source="+s.UpstreamSource)
	}
	return strings.Join(parts, " ")
}

// summaryFor renders a one-line description of a change.
func summaryFor(c diff.Change) string {
	switch c.ID {
	case "wan-link-state", "lan-link-state":
		return fmt.Sprintf("set %s link state to %s", c.Field, c.Desired)
	case "lan-address-add":
		return "add the configured address to the LAN interface"
	case "lan-address-remove":
		return "remove an address the configuration does not list"
	case "default-route-add":
		return "install the configured default route"
	case "default-route-gateway":
		return "point the default route at the configured gateway"
	case "ip-forwarding":
		return "enable IPv4 forwarding"
	case "firewall-absent":
		return "install the configured firewall ruleset"
	case "firewall-empty":
		return "populate the empty firewall ruleset"
	case "qos-absent":
		return "install the configured queue discipline"
	case "qos-algorithm", "qos-rate", "qos-policy":
		return "reconcile traffic control to match configured policy"
	case "resolvers":
		return "replace the resolver set"
	default:
		return fmt.Sprintf("reconcile %s", c.Field)
	}
}

// reversibilityFor classifies whether a change could be undone.
func reversibilityFor(c diff.Change) string {
	switch c.Risk {
	case diff.RiskCritical:
		return "partially-reversible"
	case diff.RiskHigh:
		return "reversible"
	case diff.RiskMedium:
		return "reversible"
	default:
		return "reversible"
	}
}

// isDisruptive reports whether a change would interrupt connectivity.
func isDisruptive(c diff.Change) bool {
	switch c.ID {
	case "lan-address-remove", "default-route-gateway",
		"firewall-absent", "firewall-empty", "qos-absent", "qos-algorithm", "qos-rate", "qos-policy":
		return true
	default:
		return c.Risk == diff.RiskCritical
	}
}

// commandsFor renders the commands a change would run.
//
// These strings are for the operator to read and for review. They are never
// passed to exec: every one of them is a state-changing invocation that
// internal/guard would refuse.
func commandsFor(c diff.Change) []string {
	switch c.ID {
	case "wan-link-state", "lan-link-state":
		return []string{fmt.Sprintf("ip link set %s %s", interfaceFromField(c.Field), c.Desired)}

	case "lan-address-add":
		return []string{fmt.Sprintf("ip addr add %s dev %s", c.Desired, lanNameFromChange(c))}

	case "lan-address-remove":
		var cmds []string
		for _, addr := range splitList(c.Current) {
			cmds = append(cmds, fmt.Sprintf("ip addr del %s dev %s", addr, lanNameFromChange(c)))
		}
		return cmds

	case "default-route-add":
		return []string{fmt.Sprintf("ip route add default via %s", c.Desired)}

	case "default-route-gateway":
		return []string{fmt.Sprintf("ip route replace default via %s", c.Desired)}

	case "ip-forwarding":
		return []string{"sysctl -w net.ipv4.ip_forward=1"}

	case "firewall-absent", "firewall-empty":
		return firewallCommands(c.Desired)

	case "qos-absent", "qos-algorithm", "qos-rate", "qos-policy":
		return qosCommands(c)

	case "resolvers":
		return []string{fmt.Sprintf("# write resolvers %s to the resolver configuration", c.Desired)}

	default:
		return nil
	}
}

// qosCommands renders the tc command for a shaping change.
func qosCommands(c diff.Change) []string {
	device := qosDevice(c.Desired)
	if device == "" {
		return nil
	}

	down, up := qosRates(c.Desired)
	if down == 0 || up == 0 {
		return []string{fmt.Sprintf("tc qdisc replace dev %s root %s", device, qosAlgorithm(c.Desired))}
	}
	return []string{fmt.Sprintf(
		"tc qdisc replace dev %s root %s bandwidth %dkbit upload %dkbit",
		device, qosAlgorithm(c.Desired), down, up)}
}

// qosAlgorithm extracts the algorithm from a desired value.
func qosAlgorithm(desired string) string {
	fields := strings.Fields(desired)
	if len(fields) == 0 {
		return "cake"
	}
	return fields[0]
}

// qosDevice extracts the interface name from a desired value.
func qosDevice(desired string) string {
	fields := strings.Fields(desired)
	for i, f := range fields {
		if f == "on" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// qosRates extracts the download and upload rates from a desired value.
func qosRates(desired string) (down, up int) {
	for _, f := range strings.Fields(desired) {
		switch {
		case strings.HasPrefix(f, "down="):
			fmt.Sscanf(f, "down=%d", &down)
		case strings.HasPrefix(f, "up="):
			fmt.Sscanf(f, "up=%d", &up)
		}
	}
	return down, up
}

func firewallCommands(desired string) []string {
	policy := "drop"
	if strings.Contains(desired, "accept") {
		policy = "accept"
	}
	return []string{
		"nft add table inet thn",
		fmt.Sprintf("nft add chain inet thn input { type filter hook input priority 0 ; policy %s ; }", policy),
		fmt.Sprintf("nft add chain inet thn forward { type filter hook forward priority 0 ; policy %s ; }", policy),
		"nft add rule inet thn input ct state established,related accept",
		"nft add rule inet thn input iifname lo accept",
	}
}

// interfaceFromField recovers an interface name from a change's field path.
func interfaceFromField(field string) string {
	switch {
	case strings.HasPrefix(field, "wan"):
		return "(wan)"
	case strings.HasPrefix(field, "lan"):
		return "(lan)"
	default:
		return "(iface)"
	}
}

// lanNameFromChange recovers the LAN interface name for a command.
func lanNameFromChange(c diff.Change) string {
	if c.Desired != "" && !strings.Contains(c.Desired, "/") {
		return c.Desired
	}
	return "(lan)"
}

// splitList splits a comma-separated current value.
func splitList(s string) []string {
	if s == "" || s == "(none)" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// order sorts the steps by phase, then by descending risk within a phase.
func (p *Plan) order() {
	sort.SliceStable(p.Steps, func(i, j int) bool {
		a, b := p.Steps[i], p.Steps[j]
		if a.Phase != b.Phase {
			return a.Phase < b.Phase
		}
		if a.Risk != b.Risk {
			return riskRank(a.Risk) > riskRank(b.Risk)
		}
		return a.Field < b.Field
	})
}

// riskRank orders risks for sorting.
func riskRank(r diff.Risk) int {
	switch r {
	case diff.RiskNone:
		return 0
	case diff.RiskLow:
		return 1
	case diff.RiskMedium:
		return 2
	case diff.RiskHigh:
		return 3
	case diff.RiskCritical:
		return 4
	default:
		return 0
	}
}

// simulate describes the outcome without performing it.
func (p *Plan) simulate() {
	sim := Simulation{}

	for _, s := range p.Steps {
		// A declared service intent is not something that WOULD be applied:
		// this build has no implementation to apply it with. Counting it as
		// a pending action would tell the operator a DHCP or DNS service
		// would start, which is the one claim this milestone must not make.
		if s.Reversible == "not-applied" {
			sim.Consequences = append(sim.Consequences,
				fmt.Sprintf("%s describes requested behaviour only; nothing is started or configured for it", s.ID))
			continue
		}
		sim.WouldApply = append(sim.WouldApply, s.Summary)
	}
	for _, c := range p.Pending {
		sim.Pending = append(sim.Pending, c.Reason)
	}
	for _, c := range p.Blocked {
		sim.Blocked = append(sim.Blocked, c.Reason)
	}

	// Consequences.
	applied := map[string]bool{}
	for _, s := range p.Steps {
		applied[s.ID] = true
	}
	if applied["ip-forwarding"] {
		sim.Consequences = append(sim.Consequences,
			"the host would forward IPv4 traffic between interfaces")
	}
	for id := range applied {
		switch {
		case id == "firewall-absent" || id == "firewall-empty":
			sim.Consequences = append(sim.Consequences,
				"inbound and forwarded traffic would be filtered by the configured policy")
		case id == "lan-address-add":
			sim.Consequences = append(sim.Consequences,
				"the LAN interface would carry the configured address")
		case id == "default-route-add" || id == "default-route-gateway":
			sim.Consequences = append(sim.Consequences,
				"traffic would leave through the configured default gateway")
		case id == "qos-absent" || id == "qos-algorithm" || id == "qos-rate" || id == "qos-policy":
			sim.Consequences = append(sim.Consequences,
				"outbound traffic would be shaped by the configured queue discipline")
		}
	}

	// Disruptions, worst first.
	for _, s := range p.Steps {
		if !s.Disruptive {
			continue
		}
		switch s.ID {
		case "lan-address-remove":
			sim.Disruptions = append(sim.Disruptions,
				fmt.Sprintf("%s: traffic on the LAN segment would be interrupted while the address is replaced", s.ID))
		case "firewall-absent", "firewall-empty":
			sim.Disruptions = append(sim.Disruptions,
				fmt.Sprintf("%s: if the ruleset has no accept path for the management session, this host becomes unreachable and needs physical access to recover", s.ID))
		case "default-route-gateway":
			sim.Disruptions = append(sim.Disruptions,
				fmt.Sprintf("%s: the current default route would be replaced, which would drop any session using it", s.ID))
		case "qos-absent", "qos-algorithm", "qos-rate", "qos-policy":
			sim.Disruptions = append(sim.Disruptions,
				fmt.Sprintf("%s: traffic on the shaped interface would pause briefly while the queue discipline is replaced", s.ID))
		}
	}
	sort.Strings(sim.Disruptions)

	// Dependency check. Address changes must precede the services that depend
	// on the interface existing.
	sawAddress := false
	for _, s := range p.Steps {
		if s.Subsystem == "address" || s.ID == "lan-link-state" {
			sawAddress = true
			continue
		}
		if (s.Subsystem == "nftables" || s.Subsystem == "qdisc") && !sawAddress && s.Phase > 1 {
			sim.OutOfOrder = append(sim.OutOfOrder,
				fmt.Sprintf("%s would run before the LAN interface is configured", s.ID))
		}
	}

	// Headline: the single most important thing for the operator to read.
	switch {
	case len(sim.Blocked) > 0:
		sim.Headline = fmt.Sprintf("%d change(s) cannot be made with this configuration; see the blocked section", len(sim.Blocked))
	case len(sim.Disruptions) > 0:
		sim.Headline = fmt.Sprintf("%d change(s) would be made, %d of which would interrupt connectivity",
			len(sim.WouldApply), len(sim.Disruptions))
	case len(sim.WouldApply) > 0:
		sim.Headline = fmt.Sprintf("%d change(s) would be made, none of which interrupt connectivity", len(sim.WouldApply))
	case len(sim.Pending) > 0:
		sim.Headline = "nothing to do yet; the configuration is not yet complete enough to act on"
	case declaredIntent(p.Steps) > 0:
		sim.Headline = fmt.Sprintf(
			"the host already matches the configuration; %d requested service behaviour(s) are described but not applied",
			declaredIntent(p.Steps))
	default:
		sim.Headline = "nothing to do: the host already matches the configuration"
	}

	p.Simulation = sim
}

// declaredIntent counts the steps that describe requested service behaviour
// rather than describing a change this build could make.
func declaredIntent(steps []Step) int {
	n := 0
	for _, s := range steps {
		if s.Reversible == "not-applied" {
			n++
		}
	}
	return n
}

// checkReady reports whether the plan can be acted on.
func (p *Plan) checkReady() bool {
	if len(p.Blocked) > 0 {
		return false
	}
	if len(p.Pending) > 0 {
		return false
	}
	for _, prec := range p.Preconditions {
		if !prec.Satisfied {
			return false
		}
	}
	for _, s := range p.Steps {
		if s.Reversible == "irreversible" {
			return false
		}
	}
	return true
}

// summarise renders the one-line description.
func (p *Plan) summarise() string {
	return fmt.Sprintf("plan %s generation %d: %d step(s), %d pending, %d blocked%s",
		p.ID, p.Generation, len(p.Steps), len(p.Pending), len(p.Blocked),
		map[bool]string{true: "", false: " [NOT READY]"}[p.Ready])
}

// deriveID computes a content-addressed plan identifier.
func deriveID(p *Plan) string {
	h := sha256.New()
	fmt.Fprintf(h, "gen=%d;live=%t;", p.Generation, p.Live)
	fmt.Fprintf(h, "obs=%s;des=%s;assign=%s;", p.Inputs.ObservedDigest, p.Inputs.DesiredDigest, p.Inputs.AssignmentDigest)
	for _, s := range p.Steps {
		fmt.Fprintf(h, "%s|%s|%d|%s|%s;", s.ID, s.Action, s.Phase, s.Field, s.Desired)
	}
	for _, c := range p.Blocked {
		fmt.Fprintf(h, "blocked:%s;", c.ID)
	}
	for _, c := range p.Pending {
		fmt.Fprintf(h, "pending:%s;", c.ID)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// StepsByPhase returns the steps in one phase.
func (p *Plan) StepsByPhase(n int) []Step {
	var out []Step
	for _, s := range p.Steps {
		if s.Phase == n {
			out = append(out, s)
		}
	}
	return out
}

// StepsByAction returns the steps with a specific action.
func (p *Plan) StepsByAction(a Action) []Step {
	var out []Step
	for _, s := range p.Steps {
		if s.Action == a {
			out = append(out, s)
		}
	}
	return out
}

// Riskiest returns the highest-risk step, or nil when there are none.
func (p *Plan) Riskiest() *Step {
	if len(p.Steps) == 0 {
		return nil
	}
	best := p.Steps[0]
	for _, s := range p.Steps[1:] {
		if riskRank(s.Risk) > riskRank(best.Risk) {
			best = s
		}
	}
	return &best
}
