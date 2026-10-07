package qos

// Package-level M7.4 additions: QoS intent and its capability-aware report.
//
// # What this file adds to the package
//
// internal/qos already owned the shaping *policy*: the algorithm, the rates,
// the interface to shape, the queue depths. That model stays exactly where it
// is; it is what a rendered tc line is built from and it is still built from.
//
// What this file adds is the intent above it, and it exists to keep three
// things apart that are constantly confused:
//
//	observed    a qdisc is attached to this interface right now
//	capability  THN has sufficient evidence that an algorithm can be used
//	intent      the operator wants shaping, at a rate, on a role
//
// # The rule this file is built around
//
// "Unknown" is not "unavailable".
//
// CAKE is the hard case and the reason this layer exists. `tc` being installed
// proves nothing about CAKE: sch_cake is a kernel module and tc does not
// consult it until asked to install one, and asking is mutation. So the only
// non-mutating evidence that CAKE works is a CAKE discipline already attached.
//
// Absent that evidence the honest answer is "unknown", and an unknown must:
//
//	never be reported as unavailable (that would be a fabricated fact)
//	never be reported as available   (that would plan with an algorithm the
//	                                 kernel may not have)
//	never be resolved by testing it  (that would mutate the host)
//
// A policy that wants CAKE on a host where CAKE is unknown is therefore
// PENDING, not broken and not silently disabled. The operator asked for
// something; THN cannot yet confirm it can be delivered, and says exactly
// that.
//
// # Device independence
//
// Shaping attaches to a logical role, not to a kernel name. A pool of
// evidence gathered here does not change when a NIC moves slots, and the
// "first Ethernet is the WAN" inference that would let it is not present
// anywhere in this file. The LANRole passed in carries a stable identity and a
// resolved name, and the name is carried as an observation.
//
// # Determinism
//
// ValidateIntent is pure and total. It reads no host, runs no probe, executes
// no command, and returns the same report for the same inputs every time. The
// capability evidence it consults is passed in, already established by
// internal/host, which is where the M7.1.1 probe model lives and where this
// package deliberately does not duplicate it.
//
// # What this file does not do
//
// It attaches nothing. No qdisc is added, replaced or deleted, no kernel
// module is loaded, and no rate is imposed on a live link. Describing the
// shaping a machine should have is a different act from giving it that
// shaping, and only the first is implemented.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/venth/thn-gateway/internal/host"
)

// Verdict is the overall outcome of checking a QoS intent.
//
// The three values are the same three internal/gateway uses, and mean the
// same thing:
//
//	VALID    the intent is complete and internally consistent
//	PENDING  coherent but incomplete; a prerequisite is unresolved
//	BLOCKED  the intent cannot be built as written
type Verdict string

const (
	// VerdictValid means every part of the QoS intent was satisfied.
	VerdictValid Verdict = "VALID"

	// VerdictBlocked means QoS cannot be built as written. More configuration
	// will not fix it: the algorithm is not one THN knows, or the requested
	// algorithm is confirmed unavailable on this host.
	VerdictBlocked Verdict = "BLOCKED"

	// VerdictPending means the intent is coherent but a prerequisite is
	// unresolved. This is the verdict for "CAKE is unknown", and it is
	// deliberately not BLOCKED: nothing is wrong with the document.
	VerdictPending Verdict = "PENDING"
)

// LANRole is the logical role the shaping policy attaches to.
//
// It mirrors gateway.RoleIntent as M7.3's dhcp.LANRole and dns.LANRole do:
// what the operator wrote, kept separate from what that name resolves to.
type LANRole struct {
	// Selector is what the operator wrote: a stable ID, a kernel name, or a
	// role name delegating to a stored assignment.
	Selector string `json:"selector,omitempty"`

	// Declared reports whether the operator named the role at all.
	Declared bool `json:"declared"`

	// Resolved reports whether the selector matched an observed interface.
	Resolved bool `json:"resolved"`

	// Interface is the observed kernel name, empty when unresolved.
	Interface string `json:"interface,omitempty"`

	// StableID is the observed rename-stable identity, empty when unresolved.
	StableID string `json:"stable_id,omitempty"`

	// Conflict reports whether the role is in conflict with another role or pointed at LAN.
	Conflict bool `json:"conflict,omitempty"`
}

// Role names the logical role shaping is bound to.
//
// It is a string rather than an enum so this package keeps no dependency on
// internal/host: the caller passes what gateway intent resolved, and this
// layer reasons about it without knowing the role vocabulary.
const RoleWAN = "wan"

// Capability is how firmly THN knows an algorithm can be used here.
//
// The three states are not interchangeable and the difference is the whole
// point of this layer:
//
//	available  THN has evidence the algorithm works on this host
//	unavailable  THN has evidence it does not
//	unknown    THN did not, and deliberately did not, find out
type Capability string

const (
	// CapabilityAvailable means THN has sufficient evidence.
	CapabilityAvailable Capability = "available"

	// CapabilityUnavailable means THN confirmed it is not usable here.
	CapabilityUnavailable Capability = "unavailable"

	// CapabilityUnknown means THN could not determine it without mutating
	// the host, so it did not try.
	CapabilityUnknown Capability = "unknown"
)

// Evidence records how a capability verdict was reached.
//
// It is carried into the report so an operator can see not just that CAKE is
// unknown but WHY, which is the difference between a diagnostic an operator
// can act on and one they have to re-derive by hand.
type Evidence struct {
	// State is the verdict.
	State Capability `json:"state"`

	// Source names what produced the verdict: "observed", "probe" or
	// "structural-inference".
	Source string `json:"source,omitempty"`

	// Reason is the human explanation.
	Reason string `json:"reason,omitempty"`
}

// Intent is the canonical statement of what shaping this machine should apply.
//
// Device-independent by construction: the only interface reference is a
// logical role's stable identity, and the resolved kernel name is carried
// beside it as an observation.
type Intent struct {
	// Enabled is the explicit request for traffic shaping.
	//
	// It defaults false and is read from the document, never inferred. Unlike
	// DHCP, a wrong shaped rate does not merely fail to help: it actively
	// caps a real link, and the failure is invisible because the network is
	// simply slower. Guessing here would be harmful, so THN does not.
	Enabled bool `json:"enabled"`

	// Role is the logical role shaping attaches to. WAN is the bottleneck
	// link for a gateway, so that is the default binding.
	Role string `json:"role,omitempty"`

	// RoleSelector, RoleDeclared, RoleResolved, RoleInterface and RoleStableID
	// mirror the LANRole, flattened so the report can show them side by side
	// with the rates.
	RoleSelector  string `json:"role_selector,omitempty"`
	RoleDeclared  bool   `json:"role_declared"`
	RoleResolved  bool   `json:"role_resolved"`
	RoleConflict  bool   `json:"role_conflict,omitempty"`
	RoleInterface string `json:"role_interface,omitempty"`
	RoleStableID  string `json:"role_stable_id,omitempty"`

	// Algorithm is the requested shaper.
	Algorithm Algorithm `json:"algorithm"`

	// Bandwidth is the requested rate.
	Bandwidth Bandwidth `json:"bandwidth"`

	// Limits are the queue depths.
	Limits Limits `json:"limits"`

	// Capability is how firmly THN knows Algorithm can be used here.
	//
	// This is the field the milestone is about. It is deliberately not a
	// boolean: a boolean would force "unknown" to become either "yes" or
	// "no", and both are fabrications.
	Capability Evidence `json:"capability"`

	// ObservedQdiscs are the queue disciplines currently attached, as
	// observed. They are carried so the report can distinguish "CAKE is
	// unattached" from "CAKE is unknown" without conflating them.
	//
	// None of these is adopted. An existing qdisc on the WAN is observed
	// infrastructure; THN does not take ownership of it merely because QoS
	// intent exists.
	ObservedQdiscs []string `json:"observed_qdiscs,omitempty"`

	// Policy is the document-shaped model the rest of the package consumes.
	Policy Policy `json:"-"`
}

// Report is the outcome of validating a QoS intent.
type Report struct {
	// Intent is what was checked.
	Intent Intent `json:"intent"`

	// Verdict is the overall outcome.
	Verdict Verdict `json:"verdict"`

	// Summary is the one-line human explanation.
	Summary string `json:"summary"`

	// Findings is everything the check established, blocking first.
	//
	// Findings carry the same codes this package's policy validator emits, so
	// a consumer dispatching on qos-cake-unknown sees one vocabulary whichever
	// layer produced the finding.
	Findings []Finding `json:"findings"`
}

// Blocking returns the findings that prevent the intent being satisfied.
func (r Report) Blocking() []Finding { return r.bySeverity(SeverityError) }

// Warnings returns the findings that do not block.
func (r Report) Warnings() []Finding { return r.bySeverity(SeverityWarning) }

func (r Report) bySeverity(s Severity) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

// FromPolicy derives QoS intent from the document-shaped policy, the role it
// binds to, and the capability evidence already established by internal/host.
//
// This is the only place a policy becomes intent. Everything downstream —
// validation, desired state, the planner — consumes Intent, so the rules for
// reading a document live in exactly one function.
func FromPolicy(p Policy, role LANRole, cap Evidence, observed []string) Intent {
	in := Intent{
		Enabled:        p.Enabled,
		Role:           RoleWAN,
		RoleSelector:   role.Selector,
		RoleDeclared:   role.Declared,
		RoleResolved:   role.Resolved,
		RoleConflict:   role.Conflict,
		RoleInterface:  role.Interface,
		RoleStableID:   role.StableID,
		Algorithm:      p.Algorithm,
		Bandwidth:      p.Bandwidth,
		Limits:         p.Limits,
		Capability:     cap,
		ObservedQdiscs: sortedQdiscs(observed),
		Policy:         p,
	}

	// The policy's own interface is replaced with the role-resolved name so
	// the two models cannot disagree about which link is shaped.
	//
	// Only when the role actually resolved. An unresolved role has no kernel
	// name to contribute, and overwriting the declared selector with an empty
	// string would erase what the operator wrote and make the policy report
	// "no interface configured" for a document that names one perfectly well.
	if role.Resolved && role.Interface != "" {
		in.Policy.Interface = role.Interface
	}

	return in
}

// sortedQdiscs copies and sorts observed qdisc kinds.
//
// Sorted because Go randomises map iteration and this is compared across runs;
// a report whose observed list reorders between runs cannot be diffed, and two
// identical hosts producing two different documents is a defect everywhere else
// in THN.
func sortedQdiscs(in []string) []string {
	if in == nil {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// ValidateIntent checks a QoS intent.
//
// Pure and total: no host is read, no probe is run, no command is executed.
//
// The dependency order is the milestone's requirement and it is enforced
// structurally: the role binding is checked first, and the capability check
// only runs once there is a resolved link to attach to. An operator whose WAN
// is not attached is told that, rather than being told CAKE is unavailable.
func ValidateIntent(in Intent) Report {
	rep := Report{Intent: in}

	// A document that does not want shaping is not an invalid shaping policy.
	// It is a different, valid thing, and reporting its absent rates as
	// errors would punish the operator for declining to configure it.
	if !in.Enabled || in.Algorithm == AlgorithmNone {
		rep.Findings = append(rep.Findings, Finding{
			Field:    "enabled",
			Code:     CodeQoSDisabled,
			Severity: SeverityInfo,
			Message:  "this document does not ask for traffic shaping; its rates and algorithm are not required",
			Hint:     "set qos.enabled to true to have this machine shape its uplink",
		})
		rep.Verdict = VerdictValid
		rep.Summary = "traffic shaping not requested"
		return rep
	}

	if in.Algorithm == "" {
		rep.Findings = append(rep.Findings, Finding{
			Field:    "algorithm",
			Code:     CodeAlgorithmMissing,
			Severity: SeverityError,
			Message:  "traffic shaping is enabled but no algorithm was specified",
			Hint:     "set algorithm to cake",
		})
	}

	roleReady, roleFindings := checkRoleBinding(in)
	rep.Findings = append(rep.Findings, roleFindings...)

	// The policy rules are reused verbatim rather than reimplemented, so the
	// intent layer and `thn qos validate` cannot reach different conclusions
	// about the same document.
	//
	// The validator's own capability finding is dropped when this layer is
	// going to report it with better evidence. Both reach the same
	// conclusion — Select saw the uncertainty — but only this layer knows
	// why, and two warnings saying the same thing in different words is two
	// problems to an operator, not one.
	capabilityUnknown := in.Capability.State == CapabilityUnknown ||
		in.Algorithm == "" || in.Algorithm == AlgorithmNone

	for _, f := range Validate(in.Policy, availabilityFor(in)).Findings {
		if capabilityUnknown && f.Code == CodeCakeUnknown {
			continue
		}
		if len(roleFindings) > 0 && f.Code == CodeInterfaceMissing {
			continue
		}
		rep.Findings = append(rep.Findings, f)
	}

	// Capability is checked last and only when there is somewhere to attach.
	// Reporting "CAKE unavailable" for a host whose WAN was never identified
	// would blame the wrong thing entirely.
	if roleReady {
		rep.Findings = append(rep.Findings, checkCapability(in)...)
	}

	if len(in.ObservedQdiscs) > 0 {
		rep.Findings = append(rep.Findings, Finding{
			Field:    "observed",
			Code:     CodeExistingQdiscUnmanaged,
			Severity: SeverityInfo,
			Message: fmt.Sprintf(
				"existing queue discipline(s) %s observed; THN does not adopt or manage unmanaged qdiscs",
				strings.Join(in.ObservedQdiscs, ", ")),
			Hint: "existing qdiscs remain unmanaged until THN traffic control is applied",
		})
	}

	rep.Findings = dedupeFindings(rep.Findings)
	sortFindings(rep.Findings)
	rep.Verdict = verdictOf(rep.Findings)
	rep.Summary = summarise(rep)
	return rep
}

// availabilityFor projects the intent's capability evidence onto the
// algorithm set the policy validator consumes.
//
// The mapping is the load-bearing part and it is deliberately conservative:
// only an algorithm THN has evidence for is marked available. An unknown
// capability contributes NOTHING, because adding it would be a guess and
// omitting nothing would present a guess as a fact.
func availabilityFor(in Intent) Availability {
	a := Availability{
		Algorithms: map[Algorithm]bool{},
		Source:     capabilitySource(in.Capability),
	}

	// Only the requested algorithm's evidence is carried: the policy
	// validator's fallback logic reasons about the set, and inventing entries
	// for algorithms THN did not probe would let it render a fallback that
	// was never established.
	if in.Capability.State == CapabilityAvailable {
		a.Algorithms[in.Algorithm] = true
	}

	// The confidence is what stops an empty set reading as "this host has
	// nothing". Without it, an unestablished capability becomes a refusal,
	// and the intent layer's own careful distinction between unknown and
	// unavailable would be undone one layer down.
	switch in.Capability.State {
	case CapabilityAvailable, CapabilityUnavailable:
		a.Confidence = ConfidenceObserved
	default:
		a.Confidence = ConfidenceUnknown
		a.Error = in.Capability.Reason
	}

	return a
}

// capabilitySource names what established the verdict.
func capabilitySource(e Evidence) string {
	if e.Source != "" {
		return e.Source
	}
	switch e.State {
	case CapabilityAvailable:
		return "observed"
	default:
		return "unknown"
	}
}

// checkRoleBinding reports what the shaping policy depends on, and whether
// there is somewhere to attach.
//
// Shaping must go on the link facing the bottleneck, which for a gateway is
// the WAN. This is where that binding is checked, and it is checked against a
// logical role so that "the uplink" is expressible without knowing the kernel
// name.
func checkRoleBinding(in Intent) (bool, []Finding) {
	var out []Finding

	if in.RoleConflict {
		out = append(out, Finding{
			Field:    "interface",
			Code:     CodeWANConflict,
			Severity: SeverityError,
			Message: fmt.Sprintf(
				"the shaping interface selector %q is in conflict with the LAN; shaping belongs on the WAN uplink bottleneck",
				in.RoleSelector),
			Hint: "set qos.interface to the wan role, or resolve the interface conflict between WAN and LAN",
		})
		return false, out
	}

	if !in.RoleDeclared {
		out = append(out, Finding{
			Field:    "interface",
			Code:     CodeWANMissing,
			Severity: SeverityError,
			Message:  "traffic shaping is enabled but no uplink interface is configured, so there is no link to shape",
			Hint:     "set qos.interface to the wan role, or set network.wan so the role can be resolved",
		})
		return false, out
	}

	if !in.RoleResolved {
		out = append(out, Finding{
			Field:    "interface",
			Code:     CodeWANUnresolved,
			Severity: SeverityWarning,
			Message: fmt.Sprintf(
				"the uplink selector %q has not been resolved against a host; "+
					"shaping cannot be checked against a link that is not identified yet",
				in.RoleSelector),
			Hint: "run `thn validate --live` on the gateway, or attach the WAN",
		})
		return false, out
	}

	return true, nil
}

// blockingFindings returns the error-severity entries.
func blockingFindings(in []Finding) []Finding {
	var out []Finding
	for _, f := range in {
		if f.Severity == SeverityError {
			out = append(out, f)
		}
	}
	return out
}

// checkCapability reports what THN knows about the requested algorithm.
//
// This is the function the milestone exists for, so its asymmetry is the
// whole design:
//
//	available    the request can be planned as actionable desired state
//	unknown      PENDING: the request is coherent, the prerequisite is not
//	             established, and no mutation was performed to find out
//	unavailable  BLOCKED: THN has evidence the algorithm is not usable here
//
// The unknown branch must never fall through to the unavailable branch. A
// machine THN could not ask is not a machine that said no.
func checkCapability(in Intent) []Finding {
	alg := in.Algorithm
	if alg == "" || alg == AlgorithmNone {
		return nil
	}

	switch in.Capability.State {
	case CapabilityAvailable:
		return nil

	case CapabilityUnavailable:
		code := CodeAlgorithmUnavailable
		if alg == AlgorithmCake {
			code = CodeCakeUnavailable
		}
		return []Finding{{
			Field:    "algorithm",
			Code:     code,
			Severity: SeverityError,
			Message: fmt.Sprintf(
				"THN has evidence that %s cannot be used on this host: %s",
				alg, orUnknown(in.Capability.Reason)),
			Hint: "choose a different algorithm, or install the kernel module that provides it",
		}}

	default:
		// Unknown is reported here and NOT by the policy validator.
		//
		// The validator also reaches this conclusion — Select reports it
		// uncertain — and letting both emit would give an operator the same
		// warning twice with different wording, which reads as two problems
		// rather than one. This layer owns the capability question because it
		// owns the evidence, so it owns the finding too.
		//
		// It is a warning, which makes the verdict PENDING rather than
		// BLOCKED — and that distinction is the point: the document is fine,
		// THN simply cannot yet confirm the host.
		return []Finding{{
			Field:    "algorithm",
			Code:     CodeCakeUnknown,
			Severity: SeverityWarning,
			Message: fmt.Sprintf(
				"QoS requested %s, but THN does not have sufficient evidence to establish %s availability on this host. "+
					"No network mutation was performed to test it: %s",
				alg, alg, orUnknown(in.Capability.Reason)),
			Hint: "run `thn host --analyze` on the gateway to see what THN could and could not establish",
		}}
	}
}

// CapabilityFrom maps a host capability verdict onto the intent's evidence.
//
// This is the seam between the M7.1.1 evidence model and the QoS intent. The
// mapping is the whole point of the milestone, so it is written out rather than
// compressed:
//
//	available + observed    → available
//	available + inferred    → unknown, because an inference about a kernel
//	                          module is not evidence the module is there
//	available + unknown     → unknown
//	unavailable + observed  → unavailable
//
// `ConfidenceInferred` deliberately lands on unknown rather than available.
// The milestone requires that inferred never be treated as observed when a
// planning gate needs actual evidence, and this is that gate: shaping would be
// attached to a real link based on a guess about a kernel module.
func CapabilityFrom(available bool, confidence host.Confidence, reason string) Evidence {
	e := Evidence{Reason: reason}

	switch {
	case available && confidence == host.ConfidenceObserved:
		e.State = CapabilityAvailable
		e.Source = "observed"
	case !available && confidence == host.ConfidenceObserved:
		e.State = CapabilityUnavailable
		e.Source = "observed"
	default:
		// Everything else is unknown, including inferred-unavailable: a
		// conclusion THN drew rather than observed is not a confirmed
		// absence, and reporting it as one would blame the host for THN's
		// uncertainty.
		e.State = CapabilityUnknown
		e.Source = "probe"
	}

	if e.Reason == "" {
		e.Reason = defaultEvidenceReason(e.State)
	}

	return e
}

// CakeCapability reads CAKE's verdict from an observed device.
//
// A nil device yields unknown, never unavailable. "THN did not look" and "THN
// looked and found nothing" are different answers and this function returns
// the honest one for each.
func CakeCapability(d *host.Device) Evidence {
	if d == nil {
		return Evidence{
			State:  CapabilityUnknown,
			Source: "not-observed",
			Reason: "no host observation was taken, so CAKE availability was not established",
		}
	}

	ev := d.EvidenceFor(host.CapCake)
	return CapabilityFrom(ev.Available, ev.Confidence, ev.Reason)
}

// defaultEvidenceReason explains a verdict that arrived without one.
func defaultEvidenceReason(s Capability) string {
	switch s {
	case CapabilityAvailable:
		return "THN observed this algorithm working on this host"
	case CapabilityUnavailable:
		return "THN observed that this algorithm is not usable on this host"
	default:
		return "THN did not, and deliberately did not, modify the host to find out"
	}
}

// sortFindings orders findings deterministically.
//
// Determinism is not cosmetic here: a CI log that reorders between runs cannot
// be diffed, and two identical runs producing two different documents is the
// behaviour this repository treats as a defect everywhere else.
func sortFindings(in []Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() < b.Severity.rank()
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		return a.Code < b.Code
	})
}

// dedupeFindings removes exact duplicates, keeping the first occurrence.
//
// The intent layer folds in the policy validator's findings, and the role
// binding can legitimately produce the same finding twice when a document
// names an interface that both the document and the role system reject. One
// problem must be reported once: a duplicated error makes an operator wonder
// whether they have two faults or one.
func dedupeFindings(in []Finding) []Finding {
	seen := make(map[string]bool, len(in))
	out := make([]Finding, 0, len(in))

	for _, f := range in {
		key := f.Field + "\x00" + f.Code + "\x00" + f.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}

	return out
}

// verdictOf reduces findings to a verdict.
func verdictOf(findings []Finding) Verdict {
	pending := false
	for _, f := range findings {
		switch f.Severity {
		case SeverityError:
			return VerdictBlocked
		case SeverityWarning:
			pending = true
		}
	}
	if pending {
		return VerdictPending
	}
	return VerdictValid
}

// summarise renders the one-line verdict explanation.
func summarise(rep Report) string {
	switch rep.Verdict {
	case VerdictValid:
		return "the requested traffic shaping can be built from this configuration"
	case VerdictPending:
		return fmt.Sprintf("traffic shaping is incomplete: %d warning(s), nothing blocking", len(rep.Warnings()))
	default:
		return fmt.Sprintf("traffic shaping cannot be built as configured: %d blocking finding(s)",
			len(rep.Blocking()))
	}
}

// BandwidthMbps renders the configured rates in Mbit/s for display.
//
// Rendering is a presentation concern and is kept out of the domain model: the
// stored unit stays kilobits per second, which is what the configuration
// contract already uses, and Mbps appears only where a human reads it.
func (in Intent) BandwidthMbps() (download, upload float64) {
	return float64(in.Bandwidth.DownloadKbps) / 1000, float64(in.Bandwidth.UploadKbps) / 1000
}

// Summary renders the intent for a human, for `thn validate` and `thn plan`.
//
// The capability block is always shown, including when it is unknown, because
// an operator deciding whether to enable shaping needs to know what THN can
// actually promise — and "unknown" is the most important of those answers.
func (in Intent) Summary() string {
	var b strings.Builder

	fmt.Fprintf(&b, "QoS:      %s\n", enabledLabel(in.Enabled))
	fmt.Fprintf(&b, "Algorithm: %s\n", in.Algorithm.String())
	fmt.Fprintf(&b, "Uplink:   %s\n", describeRole(in))
	fmt.Fprintf(&b, "Rates:    %s\n", describeBandwidth(in.Bandwidth))
	fmt.Fprintf(&b, "Evidence: %s\n", describeCapability(in.Capability))
	if len(in.ObservedQdiscs) > 0 {
		fmt.Fprintf(&b, "Observed: %s (not adopted by THN)\n", strings.Join(in.ObservedQdiscs, ", "))
	}

	return b.String()
}

// enabledLabel renders the enabled state.
func enabledLabel(on bool) string {
	if on {
		return "requested"
	}
	return "not requested"
}

// describeRole renders the resolved role, separating intent from observation.
func describeRole(in Intent) string {
	switch {
	case !in.RoleDeclared:
		return "not configured"
	case !in.RoleResolved:
		return fmt.Sprintf("%s (unresolved)", in.RoleSelector)
	default:
		return fmt.Sprintf("%s -> %s [%s]", in.RoleSelector, orUnknown(in.RoleInterface), in.RoleStableID)
	}
}

// describeBandwidth renders both directions with their direction named.
//
// "Download" and "upload" are ambiguous in a home network: whether a number
// refers to what the operator downloads or what their ISP calls download
// depends on whose point of view is being used. Naming the direction removes
// the ambiguity rather than assuming one reading.
func describeBandwidth(b Bandwidth) string {
	if b.IsZero() {
		return "(none configured)"
	}
	return fmt.Sprintf("download (internet to LAN) %dkbit/s, upload (LAN to internet) %dkbit/s",
		b.DownloadKbps, b.UploadKbps)
}

// describeCapability renders the evidence in plain language.
//
// The wording is chosen so an operator who has never heard of a qdisc still
// learns what is being asked and what THN does not yet know.
func describeCapability(e Evidence) string {
	switch e.State {
	case CapabilityAvailable:
		return "available (THN has evidence this algorithm works on this host)"
	case CapabilityUnavailable:
		return fmt.Sprintf("unavailable (%s)", orUnknown(e.Reason))
	default:
		return fmt.Sprintf("unknown — %s", orUnknown(e.Reason))
	}
}

// orUnknown renders an empty string as an explicit absence.
func orUnknown(s string) string {
	if s == "" {
		return "THN recorded no reason"
	}
	return s
}
