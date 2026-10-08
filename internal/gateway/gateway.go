// Package gateway makes the operator's gateway intent explicit, device-independent,
// and checkable.
//
// # What this package is for
//
// THN can observe that a machine has two Ethernet interfaces, that IPv4
// forwarding is enabled in the kernel, and that masquerading appears possible.
// All three are evidence that the machine COULD be a gateway. None of them is
// a statement that the operator WANTS it to be one.
//
// Before this package the distinction had nowhere to live. Configuration
// described the pieces a gateway is made of Ã¢â‚¬â€ an uplink, a downstream, an
// address, a NAT rule Ã¢â‚¬â€ and everything downstream of it assumed those pieces
// were wanted because they were written down. That assumption is usually
// correct, which is exactly why it is dangerous: a document written to
// describe what a gateway would look like on this hardware is
// indistinguishable from a document asking for one.
//
// So intent is named. GatewayConfig.Enabled says "this machine is meant to be a
// gateway", separately from everything that follows from it, and this package
// turns that statement plus the role assignments into a verdict an operator can
// read and a machine can consume.
//
// # The chain
//
//	observed hardware Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€“Âº hardware suitability Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€“Âº role resolution Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€“Âº
//	  gateway intent Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€“Âº desired state Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€“Âº plan
//
// Everything after "role resolution" already existed: internal/host resolves
// roles, internal/desired projects them, internal/planner reconciles them. This
// package sits between resolution and desired state and owns exactly one thing:
// the question "did the operator ask for a gateway, and can this one be built
// from what was asked for?"
//
// # What this package does not do
//
// It does not observe. It does not choose interfaces. It does not infer intent
// from capability Ã¢â‚¬â€ that refusal is the reason it exists. It changes nothing:
// no interface, no route, no nftables table and no sysctl is touched, here or by
// anything it calls.
//
// # Device independence
//
// An intent names interfaces the way the operator should write them: by stable
// identity (hw:Ã¢â‚¬Â¦) or, when they must, by kernel name. It never stores a
// resolved kernel name AS the intent. Resolution results are carried alongside
// the intent and never merged into it, so renaming a NIC cannot rewrite what
// the operator asked for.
package gateway

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
)

// Verdict is the overall outcome of checking an intent.
type Verdict string

const (
	// VerdictValid means every part of the intent was satisfied.
	VerdictValid Verdict = "VALID"

	// VerdictBlocked means the intent cannot be built as written.
	//
	// Blocked means "more configuration will not fix this". An unresolved
	// selector is not blocked Ã¢â‚¬â€ it is unresolved, and the operator may yet
	// attach the hardware. The distinction is preserved because the two call
	// for different responses: one is a typo, the other is a missing cable.
	VerdictBlocked Verdict = "BLOCKED"

	// VerdictPending means the intent is coherent but incomplete.
	//
	// This is the normal state while THN is developed against hardware that
	// is not attached, and it is reported as its own verdict rather than as
	// a soft block so that neither "valid" nor "broken" overstates it.
	VerdictPending Verdict = "PENDING"
)

// Severity classifies one finding.
type Severity string

const (
	// SeverityBlocking prevents the intent from being satisfied.
	SeverityBlocking Severity = "blocking"

	// SeverityWarning does not prevent anything, but an operator should know.
	SeverityWarning Severity = "warning"

	// SeverityInfo records something established that changes no verdict.
	SeverityInfo Severity = "info"
)

// Rank orders severities for deterministic sorting. Most severe first.
func (s Severity) Rank() int {
	switch s {
	case SeverityBlocking:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

// Finding codes.
//
// These are the stable, machine-readable reasons an intent is not satisfied.
// They are a vocabulary, not sentences: a UI groups on them, a CI log greps
// them, and a future automated remediation dispatches on them. The human text
// beside them is free to be reworded; these are not.
const (
	// CodeGatewayDisabled means the document does not ask for a gateway.
	CodeGatewayDisabled = "gateway-disabled"

	// CodeRoleMissing means a role the gateway needs was never named.
	CodeRoleMissing = "role-missing"

	// CodeRoleUnresolved means a selector matched no observed interface.
	//
	// Unresolved is not blocked: the interface may simply not be plugged in
	// yet, and the operator may already have written the right identity.
	CodeRoleUnresolved = "role-unresolved"

	// CodeRoleNotAssignable means the selector matched an interface that can
	// never hold a role, such as loopback.
	CodeRoleNotAssignable = "role-not-assignable"

	// CodeRoleConflict means two roles resolve to the same interface.
	CodeRoleConflict = "role-conflict"

	// CodeRoleUnsuitable means the observed interface is not a candidate for
	// the role under the current gateway profile.
	//
	// The qualifier matters. Virtual infrastructure Ã¢â‚¬â€ a container bridge, a
	// tunnel Ã¢â‚¬â€ cannot hold a LAN in the canonical two-port wired profile,
	// but it is a perfectly good way to build a bridge, a VM, or a routed
	// namespace. So this reports a conflict with THIS profile and carries
	// the evidence, rather than declaring the assignment impossible.
	CodeRoleUnsuitable = "role-unsuitable"

	// CodeLANAddressInvalid means the LAN address is not a usable address.
	CodeLANAddressInvalid = "lan-address-invalid"

	// CodeLANAddressMissing means a gateway has no LAN address.
	CodeLANAddressMissing = "lan-address-missing"

	// CodeNATOutboundInvalid means the masquerade outbound names something
	// the role system cannot resolve.
	CodeNATOutboundInvalid = "nat-outbound-invalid"

	// CodeNATOutboundUnresolved means the masquerade outbound names a role
	// that no interface currently holds.
	CodeNATOutboundUnresolved = "nat-outbound-unresolved"

	// CodeForwardingIncoherent means forwarding intent contradicts the rest
	// of the intent.
	CodeForwardingIncoherent = "forwarding-incoherent"
)

// Finding is one structured reason an intent is or is not satisfied.
//
// It carries the role, the selector as the operator wrote it, and Ã¢â‚¬â€ when the
// role resolved Ã¢â‚¬â€ the interface name and stable identity it resolved to. Those
// four together are what a UI needs to render a row an operator can act on,
// and what makes a diagnostic explainable rather than merely correct.
type Finding struct {
	// Code is the stable machine-readable reason.
	Code string `json:"code"`

	// Severity is blocking, warning or info.
	Severity Severity `json:"severity"`

	// Field is the configuration path this finding belongs to.
	Field string `json:"field"`

	// Role is the logical role involved, when one is.
	Role host.Role `json:"role,omitempty"`

	// Selector is what the operator wrote, verbatim.
	Selector string `json:"selector,omitempty"`

	// Interface is the observed kernel name the selector resolved to.
	//
	// Empty when the selector did not resolve. It is an observation about
	// this host right now, never part of the intent.
	Interface string `json:"interface,omitempty"`

	// StableID is the rename-stable identity of the resolved interface.
	StableID string `json:"stable_id,omitempty"`

	// Message is the human sentence.
	Message string `json:"message"`

	// Hint suggests a correction when there is an obvious one.
	Hint string `json:"hint,omitempty"`

	// Candidates are the interfaces that could take this role instead.
	Candidates []string `json:"candidates,omitempty"`
}

// RoleIntent is one role as the operator asked for it.
//
// Selector is the whole of the intent. Resolved, Interface and StableID are
// observations about the host at the moment of evaluation, kept in separate
// fields precisely so they cannot be mistaken for what was asked for.
type RoleIntent struct {
	// Role is the logical role.
	Role host.Role `json:"role"`

	// Selector is what the operator wrote: a stable ID, a kernel name, or a
	// logical role name delegating to a stored assignment.
	Selector string `json:"selector"`

	// Declared reports whether the operator named this role at all.
	Declared bool `json:"declared"`

	// Resolved reports whether the selector matched an observed interface.
	Resolved bool `json:"resolved"`

	// Interface is the observed kernel name, empty when unresolved.
	Interface string `json:"interface,omitempty"`

	// StableID is the observed rename-stable identity, empty when unresolved.
	StableID string `json:"stable_id,omitempty"`
}

// LANIntent is the downstream addressing the operator asked for.
type LANIntent struct {
	// Prefix is the address as written, e.g. "10.77.0.1/24".
	//
	// Empty means the operator has not chosen one. It is reported as
	// pending rather than defaulted, because a default that silently
	// supplies an address is a default that hides an absent decision.
	Prefix string `json:"prefix,omitempty"`

	// Valid reports whether Prefix parses and names a usable host address.
	Valid bool `json:"valid"`
}

// NATIntent is the masquerading the operator asked for.
type NATIntent struct {
	// Enabled reports whether NAT was asked for.
	//
	// It is read from the document and never inferred. Two NICs and a
	// possible masquerade rule are evidence; NAT is a decision.
	Enabled bool `json:"enabled"`

	// MasqueradeEnabled reports whether source NAT specifically was asked
	// for, as distinct from NAT being on.
	MasqueradeEnabled bool `json:"masquerade_enabled"`

	// Outbound is the role or selector masqueraded traffic leaves by, as
	// written. It resolves through the role system, so "wan" is the
	// canonical form and a kernel name is the explicit override.
	Outbound string `json:"outbound,omitempty"`

	// OutboundRole is the logical role the outbound resolved to, empty when
	// it named a literal interface rather than a role.
	OutboundRole host.Role `json:"outbound_role,omitempty"`

	// OutboundResolved reports whether the outbound currently resolves to an
	// interface.
	OutboundResolved bool `json:"outbound_resolved"`
}

// RoutingIntent is the forwarding the operator asked for.
type RoutingIntent struct {
	// IPv4Forwarding requests IPv4 forwarding.
	//
	// Desired state. It is deliberately NOT read from the observed
	// forwarding tunable: a host with forwarding on does not thereby want
	// it on, and conflating the two is how a gateway ends up configured to
	// match whatever the machine happened to be doing.
	IPv4Forwarding bool `json:"ipv4_forwarding"`

	// IPv6Forwarding requests IPv6 forwarding.
	IPv6Forwarding bool `json:"ipv6_forwarding"`
}

// Intent is the complete, canonical statement of what this machine should be.
//
// It is device-independent: every interface reference is a selector as written,
// and no resolved kernel name is load-bearing. Feeding this to the desired
// state model is how intent becomes something plannable.
type Intent struct {
	// Name is the logical gateway name.
	Name string `json:"name"`

	// Enabled is the explicit statement that this machine should be a
	// gateway. When false, every other field is inert and Validate reports
	// only that the gateway is not wanted.
	Enabled bool `json:"enabled"`

	// Roles are the logical roles as asked for, always present and keyed by
	// role. A role the operator did not name is present with
	// Declared false rather than absent, so "not asked for" and "missing
	// from the model" cannot be confused.
	Roles map[host.Role]RoleIntent `json:"roles"`

	// LAN is the downstream addressing.
	LAN LANIntent `json:"lan"`

	// Routing is the forwarding intent.
	Routing RoutingIntent `json:"routing"`

	// NAT is the masquerading intent.
	NAT NATIntent `json:"nat"`
}

// Report is the outcome of validating an intent against a host.
type Report struct {
	// Intent is what was checked.
	Intent Intent `json:"intent"`

	// Verdict is the overall outcome.
	Verdict Verdict `json:"verdict"`

	// Summary is the one-line human explanation.
	Summary string `json:"summary"`

	// Findings is everything the check established, blocking first.
	Findings []Finding `json:"findings"`
}

// Blocking returns the findings that prevent the intent being satisfied.
func (r Report) Blocking() []Finding { return r.bySeverity(SeverityBlocking) }

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

// Observed is what THN saw of this host, when it saw anything.
//
// Every field is optional. A static `thn validate` in CI has no host, and
// gateway intent must be checkable there Ã¢â‚¬â€ a document that cannot be reasoned
// about without the machine it is for is a document that cannot be reviewed
// before it is deployed.
type Observed struct {
	// Device is the observed host, nil when no observation was taken.
	Device *host.Device

	// Resolution is the outcome of applying the operator's role
	// assignments. Nil when no observation was taken.
	Resolution *host.Resolution

	// Intelligence is the M7.1 hardware analysis. Nil when it was not run,
	// which is reported as "not analysed" rather than as "nothing suitable".
	Intelligence *host.HardwareIntelligence
}

// FromConfig derives gateway intent from a configuration document.
//
// This is the only place a document becomes intent. Everything downstream Ã¢â‚¬â€
// validation, desired state, the planner Ã¢â‚¬â€ consumes Intent, so the rules for
// reading a document live in exactly one function.
func FromConfig(cfg config.Config, res host.Resolution) Intent {
	in := Intent{
		Name:    cfg.Gateway.Name,
		Enabled: cfg.Gateway.Enabled,
		Roles:   map[host.Role]RoleIntent{},
		LAN:     LANIntent{Prefix: cfg.Network.LANPrefix},
		Routing: RoutingIntent{
			IPv4Forwarding: cfg.Routing.IPv4Forwarding,
			IPv6Forwarding: cfg.Routing.IPv6Forwarding,
		},
		NAT: NATIntent{
			Enabled:           cfg.NAT.Enabled,
			MasqueradeEnabled: cfg.NAT.Enabled && cfg.NAT.Masquerade.Enabled,
			Outbound:          cfg.NAT.Masquerade.Outbound,
		},
	}

	// Role selectors come from the document where it names them, and from
	// the resolution otherwise. Both are recorded as selectors; neither is
	// recorded as a kernel name.
	//
	// The document wins where both speak, which is the same precedence
	// mergeBindings applies when building the assignments Ã¢â‚¬â€ this function
	// reads the same decision rather than re-deriving it.
	declared := map[host.Role]string{
		host.RoleWAN: cfg.Network.WAN,
		host.RoleLAN: cfg.Network.LAN,
	}

	for _, role := range gatewayRoles() {
		sel := strings.TrimSpace(declared[role])
		if sel == "" {
			// Not declared in the document: report what the operator
			// stored, if anything, so the intent reflects the statement
			// that was actually made about this role.
			if iface, ok := res.Assigned[role]; ok {
				sel = iface.ID
				if sel == "" {
					sel = iface.SystemName
				}
			}
		}

		ri := RoleIntent{Role: role, Selector: sel, Declared: sel != ""}

		if iface, ok := res.Assigned[role]; ok && ri.Declared {
			ri.Resolved = true
			ri.Interface = iface.SystemName
			ri.StableID = iface.ID
		}

		in.Roles[role] = ri
	}

	// The LAN prefix is checked here as well as in the config layer,
	// because the gateway layer is what has to answer "can a LAN be built
	// from this". The two must agree, so both apply the same rule.
	switch p, err := netip.ParsePrefix(cfg.Network.LANPrefix); {
	case cfg.Network.LANPrefix == "":
		in.LAN.Valid = true // absent is pending, not malformed
	case err != nil:
		in.LAN.Valid = false
	default:
		in.LAN.Valid = hostAddressProblem(p) == ""
	}

	// The masquerade outbound resolves through the role system, so "wan"
	// works without naming an interface, and a kernel name still works as
	// the explicit form.
	if in.NAT.MasqueradeEnabled {
		if role, err := host.ParseRole(in.NAT.Outbound); err == nil && role != host.RoleUnassigned {
			in.NAT.OutboundRole = role
			_, in.NAT.OutboundResolved = res.Assigned[role]
		}
	}

	return in
}

// gatewayRoles is the role set the canonical gateway profile requires.
//
// It is a constant list rather than host.KnownRoles() because guest, dmz and
// mgmt are roles THN can already hold but are not part of "the minimum for a
// gateway". A gateway with a DMZ is a gateway; a gateway without a LAN is
// not, and validating the wrong set would produce findings about roles the
// operator never intended.
func gatewayRoles() []host.Role {
	return []host.Role{host.RoleWAN, host.RoleLAN}
}

// Validate checks an intent against what was observed.
//
// Pure and total: it never returns an error, never mutates the intent or the
// host, and returns the same report for the same inputs every time. The
// ordering of Findings is deterministic, so two runs diff cleanly.
func Validate(in Intent, obs Observed) Report {
	rep := Report{Intent: in}

	// A document that does not want a gateway is not an invalid gateway.
	// It is a different, valid thing, and reporting its absent roles as
	// errors would punish the operator for declining to configure something.
	if !in.Enabled {
		rep.Findings = append(rep.Findings, Finding{
			Code:     CodeGatewayDisabled,
			Severity: SeverityInfo,
			Field:    "gateway.enabled",
			Message:  "this document does not ask for a gateway; its roles are not required",
			Hint:     "set gateway.enabled to true to configure this machine as a gateway",
		})
		rep.Verdict = VerdictValid
		rep.Summary = "gateway not requested"
		return rep
	}

	res := resolutionOf(obs)
	rep.Findings = append(rep.Findings, checkRoles(in, res, obs)...)
	rep.Findings = append(rep.Findings, checkLAN(in)...)
	rep.Findings = append(rep.Findings, checkForwarding(in)...)
	rep.Findings = append(rep.Findings, checkNAT(in, res)...)

	sortFindings(rep.Findings)
	rep.Verdict = verdictOf(rep.Findings)
	rep.Summary = summarise(rep)
	return rep
}

// resolutionOf returns the observed resolution, or an empty one.
//
// An empty Resolution rather than a nil dereference is deliberate: a document
// validated in CI must reach the same conclusions as one validated on the
// gateway, minus whatever only the host can answer. Returning an empty
// resolution lets the role checks run and report "unresolved" honestly,
// instead of skipping them and implying the roles are fine.
func resolutionOf(obs Observed) host.Resolution {
	if obs.Resolution == nil {
		return host.Resolution{Assigned: map[host.Role]host.Interface{}}
	}
	return *obs.Resolution
}

// checkRoles validates the roles a gateway needs.
func checkRoles(in Intent, res host.Resolution, obs Observed) []Finding {
	var out []Finding

	for _, role := range gatewayRoles() {
		ri := in.Roles[role]
		field := "network." + string(role)

		if !ri.Declared {
			out = append(out, Finding{
				Code:     CodeRoleMissing,
				Severity: SeverityBlocking,
				Field:    field,
				Role:     role,
				Message:  fmt.Sprintf("this gateway needs a %s interface and none is configured", role),
				Hint:     fmt.Sprintf("run `thn discover` to see this host's interfaces, then set %s", field),
			})
			continue
		}

		if ri.Resolved {
			out = append(out, checkSuitability(ri, obs)...)
			continue
		}

		// Unresolved. The resolution already recorded why, with a stable
		// code and a candidate list; this translates rather than re-derives,
		// because two implementations of "why did this selector fail" would
		// be two answers.
		problem, found := problemFor(res, role, ri.Selector)
		if !found {
			out = append(out, Finding{
				Code:     CodeRoleUnresolved,
				Severity: SeverityWarning,
				Field:    field,
				Role:     role,
				Selector: ri.Selector,
				Message: fmt.Sprintf(
					"the %s selector %q has not been resolved against a host; "+
						"run `thn validate --live` on the gateway to check it",
					role, ri.Selector),
			})
			continue
		}

		// A selector that failed because another role already holds the link
		// can still be described exactly: the interface is the one the other
		// role resolved to. Attaching it is what turns "this is a conflict"
		// into "these two roles are on this specific piece of hardware", which
		// is the difference between a diagnostic an operator can act on and
		// one they have to go and re-derive by hand.
		iface, claimed := interfaceForSelector(res, ri.Selector)
		if claimed && isDuplicate(problem.Code) {
			problem.Message = fmt.Sprintf(
				"%s; the %s and %s roles therefore describe one interface as two roles",
				problem.Message, otherRoleHolding(res, iface, role), role)
		}

		out = append(out, Finding{
			Code:       translateProblemCode(problem.Code),
			Severity:   severityForProblem(problem.Code),
			Field:      field,
			Role:       role,
			Selector:   ri.Selector,
			Interface:  iface.SystemName,
			StableID:   iface.ID,
			Message:    problem.Message,
			Hint:       hintFor(role),
			Candidates: problem.Candidates,
		})
	}

	out = append(out, checkRoleSeparation(in)...)
	return out
}

// checkRoleSeparation reports two roles resolving to one interface.
//
// The canonical gateway profile requires a distinct uplink and downstream.
// This is checked on the RESOLVED identity rather than on the written
// selectors, because the same interface can be named two different ways Ã¢â‚¬â€ by
// stable ID in one place and by kernel name in another Ã¢â‚¬â€ and the operator has
// still described one link as two roles.
func checkRoleSeparation(in Intent) []Finding {
	wan, lan := in.Roles[host.RoleWAN], in.Roles[host.RoleLAN]
	if !wan.Resolved || !lan.Resolved {
		return nil
	}
	if !sameInterface(wan, lan) {
		return nil
	}

	return []Finding{{
		Code:      CodeRoleConflict,
		Severity:  SeverityBlocking,
		Field:     "network.lan",
		Role:      host.RoleLAN,
		Selector:  lan.Selector,
		Interface: lan.Interface,
		StableID:  lan.StableID,
		Message: fmt.Sprintf(
			"WAN (%s) and LAN (%s) resolve to the same interface %s; "+
				"a gateway needs a distinct uplink and downstream",
			wan.Selector, lan.Selector, lan.Interface),
		Hint: "assign a different interface to one of the two roles",
	}}
}

// sameInterface reports whether two roles name the same observed interface.
//
// Stable ID is compared first because it is the only identifier that cannot
// be two spellings of one thing. The kernel name is the fallback for
// ephemeral identities, which have no hardware address to compare.
func sameInterface(a, b RoleIntent) bool {
	if a.StableID != "" && b.StableID != "" {
		return a.StableID == b.StableID
	}
	return a.Interface != "" && a.Interface == b.Interface
}

// checkSuitability reports a role held by an interface the hardware analysis
// argues against.
//
// This is the distinction the milestone asks for between "wrong for this
// profile" and "impossible". A container bridge cannot be the LAN of a
// two-port wired gateway, and THN says so Ã¢â‚¬â€ with the evidence attached and
// the verdict scoped to the profile Ã¢â‚¬â€ rather than refusing the assignment on
// the grounds that it can never be a network.
func checkSuitability(ri RoleIntent, obs Observed) []Finding {
	if obs.Intelligence == nil {
		return nil
	}

	intel, ok := findInterface(*obs.Intelligence, ri)
	if !ok {
		return nil
	}

	suit := intel.SuitabilityFor(ri.Role)

	switch {
	case suit.Suitability == host.SuitabilityUnsuitable:
		msg := fmt.Sprintf(
			"%s is %s and is not a candidate for the %s role in this gateway profile",
			ri.Interface, suit.Suitability.Describe(), ri.Role)
		if len(suit.Blockers) > 0 {
			msg += ": " + strings.Join(suit.Blockers, "; ")
		}
		return []Finding{{
			Code:      CodeRoleUnsuitable,
			Severity:  SeverityWarning,
			Field:     "network." + string(ri.Role),
			Role:      ri.Role,
			Selector:  ri.Selector,
			Interface: ri.Interface,
			StableID:  ri.StableID,
			Message:   msg,
			Hint: fmt.Sprintf(
				"this is a finding about the current gateway profile, not a statement that %s cannot "+
					"carry traffic; bridges, VLANs and namespaces are all built from such interfaces",
				ri.Interface),
		}}

	case suit.Suitability == host.SuitabilityLimitedCandidate && len(suit.Limitations) > 0:
		return []Finding{{
			Code:      CodeRoleUnsuitable,
			Severity:  SeverityInfo,
			Field:     "network." + string(ri.Role),
			Role:      ri.Role,
			Selector:  ri.Selector,
			Interface: ri.Interface,
			StableID:  ri.StableID,
			Message: fmt.Sprintf(
				"%s holds the %s role with observed limitations: %s",
				ri.Interface, ri.Role, strings.Join(suit.Limitations, "; ")),
		}}
	}

	return nil
}

// findInterface locates the M7.1 analysis for a resolved role.
func findInterface(intel host.HardwareIntelligence, ri RoleIntent) (host.InterfaceIntelligence, bool) {
	for _, i := range intel.Interfaces {
		if ri.StableID != "" && i.ID == ri.StableID {
			return i, true
		}
		if ri.Interface != "" && i.SystemName == ri.Interface {
			return i, true
		}
	}
	return host.InterfaceIntelligence{}, false
}

// checkLAN validates the downstream addressing.
func checkLAN(in Intent) []Finding {
	if in.LAN.Prefix == "" {
		// Absent is pending, not broken: the operator may not have chosen an
		// address yet. It blocks only because the gateway cannot serve a LAN
		// without one Ã¢â‚¬â€ which is a statement about the gateway, not about
		// the address being malformed.
		return []Finding{{
			Code:     CodeLANAddressMissing,
			Severity: SeverityBlocking,
			Field:    "network.lan_prefix",
			Message:  "a gateway needs an address on its LAN",
			Hint:     "set network.lan_prefix, e.g. 10.77.0.1/24",
		}}
	}

	if in.LAN.Valid {
		return nil
	}

	detail := fmt.Sprintf("%q is not a usable LAN address", in.LAN.Prefix)
	if p, err := netip.ParsePrefix(in.LAN.Prefix); err == nil {
		if msg := hostAddressProblem(p); msg != "" {
			detail = msg
		}
	}

	return []Finding{{
		Code:     CodeLANAddressInvalid,
		Severity: SeverityBlocking,
		Field:    "network.lan_prefix",
		Message:  detail,
		Hint:     "use a host address with its prefix length, e.g. 10.77.0.1/24",
	}}
}

// checkForwarding validates the forwarding intent against the rest of it.
func checkForwarding(in Intent) []Finding {
	if in.Routing.IPv4Forwarding {
		return nil
	}

	// Forwarding off with a gateway on is the shape of a bridge, which is a
	// legitimate thing to want. What is not legitimate is asking to
	// masquerade LAN traffic while refusing to forward it, because no LAN
	// packet would ever reach the rule that rewrites its source address.
	if in.NAT.Enabled && in.NAT.MasqueradeEnabled {
		return []Finding{{
			Code:     CodeForwardingIncoherent,
			Severity: SeverityBlocking,
			Field:    "routing.ipv4_forwarding",
			Message: "NAT is requested but IPv4 forwarding is not, so no LAN traffic " +
				"will ever reach the masquerade rule",
			Hint: "set routing.ipv4_forwarding to true, or disable NAT",
		}}
	}

	return []Finding{{
		Code:     CodeForwardingIncoherent,
		Severity: SeverityInfo,
		Field:    "routing.ipv4_forwarding",
		Message:  "IPv4 forwarding is not requested; this gateway will not route between the WAN and LAN",
	}}
}

// checkNAT validates the masquerade intent.
func checkNAT(in Intent, res host.Resolution) []Finding {
	if !in.NAT.Enabled || !in.NAT.MasqueradeEnabled {
		return nil
	}

	switch {
	case strings.TrimSpace(in.NAT.Outbound) == "":
		return []Finding{{
			Code:     CodeNATOutboundInvalid,
			Severity: SeverityBlocking,
			Field:    "nat.masquerade.outbound",
			Message: "masquerading is requested with no outbound interface, so source addresses " +
				"would be rewritten on every interface including the LAN",
			Hint: `set nat.masquerade.outbound to the "wan" role, or to the uplink interface`,
		}}

	case in.NAT.OutboundRole == host.RoleLAN:
		return []Finding{{
			Code:     CodeNATOutboundInvalid,
			Severity: SeverityBlocking,
			Field:    "nat.masquerade.outbound",
			Role:     host.RoleLAN,
			Selector: in.NAT.Outbound,
			Message:  "masqueraded traffic must leave through the WAN, not the LAN",
			Hint:     `set nat.masquerade.outbound to the "wan" role`,
		}}

	case in.NAT.OutboundRole == host.RoleWAN && !in.NAT.OutboundResolved && res.Assigned != nil:
		return []Finding{{
			Code:     CodeNATOutboundUnresolved,
			Severity: SeverityWarning,
			Field:    "nat.masquerade.outbound",
			Role:     host.RoleWAN,
			Selector: in.NAT.Outbound,
			Message:  "the WAN role holds no interface on this host, so masquerade has no outbound target",
			Hint:     "assign an uplink to the WAN role, or name the interface directly",
		}}
	}

	return nil
}

// problemFor finds the resolution problem explaining an unresolved role.
func problemFor(res host.Resolution, role host.Role, selector string) (host.Problem, bool) {
	for _, p := range res.Problems {
		if p.Role != role {
			continue
		}
		// An empty recorded selector means the assignment layer did not
		// carry one Ã¢â‚¬â€ the role was requested but nothing named it. That is
		// still the explanation, so it matches.
		if p.Selector == "" || p.Selector == selector {
			return p, true
		}
	}
	return host.Problem{}, false
}

// translateProblemCode maps a host resolution problem onto a gateway finding
// code.
//
// The two vocabularies are kept separate rather than merged because they
// answer different questions: host.Problem says why an assignment could not
// be satisfied, while a gateway finding says what that means for the gateway
// being asked for. Reusing one string for both would make it impossible to
// tell "this selector is broken" from "this gateway is not valid".
func translateProblemCode(code string) string {
	switch code {
	case "not-assignable":
		return CodeRoleNotAssignable
	case "duplicate-interface", "duplicate-role":
		return CodeRoleConflict
	default:
		return CodeRoleUnresolved
	}
}

// isDuplicate reports whether a resolution problem code means two roles
// collided on one interface.
func isDuplicate(code string) bool {
	return code == "duplicate-interface" || code == "duplicate-role"
}

// interfaceForSelector finds the resolved interface a selector names.
//
// A selector that failed to resolve because another role holds the link still
// names a real interface Ã¢â‚¬â€ the one that role took. Looking it up here is what
// lets a conflict carry the hardware identity, rather than leaving the
// operator to work out which of their NICs two roles collided on.
func interfaceForSelector(res host.Resolution, selector string) (host.Interface, bool) {
	for _, iface := range res.Assigned {
		if selector == iface.ID || (selector != "" && selector == iface.SystemName) {
			return iface, true
		}
	}
	return host.Interface{}, false
}

// otherRoleHolding names the role that already holds an interface, excluding
// the one being reported.
func otherRoleHolding(res host.Resolution, iface host.Interface, exclude host.Role) host.Role {
	roles := make([]string, 0, len(res.Assigned))
	for role, held := range res.Assigned {
		if role == exclude || held.ID != iface.ID {
			continue
		}
		roles = append(roles, string(role))
	}
	sort.Strings(roles)
	if len(roles) == 0 {
		return host.RoleUnassigned
	}
	return host.Role(roles[0])
}

// severityForProblem grades a resolution problem as a gateway finding.
//
// The grading is not uniform, and the differences are the point:
//
//   - Unresolved is a warning. The hardware may simply not be attached, and
//     the operator may already have written the identity correctly. Blocking
//     would train operators to ignore the code that means "plug it in".
//   - Not-assignable is blocking. Loopback will never be an uplink, on this
//     host or any other, so more configuration cannot fix it.
//   - A duplicate is blocking. Two roles on one interface is a description of
//     a machine that cannot route between two networks, because there are not
//     two networks.
func severityForProblem(code string) Severity {
	switch code {
	case "not-assignable", "duplicate-interface", "duplicate-role":
		return SeverityBlocking
	default:
		return SeverityWarning
	}
}

// hintFor returns the operator-facing remedy for an unresolved role.
func hintFor(role host.Role) string {
	switch role {
	case host.RoleWAN:
		return "run `thn discover` to see this host's interfaces and their stable identities"
	case host.RoleLAN:
		return "run `thn discover` to see this host's interfaces; the LAN may not be attached"
	default:
		return ""
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
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		return a.Selector < b.Selector
	})
}

// verdictOf reduces findings to a verdict.
func verdictOf(findings []Finding) Verdict {
	pending := false
	for _, f := range findings {
		switch f.Severity {
		case SeverityBlocking:
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
		return "the requested gateway can be built from this configuration"
	case VerdictPending:
		return fmt.Sprintf("the gateway is incomplete: %d warning(s), nothing blocking", len(rep.Warnings()))
	default:
		return fmt.Sprintf("the gateway cannot be built as configured: %d blocking finding(s)",
			len(rep.Blocking()))
	}
}

// hostAddressProblem reports why prefix cannot name an interface address, or
// "" when it can.
//
// netip.ParsePrefix accepts a prefix whose address is its own network address,
// because "10.77.0.0/24" is a perfectly good way to name a network. It is not
// a good way to name the address this machine will hold on its LAN, so the
// distinction is made here rather than being left to a later layer that would
// have to guess what the operator meant.
//
// This rule lives in the intent layer rather than in internal/config on
// purpose. The document layer's stated policy is that a masked network address
// is accepted, and that policy is asserted by internal/validation's matrix. It
// is a defensible policy for a field that also names networks. But "what
// address does the gateway hold on its LAN" is a question only the intent
// layer asks, and it is the layer that has to answer it.
//
// IPv4 only. In IPv6 the first address of a prefix is a valid host address
// under RFC 4291, so rejecting it would be wrong rather than strict.
func hostAddressProblem(prefix netip.Prefix) string {
	if !prefix.Addr().Is4() {
		return ""
	}

	// /31 and /32 have no network or broadcast address in the IPv4 sense:
	// RFC 3021 makes both endpoints of a /31 usable, and a /32 is one host.
	// Neither can be assigned an address it does not have.
	if prefix.Bits() >= 31 {
		return ""
	}

	masked := prefix.Masked()
	if prefix.Addr() == masked.Addr() {
		return fmt.Sprintf(
			"%s is the network address of %s and cannot be assigned to an interface; "+
				"use a host address such as %s",
			prefix.Addr(), masked, hostAddressExample(masked))
	}
	if prefix.Addr() == lastHostAddress(masked) {
		return fmt.Sprintf(
			"%s is the broadcast address of %s and cannot be assigned to an interface; "+
				"use a host address such as %s",
			prefix.Addr(), masked, hostAddressExample(masked))
	}
	return ""
}

// lastHostAddress returns the all-ones address of an IPv4 prefix.
//
// It walks whole bytes rather than individual bits because a /8 LAN has 24
// host bits and no single byte holds them: the naive `1 << (7 - i)` form
// produces a negative shift for any prefix shorter than /16 and takes the
// process down on a perfectly ordinary configuration.
func lastHostAddress(prefix netip.Prefix) netip.Addr {
	if !prefix.Addr().Is4() {
		return prefix.Addr()
	}

	raw := prefix.Masked().Addr().As4()
	hostBits := 32 - prefix.Bits()

	for i := 0; i < len(raw) && hostBits > 0; i++ {
		n := 8
		if hostBits < n {
			n = hostBits
		}
		raw[len(raw)-1-i] |= byte(0xFF >> (8 - n))
		hostBits -= n
	}

	return netip.AddrFrom4(raw)
}

// hostAddressExample returns a plausible host address for prefix, so a
// diagnostic can show the operator what to type rather than only what is
// wrong.
func hostAddressExample(prefix netip.Prefix) netip.Addr {
	if !prefix.Addr().Is4() {
		return prefix.Addr()
	}
	raw := prefix.Masked().Addr().As4()
	if prefix.Bits() < 31 {
		raw[len(raw)-1]++
	}
	return netip.AddrFrom4(raw)
}

// Summary renders the intent for a human, for `thn validate` and `thn plan`.
//
// It shows intent and observation as separate parts because the whole point of
// this milestone is that they are separate. A reader who cannot tell which
// line came from the document and which came from the machine will read the
// pair as one fact.
func (in Intent) Summary() string {
	var b strings.Builder

	fmt.Fprintf(&b, "gateway:  %s\n", enabledLabel(in.Enabled))
	for _, role := range gatewayRoles() {
		fmt.Fprintf(&b, "%-8s %s\n", roleLabel(role), describeRole(in.Roles[role]))
	}
	fmt.Fprintf(&b, "LAN addr: %s\n", orNone(in.LAN.Prefix))
	fmt.Fprintf(&b, "forward:  ipv4=%t ipv6=%t (desired)\n",
		in.Routing.IPv4Forwarding, in.Routing.IPv6Forwarding)
	fmt.Fprintf(&b, "NAT:      %s\n", describeNAT(in.NAT))

	return b.String()
}

// enabledLabel renders the gateway-enabled state.
func enabledLabel(on bool) string {
	if on {
		return "requested"
	}
	return "not requested"
}

// roleLabel renders a role as a heading.
func roleLabel(r host.Role) string { return strings.ToUpper(string(r)) + ":" }

// describeRole renders one role's intent and, when it resolved, the interface
// it resolved to. The stable identity is printed alongside the kernel name so
// that a reader can see which link the document is actually talking about.
func describeRole(ri RoleIntent) string {
	switch {
	case !ri.Declared:
		return "not configured"
	case !ri.Resolved:
		return fmt.Sprintf("%s (unresolved)", ri.Selector)
	default:
		return fmt.Sprintf("%s -> %s [%s]", ri.Selector, orNone(ri.Interface), orNone(ri.StableID))
	}
}

// describeNAT renders the masquerade intent.
func describeNAT(n NATIntent) string {
	if !n.Enabled {
		return "disabled"
	}
	if !n.MasqueradeEnabled {
		return "enabled, no masquerade requested"
	}
	out := "masquerade"
	if n.Outbound != "" {
		out += " via " + n.Outbound
	} else {
		out += " with no outbound target"
	}
	if n.OutboundRole != "" && !n.OutboundResolved {
		out += " (unresolved)"
	}
	return out
}

// orNone renders an empty string as an explicit absence.
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
