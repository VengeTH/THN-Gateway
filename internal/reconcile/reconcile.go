// Package reconcile is the gateway's own decision about a requested desired
// state: accept, or refuse, and say why.
//
// # Where this sits
//
// The fleet layer is a control plane. It is useful, and it is the wrong place
// to put safety, because a control plane is remote, credentialed, network-
// reachable and manages many devices at once. Everything that makes it
// dangerous is a property of being central.
//
// This package is on the other side of that boundary. It runs on the gateway,
// it sees the gateway's own observed state, and it is the last thing consulted
// before anything would happen. It exists so that the answer to "is this
// change safe on *this* device" comes from the device.
//
// A control plane that is compromised can therefore send any desired state it
// likes. Every one of them arrives here, and the ones that would remove the
// management path, require a capability the kernel does not have, or create an
// overlapping network are refused — regardless of how they were authorised
// upstream, and regardless of whether the approval was genuine.
//
// # What a refusal means
//
// A refusal is not a validation error and it is not a failure. It is the
// gateway exercising the authority it holds over its own safety, and it is
// reported as a distinct outcome rather than as an empty plan. A caller must
// be able to tell "I asked for something and was told no" from "I asked for
// something and nothing needed doing".
//
// # This package does not apply
//
// It decides. It does not execute, and it cannot. `activation.CanApply()`
// remains false in this build, and nothing here changes that. A later slice
// may call this package and then apply; the refusal it produces has to be
// honoured by whatever does that, which is why the refusals are values with
// reasons rather than a bool.
package reconcile

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/authority"
	"github.com/VengeTH/THN-Gateway/internal/diff"
)

// Reason classifies why the gateway refused.
type Reason string

const (
	// ReasonNotRefused is the zero value: the gateway did not object.
	ReasonNotRefused Reason = ""

	// ReasonManagementPath means the change would remove or weaken the path
	// the operator uses to reach the gateway, or that the gateway needs to
	// recover itself.
	//
	// This is the most important refusal in the package. A gateway that has
	// locked itself out is unreachable and unfixable by remote means, and the
	// person who caused it cannot tell from outside. The gateway can.
	ReasonManagementPath Reason = "removes-the-management-path"

	// ReasonCapabilityUnavailable means the host lacks something the desired
	// state requires — a shaping algorithm the kernel does not have, a
	// firewall backend that is not installed.
	//
	// The gateway refuses rather than substituting something else, because a
	// silent substitution is a configuration that looks applied and is not. A
	// degraded rate is a better outcome than a claimed rate that is not real.
	ReasonCapabilityUnavailable Reason = "required-capability-unavailable"

	// ReasonOverlappingNetwork means the desired state would create a network
	// that overlaps one already present, on this host or behind it.
	//
	// Two devices on the same subnet with the gateway between them is a
	// topology that produces symptoms nobody can diagnose remotely: DHCP
	// answers from the wrong server, routes blackhole, and no log says why.
	ReasonOverlappingNetwork Reason = "overlapping-network"

	// ReasonReachability means the change would alter how the gateway is
	// reached. Not refused outright — see the comment on the check — but
	// escalated, because it is the category of change that strands operators.
	ReasonReachability Reason = "alters-reachability"

	// ReasonBlocked means a change the diff already classified as blocked, and
	// which therefore cannot be made at all.
	ReasonBlocked Reason = "blocked-change"

	// ReasonPolicy means the change is not permitted by the authority floor.
	//
	// The gateway checks this too, even though the control plane checks it as
	// well. Two independent checks of the same rule is the arrangement this
	// project uses everywhere else: the guard allowlist, the render-not-apply
	// discipline, the safety-invariant tests.
	ReasonPolicy Reason = "not-permitted"

	// ReasonUnobservable means the gateway could not see the subsystem, so it
	// cannot say whether the desired state already holds.
	//
	// This is emphatically not a change request. A gateway that cannot read
	// its own firewall has not been asked to install one, and reporting that
	// as an operation would tell a control plane to push a firewall change at a
	// device that could not see it to begin with — the worst possible moment
	// to be making changes. The distinction is the same one the signals
	// package makes: an unread value is not a false one.
	ReasonUnobservable Reason = "could-not-be-observed"
)

// Refusal is one reason the gateway declined, with enough detail for a human to
// decide what to do about it.
type Refusal struct {
	// Reason classifies the refusal.
	Reason Reason `json:"reason"`

	// Field is what was objected to.
	Field string `json:"field,omitempty"`

	// Operation is the authority operation the change would have required.
	Operation authority.Operation `json:"operation,omitempty"`

	// Detail is a sentence for an operator.
	//
	// Not a template with a value substituted in. These sentences are read by
	// somebody deciding whether to override, and a refusal they cannot
	// understand is a refusal they will override.
	Detail string `json:"detail"`

	// Overridable reports whether a human may proceed anyway.
	//
	// False means no. The gateway will refuse this change regardless of what
	// the control plane sends, and the only fix is a different configuration.
	Overridable bool `json:"overridable"`
}

// Result is the gateway's decision about a whole desired state.
type Result struct {
	// Accepted reports whether the gateway is willing to proceed.
	//
	// False if any non-overridable refusal was raised, or if the policy
	// forbids part of the change.
	Accepted bool `json:"accepted"`

	// Status is a one-word summary for dashboards and for the control plane's
	// own listing.
	Status Status `json:"status"`

	// Operations are the authority operations the change would require, in
	// sorted order. Reported even when refused, so the control plane can show
	// what it was asking for.
	Operations []authority.Operation `json:"operations,omitempty"`

	// Refusals are the reasons, most serious first.
	Refusals []Refusal `json:"refusals,omitempty"`

	// HighestOperation is the strictest tier the change requires, which is what
	// determines how it must be rolled out.
	HighestOperation authority.Operation `json:"-"`

	// RequiredTier is the strictest tier across the operations.
	RequiredTier authority.Tier `json:"required_tier,omitempty"`

	// Converged reports that observed already matches desired.
	Converged bool `json:"converged"`

	// ChangeCount is how many differences the change set contains.
	ChangeCount int `json:"change_count"`

	// Unobservable names the subsystems the gateway could not inspect.
	//
	// Reported separately from Operations, and never folded into them. A
	// control plane reading a list of operations has to be able to trust that
	// every entry is a change somebody asked for.
	Unobservable []string `json:"unobservable,omitempty"`

	// At is when the decision was made.
	At time.Time `json:"at"`
}

// Status summarises the decision.
type Status string

const (
	// StatusNoChange means observed already matches desired.
	StatusNoChange Status = "no-change"
	// StatusUndeterminable means the gateway could not inspect enough of
	// itself to say. Distinct from both accepted and refused: nothing is wrong,
	// nothing is permitted, and nothing was learned.
	StatusUndeterminable Status = "undeterminable"
	// StatusAccepted means the gateway is willing to proceed.
	StatusAccepted Status = "accepted"
	// StatusAcceptedWithRefusals means it will proceed with the permitted
	// part and refuse the rest.
	StatusAcceptedWithRefusals Status = "accepted-with-refusals"
	// StatusRefused means it will not proceed.
	StatusRefused Status = "refused"
)

// Observe is what the gateway knows about itself, beyond the desired/observed
// comparison.
//
// These are the facts the refusals need that `diff.Observed` does not carry.
// They are gathered on the gateway, from the gateway, and are the reason this
// package cannot be implemented on the control plane: the control plane has a
// desired state and a rule set, and does not have the kernel's opinion.
type Observe struct {
	// ShapingAlgorithms are the qdisc algorithms the kernel offers.
	//
	// Empty means unknown, not "none available". An empty list must not be
	// read as "everything is unavailable", or a gateway that could not
	// enumerate them would refuse every QoS change for the wrong reason.
	ShapingAlgorithms []string

	// FirewallBackend is the installed firewall, or empty if none.
	FirewallBackend string

	// ManagementPath is the interface or transport the operator reaches the
	// gateway through. Empty means the gateway does not know, in which case
	// the management-path refusal is not raised — an unknown path is not a
	// removed one, and inventing a refusal here would block ordinary changes
	// on every gateway where the path is not configured.
	ManagementPath string

	// LocalNetworks are the networks already present on or behind this host.
	// Overlap detection checks the desired LAN address against these.
	LocalNetworks []string

	// Current is the observed host state, for the change set.
	Current diff.Observed
}

// Decide is the gateway's decision.
//
// The signature is a struct rather than five positional arguments because the
// arguments are all of named types that would be easy to transpose, and a
// transposition here would be a safety decision made about the wrong input.
func Decide(
	policy authority.Policy,
	who authority.Principal,
	ev authority.Evidence,
	d diff.Result,
	obs Observe,
	at time.Time,
) Result {
	res := Result{
		At:           at.UTC(),
		Converged:    d.Converged,
		ChangeCount:  len(d.Changes),
		RequiredTier: authority.TierAutomatic,
	}

	if len(d.Changes) == 0 {
		res.Accepted = true
		res.Status = StatusNoChange
		return res
	}

	// Classify every change into an operation. Doing this first means the
	// refusal can name what was being asked for, which is the difference
	// between "refused" and "refused: disabling the firewall".
	//
	// Pending changes are excluded and collected separately. A pending change
	// is the diff saying it could not ask, not that it found a difference —
	// mapping one into a write operation would have a control plane push
	// changes at a gateway that could not see the subsystem in question.
	ops := make([]authority.Operation, 0, len(d.Changes))
	byOp := make(map[authority.Operation][]diff.Change)
	var unobservable []string

	for _, c := range d.Changes {
		if c.Kind == diff.KindPending {
			unobservable = append(unobservable, c.Field)
			continue
		}
		op := OperationFor(c)
		if !containsOperation(ops, op) {
			ops = append(ops, op)
		}
		byOp[op] = append(byOp[op], c)
	}
	sort.Strings(unobservable)
	res.Unobservable = unobservable

	sort.Slice(ops, func(i, j int) bool { return ops[i] < ops[j] })

	res.Operations = ops

	// Every change was a pending item: the gateway saw nothing and concluded
	// nothing. That is its own outcome, and reporting it as "no change" would
	// tell a control plane the gateway matches the desired state, which is the
	// opposite of what is known.
	if len(ops) == 0 {
		res.HighestOperation = ""
		res.RequiredTier = authority.TierAutomatic
		res.Refusals = append(res.Refusals, Refusal{
			Reason: ReasonUnobservable,
			Field:  "host.inspection",
			Detail: unobservableDetail(unobservable),
			// Not overridable: there is nothing to override. An approval does
			// not make an unreadable subsystem readable.
			Overridable: false,
		})
		res.Accepted = false
		res.Status = StatusUndeterminable
		return res
	}

	res.HighestOperation = strictestOperation(policy, ops)
	res.RequiredTier = policy.Effective(res.HighestOperation)

	res.Refusals = append(res.Refusals, policyRefusals(policy, who, ev, ops)...)
	res.Refusals = append(res.Refusals, blockedRefusals(d)...)
	res.Refusals = append(res.Refusals, reachabilityRefusals(byOp)...)
	res.Refusals = append(res.Refusals, managementRefusals(byOp)...)
	res.Refusals = append(res.Refusals, capabilityRefusals(byOp, obs)...)
	res.Refusals = append(res.Refusals, overlapRefusals(d, obs)...)

	// Most serious last, so the refusal an operator should see first after
	// sorting is the one that cannot be overridden.
	sort.SliceStable(res.Refusals, func(i, j int) bool {
		if res.Refusals[i].Overridable != res.Refusals[j].Overridable {
			return res.Refusals[j].Overridable
		}
		return res.Refusals[i].Reason < res.Refusals[j].Reason
	})

	res.Accepted = true
	for _, f := range res.Refusals {
		if !f.Overridable {
			res.Accepted = false
		}
	}

	switch {
	case !res.Accepted:
		res.Status = StatusRefused
	case len(res.Refusals) > 0:
		res.Status = StatusAcceptedWithRefusals
	default:
		res.Status = StatusAccepted
	}

	return res
}

// unobservableDetail writes the sentence for a gateway that could not see.
func unobservableDetail(fields []string) string {
	if len(fields) == 0 {
		return "The gateway could not inspect the subsystems involved, so it cannot say " +
			"whether the desired state already holds. It will not guess, and it will not " +
			"treat an unobservable subsystem as one that needs changing."
	}
	return fmt.Sprintf(
		"The gateway could not inspect %s, so it cannot say whether the desired state "+
			"already holds. An unreadable subsystem is not a broken one: these are "+
			"reported as unobservable rather than as changes, because treating them as "+
			"changes would have the fleet push updates at a gateway that could not "+
			"see the thing being updated.",
		strings.Join(fields, ", "))
}

// OperationFor classifies a change into the operation it is asking for.
//
// The mapping is by change identifier, and every identifier is one the diff
// package actually emits: the `role + "-name-mismatch"`, `role + "-link-state"`
// and `role + "-address-{add,remove}"` families, the explicit
// `default-route-*`, `ip-forwarding`, `firewall-*`, `qos-*` and `resolvers`,
// and the `*-unobservable` pending items.
//
// A change whose identifier is not recognised maps to OpUpdateSoftware — the
// only operation that is not about network state — and that is deliberate: an
// unrecognised change is treated as the most cautious operation that could
// apply, rather than the least demanding one that could be hoped for.
func OperationFor(c diff.Change) authority.Operation {
	switch c.ID {
	case "resolvers":
		return authority.OpChangeResolvers

	case "qos-absent", "qos-algorithm":
		return authority.OpChangeQoS

	case "firewall-empty":
		return authority.OpAddFirewallRule
	case "firewall-absent":
		// An absent firewall is a firewall that is off. This is the change
		// that disables the firewall, not one that adds a rule to it, and
		// conflating the two is how a strict tier gets applied to a strict
		// change and the other way round.
		return authority.OpDisableFirewall

	case "default-route-add", "default-route-gateway":
		return authority.OpChangeDefaultRoute

	case "ip-forwarding":
		return authority.OpChangeWAN

	default:
		switch {
		case strings.HasPrefix(c.ID, "wan-"):
			return authority.OpChangeWAN
		case strings.HasPrefix(c.ID, "lan-"):
			return authority.OpChangeLAN
		default:
			return authority.OpUpdateSoftware
		}
	}
}

// policyRefusals are the parts of the change the gateway will not perform
// because its own authority forbids them.
func policyRefusals(
	policy authority.Policy,
	who authority.Principal,
	ev authority.Evidence,
	ops []authority.Operation,
) []Refusal {
	var out []Refusal

	for _, op := range ops {
		decision := authority.Decide(policy, who, op, ev)
		if decision.Allowed && decision.Satisfied {
			continue
		}
		out = append(out, Refusal{
			Reason:      ReasonPolicy,
			Field:       string(op),
			Operation:   op,
			Detail:      decision.Reason,
			Overridable: false,
		})
	}
	return out
}

// blockedRefusals are changes the diff already ruled impossible.
func blockedRefusals(d diff.Result) []Refusal {
	var out []Refusal
	for _, c := range d.Changes {
		if c.Kind != diff.KindBlocked {
			continue
		}
		out = append(out, Refusal{
			Reason:      ReasonBlocked,
			Field:       c.Field,
			Detail:      fmt.Sprintf("%s cannot be reconciled: %s", c.Field, c.Reason),
			Overridable: false,
		})
	}
	return out
}

// reachabilityRefusals escalate changes that alter how the gateway is reached.
//
// These are overridable rather than refused outright, and the reason is worth
// stating: a gateway is sometimes genuinely moved to a new uplink, and a tool
// that cannot express that is a tool people stop using. The gateway's job here
// is to make the consequence impossible to miss, not to prevent it.
//
// What is not overridable is the subset handled by managementRefusals — a
// change that removes the path entirely, as opposed to altering it.
func reachabilityRefusals(byOp map[authority.Operation][]diff.Change) []Refusal {
	var out []Refusal

	for _, op := range []authority.Operation{
		authority.OpChangeWAN,
		authority.OpChangeLAN,
		authority.OpChangeDefaultRoute,
	} {
		changes := byOp[op]
		if len(changes) == 0 {
			continue
		}
		out = append(out, Refusal{
			Reason:    ReasonReachability,
			Field:     string(op),
			Operation: op,
			Detail: fmt.Sprintf(
				"%d change(s) would alter how this gateway is reached (%s). "+
					"After this is applied the gateway may only be reachable by its new path; "+
					"confirm you have a way back before proceeding.",
				len(changes), summariseFields(changes)),
			Overridable: true,
		})
	}
	return out
}

// managementRefusals are the non-overridable ones.
//
// A change that turns the firewall off is not an alteration of the management
// path — it is the removal of one, and it is the reason this package exists.
func managementRefusals(byOp map[authority.Operation][]diff.Change) []Refusal {
	var out []Refusal

	if changes := byOp[authority.OpDisableFirewall]; len(changes) > 0 {
		out = append(out, Refusal{
			Reason:    ReasonManagementPath,
			Field:     "firewall",
			Operation: authority.OpDisableFirewall,
			Detail: "Disabling the host firewall would remove the path this gateway is " +
				"managed and recovered through, and cannot be undone by anything that " +
				"needs the gateway to be reachable. This gateway will not do it. If the " +
				"firewall is genuinely in the way, the change to make is a rule that " +
				"permits what you need, not the removal of the set.",
			Overridable: false,
		})
	}

	if changes := byOp[authority.OpShellCommand]; len(changes) > 0 {
		out = append(out, Refusal{
			Reason:      ReasonManagementPath,
			Operation:   authority.OpShellCommand,
			Detail:      "Running a command on the gateway is not something this gateway accepts from a control plane.",
			Overridable: false,
		})
	}

	return out
}

// capabilityRefusals are changes the host cannot perform.
//
// The gateway refuses rather than degrading. A shaping policy that asked for
// cake on a kernel without it can either be refused, or quietly applied as
// fq_codel at a different rate — and the second is worse, because the
// configuration now claims something that is not true.
func capabilityRefusals(byOp map[authority.Operation][]diff.Change, obs Observe) []Refusal {
	var out []Refusal

	if changes := byOp[authority.OpChangeQoS]; len(changes) > 0 {
		wanted := wantedAlgorithm(changes)
		if wanted != "" && !algorithmAvailable(wanted, obs.ShapingAlgorithms) {
			detail := fmt.Sprintf(
				"The desired shaping policy asks for %q, which this kernel does not offer.", wanted)
			if len(obs.ShapingAlgorithms) == 0 {
				detail = fmt.Sprintf(
					"The desired shaping policy asks for %q, and this gateway could not enumerate "+
						"the algorithms its kernel offers, so it cannot confirm the request is one "+
						"it can honour. It will not apply a policy it cannot verify.", wanted)
			} else {
				detail += fmt.Sprintf(
					" Available here: %s. Applying it as something else would leave the "+
						"configuration claiming a rate that is not in force.",
					strings.Join(obs.ShapingAlgorithms, ", "))
			}
			out = append(out, Refusal{
				Reason:      ReasonCapabilityUnavailable,
				Field:       "qos.algorithm",
				Operation:   authority.OpChangeQoS,
				Detail:      detail,
				Overridable: false,
			})
		}
	}

	if changes := byOp[authority.OpAddFirewallRule]; len(changes) > 0 {
		if obs.FirewallBackend == "" {
			out = append(out, Refusal{
				Reason:    ReasonCapabilityUnavailable,
				Field:     "firewall.backend",
				Operation: authority.OpAddFirewallRule,
				Detail: "No firewall backend is installed on this gateway, so there is nothing to " +
					"add a rule to. Rendering a ruleset the host cannot load would produce a " +
					"configuration that looks applied and protects nothing.",
				Overridable: false,
			})
		}
	}

	return out
}

// wantedAlgorithm extracts the algorithm a QoS change is asking for.
func wantedAlgorithm(changes []diff.Change) string {
	for _, c := range changes {
		if c.ID == "qos-algorithm" && c.Desired != "" {
			return strings.Trim(strings.ToLower(c.Desired), `"`)
		}
	}
	return ""
}

// algorithmAvailable reports whether the kernel offers an algorithm.
//
// An empty list means "not enumerated", not "nothing available" — the two have
// opposite meanings and conflating them would refuse every QoS change on a
// gateway where enumeration failed.
func algorithmAvailable(want string, available []string) bool {
	if len(available) == 0 {
		return false
	}
	for _, a := range available {
		if strings.EqualFold(a, want) {
			return true
		}
	}
	return false
}

// overlapRefusals are changes that would create an overlapping network.
func overlapRefusals(d diff.Result, obs Observe) []Refusal {
	var out []Refusal

	for _, c := range d.Changes {
		if c.ID != "lan-address-add" || c.Desired == "" {
			continue
		}

		for _, local := range obs.LocalNetworks {
			if sameNetwork(c.Desired, local) {
				out = append(out, Refusal{
					Reason:    ReasonOverlappingNetwork,
					Field:     c.Field,
					Operation: authority.OpChangeLAN,
					Detail: fmt.Sprintf(
						"The desired LAN address %s overlaps %s, which is already present on or "+
							"behind this host. Two networks that overlap produce symptoms nobody "+
							"can diagnose remotely: DHCP answers from the wrong server and routes "+
							"blackhole. This gateway will not create one.",
						c.Desired, local),
					Overridable: false,
				})
			}
		}
	}

	return out
}

// sameNetwork reports whether two CIDR strings describe overlapping networks.
//
// The check is prefix containment rather than a parse-and-compare, so that a
// malformed address on either side fails to overlap rather than panicking. A
// gateway refusing to start because a comparison helper could not parse a
// string would be a self-inflicted outage.
func sameNetwork(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	ap, aerr := netip.ParsePrefix(a)
	bp, berr := netip.ParsePrefix(b)
	if aerr != nil || berr != nil {
		return false
	}
	return ap.Overlaps(bp)
}

// strictestOperation returns the operation requiring the most assurance.
func strictestOperation(policy authority.Policy, ops []authority.Operation) authority.Operation {
	var best authority.Operation
	bestTier := authority.TierAutomatic

	for _, op := range ops {
		if t := policy.Effective(op); t > bestTier {
			bestTier, best = t, op
		}
	}
	return best
}

func containsOperation(ops []authority.Operation, op authority.Operation) bool {
	for _, o := range ops {
		if o == op {
			return true
		}
	}
	return false
}

func summariseFields(changes []diff.Change) string {
	seen := make(map[string]bool, len(changes))
	var fields []string
	for _, c := range changes {
		if !seen[c.Field] {
			seen[c.Field] = true
			fields = append(fields, c.Field)
		}
	}
	if len(fields) > 4 {
		return strings.Join(fields[:4], ", ") + fmt.Sprintf(" and %d more", len(fields)-4)
	}
	return strings.Join(fields, ", ")
}

// RenderRefusals formats a refusal list for a terminal.
//
// The gateway's own reasons are printed before anything else, before the
// operations, before the approval tiers. The gateway is the authority, and an
// interface that leads with the approval state reads as though the approval
// were the decision.
func RenderRefusals(r Result) string {
	var sb strings.Builder

	switch r.Status {
	case StatusNoChange:
		return "Nothing to do: the gateway already matches the desired state.\n"
	case StatusUndeterminable:
		sb.WriteString("UNDETERMINABLE. The gateway could not inspect enough of itself to\n")
		sb.WriteString("answer, and is not asking for anything to be changed.\n\n")
		for _, f := range r.Refusals {
			if f.Reason != ReasonUnobservable {
				continue
			}
			sb.WriteString("Why\n")
			sb.WriteString("───\n")
			sb.WriteString(indent(f.Detail, "  "))
		}
		sb.WriteString("\n")
		if len(r.Unobservable) > 0 {
			sb.WriteString("Unobservable subsystems:\n")
			for _, u := range r.Unobservable {
				fmt.Fprintf(&sb, "  %s\n", u)
			}
			sb.WriteString("\n")
		}
		return sb.String()
	case StatusAccepted:
		fmt.Fprintf(&sb, "Accepted. %d change(s) may proceed.\n", r.ChangeCount)
	case StatusAcceptedWithRefusals:
		fmt.Fprintf(&sb, "Accepted in part. %d change(s) may proceed, %d refused.\n\n",
			r.ChangeCount, len(r.Refusals))
	case StatusRefused:
		fmt.Fprintf(&sb, "REFUSED. %d of %d change(s) will not be made.\n\n",
			len(r.Refusals), r.ChangeCount)
	}

	if len(r.Refusals) > 0 {
		sb.WriteString("Why\n")
		sb.WriteString("───\n")
		for _, f := range r.Refusals {
			verdict := "overridable"
			if !f.Overridable {
				verdict = "NOT overridable"
			}
			fmt.Fprintf(&sb, "\n[%s] %s (%s)\n", f.Reason, verdict, f.Field)
			sb.WriteString(indent(f.Detail, "  "))
		}
		sb.WriteString("\n")
	}

	if len(r.Operations) > 0 {
		fmt.Fprintf(&sb, "Operations requested (strictest requires %s):\n", r.RequiredTier)
		for _, op := range r.Operations {
			fmt.Fprintf(&sb, "  %-32s %s\n", op, authority.FloorFor(op))
		}
	}

	return sb.String()
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}
