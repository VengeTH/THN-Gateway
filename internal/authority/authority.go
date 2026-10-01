// Package authority decides whether a requested change to a gateway may be
// made, by whom, and under what conditions.
//
// # What this is for
//
// A gateway that can only be read is easy to make safe. A fleet that can also
// be written is not, and the difficulty is not in the writing — it is in
// deciding what is allowed to be written, and in making sure that decision
// cannot be talked around by the thing being controlled.
//
// This package is that decision. It has exactly three inputs: an Operation,
// which is what is being asked for in terms of intent rather than mechanism; a
// Policy, which is what the organisation permits; and a Principal, which is
// who is asking. It returns a Decision. Nothing else in the system is allowed
// to answer the question.
//
// # Operations are intent, never mechanism
//
// An Operation names what the caller wants to be true of the gateway. It never
// names a command. "Change the QoS policy" is an operation; "run tc qdisc
// replace dev eth0 root cake 200mbit" is not expressible, because there is
// nothing to express it with.
//
// This is the single most important property in the package. A fleet that can
// be sent commands is a remote shell with extra steps, and the security of
// such a system rests entirely on the correctness of every caller — on nobody
// ever constructing the wrong command, on the transport being safe, on the
// operator not being in a hurry. A fleet that can only be sent desired state
// is constrained by the gateway, which is the only component whose safety
// matters when the fleet layer is compromised.
//
// The consequence is a real limitation: this package cannot authorise arbitrary
// maintenance, and OpShellCommand exists only to be refused. It is in the
// vocabulary so that an attempt to express it resolves to a refusal rather than
// to an unrecognised operation that somebody might later wire to something
// that works.
//
// # The floor cannot be lowered
//
// Every operation has a Floor: the strictest requirement the binary itself
// enforces. A Policy may raise a requirement but may never lower one, and that
// is arranged so that "lower" is not a representable state rather than so that
// it is checked for at runtime.
//
// A Policy stores only overrides. The effective tier for an operation is the
// stricter of the override and the floor, computed on read. There is no field
// anywhere that can hold "weaker than the floor", no setter that writes one,
// and no code path that assigns a tier without going through Effective. A
// configuration file naming a permissive tier for an operation this package
// considers forbidden does not weaken it; it is ignored.
//
// This matters because the configuration is the part an attacker reaches
// first. Any scheme in which a policy file can relax a rule has a rule-relaxing
// bug somewhere, and the bug is worth waiting for. This one has nothing to find.
package authority

import (
	"fmt"
	"sort"
	"strings"
)

// Operation is what a caller wants to be true of a gateway.
//
// The vocabulary is closed. An operation outside it is refused, because a
// system that accepts new operations without review has no review.
type Operation string

const (
	// OpReadTelemetry reads what the gateway reports about itself.
	OpReadTelemetry Operation = "read.telemetry"

	// OpReadConfiguration reads the gateway's configuration.
	OpReadConfiguration Operation = "read.configuration"

	// OpChangeResolvers changes which resolvers the gateway offers clients.
	//
	// Low consequence: a wrong resolver list degrades name resolution, and the
	// gateway keeps forwarding traffic.
	OpChangeResolvers Operation = "config.change.resolvers"

	// OpChangeQoS changes the traffic shaping policy.
	OpChangeQoS Operation = "config.change.qos"

	// OpAddFirewallRule adds a rule to the host firewall.
	//
	// Higher consequence than its risk suggests: a rule added here is a rule
	// that reaches production, and a permissive one is an exposure that does not
	// announce itself.
	OpAddFirewallRule Operation = "firewall.add-rule"

	// OpDeploySecurityRule deploys a security rule set across more than one
	// gateway, and is therefore governed by rollout rather than by approval.
	OpDeploySecurityRule Operation = "firewall.deploy-rule"

	// OpUpdateSoftware updates the THN binary or its supporting packages.
	//
	// The only operation in the vocabulary that changes code rather than
	// configuration, and therefore the one with the widest blast radius.
	OpUpdateSoftware Operation = "software.update"

	// OpRestartService restarts a service the gateway manages.
	OpRestartService Operation = "service.restart"

	// OpChangeWAN changes the uplink: its name, its address, or its link.
	//
	// A change here can remove the path the operator is using to reach the
	// gateway, which is why the gateway itself refuses some of these.
	OpChangeWAN Operation = "network.change.wan"

	// OpChangeLAN changes the downstream network: its name, address or link.
	OpChangeLAN Operation = "network.change.lan"

	// OpChangeDefaultRoute changes the default route or its next hop.
	OpChangeDefaultRoute Operation = "network.change.default-route"

	// OpDisableFirewall turns the host firewall off.
	//
	// This is the operation a security incident drives somebody to at two in
	// the morning, which is exactly why it needs the strictest tier rather
	// than the fastest.
	OpDisableFirewall Operation = "firewall.disable"

	// OpFactoryReset returns the gateway to a known-empty state.
	//
	// Not expressible as a desired state at all, because "empty" is not a
	// state this tool can describe. It exists so the attempt is refused.
	OpFactoryReset Operation = "device.factory-reset"

	// OpShellCommand runs an arbitrary command on the gateway.
	//
	// Present only to be forbidden, and never permitted at any tier by any
	// policy. See the package comment for why it is here rather than absent.
	OpShellCommand Operation = "device.shell"
)

// AllOperations returns every operation, for documentation and tests.
func AllOperations() []Operation {
	return []Operation{
		OpReadTelemetry, OpReadConfiguration,
		OpChangeResolvers, OpChangeQoS,
		OpAddFirewallRule, OpDeploySecurityRule,
		OpUpdateSoftware, OpRestartService,
		OpChangeWAN, OpChangeLAN, OpChangeDefaultRoute,
		OpDisableFirewall, OpFactoryReset, OpShellCommand,
	}
}

// Tier is how much assurance an operation requires.
//
// The ordering is total and it runs from most permissive to strictest, so that
// "stricter of" is a simple maximum. That is what lets Effective be a single
// comparison rather than a table of cases.
type Tier int

const (
	// TierAutomatic needs no approval and no record.
	TierAutomatic Tier = iota

	// TierRecorded is performed freely but written to the audit trail.
	TierRecorded

	// TierNotified requires the operator to be told before it happens.
	TierNotified

	// TierApproval requires an explicit human approval for this change.
	TierApproval

	// TierControlled requires a staged rollout rather than a fleet-wide push.
	TierControlled

	// TierStrong requires strong approval and a deliberately small blast
	// radius: few gateways, at a time.
	TierStrong

	// TierForbidden may not be performed at all.
	TierForbidden
)

// String renders the tier.
func (t Tier) String() string {
	switch t {
	case TierAutomatic:
		return "automatic"
	case TierRecorded:
		return "recorded"
	case TierNotified:
		return "notified"
	case TierApproval:
		return "approval"
	case TierControlled:
		return "controlled"
	case TierStrong:
		return "strong-approval"
	case TierForbidden:
		return "forbidden"
	default:
		return fmt.Sprintf("tier(%d)", int(t))
	}
}

// Valid reports whether the tier is one this package knows.
func (t Tier) Valid() bool { return t >= TierAutomatic && t <= TierForbidden }

// Floor is the strictest requirement for an operation that the binary itself
// enforces, and the minimum any policy must respect.
//
// This table is the answer to "what if the fleet layer is compromised". A
// compromised control plane can send any desired state it likes, including
// configurations that disable the firewall or shell out; every one of those
// resolves here to TierForbidden and stops.
//
// The table is deliberately not configurable, not overridable and not read
// from disk. It is a property of the binary, like the guard allowlist, for the
// same reason: a limit that can be configured is a limit that can be removed.
var Floor = map[Operation]Tier{
	// Reads are free. They change nothing and a gateway whose state cannot be
	// read cannot be managed at all.
	OpReadTelemetry:      TierAutomatic,
	OpReadConfiguration:  TierAutomatic,
	OpChangeResolvers:    TierApproval,
	OpChangeQoS:          TierApproval,
	OpAddFirewallRule:    TierApproval,
	OpDeploySecurityRule: TierControlled,
	OpUpdateSoftware:     TierApproval,
	OpRestartService:     TierApproval,

	// Reachability changes. Strong approval rather than outright refusal,
	// because a gateway is sometimes genuinely moved to a new uplink, and a
	// tool that cannot express that is a tool people stop using. The gateway
	// may still refuse the individual change; see internal/reconcile.
	OpChangeWAN:          TierStrong,
	OpChangeLAN:          TierStrong,
	OpChangeDefaultRoute: TierStrong,

	// The three below never happen through the fleet API.
	//
	// OpDisableFirewall is in this list rather than in TierStrong because a
	// firewall can be re-enabled after it is disabled and nobody watching a
	// dashboard will notice it was off for six hours. TierStrong does not
	// help against that, because the approval and the audit are the same
	// mechanism as the change.
	OpDisableFirewall: TierForbidden,
	OpFactoryReset:    TierForbidden,
	OpShellCommand:    TierForbidden,
}

// FloorFor returns the strictest requirement the binary enforces for an
// operation.
//
// An operation outside the vocabulary is TierForbidden. That is deliberate:
// an unrecognised operation is refused rather than defaulted, because a
// default here would make forgetting to classify something the permissive
// choice.
func FloorFor(op Operation) Tier {
	if t, ok := Floor[op]; ok {
		return t
	}
	return TierForbidden
}

// Policy is what an organisation permits.
//
// It stores only overrides — tiers *stricter* than the floor. There is no way
// to express a permission weaker than the floor, so there is no parsing,
// validating or sanitising step that could be wrong: a policy that names a
// permissive tier simply has no effect on that operation.
type Policy struct {
	// name identifies the policy in decisions and audit entries.
	name string

	// overrides holds raised tiers only.
	overrides map[Operation]Tier

	// lowerings counts refused requests to weaken a tier.
	lowerings int
}

// NewPolicy returns an empty policy, which permits exactly what the floor
// permits and nothing more.
func NewPolicy(name string) Policy {
	return Policy{name: name, overrides: make(map[Operation]Tier)}
}

// Name returns the policy's name.
func (p Policy) Name() string { return p.name }

// Raise returns a copy of the policy that additionally requires tier for op.
//
// A request to lower a tier is recorded and ignored rather than reported as an
// error, because it is not a mistake in the policy file — it is either a
// misunderstanding or an attempt, and in both cases the outcome is the same.
// Refusing to parse the file would leave an operator with a control plane that
// does not load at all, which is a worse outcome than one that loads and
// quietly refuses the specific thing that was asked for.
//
// The attempt is counted by LoweringAttempts so that it can be surfaced.
func (p Policy) Raise(op Operation, tier Tier) Policy {
	out := Policy{name: p.name, lowerings: p.lowerings,
		overrides: make(map[Operation]Tier, len(p.overrides)+1)}
	for k, v := range p.overrides {
		out.overrides[k] = v
	}

	switch {
	case !tier.Valid():
		// An unparseable tier is not an override. Leave the floor alone.
	case tier < FloorFor(op):
		out.lowerings++
	case tier > FloorFor(op):
		out.overrides[op] = tier
	default:
		// Equal to the floor: recording it would imply the policy chose it.
	}
	return out
}

// LoweringAttempts counts requests to weaken a tier that were refused.
//
// This exists so the refusal is visible. A control plane whose policy file is
// quietly ignored in one respect is a control plane nobody is watching.
func (p Policy) LoweringAttempts() int { return p.lowerings }

// Effective returns the tier that actually applies to an operation: the
// stricter of what the policy raised and what the binary enforces.
func (p Policy) Effective(op Operation) Tier {
	floor := FloorFor(op)
	if override, ok := p.overrides[op]; ok && override > floor {
		return override
	}
	return floor
}

// Overrides returns the raised tiers, for rendering a policy to an operator.
//
// Only overrides appear. An operator reviewing this sees what their policy
// adds, not a restatement of the defaults, which is the part they cannot
// change and therefore the part they need least of their attention spent on.
func (p Policy) Overrides() map[Operation]Tier {
	out := make(map[Operation]Tier, len(p.overrides))
	for k, v := range p.overrides {
		out[k] = v
	}
	return out
}

// Role is a job function, which is coarse on purpose.
//
// RBAC at this layer answers "may this class of person do this class of
// thing". Fine-grained per-gateway grants belong to the fleet's scope model,
// which has the information this package does not.
type Role string

const (
	// RoleViewer may read.
	RoleViewer Role = "viewer"
	// RoleAuditor may read and inspect the audit trail.
	RoleAuditor Role = "auditor"
	// RoleNetworkOperator may make routine network changes.
	RoleNetworkOperator Role = "network-operator"
	// RoleSecurityOperator may change firewall and security policy.
	RoleSecurityOperator Role = "security-operator"
	// RoleAdmin may do anything the policy permits.
	RoleAdmin Role = "admin"
)

// RoleRank orders roles so that "at least" is a comparison.
func RoleRank(r Role) int {
	switch r {
	case RoleViewer:
		return 0
	case RoleAuditor:
		return 1
	case RoleNetworkOperator:
		return 2
	case RoleSecurityOperator:
		return 3
	case RoleAdmin:
		return 4
	default:
		// An unknown role ranks lowest, so an unrecognised value cannot grant.
		return -1
	}
}

// AtLeast reports whether the role is at least the given level.
func (r Role) AtLeast(min Role) bool { return RoleRank(r) >= RoleRank(min) }

// principalMinimum is the least role that may request each operation.
//
// Requests are authorised in two independent ways: the policy says whether the
// change is permitted at all, and the role says whether this person may ask.
// Both must agree. A policy that permits a firewall change is not a grant to
// somebody whose role does not include it, and a security operator cannot
// perform an operation the policy forbids.
var principalMinimum = map[Operation]Role{
	OpReadTelemetry:     RoleViewer,
	OpReadConfiguration: RoleViewer,

	OpChangeResolvers: RoleNetworkOperator,
	OpChangeQoS:       RoleNetworkOperator,

	OpAddFirewallRule:    RoleSecurityOperator,
	OpDeploySecurityRule: RoleSecurityOperator,
	OpUpdateSoftware:     RoleSecurityOperator,
	OpRestartService:     RoleSecurityOperator,

	OpChangeWAN:          RoleAdmin,
	OpChangeLAN:          RoleAdmin,
	OpChangeDefaultRoute: RoleAdmin,

	OpDisableFirewall: RoleAdmin,
	OpFactoryReset:    RoleAdmin,
	OpShellCommand:    RoleAdmin,
}

// MinimumRole returns the least role that may request an operation. An
// unrecognised operation requires RoleAdmin, which combined with its forbidden
// floor still refuses it.
func MinimumRole(op Operation) Role {
	if r, ok := principalMinimum[op]; ok {
		return r
	}
	return RoleAdmin
}

// Principal is who is asking.
type Principal struct {
	// Name identifies the principal in decisions and audit entries.
	Name string

	// Role is their job function.
	Role Role
}

// Decision is the outcome of an authorisation request.
type Decision struct {
	// Operation is what was asked for.
	Operation Operation `json:"operation"`

	// Allowed reports whether the request may proceed at all, ignoring
	// whether the necessary approvals are in hand. It is false for an
	// operation no policy permits.
	Allowed bool `json:"allowed"`

	// Satisfied reports whether the request may proceed now, with the
	// approval state supplied.
	//
	// A request can be Allowed and not Satisfied: the policy permits the
	// change and it needs approval that has not been given. That distinction
	// is the difference between "no" and "not yet", and a system that cannot
	// express it can only say no to everything or yes to everything.
	Satisfied bool `json:"satisfied"`

	// Required is the effective tier: what this request needs.
	Required Tier `json:"required"`

	// Policy and Role are echoed so an audit entry is self-contained.
	Policy string `json:"policy"`
	Role   Role   `json:"role"`

	// Reason explains the decision in one sentence, always populated.
	Reason string `json:"reason"`
}

// Audit renders the decision for the audit trail.
func (d Decision) Audit() string {
	var sb strings.Builder
	sb.WriteString(string(d.Operation))
	sb.WriteString(" requires=")
	sb.WriteString(d.Required.String())
	sb.WriteString(" allowed=")
	sb.WriteString(fmt.Sprintf("%t", d.Allowed))
	sb.WriteString(" satisfied=")
	sb.WriteString(fmt.Sprintf("%t", d.Satisfied))
	return sb.String()
}

// Evidence is proof that the required approvals are in hand.
type Evidence struct {
	// Approved reports that a named human approved this specific change.
	Approved bool

	// ApprovedBy names them, for the audit trail.
	ApprovedBy string

	// BatchSize is how many gateways the request covers. A controlled rollout
	// is not satisfied by an approval for the whole fleet.
	BatchSize int

	// TotalGateways is the size of the fleet the batch is drawn from.
	//
	// A batch of one gateway from a fleet of one is not a canary, and treating
	// it as one would let a fleet-wide change pass the canary check.
	TotalGateways int

	// RolloutHalted reports that a previous stage of this rollout failed a
	// health check. A halted rollout stays halted; continuing it is a new
	// decision, not an automatic next step.
	RolloutHalted bool
}

// MinFleetForBatchLimit is the fleet size above which a batch limit applies.
//
// Below this there is nothing to roll out: a "canary" of one gateway out of
// three is all of them, and requiring a smaller batch would make strong-approval
// operations impossible on exactly the deployments most likely to use them.
// Most real installations are small, and a rule that cannot be satisfied on a
// small installation is a rule that gets configured away.
const MinFleetForBatchLimit = 10

// batchTooWide reports whether a batch is too large to be a deliberate stage.
//
// The test is a fraction of a fleet, and only applies to fleets large enough
// for staging to mean anything.
func batchTooWide(ev Evidence) bool {
	if ev.TotalGateways < MinFleetForBatchLimit {
		return false
	}
	return ev.BatchSize*10 > ev.TotalGateways
}

// Decide authorises an operation.
//
// The order is deliberate: the floor is consulted before the role, and the
// role before the evidence. That ordering means the most fundamental refusal
// — an operation this binary does not perform — is reached first, and a caller
// cannot reach the later, more permissive checks by satisfying them.
func Decide(p Policy, who Principal, op Operation, ev Evidence) Decision {
	d := Decision{
		Operation: op,
		Required:  p.Effective(op),
		Policy:    p.Name(),
		Role:      who.Role,
	}

	// 1. The floor. Nothing below this line can make the request permitted.
	if FloorFor(op) == TierForbidden {
		d.Reason = fmt.Sprintf(
			"%s is not performed through the fleet API at any tier, by any role, under any policy; "+
				"it is a property of the binary rather than of the configuration", op)
		return d
	}

	// 2. The role. A permissive policy is not a grant to everyone.
	min := MinimumRole(op)
	if !who.Role.AtLeast(min) {
		d.Reason = fmt.Sprintf(
			"role %s may not request %s; the least role that may is %s",
			who.Role, op, min)
		return d
	}

	d.Allowed = true

	// 3. The evidence required by the effective tier.
	switch d.Required {
	case TierAutomatic:
		d.Satisfied = true
		d.Reason = "permitted, and needs no approval"

	case TierRecorded:
		d.Satisfied = true
		d.Reason = "permitted, and written to the audit trail"

	case TierNotified:
		d.Satisfied = true
		d.Reason = "permitted, and the operator must be notified"

	case TierApproval:
		if ev.Approved {
			d.Satisfied = true
			d.Reason = "permitted; approved by " + orAnonymous(ev.ApprovedBy)
		} else {
			d.Reason = "permitted, but requires an explicit approval that has not been given"
		}

	case TierControlled:
		switch {
		case ev.RolloutHalted:
			d.Reason = "permitted, but the rollout this change belongs to has already halted; " +
				"continuing it is a new decision"
		case !ev.Approved:
			d.Reason = "permitted, but a staged rollout requires approval"
		case batchTooWide(ev):
			d.Reason = fmt.Sprintf(
				"permitted, but a batch of %d from %d gateways is too large to be a first stage; "+
					"start smaller", ev.BatchSize, ev.TotalGateways)
		default:
			d.Satisfied = true
			d.Reason = fmt.Sprintf(
				"permitted as a staged rollout of %d gateway/gateways, approved by %s",
				ev.BatchSize, orAnonymous(ev.ApprovedBy))
		}

	case TierStrong:
		switch {
		case !ev.Approved:
			d.Reason = "permitted, but this changes reachability and requires strong approval"
		case batchTooWide(ev):
			d.Reason = fmt.Sprintf(
				"this changes reachability; a batch of %d from %d gateways is wider than strong "+
					"approval covers", ev.BatchSize, ev.TotalGateways)
		default:
			d.Satisfied = true
			d.Reason = "permitted under strong approval, in a deliberately narrow batch"
		}
	}

	return d
}

func orAnonymous(s string) string {
	if strings.TrimSpace(s) == "" {
		return "an unnamed approver"
	}
	return s
}

// Audit is an append-only record of authorisation decisions.
//
// Every decision is recorded, including the permitted ones. A trail that only
// records refusals cannot answer the question an incident asks, which is what
// was allowed and who allowed it.
type AuditEntry struct {
	Decision Decision
	// At is when the decision was made.
	At string
}

// RenderPolicies returns every operation with its floor, for `thn authority
// policy` and for documentation.
//
// Rendering the floor is not the same as rendering a policy. It answers "what
// does this binary allow", which is a question about the binary, and it is the
// thing an operator should be shown before they write a policy — so that they
// can see which of their intended permissions were already impossible.
func RenderPolicy(p Policy) string {
	var sb strings.Builder

	sb.WriteString("Operations this binary permits\n")
	sb.WriteString("───────────────────────────────\n")
	sb.WriteString("A policy may raise a requirement. It cannot lower one.\n\n")

	for _, op := range AllOperations() {
		t := FloorFor(op)
		fmt.Fprintf(&sb, "  %-30s %-18s requires %s\n",
			op, MinimumRole(op), t)
		if t == TierForbidden {
			sb.WriteString("      never performed through the fleet API\n")
		}
	}

	overrides := p.Overrides()
	if len(overrides) == 0 {
		sb.WriteString("\nThis policy raises nothing above those defaults.\n")
		return sb.String()
	}

	sb.WriteString("\nRaised by this policy\n")
	sb.WriteString("─────────────────────\n")
	keys := make([]Operation, 0, len(overrides))
	for op := range overrides {
		keys = append(keys, op)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, op := range keys {
		fmt.Fprintf(&sb, "  %-32s %s (was %s)\n", op, overrides[op], FloorFor(op))
	}

	if n := p.LoweringAttempts(); n > 0 {
		fmt.Fprintf(&sb, "\n%d request(s) to lower a requirement were refused.\n", n)
		sb.WriteString("A request to weaken a rule is not a mistake that can be corrected by\n")
		sb.WriteString("editing the policy: it means somebody believed the rule was wrong.\n")
	}
	return sb.String()
}
