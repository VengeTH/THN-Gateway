// Package recovery models the rollback that a future activation would need.
//
// # Why this exists before activation does
//
// Rollback planning and rollback execution are different problems, and only
// the second one is dangerous. The first is valuable long before THN can
// change anything: an operator reviewing a plan wants to know what the
// rollback story is before committing to a change, and a gateway that cannot
// describe its own recovery path is a gateway whose first outage will be
// improvised.
//
// So this package implements the description half. Given a plan and an
// observation, it computes what a recovery would target, which parts are
// reversible, and what could not be put back. It contains no code that performs
// a recovery.
//
// # Reversibility
//
// Not everything a gateway does can be undone, and pretending otherwise is the
// most dangerous thing a recovery planner can do. The planner therefore marks
// each step with an explicit reversibility class:
//
//	Reversible    the previous value is known and can be reinstated
//	PartiallyReversible the previous state is known only in part
//	Irreversible  the change cannot be undone; it requires operator action
//
// An irreversible step is never silently included: it is surfaced as a
// blocking finding so that it cannot be agreed to by accident.
package recovery

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Reversibility classifies whether a step can be undone.
type Reversibility string

const (
	// Reversible means the prior state is fully known and reinstatable.
	Reversible Reversibility = "reversible"
	// PartiallyReversible means some of the prior state is unknowable.
	PartiallyReversible Reversibility = "partially-reversible"
	// Irreversible means the change cannot be undone by THN.
	Irreversible Reversibility = "irreversible"
)

// Step is one unit of recovery work.
type Step struct {
	// ID is a stable identifier, unique within the plan.
	ID string `json:"id"`
	// Description explains what would be restored.
	Description string `json:"description"`
	// Target names the subsystem: "address", "route", "link", "nftables",
	// "qdisc", "sysctl".
	Target string `json:"target"`
	// Reversibility classifies the step.
	Reversibility Reversibility `json:"reversibility"`
	// RestoreFrom records what the prior value was, when it is known.
	RestoreFrom string `json:"restore_from,omitempty"`
	// RequiresOperator marks a step that cannot be automated.
	RequiresOperator bool `json:"requires_operator,omitempty"`
	// Reason explains why reversibility was classified this way.
	Reason string `json:"reason,omitempty"`
}

// Plan is the recovery plan derived from a gateway plan and an observation.
type Plan struct {
	// ID identifies this recovery plan.
	ID string `json:"id"`
	// GeneratedAt is when the plan was derived.
	GeneratedAt time.Time `json:"generated_at"`
	// TargetGeneration is the configuration generation the plan applies to.
	TargetGeneration int `json:"target_generation"`
	// Steps are the recovery steps in application order.
	Steps []Step `json:"steps"`
	// Blocking lists findings that prevent the plan from being agreed to.
	Blocking []Finding `json:"blocking,omitempty"`
	// Verdict summarises whether recovery is possible.
	Verdict Verdict `json:"verdict"`

	// operatorNeeded records that at least one step requires a human. It is
	// tracked separately from the steps themselves because a step can imply
	// operator involvement without being explicitly flagged at the call site.
	operatorNeeded bool
}

// Verdict is the overall recoverability assessment.
type Verdict string

const (
	// VerdictRecoverable means every step can be undone automatically.
	VerdictRecoverable Verdict = "recoverable"
	// VerdictRecoverableWithOperator means at least one step needs a human.
	VerdictRecoverableWithOperator Verdict = "recoverable-with-operator"
	// VerdictPartiallyRecoverable means some changes cannot be undone.
	VerdictPartiallyRecoverable Verdict = "partially-recoverable"
	// VerdictNotRecoverable means recovery would not restore the prior state.
	VerdictNotRecoverable Verdict = "not-recoverable"
)

// Finding is a recovery-plan concern.
type Finding struct {
	// Step identifies the step the finding concerns.
	Step string `json:"step"`
	// Severity is "info", "warning" or "error".
	Severity string `json:"severity"`
	// Message describes the finding.
	Message string `json:"message"`
}

// Input is the data the planner needs: what THN intends to change, and what
// the host currently looks like.
type Input struct {
	// TargetGeneration is the configuration generation being planned.
	TargetGeneration int
	// DesiredLANPrefix is the address THN intends to place on the LAN.
	DesiredLANPrefix string
	// DesiredResolvers is the resolver set THN intends to configure.
	DesiredResolvers []string
	// ObservedLANPrefix is the LAN address currently on the host, if any.
	ObservedLANPrefix string
	// ObservedDefaultGateway is the current default route gateway, if any.
	ObservedDefaultGateway string
	// ObservedResolvers is the resolver set currently configured.
	ObservedResolvers []string
	// FirewallTablesPresent reports whether a ruleset already exists.
	FirewallTablesPresent bool
	// QoSPresent reports whether a queue discipline is already configured.
	QoSPresent bool
}

// Build derives the recovery plan for an input.
//
// The planner is deliberately conservative: when it does not know the prior
// state of something THN would change, it says so rather than assuming a
// default. Assuming a default here would produce a recovery plan that looks
// complete and silently restores the wrong configuration.
func Build(in Input) *Plan {
	p := &Plan{
		ID:               "recovery",
		GeneratedAt:      time.Now().UTC(),
		TargetGeneration: in.TargetGeneration,
		Verdict:          VerdictRecoverable,
	}

	// --- LAN address ---
	//
	// Replacing an address is reversible only if the previous address was
	// observed. If the host already had a LAN address that THN did not
	// record, reinstating "nothing" would silently disconnect whatever was
	// using it.
	switch {
	case in.ObservedLANPrefix == "":
		p.add(Step{
			ID:               "remove-lan-address",
			Description:      fmt.Sprintf("remove the LAN address %s that THN would add", in.DesiredLANPrefix),
			Target:           "address",
			Reversibility:    Reversible,
			RestoreFrom:      "(no prior address)",
			RequiresOperator: false,
			Reason:           "the host currently has no LAN address, so removing it restores the observed state",
		})
	case in.ObservedLANPrefix == in.DesiredLANPrefix:
		// No change required; nothing to recover.
	default:
		p.add(Step{
			ID:            "restore-lan-address",
			Description:   fmt.Sprintf("restore the LAN address %s currently on the host", in.ObservedLANPrefix),
			Target:        "address",
			Reversibility: Reversible,
			RestoreFrom:   in.ObservedLANPrefix,
			Reason:        "the prior address was observed and can be reinstated",
		})
	}

	// --- Default route ---
	if in.ObservedDefaultGateway != "" {
		p.add(Step{
			ID:            "restore-default-route",
			Description:   fmt.Sprintf("restore the default route via %s", in.ObservedDefaultGateway),
			Target:        "route",
			Reversibility: Reversible,
			RestoreFrom:   in.ObservedDefaultGateway,
			Reason:        "the prior gateway was observed and can be reinstated",
		})
	} else {
		p.add(Step{
			ID:            "remove-default-route",
			Description:   "remove the default route that THN would install",
			Target:        "route",
			Reversibility: Reversible,
			RestoreFrom:   "(no prior default route)",
			Reason:        "the host currently has no default route, so removing it restores the observed state",
		})
	}

	// --- Resolvers ---
	if !sameStrings(in.ObservedResolvers, in.DesiredResolvers) {
		if len(in.ObservedResolvers) == 0 {
			p.add(Step{
				ID:               "restore-resolvers-unknown",
				Description:      "restore the resolver configuration, which was not observed before the change",
				Target:           "resolver",
				Reversibility:    PartiallyReversible,
				RequiresOperator: true,
				Reason:           "THN did not record the prior resolver set; if the host was managed by NetworkManager or systemd-resolved, the file must be restored by hand",
			})
			p.block(Finding{
				Step:     "restore-resolvers-unknown",
				Severity: "warning",
				Message:  "the prior resolver configuration was not observed, so recovery is incomplete without operator input",
			})
			p.noteOperator()
		} else {
			p.add(Step{
				ID:            "restore-resolvers",
				Description:   fmt.Sprintf("restore resolvers to %s", strings.Join(in.ObservedResolvers, ", ")),
				Target:        "resolver",
				Reversibility: Reversible,
				RestoreFrom:   strings.Join(in.ObservedResolvers, ", "),
				Reason:        "the prior resolver set was observed",
			})
		}
	}

	// --- Firewall ---
	//
	// Replacing a ruleset is the most dangerous operation THN would perform,
	// because an over-broad drop policy takes the device off the network. It
	// is only reversible if the existing ruleset was captured first, which is
	// why this step is flagged as requiring the operator to confirm capture.
	if in.FirewallTablesPresent {
		p.add(Step{
			ID:               "restore-firewall-ruleset",
			Description:      "restore the nftables ruleset that was on the host before THN replaced it",
			Target:           "nftables",
			Reversibility:    PartiallyReversible,
			RequiresOperator: true,
			Reason:           "a full ruleset can only be restored from a captured copy; if the capture is missing the host may be left unreachable",
		})
		p.block(Finding{
			Step:     "restore-firewall-ruleset",
			Severity: "error",
			Message:  "a firewall ruleset already exists on this host; confirm it has been captured before any activation, or the device may become unreachable with no way back",
		})
		p.noteOperator()
	} else {
		p.add(Step{
			ID:            "flush-firewall",
			Description:   "flush the nftables ruleset that THN would install",
			Target:        "nftables",
			Reversibility: Reversible,
			RestoreFrom:   "(empty ruleset)",
			Reason:        "the host currently has no ruleset, so an empty ruleset is the correct prior state",
		})
	}

	// --- QoS ---
	if in.QoSPresent {
		p.add(Step{
			ID:               "restore-qdisc",
			Description:      "restore the queue discipline that THN would replace",
			Target:           "qdisc",
			Reversibility:    PartiallyReversible,
			RequiresOperator: true,
			Reason:           "the prior qdisc parameters must have been recorded; without them the device falls back to the default pfifo_fast",
		})
		p.block(Finding{
			Step:     "restore-qdisc",
			Severity: "warning",
			Message:  "a queue discipline is already configured; record its parameters before any activation or the shaped settings will be lost",
		})
		p.noteOperator()
	} else {
		p.add(Step{
			ID:            "remove-qdisc",
			Description:   "remove the queue discipline that THN would install",
			Target:        "qdisc",
			Reversibility: Reversible,
			RestoreFrom:   "(default queue discipline)",
			Reason:        "the host currently has no custom qdisc",
		})
	}

	// --- Kernel tunables ---
	//
	// net.ipv4.ip_forward is the one tunable THN would set. It is reversible
	// only because its prior value is observable, and restoring it is safe.
	p.add(Step{
		ID:            "restore-ip-forward",
		Description:   "restore the observed value of net.ipv4.ip_forward",
		Target:        "sysctl",
		Reversibility: Reversible,
		RestoreFrom:   "(observed value)",
		Reason:        "the prior value is readable at recovery time, so it can be reinstated",
	})

	p.finalise()
	return p
}

// add appends a step.
func (p *Plan) add(s Step) { p.Steps = append(p.Steps, s) }

// block records a finding that must be resolved before activation.
func (p *Plan) block(f Finding) { p.Blocking = append(p.Blocking, f) }

// noteOperator records that at least one step needs a human.
func (p *Plan) noteOperator() { p.operatorNeeded = true }

// finalise computes the verdict from the accumulated steps and findings.
func (p *Plan) finalise() {
	hasError := false
	for _, f := range p.Blocking {
		if f.Severity == "error" {
			hasError = true
		}
	}

	if hasError {
		p.Verdict = VerdictNotRecoverable
		return
	}

	irreversible := false
	operator := p.operatorNeeded
	for _, s := range p.Steps {
		switch s.Reversibility {
		case Irreversible:
			irreversible = true
		case PartiallyReversible:
			operator = true
		}
		if s.RequiresOperator {
			operator = true
		}
	}

	switch {
	case irreversible:
		p.Verdict = VerdictPartiallyRecoverable
	case operator:
		p.Verdict = VerdictRecoverableWithOperator
	default:
		p.Verdict = VerdictRecoverable
	}
}

// Summary renders a one-line human-readable verdict.
func (p *Plan) Summary() string {
	return fmt.Sprintf("recovery: %s (%d steps, %d blocking findings)",
		p.Verdict, len(p.Steps), len(p.Blocking))
}

// StepsForTarget returns the steps affecting a subsystem.
func (p *Plan) StepsForTarget(target string) []Step {
	var out []Step
	for _, s := range p.Steps {
		if s.Target == target {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

// sameStrings reports whether two string slices are equal in order.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
