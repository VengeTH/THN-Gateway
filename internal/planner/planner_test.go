package planner

import (
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/diff"
)

// drift builds a drift change with the given identity.
func drift(id, subsystem, field string, risk diff.Risk) diff.Change {
	return diff.Change{
		ID:        id,
		Kind:      diff.KindDrift,
		Risk:      risk,
		Subsystem: subsystem,
		Field:     field,
		Current:   "current-value",
		Desired:   "desired-value",
		Reason:    "test drift",
	}
}

// pending builds a pending change.
func pending(id, subsystem, field string) diff.Change {
	return diff.Change{
		ID:        id,
		Kind:      diff.KindPending,
		Risk:      diff.RiskNone,
		Subsystem: subsystem,
		Field:     field,
		Reason:    "test pending",
	}
}

// blocked builds a blocked change.
func blocked(id, subsystem, field string) diff.Change {
	return diff.Change{
		ID:        id,
		Kind:      diff.KindBlocked,
		Risk:      diff.RiskCritical,
		Subsystem: subsystem,
		Field:     field,
		Reason:    "test blocked",
	}
}

// result builds a Result from changes.
func result(changes ...diff.Change) diff.Result {
	var r diff.Result
	for _, c := range changes {
		r.Changes = append(r.Changes, c)
		switch c.Kind {
		case diff.KindDrift:
			r.DriftCount++
		case diff.KindPending:
			r.PendingCount++
		case diff.KindBlocked:
			r.BlockedCount++
		}
	}
	r.Converged = r.DriftCount == 0 && r.BlockedCount == 0
	return r
}

func TestStepsAreOrderedByPhase(t *testing.T) {
	// Deliberately supplied out of order: services before addressing.
	d := result(
		drift("firewall-absent", "nftables", "firewall.enabled", diff.RiskCritical),
		drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium),
		drift("lan-address-add", "address", "lan.address", diff.RiskLow),
		drift("resolvers", "resolver", "network.dns", diff.RiskLow),
	)

	p := Build(d, Options{Generation: 1, Source: "test"})

	if len(p.Steps) != 4 {
		t.Fatalf("got %d steps, want 4", len(p.Steps))
	}
	if p.Steps[0].Phase != 1 {
		t.Errorf("first step phase = %d, want 1 (addressing)", p.Steps[0].Phase)
	}
	if p.Steps[3].Phase != 4 {
		t.Errorf("last step phase = %d, want 4 (housekeeping)", p.Steps[3].Phase)
	}
	for i := 1; i < len(p.Steps); i++ {
		if p.Steps[i].Phase < p.Steps[i-1].Phase {
			t.Errorf("phases out of order at %d: %d then %d",
				i, p.Steps[i-1].Phase, p.Steps[i].Phase)
		}
	}
}

func TestRiskiestComesFirstWithinPhase(t *testing.T) {
	d := result(
		drift("qos-absent", "qdisc", "qos.enabled", diff.RiskMedium),
		drift("firewall-absent", "nftables", "firewall.enabled", diff.RiskCritical),
	)

	p := Build(d, Options{Generation: 1})

	// Both are in phase 3, so the critical one must be rendered first.
	if p.Steps[0].ID != "firewall-absent" {
		t.Errorf("first step = %q, want the critical firewall change", p.Steps[0].ID)
	}
}

func TestPendingAndBlockedBecomeNoSteps(t *testing.T) {
	// Only drift is actionable. Pending is outstanding work; blocked is
	// unresolvable. Neither may appear as a step to perform.
	d := result(
		drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium),
		pending("lan-not-attached", "link", "lan.interface"),
		pending("nat-pending", "nftables", "nat.interfaces"),
		blocked("lan-name-mismatch", "link", "lan.interface"),
	)

	p := Build(d, Options{Generation: 1})

	if len(p.Steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(p.Steps))
	}
	if len(p.Pending) != 2 {
		t.Errorf("got %d pending, want 2", len(p.Pending))
	}
	if len(p.Blocked) != 1 {
		t.Errorf("got %d blocked, want 1", len(p.Blocked))
	}
}

func TestBlockedPreventsReady(t *testing.T) {
	d := result(
		drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium),
		blocked("wan-name-mismatch", "link", "wan.interface"),
	)

	p := Build(d, Options{Generation: 1})

	if p.Ready {
		t.Error("a plan with a blocked change must not be ready")
	}
	if !strings.Contains(p.Simulation.Headline, "cannot be made") {
		t.Errorf("headline should lead with the blocker, got %q", p.Simulation.Headline)
	}
}

func TestFirewallWarnsAboutUnreachability(t *testing.T) {
	// This is the single most important warning in the whole system: a
	// filter policy with no accept path for the management session leaves
	// the device unreachable.
	d := result(drift("firewall-absent", "nftables", "firewall.enabled", diff.RiskCritical))

	p := Build(d, Options{Generation: 1})

	joined := strings.Join(p.Simulation.Disruptions, " ")
	if !strings.Contains(joined, "unreachable") {
		t.Errorf("disruptions must warn about becoming unreachable, got %v", p.Simulation.Disruptions)
	}
	if p.Steps[0].Reversible != "partially-reversible" {
		t.Errorf("a firewall change is only partially reversible, got %q", p.Steps[0].Reversible)
	}
}

func TestAddressRemovalIsDisruptive(t *testing.T) {
	d := result(drift("lan-address-remove", "address", "lan.address", diff.RiskHigh))

	p := Build(d, Options{Generation: 1})

	if !p.Steps[0].Disruptive {
		t.Error("removing an address must be marked disruptive")
	}
	if len(p.Simulation.Disruptions) == 0 {
		t.Error("a disruptive step must produce a disruption note")
	}
}

func TestEmptyPlanIsNotReadyWhenPending(t *testing.T) {
	// Nothing to do, but work is outstanding: the plan cannot be acted on,
	// and it must say so rather than claiming success.
	d := result(
		pending("lan-not-attached", "link", "lan.interface"),
		pending("wan-unobservable", "link", "wan.interface"),
	)

	p := Build(d, Options{Generation: 1})

	if len(p.Steps) != 0 {
		t.Errorf("got %d steps, want 0", len(p.Steps))
	}
	if p.Ready {
		t.Error("a plan with pending work and no steps is not ready")
	}
	if !strings.Contains(p.Simulation.Headline, "not yet") {
		t.Errorf("headline should say the configuration is incomplete, got %q", p.Simulation.Headline)
	}
}

func TestFullyConvergedPlanIsReady(t *testing.T) {
	p := Build(result(), Options{Generation: 1})

	if len(p.Steps) != 0 || !p.Ready {
		t.Errorf("an empty diff should produce a ready plan with no steps")
	}
	if !strings.Contains(p.Simulation.Headline, "already matches") {
		t.Errorf("headline = %q, want a converged message", p.Simulation.Headline)
	}
}

func TestPlanIDIsContentAddressed(t *testing.T) {
	d := result(drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium))

	a := Build(d, Options{Generation: 1})
	b := Build(d, Options{Generation: 1})

	if a.ID != b.ID {
		t.Errorf("identical inputs produced different IDs: %q and %q", a.ID, b.ID)
	}
	if a.ID == "" {
		t.Error("plan ID must not be empty")
	}
}

func TestPlanIDChangesWithContent(t *testing.T) {
	// If the ID did not move, "has the configuration drifted since the last
	// plan?" would be unanswerable.
	base := drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium)
	a := Build(result(base), Options{Generation: 1})

	changed := base
	changed.Desired = "something-else"
	b := Build(result(changed), Options{Generation: 1})

	if a.ID == b.ID {
		t.Error("a change in plan content must change the plan ID")
	}
}

func TestPlanIDChangesWithGeneration(t *testing.T) {
	d := result(drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium))

	a := Build(d, Options{Generation: 1})
	b := Build(d, Options{Generation: 2})

	if a.ID == b.ID {
		t.Error("a new configuration generation must produce a new plan ID")
	}
}

func TestQoSCommandsCarryRates(t *testing.T) {
	c := drift("qos-absent", "qdisc", "qos.enabled", diff.RiskMedium)
	c.Desired = "cake on enp0s31f6 down=100000 up=20000"

	p := Build(result(c), Options{Generation: 1})

	if len(p.Steps[0].Commands) == 0 {
		t.Fatal("a QoS step must render a command")
	}
	cmd := p.Steps[0].Commands[0]
	for _, want := range []string{"tc qdisc replace", "enp0s31f6", "cake", "100000", "20000"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command %q is missing %q", cmd, want)
		}
	}
}

func TestForwardingCommandIsRendered(t *testing.T) {
	d := result(drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium))

	p := Build(d, Options{Generation: 1})

	if len(p.Steps[0].Commands) == 0 {
		t.Fatal("the forwarding step must render a command")
	}
	if !strings.Contains(p.Steps[0].Commands[0], "ip_forward=1") {
		t.Errorf("command = %q, want a sysctl forwarding write", p.Steps[0].Commands[0])
	}
}

func TestRiskiestHelper(t *testing.T) {
	d := result(
		drift("qos-absent", "qdisc", "qos.enabled", diff.RiskMedium),
		drift("firewall-absent", "nftables", "firewall.enabled", diff.RiskCritical),
	)

	p := Build(d, Options{Generation: 1})

	r := p.Riskiest()
	if r == nil || r.ID != "firewall-absent" {
		t.Errorf("Riskiest = %+v, want the critical firewall step", r)
	}
}

func TestRiskiestOnEmptyPlan(t *testing.T) {
	p := Build(result(), Options{Generation: 1})

	if p.Riskiest() != nil {
		t.Error("Riskiest must be nil when there are no steps")
	}
}

func TestSummaryEmbedsID(t *testing.T) {
	p := Build(result(drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium)),
		Options{Generation: 7})

	if !strings.Contains(p.Summary, p.ID) {
		t.Errorf("summary %q must embed the plan ID %q", p.Summary, p.ID)
	}
	if !strings.Contains(p.Summary, "generation 7") {
		t.Errorf("summary %q must state the generation", p.Summary)
	}
}

func TestPhasesAreExportedAndOrdered(t *testing.T) {
	ph := Phases()

	if len(ph) == 0 {
		t.Fatal("phase table must not be empty")
	}
	for i := 1; i < len(ph); i++ {
		if ph[i].Number <= ph[i-1].Number {
			t.Errorf("phases out of order: %d then %d", ph[i-1].Number, ph[i].Number)
		}
	}
	for _, p := range ph {
		if p.Purpose == "" {
			t.Errorf("phase %d has no purpose; an operator cannot review it", p.Number)
		}
	}
}

func TestStepsByPhase(t *testing.T) {
	d := result(
		drift("lan-address-add", "address", "lan.address", diff.RiskLow),
		drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium),
	)

	p := Build(d, Options{Generation: 1})

	if len(p.StepsByPhase(1)) != 1 {
		t.Error("phase 1 should hold the addressing step")
	}
	if len(p.StepsByPhase(2)) != 1 {
		t.Error("phase 2 should hold the forwarding step")
	}
	if len(p.StepsByPhase(3)) != 0 {
		t.Error("phase 3 should be empty")
	}
}
