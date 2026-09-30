package recovery

import "testing"

func TestBuildOnCleanHostIsRecoverable(t *testing.T) {
	// The expected development state: nothing configured yet, so every
	// change THN would make is trivially reversible.
	p := Build(Input{
		TargetGeneration:  1,
		DesiredLANPrefix:  "10.77.0.1/24",
		DesiredResolvers:  nil,
		ObservedLANPrefix: "",
	})

	if p.Verdict != VerdictRecoverable {
		t.Errorf("verdict = %q, want %q", p.Verdict, VerdictRecoverable)
	}
	if len(p.Blocking) != 0 {
		t.Errorf("clean host should have no blocking findings, got %+v", p.Blocking)
	}
	if len(p.Steps) == 0 {
		t.Error("expected at least one recovery step")
	}
}

func TestBuildWithExistingFirewallIsNotRecoverable(t *testing.T) {
	// This is the dangerous case: an existing ruleset that THN would replace.
	// Replacing it without a captured copy can leave the device unreachable
	// with no way back, so the planner must refuse to call it recoverable.
	p := Build(Input{
		TargetGeneration:      2,
		DesiredLANPrefix:      "10.77.0.1/24",
		ObservedLANPrefix:     "192.168.1.50/24",
		FirewallTablesPresent: true,
	})

	if p.Verdict != VerdictNotRecoverable {
		t.Errorf("verdict = %q, want %q", p.Verdict, VerdictNotRecoverable)
	}

	var found bool
	for _, f := range p.Blocking {
		if f.Step == "restore-firewall-ruleset" && f.Severity == "error" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an error blocking finding for the firewall, got %+v", p.Blocking)
	}
}

func TestBuildWithExistingQoSNeedsOperator(t *testing.T) {
	p := Build(Input{
		TargetGeneration: 3,
		DesiredLANPrefix: "10.77.0.1/24",
		QoSPresent:       true,
	})

	if p.Verdict != VerdictRecoverableWithOperator {
		t.Errorf("verdict = %q, want %q", p.Verdict, VerdictRecoverableWithOperator)
	}
	if len(p.StepsForTarget("qdisc")) == 0 {
		t.Error("expected a qdisc recovery step")
	}
}

func TestBuildFlagsUnobservedResolvers(t *testing.T) {
	// Changing resolvers when the prior set was never captured leaves the
	// host depending on NetworkManager or systemd-resolved state that THN
	// cannot restore blind.
	p := Build(Input{
		TargetGeneration:  4,
		DesiredLANPrefix:  "10.77.0.1/24",
		DesiredResolvers:  []string{"1.1.1.1", "9.9.9.9"},
		ObservedResolvers: nil,
	})

	steps := p.StepsForTarget("resolver")
	if len(steps) != 1 {
		t.Fatalf("expected one resolver step, got %d", len(steps))
	}
	if steps[0].Reversibility != PartiallyReversible {
		t.Errorf("reversibility = %q, want %q", steps[0].Reversibility, PartiallyReversible)
	}
	if !steps[0].RequiresOperator {
		t.Error("restoring unobserved resolvers must require operator involvement")
	}
}

func TestBuildRestoresObservedValues(t *testing.T) {
	p := Build(Input{
		TargetGeneration:       5,
		DesiredLANPrefix:       "10.77.0.1/24",
		DesiredResolvers:       []string{"1.1.1.1"},
		ObservedLANPrefix:      "192.168.1.50/24",
		ObservedDefaultGateway: "192.168.1.1",
		ObservedResolvers:      []string{"9.9.9.9"},
	})

	// The prior LAN address and gateway must appear verbatim, so that an
	// operator reading the plan can see exactly what would be put back.
	var sawLAN, sawGateway bool
	for _, s := range p.Steps {
		if s.Target == "address" && s.RestoreFrom == "192.168.1.50/24" {
			sawLAN = true
		}
		if s.Target == "route" && s.RestoreFrom == "192.168.1.1" {
			sawGateway = true
		}
	}
	if !sawLAN {
		t.Error("plan does not record the observed LAN address for restoration")
	}
	if !sawGateway {
		t.Error("plan does not record the observed gateway for restoration")
	}
}

func TestBuildIsIdempotentOnInput(t *testing.T) {
	// The same input must produce the same steps; a planner that varied
	// between runs could not be reviewed or agreed to.
	in := Input{
		TargetGeneration: 6,
		DesiredLANPrefix: "10.77.0.1/24",
		QoSPresent:       true,
	}

	a := Build(in)
	b := Build(in)

	if len(a.Steps) != len(b.Steps) {
		t.Fatalf("step counts differ: %d vs %d", len(a.Steps), len(b.Steps))
	}
	if a.Verdict != b.Verdict {
		t.Errorf("verdicts differ: %q vs %q", a.Verdict, b.Verdict)
	}
	for i := range a.Steps {
		if a.Steps[i].ID != b.Steps[i].ID {
			t.Errorf("step %d differs: %q vs %q", i, a.Steps[i].ID, b.Steps[i].ID)
		}
	}
}

func TestEveryStepHasReasonAndReversibility(t *testing.T) {
	// Each step must justify its classification. A step with an empty reason
	// is one an operator cannot evaluate.
	p := Build(Input{
		TargetGeneration:      7,
		DesiredLANPrefix:      "10.77.0.1/24",
		DesiredResolvers:      []string{"1.1.1.1"},
		FirewallTablesPresent: true,
		QoSPresent:            true,
	})

	for _, s := range p.Steps {
		if s.ID == "" {
			t.Error("step is missing an ID")
		}
		if s.Description == "" {
			t.Errorf("step %s is missing a description", s.ID)
		}
		if s.Reason == "" {
			t.Errorf("step %s is missing a reason", s.ID)
		}
		switch s.Reversibility {
		case Reversible, PartiallyReversible, Irreversible:
		default:
			t.Errorf("step %s has invalid reversibility %q", s.ID, s.Reversibility)
		}
	}
}

func TestSummaryIsNonEmpty(t *testing.T) {
	p := Build(Input{DesiredLANPrefix: "10.77.0.1/24"})
	if p.Summary() == "" {
		t.Error("Summary must not be empty")
	}
}
