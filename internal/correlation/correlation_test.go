package correlation_test

import (
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/correlation"
	"github.com/VengeTH/THN-Gateway/internal/rules"
	"github.com/VengeTH/THN-Gateway/internal/signals"
)

var base = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

// instance builds a firing rule instance with the given labels.
//
// The labels live on the evidence signal rather than on the instance, because
// that is where a real evaluator puts them: the labels belong to the
// observation that produced the firing, not to the rule.
func instance(name, source string, sev rules.Severity, labels map[string]string) rules.Instance {
	return rules.Instance{
		Rule:     name,
		State:    rules.StateFiring,
		Severity: sev,
		Evidence: &signals.Signal{
			Name: "x", Source: source, Value: signals.Bool(false), At: base, Labels: labels,
		},
	}
}

// netLabels is a label set for a network-sourced instance.
func netLabels() map[string]string { return map[string]string{"source": "network"} }

// dhcpLabels is a label set for a DHCP-sourced instance.
func dhcpLabels() map[string]string { return map[string]string{"source": "dhcp"} }

// noWindow is a correlator with no grouping window, so groups are emitted on
// the first pass. Tests that are not about the window use it to stay simple.
func noWindow(t *testing.T, inhibit ...correlation.InhibitRule) *correlation.Correlator {
	t.Helper()

	c, err := correlation.New(correlation.Config{
		GroupBy:     []string{"source"},
		GroupWindow: 0,
		Inhibit:     inhibit,
	})
	if err != nil {
		t.Fatalf("building the correlator: %v", err)
	}
	return c
}

// TestFiringRulesInTheSameGroupBecomeOneGroup is the package's reason for
// existing at the simplest level.
func TestFiringRulesInTheSameGroupBecomeOneGroup(t *testing.T) {
	c := noWindow(t)

	groups := c.Process([]rules.Instance{
		instance("no-default-route", "network", rules.SeverityCritical, netLabels()),
		instance("ipv4-forwarding-off", "network", rules.SeverityWarning, netLabels()),
		instance("wan-down", "network", rules.SeverityCritical, netLabels()),
	}, base)

	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1; three conditions from one subsystem are "+
			"one problem, not three", len(groups))
	}
	if len(groups[0].Members) != 3 {
		t.Errorf("members = %d, want 3", len(groups[0].Members))
	}
}

// TestDifferentSourcesDoNotGroup is the boundary that keeps correlation from
// being useless. Merging an uplink fault with a full DHCP pool would hide both.
func TestDifferentSourcesDoNotGroup(t *testing.T) {
	c := noWindow(t)

	groups := c.Process([]rules.Instance{
		instance("no-default-route", "network", rules.SeverityCritical, netLabels()),
		instance("dhcp-pool-exhausted", "dhcp", rules.SeverityCritical, dhcpLabels()),
	}, base)

	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2; a network fault and a pool problem have "+
			"nothing to do with each other", len(groups))
	}
}

// TestInhibitionSuppressesAConsequence: the arithmetic this package exists to
// fix. A down uplink has no default route, and reporting both tells an
// operator to look at two things when there is one.
func TestInhibitionSuppressesAConsequence(t *testing.T) {
	c := noWindow(t, correlation.InhibitRule{
		Source: "wan-down",
		Target: "no-default-route",
		Reason: "a down uplink has no usable default route",
	})

	groups := c.Process([]rules.Instance{
		instance("wan-down", "network", rules.SeverityCritical, netLabels()),
		instance("no-default-route", "network", rules.SeverityCritical, netLabels()),
	}, base)

	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	g := groups[0]

	if len(g.Reportable()) != 1 {
		t.Errorf("reportable = %d, want 1; the consequence must be suppressed", len(g.Reportable()))
	}
	if g.Reportable()[0].Rule != "wan-down" {
		t.Errorf("the surviving member is %q, want the cause", g.Reportable()[0].Rule)
	}
}

// TestASuppressedMemberIsKeptNotDiscarded: the information is still true, and
// losing it would mean that resolving the cause loses what else was true at
// the time.
func TestASuppressedMemberIsKeptNotDiscarded(t *testing.T) {
	c := noWindow(t, correlation.InhibitRule{
		Source: "wan-down", Target: "no-default-route",
		Reason: "a down uplink has no usable default route",
	})

	groups := c.Process([]rules.Instance{
		instance("wan-down", "network", rules.SeverityCritical, netLabels()),
		instance("no-default-route", "network", rules.SeverityCritical, netLabels()),
	}, base)

	suppressed := groups[0].Suppressed()
	if len(suppressed) != 1 {
		t.Fatalf("suppressed = %d, want 1; the member must be kept and marked", len(suppressed))
	}

	m := suppressed[0]
	if m.SuppressedBy != "wan-down" {
		t.Errorf("suppressed by %q, want wan-down", m.SuppressedBy)
	}
	if m.SuppressedReason == "" {
		t.Error("the suppression has no reason; an operator reading the incident " +
			"cannot tell why something was not reported")
	}
}

// TestASuppressedRuleDoesNotSuppressAnything is the cascade guard.
//
// Without this, a chain of consequences would silence a tree: A fires, B is
// suppressed by A, and B then suppresses C. Two levels of causality would
// remove an entire subtree from the report.
func TestASuppressedRuleDoesNotSuppressAnything(t *testing.T) {
	c := noWindow(t,
		correlation.InhibitRule{
			Source: "wan-down", Target: "no-default-route",
			Reason: "a down uplink has no usable default route",
		},
		correlation.InhibitRule{
			Source: "no-default-route", Target: "dhcp-pool-exhausted",
			Reason: "test cascade",
		},
	)

	// The pool rule is in a different group, so give everything the network
	// source to make the cascade reachable.
	pool := map[string]string{"source": "network"}
	groups := c.Process([]rules.Instance{
		instance("wan-down", "network", rules.SeverityCritical, netLabels()),
		instance("no-default-route", "network", rules.SeverityWarning, netLabels()),
		instance("dhcp-pool-exhausted", "network", rules.SeverityWarning, pool),
	}, base)

	g := groups[0]

	// Two survive: the cause, and the rule that would have been suppressed by
	// the suppressed one. That second rule is the point of the test.
	if len(g.Reportable()) != 2 {
		t.Fatalf("reportable = %d, want 2: %+v", len(g.Reportable()), g.Reportable())
	}

	// Asserted as a set, not by position: members are sorted by rule name so
	// two groups with the same content render identically.
	surviving := map[string]bool{}
	for _, m := range g.Reportable() {
		surviving[m.Rule] = true
	}
	if !surviving["wan-down"] {
		t.Error("the cause was suppressed; a cause is never suppressed by its own consequence")
	}
	if !surviving["dhcp-pool-exhausted"] {
		t.Error("a rule was suppressed by an already-suppressed rule; the " +
			"suppression cascaded")
	}
	if g.Suppressed()[0].Rule != "no-default-route" {
		t.Errorf("suppressed %q, want no-default-route", g.Suppressed()[0].Rule)
	}
}

// TestGroupFingerprintSurvivesShrinkingMembers is the property that makes a
// degrading gateway one incident rather than a stream.
//
// Five conditions firing, then four, then three, then one, are one incident
// getting worse. Fingerprinting on the member set would open four.
func TestGroupFingerprintSurvivesShrinkingMembers(t *testing.T) {
	c := noWindow(t)

	all := []rules.Instance{
		instance("a", "network", rules.SeverityCritical, netLabels()),
		instance("b", "network", rules.SeverityWarning, netLabels()),
		instance("c", "network", rules.SeverityWarning, netLabels()),
	}

	first := c.Process(all, base)
	if len(first) != 1 {
		t.Fatalf("groups = %d, want 1", len(first))
	}
	fp := first[0].Fingerprint

	// Drop members one at a time, advancing time so nothing is windowed.
	for i := 1; i < len(all); i++ {
		got := c.Process(all[i:], base.Add(time.Duration(i)*time.Minute))
		if len(got) != 1 {
			t.Fatalf("groups = %d, want 1 after dropping %d members", len(got), i)
		}
		if got[0].Fingerprint != fp {
			t.Errorf("the fingerprint changed when the member set shrank: %q then %q; "+
				"one degrading incident is opening a new one per member change", fp, got[0].Fingerprint)
		}
	}
}

// TestAGroupOfOnlySuppressedMembersIsNotEmitted: a consequence whose cause has
// already resolved is not a problem, and opening an incident for it reports the
// absence of a cause as if it were a cause.
// TestAGroupOfOnlySuppressedMembersIsUnreachable is a property, not a
// scenario.
//
// Inhibition only applies within a group, and a group is keyed by the labels
// that inhibition matches on. So a cause suppressing its own consequence puts
// both in the same group — and the cause is always reportable, because a
// member never suppresses itself and a suppressed member suppresses nothing.
//
// The consequence is that a group can never consist solely of suppressed
// members. Group.Empty exists as a defence, but reaching it would mean
// inhibition had been wired wrong.
func TestAGroupOfOnlySuppressedMembersIsUnreachable(t *testing.T) {
	c := noWindow(t, correlation.InhibitRule{
		Source: "a", Target: "*",
		Reason: "everything here is a consequence of a",
	})

	groups := c.Process([]rules.Instance{
		instance("a", "network", rules.SeverityCritical, netLabels()),
		instance("b", "network", rules.SeverityWarning, netLabels()),
		instance("c", "network", rules.SeverityInfo, netLabels()),
	}, base)

	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	g := groups[0]

	if g.Empty() {
		t.Fatal("the group is empty; a suppressed member suppressed the cause that " +
			"suppressed it, which the cascade guard should prevent")
	}
	if g.Reportable()[0].Rule != "a" {
		t.Errorf("the sole reportable member is %q, want the cause a", g.Reportable()[0].Rule)
	}
	if len(g.Suppressed()) != 2 {
		t.Errorf("suppressed = %d, want 2", len(g.Suppressed()))
	}

	// With no cause firing, inhibition cannot apply at all, so the remaining
	// member becomes reportable rather than staying muted.
	after := c.Process([]rules.Instance{
		instance("b", "network", rules.SeverityWarning, netLabels()),
	}, base.Add(time.Minute))

	if len(after) == 1 && after[0].Empty() {
		t.Error("a member stayed muted after its cause stopped firing; inhibition " +
			"is a suppression, not a permanent disable")
	}
}

// TestWindowDefersEmission is what stops a burst of conditions arriving across
// three observations from producing three partial incidents.
func TestWindowDefersEmission(t *testing.T) {
	c, err := correlation.New(correlation.Config{
		GroupBy:     []string{"source"},
		GroupWindow: time.Minute,
	})
	if err != nil {
		t.Fatalf("building the correlator: %v", err)
	}

	// Three observations twenty seconds apart, all strictly inside the
	// window. The last one is at 40s, so it is not sitting on the boundary —
	// a boundary case is its own test, and mixing it in here would make a
	// failure ambiguous.
	for i := 0; i < 3; i++ {
		at := base.Add(time.Duration(i) * 20 * time.Second)
		groups := c.Process([]rules.Instance{
			instance("a", "network", rules.SeverityWarning, netLabels()),
		}, at)
		if len(groups) != 0 {
			t.Fatalf("observation %d at %s emitted a group inside the window",
				i, at.Sub(base))
		}
	}

	// Past the window.
	at := base.Add(90 * time.Second)
	groups := c.Process([]rules.Instance{
		instance("a", "network", rules.SeverityWarning, netLabels()),
	}, at)
	if len(groups) != 1 {
		t.Errorf("groups = %d after the window elapsed, want 1", len(groups))
	}
}

// TestWindowBoundaryIsInclusiveOfEmission: a group seen for exactly the
// window duration has been collecting long enough, and waiting one more
// interval would delay every report by one cycle.
func TestWindowBoundaryIsInclusiveOfEmission(t *testing.T) {
	c, err := correlation.New(correlation.Config{
		GroupBy:     []string{"source"},
		GroupWindow: time.Minute,
	})
	if err != nil {
		t.Fatalf("building the correlator: %v", err)
	}

	instances := []rules.Instance{instance("a", "network", rules.SeverityWarning, netLabels())}

	if got := c.Process(instances, base); len(got) != 0 {
		t.Fatalf("a group was emitted immediately with a one-minute window")
	}
	if got := c.Process(instances, base.Add(time.Minute)); len(got) != 1 {
		t.Errorf("groups = %d at exactly the window duration, want 1", len(got))
	}
}

// TestWindowCollectsRatherThanRestarts: a group seen once a second for a
// minute must emit one group, not one per observation.
func TestWindowCollectsRatherThanRestarts(t *testing.T) {
	c, err := correlation.New(correlation.Config{
		GroupBy:     []string{"source"},
		GroupWindow: time.Minute,
	})
	if err != nil {
		t.Fatalf("building the correlator: %v", err)
	}

	emitted := 0
	for i := 0; i < 120; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		emitted += len(c.Process([]rules.Instance{
			instance("a", "network", rules.SeverityWarning, netLabels()),
		}, at))
	}

	if emitted != 1 {
		t.Errorf("emitted %d groups over two minutes of one-second observations, want 1", emitted)
	}
}

// TestAGroupThatStopsIsForgotten: a resolved fault must disappear rather than
// linger and be reported on every subsequent observation.
func TestAGroupThatStopsIsForgotten(t *testing.T) {
	c := noWindow(t)

	if got := c.Process([]rules.Instance{
		instance("a", "network", rules.SeverityWarning, netLabels()),
	}, base); len(got) != 1 {
		t.Fatalf("the group was never emitted: %v", got)
	}

	if got := c.Process(nil, base.Add(time.Minute)); len(got) != 0 {
		t.Errorf("a group with nothing firing was emitted: %v", got)
	}
}

// TestSeverityIsTheWorstReportableMember: a suppressed critical consequence
// must not raise the group's severity above its cause.
func TestSeverityIsTheWorstReportableMember(t *testing.T) {
	c := noWindow(t, correlation.InhibitRule{
		Source: "a", Target: "b", Reason: "b is a consequence of a",
	})

	groups := c.Process([]rules.Instance{
		instance("a", "network", rules.SeverityWarning, netLabels()),
		instance("b", "network", rules.SeverityCritical, netLabels()),
	}, base)

	if got := groups[0].Severity; got != rules.SeverityWarning {
		t.Errorf("group severity = %q, want warning; a suppressed member must not "+
			"raise the severity above the cause that is actually reported", got)
	}
}

// TestLabelValuesCannotForgeAGroupBoundary: a label value containing the
// separator must not be able to impersonate a different grouping.
func TestLabelValuesCannotForgeAGroupBoundary(t *testing.T) {
	c := noWindow(t)

	honest := c.Process([]rules.Instance{
		instance("a", "network", rules.SeverityWarning, netLabels()),
	}, base)

	forged := c.Process([]rules.Instance{
		instance("a", "network", rules.SeverityWarning, map[string]string{"source": "network,x=1"}),
	}, base.Add(time.Minute))

	if len(honest) != 1 || len(forged) != 1 {
		t.Fatalf("unexpected group counts: %d and %d", len(honest), len(forged))
	}
	if honest[0].Fingerprint == forged[0].Fingerprint {
		t.Error("a label value containing the separator produced the same " +
			"fingerprint as a different label set")
	}
}

// TestConfigValidationRejectsAnUnjustifiedSuppression: a suppression with no
// stated reason is one that will eventually hide something real.
func TestConfigValidationRejectsAnUnjustifiedSuppression(t *testing.T) {
	cases := []struct {
		name string
		cfg  correlation.Config
	}{
		{"no grouping labels", correlation.Config{GroupBy: nil, GroupWindow: time.Minute}},
		{"negative window", correlation.Config{GroupBy: []string{"source"}, GroupWindow: -time.Second}},
		{"suppression with no reason", correlation.Config{
			GroupBy: []string{"source"}, GroupWindow: time.Minute,
			Inhibit: []correlation.InhibitRule{{Source: "a", Target: "b"}},
		}},
		{"suppression with no target", correlation.Config{
			GroupBy: []string{"source"}, GroupWindow: time.Minute,
			Inhibit: []correlation.InhibitRule{{Source: "a", Reason: "r"}},
		}},
		{"suppress everything with everything", correlation.Config{
			GroupBy: []string{"source"}, GroupWindow: time.Minute,
			Inhibit: []correlation.InhibitRule{{Source: "*", Target: "*", Reason: "r"}},
		}},
	}

	for _, c := range cases {
		if _, err := correlation.New(c.cfg); err == nil {
			t.Errorf("%s: a configuration that %s was accepted", c.name, c.name)
		}
	}

	if _, err := correlation.New(correlation.Default()); err != nil {
		t.Errorf("the default configuration was rejected: %v", err)
	}
}

// TestGroupTitleNamesTheConditions: an incident has to say what is wrong, and
// "group network" does not.
func TestGroupTitleNamesTheConditions(t *testing.T) {
	c := noWindow(t)

	groups := c.Process([]rules.Instance{
		instance("wan-down", "network", rules.SeverityCritical, netLabels()),
		instance("no-default-route", "network", rules.SeverityCritical, netLabels()),
	}, base)

	if groups[0].Title() == "" {
		t.Error("the group has no title")
	}
}

// TestProcessingIsDeterministic: two runs over the same observations must
// produce identical groups, or two reports of an unchanged gateway differ.
func TestProcessingIsDeterministic(t *testing.T) {
	run := func() []correlation.Group {
		c := noWindow(t, correlation.InhibitRule{
			Source: "wan-down", Target: "no-default-route", Reason: "consequence",
		})
		return c.Process([]rules.Instance{
			instance("wan-down", "network", rules.SeverityCritical, netLabels()),
			instance("no-default-route", "network", rules.SeverityCritical, netLabels()),
			instance("a", "network", rules.SeverityWarning, netLabels()),
			instance("b", "network", rules.SeverityWarning, netLabels()),
			instance("c", "network", rules.SeverityInfo, netLabels()),
		}, base)
	}

	first := run()
	for i := 0; i < 30; i++ {
		got := run()
		if len(got) != len(first) {
			t.Fatalf("group count varies: %d then %d", len(first), len(got))
		}
		for j := range got {
			if got[j].Fingerprint != first[j].Fingerprint {
				t.Fatalf("fingerprints vary: %v then %v", first, got)
			}
			if got[j].Key != first[j].Key {
				t.Fatalf("keys vary: %v then %v", first, got)
			}
		}
	}
}
