package ruleset_test

import (
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/correlation"
	"github.com/VengeTH/THN-Gateway/internal/incidents"
	"github.com/VengeTH/THN-Gateway/internal/rules"
	"github.com/VengeTH/THN-Gateway/internal/ruleset"
	"github.com/VengeTH/THN-Gateway/internal/signals"
)

var base = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

// TestTheShippedRuleSetIsValid is the meta-test. A malformed rule in the
// shipped set is a bug, and it should surface in `go test` rather than in
// whichever command happens to run first on a gateway.
func TestTheShippedRuleSetIsValid(t *testing.T) {
	if err := ruleset.Validate(); err != nil {
		t.Fatalf("the shipped rule set does not validate: %v", err)
	}
}

// TestRuleNamesAreUnique: a duplicate name would make two rules share an
// evaluator instance, and one of them would silently stop being evaluated.
func TestRuleNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range ruleset.All() {
		if seen[r.Name] {
			t.Errorf("rule name %q appears more than once", r.Name)
		}
		seen[r.Name] = true
	}
}

// TestEveryRuleCanExplainItself: an operator reads these, from a distance, and
// has nothing else. A rule whose condition cannot be stated in a sentence is a
// rule that cannot be trusted.
func TestEveryRuleCanExplainItself(t *testing.T) {
	for _, r := range ruleset.All() {
		desc := r.Condition.Describe()
		if desc == "" {
			t.Errorf("rule %q has a condition that describes itself as nothing", r.Name)
		}
		if desc == "never" {
			t.Errorf("rule %q can never hold; it is either a mistake or a disabled "+
				"rule that should be removed", r.Name)
		}
	}
}

// TestEveryRuleSaysWhatToDo: a rule nobody can act on is an observation, and
// presenting it as an incident sends someone looking for something to do.
func TestEveryRuleSaysWhatToDo(t *testing.T) {
	for _, r := range ruleset.All() {
		if r.Remedy == "" {
			t.Errorf("rule %q has no remedy; an operator who sees it has nothing "+
				"to act on", r.Name)
		}
	}
}

// TestEveryRuleNamesItsSignals: a rule reading signals that do not exist can
// never fire, and would look exactly like a healthy gateway.
func TestEveryRuleNamesItsSignals(t *testing.T) {
	for _, r := range ruleset.All() {
		names := r.Condition.Signals()
		if len(names) == 0 {
			t.Errorf("rule %q reads no signals at all", r.Name)
		}
		for _, n := range names {
			if n == "" {
				t.Errorf("rule %q names an empty signal", r.Name)
			}
		}
	}
}

// TestCriticalRulesAreTheOnesThatBreakTraffic: the boundary is the one most
// worth defending, because a critical label that appears for conditions nobody
// would act on immediately trains triage, and triage is what makes the label
// mean anything.
func TestCriticalRulesAreTheOnesThatBreakTraffic(t *testing.T) {
	// Every critical rule must be justified in its own comment or remedy.
	// This is a review aid: it forces a critical label to be argued for rather
	// than reached for.
	for _, r := range ruleset.All() {
		if r.Severity != rules.SeverityCritical {
			continue
		}
		if r.Comments == nil && !hasNote(r.Remedy) {
			t.Errorf("rule %q is critical with no comment explaining why that is the "+
				"right label; the critical boundary should be argued for", r.Name)
		}
	}
}

// hasNote reports whether a remedy contains an explanation, as opposed to
// being a bare instruction.
func hasNote(s string) bool { return len(s) > 40 }

// TestRulesDerivedFromLinkStateHaveADuration: a link that flaps produces an
// incident per flap without one, and an operator who receives forty in an
// hour learns the tool is noise.
func TestRulesDerivedFromLinkStateHaveADuration(t *testing.T) {
	linkRules := []string{
		ruleset.WANDown,
		ruleset.NoDefaultRoute,
		ruleset.ForwardingOff,
		ruleset.FirewallInactive,
		ruleset.FirewallNoRules,
		ruleset.ShapingInactive,
		ruleset.DriftPersistent,
	}

	byName := map[string]rules.Rule{}
	for _, r := range ruleset.All() {
		byName[r.Name] = r
	}

	for _, name := range linkRules {
		r, ok := byName[name]
		if !ok {
			t.Errorf("rule %q is missing from the shipped set", name)
			continue
		}
		if r.For == 0 {
			t.Errorf("rule %q is derived from link or service state and has no "+
				"duration; it will fire on every flap", name)
		}
	}
}

// TestRulesDerivedFromConfigurationHaveNoDuration: a misconfiguration does
// not become configured on its own, so there is nothing to wait for.
func TestRulesDerivedFromConfigurationHaveNoDuration(t *testing.T) {
	for _, r := range ruleset.All() {
		if r.Name != ruleset.ConfigInvalid {
			continue
		}
		if r.For != 0 {
			t.Errorf("rule %q has a %s duration; a configuration error is present "+
				"or it is not, and waiting only delays the report", r.Name, r.For)
		}
	}
}

// TestEveryInhibitionNamesARealRule: a typo in an inhibition silently disables
// a suppression, and the correlation quietly stops working. Nothing looks
// broken; there are just more incidents than there should be.
func TestEveryInhibitionNamesARealRule(t *testing.T) {
	names := map[string]bool{}
	for _, r := range ruleset.All() {
		names[r.Name] = true
	}

	for _, in := range ruleset.Inhibitions() {
		if in.Source != "*" && !names[in.Source] {
			t.Errorf("an inhibition names source %q, which is not a shipped rule", in.Source)
		}
		if in.Target != "*" && !names[in.Target] {
			t.Errorf("an inhibition names target %q, which is not a shipped rule", in.Target)
		}
		if in.Reason == "" {
			t.Errorf("the inhibition of %q by %q states no reason", in.Target, in.Source)
		}
	}
}

// TestSuppressionsAreNarrow: a suppression that is too broad hides independent
// faults. An uplink that is down and a disabled forwarding sysctl are two
// problems, and reporting only the first means the second is discovered when
// the first is fixed.
func TestSuppressionsAreNarrow(t *testing.T) {
	for _, in := range ruleset.Inhibitions() {
		if in.Target != "*" {
			continue
		}
		// A blanket target is only acceptable when the source means "nothing
		// about this host can be believed".
		if in.Source != ruleset.HostUnobservable {
			t.Errorf("%q suppresses everything, but only the host-unobservable rule "+
				"justifies that: it is the one signal that makes every other "+
				"reading unreliable", in.Source)
		}
	}
}

// TestPoolRulesRequireANonZeroCapacity is the trap the ruleset documents.
//
// Utilisation against a capacity of zero divides by zero, and reading that as
// 100% would report an exhausted pool on every gateway with DHCP disabled.
func TestPoolRulesRequireANonZeroCapacity(t *testing.T) {
	byName := map[string]rules.Rule{}
	for _, r := range ruleset.All() {
		byName[r.Name] = r
	}

	for _, name := range []string{ruleset.PoolExhausted, ruleset.PoolNearlyFull} {
		r := byName[name]
		if !readsSignal(r, signals.DHCPPoolCapacity) {
			t.Errorf("rule %q does not read the pool capacity; without it a "+
				"gateway with no pool would report one as exhausted", name)
		}
	}
}

// TestWANDownRequiresTheInterfaceToBePresent: a gateway whose WAN has not
// been identified yet is not one that has lost it. Without this check, a
// half-configured gateway reports its uplink down.
func TestWANDownRequiresTheInterfaceToBePresent(t *testing.T) {
	var rule rules.Rule
	for _, r := range ruleset.All() {
		if r.Name == ruleset.WANDown {
			rule = r
		}
	}
	if rule.Condition == nil {
		t.Fatal("the wan-down rule is missing")
	}
	if !readsSignal(rule, signals.NetWANPresent) {
		t.Error("wan-down does not require the interface to be present; a gateway " +
			"whose WAN is not yet identified would report it as down")
	}
}

// TestNoRuleFiresOnAnUnobservableHost is the end-to-end expression of the
// package's central promise.
//
// A gateway THN cannot inspect produces one signal it does know — that
// inspection failed — and unknowns for everything else. Exactly one rule may
// fire, and it must be the one about THN's own blindness.
func TestNoRuleFiresOnAnUnobservableHost(t *testing.T) {
	set := signals.NewSet(base, signals.Signal{
		Name: signals.NetInspectSupported, Source: signals.SourceNetwork,
		Value: signals.Bool(false), At: base,
		Detail: "this host could not be inspected",
	})

	ev := rules.NewEvaluator(func() time.Time { return base })
	firing, _ := ev.Evaluate(ruleset.All(), set)

	if len(firing) != 1 {
		names := make([]string, 0, len(firing))
		for _, f := range firing {
			names = append(names, f.Rule)
		}
		t.Fatalf("firing on an unobservable host: %v; exactly the "+
			"host-unobservable rule may fire, and nothing else", names)
	}
	if firing[0].Rule != ruleset.HostUnobservable {
		t.Errorf("fired %q, want %q", firing[0].Rule, ruleset.HostUnobservable)
	}
	if firing[0].Severity != rules.SeverityWarning {
		t.Errorf("severity = %q, want warning; THN being blind is a problem "+
			"with THN, not with the gateway", firing[0].Severity)
	}
}

// TestEveryRuleIsUndecidableWhenItsSignalsAre is the companion check.
//
// On a set with nothing in it, no rule may fire. Any rule that does is
// deriving a conclusion from the absence of data, which is the failure this
// whole design is built to prevent.
func TestEveryRuleIsUndecidableWhenItsSignalsAre(t *testing.T) {
	empty := signals.NewSet(base)

	ev := rules.NewEvaluator(func() time.Time { return base })
	firing, _ := ev.Evaluate(ruleset.All(), empty)

	if len(firing) != 0 {
		names := make([]string, 0, len(firing))
		for _, f := range firing {
			names = append(names, f.Rule)
		}
		t.Errorf("fired on an empty observation: %v; every rule needs data", names)
	}
}

// TestAFirewallThatCannotBeReadDoesNotReportAnInactiveFirewall: the single
// most damaging false positive an alerting system can produce about a
// security control.
func TestAFirewallThatCannotBeReadDoesNotReportAnInactiveFirewall(t *testing.T) {
	set := signals.NewSet(base,
		signals.Signal{Name: signals.NetInspectSupported, Source: signals.SourceNetwork,
			Value: signals.Bool(true), At: base},
		signals.Signal{Name: signals.FirewallActive, Source: signals.SourceFirewall,
			Value: signals.Unknown(signals.KindBool), At: base},
	)

	ev := rules.NewEvaluator(func() time.Time { return base })
	firing, _ := ev.Evaluate(ruleset.All(), set)

	for _, f := range firing {
		if f.Rule == ruleset.FirewallInactive || f.Rule == ruleset.FirewallNoRules {
			t.Errorf("%q fired on an unreadable firewall state; reporting a "+
				"security control as down when it could not be checked sends an "+
				"operator to disable a working firewall", f.Rule)
		}
	}
}

// TestAFirewallThatIsKnownDownDoesFire is the negative control. Without it,
// the test above would pass with a rule that can never fire.
func TestAFirewallThatIsKnownDownDoesFire(t *testing.T) {
	set := signals.NewSet(base,
		signals.Signal{Name: signals.NetInspectSupported, Source: signals.SourceNetwork,
			Value: signals.Bool(true), At: base},
		signals.Signal{Name: signals.FirewallActive, Source: signals.SourceFirewall,
			Value: signals.Bool(false), At: base},
	)

	// The clock has to advance: the rule has a one-minute grace, and a
	// constant clock means the threshold is never met — which is the
	// difference between "the rule did not fire" and "the rule cannot fire".
	c := &stepClock{now: base}
	ev := rules.NewEvaluator(c.Now)

	for i := 0; i < 4; i++ {
		c.advance(30 * time.Second)
		firing, _ := ev.Evaluate(ruleset.All(), set)

		var found bool
		for _, f := range firing {
			if f.Rule == ruleset.FirewallInactive {
				found = true
			}
		}
		if found {
			return
		}
	}

	t.Error("an inactive firewall did not fire after two minutes; the previous " +
		"test would pass with a rule that can never fire")
}

// TestAnEmptyPoolDoesNotReportExhaustion is the division-by-zero trap, end to
// end.
func TestAnEmptyPoolDoesNotReportExhaustion(t *testing.T) {
	set := signals.NewSet(base,
		signals.Signal{Name: signals.NetInspectSupported, Source: signals.SourceNetwork,
			Value: signals.Bool(true), At: base},
		signals.Signal{Name: signals.DHCPPoolUtilisation, Source: signals.SourceDHCP,
			Value: signals.Number(0), At: base},
		signals.Signal{Name: signals.DHCPPoolCapacity, Source: signals.SourceDHCP,
			Value: signals.Number(0), At: base},
	)

	ev := rules.NewEvaluator(func() time.Time { return base })
	for i := 0; i < 3; i++ {
		firing, _ := ev.Evaluate(ruleset.All(), set)
		for _, f := range firing {
			if f.Rule == ruleset.PoolExhausted || f.Rule == ruleset.PoolNearlyFull {
				t.Errorf("%q fired with a zero-capacity pool; a gateway with DHCP "+
					"disabled is not running out of addresses", f.Rule)
			}
		}
	}
}

// TestThePipelineTurnsOneFaultIntoOneIncident is the end-to-end test of the
// whole design.
//
// A gateway that has lost its uplink produces several true conditions at once.
// The pipeline must turn them into one incident, with the consequences marked
// rather than reported. This is the arithmetic the four packages exist to fix.
func TestThePipelineTurnsOneFaultIntoOneIncident(t *testing.T) {
	now := base
	c := &stepClock{now: now}

	// A gateway whose uplink is down: present, not up, no default route, and
	// forwarding off. Every one of those is a real observation.
	set := signals.NewSet(now,
		sig(signals.NetInspectSupported, signals.Bool(true)),
		sig(signals.NetWANPresent, signals.Bool(true)),
		sig(signals.NetWANUp, signals.Bool(false)),
		sig(signals.NetLANPresent, signals.Bool(true)),
		sig(signals.NetLANUp, signals.Bool(true)),
		sig(signals.NetDefaultRoute, signals.Bool(false)),
		sig(signals.NetIPv4Forwarding, signals.Bool(false)),
	)

	ev := rules.NewEvaluator(c.Now)
	cor, err := correlation.New(ruleset.CorrelationConfig())
	if err != nil {
		t.Fatalf("building the correlator: %v", err)
	}
	mgr := incidents.NewManager(c.Now)

	// Run long enough for every grace period.
	var groups []correlation.Group
	for i := 0; i < 20; i++ {
		now = c.advance(30 * time.Second)
		firing, _ := ev.Evaluate(ruleset.All(), set)
		groups = append(groups, cor.Process(firing, now)...)
	}

	if len(groups) == 0 {
		t.Fatal("the pipeline produced no groups; the whole test proves nothing")
	}

	mgr.Apply(groups)
	all := mgr.All()
	if len(all) != 1 {
		names := make([]string, 0, len(all))
		for _, inc := range all {
			names = append(names, inc.Title)
		}
		t.Fatalf("incidents = %d, want 1: %v\nfour true conditions from one "+
			"underlying fault must be one incident", len(all), names)
	}

	inc := all[0]
	if inc.Severity != rules.SeverityCritical {
		t.Errorf("severity = %q, want critical", inc.Severity)
	}

	// Three conditions were true. The uplink being down causes the absent
	// default route, so the route is suppressed. The disabled forwarding
	// sysctl is deliberately NOT suppressed: it is an independent fault, and
	// hiding it behind the uplink means the operator discovers it only when
	// the uplink comes back.
	causes := map[string]bool{}
	for _, c := range inc.Causes {
		causes[c.Rule] = true
	}
	if !causes[ruleset.WANDown] {
		t.Error("the down uplink is not reported as a cause")
	}
	if !causes[ruleset.ForwardingOff] {
		t.Error("the disabled forwarding syscall was suppressed; it is an " +
			"independent fault and hiding it behind the uplink means the " +
			"operator finds it only when the uplink returns")
	}

	consequences := map[string]string{}
	for _, cons := range inc.Consequences {
		consequences[cons.Rule] = cons.SuppressedBy
	}
	if by, ok := consequences[ruleset.NoDefaultRoute]; !ok {
		t.Error("the absent default route was not suppressed; it is a " +
			"consequence of the down uplink, not a second fault")
	} else if by != ruleset.WANDown {
		t.Errorf("the absent default route was suppressed by %q, want %q", by, ruleset.WANDown)
	}

	// The consequences must be visible, marked, with a reason.
	if len(inc.Consequences) == 0 {
		t.Error("the consequences were discarded rather than kept; the record has " +
			"lost what else was true at the time")
	}
	for _, cons := range inc.Consequences {
		if !cons.Suppressed {
			t.Errorf("%s is listed as a consequence but is not marked suppressed", cons.Rule)
		}
		if cons.SuppressedBy == "" {
			t.Errorf("%s is a consequence with nothing saying why", cons.Rule)
		}
	}
}

// sig builds a known signal for the pipeline test.
func sig(name string, v signals.Value) signals.Signal {
	return signals.Signal{
		Name: name, Source: signals.SourceOf(name), Value: v, At: base,
		Detail: "pipeline fixture",
	}
}

// stepClock is a manually advanced clock.
type stepClock struct{ now time.Time }

func (c *stepClock) advance(d time.Duration) time.Time {
	c.now = c.now.Add(d)
	return c.now
}

func (c *stepClock) Now() time.Time { return c.now }

// readsSignal reports whether a rule's condition reads a named signal.
func readsSignal(r rules.Rule, name string) bool {
	for _, n := range r.Condition.Signals() {
		if n == name {
			return true
		}
	}
	return false
}
