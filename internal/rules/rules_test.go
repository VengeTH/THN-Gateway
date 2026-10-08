package rules_test

import (
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/rules"
	"github.com/VengeTH/THN-Gateway/internal/signals"
)

var base = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

// clock is a manually advanced clock.
//
// A test that slept would be slow and a test that used the real clock would be
// flaky. An alerting engine is exactly the code where a flaky test teaches
// people to ignore the suite, so the clock is advanced deliberately.
type clock struct{ now time.Time }

func newClock() *clock { return &clock{now: base} }

func (c *clock) advance(d time.Duration) time.Time {
	c.now = c.now.Add(d)
	return c.now
}

func (c *clock) Now() time.Time { return c.now }

// set builds a signal set at the clock's current time.
func (c *clock) set(sigs ...signals.Signal) *signals.Set {
	out := make([]signals.Signal, 0, len(sigs))
	for _, s := range sigs {
		s.At = c.now
		out = append(out, s)
	}
	return signals.NewSet(c.now, out...)
}

// boolSig is a known boolean signal.
func boolSig(name string, v bool) signals.Signal {
	return signals.Signal{Name: name, Source: sourceOf(name), Value: signals.Bool(v), At: base}
}

// numSig is a known numeric signal.
func numSig(name string, v float64) signals.Signal {
	return signals.Signal{Name: name, Source: sourceOf(name), Value: signals.Number(v), At: base}
}

func sourceOf(name string) string { return signals.SourceOf(name) }

// linkDownRule is a rule with a one-minute threshold, the shape most shipped
// rules take.
func linkDownRule() rules.Rule {
	return rules.Rule{
		Name:      "wan-down",
		Title:     "The uplink is down",
		Severity:  rules.SeverityCritical,
		For:       time.Minute,
		Condition: rules.All(rules.IsTrue("network.wan.present"), rules.IsFalse("network.wan.up")),
		Remedy:    "check the carrier",
	}
}

// downSet is an observation where the uplink is down.
//
// The sets are stamped from the clock rather than a fixed time. A fixed stamp
// would make every observation look simultaneous, and a duration threshold
// measures the distance between observations.
func downSet(c *clock) *signals.Set {
	return c.set(
		boolSig("network.wan.present", true),
		boolSig("network.wan.up", false),
	)
}

// upSet is an observation where the uplink is up.
func upSet(c *clock) *signals.Set {
	return c.set(
		boolSig("network.wan.present", true),
		boolSig("network.wan.up", true),
	)
}

// unreadableSet is an observation where the uplink's state cannot be read.
func unreadableSet(c *clock) *signals.Set {
	return c.set(
		boolSig("network.wan.present", true),
		signals.Signal{
			Name: "network.wan.up", Source: "network",
			Value: signals.Unknown(signals.KindBool), At: c.now,
		},
	)
}

// TestRuleFiresOnlyAfterItsDuration is the reason the duration exists.
//
// Without it, a link that flaps produces an incident per flap, and an operator
// who receives forty of them in an hour learns that the tool is noise.
func TestRuleFiresOnlyAfterItsDuration(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)
	rule := linkDownRule()

	// The condition holds.
	firing, _ := ev.Evaluate([]rules.Rule{rule}, downSet(c))
	if len(firing) != 0 {
		t.Fatalf("a rule fired immediately; it has a one-minute threshold")
	}

	// Still holding, still short of the threshold.
	c.advance(30 * time.Second)
	firing, _ = ev.Evaluate([]rules.Rule{rule}, downSet(c))
	if len(firing) != 0 {
		t.Fatalf("a rule fired after 30s with a 60s threshold")
	}
	if len(ev.Pending()) != 1 {
		t.Fatalf("pending = %d, want 1; a condition that holds but has not held "+
			"long enough is the early warning an operator most wants", len(ev.Pending()))
	}

	// Past the threshold.
	c.advance(31 * time.Second)
	firing, _ = ev.Evaluate([]rules.Rule{rule}, downSet(c))
	if len(firing) != 1 {
		t.Fatalf("a rule did not fire after 61s with a 60s threshold")
	}
}

// TestRuleFiresImmediatelyWithNoDuration: some conditions genuinely do not
// flap, and waiting for them would only delay the report.
func TestRuleFiresImmediatelyWithNoDuration(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)

	rule := rules.Rule{
		Name:      "config-invalid",
		Title:     "The configuration is not valid",
		Severity:  rules.SeverityCritical,
		Condition: rules.IsFalse("config.valid"),
	}

	set := signals.NewSet(c.now, boolSig("config.valid", false))

	firing, _ := ev.Evaluate([]rules.Rule{rule}, set)
	if len(firing) != 1 {
		t.Fatalf("a rule with no duration did not fire on its first evaluation")
	}
}

// TestPendingIsNotFiring is the distinction a duration threshold exists to
// make. A pending rule has not been reported, and anything that treats it as
// reported will page on a blip.
func TestPendingIsNotFiring(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)

	ev.Evaluate([]rules.Rule{linkDownRule()}, downSet(c))

	if len(ev.Firing()) != 0 {
		t.Error("a pending instance is reported as firing")
	}
	if len(ev.Pending()) != 1 {
		t.Error("the pending instance is not listed as pending")
	}
}

// TestRuleResolvesWhenTheConditionClears: an incident that never resolves is
// an incident nobody trusts.
func TestRuleResolvesWhenTheConditionClears(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)
	rule := linkDownRule()

	// Two evaluations are needed: the first starts the threshold, the second
	// is past it. A single evaluation cannot fire a rule with a duration,
	// because THN has not yet confirmed the condition is real.
	ev.Evaluate([]rules.Rule{rule}, downSet(c))
	c.advance(2 * time.Minute)
	if firing, _ := ev.Evaluate([]rules.Rule{rule}, downSet(c)); len(firing) != 1 {
		t.Fatal("the rule never fired, so the test proves nothing")
	}

	firing, transitions := ev.Evaluate([]rules.Rule{rule}, upSet(c))
	if len(firing) != 0 {
		t.Error("the rule is still firing after the uplink came back")
	}

	var resolved bool
	for _, tr := range transitions {
		if tr.To == rules.StateInactive {
			resolved = true
		}
	}
	if !resolved {
		t.Errorf("no transition to inactive was reported: %+v", transitions)
	}
}

// TestUnknownDoesNotFire is the single most important property in the package.
//
// A rule that fires on unreadable input turns a gateway THN cannot see into a
// gateway that is definitely broken, and sends an operator to fix something
// that is fine.
func TestUnknownDoesNotFire(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)

	rule := rules.Rule{
		Name:      "firewall-inactive",
		Title:     "The firewall is not running",
		Severity:  rules.SeverityCritical,
		Condition: rules.IsFalse("firewall.active"),
	}

	// The firewall state is unknown: the read failed.
	set := signals.NewSet(c.now, signals.Signal{
		Name: "firewall.active", Source: "firewall",
		Value: signals.Unknown(signals.KindBool), At: c.now,
	})

	firing, _ := ev.Evaluate([]rules.Rule{rule}, set)
	if len(firing) != 0 {
		t.Error("a rule fired on a signal that could not be read")
	}
	if len(ev.Undecidable()) != 1 {
		t.Errorf("undecidable = %d, want 1; an operator has to be able to see "+
			"which conditions THN could not evaluate", len(ev.Undecidable()))
	}
}

// TestUnknownDoesNotResolveAFiringRule is the harder half, and the one that
// would let a dead gateway look healthy.
//
// Losing sight of the input is not evidence of recovery. A rule that was
// firing and whose signal becomes unreadable must stay firing.
func TestUnknownDoesNotResolveAFiringRule(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)
	rule := linkDownRule()

	// Fire it. Two evaluations: the first starts the threshold.
	ev.Evaluate([]rules.Rule{rule}, downSet(c))
	c.advance(2 * time.Minute)
	if firing, _ := ev.Evaluate([]rules.Rule{rule}, downSet(c)); len(firing) != 1 {
		t.Fatal("the rule never fired, so the test proves nothing")
	}

	// Now the uplink becomes unreadable — the read failed.
	firing, transitions := ev.Evaluate([]rules.Rule{rule}, unreadableSet(c))

	if len(firing) != 1 {
		t.Error("a firing rule resolved because its signal became unreadable; " +
			"a gateway that has stopped answering would appear to have recovered")
	}
	for _, tr := range transitions {
		if tr.To == rules.StateInactive {
			t.Error("a transition to inactive was reported on unreadable input")
		}
	}
}

// TestUnknownDoesNotPromoteToFiring: a pending rule whose input vanishes must
// stay pending, not fire on the strength of an absence of evidence.
func TestUnknownDoesNotPromoteToFiring(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)
	rule := linkDownRule()

	ev.Evaluate([]rules.Rule{rule}, downSet(c)) // pending

	c.advance(2 * time.Minute)
	unreadable := signals.NewSet(c.now,
		boolSig("network.wan.present", true),
		signals.Signal{Name: "network.wan.up", Source: "network",
			Value: signals.Unknown(signals.KindBool), At: c.now},
	)

	firing, _ := ev.Evaluate([]rules.Rule{rule}, unreadable)
	if len(firing) != 0 {
		t.Error("a pending rule fired once its input became unreadable")
	}
}

// TestIsUnknownIsTheInverseRule is how a system watches for itself losing
// sight of the gateway — the failure that matters most on an unattended device.
func TestIsUnknownIsTheInverseRule(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)

	rule := rules.Rule{
		Name:      "wan-state-unobserved",
		Title:     "The uplink's state cannot be read",
		Severity:  rules.SeverityWarning,
		Condition: rules.IsUnknown("network.wan.up"),
	}

	// A readable, healthy uplink: the rule must stay silent.
	if firing, _ := ev.Evaluate([]rules.Rule{rule}, upSet(c)); len(firing) != 0 {
		t.Error("the unobserved rule fired on a readable interface")
	}

	// An unreadable one: it must fire.
	unreadable := signals.NewSet(c.now, signals.Signal{
		Name: "network.wan.up", Source: "network",
		Value: signals.Unknown(signals.KindBool), At: c.now,
	})
	if firing, _ := ev.Evaluate([]rules.Rule{rule}, unreadable); len(firing) != 1 {
		t.Error("the unobserved rule did not fire on an unreadable interface")
	}
}

// TestConditionReportsWhyItCouldNotBeDetermined is what makes a silent rule
// debuggable. A rule that simply does not fire, for reasons the operator
// cannot see, is indistinguishable from a rule that is working.
func TestConditionReportsWhyItCouldNotBeDetermined(t *testing.T) {
	set := signals.NewSet(base,
		boolSig("network.wan.up", false), // readable
		// dhcp.pool.utilisation is absent entirely.
	)

	cond := rules.AtOrAbove("dhcp.pool.utilisation", 0.9)

	if got := cond.Test(set); got != rules.TruthUnknown {
		t.Errorf("test = %v, want unknown for an absent signal", got)
	}

	reasons := cond.Conditions(set)
	if len(reasons) == 0 {
		t.Fatal("no reason was given; an operator cannot debug a rule that is " +
			"silent for invisible reasons")
	}
}

// TestAnyPropagatesUnknownOnlyWhenNothingIsEstablished is subtle and wrong
// the obvious way.
//
// "either the link is down or the gateway cannot see it" is true when the
// link is down, whatever the second operand says. It is unknown only when one
// holds and the other is unreadable, because then the unknown one might have
// been the true one.
func TestAnyPropagatesUnknownOnlyWhenNothingIsEstablished(t *testing.T) {
	cond := rules.Any(
		rules.IsFalse("network.wan.up"),
		rules.IsUnknown("network.wan.up"),
	)

	cases := []struct {
		name  string
		value signals.Value
		want  rules.Truth
	}{
		{"readable and false", signals.Bool(false), rules.TruthTrue},
		{"readable and true", signals.Bool(true), rules.TruthFalse},
		{"unreadable", signals.Unknown(signals.KindBool), rules.TruthTrue},
	}

	for _, c := range cases {
		set := signals.NewSet(base, signals.Signal{
			Name: "network.wan.up", Source: "network", Value: c.value, At: base,
		})
		if got := cond.Test(set); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAnyWithOneTrueAndOneUnknownIsTrue: something was established, so the
// disjunction holds. Collapsing this to unknown would make a real fault
// unreportable whenever an unrelated signal happened to be unreadable.
func TestAnyWithOneTrueAndOneUnknownIsTrue(t *testing.T) {
	set := signals.NewSet(base,
		signals.Signal{Name: "a", Source: "x", Value: signals.Bool(true), At: base},
		signals.Signal{Name: "b", Source: "y", Value: signals.Unknown(signals.KindBool), At: base},
	)

	cond := rules.Any(rules.IsTrue("a"), rules.IsFalse("b"))

	if got := cond.Test(set); got != rules.TruthTrue {
		t.Errorf("got %v, want true; one operand was established", got)
	}
}

// TestAllWithOneFalseAndOneUnknownIsFalse: a conjunction is settled by a false
// part regardless of what the others say.
func TestAllWithOneFalseAndOneUnknownIsFalse(t *testing.T) {
	set := signals.NewSet(base,
		signals.Signal{Name: "a", Source: "x", Value: signals.Bool(false), At: base},
		signals.Signal{Name: "b", Source: "y", Value: signals.Unknown(signals.KindBool), At: base},
	)

	cond := rules.All(rules.IsTrue("a"), rules.IsFalse("b"))

	if got := cond.Test(set); got != rules.TruthFalse {
		t.Errorf("got %v, want false; a false operand settles a conjunction", got)
	}
}

// TestNotPreservesUnknown: "the link is not down" is not established when THN
// could not read the link, and inverting to true would assert the opposite of
// what is known.
func TestNotPreservesUnknown(t *testing.T) {
	cond := rules.Not(rules.IsFalse("network.wan.up"))

	unreadable := signals.NewSet(base, signals.Signal{
		Name: "network.wan.up", Source: "network",
		Value: signals.Unknown(signals.KindBool), At: base,
	})

	if got := cond.Test(unreadable); got != rules.TruthUnknown {
		t.Errorf("got %v, want unknown; a negation of an unknown is unknown", got)
	}
}

// TestTypeMismatchIsUnknownNotFalse: a signal that was read but is the wrong
// type is a bug in a rule, and reporting it as "the condition did not hold"
// would hide the bug.
func TestTypeMismatchIsUnknownNotFalse(t *testing.T) {
	set := signals.NewSet(base, numSig("dhcp.pool.utilisation", 0.95))

	cond := rules.IsTrue("dhcp.pool.utilisation")

	if got := cond.Test(set); got != rules.TruthUnknown {
		t.Errorf("got %v, want unknown for a number tested as a boolean", got)
	}
}

// TestBoundaryIsExclusiveOnOneSide: Below and AtOrAbove must partition the
// numbers exactly. If they overlapped, a value at the threshold would fire
// both rules and correlation would have to merge two incidents that are one.
func TestBoundaryIsExclusiveOnOneSide(t *testing.T) {
	below := rules.Below("x", 0.5)
	above := rules.AtOrAbove("x", 0.5)

	for _, c := range []struct {
		value float64
		wantB rules.Truth
		wantA rules.Truth
	}{
		{0.49, rules.TruthTrue, rules.TruthFalse},
		{0.5, rules.TruthFalse, rules.TruthTrue}, // the boundary belongs to exactly one
		{0.51, rules.TruthFalse, rules.TruthTrue},
	} {
		set := signals.NewSet(base, numSig("x", c.value))
		if got := below.Test(set); got != c.wantB {
			t.Errorf("below(%v) = %v, want %v", c.value, got, c.wantB)
		}
		if got := above.Test(set); got != c.wantA {
			t.Errorf("atOrAbove(%v) = %v, want %v", c.value, got, c.wantA)
		}
	}
}

// TestBetweenIsInclusiveAtBothEnds: a drop ratio of exactly the threshold is
// the case the rule was written for, so both ends must be inside.
func TestBetweenIsInclusiveAtBothEnds(t *testing.T) {
	cond := rules.Between("x", 0.1, 0.2)

	for _, c := range []struct {
		value float64
		want  rules.Truth
	}{
		{0.09, rules.TruthFalse},
		{0.10, rules.TruthTrue},
		{0.15, rules.TruthTrue},
		{0.20, rules.TruthTrue},
		{0.21, rules.TruthFalse},
	} {
		set := signals.NewSet(base, numSig("x", c.value))
		if got := cond.Test(set); got != c.want {
			t.Errorf("between(%v) = %v, want %v", c.value, got, c.want)
		}
	}
}

// TestConditionDescribesItself is what makes `thn rules list` and an
// incident's explanation possible. A condition nobody can state is a rule
// nobody can trust.
func TestConditionDescribesItself(t *testing.T) {
	cases := []struct {
		cond rules.Condition
		want string
	}{
		{rules.IsTrue("a.b"), "a.b is true"},
		{rules.IsFalse("a.b"), "a.b is false"},
		{rules.IsUnknown("a.b"), "a.b could not be read"},
		{rules.Below("x", 0.5), "x is below 0.5"},
		{rules.AtOrAbove("x", 0.5), "x is at least 0.5"},
		{rules.Between("x", 0.1, 0.2), "x is between 0.1 and 0.2 inclusive"},
		{rules.Equals("x", "cake"), `x is "cake"`},
		{rules.Always(), "always"},
		{rules.Never(), "never"},
	}

	for _, c := range cases {
		if got := c.cond.Describe(); got != c.want {
			t.Errorf("describe = %q, want %q", got, c.want)
		}
	}
}

// TestNestedConditionsAreParenthesised: "a and b or c" reads as a different
// condition from "a and (b or c)", and a rule whose description is ambiguous
// is a rule whose firing cannot be predicted.
func TestNestedConditionsAreParenthesised(t *testing.T) {
	cond := rules.All(
		rules.IsTrue("a"),
		rules.Any(rules.IsFalse("b"), rules.IsUnknown("c")),
	)

	got := cond.Describe()

	if !contains(got, "(") {
		t.Errorf("describe = %q; a nested clause is not parenthesised, so the "+
			"description reads as a different condition", got)
	}
}

// TestConditionReportsItsSignals: a rule is checkable against a set that lacks
// what it needs, and that check needs the names.
func TestConditionReportsItsSignals(t *testing.T) {
	cond := rules.All(
		rules.IsTrue("b.signal"),
		rules.IsFalse("a.signal"),
		rules.IsTrue("b.signal"), // duplicate
	)

	got := cond.Signals()

	if len(got) != 2 {
		t.Fatalf("signals = %v, want two distinct names", got)
	}
	// Sorted, so two identically-built conditions report identically.
	if got[0] != "a.signal" || got[1] != "b.signal" {
		t.Errorf("signals = %v, want sorted [a.signal b.signal]", got)
	}
}

// TestSeverityMaxIsTheWorst: an incident containing one critical and four
// warnings is critical, and reporting it as a warning would bury the one that
// matters.
func TestSeverityMaxIsTheWorst(t *testing.T) {
	if got := rules.Max(rules.SeverityWarning, rules.SeverityCritical); got != rules.SeverityCritical {
		t.Errorf("max = %q, want critical", got)
	}
	if got := rules.Max(rules.SeverityCritical, rules.SeverityWarning); got != rules.SeverityCritical {
		t.Errorf("max = %q, want critical", got)
	}
	if got := rules.Max(rules.SeverityInfo, rules.SeverityInfo); got != rules.SeverityInfo {
		t.Errorf("max = %q, want info", got)
	}
}

// TestSeverityComparisons: AtLeast and WeakerThan are complements, and getting
// the boundary wrong in either direction corrupts every severity decision.
func TestSeverityComparisons(t *testing.T) {
	if !rules.SeverityCritical.AtLeast(rules.SeverityWarning) {
		t.Error("critical must be at least warning")
	}
	if !rules.SeverityWarning.AtLeast(rules.SeverityWarning) {
		t.Error("a severity must be at least itself; AtLeast is inclusive")
	}
	if rules.SeverityInfo.AtLeast(rules.SeverityCritical) {
		t.Error("info must not be at least critical")
	}

	if !rules.SeverityWarning.WeakerThan(rules.SeverityCritical) {
		t.Error("warning must be weaker than critical")
	}
	if rules.SeverityCritical.WeakerThan(rules.SeverityCritical) {
		t.Error("WeakerThan is strict; a severity is not weaker than itself")
	}
}

// TestRuleValidationRejectsUnusableRules: a rule without a name or a title
// produces an incident that says nothing.
func TestRuleValidationRejectsUnusableRules(t *testing.T) {
	cases := []struct {
		name string
		rule rules.Rule
	}{
		{"no name", rules.Rule{Title: "t", Severity: rules.SeverityInfo, Condition: rules.Always()}},
		{"no title", rules.Rule{Name: "n", Severity: rules.SeverityInfo, Condition: rules.Always()}},
		{"no condition", rules.Rule{Name: "n", Title: "t", Severity: rules.SeverityInfo}},
		{"bad severity", rules.Rule{Name: "n", Title: "t", Severity: "urgent", Condition: rules.Always()}},
		{"negative duration", rules.Rule{Name: "n", Title: "t", Severity: rules.SeverityInfo,
			For: -time.Second, Condition: rules.Always()}},
	}

	for _, c := range cases {
		if err := c.rule.Validate(); err == nil {
			t.Errorf("%s: a rule with %s validated", c.name, c.name)
		}
	}

	if err := linkDownRule().Validate(); err != nil {
		t.Errorf("a well-formed rule failed validation: %v", err)
	}
}

// TestRuleWithNoDurationStringCleanly is a small thing that would look wrong
// in every rule listing otherwise.
func TestRuleWithNoDurationStringCleanly(t *testing.T) {
	r := rules.Rule{
		Name: "config-invalid", Title: "t",
		Severity: rules.SeverityCritical, Condition: rules.IsFalse("config.valid"),
	}

	if got := r.String(); contains(got, "for at least") {
		t.Errorf("String = %q; a rule with no duration must not claim one", got)
	}
}

// TestEvaluateIsDeterministic: two runs over the same observations must
// produce the same firing set, or an operator comparing two reports of an
// unchanged gateway would see differences that are not there.
func TestEvaluateIsDeterministic(t *testing.T) {
	run := func() []rules.Instance {
		c := newClock()
		ev := rules.NewEvaluator(c.Now)
		ruleset := []rules.Rule{linkDownRule()}
		c.advance(2 * time.Minute)
		firing, _ := ev.Evaluate(ruleset, downSet(c))
		return firing
	}

	first := run()
	for i := 0; i < 20; i++ {
		got := run()
		if len(got) != len(first) {
			t.Fatalf("firing count varies: %d then %d", len(first), len(got))
		}
		for j := range got {
			if got[j].Rule != first[j].Rule {
				t.Fatalf("firing set varies: %v then %v", first, got)
			}
		}
	}
}

// TestEvaluatorClockGovernsNotTheObservation is a regression test for a
// design error.
//
// The evaluator used to take its notion of "now" from the observation's own
// timestamp. That is wrong: a timestamp is data, and a data value is not a
// clock. A collector that stamps every set with the same construction time
// froze every duration threshold, so a rule with a one-minute grace could
// never fire at all — and it failed silently, looking exactly like a healthy
// gateway.
//
// Replay is driven through the evaluator's clock instead, which is where a
// clock belongs.
func TestEvaluatorClockGovernsNotTheObservation(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)

	rule := rules.Rule{
		Name: "n", Title: "t", Severity: rules.SeverityInfo,
		For: time.Minute, Condition: rules.IsFalse("config.valid"),
	}

	// An observation stamped a long time ago, evaluated an hour later. The
	// evaluator's clock governs, so the rule behaves as if the observation
	// were current.
	stale := signals.NewSet(base, boolSig("config.valid", false))
	c.advance(time.Hour)

	if firing, _ := ev.Evaluate([]rules.Rule{rule}, stale); len(firing) != 0 {
		t.Error("a rule fired on its first evaluation with a one-minute threshold")
	}

	// A second observation, identically stamped, must be able to fire it. If
	// the set's timestamp governed, the elapsed time would be zero and this
	// would never fire however many times it was evaluated.
	stale2 := signals.NewSet(base, boolSig("config.valid", false))
	c.advance(61 * time.Second)

	if firing, _ := ev.Evaluate([]rules.Rule{rule}, stale2); len(firing) != 1 {
		t.Error("a rule whose observations are identically stamped can never " +
			"reach its threshold; the observation timestamp must not be the clock")
	}
}

// TestReplayThroughTheEvaluatorClock: the same recorded data, replayed, must
// produce the same states as if it had been live. This is the case the
// previous design was reaching for, done through the clock instead.
func TestReplayThroughTheEvaluatorClock(t *testing.T) {
	rule := rules.Rule{
		Name: "n", Title: "t", Severity: rules.SeverityInfo,
		For: time.Minute, Condition: rules.IsFalse("config.valid"),
	}

	c := newClock()
	ev := rules.NewEvaluator(c.Now)

	ev.Evaluate([]rules.Rule{rule}, c.set(boolSig("config.valid", false)))
	if len(ev.Firing()) != 0 {
		t.Fatal("fired immediately")
	}

	// Replay jumps the clock forward instead of sleeping.
	c.advance(61 * time.Second)
	if firing, _ := ev.Evaluate([]rules.Rule{rule}, c.set(boolSig("config.valid", false))); len(firing) != 1 {
		t.Error("a replayed evaluation did not fire; the clock is the only " +
			"thing that moves during a replay and it must be able to")
	}
}

// TestResetForgetsEverything: changing the rule set must not leave instances
// holding state for conditions that are no longer evaluated.
func TestResetForgetsEverything(t *testing.T) {
	c := newClock()
	ev := rules.NewEvaluator(c.Now)

	ev.Evaluate([]rules.Rule{linkDownRule()}, downSet(c))
	c.advance(2 * time.Minute)
	ev.Evaluate([]rules.Rule{linkDownRule()}, downSet(c))
	if len(ev.Firing()) != 1 {
		t.Fatal("the rule never fired, so the test proves nothing")
	}

	ev.Reset()

	if len(ev.Firing()) != 0 || len(ev.All()) != 0 {
		t.Errorf("state survived Reset: %v", ev.All())
	}
}

// contains is a substring test, named so the call sites read as prose.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
