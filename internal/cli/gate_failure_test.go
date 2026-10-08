package cli

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/planner"
	"github.com/VengeTH/THN-Gateway/internal/recovery"
)

// This file holds the failure and rollback phases of the gate.
//
// Together they cover the question the other phases cannot: when the gateway
// is in the wrong state, does THN notice, say what it would do about it, and
// say what it would take to get back?
//
// The bias throughout is towards reporting rather than acting. This build has
// no apply path, which is the correct posture for a remotely-managed
// unattended device — and a gate that quietly depended on an apply path would
// be the one place in the project capable of changing the host.

// TestGateFailureDetectsDrift is the failure phase's core property.
//
// A gateway whose host state has moved away from its configuration is the
// normal condition, not an exception: someone edited a file, a service
// restarted, an interface came up in a different order. The failure is a tool
// that does not notice.
func TestGateFailureDetectsDrift(t *testing.T) {
	// The host as it actually is: firewall down, shaping off, and the
	// forwarding sysctl not set. All three are things that happen.
	observed := diff.Observed{
		HostName:            "thn-gate",
		Supported:           true,
		WANName:             gateWANIface,
		WANPresent:          true,
		WANUp:               true,
		LANName:             gateLANIface,
		LANPresent:          true,
		LANUp:               true,
		LANAddresses:        []string{gateLANAddr},
		DefaultGateway:      gateUpstreamGW,
		HasDefaultRoute:     true,
		IPv4Forwarding:      false, // drifted
		IPv4ForwardingKnown: true,
		FirewallActive:      false, // drifted
		FirewallRuleCount:   0,
		QoSActive:           false, // drifted
		Resolvers:           []string{"1.1.1.1", "9.9.9.9"},
		ResolversKnown:      true,
	}

	want := desiredFor(desired.FromConfig(topologyConfig()))

	result := diff.Compare(observed, want)

	if result.Converged {
		t.Fatal("the host has drifted from its configuration but Compare reports it " +
			"as converged; a gateway that cannot tell the difference between its " +
			"intended and actual state cannot recover from anything")
	}
	if result.DriftCount == 0 {
		t.Fatal("no drift was reported despite three drifted fields")
	}

	// The drift must be attributed to the right subsystems, or an operator
	// cannot act on it. A drift report that says "something differs" is
	// useless on a device nobody can physically reach.
	subsystems := map[string]bool{}
	for _, c := range result.Changes {
		subsystems[c.Subsystem] = true
	}
	for _, wantSub := range []string{"sysctl", "nftables", "qdisc"} {
		if !subsystems[wantSub] {
			t.Errorf("drift in %q was not reported; subsystems found: %v",
				wantSub, keysOfBool(subsystems))
		}
	}

	if result.HighestRisk == diff.RiskNone {
		t.Error("three drifted fields produced a risk of none")
	}
}

// TestGateFailureDoesNotDriftWhenConverged is the negative control.
//
// Without it, a Compare that reported drift unconditionally would pass the
// test above while being useless in practice — and an operator would learn to
// ignore it.
func TestGateFailureDoesNotDriftWhenConverged(t *testing.T) {
	want := desiredFor(desired.FromConfig(topologyConfig()))

	// The host matching the configuration exactly.
	observed := diff.Observed{
		HostName:            "thn-gate",
		Supported:           true,
		WANName:             gateWANIface,
		WANPresent:          true,
		WANUp:               true,
		LANName:             gateLANIface,
		LANPresent:          true,
		LANUp:               true,
		LANAddresses:        []string{gateLANAddr},
		DefaultGateway:      gateUpstreamGW,
		HasDefaultRoute:     true,
		IPv4Forwarding:      true,
		IPv4ForwardingKnown: true,
		FirewallActive:      true,
		FirewallRuleCount:   12,
		QoSActive:           true,
		QoSAlgorithm:        "cake",
		Resolvers:           []string{"1.1.1.1", "9.9.9.9"},
		ResolversKnown:      true,
	}

	result := diff.Compare(observed, want)

	if !result.Converged {
		t.Errorf("a host matching its configuration reports %d changes: %v",
			len(result.Changes), result.Changes)
	}
}

// TestGateFailureIsPendingNotDriftedWhenUnsupported is the honest-degradation
// case.
//
// THN is developed against a gateway whose hardware is absent. On such a host
// nothing can be observed, and every change must be reported as pending rather
// than as drift — because "this is wrong" and "I cannot tell" are different
// claims, and a tool that conflates them produces confident nonsense.
func TestGateFailureIsPendingNotDriftedWhenUnsupported(t *testing.T) {
	observed := diff.Observed{
		HostName:  "thn-gate",
		Supported: false,
		WANName:   gateWANIface,
		WANUp:     true,
		// Everything else unknown: no observations were possible.
	}
	want := desiredFor(desired.FromConfig(topologyConfig()))

	result := diff.Compare(observed, want)

	if result.DriftCount != 0 {
		t.Errorf("drift = %d on a host that cannot be observed; unobservable state "+
			"must be pending, never drift", result.DriftCount)
	}
	if result.PendingCount == 0 {
		t.Error("nothing is pending on an unobservable host; the operator is given " +
			"no indication that the gateway has not been checked")
	}

	// Converged here means "no actionable change", not "verified correct". An
	// unobservable host has nothing actionable because nothing could be read,
	// and the report distinguishes the two cases separately. Asserting
	// Converged == false here would contradict the documented contract, and
	// more importantly would demand a claim the tool is right not to make: it
	// cannot know this host is correct.
	if !result.Converged {
		t.Errorf("converged = false with no drift and no blocked changes; an " +
			"unobservable host has nothing actionable, which is what Converged reports")
	}

	// The distinction that matters is preserved: nothing is claimed to be
	// wrong, and everything is claimed to be unverified.
	if result.HighestRisk == diff.RiskNone && result.PendingCount == 0 {
		t.Error("an unobservable host produced neither risk nor pending work")
	}
}

// TestGateFailurePlansRecoveryInOrder checks that a drift report becomes an
// ordered, reviewable plan rather than a list.
//
// The ordering matters. Enabling forwarding before a firewall exists opens the
// host; installing a firewall before addressing exists does nothing. A plan
// that lists the right steps in the wrong order is worse than no plan, because
// it looks authoritative.
func TestGateFailurePlansRecoveryInOrder(t *testing.T) {
	observed := diff.Observed{
		HostName:            "thn-gate",
		Supported:           true,
		WANName:             gateWANIface,
		WANPresent:          true,
		WANUp:               true,
		LANName:             gateLANIface,
		LANPresent:          true,
		LANUp:               true,
		LANAddresses:        []string{gateLANAddr},
		DefaultGateway:      gateUpstreamGW,
		HasDefaultRoute:     true,
		IPv4Forwarding:      false,
		IPv4ForwardingKnown: true,
		FirewallActive:      false,
		Resolvers:           []string{"1.1.1.1", "9.9.9.9"},
		ResolversKnown:      true,
	}
	want := desiredFor(desired.FromConfig(topologyConfig()))

	plan := planner.Build(diff.Compare(observed, want), planner.Options{
		Generation: 1,
		Source:     "gate",
		Live:       false,
		Now:        gateFixedTime,
	})

	if plan == nil {
		t.Fatal("planner.Build returned nil for a known-drifted host")
	}
	if len(plan.Steps) == 0 {
		t.Fatal("the plan has no steps; drift was detected but nothing would be done")
	}

	// The plan must be identified, so two runs can be compared.
	if plan.ID == "" {
		t.Error("the plan has no ID; two plans could not be told apart")
	}

	// Steps must be in ascending phase order. Applying them out of order is
	// how a plan becomes an outage.
	lastPhase := 0
	for i, step := range plan.Steps {
		if step.Phase < lastPhase {
			t.Errorf("step %d (%s) is in phase %d, after a step in phase %d; "+
				"the plan is out of order", i, step.Summary, step.Phase, lastPhase)
		}
		lastPhase = step.Phase
	}

	// A step with no reason is unactionable.
	for _, step := range plan.Steps {
		if step.Reason == "" {
			t.Errorf("step %q has no reason; an operator cannot tell why it is needed", step.Summary)
		}
	}

	// Enabling forwarding is a prerequisite, not a disruption. diff classifies
	// it as RiskMedium — "changes behaviour but not reachability" — because a
	// gateway with forwarding off simply routes nothing, and a client sees no
	// route rather than a lost session. Treating it as disruptive would flag
	// the one step every gateway needs, and train operators to ignore the
	// flag on the steps that matter.
	//
	// What must be marked disruptive is replacing a firewall: an over-broad
	// ruleset takes the device off the network entirely, and from a remote
	// session that is unrecoverable without console access.
	for _, step := range plan.Steps {
		if step.Subsystem == "nftables" && !step.Disruptive {
			t.Error("the firewall step is not marked disruptive; an over-broad ruleset " +
				"can take the device off the network with no way back from a remote session")
		}
		if step.Subsystem == "sysctl" && step.Disruptive {
			t.Error("the forwarding step is marked disruptive; diff classifies it as " +
				"RiskMedium because it changes behaviour, not reachability")
		}
	}
}

// TestGateFailurePlanIsDeterministic guards the property that makes a plan
// reviewable.
//
// A plan whose content hash changes between identical runs cannot be compared
// against a previous plan, which is the main thing an operator does with one.
func TestGateFailurePlanIsDeterministic(t *testing.T) {
	observed := diff.Observed{
		HostName: "thn-gate", Supported: true,
		WANName: gateWANIface, WANPresent: true, WANUp: true,
		LANName: gateLANIface, LANPresent: true, LANUp: true,
		LANAddresses:   []string{gateLANAddr},
		DefaultGateway: gateUpstreamGW, HasDefaultRoute: true,
		IPv4Forwarding: false, IPv4ForwardingKnown: true,
		FirewallActive: false, ResolversKnown: true,
	}
	want := desiredFor(desired.FromConfig(topologyConfig()))

	build := func() *planner.Plan {
		return planner.Build(diff.Compare(observed, want), planner.Options{
			Generation: 1, Source: "gate", Live: false, Now: gateFixedTime,
		})
	}

	first := build()
	if first == nil {
		t.Fatal("planner.Build returned nil")
	}

	for i := 0; i < 10; i++ {
		got := build()
		if got.ID != first.ID {
			t.Fatalf("plan ID changed between identical runs: %q then %q", first.ID, got.ID)
		}
		if len(got.Steps) != len(first.Steps) {
			t.Fatalf("step count varies: %d then %d", len(first.Steps), len(got.Steps))
		}
	}
}

// TestGateRollbackIsPlannedForAFailedActivation is the rollback phase's core
// property.
//
// The question is not "can this be undone" but "does THN say so before it
// starts". A gateway that changes its own addressing and then cannot report
// how to get back is worse than one that never changed it.
func TestGateRollbackIsPlannedForAFailedActivation(t *testing.T) {
	// Everything as it was before an activation that did not complete, with
	// no pre-existing ruleset to account for. This is the case where recovery
	// genuinely is clean, so a pessimistic verdict here would be wrong in the
	// other direction — an operator who is told recovery is impossible when
	// it is not will hesitate to fix a broken gateway.
	plan := recovery.Build(recovery.Input{
		TargetGeneration:       2,
		DesiredLANPrefix:       gateLANAddr,
		DesiredResolvers:       []string{"1.1.1.1", "9.9.9.9"},
		ObservedLANPrefix:      gateLANAddr,
		ObservedDefaultGateway: gateUpstreamGW,
		ObservedResolvers:      []string{"1.1.1.1", "9.9.9.9"},
		FirewallTablesPresent:  false,
		QoSPresent:             false,
	})

	if plan == nil {
		t.Fatal("recovery.Build returned nil")
	}
	if len(plan.Steps) == 0 {
		t.Fatal("the recovery plan has no steps; a failed activation would leave " +
			"nothing to restore from")
	}

	// A fully-recovered state is the best case, and it must be reported as
	// such rather than pessimistically.
	if plan.Verdict != recovery.VerdictRecoverable {
		t.Errorf("verdict = %q, want %q; nothing was lost and the plan says otherwise",
			plan.Verdict, recovery.VerdictRecoverable)
	}

	// Every step must name what it restores and whether it can be undone.
	for _, step := range plan.Steps {
		if step.Description == "" {
			t.Errorf("a recovery step has no description: %+v", step)
		}
		if step.Reversibility == "" {
			t.Errorf("step %q does not say whether it is reversible", step.Description)
		}
	}
}

// TestGateRollbackBlocksWhenAPriorRulesetExists is the assertion the previous
// test deliberately avoided.
//
// Replacing a ruleset cannot be undone from memory: the prior ruleset has to
// have been captured to a file first, and if it was not, the host may be left
// with no way back. On an unattended device that is unrecoverable without
// console access, so the plan must block rather than claim recoverability.
//
// A plan that reported "recoverable" here would be the most dangerous output
// in the project: it would tell a remote operator they had a way back when
// they did not.
func TestGateRollbackBlocksWhenAPriorRulesetExists(t *testing.T) {
	plan := recovery.Build(recovery.Input{
		TargetGeneration:       2,
		DesiredLANPrefix:       gateLANAddr,
		DesiredResolvers:       []string{"1.1.1.1"},
		ObservedLANPrefix:      gateLANAddr,
		ObservedDefaultGateway: gateUpstreamGW,
		ObservedResolvers:      []string{"1.1.1.1"},
		FirewallTablesPresent:  true, // a ruleset is already on the host
		QoSPresent:             true,
	})

	if plan == nil {
		t.Fatal("recovery.Build returned nil")
	}

	if plan.Verdict == recovery.VerdictRecoverable {
		t.Error("verdict = recoverable, but a pre-existing ruleset was not captured; " +
			"the plan would tell a remote operator they have a way back when they do not")
	}
	if len(plan.Blocking) == 0 {
		t.Error("an uncaptured prior ruleset produced no blocking finding")
	}

	// The blocking finding must be an error, not a warning. A warning is
	// something an operator can acknowledge and proceed past.
	var blockingErrors int
	for _, f := range plan.Blocking {
		if f.Severity == "error" {
			blockingErrors++
		}
		if f.Message == "" {
			t.Errorf("a blocking finding has no message: %+v", f)
		}
	}
	if blockingErrors == 0 {
		t.Error("the uncaptured ruleset is not blocking at error severity")
	}
}

// TestGateRollbackSaysWhenOperatorIsRequired is the case that matters most on
// an unattended device.
//
// Some recovery steps cannot be automated. A plan that claims full
// recoverability while containing a step that needs a human at the keyboard is
// worse than one that says so, because the operator will not be there to
// intervene and will not know they needed to be.
func TestGateRollbackSaysWhenOperatorIsRequired(t *testing.T) {
	// A gateway that lost its LAN addressing entirely and has no default
	// route: there is no network over which to reach the operator.
	plan := recovery.Build(recovery.Input{
		TargetGeneration:       2,
		DesiredLANPrefix:       "10.99.0.1/24", // a different LAN
		DesiredResolvers:       []string{"9.9.9.9"},
		ObservedLANPrefix:      "", // lost
		ObservedDefaultGateway: "", // lost
		ObservedResolvers:      nil,
		FirewallTablesPresent:  false,
		QoSPresent:             false,
	})

	if plan == nil {
		t.Fatal("recovery.Build returned nil")
	}

	if len(plan.Steps) == 0 {
		t.Fatal("no recovery steps for a gateway that has lost its addressing")
	}

	// Either some step needs an operator, or the verdict says so. What must
	// not happen is a clean bill of health.
	var needsOperator bool
	for _, step := range plan.Steps {
		if step.RequiresOperator {
			needsOperator = true
		}
	}

	if !needsOperator && plan.Verdict == recovery.VerdictRecoverable {
		t.Error("a gateway that has lost its LAN and default route is reported as " +
			"fully recoverable with no operator step; recovering it needs someone at " +
			"the keyboard")
	}
}

// TestGateRollbackClassifiesIrreversibleSteps pins the classification the
// verdict is derived from.
//
// A step that cannot be undone must be labelled as such at the point it is
// planned, not discovered afterwards. The label is what lets an operator
// decide whether to proceed.
func TestGateRollbackClassifiesIrreversibleSteps(t *testing.T) {
	plan := recovery.Build(recovery.Input{
		TargetGeneration:       2,
		DesiredLANPrefix:       "10.77.0.1/24",
		DesiredResolvers:       []string{"1.1.1.1"},
		ObservedLANPrefix:      "192.168.1.1/24", // the previous LAN
		ObservedDefaultGateway: gateUpstreamGW,
		ObservedResolvers:      []string{"8.8.8.8"},
		FirewallTablesPresent:  true,
		QoSPresent:             true,
	})

	known := map[recovery.Reversibility]bool{
		recovery.Reversible:          true,
		recovery.PartiallyReversible: true,
		recovery.Irreversible:        true,
	}

	for _, step := range plan.Steps {
		if !known[step.Reversibility] {
			t.Errorf("step %q has reversibility %q, which is not one of the three "+
				"defined values; an unrecognised label is indistinguishable from none",
				step.Description, step.Reversibility)
		}
	}
}

// TestGateActivationIsRefused is the phase that ties the other two together.
//
// Everything above describes a gateway that has drifted and how it would be
// put right. This asserts that, in this build, none of it happens by itself.
//
// The refusal must survive every obvious attempt to get around it, because the
// circumstances it protects against are exactly the ones where someone would
// try: a gateway that is already broken, a configuration that says to.
func TestGateActivationIsRefused(t *testing.T) {
	// A gateway that has drifted must not repair itself. An apply path
	// existing in the binary does not make that path reachable without
	// presence and authorization.
	assertActivationRemainsGated(t, "adding recovery modelling")

	// The applier that ships must refuse, not no-op. A no-op reports success
	// and the operator believes a change was made.
	disabled := activation.Disabled{}

	err := disabled.Apply(activation.Context{Generation: 1})
	if err == nil {
		t.Fatal("the disabled applier reported success; a change that did not happen " +
			"must never be reported as one that did")
	}
	if disabled.Available() {
		t.Error("the disabled applier reports itself as available")
	}

	// The gate must hold against configuration and flags, not just against a
	// bare invocation.
	_, path := loadTopology(t, topologyConfig())

	// No invocation may succeed. This is the contract, and it holds whether the
	// refusal happens at the flag parser or at the activation machine — both
	// are refusals, and both must be refusals.
	for _, args := range [][]string{
		{"activate"},
		{"activate", "--config", path},
		{"activate", "--config", path, "--force"},
		{"activate", "--config", path, "--yes"},
		{"activate", "--yes", "--confirm-present"},
		{"activate", "--config", path, "--json"},
	} {
		_, stderr, code := runGateCLI(t, args...)

		if code == ExitOK {
			t.Errorf("thn %s exited 0; activation must be refused",
				strings.Join(args, " "))
		}
		// Whatever the refusal, it must not claim a change was made.
		if strings.Contains(stderr, "activated") || strings.Contains(stderr, "applied") {
			t.Errorf("thn %s claimed a change was made:\n%s", strings.Join(args, " "), stderr)
		}
	}

	// For the invocations that parse, the refusal must be explicit about what
	// is missing. A bare "unknown flag" is a valid rejection but a poor one:
	// an operator who typed --config wants to know this build cannot activate,
	// not that they mistyped a flag.
	//
	// The refusal must name the gates AND the confirmations, because those are
	// different fixes: one is a missing cable, the other is a missing flag.
	for _, args := range [][]string{
		{"activate"},
		{"activate", "--yes"},
		{"activate", "--yes", "--confirm-present"},
	} {
		_, stderr, code := runGateCLI(t, args...)

		if code == ExitOK {
			t.Errorf("thn %s exited 0; activation must be refused",
				strings.Join(args, " "))
		}
		if !strings.Contains(stderr, "Blocking gates") {
			t.Errorf("thn %s did not name the blocking gates:\n%s",
				strings.Join(args, " "), stderr)
		}
		if !strings.Contains(stderr, "--confirm-present") {
			t.Errorf("thn %s did not say how physical presence is confirmed:\n%s",
				strings.Join(args, " "), stderr)
		}
	}
}

// TestGateActivationGatesAreNeverAllSatisfied is the structural half of the
// refusal.
//
// The apply path is gated, and one of those gates is permanently unsatisfiable
// in this build. If that ever changed, every guard would open at once — so it
// is asserted rather than assumed.
func TestGateActivationGatesAreNeverAllSatisfied(t *testing.T) {
	result := activation.Evaluate(activation.GateInput{
		PlanValidated: true,
		ConfigValid:   true,
		WAN:           activation.RoleGate{Role: "wan", Satisfied: true, Interface: "uplink0"},
		LAN:           activation.RoleGate{Role: "lan", Satisfied: true, Interface: "downlink0"},
		// Everything else at its best possible value.
	})

	if result.AllSatisfied {
		t.Error("every activation gate is satisfied; the apply path would be " +
			"unblocked in a build that has none")
	}
	if len(result.Gates) == 0 {
		t.Fatal("no gates were evaluated")
	}
	if len(result.Blocking) == 0 {
		t.Error("the gates report everything satisfied but name no blockers")
	}

	// The refusal must name which gate is blocking, or an operator is left
	// guessing whether to fix something.
	for _, g := range result.Gates {
		if g.Satisfied {
			continue
		}
		if g.Reason == "" {
			t.Errorf("unsatisfied gate %q gives no reason", g.Name)
		}
	}

	// The stages THN can perform must be a strict subset of the whole set.
	implemented := activation.ImplementedStages()
	unsupported := activation.UnsupportedStages()

	if len(implemented) == 0 {
		t.Error("no stages are implemented")
	}
	for _, s := range implemented {
		for _, u := range unsupported {
			if s == u {
				t.Errorf("stage %q is reported as both implemented and unsupported", s)
			}
		}
	}
	if len(implemented)+len(unsupported) == 0 {
		t.Error("the stage list is empty")
	}
}

// TestGateTimeIsFixed guards the gate's own determinism.
//
// Every timestamp-sensitive assertion in this gate uses gateFixedTime. If a
// future change reaches for time.Now instead, the gate starts passing or
// failing depending on the hour, and a gate that does that gets ignored.
func TestGateTimeIsFixed(t *testing.T) {
	if gateFixedTime.IsZero() {
		t.Error("gateFixedTime is the zero time")
	}
	if gateFixedTime.Location() != time.UTC {
		t.Errorf("gateFixedTime is in %s, want UTC; a local zone would make the "+
			"gate's timestamps depend on where it runs", gateFixedTime.Location())
	}

	// The topology timestamps are all relative to this instant, so a change
	// to it cannot leave one of them in the past.
	issued := gateFixedTime
	if issued.After(time.Now()) {
		t.Error("gateFixedTime is in the future; a lease issued then would be " +
			"born expired relative to a real clock")
	}
}

// keysOfBool renders a set for failure messages.
func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	return out
}
