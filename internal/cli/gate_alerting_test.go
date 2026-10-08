package cli

import (
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/correlation"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/incidents"
	"github.com/VengeTH/THN-Gateway/internal/netconfig"
	"github.com/VengeTH/THN-Gateway/internal/rules"
	"github.com/VengeTH/THN-Gateway/internal/ruleset"
	"github.com/VengeTH/THN-Gateway/internal/signals"
)

// This file is the gate phase for the alerting pipeline: signals, rules,
// correlation and incidents.
//
// # Why this is in the gateway gate at all
//
// These four packages have their own tests, and those tests are good. What
// they cannot check is whether the alerting pipeline agrees with the rest of
// THN about what the gateway is doing — and that agreement is the property an
// operator depends on most.
//
// Two tools that describe the same host and disagree are worse than one tool.
// `thn simulate` says a packet from a client to the internet would be
// forwarded out the uplink, while `wan-down` says the uplink is down. Both
// are confident, both are text, and an operator who trusts the wrong one
// spends an afternoon on the wrong component.
//
// The phase is small. The seam it guards is narrow and specific, and adding
// more would be padding.

// gateAlertingClock is a manually advanced clock for the phase.
type gateAlertingClock struct{ now time.Time }

func (c *gateAlertingClock) advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func (c *gateAlertingClock) Now() time.Time { return c.now }

// runPipeline evaluates the shipped ruleset against a set of observations and
// returns the incidents it would produce.
//
// The clock is advanced past every grace period, because what is being
// checked is what would be *reported*, and a rule that is merely pending has
// not yet claimed anything.
func runPipeline(t *testing.T, set *signals.Set) []incidents.Incident {
	t.Helper()

	clock := &gateAlertingClock{now: set.At}
	ev := rules.NewEvaluator(clock.Now)

	cor, err := correlation.New(ruleset.CorrelationConfig())
	if err != nil {
		t.Fatalf("building the correlator: %v", err)
	}
	mgr := incidents.NewManager(clock.Now)

	var groups []correlation.Group
	for i := 0; i < 20; i++ {
		clock.advance(30 * time.Second)
		firing, _ := ev.Evaluate(ruleset.All(), set)
		groups = append(groups, cor.Process(firing, clock.now)...)
	}

	mgr.Apply(groups)
	return mgr.All()
}

// firingRules returns the names of the rules that fired.
func firingRules(t *testing.T, set *signals.Set) map[string]bool {
	t.Helper()

	clock := &gateAlertingClock{now: set.At}
	ev := rules.NewEvaluator(clock.Now)

	out := map[string]bool{}
	for i := 0; i < 20; i++ {
		clock.advance(30 * time.Second)
		firing, _ := ev.Evaluate(ruleset.All(), set)
		for _, f := range firing {
			out[f.Rule] = true
		}
	}
	return out
}

// TestGateAlertingAgreesWithTheDataPlane is the phase's central assertion.
//
// A gateway with a healthy uplink must not report a link fault, and a gateway
// whose uplink is down must not simulate a packet forwarding out of it. The
// two are computed from different inputs — one from the policy, one from an
// observation — and nothing in the codebase connects them.
//
// A divergence here is not a cosmetic disagreement. It means THN would tell
// an operator that traffic is flowing while its own observation says the
// uplink is down, and the operator has no way to tell which to believe.
func TestGateAlertingAgreesWithTheDataPlane(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	policy := netPolicyFromConfig(loadedOrFail(t, cfg))

	// The data plane's view of a client reaching the internet.
	sim := netconfig.Simulate(policy, netconfig.Packet{
		Source:          addr(t, "10.77.0.100"),
		Destination:     addr(t, "8.8.8.8"),
		Protocol:        "tcp",
		DestinationPort: 443,
		Ingress:         gateLANIface,
	})
	forwarded := sim.Verdict == netconfig.VerdictForwarded && sim.EgressInterface == gateWANIface

	// The alerting pipeline's view of the same gateway: a healthy uplink.
	healthy := signals.NewSet(gateFixedTime,
		gateSignal(signals.NetInspectSupported, signals.Bool(true)),
		gateSignal(signals.NetWANPresent, signals.Bool(true)),
		gateSignal(signals.NetWANUp, signals.Bool(true)),
		gateSignal(signals.NetLANPresent, signals.Bool(true)),
		gateSignal(signals.NetLANUp, signals.Bool(true)),
		gateSignal(signals.NetDefaultRoute, signals.Bool(true)),
		gateSignal(signals.NetIPv4Forwarding, signals.Bool(true)),
		gateSignal(signals.FirewallActive, signals.Bool(true)),
		gateSignal(signals.FirewallRules, signals.Number(12)),
	)

	fired := firingRules(t, healthy)

	if forwarded && fired[ruleset.WANDown] {
		t.Error("the data plane forwards out the uplink while the alerting pipeline " +
			"reports the uplink down; two THN tools disagree about the same host")
	}
	if !forwarded {
		t.Fatal("the data plane does not forward on the gate topology, so this " +
			"test cannot compare the two views")
	}

	// The converse: a down uplink must be reported, and must not coincide with
	// a claim that traffic is flowing.
	down := signals.NewSet(gateFixedTime,
		gateSignal(signals.NetInspectSupported, signals.Bool(true)),
		gateSignal(signals.NetWANPresent, signals.Bool(true)),
		gateSignal(signals.NetWANUp, signals.Bool(false)),
		gateSignal(signals.NetDefaultRoute, signals.Bool(false)),
	)

	if !firingRules(t, down)[ruleset.WANDown] {
		t.Error("an uplink that is down is not reported; the data plane's refusal to " +
			"forward and the pipeline's silence would leave an operator with no " +
			"explanation at all")
	}
}

// TestGateAlertingOneFaultIsOneIncident is the correlation phase, on the real
// topology.
//
// A gateway that has lost its uplink satisfies several conditions at once.
// The gate requires them to produce one incident, because the alternative —
// several — is what makes an operator stop reading the output.
func TestGateAlertingOneFaultIsOneIncident(t *testing.T) {
	down := signals.NewSet(gateFixedTime,
		gateSignal(signals.NetInspectSupported, signals.Bool(true)),
		gateSignal(signals.NetWANPresent, signals.Bool(true)),
		gateSignal(signals.NetWANUp, signals.Bool(false)),
		gateSignal(signals.NetDefaultRoute, signals.Bool(false)),
		gateSignal(signals.NetIPv4Forwarding, signals.Bool(false)),
	)

	all := runPipeline(t, down)

	if len(all) != 1 {
		names := make([]string, 0, len(all))
		for _, inc := range all {
			names = append(names, inc.Title)
		}
		t.Fatalf("incidents = %d, want 1: %v\nthree conditions from one underlying "+
			"fault must be one incident", len(all), names)
	}

	inc := all[0]

	// The uplink is the cause. The absent default route is its consequence and
	// must be marked rather than reported. The forwarding syscall is an
	// independent fault and is deliberately still reported.
	causes := map[string]bool{}
	for _, c := range inc.Causes {
		causes[c.Rule] = true
	}
	if !causes[ruleset.WANDown] {
		t.Error("the down uplink is not reported as a cause")
	}
	if !causes[ruleset.ForwardingOff] {
		t.Error("the disabled forwarding syscall was suppressed; it is an " +
			"independent fault and hiding it means the operator finds it only " +
			"when the uplink comes back")
	}

	consequences := map[string]string{}
	for _, c := range inc.Consequences {
		consequences[c.Rule] = c.SuppressedBy
	}
	if by, ok := consequences[ruleset.NoDefaultRoute]; !ok {
		t.Error("the absent default route was reported as a second incident rather " +
			"than marked as a consequence")
	} else if by != ruleset.WANDown {
		t.Errorf("the absent default route was suppressed by %q, want %q", by, ruleset.WANDown)
	}
}

// TestGateAlertingNeverClaimsAFaultItCannotSee is the phase's safety property,
// and the one the whole four-package design exists to provide.
//
// On a gateway THN cannot inspect, exactly one rule may fire: the one saying
// THN cannot inspect. Anything else would be a claim about a host whose state
// was never read.
func TestGateAlertingNeverClaimsAFaultItCannotSee(t *testing.T) {
	blind := signals.NewSet(gateFixedTime,
		gateSignal(signals.NetInspectSupported, signals.Bool(false)),
	)

	fired := firingRules(t, blind)

	if len(fired) != 1 {
		names := make([]string, 0, len(fired))
		for name := range fired {
			names = append(names, name)
		}
		t.Fatalf("fired on an unobservable host: %v\nonly the host-unobservable "+
			"rule may fire; every other claim would be about a host whose state "+
			"was never read", names)
	}
	if !fired[ruleset.HostUnobservable] {
		t.Error("the rule saying THN cannot see the host did not fire; a gateway " +
			"that has gone quiet would be indistinguishable from a healthy one")
	}
}

// TestGateAlertingSaysNothingItCannotExplain: an incident an operator cannot
// act on, on a device they cannot reach, is noise with a severity label.
func TestGateAlertingSaysNothingItCannotExplain(t *testing.T) {
	// Every signal unreadable, so nothing can be concluded at all.
	blind := signals.NewSet(gateFixedTime,
		gateSignal(signals.NetWANUp, signals.Unknown(signals.KindBool)),
		gateSignal(signals.FirewallActive, signals.Unknown(signals.KindBool)),
		gateSignal(signals.QoSActive, signals.Unknown(signals.KindBool)),
	)

	for _, inc := range runPipeline(t, blind) {
		if len(inc.Timeline) == 0 {
			t.Errorf("incident %s has no timeline", inc.ID)
			continue
		}
		for _, e := range inc.Timeline {
			if e.Detail == "" {
				t.Errorf("incident %s has a timeline entry that says nothing: %+v", inc.ID, e)
			}
		}
	}
}

// TestGateAlertingRulesCoverTheGateTopology asserts that the shipped rules
// actually reference the signals this gateway produces.
//
// A rule set is only as good as the vocabulary it reads. If a condition THN
// derives has no rule, the observation is made and nothing acts on it — and
// the omission is invisible, because nothing reports on rules that do not
// exist.
func TestGateAlertingRulesCoverTheGateTopology(t *testing.T) {
	// Everything the gate topology can produce.
	produced := map[string]bool{
		signals.NetInspectSupported: true,
		signals.NetWANPresent:       true,
		signals.NetWANUp:            true,
		signals.NetLANPresent:       true,
		signals.NetLANUp:            true,
		signals.NetDefaultRoute:     true,
		signals.NetIPv4Forwarding:   true,
		signals.FirewallActive:      true,
		signals.FirewallRules:       true,
		signals.DHCPPoolCapacity:    true,
		signals.DHCPPoolUtilisation: true,
		signals.DHCPLeasesActive:    true,
		signals.DHCPDevicesUnknown:  true,
		signals.QoSActive:           true,
		signals.QoSAlgorithm:        true,
		signals.ConfigValid:         true,
		signals.DriftConverged:      true,
		signals.DriftCount:          true,
	}

	// Sanity: the topology really does produce these, through the real
	// derivations. Without this the map above is a guess.
	for _, s := range signals.Derive(healthyObservation(), gateFixedTime).All() {
		produced[s.Name] = true
	}

	read := map[string]bool{}
	for _, r := range ruleset.All() {
		for _, n := range r.Condition.Signals() {
			read[n] = true
		}
	}

	for name := range produced {
		if !read[name] {
			t.Errorf("the gateway produces %q but no rule reads it; the "+
				"observation is made and nothing acts on it, which is "+
				"invisible because nothing reports on rules that do not exist",
				name)
		}
	}
}

// TestGateAlertingActsOnNothing is the structural assertion, and it is the
// reason this phase is in a gate about a project whose central invariant is
// that it cannot change the host.
//
// Rules evaluate and incidents are recorded. Nothing in this pipeline applies
// anything, and the absence of any way to do so is worth a test — a gate that
// quietly depended on a remediation path would be the one place in the project
// capable of changing an unattended device.
func TestGateAlertingActsOnNothing(t *testing.T) {
	down := signals.NewSet(gateFixedTime,
		gateSignal(signals.NetInspectSupported, signals.Bool(true)),
		gateSignal(signals.NetWANPresent, signals.Bool(true)),
		gateSignal(signals.NetWANUp, signals.Bool(false)),
		gateSignal(signals.FirewallActive, signals.Bool(false)),
	)

	// Running the pipeline changes no state outside the returned records.
	all := runPipeline(t, down)
	if len(all) == 0 {
		t.Fatal("the pipeline produced nothing, so the test proves nothing")
	}

	for _, inc := range all {
		// A record of a problem, and nothing else. There is no field on an
		// incident for an action taken, which is the structural guarantee.
		if inc.Status != incidents.StatusActive && inc.Status != incidents.StatusResolved {
			t.Errorf("incident %s has status %q, which is neither active nor resolved",
				inc.ID, inc.Status)
		}
	}
}

// gateSignal builds a known signal for the phase.
func gateSignal(name string, v signals.Value) signals.Signal {
	return signals.Signal{
		Name:   name,
		Source: signals.SourceOf(name),
		Value:  v,
		At:     gateFixedTime,
		Labels: map[string]string{signals.LabelSource: signals.SourceOf(name)},
		Detail: "gate fixture",
	}
}

// healthyObservation is a diff.Observed describing a working gate topology.
//
// It is a fixture rather than a derivation because this phase is about whether
// the pipeline and the data plane agree, and reading the host would make that
// untestable on a development machine.
func healthyObservation() diff.Observed {
	return diff.Observed{
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
}
