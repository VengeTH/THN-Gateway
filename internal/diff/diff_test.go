package diff

import (
	"strings"
	"testing"
)

// host builds a plausible observed state: a WAN that is up and forwarding
// off, no LAN, no firewall, no QoS.
func host() Observed {
	return Observed{
		HostName:            "test-host",
		Supported:           true,
		WANName:             "enp0s31f6",
		WANPresent:          true,
		WANUp:               true,
		LANPresent:          false,
		HasDefaultRoute:     true,
		DefaultGateway:      "192.168.1.1",
		IPv4Forwarding:      false,
		IPv4ForwardingKnown: true,
		FirewallActive:      false,
		QoSActive:           false,
	}
}

// want builds a desired state matching host(), plus the arguments under test.
func want() Desired {
	return Desired{
		WANName:         "enp0s31f6",
		WANPresent:      true,
		WANUp:           true,
		LANName:         "enx0011",
		LANPresent:      true,
		LANUp:           true,
		LANAddresses:    []string{"10.77.0.1/24"},
		IPv4Forwarding:  true,
		FirewallEnabled: true,
		FirewallBackend: "nftables",
		FirewallPolicy:  "drop",
	}
}

// find returns the change with the given ID.
func find(t *testing.T, r Result, id string) Change {
	t.Helper()
	for _, c := range r.Changes {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("change %q not found in %d changes", id, len(r.Changes))
	return Change{}
}

func TestConvergedWhenEverythingMatches(t *testing.T) {
	o := host()
	o.LANPresent, o.LANName, o.LANAddresses, o.LANUp = true, "enx0011", []string{"10.77.0.1/24"}, true
	o.IPv4Forwarding = true
	o.FirewallActive, o.FirewallRuleCount = true, 12
	o.ResolversKnown, o.Resolvers = true, []string{"1.1.1.1", "9.9.9.9"}

	w := want()
	w.NATEnabled = false
	w.DNSPresent = false

	r := Compare(o, w)

	if !r.Converged {
		t.Errorf("expected convergence, got: %s", r.Summary())
	}
	for _, c := range r.Changes {
		t.Errorf("unexpected change: %s", c)
	}
}

// TestUnattachedInterfaceIsPendingNotDrift is the central invariant of this
// package. A LAN that is configured but not plugged in must never be reported
// as a change, because a planner that treats it as one would try to configure
// an interface that does not exist.
func TestUnattachedInterfaceIsPendingNotDrift(t *testing.T) {
	r := Compare(host(), want())

	c := find(t, r, "lan-not-attached")
	if c.Kind != KindPending {
		t.Errorf("kind = %q, want %q", c.Kind, KindPending)
	}
	if c.Risk != RiskNone {
		t.Errorf("risk = %q, want %q — a pending item must carry no risk", c.Risk, RiskNone)
	}

	// No item about the LAN may be drift: the interface is absent, so there
	// is nothing to reconcile. Drift elsewhere (forwarding, firewall) is
	// legitimate and is not what this test is about.
	for _, ch := range r.ByKind(KindDrift) {
		if strings.HasPrefix(ch.ID, "lan-") {
			t.Errorf("LAN item reported as drift: %s", ch)
		}
	}
}

func TestUnidentifiedInterfaceIsPending(t *testing.T) {
	w := want()
	w.LANPresent = false
	w.LANName = ""
	w.LANAddresses = nil

	r := Compare(host(), w)

	c := find(t, r, "lan-unidentified")
	if c.Kind != KindPending {
		t.Errorf("kind = %q, want %q", c.Kind, KindPending)
	}
	if c.Reason == "" {
		t.Error("a pending item must explain itself")
	}
}

func TestInterfaceNameMismatchIsBlocked(t *testing.T) {
	// The host has a NIC the configuration did not name. This is the case
	// where reconciling would reconfigure the wrong hardware, so it must be
	// blocked rather than drift.
	o := host()
	o.LANPresent, o.LANName = true, "eth9"

	r := Compare(o, want())

	c := find(t, r, "lan-name-mismatch")
	if c.Kind != KindBlocked {
		t.Errorf("kind = %q, want %q", c.Kind, KindBlocked)
	}
	if c.Risk != RiskCritical {
		t.Errorf("risk = %q, want %q", c.Risk, RiskCritical)
	}
	if r.Converged {
		t.Error("a blocked change must prevent convergence")
	}
}

func TestForwardingDriftIsDetected(t *testing.T) {
	r := Compare(host(), want())

	c := find(t, r, "ip-forwarding")
	if c.Kind != KindDrift {
		t.Errorf("kind = %q, want %q", c.Kind, KindDrift)
	}
	if c.Current != "disabled" || c.Desired != "enabled" {
		t.Errorf("current/desired = %q/%q, want disabled/enabled", c.Current, c.Desired)
	}
}

func TestUnreadableForwardingIsPending(t *testing.T) {
	o := host()
	o.IPv4ForwardingKnown = false

	r := Compare(o, want())

	c := find(t, r, "ip-forwarding-unknown")
	if c.Kind != KindPending {
		t.Errorf("kind = %q, want %q", c.Kind, KindPending)
	}
}

func TestMissingFirewallIsCriticalDrift(t *testing.T) {
	r := Compare(host(), want())

	c := find(t, r, "firewall-absent")
	if c.Kind != KindDrift {
		t.Errorf("kind = %q, want %q", c.Kind, KindDrift)
	}
	if c.Risk != RiskCritical {
		t.Errorf("risk = %q, want %q — an absent firewall is the riskiest change", c.Risk, RiskCritical)
	}
	if r.HighestRisk != RiskCritical {
		t.Errorf("HighestRisk = %q, want %q", r.HighestRisk, RiskCritical)
	}
}

func TestEmptyFirewallIsFlagged(t *testing.T) {
	// A table with no rules is worse than no table: the base policy applies
	// to everything with no accept path.
	o := host()
	o.FirewallActive, o.FirewallRuleCount = true, 0

	r := Compare(o, want())

	c := find(t, r, "firewall-empty")
	if c.Kind != KindDrift {
		t.Errorf("kind = %q, want %q", c.Kind, KindDrift)
	}
}

func TestAddressAddIsLowRiskAndRemoveIsHigh(t *testing.T) {
	o := host()
	o.LANPresent, o.LANName, o.LANAddresses = true, "enx0011", []string{"192.168.5.5/24"}

	r := Compare(o, want())

	add := find(t, r, "lan-address-add")
	if add.Risk != RiskLow {
		t.Errorf("adding an address is risk %q, want %q", add.Risk, RiskLow)
	}
	rem := find(t, r, "lan-address-remove")
	if rem.Risk != RiskHigh {
		t.Errorf("removing an address is risk %q, want %q", rem.Risk, RiskHigh)
	}
}

func TestWANAddressingIsNotManaged(t *testing.T) {
	// THN does not manage uplink addressing, so a WAN that is up but whose
	// addressing the configuration says nothing about must produce no change
	// at all. The WAN carries no address list in Observed precisely because
	// it is never rewritten.
	o := host()

	r := Compare(o, want())

	for _, c := range r.Changes {
		if strings.HasPrefix(c.ID, "wan-address") {
			t.Errorf("WAN addressing must not be diffed, got %s", c)
		}
	}
	if len(r.ByKind(KindDrift)) != 2 {
		// Only forwarding and the firewall should drift; the LAN is not
		// attached so it is pending, and the WAN matches.
		for _, c := range r.ByKind(KindDrift) {
			t.Logf("drift: %s", c.ID)
		}
		t.Errorf("expected exactly 2 drift items, got %d", len(r.ByKind(KindDrift)))
	}
}

func TestUnresolvableNATIsPending(t *testing.T) {
	w := want()
	w.NATEnabled, w.NATResolved = true, false

	r := Compare(host(), w)

	c := find(t, r, "nat-pending")
	if c.Kind != KindPending {
		t.Errorf("kind = %q, want %q", c.Kind, KindPending)
	}
}

func TestQoSUnresolvedIsPending(t *testing.T) {
	w := want()
	w.QoSEnabled, w.QoSResolved = true, false

	r := Compare(host(), w)

	c := find(t, r, "qos-pending")
	if c.Kind != KindPending {
		t.Errorf("kind = %q, want %q", c.Kind, KindPending)
	}
}

func TestQoSAlgorithmMismatchCarriesRates(t *testing.T) {
	// The desired value must carry everything a renderer needs, so that a
	// plan step never has to reach back into the desired state.
	o := host()
	o.QoSActive, o.QoSAlgorithm = true, "fq_codel"

	w := want()
	w.QoSEnabled, w.QoSResolved = true, true
	w.QoSAlgorithm, w.QoSInterface = "cake", "enp0s31f6"
	w.QoSDownloadKbps, w.QoSUploadKbps = 100000, 20000

	r := Compare(o, w)

	c := find(t, r, "qos-algorithm")
	for _, want := range []string{"cake", "enp0s31f6", "down=100000", "up=20000"} {
		if !strings.Contains(c.Desired, want) {
			t.Errorf("Desired %q is missing %q", c.Desired, want)
		}
	}
}

func TestUnknownResolversArePending(t *testing.T) {
	w := want()
	w.DNSPresent, w.DNSServers = true, []string{"1.1.1.1"}

	r := Compare(host(), w)

	c := find(t, r, "resolvers-unknown")
	if c.Kind != KindPending {
		t.Errorf("kind = %q, want %q", c.Kind, KindPending)
	}
}

func TestResolverDriftIsDetected(t *testing.T) {
	o := host()
	o.ResolversKnown, o.Resolvers = true, []string{"9.9.9.9"}

	w := want()
	w.DNSPresent, w.DNSServers = true, []string{"1.1.1.1"}

	r := Compare(o, w)

	c := find(t, r, "resolvers")
	if c.Kind != KindDrift {
		t.Errorf("kind = %q, want %q", c.Kind, KindDrift)
	}
}

func TestResolverOrderDoesNotMatter(t *testing.T) {
	o := host()
	o.ResolversKnown, o.Resolvers = true, []string{"9.9.9.9", "1.1.1.1"}

	w := want()
	w.DNSPresent, w.DNSServers = true, []string{"1.1.1.1", "9.9.9.9"}

	r := Compare(o, w)

	for _, c := range r.Changes {
		if c.ID == "resolvers" {
			t.Error("resolver order must not be treated as drift")
		}
	}
}

func TestUnsupportedPlatformMakesServicesPending(t *testing.T) {
	o := host()
	o.Supported = false

	r := Compare(o, want())

	if len(r.ByKind(KindPending)) == 0 {
		t.Error("an unobservable host must produce pending items, not silent success")
	}
	if len(r.ByKind(KindDrift)) != 0 {
		t.Error("an unobservable host must not report drift — nothing was observed")
	}
}

func TestBlockedSortedFirstAndRiskiest(t *testing.T) {
	o := host()
	o.LANPresent, o.LANName = true, "eth9" // forces a blocked critical change

	r := Compare(o, want())

	if len(r.Changes) == 0 {
		t.Fatal("expected changes")
	}
	if r.Changes[0].Kind != KindBlocked {
		t.Errorf("first change kind = %q, want blocked", r.Changes[0].Kind)
	}
	if got := r.Riskiest(); got == nil || got.Kind != KindBlocked {
		t.Errorf("Riskiest = %+v, want the blocked change", got)
	}
}

func TestPendingDoesNotPreventConvergence(t *testing.T) {
	// Pending means "not yet asked", not "wrong". A host that matches
	// everything except a subsystem nobody has configured is converged.
	o := host()
	o.LANPresent, o.LANName, o.LANAddresses, o.LANUp = true, "enx0011", []string{"10.77.0.1/24"}, true
	o.IPv4Forwarding = true
	o.FirewallActive, o.FirewallRuleCount = true, 12

	w := want()
	w.NATEnabled = true // unresolved -> pending

	r := Compare(o, w)

	if r.PendingCount == 0 {
		t.Fatal("expected a pending item")
	}
	if !r.Converged {
		t.Errorf("pending items must not block convergence: %s", r.Summary())
	}
}

func TestCompareIsDeterministic(t *testing.T) {
	// The same inputs must always produce the same ordering, or two plans
	// could not be compared.
	first := Compare(host(), want())
	for i := 0; i < 5; i++ {
		next := Compare(host(), want())
		if len(next.Changes) != len(first.Changes) {
			t.Fatalf("change count varies between runs")
		}
		for j := range next.Changes {
			if next.Changes[j].ID != first.Changes[j].ID {
				t.Fatalf("ordering varies: position %d is %q then %q",
					j, first.Changes[j].ID, next.Changes[j].ID)
			}
		}
	}
}

func TestSummaryMentionsBlocked(t *testing.T) {
	o := host()
	o.LANPresent, o.LANName = true, "eth9"

	r := Compare(o, want())

	if got := r.Summary(); !strings.Contains(got, "blocked") {
		t.Errorf("summary %q should mention blocked changes", got)
	}
}

func TestEmptyResultIsConverged(t *testing.T) {
	// A desired state that asks for nothing must converge without findings.
	r := Compare(host(), Desired{})

	if !r.Converged {
		t.Error("an empty desired state should be converged")
	}
}
