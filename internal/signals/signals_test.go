package signals_test

import (
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/dhcp"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/identity"
	"github.com/VengeTH/THN-Gateway/internal/signals"
)

var at = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

// sig is a shorthand for building a known signal.
func sig(name, source string, v signals.Value) signals.Signal {
	return signals.Signal{Name: name, Source: source, Value: v, At: at, Detail: "test"}
}

// TestValueKnownIsIndependentOfTheValueItHolds is the property everything else
// rests on.
//
// A false boolean and an unreadable boolean have the same payload. Without the
// Known flag they would be indistinguishable, and every rule above would have
// to rediscover the difference on its own.
func TestValueKnownIsIndependentOfTheValueItHolds(t *testing.T) {
	unknownFalse := signals.Unknown(signals.KindBool)
	realFalse := signals.Bool(false)

	// The payloads match, which is exactly the hazard. What separates them is
	// the Known flag, and that is the only thing a rule may consult.
	if unknownFalse.Bool != realFalse.Bool {
		t.Error("the payloads differ, which would have hidden the hazard this " +
			"test exists to document")
	}
	if unknownFalse.Known {
		t.Error("an unknown value reports itself known")
	}
	if !realFalse.Known {
		t.Error("a constructed false value reports itself unknown")
	}
	if unknownFalse.String() != "unknown" {
		t.Errorf("unknown renders as %q, want %q", unknownFalse.String(), "unknown")
	}
	if realFalse.String() != "false" {
		t.Errorf("false renders as %q, want %q", realFalse.String(), "false")
	}
}

// TestAbsentSignalIsUnknownNotFalse is the case that would otherwise make a
// failed observation look like a healthy gateway.
func TestAbsentSignalIsUnknownNotFalse(t *testing.T) {
	set := signals.NewSet(at, sig("network.wan.up", "network", signals.Bool(true)))

	got := set.Value("network.lan.up")
	if got.Known {
		t.Error("a signal that was never emitted is reported as known")
	}
	if got.Bool {
		t.Error("an absent signal reads as true")
	}
}

// TestSetIgnoresDuplicateNames: two signals with one name would make the
// result depend on read order, and the collector's order is not something a
// rule author can see.
func TestSetIgnoresDuplicateNames(t *testing.T) {
	set := signals.NewSet(at,
		sig("dup", "a", signals.Bool(true)),
		sig("dup", "b", signals.Bool(false)),
	)

	if set.Len() != 1 {
		t.Fatalf("len = %d, want 1", set.Len())
	}
	got, ok := set.Get("dup")
	if !ok {
		t.Fatal("the signal is missing entirely")
	}
	if got.Source != "a" {
		t.Errorf("kept source %q, want the first; the first wins so the result does "+
			"not depend on map iteration", got.Source)
	}
}

// TestSetPreservesInsertionOrder: the order reflects the sequence reads
// happened in, and display output should reflect that.
func TestSetPreservesInsertionOrder(t *testing.T) {
	set := signals.NewSet(at,
		sig("z.one", "z", signals.Bool(true)),
		sig("a.two", "a", signals.Bool(true)),
	)

	names := set.Names()
	if len(names) != 2 || names[0] != "z.one" || names[1] != "a.two" {
		t.Errorf("names = %v, want insertion order [z.one a.two]", names)
	}
}

// TestSetIsImmutableAfterConstruction: rules read a set while a collector may
// be building the next one, so a mutable set would be a data race.
func TestSetIsImmutableAfterConstruction(t *testing.T) {
	build := func() *signals.Set {
		return signals.NewSet(at,
			sig("one", "a", signals.Bool(true)),
			sig("two", "a", signals.Bool(false)),
		)
	}

	a := build()
	before := a.Len()

	_ = build()

	if a.Len() != before {
		t.Error("building a new set changed an existing one")
	}
}

// TestNilSetIsSafe: a collector that failed may hand over nothing, and the
// accessors must not panic on it.
func TestNilSetIsSafe(t *testing.T) {
	var set *signals.Set

	if _, ok := set.Get("anything"); ok {
		t.Error("a nil set returned a signal")
	}
	if set.Value("anything").Known {
		t.Error("a nil set returned a known value")
	}
	if set.Len() != 0 || set.All() != nil || set.Names() != nil || set.Unknown() != nil {
		t.Error("a nil set returned non-empty collections")
	}
}

// TestLabelFingerprintIsOrderIndependent: two signals with the same labels in a
// different insertion order must produce the same fingerprint, or correlation
// would treat them as different groups.
func TestLabelFingerprintIsOrderIndependent(t *testing.T) {
	a := signals.Signal{Labels: map[string]string{"iface": "eth0", "role": "wan"}}
	b := signals.Signal{Labels: map[string]string{"role": "wan", "iface": "eth0"}}

	if a.LabelFingerprint() != b.LabelFingerprint() {
		t.Errorf("fingerprints differ: %q vs %q", a.LabelFingerprint(), b.LabelFingerprint())
	}
}

// TestLabelFingerprintDistinguishesDifferentLabels: the whole value of a
// fingerprint is that two different label sets cannot produce the same one.
func TestLabelFingerprintDistinguishesDifferentLabels(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]string
	}{
		{"different values", map[string]string{"i": "eth0"}, map[string]string{"i": "eth1"}},
		{"different keys", map[string]string{"i": "eth0"}, map[string]string{"j": "eth0"}},
		{"one is a subset", map[string]string{"i": "eth0"}, map[string]string{"i": "eth0", "r": "wan"}},
		{"swapped keys", map[string]string{"i": "a", "r": "b"}, map[string]string{"i": "b", "r": "a"}},
	}

	for _, c := range cases {
		a := signals.Signal{Labels: c.a}
		b := signals.Signal{Labels: c.b}

		// The subset case legitimately produces a different fingerprint; the
		// swapped-keys case must too, because they are different label sets.
		if a.LabelFingerprint() == b.LabelFingerprint() {
			t.Errorf("%s: two different label sets produced the same fingerprint %q",
				c.name, a.LabelFingerprint())
		}
	}
}

// TestLabelFingerprintEscapesSeparators: a hostname containing a comma could
// otherwise forge a label boundary and impersonate another device's labels.
func TestLabelFingerprintEscapesSeparators(t *testing.T) {
	honest := signals.Signal{Labels: map[string]string{"a": "one", "b": "two"}}
	forged := signals.Signal{Labels: map[string]string{"a": "one,b=two"}}

	if honest.LabelFingerprint() == forged.LabelFingerprint() {
		t.Errorf("a comma in a label value forged the same fingerprint as two labels: %q",
			forged.LabelFingerprint())
	}
}

// TestDeriveOnAnUnobservableHostReportsUnknown is the single most important
// derivation test.
//
// A gateway that cannot be inspected has reported nothing. Reporting "the WAN
// is down" would be inventing a fault, and reporting "the WAN is up" would be
// inventing health. Both would be wrong, and the first is the one that costs
// an operator an afternoon.
func TestDeriveOnAnUnobservableHostReportsUnknown(t *testing.T) {
	obs := diff.Observed{
		HostName:  "thn",
		Supported: false,
		WANName:   "eth0",
		WANUp:     false,
		// Everything else at its worst, as a partially-failed observation
		// might be. None of it should be believed.
		FirewallActive:  false,
		QoSActive:       false,
		HasDefaultRoute: false,
		IPv4Forwarding:  false,
	}

	set := signals.Derive(obs, at)

	for _, name := range []string{
		signals.NetWANUp, signals.NetLANUp,
		signals.NetDefaultRoute, signals.NetIPv4Forwarding,
		signals.FirewallActive, signals.QoSActive,
	} {
		v := set.Value(name)
		if v.Known {
			t.Errorf("%s is known (%v) on a host that could not be inspected", name, v)
		}
	}

	// Except the one signal that records the failure itself, which is known.
	if v := set.Value(signals.NetInspectSupported); !v.Known || v.Bool {
		t.Errorf("network.inspect.supported = %v, want a known false", v)
	}
}

// TestDeriveOnAFailedForwardingRead: diff.Observed carries a separate "known"
// flag for the forwarding sysctl, and conflating the two would report a
// disabled gateway on a host THN simply could not read.
func TestDeriveOnAFailedForwardingRead(t *testing.T) {
	obs := diff.Observed{
		Supported: true, WANName: "eth0", WANPresent: true, WANUp: true,
		IPv4Forwarding:      false,
		IPv4ForwardingKnown: false, // the read failed
	}

	set := signals.Derive(obs, at)

	if v := set.Value(signals.NetIPv4Forwarding); v.Known {
		t.Errorf("forwarding = %v, want unknown when the read failed", v)
	}
}

// TestDeriveOnAReadForwardingSysctl is the negative case: the same policy with
// a successful read must report the real value.
func TestDeriveOnAReadForwardingSysctl(t *testing.T) {
	obs := diff.Observed{
		Supported: true, WANName: "eth0", WANPresent: true, WANUp: true,
		IPv4Forwarding:      false,
		IPv4ForwardingKnown: true,
	}

	set := signals.Derive(obs, at)

	v := set.Value(signals.NetIPv4Forwarding)
	if !v.Known || v.Bool {
		t.Errorf("forwarding = %v, want a known false", v)
	}
	if !detailContains(t, set, signals.NetIPv4Forwarding, "not forwarding") {
		t.Error("the signal does not explain what a disabled forwarding sysctl means")
	}
}

// TestDeriveLeavesUnobservedSubsystemsUnknown: diff.Observed carries no
// firewall or shaping state, so those signals must be unknown rather than
// guessed.
func TestDeriveLeavesUnobservedSubsystemsUnknown(t *testing.T) {
	set := signals.Derive(diff.Observed{Supported: true, WANName: "eth0"}, at)

	for _, name := range []string{
		signals.FirewallActive, signals.FirewallRules,
		signals.QoSActive, signals.QoSAlgorithm,
	} {
		if v := set.Value(name); v.Known {
			t.Errorf("%s = %v, want unknown; diff.Observed carries no such "+
				"observation and guessing would invent one", name, v)
		}
	}
}

// TestEverySignalCarriesAnExplanation: THN is read from a distance, so the
// detail is the only thing an operator has.
func TestEverySignalCarriesAnExplanation(t *testing.T) {
	obs := diff.Observed{
		Supported: true, WANName: "eth0", WANPresent: true, WANUp: false,
		LANName: "eth1", LANPresent: true, LANUp: true,
		HasDefaultRoute: true, IPv4Forwarding: true, IPv4ForwardingKnown: true,
	}

	set := signals.Derive(obs, at)

	for _, s := range set.All() {
		if s.Detail == "" {
			t.Errorf("signal %q carries no explanation", s.Name)
		}
		if s.At.IsZero() {
			t.Errorf("signal %q carries no timestamp", s.Name)
		}
		if s.Source == "" {
			t.Errorf("signal %q carries no source", s.Name)
		}
	}
}

// TestDeriveDHCPReportsAnEmptyPoolAsZeroNotHundredPercent is a real trap.
//
// Utilisation against a capacity of zero divides by zero, and the two ways of
// handling it are "100% full" and "unknown". The first is catastrophic: every
// gateway with DHCP disabled would report an exhausted pool.
func TestDeriveDHCPReportsAnEmptyPoolAsZeroNotHundredPercent(t *testing.T) {
	got := signals.DeriveDHCP(dhcp.Summary{
		Total: 0, PoolCapacity: 0, AddressesInUse: 0,
	}, at, at)

	for _, s := range got {
		if s.Name != signals.DHCPPoolUtilisation {
			continue
		}
		if !s.Value.Known {
			t.Fatal("utilisation is unknown; a rule guarding it would silently " +
				"never fire on a gateway with no pool")
		}
		if s.Value.Number != 0 {
			t.Errorf("utilisation = %v, want 0 for an empty pool", s.Value.Number)
		}
		return
	}
	t.Fatal("no utilisation signal was produced")
}

// TestDeriveDHCPUsesTheSuppliedUtilisationRatherThanRecomputing: the caller
// already computed it, and recomputing from addresses-in-use and capacity
// would give a different answer wherever the two disagree.
func TestDeriveDHCPUsesTheSuppliedUtilisationRatherThanRecomputing(t *testing.T) {
	sum := dhcp.Summary{
		PoolCapacity: 150, AddressesInUse: 100,
		PoolUtilisation: 0.42, // deliberately not 100/150
	}

	for _, s := range signals.DeriveDHCP(sum, at, at) {
		if s.Name == signals.DHCPPoolUtilisation {
			if s.Value.Number != 0.42 {
				t.Errorf("utilisation = %v, want the caller's 0.42", s.Value.Number)
			}
			return
		}
	}
	t.Fatal("no utilisation signal was produced")
}

// TestDeriveDHCPFlagsAFutureCollectionRatherThanANegativeAge: a collection
// stamped in the future means the clock is wrong, and reporting a negative age
// would let a rule compute a negative rate.
func TestDeriveDHCPFlagsAFutureCollectionRatherThanANegativeAge(t *testing.T) {
	future := at.Add(time.Hour)

	for _, s := range signals.DeriveDHCP(dhcp.Summary{}, future, at) {
		if s.Name != signals.DHCPLastCollectedAge {
			continue
		}
		if s.Value.Number < 0 {
			t.Errorf("age = %v, want the negative clamped to something reportable", s.Value.Number)
		}
		if !contains(s.Detail, "clock") {
			t.Errorf("detail %q does not mention the clock being wrong", s.Detail)
		}
		return
	}
	t.Fatal("no age signal was produced")
}

// TestDeriveQoSDistinguishesAnAbsentQdiscFromAnUnshapedOne is the important
// negative observation.
//
// Both mean "not shaping", but they mean different things to an operator: one
// is a misconfiguration, the other is the kernel's default. A gateway with no
// qdisc has not been set up; one with pfifo_fast has been set up wrong.
func TestDeriveQoSDistinguishesAnAbsentQdiscFromAnUnshapedOne(t *testing.T) {
	absent := signals.DeriveQoS(qostcAbsent(), at)
	unshaped := signals.DeriveQoS(qostcDefaultQueue(), at)

	for _, s := range absent {
		if s.Name == signals.QoSActive {
			if !s.Value.Known || s.Value.Bool {
				t.Errorf("absent qdisc: active = %v, want a known false", s.Value)
			}
			if !contains(s.Detail, "no root queue discipline") {
				t.Errorf("absent qdisc: detail %q does not say the qdisc is absent", s.Detail)
			}
		}
	}

	for _, s := range unshaped {
		if s.Name == signals.QoSActive {
			if !s.Value.Known || s.Value.Bool {
				t.Errorf("pfifo_fast: active = %v, want a known false", s.Value)
			}
			if !contains(s.Detail, "kernel default") {
				t.Errorf("pfifo_fast: detail %q does not identify the default queue", s.Detail)
			}
		}
	}
}

// TestDeriveQoSReportsTheKernelRate: a shaper reporting no rate looks exactly
// like one that was never configured.
func TestDeriveQoSReportsTheKernelRate(t *testing.T) {
	for _, s := range signals.DeriveQoS(qostcCake(), at) {
		if s.Name == signals.QoSAlgorithm {
			if s.Value.Str != "cake" {
				t.Errorf("algorithm = %q, want cake", s.Value.Str)
			}
		}
		if s.Name == signals.QoSDropRatio {
			if !s.Value.Known {
				t.Error("drop ratio is unknown for a qdisc that reported drops")
			}
		}
	}
}

// TestDeriveDevicesCountsThreeDifferentQuestions: collapsing "how many
// devices", "how many are uncertain" and "how many have gone quiet" into one
// number answers none of them.
//
// The weak-identity count is asserted as zero, and that is a real property of
// identity rather than an accident of the fixture. identity.Observe rejects
// an observation with no MAC address, on the grounds that an address is never
// an identity — so a device can only ever reach the registry with a MAC, and
// ConfidenceWeak ("hostname alone") is unreachable through it. The count is
// kept because a future identification source could reach that bucket, and
// because a rule watching for weakly-identified hardware should not have to be
// added and wired at the same time as the source that produces them.
func TestDeriveDevicesCountsThreeDifferentQuestions(t *testing.T) {
	reg := identity.NewRegistry()

	// Observe returns (device, wasKnown). The second value is whether the
	// device was already present, not whether the observation succeeded, so
	// it is not used as a success flag here.
	for _, mac := range []string{
		"aa:bb:cc:dd:ee:01",
		"aa:bb:cc:dd:ee:02",
		"aa:bb:cc:dd:ee:03",
	} {
		if _, wasKnown := reg.Observe(identity.Observation{
			MAC:      mac,
			Address:  mustAddr(t, "10.77.0.10"),
			Hostname: "host",
		}, at); wasKnown {
			t.Errorf("a first sighting of %s reported the device as already known", mac)
		}
	}

	got := map[string]signals.Value{}
	for _, s := range signals.DeriveDevices(reg, at, time.Hour) {
		got[s.Name] = s.Value
	}

	for _, name := range []string{signals.DevicesTotal, signals.DevicesWeakID, signals.DevicesStaleAfter} {
		if !got[name].Known {
			t.Errorf("%s is unknown with a registry supplied", name)
		}
	}
	if got[signals.DevicesTotal].Number != 3 {
		t.Errorf("total = %v, want 3", got[signals.DevicesTotal].Number)
	}

	// Every device in the registry has a MAC, so none is weakly identified.
	if got[signals.DevicesWeakID].Number != 0 {
		t.Errorf("weak = %v, want 0; identity rejects observations with no MAC",
			got[signals.DevicesWeakID].Number)
	}

	// All three were seen now, so none is stale.
	if got[signals.DevicesStaleAfter].Number != 0 {
		t.Errorf("stale = %v, want 0; every device was just seen",
			got[signals.DevicesStaleAfter].Number)
	}
}

// TestDeriveDevicesCountsAStaleDevice: the stale count is the one that has to
// work, because it is what tells an operator a device has gone quiet.
func TestDeriveDevicesCountsAStaleDevice(t *testing.T) {
	reg := identity.NewRegistry()
	_, _ = reg.Observe(identity.Observation{MAC: "aa:bb:cc:dd:ee:01"}, at.Add(-48*time.Hour))
	_, _ = reg.Observe(identity.Observation{MAC: "aa:bb:cc:dd:ee:02"}, at)

	for _, s := range signals.DeriveDevices(reg, at, time.Hour) {
		if s.Name == signals.DevicesStaleAfter && s.Value.Number != 1 {
			t.Errorf("stale = %v, want 1", s.Value.Number)
		}
	}
}

// TestDeriveDevicesWithNoRegistryIsUnknownNotZero: "I have no registry" and
// "there are no devices" are different, and the first must not read as the
// second.
func TestDeriveDevicesWithNoRegistryIsUnknownNotZero(t *testing.T) {
	for _, s := range signals.DeriveDevices(nil, at, time.Hour) {
		if s.Value.Known {
			t.Errorf("%s = %v, want unknown with no registry", s.Name, s.Value)
		}
	}
}

// TestDeriveValidationMapsCounts: validation's severities and the signal
// vocabulary are the same concept, and the translation happens once.
func TestDeriveValidationMapsCounts(t *testing.T) {
	got := signals.DeriveValidation(validationResult(2, 5, 1), at)

	want := map[string]float64{
		signals.ConfigErrCount:  2,
		signals.ConfigWarnCount: 5,
	}
	for name, expected := range want {
		found := false
		for _, s := range got {
			if s.Name != name {
				continue
			}
			found = true
			if s.Value.Number != expected {
				t.Errorf("%s = %v, want %v", name, s.Value.Number, expected)
			}
		}
		if !found {
			t.Errorf("no %s signal was produced", name)
		}
	}

	for _, s := range got {
		if s.Name == signals.ConfigValid && s.Value.Bool {
			t.Error("a result with 2 errors reports itself valid")
		}
	}
}

// TestDeriveDriftDistinguishesPendingFromConverged: diff reports "converged"
// on an unobservable host with work still pending, and a rule that reads that
// as "all is well" would go quiet exactly when it should speak.
func TestDeriveDriftDistinguishesPendingFromConverged(t *testing.T) {
	got := signals.DeriveDrift(diff.Result{Converged: true, PendingCount: 3}, at)

	for _, s := range got {
		if s.Name != signals.DriftConverged {
			continue
		}
		if !s.Value.Bool {
			t.Error("converged is false, want true")
		}
		// The detail has to carry the distinction, because the value alone
		// does not.
		if !contains(s.Detail, "pending") {
			t.Errorf("detail %q does not mention the pending work; an operator "+
				"reading only this would conclude the gateway is verified", s.Detail)
		}
		return
	}
	t.Fatal("no converged signal was produced")
}

// TestSetUnknownListsOnlyUnreadableSignals: the "here is what I could not see"
// list is the whole story on a gateway that has gone quiet.
func TestSetUnknownListsOnlyUnreadableSignals(t *testing.T) {
	set := signals.NewSet(at,
		sig("known.one", "a", signals.Bool(true)),
		sig("unknown.one", "b", signals.Unknown(signals.KindBool)),
		sig("known.two", "c", signals.Number(1)),
		sig("unknown.two", "d", signals.Unknown(signals.KindNumber)),
	)

	unknown := set.Unknown()
	if len(unknown) != 2 {
		t.Fatalf("unknown = %d, want 2: %v", len(unknown), unknown)
	}
	for _, s := range unknown {
		if s.Value.Known {
			t.Errorf("%s is listed as unknown but is known", s.Name)
		}
	}
}

// TestSourceOfSplitsOnDots: grouping by source relies on the first segment
// being the subsystem.
func TestSourceOfSplitsOnDots(t *testing.T) {
	cases := map[string]string{
		"wan.link.up":     "wan",
		"firewall.active": "firewall",
		"nodots":          "nodots",
		"a.b.c.d":         "a",
		"":                "",
	}
	for name, want := range cases {
		if got := signals.SourceOf(name); got != want {
			t.Errorf("SourceOf(%q) = %q, want %q", name, got, want)
		}
	}
}
