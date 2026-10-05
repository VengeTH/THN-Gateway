package host

// M7.0 capability confidence and gateway readiness.
//
// # What is being protected here
//
// Two properties that M7.0 exists to establish, each of which fails silently:
//
//  1. observed, inferred and unknown must remain three distinct things. A
//     capability model where the three collapse renders as a clean table and
//     enables a gateway on a host whose nft binary is missing.
//
//  2. Unknown must never satisfy a hard gate. If it does, the gate meant to
//     catch exactly that is decorative.
//
// The fixtures below are named A–D per the M7.0 specification. None of them
// mentions a real machine: the interface names are deliberately unremarkable
// (wan0, wan1, eth0) so that no test can pass by matching a remembered host.

import (
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/network"
)

// nowFixture is the observation time for every fixture. Fixed so that two
// runs of the same test produce identical models.
var nowFixture = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// fixtureSnapshot builds a snapshot the M7.0 capability model can consume.
//
// The Checked flags default to true because a fixture that did not probe a
// subsystem is asserting "nft is absent", which is a claim, not an absence.
// Tests that want the unprobed case say so explicitly.
func fixtureSnapshot(ifaces []network.Interface) *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: nowFixture(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: ifaces,
		Sysctl:     []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
		NFTables:   network.NFTablesState{Checked: true, Available: true, QuerySucceeded: true},
		TrafficControl: network.TCState{
			Checked: true, Available: true, QuerySucceeded: true,
		},
		System: network.System{Distribution: "debian", Version: "12"},
	}
}

func ethernet(name, mac string, index int) network.Interface {
	return network.Interface{
		Name: name, Index: index, MAC: mac, MTU: 1500,
		Kind: "ether", LinkType: "ether", Physical: true,
		AdminUp: true, State: network.LinkUp, SpeedMbps: 1000,
	}
}

// fixtureA is the basic gateway candidate: two physical Ethernet interfaces,
// forwarding on, nftables and tc both answering.
func fixtureA() *Device {
	return FromSnapshot(fixtureSnapshot([]network.Interface{
		ethernet("wan0", "3c:ec:ef:11:22:33", 2),
		ethernet("wan1", "3c:ec:ef:11:22:44", 3),
	}))
}

// fixtureB is the single-interface host. Observable, but not a two-port
// gateway.
func fixtureB() *Device {
	return FromSnapshot(fixtureSnapshot([]network.Interface{
		ethernet("eth0", "52:54:00:12:34:56", 2),
	}))
}

// fixtureC carries infrastructure THN does not own.
func fixtureC() *Device {
	snap := fixtureSnapshot([]network.Interface{
		ethernet("enp1s0", "b8:27:eb:aa:bb:cc", 2),
		ethernet("enp2s0", "b8:27:eb:aa:bb:cd", 3),
		{Name: "docker0", Index: 4, MAC: "02:42:1a:2b:3c:4d", Kind: "bridge",
			LinkType: "ether", State: network.LinkUp},
		{Name: "veth9f2a1c", Index: 5, MAC: "9e:1f:2a:3b:4c:5d", Kind: "veth",
			LinkType: "ether", State: network.LinkUp},
		{Name: "tailscale0", Index: 6, Kind: "tun", LinkType: "none", State: network.LinkUp},
		{Name: "lo", Index: 1, Kind: "loopback", LinkType: "loopback", State: network.LinkUp},
	})
	snap.NFTables.Tables = []network.NftTable{
		{Family: "ip", Name: "filter", Chains: []string{"INPUT", "FORWARD"}},
		{Family: "ip", Name: "docker-forward", Chains: []string{"DOCKER-FORWARD"}},
	}
	snap.NFTables.Managed = false
	snap.Routes = []network.Route{
		{Destination: "default", Gateway: "192.168.2.1", Interface: "enp1s0",
			Protocol: "dhcp", Default: true},
		{Destination: "172.17.0.0/16", Interface: "docker0", Protocol: "kernel"},
	}
	return FromSnapshot(snap)
}

// fixtureD is the unknown-capability host: tc answers, but nothing on it is
// CAKE, so CAKE must remain unknown rather than becoming available.
func fixtureD() *Device {
	snap := fixtureSnapshot([]network.Interface{
		ethernet("wan0", "3c:ec:ef:11:22:33", 2),
		ethernet("wan1", "3c:ec:ef:11:22:44", 3),
	})
	snap.TrafficControl.Qdiscs = []network.Qdisc{{Kind: "fq_codel", Handle: "0", Root: true}}
	return FromSnapshot(snap)
}

// ---------------------------------------------------- confidence semantics

// TestConfidenceValuesAreDistinct is the foundational property.
//
// If these three are not three distinct values then the rest of the model is
// decoration, and this test is the cheapest place to notice that.
func TestConfidenceValuesAreDistinct(t *testing.T) {
	seen := map[Confidence]bool{}
	for _, c := range []Confidence{ConfidenceObserved, ConfidenceInferred, ConfidenceUnknown} {
		if seen[c] {
			t.Errorf("confidence %q appears twice; the three states must be distinct", c)
		}
		seen[c] = true
	}
	if len(seen) != 3 {
		t.Errorf("%d distinct confidence values, want 3", len(seen))
	}
}

// TestSatisfiesRejectsInferredAndUnknown is the central gate rule.
//
// An inferred capability is a conclusion THN drew from the platform. An
// unknown one is a gap. Neither is evidence about this machine, and a hard
// gate that accepts either is not a gate.
func TestSatisfiesRejectsInferredAndUnknown(t *testing.T) {
	cases := []struct {
		name  string
		state CapabilityState
		want  bool
	}{
		{"observed and available", CapabilityState{Available: true, Confidence: ConfidenceObserved}, true},
		{"observed but unavailable", CapabilityState{Available: false, Confidence: ConfidenceObserved}, false},
		{"inferred and available", CapabilityState{Available: true, Confidence: ConfidenceInferred}, false},
		{"unknown and available", CapabilityState{Available: true, Confidence: ConfidenceUnknown}, false},
		{"empty confidence", CapabilityState{Available: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.Satisfies(); got != tc.want {
				t.Errorf("Satisfies() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseConfidenceDefaultsToUnknown proves the fail-closed default.
//
// A blank, misspelled or unexpected confidence must land on unknown, never on
// observed. A typo in a confidence string must not silently promote an
// inference into something a gate will accept.
func TestParseConfidenceDefaultsToUnknown(t *testing.T) {
	cases := map[string]Confidence{
		"observed":    ConfidenceObserved,
		"OBSERVED":    ConfidenceObserved,
		"  observed ": ConfidenceObserved,
		"inferred":    ConfidenceInferred,
		"unknown":     ConfidenceUnknown,
		"":            ConfidenceUnknown,
		"guess":       ConfidenceUnknown,
		"probed":      ConfidenceUnknown,
	}
	for in, want := range cases {
		if got := ParseConfidence(in); got != want {
			t.Errorf("ParseConfidence(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFixtureAObservedCapabilitiesAreObserved proves a healthy gateway host
// reports its capabilities as observed.
//
// If nft and tc were actually queried — and the fixture says they were — the
// verdict is an observation, not a conclusion from the platform.
func TestFixtureAObservedCapabilitiesAreObserved(t *testing.T) {
	d := fixtureA()

	for _, c := range []Capability{CapNFTables, CapTC, CapFirewall, CapForwarding} {
		s, ok := d.Capabilities[c]
		if !ok {
			t.Errorf("capability %s is absent from a host where it was probed", c)
			continue
		}
		if !s.Available {
			t.Errorf("capability %s is unavailable on a host where it answered", c)
		}
		if s.Confidence != ConfidenceObserved {
			t.Errorf("capability %s confidence = %q, want observed: the fixture probed it",
				c, s.Confidence)
		}
	}
}

// TestFixtureDCakeStaysUnknown is the "fail closed" requirement, stated.
//
// `tc` is installed and answered. That is the whole of what is known. CAKE is
// a kernel module, and asking whether it is loadable would mean loading it —
// which is mutation. So CAKE is UNKNOWN, and unknown does not satisfy a gate.
func TestFixtureDCakeStaysUnknown(t *testing.T) {
	d := fixtureD()

	cake, ok := d.Capabilities[CapCake]
	if !ok {
		t.Fatal("CAKE is absent from the capability table; every capability must appear")
	}
	if cake.Available {
		t.Error("CAKE reported available; tc being installed says nothing about sch_cake")
	}
	if cake.Confidence != ConfidenceUnknown {
		t.Errorf("CAKE confidence = %q, want unknown: tc exists but CAKE was never confirmed",
			cake.Confidence)
	}
	if cake.Satisfies() {
		t.Error("CAKE satisfies a gate; an unknown capability must never do so")
	}
}

// TestCakeIsObservedOnlyWhenAttached proves the positive case exists.
//
// Without this the previous test would pass for the wrong reason — CAKE could
// be permanently unknown and still satisfy "must not be available". A CAKE
// discipline actually attached is real evidence, and must be recorded as such.
func TestCakeIsObservedOnlyWhenAttached(t *testing.T) {
	snap := fixtureSnapshot([]network.Interface{
		ethernet("wan0", "3c:ec:ef:11:22:33", 2),
	})
	snap.TrafficControl.CakeObserved = true
	d := FromSnapshot(snap)

	cake, _ := d.Capabilities[CapCake]
	if !cake.Available {
		t.Error("CAKE is unavailable on a host with a CAKE discipline attached")
	}
	if cake.Confidence != ConfidenceObserved {
		t.Errorf("CAKE confidence = %q, want observed", cake.Confidence)
	}
	if !cake.Satisfies() {
		t.Error("an observed, available CAKE should satisfy a gate")
	}
}

// TestUnprobedSubsystemsAreUnknownNotAbsent is the bug this model prevents.
//
// A zero-valued subsystem state means "nobody looked". Reporting it as
// "nftables is not installed" would be asserting a finding nobody made, and
// on an unsupported platform would claim a positive result from no probe.
func TestUnprobedSubsystemsAreUnknownNotAbsent(t *testing.T) {
	d := FromSnapshot(&network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			ethernet("wan0", "3c:ec:ef:11:22:33", 2),
		},
	})

	nft, _ := d.Capabilities[CapNFTables]
	if nft.Confidence != ConfidenceUnknown {
		t.Errorf("nftables confidence = %q, want unknown for an unprobed host", nft.Confidence)
	}
	if nft.Satisfies() {
		t.Error("an unprobed nftables must not satisfy a gate")
	}

	cake, _ := d.Capabilities[CapCake]
	if cake.Confidence != ConfidenceUnknown {
		t.Errorf("CAKE confidence = %q, want unknown for an unprobed host", cake.Confidence)
	}
}

// TestCapabilityPresenceAndAbsenceCarryDifferentConfidence proves the
// presence-based capabilities label their evidence honestly.
//
// A veth pair that exists is observed evidence. Its absence is not evidence
// of impossibility — THN did not try to create one, because creating one
// would mutate a production host — so absence is inferred.
func TestCapabilityPresenceAndAbsenceCarryDifferentConfidence(t *testing.T) {
	present := FromSnapshot(fixtureSnapshot([]network.Interface{
		{Name: "veth1", Index: 4, Kind: "veth", LinkType: "ether", State: network.LinkUp},
	}))
	absent := FromSnapshot(fixtureSnapshot([]network.Interface{
		ethernet("wan0", "3c:ec:ef:11:22:33", 2),
	}))

	withVeth, _ := present.Capabilities[CapVeth]
	if withVeth.Confidence != ConfidenceObserved {
		t.Errorf("veth confidence = %q; an observed veth interface is evidence", withVeth.Confidence)
	}
	if !withVeth.Available {
		t.Error("veth should be available when a veth interface was observed")
	}

	withoutVeth, _ := absent.Capabilities[CapVeth]
	if withoutVeth.Confidence != ConfidenceInferred {
		t.Errorf("veth confidence = %q; absence is an inference, not an observation", withoutVeth.Confidence)
	}
	if withoutVeth.Satisfies() {
		t.Error("an inferred capability must not satisfy a gate")
	}
}

// TestEveryCapabilityCarriesAConfidenceAndReason preserves the invariant the
// pre-existing suite already enforced, across the widened capability set.
func TestEveryCapabilityCarriesAConfidenceAndReason(t *testing.T) {
	for name, d := range map[string]*Device{
		"A gateway candidate":   fixtureA(),
		"B single interface":    fixtureB(),
		"C with infrastructure": fixtureC(),
		"D unknown CAKE":        fixtureD(),
	} {
		t.Run(name, func(t *testing.T) {
			for _, c := range AllCapabilities() {
				s, ok := d.Capabilities[c]
				if !ok {
					t.Errorf("capability %s is absent", c)
					continue
				}
				switch s.Confidence {
				case ConfidenceObserved, ConfidenceInferred, ConfidenceUnknown:
				default:
					t.Errorf("capability %s has confidence %q, which is not a known value", c, s.Confidence)
				}
				if s.Reason == "" {
					t.Errorf("capability %s has no reason", c)
				}
			}
		})
	}
}
