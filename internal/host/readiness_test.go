package host

// M7.0 gateway readiness.
//
// # What is being protected here
//
// Readiness is the part of M7.0 an operator acts on, so its failure modes
// matter more than its internals. The three that count:
//
//  1. Uncertainty must not masquerade as a block. A host THN understands
//     less is not a host an operator can use less.
//
//  2. Distinct failures must stay distinct. "Forwarding is off" and "THN
//     could not read forwarding" call for opposite responses, and they render
//     identically if the model has only one boolean for it.
//
//  3. Foreign infrastructure must never block. Docker and Tailscale are
//     normal on a real gateway, and a readiness report that treats them as
//     problems invites an operator to delete working infrastructure.
//
// The fixtures are shared with capability_test.go, which explains what each
// of A through D represents.

import (
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/network"
)

// TestFixtureAIsGatewayCapable proves the happy path is not blocked.
//
// Note the status is READY_WITH_WARNINGS, not READY, and that is the correct
// answer rather than a near miss. Fixture A has real, unresolved questions
// about itself: nothing on it is running CAKE, so whether this kernel could
// run CAKE is unknown, and no veth or namespace interface exists so those two
// are inferred rather than observed. The specification's own example of a
// healthy host shows the same shape — a READY section with a CAKE warning
// beneath it.
//
// What matters is that the host is gateway-capable, which is precisely the
// spec's stated expectation for this fixture.
func TestFixtureAIsGatewayCapable(t *testing.T) {
	r := EvaluateReadiness(fixtureA(), ReadinessRequest{RequiredInterfaces: 2})

	if r.Blocked {
		t.Fatalf("fixture A is blocked: %+v", r.Blocking())
	}
	if r.Status == BlockedStatus {
		t.Errorf("status = %s, want a non-blocked verdict", r.Status)
	}
	if r.Status != ReadyWithWarningsStatus {
		t.Errorf("status = %s, want READY_WITH_WARNINGS: CAKE and the "+
			"presence-based capabilities are genuinely unconfirmed here", r.Status)
	}
	if len(r.Facts) == 0 {
		t.Error("no facts were reported; readiness must show what it checked, not only what failed")
	}
}

// TestPlainReadyIsReachable proves READY is a live verdict and not dead code.
//
// Every capability that can be probed is probed here, so nothing is left
// uncertain except the three permanent userspace inferences. Without this
// test, a change that made every capability uncertain would turn every host
// into READY_WITH_WARNINGS and nobody would notice, because the weaker
// verdict still looks fine.
func TestPlainReadyIsReachable(t *testing.T) {
	snap := fixtureSnapshot([]network.Interface{
		ethernet("wan0", "3c:ec:ef:11:22:33", 2),
		ethernet("wan1", "3c:ec:ef:11:22:44", 3),
		// A CAKE discipline, a veth and a bridge: the evidence that turns
		// the three remaining uncertainties into observations.
		{Name: "docker0", Index: 4, Kind: "bridge", LinkType: "ether", State: network.LinkUp},
		{Name: "veth1", Index: 5, Kind: "veth", LinkType: "ether", State: network.LinkUp},
	})
	snap.TrafficControl.CakeObserved = true
	d := FromSnapshot(snap)

	r := EvaluateReadiness(d, ReadinessRequest{RequiredInterfaces: 2})
	if r.Status != ReadyStatus {
		t.Errorf("status = %s, want READY; a fully observed host must reach the top "+
			"verdict. findings: %+v", r.Status, r.Findings)
	}
}

// TestPermanentInferencesDoNotWarnForever proves the noise floor is controlled.
//
// NAT, DHCP and DNS are served in userspace and will never be probed on any
// host. If they raised warnings, every report would carry three entries that
// can never change, and an operator would learn to skip the warning list
// entirely — which is how the one warning that mattered gets missed.
func TestPermanentInferencesDoNotWarnForever(t *testing.T) {
	d := fixtureA()

	for _, c := range []Capability{CapNAT, CapDHCP, CapDNS} {
		s, ok := d.Capabilities[c]
		if !ok {
			t.Fatalf("capability %s is absent", c)
		}
		if s.Confidence != ConfidenceInferred {
			t.Errorf("capability %s confidence = %q, want inferred: userspace services are never probed",
				c, s.Confidence)
		}
	}

	r := EvaluateReadiness(d, ReadinessRequest{RequiredInterfaces: 2})
	for _, f := range r.Findings {
		switch f.Subject {
		case string(CapNAT), string(CapDHCP), string(CapDNS):
			t.Errorf("permanent inference %s raised a finding: %s", f.Subject, f.Message)
		}
	}
}

// TestFixtureBIsBlockedForInterfaceCount is Fixture B's expectation.
//
// It must be blocked for exactly one reason — not enough interfaces for the
// two-port topology — and must still be fully described.
func TestFixtureBIsBlockedForInterfaceCount(t *testing.T) {
	r := EvaluateReadiness(fixtureB(), ReadinessRequest{RequiredInterfaces: 2})

	if r.Status != BlockedStatus {
		t.Fatalf("status = %s, want BLOCKED", r.Status)
	}
	if !r.HasCode("insufficient-interfaces") {
		t.Errorf("no insufficient-interfaces finding; got %+v", r.Findings)
	}
	if r.HasCode("no-physical-interfaces") {
		t.Error("a host with one NIC must not be reported as having none")
	}

	// The same host asked only for one port is fine. That is the difference
	// between "not a gateway" and "not THIS gateway".
	one := EvaluateReadiness(fixtureB(), ReadinessRequest{RequiredInterfaces: 1})
	if one.Blocked {
		t.Errorf("a single-port topology was blocked on a single-NIC host: %+v", one.Findings)
	}
}

// TestFixtureCUnmanagedInfrastructureIsPreserved is Fixture C's expectation.
//
// The host must be describable and the foreign resources must be visible, but
// none of them may be treated as a problem or as something to remove.
func TestFixtureCUnmanagedInfrastructureIsPreserved(t *testing.T) {
	d := fixtureC()

	// Every interface survives discovery.
	if len(d.Interfaces) != 6 {
		t.Fatalf("%d interfaces after discovery, want 6; nothing may be dropped", len(d.Interfaces))
	}

	// Only the two real NICs are physical.
	if got := len(d.PhysicalInterfaces()); got != 2 {
		t.Errorf("%d physical interfaces, want 2", got)
	}

	// The foreign nftables tables are all still there.
	if len(d.NFTables.Tables) != 2 {
		t.Errorf("%d nftables tables, want 2; unmanaged tables must be preserved", len(d.NFTables.Tables))
	}
	if d.NFTables.THNTablePresent {
		t.Error("THN's own table was reported present on a host that has none")
	}
	if d.NFTables.Managed {
		t.Error("a host carrying Docker's tables must not be reported as fully managed")
	}

	// The routes survive, including the default one THN must not claim.
	if len(d.Routes) != 2 {
		t.Errorf("%d routes, want 2", len(d.Routes))
	}
	def, ok := d.DefaultRoute()
	if !ok {
		t.Fatal("the default route was dropped")
	}
	if def.Interface != "enp1s0" {
		t.Errorf("default route dev = %q, want enp1s0", def.Interface)
	}

	// And it is reported to the operator as unmanaged — as information, not
	// as a fault. Docker and Tailscale are normal on a real gateway.
	r := EvaluateReadiness(d, ReadinessRequest{RequiredInterfaces: 2})
	if !r.HasCode("unmanaged-infrastructure") {
		t.Errorf("foreign infrastructure was not reported; got %+v", r.Findings)
	}
	if len(r.Notes()) == 0 {
		t.Error("unmanaged infrastructure should be recorded as a note")
	}
	for _, f := range r.Blocking() {
		if f.Code == "unmanaged-infrastructure" {
			t.Error("unmanaged infrastructure must never block; Docker and Tailscale are normal")
		}
	}
	for _, f := range r.Warnings() {
		if f.Code == "unmanaged-infrastructure" {
			t.Error("unmanaged infrastructure is an observation, not an uncertainty; " +
				"it must not appear as a warning")
		}
	}
}

// TestFixtureDWarnsWithoutBlocking proves uncertainty is not a block.
//
// A host THN understands less is not a host an operator can use less. CAKE
// being unconfirmable is a gap in THN's knowledge, not a defect in the host.
func TestFixtureDWarnsWithoutBlocking(t *testing.T) {
	r := EvaluateReadiness(fixtureD(), ReadinessRequest{RequiredInterfaces: 2})

	if r.Blocked {
		t.Errorf("an unconfirmable CAKE capability blocked the host: %+v", r.Blocking())
	}
	if r.Status == ReadyStatus {
		t.Error("a host with an unknown capability must not report plain READY; " +
			"the uncertainty is the useful part of the answer")
	}
	if r.Status != ReadyWithWarningsStatus {
		t.Errorf("status = %s, want READY_WITH_WARNINGS", r.Status)
	}

	found := false
	for _, f := range r.Findings {
		if f.Subject == string(CapCake) {
			found = true
			if f.Confidence != ConfidenceUnknown {
				t.Errorf("CAKE finding confidence = %q, want unknown", f.Confidence)
			}
		}
	}
	if !found {
		t.Errorf("no finding mentioned CAKE; got %+v", r.Findings)
	}
}

// TestUnreadableForwardingBlocksSeparately proves the two forwarding failures
// are distinguishable.
//
// Both render as "forwarding is off", and they call for opposite responses:
// one is a THN privilege problem, the other is a host that needs a setting
// changed. A single code would lose that.
func TestUnreadableForwardingBlocksSeparately(t *testing.T) {
	twoNICs := []network.Interface{
		ethernet("wan0", "3c:ec:ef:11:22:33", 2),
		ethernet("wan1", "3c:ec:ef:11:22:44", 3),
	}

	offSnap := fixtureSnapshot(twoNICs)
	offSnap.Sysctl = []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}}

	unreadableSnap := fixtureSnapshot(twoNICs)
	unreadableSnap.Sysctl = []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "unknown"}}

	enabled := EvaluateReadiness(fixtureA(), ReadinessRequest{RequiredInterfaces: 2})
	disabled := EvaluateReadiness(FromSnapshot(offSnap), ReadinessRequest{RequiredInterfaces: 2})
	undetermined := EvaluateReadiness(FromSnapshot(unreadableSnap), ReadinessRequest{RequiredInterfaces: 2})

	if enabled.HasCode("forwarding-unavailable") {
		t.Error("forwarding-unavailable was raised on a host with forwarding enabled")
	}
	if !disabled.HasCode("forwarding-unavailable") {
		t.Error("forwarding-unavailable was not raised on a host with forwarding off")
	}
	if disabled.HasCode("forwarding-undetermined") {
		t.Error("a readable sysctl of 0 must be reported as disabled, not undetermined")
	}
	if !undetermined.HasCode("forwarding-undetermined") {
		t.Error("an unreadable sysctl must be reported as undetermined")
	}
	if undetermined.HasCode("forwarding-unavailable") {
		t.Error("an unreadable sysctl must not be reported as a confirmed-off setting")
	}
}

// TestUnresolvedRoleBlocks proves an unassigned role prevents readiness.
func TestUnresolvedRoleBlocks(t *testing.T) {
	d := fixtureA()
	res := Resolve(d, []Assignment{{Role: RoleLAN, Selector: "no-such-interface"}})

	r := EvaluateReadiness(d, ReadinessRequest{
		RequiredInterfaces: 2,
		Resolutions:        map[Role]Resolution{RoleLAN: res},
	})

	if !r.Blocked {
		t.Errorf("an unresolved LAN did not block: %+v", r.Findings)
	}
	if !r.HasCode("role-unknown-interface") {
		t.Errorf("the role problem was not surfaced; got %+v", r.Findings)
	}
}

// TestConflictingRoleBlocks proves a duplicate assignment is reported.
func TestConflictingRoleBlocks(t *testing.T) {
	d := fixtureA()
	res := Resolve(d, []Assignment{
		{Role: RoleWAN, Selector: "wan0"},
		{Role: RoleWAN, Selector: "wan1"},
	})

	r := EvaluateReadiness(d, ReadinessRequest{
		RequiredInterfaces: 2,
		Resolutions:        map[Role]Resolution{RoleWAN: res},
	})

	if !r.Blocked {
		t.Errorf("a duplicate role did not block: %+v", r.Findings)
	}
	if !r.HasCode("role-duplicate-role") {
		t.Errorf("the duplicate was not surfaced; got %+v", r.Findings)
	}
}

// TestResolvedRolesDoNotBlock proves a good configuration still passes.
func TestResolvedRolesDoNotBlock(t *testing.T) {
	d := fixtureA()
	res := Resolve(d, []Assignment{
		{Role: RoleWAN, Selector: "wan0"},
		{Role: RoleLAN, Selector: "wan1"},
	})

	r := EvaluateReadiness(d, ReadinessRequest{
		RequiredInterfaces: 2,
		Resolutions:        map[Role]Resolution{RoleWAN: res, RoleLAN: res},
	})

	if r.Blocked {
		t.Errorf("a fully resolved configuration blocked: %+v", r.Blocking())
	}
}

// TestReadinessIsDeterministic proves two evaluations agree exactly.
//
// A report that reorders its findings between runs cannot be diffed, and
// cannot be compared against a previous run in CI.
func TestReadinessIsDeterministic(t *testing.T) {
	d := fixtureC()
	req := ReadinessRequest{RequiredInterfaces: 2}

	first := EvaluateReadiness(d, req)
	for i := 0; i < 5; i++ {
		next := EvaluateReadiness(d, req)
		if len(next.Findings) != len(first.Findings) {
			t.Fatalf("run %d produced %d findings, first run produced %d",
				i, len(next.Findings), len(first.Findings))
		}
		for j := range next.Findings {
			if next.Findings[j].Code != first.Findings[j].Code ||
				next.Findings[j].Subject != first.Findings[j].Subject {
				t.Fatalf("run %d finding %d = %s/%s, want %s/%s",
					i, j, next.Findings[j].Subject, next.Findings[j].Code,
					first.Findings[j].Subject, first.Findings[j].Code)
			}
		}
	}
}

// TestReadinessBlocksWhenInspectionIsUnsupported proves the honest answer on a
// machine THN cannot inspect.
func TestReadinessBlocksWhenInspectionIsUnsupported(t *testing.T) {
	d := FromSnapshot(&network.Snapshot{Platform: "windows", Supported: false})

	r := EvaluateReadiness(d, ReadinessRequest{RequiredInterfaces: 2})
	if r.Status != BlockedStatus {
		t.Errorf("status = %s, want BLOCKED on an uninspectable host", r.Status)
	}
	if !r.HasCode("inspection-unavailable") {
		t.Errorf("no inspection-unavailable finding; got %+v", r.Findings)
	}
}

// TestReadinessOnNilDeviceDoesNotPanic proves the function is total.
func TestReadinessOnNilDeviceDoesNotPanic(t *testing.T) {
	r := EvaluateReadiness(nil, ReadinessRequest{})
	if r.Status != BlockedStatus {
		t.Errorf("status = %s, want BLOCKED", r.Status)
	}
}

// TestNoCapabilityIsSatisfiedByInference is the whole model, stated as a
// property over every fixture.
//
// Whatever a host looks like, no capability that was never actually probed
// may satisfy a gate. This is the invariant that stops the inference path
// from quietly becoming a back door into activation.
func TestNoCapabilityIsSatisfiedByInference(t *testing.T) {
	fixtures := map[string]*Device{
		"A": fixtureA(),
		"B": fixtureB(),
		"C": fixtureC(),
		"D": fixtureD(),
	}

	for name, d := range fixtures {
		t.Run(name, func(t *testing.T) {
			for _, c := range AllCapabilities() {
				s, ok := d.Capabilities[c]
				if !ok {
					continue
				}
				if s.Satisfies() && s.Confidence != ConfidenceObserved {
					t.Errorf("capability %s satisfies a gate on confidence %q; "+
						"only an observation may satisfy a gate", c, s.Confidence)
				}
			}
		})
	}
}

// TestReadinessNeverMutatesTheDevice proves readiness is a pure read.
//
// The function takes a *Device and returns a verdict. If it modified the
// device on the way — attaching a role, flagging an interface — then the
// observation a caller subsequently reports would no longer be what was
// observed. That is the whole claim M7.0 rests on, so it is checked directly
// rather than left to inspection.
func TestReadinessNeverMutatesTheDevice(t *testing.T) {
	d := fixtureC()
	before := d.Interfaces
	beforeCaps := len(d.Capabilities)

	EvaluateReadiness(d, ReadinessRequest{RequiredInterfaces: 2})

	if len(d.Interfaces) != len(before) {
		t.Errorf("readiness changed the interface count from %d to %d",
			len(before), len(d.Interfaces))
	}
	if len(d.Capabilities) != beforeCaps {
		t.Errorf("readiness changed the capability count from %d to %d",
			beforeCaps, len(d.Capabilities))
	}
	for i := range d.Interfaces {
		if d.Interfaces[i].Role != before[i].Role {
			t.Errorf("readiness assigned role %q to %s; it must assign nothing",
				d.Interfaces[i].Role, d.Interfaces[i].SystemName)
		}
	}
}
