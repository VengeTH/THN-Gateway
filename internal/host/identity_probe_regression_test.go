package host

// Regression tests for identity derivation and probe failure handling (CI portability & M7.1/M7.1.1 contract).
//
// Invariants covered:
//   1. Identity:
//      - Multiple interface records referring to the same physical device (e.g. Azure SR-IOV Accelerated Networking)
//      - Kernel-name changes do not change stable identity
//      - Stable identity is repeatable and deterministic
//      - Genuinely different physical devices do not collapse into one identity
//   2. Probe failures:
//      - Missing `iw` does not establish positive wireless capabilities
//      - Permission-denied nftables probe degrades to unknown and does not establish firewall
//      - Execution failure does not establish positive capability
//      - Not-checked probes remain distinguishable from evidence
//      - Inferred capabilities do not satisfy hard gates

import (
	"testing"

	"github.com/venth/thn-gateway/internal/network"
)

// TestMultipleInterfacesReferencingSamePhysicalDevice verifies that when
// multiple kernel interface records refer to the same physical hardware
// (such as Azure Accelerated Networking pairing synthetic eth0 and VF enP...
// with the same MAC and Ethernet kind), both receive the same stable hardware
// identity without crashing, colliding unexpectedly, or allowing dual role assignment.
func TestMultipleInterfacesReferencingSamePhysicalDevice(t *testing.T) {
	mac := "00:15:5d:01:02:03"
	expectedID := IDFor(mac)

	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{
				Name: "eth0", Index: 2, MAC: mac, Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkUp,
			},
			{
				Name: "enP25351s1", Index: 3, MAC: mac, Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkUp,
			},
			{
				Name: "lo", Index: 1, Kind: "loopback", AdminUp: true, State: network.LinkUp,
			},
		},
	}

	d := FromSnapshot(snap)

	if len(d.Interfaces) != 3 {
		t.Fatalf("expected 3 interfaces, got %d", len(d.Interfaces))
	}

	var eth0, vf Interface
	for _, i := range d.Interfaces {
		switch i.SystemName {
		case "eth0":
			eth0 = i
		case "enP25351s1":
			vf = i
		}
	}

	if eth0.ID == "" || vf.ID == "" {
		t.Fatal("one or both interfaces received empty identity")
	}

	// 1. Both must receive IdentityHardware.
	if eth0.IDKind != IdentityHardware || vf.IDKind != IdentityHardware {
		t.Errorf("expected IdentityHardware for both; got eth0=%s, vf=%s", eth0.IDKind, vf.IDKind)
	}

	// 2. Both must share the same stable ID matching the physical device.
	if eth0.ID != expectedID {
		t.Errorf("eth0 ID = %q, want %q", eth0.ID, expectedID)
	}
	if vf.ID != expectedID {
		t.Errorf("vf ID = %q, want %q", vf.ID, expectedID)
	}
	if eth0.ID != vf.ID {
		t.Errorf("interfaces sharing physical hardware have different IDs: eth0=%s, vf=%s", eth0.ID, vf.ID)
	}

	// 3. Resolve must reject assigning both interfaces to separate roles,
	// because they are the same physical device.
	res := Resolve(d, []Assignment{
		{Role: RoleWAN, Selector: "eth0"},
		{Role: RoleLAN, Selector: "enP25351s1"},
	})
	if res.OK() {
		t.Fatal("Resolve allowed assigning both interfaces of the same physical device to separate roles")
	}
	foundDup := false
	for _, p := range res.Problems {
		if p.Code == "duplicate-interface" {
			foundDup = true
			break
		}
	}
	if !foundDup {
		t.Errorf("expected duplicate-interface problem, got: %+v", res.Problems)
	}

	// 4. Resolve must succeed when assigning WAN by the stable selector.
	resSingle := Resolve(d, []Assignment{
		{Role: RoleWAN, Selector: expectedID},
	})
	if !resSingle.OK() {
		t.Errorf("Resolve failed for selector %s: %+v", expectedID, resSingle.Problems)
	}
	if assigned, ok := resSingle.Assigned[RoleWAN]; !ok || assigned.ID != expectedID {
		t.Errorf("expected WAN assigned to %s, got %+v", expectedID, assigned)
	}
}

// TestKernelNameChangesPreserveStableIdentity proves that renaming an interface
// (or encountering different naming conventions like eth0 vs enp0s31f6) preserves
// the exact stable hardware identity.
func TestKernelNameChangesPreserveStableIdentity(t *testing.T) {
	mac := "3c:ec:ef:aa:bb:cc"
	id1, kind1 := InterfaceID(KindEthernet, mac, 2)
	id2, kind2 := InterfaceID(KindEthernet, mac, 7)

	if kind1 != IdentityHardware || kind2 != IdentityHardware {
		t.Errorf("expected IdentityHardware, got %s and %s", kind1, kind2)
	}
	if id1 != id2 {
		t.Errorf("hardware identity changed with index/name: %q vs %q", id1, id2)
	}
	if id1 != IDFor(mac) {
		t.Errorf("IDFor mismatch: %q vs %q", id1, IDFor(mac))
	}
}

// TestStableIdentityIsRepeatable proves that identity calculation is deterministic
// across multiple invocations.
func TestStableIdentityIsRepeatable(t *testing.T) {
	mac := "52:54:00:12:34:56"
	first, _ := InterfaceID(KindEthernet, mac, 2)
	for i := 0; i < 50; i++ {
		again, _ := InterfaceID(KindEthernet, mac, 2)
		if again != first {
			t.Fatalf("identity not repeatable: first=%s, iteration=%s", first, again)
		}
	}
}

// TestGenuinelyDifferentPhysicalDevicesDoNotCollapse proves that distinct physical
// devices, different kinds, or ephemeral links never share the same identity.
func TestGenuinelyDifferentPhysicalDevicesDoNotCollapse(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "eth0", Index: 2, MAC: "00:11:22:33:44:01", Kind: "ether", LinkType: "ether", Physical: true},
			{Name: "eth1", Index: 3, MAC: "00:11:22:33:44:02", Kind: "ether", LinkType: "ether", Physical: true},
			{Name: "bond0", Index: 4, MAC: "00:11:22:33:44:01", Kind: "bond", LinkType: "ether", Physical: false},
			{Name: "dummy0", Index: 5, MAC: "", Kind: "dummy", LinkType: "ether", Physical: false},
			{Name: "lo", Index: 1, MAC: "00:00:00:00:00:00", Kind: "loopback", LinkType: "loopback", Physical: false},
		},
	}

	d := FromSnapshot(snap)

	byName := map[string]Interface{}
	for _, i := range d.Interfaces {
		byName[i.SystemName] = i
	}

	eth0 := byName["eth0"]
	eth1 := byName["eth1"]
	bond0 := byName["bond0"]
	dummy0 := byName["dummy0"]
	lo := byName["lo"]

	// Different MACs must produce different IDs.
	if eth0.ID == eth1.ID {
		t.Errorf("eth0 and eth1 with different MACs shared identity %s", eth0.ID)
	}

	// Different kinds must produce different IDs even if sharing MAC.
	if eth0.ID == bond0.ID {
		t.Errorf("eth0 and bond0 with same MAC shared identity %s", eth0.ID)
	}

	// Ephemeral interfaces must have ephemeral identity and distinct IDs.
	if dummy0.IDKind != IdentityEphemeral {
		t.Errorf("dummy0 got kind %s, want ephemeral", dummy0.IDKind)
	}
	if lo.IDKind != IdentityEphemeral {
		t.Errorf("lo got kind %s, want ephemeral", lo.IDKind)
	}
	if dummy0.ID == lo.ID {
		t.Errorf("dummy0 and lo shared ephemeral identity %s", dummy0.ID)
	}
}

// TestMissingIwDoesNotEstablishPositiveWirelessCapability verifies that when
// iw is not installed on PATH, wireless probes record tool_unavailable and
// neither wireless-ap nor wireless-client is established as an available, observed capability.
func TestMissingIwDoesNotEstablishPositiveWirelessCapability(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "lo", Index: 1, Kind: "loopback"},
			{Name: "eth0", Index: 2, MAC: "00:11:22:33:44:55", Kind: "ether", LinkType: "ether", Physical: true},
		},
		Probes: []network.Probe{
			{
				Subsystem: "wireless", Operation: "nl80211-modes", Tool: "iw",
				Stage: network.StageExecute, Outcome: network.ProbeToolUnavailable,
				Detail: "the tool is not installed or not on PATH",
				Reason: "executing iw: exec: \"iw\": executable file not found in $PATH",
			},
		},
	}

	d := FromSnapshot(snap)

	// Wireless capabilities must NOT be available.
	if d.Has(CapWirelessAP) {
		t.Error("wireless-ap was reported available when iw was missing and no wireless interfaces exist")
	}
	if d.Has(CapWirelessClient) {
		t.Error("wireless-client was reported available when iw was missing and no wireless interfaces exist")
	}

	// Hard gates must not be satisfied.
	if d.Satisfies(CapWirelessAP) {
		t.Error("wireless-ap satisfied hard gate with missing iw")
	}
	if d.Satisfies(CapWirelessClient) {
		t.Error("wireless-client satisfied hard gate with missing iw")
	}

	// FalseConfidenceCapabilities must not flag false confidence
	// (tool_unavailable is not a false-confidence claim because no capability claimed observed).
	if len(d.FalseConfidenceCapabilities()) != 0 {
		t.Errorf("unexpected false confidence capabilities: %v", d.FalseConfidenceCapabilities())
	}
}

// TestWirelessProbeExecutionFailedDegradesToUnknown proves that when a wireless
// probe ends in execution_failed (e.g. tool execution failure), wireless capabilities
// degrade to ConfidenceUnknown and do not claim false ConfidenceObserved.
// Furthermore, CapNetns and CapVeth are not polluted by the wireless probe.
func TestWirelessProbeExecutionFailedDegradesToUnknown(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "lo", Index: 1, Kind: "loopback"},
			{Name: "docker0", Index: 2, Kind: "bridge", LinkType: "ether"},
		},
		Probes: []network.Probe{
			{
				Subsystem: "wireless", Operation: "nl80211-modes", Tool: "iw",
				Stage: network.StageExecute, Outcome: network.ProbeExecutionFailed,
				Detail: "the tool ran but did not succeed",
				Reason: "iw exited with error",
			},
		},
		NFTables: network.NFTablesState{
			Checked:   true,
			Available: false,
			Reason:    "nft is absent",
			Probe: network.Probe{
				Subsystem: "nftables", Operation: "list-tables",
				Stage: network.StageExecute, Outcome: network.ProbeToolUnavailable,
				Detail: "the tool is not installed",
			},
		},
		TrafficControl: network.TCState{
			Checked:   true,
			Available: false,
			Reason:    "tc is absent",
			Probe: network.Probe{
				Subsystem: "traffic-control", Operation: "qdisc-show",
				Stage: network.StageExecute, Outcome: network.ProbeToolUnavailable,
				Detail: "the tool is not installed",
			},
		},
	}

	d := FromSnapshot(snap)

	// Wireless capabilities must degrade to ConfidenceUnknown, not ConfidenceObserved
	for _, c := range []Capability{CapWirelessAP, CapWirelessClient} {
		state := d.Capabilities[c]
		if state.Confidence != ConfidenceUnknown {
			t.Errorf("%s confidence = %q, want unknown when wireless probe failed", c, state.Confidence)
		}
		if state.Available {
			t.Errorf("%s available = true, want false when wireless probe failed", c)
		}
	}

	// CapNetns (observed via docker0 bridge) must not inherit the failed wireless probe.
	netnsEv := d.EvidenceFor(CapNetns)
	if netnsEv.Probe.Subsystem == "wireless" {
		t.Errorf("CapNetns inherited wireless probe: %+v", netnsEv.Probe)
	}

	// No false confidence capabilities!
	if falseConf := d.FalseConfidenceCapabilities(); len(falseConf) != 0 {
		t.Errorf("unexpected false confidence capabilities: %v", falseConf)
	}

	// All unknowns must explain themselves!
	if unexplained := d.UnknownCapabilitiesExplainThemselves(); len(unexplained) != 0 {
		t.Errorf("unexplained unknown capabilities: %v", unexplained)
	}
}

// TestPermissionDeniedNFTablesProbeDoesNotEstablishPositiveFirewall verifies
// that when nft fails due to lack of root privileges (EPERM), nftables and firewall
// capabilities degrade to unknown and never satisfy hard gates.
func TestPermissionDeniedNFTablesProbeDoesNotEstablishPositiveFirewall(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		NFTables: network.NFTablesState{
			Checked:        true,
			Available:      true, // tool binary exists
			QuerySucceeded: false,
			Reason:         "nft is installed but the ruleset could not be read: exit 1: Operation not permitted (you must be root)",
			Probe: network.Probe{
				Subsystem: "nftables", Operation: "list-tables", Tool: "nft",
				Stage: network.StageExecute, Outcome: network.ProbeExecutionFailed, ExitStatus: 1,
				Detail: "the tool ran but did not succeed",
				Reason: "nft: exit 1: Operation not permitted (you must be root)",
			},
		},
		TrafficControl: network.TCState{
			Checked:        true,
			Available:      true,
			QuerySucceeded: false,
			Reason:         "tc is installed but queue disciplines could not be read: exit 1: Operation not permitted",
			Probe: network.Probe{
				Subsystem: "traffic-control", Operation: "qdisc-show", Tool: "tc",
				Stage: network.StageExecute, Outcome: network.ProbeExecutionFailed, ExitStatus: 1,
				Detail: "the tool ran but did not succeed",
				Reason: "tc: exit 1: RTNETLINK answers: Operation not permitted",
			},
		},
	}

	d := FromSnapshot(snap)

	// Both must be unknown confidence and unavailable.
	for _, c := range []Capability{CapNFTables, CapFirewall} {
		state := d.Capabilities[c]
		if state.Confidence != ConfidenceUnknown {
			t.Errorf("%s confidence = %q, want unknown", c, state.Confidence)
		}
		if state.Available {
			t.Errorf("%s was reported available despite failed query", c)
		}
		if d.Satisfies(c) {
			t.Errorf("%s satisfied hard gate despite failed query", c)
		}
	}

	// No unexplained unknown: the probe record is present and names stage and detail.
	if unexplained := d.UnknownCapabilitiesExplainThemselves(); len(unexplained) != 0 {
		t.Errorf("unexplained unknown capabilities: %v", unexplained)
	}

	// No false confidence: neither claimed observed.
	if falseConf := d.FalseConfidenceCapabilities(); len(falseConf) != 0 {
		t.Errorf("false confidence capabilities: %v", falseConf)
	}
}

// TestExecutionFailureNeverEstablishesPositiveCapability ensures that any probe
// ending in execution_failed cannot produce an observed capability or satisfy hard gates.
func TestExecutionFailureNeverEstablishesPositiveCapability(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		TrafficControl: network.TCState{
			Checked:        true,
			Available:      true,
			QuerySucceeded: false,
			Reason:         "tc is installed but queue disciplines could not be read: exit 1: Operation not permitted",
			Probe: network.Probe{
				Subsystem: "traffic-control", Operation: "qdisc-show", Tool: "tc",
				Stage: network.StageExecute, Outcome: network.ProbeExecutionFailed, ExitStatus: 1,
				Detail: "the tool ran but did not succeed",
				Reason: "tc: exit 1: RTNETLINK answers: Operation not permitted",
			},
		},
	}

	d := FromSnapshot(snap)

	if d.Satisfies(CapTC) {
		t.Error("CapTC satisfied hard gate despite execution failure")
	}
	if d.Satisfies(CapCake) {
		t.Error("CapCake satisfied hard gate despite execution failure")
	}
	if d.Capabilities[CapTC].Confidence == ConfidenceObserved {
		t.Error("CapTC claimed ConfidenceObserved despite execution failure")
	}
}

// TestNotCheckedIsDistinguishableFromEvidence proves that unrun / not_checked
// probes are distinguishable from evidence and execution failure.
func TestNotCheckedIsDistinguishableFromEvidence(t *testing.T) {
	p := NotCheckedProbe("nftables", "list-tables")
	if p.Outcome != network.ProbeNotChecked {
		t.Errorf("outcome = %q, want not_checked", p.Outcome)
	}
	if p.Outcome.OK() {
		t.Error("not_checked reported OK() == true")
	}
	if p.Outcome.BlocksClaim() {
		t.Error("not_checked reported BlocksClaim() == true; unrun probe does not block structural claims")
	}

	// When a subsystem is not checked at all:
	snap := &network.Snapshot{
		Platform:       "linux",
		Supported:      true,
		NFTables:       network.NFTablesState{Checked: false},
		TrafficControl: network.TCState{Checked: false},
	}
	d := FromSnapshot(snap)

	for _, c := range []Capability{CapNFTables, CapFirewall, CapTC, CapCake, CapQoS} {
		if d.Capabilities[c].Confidence != ConfidenceUnknown {
			t.Errorf("%s confidence = %q, want unknown for unchecked subsystem", c, d.Capabilities[c].Confidence)
		}
		if d.Satisfies(c) {
			t.Errorf("%s satisfied hard gate when unchecked", c)
		}
	}
}

// TestInferredCapabilitiesDoNotSatisfyHardGates proves that inferred capabilities
// (CapNAT, CapDHCP, CapDNS) never satisfy hard gates (Satisfies() == false), even
// when Available is true.
func TestInferredCapabilitiesDoNotSatisfyHardGates(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
	}
	d := FromSnapshot(snap)

	for _, c := range []Capability{CapNAT, CapDHCP, CapDNS} {
		state, ok := d.Capabilities[c]
		if !ok {
			t.Fatalf("missing capability %s", c)
		}
		if state.Confidence != ConfidenceInferred {
			t.Errorf("%s confidence = %q, want inferred", c, state.Confidence)
		}
		if !state.Available {
			t.Errorf("%s available = false, want true", c)
		}
		// Hard gate check: Satisfies() must be false!
		if state.Satisfies() {
			t.Errorf("%s.Satisfies() = true; inferred capability must never satisfy hard gate", c)
		}
		if d.Satisfies(c) {
			t.Errorf("d.Satisfies(%s) = true; inferred capability must never satisfy hard gate", c)
		}
	}
}
