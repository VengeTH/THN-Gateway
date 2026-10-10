package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

// simIfaceWithSpeed constructs an observed interface with an explicit link speed.
func simIfaceWithSpeed(name string, idx int, mac, linkKind string, up bool, speed int) network.Interface {
	state := network.LinkDown
	if up {
		state = network.LinkUp
	}

	kindOut := linkKind
	mode := ""
	physical := false

	switch linkKind {
	case "ether":
		physical = true
	case "wlan":
		kindOut, mode, physical = "ether", network.WirelessModeClient, true
		if speed == 0 {
			speed = 433
		}
	}

	return network.Interface{
		Name:         name,
		Index:        idx,
		MAC:          mac,
		Kind:         kindOut,
		Physical:     physical,
		AdminUp:      up,
		Carrier:      up,
		LinkType:     "ether",
		State:        state,
		SpeedMbps:    speed,
		WirelessMode: mode,
	}
}

// hostWithOneGigabitNIC returns a device with only one physical Ethernet port (WAN).
func hostWithOneGigabitNIC() *host.Device {
	snap := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simIfaceWithSpeed("enp0s31f6", 2, "7c:61:70:fd:7f:34", "ether", true, 1000),
			simIfaceWithSpeed("docker0", 4, "02:42:8a:1b:2c:3d", "bridge", true, 0),
			simIfaceWithSpeed("lo", 1, "", "loopback", true, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
	}
	return host.FromSnapshot(snap)
}

// hostWith100MbpsUSBNIC returns the current Dell host carrying the 100M USB adapter.
func hostWith100MbpsUSBNIC() *host.Device {
	snap := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simIfaceWithSpeed("enp0s31f6", 2, "7c:61:70:fd:7f:34", "ether", true, 1000),
			simIfaceWithSpeed("enx00e099001812", 3, "2c:88:6f:45:ad:0c", "ether", false, 100),
			simIfaceWithSpeed("docker0", 4, "02:42:8a:1b:2c:3d", "bridge", true, 0),
			simIfaceWithSpeed("lo", 1, "", "loopback", true, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
	}
	return host.FromSnapshot(snap)
}

// hostWithTwoFastEthernetNICs returns a device carrying two DIFFERENT 100 Mbps
// adapters.
//
// The development-override scoping test needs this: with only one Fast
// Ethernet adapter present, "the other adapter was rejected" proves nothing,
// because an unresolved selector is rejected by any policy at all. The claim
// under test is that naming adapter A does not admit adapter B, so both have
// to genuinely exist and both have to be assignable.
func hostWithTwoFastEthernetNICs() *host.Device {
	snap := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simIfaceWithSpeed("enp0s31f6", 2, "7c:61:70:fd:7f:34", "ether", true, 1000),
			simIfaceWithSpeed("enx00e099001812", 3, "2c:88:6f:45:ad:0c", "ether", true, 100), // approved by name
			simIfaceWithSpeed("enx00e099001813", 4, "2c:88:6f:45:ad:0d", "ether", true, 100), // NOT approved
			simIfaceWithSpeed("lo", 1, "", "loopback", true, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
	}
	return host.FromSnapshot(snap)
}

// hostWithGigabitUSBNIC returns a device with the new Gigabit USB adapter attached.
func hostWithGigabitUSBNIC() *host.Device {
	snap := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simIfaceWithSpeed("enp0s31f6", 2, "7c:61:70:fd:7f:34", "ether", true, 1000),
			simIfaceWithSpeed("enx00e099001812", 3, "2c:88:6f:45:ad:0c", "ether", false, 100),
			simIfaceWithSpeed("enx112233445566", 4, "00:e0:4c:68:01:23", "ether", true, 1000), // Dedicated Gigabit USB NIC
			simIfaceWithSpeed("docker0", 5, "02:42:8a:1b:2c:3d", "bridge", true, 0),
			simIfaceWithSpeed("lo", 1, "", "loopback", true, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
	}
	return host.FromSnapshot(snap)
}

// TestGigabitLANGating_NoLANNIC_Blocked verifies that when no LAN hardware is present or assigned,
// the lan-identified gate blocks activation.
func TestGigabitLANGating_NoLANNIC_Blocked(t *testing.T) {
	dev := hostWithOneGigabitNIC()
	wanID := host.IDFor("7c:61:70:fd:7f:34")

	res := host.Resolve(dev, []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
	})

	gate := roleGate(dev, res, host.RoleLAN, "", productionLANPolicy())
	if gate.Satisfied {
		t.Errorf("expected lan-identified gate to be BLOCKED when no LAN NIC exists, got satisfied")
	}
	if !strings.Contains(gate.Reason, "not assigned") && !strings.Contains(gate.Reason, "unresolved") {
		t.Errorf("expected missing assignment reason, got %q", gate.Reason)
	}
}

// TestGigabitLANGating_100MbpsLANNIC_Blocked verifies that under PRODUCTION
// policy the 100 Mbps Fast Ethernet adapter is rejected and blocks the
// lan-identified gate.
//
// This is the default, and the default has to be tested on its own terms: it
// is not "the override minus the override", it is the behaviour an operator
// gets who has never heard of the override.
func TestGigabitLANGating_100MbpsLANNIC_Blocked(t *testing.T) {
	dev := hostWith100MbpsUSBNIC()
	wanID := host.IDFor("7c:61:70:fd:7f:34")
	usb100mID := host.IDFor("2c:88:6f:45:ad:0c")

	res := host.Resolve(dev, []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
		{Role: host.RoleLAN, Selector: usb100mID},
	})

	gate := roleGate(dev, res, host.RoleLAN, usb100mID, productionLANPolicy())
	if gate.Satisfied {
		t.Errorf("CRITICAL SAFETY DEFECT: a 100 Mbps adapter satisfied the production LAN gate")
	}
	if gate.DevelopmentOverride {
		t.Errorf("production policy reported a development override")
	}
	if !strings.Contains(gate.Reason, "Gigabit") {
		t.Errorf("expected the reason to name the Gigabit requirement, got %q", gate.Reason)
	}
}

// TestGigabitLANGating_GigabitNICDiscovered_HardwarePrerequisiteSatisfied proves that
// a newly attached Gigabit USB adapter is discovered and satisfies the hardware candidate requirement,
// but is NOT automatically adopted without an explicit assignment.
func TestGigabitLANGating_GigabitNICDiscovered_HardwarePrerequisiteSatisfied(t *testing.T) {
	dev := hostWithGigabitUSBNIC()

	// 1. Verify it was discovered as physical Ethernet with 1000 Mbps
	var gigabitNIC *host.Interface
	for _, iface := range dev.PhysicalInterfaces() {
		if iface.SystemName == "enx112233445566" {
			gigabitNIC = &iface
			break
		}
	}
	if gigabitNIC == nil {
		t.Fatalf("new Gigabit USB adapter was not discovered")
	}
	if gigabitNIC.SpeedMbps != 1000 {
		t.Errorf("speed = %d, want 1000 Mbps", gigabitNIC.SpeedMbps)
	}

	// 2. Verify it is NOT automatically adopted as LAN
	unassignedRes := host.Resolve(dev, []host.Assignment{})
	if _, assigned := unassignedRes.Assigned[host.RoleLAN]; assigned {
		t.Errorf("AUTOMATIC ADOPTION DEFECT: unassigned gateway automatically adopted an interface as LAN")
	}

	unassignedGate := roleGate(dev, unassignedRes, host.RoleLAN, "", productionLANPolicy())
	if unassignedGate.Satisfied {
		t.Errorf("lan-identified must not be satisfied without an explicit assignment")
	}
}

// TestGigabitLANGating_GigabitNICAssignedLAN_LanIdentifiedSatisfied proves that once
// the dedicated Gigabit USB adapter is explicitly assigned to LAN, the lan-identified gate passes.
func TestGigabitLANGating_GigabitNICAssignedLAN_LanIdentifiedSatisfied(t *testing.T) {
	dev := hostWithGigabitUSBNIC()
	wanID := host.IDFor("7c:61:70:fd:7f:34")
	gigabitLANID := host.IDFor("00:e0:4c:68:01:23")

	res := host.Resolve(dev, []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
		{Role: host.RoleLAN, Selector: gigabitLANID},
	})

	gate := roleGate(dev, res, host.RoleLAN, gigabitLANID, productionLANPolicy())
	if !gate.Satisfied {
		t.Errorf("expected lan-identified gate to be SATISFIED with Gigabit adapter assigned, got: %s", gate.Reason)
	}
	if gate.Interface != "enx112233445566" {
		t.Errorf("gate interface = %q, want enx112233445566", gate.Interface)
	}
}

// TestGigabitLANGating_BothWANAndLANAssigned_RolePrerequisitesSatisfied verifies that
// with both Gigabit WAN and Gigabit LAN assigned:
// - wan-present passes
// - lan-identified passes
// - no-role-conflicts passes
// - physical-presence STILL blocks (fail closed)
func TestGigabitLANGating_BothWANAndLANAssigned_RolePrerequisitesSatisfied(t *testing.T) {
	dev := hostWithGigabitUSBNIC()
	wanID := host.IDFor("7c:61:70:fd:7f:34")
	gigabitLANID := host.IDFor("00:e0:4c:68:01:23")

	res := host.Resolve(dev, []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
		{Role: host.RoleLAN, Selector: gigabitLANID},
	})

	wanGate := roleGate(dev, res, host.RoleWAN, wanID, productionLANPolicy())
	lanGate := roleGate(dev, res, host.RoleLAN, gigabitLANID, productionLANPolicy())

	if !wanGate.Satisfied {
		t.Errorf("WAN gate failed: %s", wanGate.Reason)
	}
	if !lanGate.Satisfied {
		t.Errorf("LAN gate failed: %s", lanGate.Reason)
	}

	input := activation.GateInput{
		PlanValidated:        true,
		ConfigValid:          true,
		WAN:                  wanGate,
		LAN:                  lanGate,
		NoRoleConflicts:      true,
		HostReadinessOK:      true,
		CapabilitiesObserved: true,
		DigestsFresh:         true,
		ManagementSafe:       true,
		RecoveryOK:           true,
		SubsystemsExecutable: true,
		PresenceConfirmed:    false, // remote operator; no physical presence confirmed
	}

	gates := activation.EvaluateProduction(input)

	if gates.AllSatisfied {
		t.Fatalf("SECURITY VIOLATION: production activation permitted with physical presence withheld")
	}

	blockingMap := make(map[string]bool)
	for _, b := range gates.Blocking {
		blockingMap[b] = true
	}

	if !blockingMap["physical-presence"] {
		t.Errorf("expected physical-presence gate to block, blocking gates: %v", gates.Blocking)
	}
	if blockingMap["wan-present"] || blockingMap["lan-identified"] || blockingMap["no-role-conflicts"] {
		t.Errorf("role gates should be satisfied, but blocked: %v", gates.Blocking)
	}
}

// TestPreflightCommand_OutputAndGating tests the new read-only `thn activation preflight` command.
func TestPreflightCommand_OutputAndGating(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 100_000, 20_000)

	stdout, stderr, code := runCLI(t, "activation", "preflight", "--config", cfgPath)

	if code == ExitOK {
		t.Errorf("preflight must exit non-zero (BLOCKED) when prerequisites are unmet; stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "THN ACTIVATION PREFLIGHT") {
		t.Errorf("missing preflight header; stdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "Physical presence") {
		t.Errorf("missing physical presence row; stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "OVERALL VERDICT: BLOCKED") {
		t.Errorf("missing overall verdict; stdout:\n%s", stdout)
	}
}

// TestActivationInspect_SummaryOutput tests that `thn activation inspect` includes the cutover status block.
func TestActivationInspect_SummaryOutput(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 100_000, 20_000)

	stdout, _, code := runCLI(t, "activation", "inspect", "--config", cfgPath)

	if code != ExitOK {
		t.Errorf("inspect exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "PHYSICAL CUTOVER STATUS:") {
		t.Errorf("missing physical cutover status section; stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Physical presence:") {
		t.Errorf("missing physical presence line; stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Activation verdict: BLOCKED") {
		t.Errorf("missing activation verdict line; stdout:\n%s", stdout)
	}
}
