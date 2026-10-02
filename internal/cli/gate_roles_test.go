package cli

// The gate that used to guess.
//
// # What regressed, and what this prevents
//
// `observeHost` used to do this when `network.lan` was empty:
//
//	for i := range snap.Interfaces {
//	    cand := snap.Interfaces[i]
//	    if cand.Name == cfg.Network.WAN || cand.Name == "lo" { continue }
//	    obs.LANPresent = true
//	    break
//	}
//
// `snap.Interfaces` is sorted by NAME, so "first non-loopback, non-WAN" meant
// whichever name sorted first. On a host with any of them that is
// `bond0`, `docker0` or `tailscale0` — never the interface an operator meant.
//
// It then set `obs.LANPresent = true`, and `thn readiness` fed that straight
// into the `lan-identified` activation gate. The gate reported SATISFIED on an
// interface nobody had named. That is precisely the failure the whole role
// model exists to prevent: a gateway that would apply its LAN to the wrong
// link, and report that it was ready.
//
// The fix was to delete the guess, not to refine it.
//
// # What these tests hold
//
// They call the real production function. A test that reimplemented the
// matching would agree with whatever the implementation did, including the
// bug it was written to catch.

import (
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/network"
)

// guessyHost is the shape that made the bug reachable: several interfaces,
// none of which an operator would call "the LAN", and a WAN that is not
// alphabetically first.
func guessyHost() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			// Already sorted by name, exactly as the inspector returns them.
			simInterface("docker0", 2, "02:42:8a:1b:2c:3d", "bridge", false),
			simInterface("enp0s31f6", 3, "aa:bb:cc:dd:ee:01", "ether", true),
			simInterface("enp1s0", 4, "aa:bb:cc:dd:ee:02", "ether", true),
			simInterface("tailscale0", 5, "5a:ab:cd:ef:00:01", "tun", true),
			simInterface("lo", 1, "", "loopback", true),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

// TestAnUnassignedLANIsNeverGuessed is the core regression guard.
//
// Note the host deliberately includes `enp1s0`: a real, plausible LAN. The
// old code would have bound `docker0` (first after `lo` alphabetically among
// non-WAN names) and reported the gateway ready. THN must do neither.
func TestAnUnassignedLANIsNeverGuessed(t *testing.T) {
	cfg := config.Defaults()
	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "" // the operator has not said which NIC is the LAN

	obs, snap, _, device := observeHost(cfg)

	if snap == nil || !snap.Supported {
		t.Skip("this host cannot be inspected; the guess path is unreachable here")
	}

	if obs.LANPresent {
		t.Fatalf("LAN was reported present without being assigned; it was bound to %q. "+
			"The first-match fallback has been reintroduced.", obs.LANName)
	}
	if obs.LANName != "" {
		t.Errorf("LANName = %q, want empty: nothing was assigned", obs.LANName)
	}

	// And the device model must agree, because the readiness gate reads it.
	d := host.FromSnapshot(snap)
	for _, i := range d.Interfaces {
		if i.Role == host.RoleLAN {
			t.Errorf("interface %s was given the LAN role by discovery", i.SystemName)
		}
	}
	_ = device
}

// TestTheWANIsResolvedByAssignmentNotByPosition checks the sibling path.
//
// `network.wan` IS configured here, so it must resolve — but to the interface
// that was ASKED FOR, even though it is not the first one in the sorted list.
func TestTheWANIsResolvedByAssignmentNotByPosition(t *testing.T) {
	cfg := config.Defaults()
	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "enp1s0"

	obs, snap, _, _ := observeHost(cfg)
	if snap == nil || !snap.Supported {
		t.Skip("this host cannot be inspected")
	}

	if !obs.WANPresent {
		t.Fatal("a configured, existing uplink was not found")
	}
	if obs.WANName != "enp0s31f6" {
		t.Errorf("WAN resolved to %q, want the configured enp0s31f6", obs.WANName)
	}
	if !obs.LANPresent {
		t.Fatal("a configured, existing LAN was not found")
	}
	if obs.LANName != "enp1s0" {
		t.Errorf("LAN resolved to %q, want the configured enp1s0", obs.LANName)
	}
}

// TestAMissingInterfaceIsReportedRatherThanSubstituted proves the negative
// path: a selector that matches nothing must leave the role unfilled, and the
// readiness reason must name what WAS observed.
func TestAMissingInterfaceIsReportedRatherThanSubstituted(t *testing.T) {
	cfg := config.Defaults()
	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "thisnicdoesnotexist"

	obs, snap, _, _ := observeHost(cfg)
	if snap == nil || !snap.Supported {
		t.Skip("this host cannot be inspected")
	}

	if obs.LANPresent {
		t.Fatalf("a nonexistent LAN resolved to %q", obs.LANName)
	}

	d := host.FromSnapshot(snap)
	res := host.Resolve(d, roleAssignments(cfg))

	if res.OK() {
		t.Fatal("the resolution reported success for a nonexistent interface")
	}
	lan := roleGate(d, res, host.RoleLAN, cfg.Network.LAN)

	// Part 13: the reason must be actionable, not "interface not found".
	for _, want := range []string{string(host.RoleLAN), "enp0s31f6", "discover"} {
		if !strings.Contains(strings.ToLower(lan.Reason), strings.ToLower(want)) {
			t.Errorf("the reason does not mention %q, so an operator cannot act on it:\n%s",
				want, lan.Reason)
		}
	}
}

// TestAnUnassignedRoleIsDistinguishedFromAMissingOne is the error-model
// requirement, as a test.
//
// "You have not said" and "you said something that is not there" need
// different fixes. Reporting both as "interface not found" sends an operator
// to change the wrong thing.
func TestAnUnassignedRoleIsDistinguishedFromAMissingOne(t *testing.T) {
	snap := guessyHost()
	if snap == nil {
		t.Skip("unreachable")
	}
	d := host.FromSnapshot(snap)

	unassigned := roleGate(d, host.Resolve(d, []host.Assignment{}), host.RoleLAN, "")
	missing := roleGate(d, host.Resolve(d, []host.Assignment{{Role: host.RoleLAN, Selector: "nope0"}}),
		host.RoleLAN, "nope0")

	if unassigned.Satisfied || missing.Satisfied {
		t.Fatal("an unresolved role reported satisfied")
	}
	if unassigned.Reason == missing.Reason {
		t.Errorf("both unresolved roles read the same:\n%q", unassigned.Reason)
	}
	if !strings.Contains(unassigned.Reason, "not assigned") {
		t.Errorf("an unassigned role does not say so:\n%s", unassigned.Reason)
	}
	// The missing case names the selector that found nothing, because that is
	// what the operator has to change.
	if !strings.Contains(missing.Reason, "nope0") {
		t.Errorf("a missing selector is not named in the reason:\n%s", missing.Reason)
	}
}

// TestAnUninspectableHostBlocksBothRolesRatherThanPassingThem is the
// fail-closed rule at the gate boundary.
//
// A developer laptop that cannot inspect itself must not produce a readiness
// report that says the roles are fine.
func TestAnUninspectableHostBlocksBothRolesRatherThanPassingThem(t *testing.T) {
	d := host.FromSnapshot(&network.Snapshot{Supported: false, Platform: "windows"})
	res := host.Resolve(d, nil)

	wan := roleGate(d, res, host.RoleWAN, "")
	lan := roleGate(d, res, host.RoleLAN, "")

	if wan.Satisfied || lan.Satisfied {
		t.Fatal("an uninspected host satisfied a role gate")
	}
	for _, g := range []struct {
		name, reason string
	}{
		{"wan", wan.Reason}, {"lan", lan.Reason},
	} {
		if g.reason == "" {
			t.Errorf("the %s gate blocked with no reason", g.name)
		}
		if !strings.Contains(g.reason, "discover") {
			t.Errorf("the %s gate does not say how to proceed:\n%s", g.name, g.reason)
		}
	}
}

// TestRoleAssignmentsEmitStableIdentitiesNotKernelNames is the onboarding
// contract.
//
// `thn discover --emit` exists so an operator does not transcribe kernel names
// by hand and get them subtly wrong. If it emitted names, the configuration
// would break the moment a NIC moved slots — the exact problem the milestone
// set out to remove.
func TestRoleAssignmentsEmitStableIdentitiesNotKernelNames(t *testing.T) {
	d := host.FromSnapshot(guessyHost())
	res := host.Resolve(d, []host.Assignment{
		{Role: host.RoleWAN, Selector: "enp0s31f6"},
		{Role: host.RoleLAN, Selector: "enp1s0"},
	})
	if !res.OK() {
		t.Fatalf("the fixture did not resolve: %+v", res.Problems)
	}
	applyResolutionTo(d, res)

	out := RenderAssignments(d)

	for _, want := range []string{"network:", "wan:", "lan:", "hw:"} {
		if !strings.Contains(out, want) {
			t.Errorf("the emitted fragment does not contain %q:\n%s", want, out)
		}
	}
	for _, kernelName := range []string{"enp0s31f6", "enp1s0"} {
		if strings.Contains(out, kernelName+"\n") {
			t.Errorf("the emitted fragment names the kernel interface %q:\n%s", kernelName, out)
		}
	}

	// And it must not pretend to have applied anything.
	if !strings.Contains(out, "Nothing above was applied") {
		t.Errorf("the fragment does not state that nothing was applied:\n%s", out)
	}
}

// TestRenderedProfilesDistinguishAvailableFromNot is the beginner-facing
// half of the profile model.
func TestRenderedProfilesDistinguishAvailableFromNot(t *testing.T) {
	// A host with one wired NIC and no wireless cannot be an access point.
	snap := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simInterface("ens3", 2, "cc:dd:ee:ff:00:01", "ether", true),
			simInterface("lo", 1, "", "loopback", true),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
	d := host.FromSnapshot(snap)
	res := host.Resolve(d, []host.Assignment{
		{Role: host.RoleWAN, Selector: "ens3"},
		{Role: host.RoleLAN, Selector: "ens3"},
	})
	out := RenderProfiles(evaluateProfiles(d, res))

	for _, want := range []string{"Profiles", "access-point", "NOT AVAILABLE"} {
		if !strings.Contains(out, want) {
			t.Errorf("the profile rendering does not contain %q:\n%s", want, out)
		}
	}

	// The access point needs wireless; this host has none, so the rendering
	// must say which capability was missing rather than only that it failed.
	if !strings.Contains(out, "wireless-ap") {
		t.Errorf("the rendering does not name the missing capability:\n%s", out)
	}
}
