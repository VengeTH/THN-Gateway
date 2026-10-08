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
//
// # Interface names are OBSERVED, never assumed
//
// An earlier version of this file configured `network.wan: enp0s31f6` and
// `network.lan: enp1s0` and called the live observeHost.
//
// Those are one developer's NIC names. The suite passed on their machine and
// on every Windows machine — where the inspector is unsupported and the tests
// skip — and then failed on the first real gateway, because that gateway does
// not have an `enp1s0`.
//
// A test that names the hardware it runs on is a test that can only ever pass
// on that hardware. Worse, it is the same defect this milestone exists to
// remove, committed into the test suite where it looked like evidence.
//
// So every live assertion below derives its interfaces from the observation
// itself. The machine names nothing; the test asks what is there.

import (
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

// observedAssignable returns the names of interfaces on THIS host that could
// hold a role, in a stable order.
//
// It is the replacement for hardcoding. On a gateway it returns whatever that
// gateway actually has — two NICs, one NIC, four NICs, none — and the tests
// below are written to be meaningful in every case rather than to assume one.
func observedAssignable(t *testing.T) (snap *network.Snapshot, names []string) {
	t.Helper()

	snap, err := network.NewInspector().Inspect(cmdContext())
	if err != nil {
		t.Skipf("could not inspect this host: %v", err)
	}
	if !snap.Supported {
		t.Skip("this host cannot be inspected; the live role paths are unreachable here")
	}

	d := host.FromSnapshot(snap)
	for _, i := range d.RoleCandidates() {
		names = append(names, i.SystemName)
	}
	return snap, names
}

// requireAssignable returns at least n assignable interfaces, or skips.
func requireAssignable(t *testing.T, n int) []string {
	t.Helper()
	_, names := observedAssignable(t)
	if len(names) < n {
		t.Skipf("this host has %d assignable interface(s); %d are needed to exercise this path",
			len(names), n)
	}
	return names
}

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
// Note the DETERMINISTIC half first: `guessyHost` contains a real, plausible
// LAN (`enp1s0`) that is NOT the first interface in sorted order — `docker0`
// sorts before it. The old code would have bound `docker0` and reported the
// gateway ready. That is checked without touching a real machine, so the
// regression cannot reappear merely because no one ran this on a laptop.
//
// The live half then confirms the same thing on whatever host it runs on.
func TestAnUnassignedLANIsNeverGuessed(t *testing.T) {
	t.Run("deterministic fixture", func(t *testing.T) {
		d := host.FromSnapshot(guessyHost())

		res := host.Resolve(d, []host.Assignment{
			{Role: host.RoleWAN, Selector: "enp0s31f6"},
			// LAN deliberately left unassigned.
		})

		if _, assigned := res.Assigned[host.RoleLAN]; assigned {
			t.Fatal("an unassigned LAN role was filled anyway")
		}
		for _, i := range d.Interfaces {
			if i.Role == host.RoleLAN {
				t.Fatalf("discovery assigned role lan to %s", i.SystemName)
			}
		}
	})

	t.Run("live host", func(t *testing.T) {
		names := requireAssignable(t, 1)
		cfg := config.Defaults()
		cfg.Network.WAN = names[0]
		cfg.Network.LAN = "" // the operator has not said which NIC is the LAN

		obs, snap, _, _ := observeHost(cfg)
		if snap == nil || !snap.Supported {
			t.Skip("this host cannot be inspected")
		}

		if obs.LANPresent {
			t.Fatalf("LAN was reported present without being assigned; it was bound to %q. "+
				"The first-match fallback has been reintroduced.", obs.LANName)
		}
		if obs.LANName != "" {
			t.Errorf("LANName = %q, want empty: nothing was assigned", obs.LANName)
		}
		if !obs.WANPresent {
			t.Fatalf("the configured uplink %s was not found on this host", names[0])
		}

		// And the device model must agree, because the readiness gate reads it.
		d := host.FromSnapshot(snap)
		for _, i := range d.Interfaces {
			if i.Role == host.RoleLAN {
				t.Errorf("interface %s was given the LAN role by discovery", i.SystemName)
			}
		}
	})
}

// TestTheWANIsResolvedByAssignmentNotByPosition checks the sibling path.
//
// `network.wan` IS configured, so it must resolve — but to the interface that
// was ASKED FOR, not to whichever one sorts first.
//
// Two assignable interfaces are taken from the observation, so this is
// meaningful on a two-NIC gateway, a one-NIC VM (skipped) and a four-NIC
// server alike.
func TestTheWANIsResolvedByAssignmentNotByPosition(t *testing.T) {
	t.Run("deterministic fixture", func(t *testing.T) {
		d := host.FromSnapshot(guessyHost())

		// Deliberately assign the WAN to the interface that is NOT first in
		// sorted order. Anything positional would get this wrong.
		res := host.Resolve(d, []host.Assignment{
			{Role: host.RoleWAN, Selector: "enp0s31f6"},
			{Role: host.RoleLAN, Selector: "enp1s0"},
		})

		if !res.OK() {
			t.Fatalf("the fixture did not resolve: %+v", res.Problems)
		}
		if got := res.Assigned[host.RoleWAN].SystemName; got != "enp0s31f6" {
			t.Errorf("WAN resolved to %q, want the asked-for enp0s31f6", got)
		}
		if got := res.Assigned[host.RoleLAN].SystemName; got != "enp1s0" {
			t.Errorf("LAN resolved to %q, want the asked-for enp1s0", got)
		}
	})

	t.Run("live host", func(t *testing.T) {
		names := requireAssignable(t, 2)
		cfg := config.Defaults()
		cfg.Network.WAN = names[0]
		cfg.Network.LAN = names[1]

		obs, snap, _, _ := observeHost(cfg)
		if snap == nil || !snap.Supported {
			t.Skip("this host cannot be inspected")
		}

		if !obs.WANPresent {
			t.Fatalf("a configured, existing uplink (%s) was not found", names[0])
		}
		if obs.WANName != names[0] {
			t.Errorf("WAN resolved to %q, want the configured %s", obs.WANName, names[0])
		}
		if !obs.LANPresent {
			t.Fatalf("a configured, existing LAN (%s) was not found", names[1])
		}
		if obs.LANName != names[1] {
			t.Errorf("LAN resolved to %q, want the configured %s", obs.LANName, names[1])
		}
		if obs.WANName == obs.LANName {
			t.Errorf("WAN and LAN both resolved to %s", obs.WANName)
		}
	})
}

// TestAMissingInterfaceIsReportedRatherThanSubstituted proves the negative
// path: a selector that matches nothing must leave the role unfilled, and the
// readiness reason must be actionable rather than merely accurate.
//
// "Accurate" is the weaker requirement and it was the only one originally
// asserted here. The message said what was wrong but not what to do, so an
// operator reading it could not tell whether THN was broken or their
// configuration was. Both facts are required now: what went wrong, what was
// actually seen, what could take the role, and that `thn discover` is how to
// look — without implying that discovery will choose for them.
func TestAMissingInterfaceIsReportedRatherThanSubstituted(t *testing.T) {
	const missing = "thn-test-no-such-interface"

	names := requireAssignable(t, 1)
	cfg := config.Defaults()
	cfg.Network.WAN = names[0]
	cfg.Network.LAN = missing

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

	// What the operator needs in order to act.
	for _, want := range []string{
		string(host.RoleLAN), // which role is broken
		missing,              // what they asked for
		"Observed",           // what is actually there
		"discover",           // how to look at it
	} {
		if !strings.Contains(strings.ToLower(lan.Reason), strings.ToLower(want)) {
			t.Errorf("the reason does not mention %q, so an operator cannot act on it:\n%s",
				want, lan.Reason)
		}
	}

	// And the observed list must be real: this host's actual interfaces.
	if !strings.Contains(lan.Reason, names[0]) {
		t.Errorf("the reason does not list this host's real interface %s:\n%s", names[0], lan.Reason)
	}

	// Discovery must not be presented as something that resolves this on its
	// own. THN does not choose roles, and a message implying otherwise would
	// be a lie about the product.
	lowered := strings.ToLower(lan.Reason)
	for _, forbidden := range []string{"automatically", "will choose", "auto-assign"} {
		if strings.Contains(lowered, forbidden) {
			t.Errorf("the reason implies discovery assigns roles (%q):\n%s", forbidden, lan.Reason)
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

// TestEveryUnresolvedRoleReasonIsActionable pins the operator-facing contract
// on a fixture, so it holds on every platform rather than only on whichever
// host someone happened to run it on.
//
// The rule is: a reason must say what was WRONG, what was SEEN, and what to
// DO — and it must never claim THN will resolve the role itself. An accurate
// diagnostic that leaves an operator with nothing to act on is a support
// ticket, not a fix.
func TestEveryUnresolvedRoleReasonIsActionable(t *testing.T) {
	d := host.FromSnapshot(guessyHost())

	cases := []struct {
		name    string
		assign  []host.Assignment
		role    host.Role
		asked   string
		mustSay []string
		mustNot []string
	}{
		{
			name:   "nothing assigned",
			assign: nil,
			role:   host.RoleLAN,
			asked:  "",
			mustSay: []string{
				"role lan", "not assigned", "docker0", "discover",
			},
			mustNot: []string{"automatically", "will choose"},
		},
		{
			name:   "a selector that matches nothing",
			assign: []host.Assignment{{Role: host.RoleLAN, Selector: "thn-test-no-such-interface"}},
			role:   host.RoleLAN,
			asked:  "thn-test-no-such-interface",
			mustSay: []string{
				"role lan", "thn-test-no-such-interface",
				"Observed", "discover",
			},
			mustNot: []string{"automatically", "will choose"},
		},
		{
			name:    "a selector that can never hold a role",
			assign:  []host.Assignment{{Role: host.RoleWAN, Selector: "lo"}},
			role:    host.RoleWAN,
			asked:   "lo",
			mustSay: []string{"role wan", "loopback", "discover"},
			mustNot: []string{"automatically"},
		},
		{
			name: "one interface claimed by two roles",
			assign: []host.Assignment{
				{Role: host.RoleWAN, Selector: "enp0s31f6"},
				{Role: host.RoleLAN, Selector: "enp0s31f6"},
			},
			role:    host.RoleLAN,
			asked:   "enp0s31f6",
			mustSay: []string{"discover"},
			mustNot: []string{"automatically"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := roleGate(d, host.Resolve(d, c.assign), c.role, c.asked)

			if g.Satisfied {
				t.Fatalf("role %s reported satisfied", c.role)
			}
			if g.Reason == "" {
				t.Fatal("an unresolved gate produced no reason")
			}
			lowered := strings.ToLower(g.Reason)
			for _, want := range c.mustSay {
				if !strings.Contains(lowered, strings.ToLower(want)) {
					t.Errorf("the reason does not mention %q:\n%s", want, g.Reason)
				}
			}
			for _, forbidden := range c.mustNot {
				if strings.Contains(lowered, strings.ToLower(forbidden)) {
					t.Errorf("the reason implies discovery resolves roles itself (%q):\n%s",
						forbidden, g.Reason)
				}
			}
		})
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
