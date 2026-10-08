package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

// Explicit assignment, asserted end to end.
//
// # What these tests are for
//
// The milestone's design principle is one sentence: the administrator decides
// the topology, and THN says whether that decision is currently resolvable.
//
// Every test below attacks one of the ways that sentence can be quietly
// broken — by letting hardware acquire a role, by substituting hardware, by
// keying a binding on a name, or by collapsing two of the four states
// (observed / assigned / resolved / ready) into one.
//
// # The store is real
//
// These tests open an actual SQLite database in a temp directory and reopen
// it. A fake would pass whether or not the assignment survived a restart,
// and surviving a restart is the entire claim.

// gwHost builds a two-NIC host plus the virtual links a real gateway has.
//
// The NICs carry DIFFERENT hardware addresses from any other host in this
// package, so a selector cannot accidentally match by coincidence.
func gwHost() *host.Device {
	snap := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simIface("enp0s31f6", 2, "aa:bb:cc:00:00:01", "ether", true),
			simIface("enp1s0", 3, "aa:bb:cc:00:00:02", "ether", true),
			simIface("docker0", 4, "02:42:8a:1b:2c:3d", "bridge", true),
			simIface("veth9a@if4", 5, "9a:1b:2c:3d:4e:5f", "veth", true),
			simIface("lo", 1, "", "loopback", true),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
	return host.FromSnapshot(snap)
}

// simIface builds one observed interface for these tests.
//
// It sets Physical and SpeedMbps the way ParseLinks would, because those two
// are computed at the parsing boundary and a fixture that leaves them false
// while claiming a gigabit link renders as "every interface is virtual at
// 1 Gbps" — which is not a fixture, it is a different machine.
func simIface(name string, idx int, mac, linkKind string, up bool) network.Interface {
	state := network.LinkDown
	if up {
		state = network.LinkUp
	}

	kindOut := linkKind
	mode := ""
	physical := false
	speed := 0

	switch linkKind {
	case "ether":
		physical, speed = true, 1000
	case "wlan":
		// This is what `ip` reports on a mac80211 driver: an Ethernet link
		// type with no wireless object. The wireless identity comes from
		// nl80211, which is why the mode is carried alongside.
		kindOut, mode, physical, speed = "ether", network.WirelessModeClient, true, 433
	}

	return network.Interface{
		Name:         name,
		Index:        idx,
		MAC:          mac,
		MTU:          1500,
		SpeedMbps:    speed,
		Kind:         kindOut,
		LinkType:     "ether",
		Physical:     physical,
		State:        state,
		AdminUp:      true,
		Carrier:      up,
		WirelessMode: mode,
		Role:         network.RoleUnassigned,
	}
}

func idOf(mac string) string { return host.IDFor(mac) }

// # A — explicit assignment is recorded and persisted.

func TestAnExplicitAssignmentIsRecordedAndSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	wanID := idOf("aa:bb:cc:00:00:01")
	lanID := idOf("aa:bb:cc:00:00:02")

	write(t, path, []state.InterfaceAssignment{
		{Role: "wan", Selector: wanID, IDKind: "hardware"},
		{Role: "lan", Selector: lanID, IDKind: "hardware"},
	})

	// Reopen: a fresh handle, a fresh connection. This is the restart.
	got := read(t, path)
	if len(got) != 2 {
		t.Fatalf("got %d assignments after reopen, want 2", len(got))
	}
	byRole := map[string]string{}
	for _, a := range got {
		byRole[a.Role] = a.Selector
	}
	if byRole["wan"] != wanID {
		t.Errorf("wan = %q, want %q", byRole["wan"], wanID)
	}
	if byRole["lan"] != lanID {
		t.Errorf("lan = %q, want %q", byRole["lan"], lanID)
	}
	if byRole["wan"] == byRole["lan"] {
		t.Error("both roles point at the same interface")
	}
}

// # B — no positional inference.
//
// The two orders are the whole test. If anything in the path from a stored
// assignment to a resolved role consulted interface order, these disagree.

func TestInterfaceOrderingCannotChangeAnAssignment(t *testing.T) {
	wanID := idOf("aa:bb:cc:00:00:01")
	lanID := idOf("aa:bb:cc:00:00:02")

	forward := gwHost()
	reverse := gwHost()
	// Rotate the tail so order differs but content does not.
	reverse.Interfaces = append(reverse.Interfaces[3:], reverse.Interfaces[:3]...)

	for name, d := range map[string]*host.Device{"forward": forward, "reversed": reverse} {
		res := host.Resolve(d, []host.Assignment{
			{Role: host.RoleWAN, Selector: wanID},
			{Role: host.RoleLAN, Selector: lanID},
		})
		if !res.OK() {
			t.Fatalf("%s: resolution failed: %+v", name, res.Problems)
		}
		if res.Assigned[host.RoleWAN].SystemName != "enp0s31f6" {
			t.Errorf("%s: WAN resolved to %q", name, res.Assigned[host.RoleWAN].SystemName)
		}
		if res.Assigned[host.RoleLAN].SystemName != "enp1s0" {
			t.Errorf("%s: LAN resolved to %q", name, res.Assigned[host.RoleLAN].SystemName)
		}
	}
}

// An interface that merely EXISTS must not acquire a role.
func TestAnObservedInterfaceNeverAcquiresARoleOnItsOwn(t *testing.T) {
	d := gwHost()
	if len(d.RoleCandidates()) < 2 {
		t.Fatal("the fixture is missing candidates")
	}

	res := host.Resolve(d, nil)
	if len(res.Assigned) != 0 {
		t.Errorf("resolving nothing produced %d roles", len(res.Assigned))
	}
	for _, i := range d.Interfaces {
		if i.Role != host.RoleUnassigned {
			t.Errorf("%s acquired role %q from being observed", i.SystemName, i.Role)
		}
	}
}

// # C — a missing interface is never substituted.

func TestAMissingInterfaceIsNeverSubstituted(t *testing.T) {
	d := gwHost()
	const absent = "hw:0000000000000000"

	res := host.Resolve(d, []host.Assignment{{Role: host.RoleWAN, Selector: absent}})

	if wan, filled := res.Assigned[host.RoleWAN]; filled {
		t.Fatalf("a missing uplink was silently replaced by %q", wan.SystemName)
	}
	if len(res.Problems) == 0 {
		t.Fatal("no problem was reported for a missing uplink")
	}
	if res.Problems[0].Code != "unknown-interface" {
		t.Errorf("code = %q, want unknown-interface", res.Problems[0].Code)
	}

	// And the other interface was NOT taken as a consolation prize.
	if lan, filled := res.Assigned[host.RoleLAN]; filled {
		t.Errorf("the LAN role was filled by %q despite no assignment", lan.SystemName)
	}
}

// The store must also refuse to invent one: the binding persists, unresolved.
func TestAMissingInterfaceLeavesTheBindingIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	const absent = "hw:0000000000000000"

	write(t, path, []state.InterfaceAssignment{{Role: "wan", Selector: absent}})

	got := read(t, path)
	if len(got) != 1 {
		t.Fatalf("the binding was altered by the interface being absent: %+v", got)
	}
	if got[0].Selector != absent {
		t.Errorf("selector = %q, want %q", got[0].Selector, absent)
	}
	if got[0].Role != "wan" {
		t.Errorf("role = %q; the binding drifted to another role", got[0].Role)
	}
}

// # D — a kernel name change must not lose the assignment.

func TestAKernelRenameKeepsTheAssignment(t *testing.T) {
	wanID := idOf("aa:bb:cc:00:00:01")
	lanID := idOf("aa:bb:cc:00:00:02")

	// Before: the kernel's predictable names.
	before := host.FromSnapshot(&network.Snapshot{
		Supported: true,
		Interfaces: []network.Interface{
			simIface("enp0s31f6", 2, "aa:bb:cc:00:00:01", "ether", true),
			simIface("enp1s0", 3, "aa:bb:cc:00:00:02", "ether", true),
			simIface("lo", 1, "", "loopback", true),
		},
	})

	// After: the same hardware, renamed — different names, different
	// indices, identical hardware addresses.
	after := host.FromSnapshot(&network.Snapshot{
		Supported: true,
		Interfaces: []network.Interface{
			simIface("eth0", 7, "aa:bb:cc:00:00:02", "ether", true),
			simIface("eth1", 8, "aa:bb:cc:00:00:01", "ether", true),
			simIface("lo", 1, "", "loopback", true),
		},
	})

	assign := []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
		{Role: host.RoleLAN, Selector: lanID},
	}

	first := host.Resolve(before, assign)
	if !first.OK() {
		t.Fatalf("before: %+v", first.Problems)
	}

	second := host.Resolve(after, assign)
	if !second.OK() {
		t.Fatalf("after the rename the assignment failed: %+v", second.Problems)
	}

	// The roles follow the HARDWARE, so their kernel names change with it.
	if got := second.Assigned[host.RoleWAN].SystemName; got != "eth1" {
		t.Errorf("WAN is now %q; the identity did not survive the rename", got)
	}
	if got := second.Assigned[host.RoleLAN].SystemName; got != "eth0" {
		t.Errorf("LAN is now %q; the identity did not survive the rename", got)
	}
	if first.Assigned[host.RoleWAN].ID != second.Assigned[host.RoleWAN].ID {
		t.Error("the stored identity itself changed across a rename")
	}
}

// # E — virtual links are refused, with a reason.

func TestVirtualLinksAreRefusedWithAReason(t *testing.T) {
	d := gwHost()

	cases := []struct{ name, wantCode string }{
		{"lo", "not-assignable"},
		{"docker0", ""}, // a bridge IS assignable; see the note below
		{"veth9a@if4", "not-assignable"},
		{"nosuchiface", "unknown-interface"},
	}

	for _, c := range cases {
		p, refused := checkAssignable(d, c.name)
		if c.wantCode == "" {
			if refused {
				t.Errorf("%s was refused (%s); a bridge is a legitimate LAN", c.name, p.Message)
			}
			continue
		}
		if !refused {
			t.Errorf("%s was accepted; it must be refused", c.name)
			continue
		}
		if p.Code != c.wantCode {
			t.Errorf("%s: code = %q, want %q", c.name, p.Code, c.wantCode)
		}
		if p.Message == "" {
			t.Errorf("%s: refusal carries no reason", c.name)
		}
	}

	// The refusal must be renderable into something an operator can act on.
	out := RenderAssignmentRefusal(d, "veth9a@if4", host.RoleWAN, host.Problem{
		Code: "not-assignable", Message: "veth9a@if4 is veth and cannot hold a role",
	})
	for _, want := range []string{"Cannot assign", "Reason:", "Suggested action:", "Nothing was changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal does not contain %q:\n%s", want, out)
		}
	}
}

// The model, not the CLI, is what marks a veth unassignable — and it must
// survive the whole path into a diagnostic.
func TestAContainerEndpointIsRefusedAtResolutionToo(t *testing.T) {
	d := gwHost()
	res := host.Resolve(d, []host.Assignment{{Role: host.RoleWAN, Selector: "veth9a@if4"}})

	if res.OK() {
		t.Fatal("a container endpoint was accepted as an uplink")
	}
	if res.Problems[0].Code != "not-assignable" {
		t.Errorf("code = %q, want not-assignable", res.Problems[0].Code)
	}
}

// # F — a wireless client is assignable.
//
// The milestone is explicit that role validation must not encode a topology
// policy. A wireless client is a legitimate uplink in a topology that wants
// one, and rejecting it would be THN inventing requirements.
func TestAWirelessClientIsAssignableToARole(t *testing.T) {
	d := host.FromSnapshot(&network.Snapshot{
		Supported: true,
		Interfaces: []network.Interface{
			simIface("wlp2s0", 3, "aa:bb:cc:00:00:03", "wlan", true),
			simIface("enp1s0", 2, "aa:bb:cc:00:00:02", "ether", true),
			simIface("lo", 1, "", "loopback", true),
		},
	})

	for _, selector := range []string{"wlp2s0", idOf("aa:bb:cc:00:00:03")} {
		if p, refused := checkAssignable(d, selector); refused {
			t.Errorf("wireless %s was refused: %s — THN must not require a role to be Ethernet",
				selector, p.Message)
		}
	}

	// And it resolves, as a WAN.
	res := host.Resolve(d, []host.Assignment{{Role: host.RoleWAN, Selector: "wlp2s0"}})
	if !res.OK() {
		t.Fatalf("a wireless uplink did not resolve: %+v", res.Problems)
	}
	if res.Assigned[host.RoleWAN].SystemName != "wlp2s0" {
		t.Errorf("WAN resolved to %q", res.Assigned[host.RoleWAN].SystemName)
	}
}

// # G — duplicate and conflicting assignments.

func TestReassigningARoleReplacesItExplicitly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	first := idOf("aa:bb:cc:00:00:01")
	second := idOf("aa:bb:cc:00:00:02")

	write(t, path, []state.InterfaceAssignment{{Role: "wan", Selector: first}})

	previous, conflict, err := put(t, path, state.InterfaceAssignment{Role: "wan", Selector: second})
	if err != nil {
		t.Fatalf("reassigning a role should succeed: %v", err)
	}
	if conflict != nil {
		t.Fatalf("reassigning the SAME role reported a conflict: %+v", conflict)
	}
	if previous == nil || previous.Selector != first {
		t.Errorf("the previous binding was not reported: %+v", previous)
	}

	got := read(t, path)
	if len(got) != 1 {
		t.Fatalf("reassignment produced %d rows; a role is single-valued", len(got))
	}
	if got[0].Selector != second {
		t.Errorf("selector = %q, want the newly assigned %q", got[0].Selector, second)
	}
}

func TestOneInterfaceCannotHoldTwoRoles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	wanID := idOf("aa:bb:cc:00:00:01")

	write(t, path, []state.InterfaceAssignment{{Role: "wan", Selector: wanID}})

	previous, conflict, err := put(t, path, state.InterfaceAssignment{Role: "lan", Selector: wanID})
	if err == nil {
		t.Fatal("one interface was accepted for two roles")
	}
	if conflict == nil {
		t.Fatal("no conflict was described")
	}
	if conflict.ExistingRole != "wan" || conflict.WantedRole != "lan" {
		t.Errorf("conflict = %+v; it does not name both roles", conflict)
	}
	if previous != nil {
		t.Errorf("a refused write reported a replacement: %+v", previous)
	}

	// And the store is unchanged: one role, one interface.
	got := read(t, path)
	if len(got) != 1 || got[0].Role != "wan" {
		t.Errorf("the store changed despite the refusal: %+v", got)
	}

	// The renderer must say what to do about it.
	out := RenderAssignmentConflict(conflict)
	for _, want := range []string{"Cannot assign", "already assigned", "thn interface unassign", "Nothing was changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the conflict rendering lacks %q:\n%s", want, out)
		}
	}
}

// # H — persistence across a rename, in the store, not just in a fixture.

func TestAStoredAssignmentIsKeyedByIdentityNotByName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	wanID := idOf("aa:bb:cc:00:00:01")

	// The operator assigned by stable ID. The store must hold that, not
	// whatever kernel name happened to be current.
	write(t, path, []state.InterfaceAssignment{{Role: "wan", Selector: wanID}})

	got := read(t, path)
	if len(got) != 1 {
		t.Fatalf("got %d assignments", len(got))
	}
	if strings.HasPrefix(got[0].Selector, "eth") || strings.HasPrefix(got[0].Selector, "enp") {
		t.Errorf("the store holds a kernel name (%q) where a stable identity was given", got[0].Selector)
	}
	if !strings.HasPrefix(got[0].Selector, "hw:") {
		t.Errorf("selector = %q, want a stable identity", got[0].Selector)
	}
}

// # I — observed / assigned / resolved / ready are four different things.

func TestTheFourStatesAreDistinct(t *testing.T) {
	d := gwHost()
	path := filepath.Join(t.TempDir(), "state.db")
	wanID := idOf("aa:bb:cc:00:00:01")

	// OBSERVED but not ASSIGNED: hardware exists, nothing was said about it.
	if len(d.RoleCandidates()) == 0 {
		t.Fatal("no observed candidates")
	}
	res := host.Resolve(d, nil)
	if _, filled := res.Assigned[host.RoleWAN]; filled {
		t.Error("an observed interface satisfied an unassigned role")
	}

	// ASSIGNED and RESOLVED: the statement names present hardware.
	write(t, path, []state.InterfaceAssignment{{Role: "wan", Selector: wanID}})
	resolved := host.Resolve(d, []host.Assignment{{Role: host.RoleWAN, Selector: wanID}})
	if !resolved.OK() {
		t.Fatalf("an assigned, present interface did not resolve: %+v", resolved.Problems)
	}

	// ASSIGNED but NOT RESOLVED: the statement names absent hardware.
	const absent = "hw:0000000000000000"
	write(t, path, []state.InterfaceAssignment{{Role: "wan", Selector: absent}})
	unresolved := host.Resolve(d, []host.Assignment{{Role: host.RoleWAN, Selector: absent}})
	if unresolved.OK() {
		t.Fatal("an absent interface satisfied an assigned role")
	}

	// READY is a fifth thing entirely, and lives in activation. The point
	// here is that none of the above produces it: readiness still reports
	// the build as the blocker.
	in := activation.GateInput{
		WAN:           activation.RoleGate{Role: "wan", Satisfied: true},
		LAN:           activation.RoleGate{Role: "lan"},
		PlanValidated: true,
		ConfigValid:   true,
	}
	if activation.Evaluate(in).AllSatisfied {
		t.Error("resolved role made the activation gates pass")
	}
}

// # Precedence between the document and the store.

func TestTheDocumentWinsAndADisagreementIsReported(t *testing.T) {
	cfg := config.Defaults()
	cfg.Network.WAN = idOf("aa:bb:cc:00:00:01")

	stored := []state.InterfaceAssignment{
		{Role: "wan", Selector: idOf("aa:bb:cc:00:00:02")}, // disagrees
		{Role: "lan", Selector: idOf("aa:bb:cc:00:00:02")}, // does not
	}

	bindings, conflicts, fromConfig := mergeBindings(cfg, stored)

	if len(conflicts) != 1 {
		t.Fatalf("got %d conflicts, want 1: %+v", len(conflicts), conflicts)
	}
	if conflicts[0].Role != "wan" {
		t.Errorf("the conflict names role %q, want wan", conflicts[0].Role)
	}

	wanSel := selectorFor(bindings, host.RoleWAN)
	if wanSel != cfg.Network.WAN {
		t.Errorf("wan bound to %q, want the documented %q", wanSel, cfg.Network.WAN)
	}
	if !fromConfig[host.RoleWAN] {
		t.Error("the winning wan binding was not marked as coming from the document")
	}
	if fromConfig[host.RoleLAN] {
		t.Error("the stored lan binding was wrongly marked as coming from the document")
	}

	// And it resolves against real hardware.
	d := gwHost()
	res := host.Resolve(d, bindings)
	if !res.OK() {
		t.Fatalf("merged bindings did not resolve: %+v", res.Problems)
	}
	if res.Assigned[host.RoleWAN].SystemName != "enp0s31f6" {
		t.Errorf("wan resolved to %q, want enp0s31f6", res.Assigned[host.RoleWAN].SystemName)
	}
}

func TestAStoredBindingFillsARoleTheDocumentLeavesEmpty(t *testing.T) {
	cfg := config.Defaults() // network.wan and network.lan are both empty

	bindings, conflicts, fromConfig := mergeBindings(cfg, []state.InterfaceAssignment{
		{Role: "wan", Selector: idOf("aa:bb:cc:00:00:01")},
	})

	if len(conflicts) != 0 {
		t.Fatalf("an empty document cannot conflict: %+v", conflicts)
	}
	if fromConfig[host.RoleWAN] {
		t.Error("a stored binding was attributed to the document")
	}
	if got := selectorFor(bindings, host.RoleWAN); got != idOf("aa:bb:cc:00:00:01") {
		t.Errorf("wan bound to %q", got)
	}
}

// Roles with no configuration key can ONLY be bound by assignment.
func TestRolesWithoutAConfigKeyAreStillAssignable(t *testing.T) {
	cfg := config.Defaults()

	bindings, _, _ := mergeBindings(cfg, []state.InterfaceAssignment{
		{Role: "mgmt", Selector: idOf("aa:bb:cc:00:00:01")},
		{Role: "guest", Selector: idOf("aa:bb:cc:00:00:02")},
	})

	for _, r := range []host.Role{host.RoleMGMT, host.RoleGuest} {
		if selectorFor(bindings, r) == "" {
			t.Errorf("role %s could not be bound at all", r)
		}
	}

	d := gwHost()
	res := host.Resolve(d, bindings)
	if !res.OK() {
		t.Fatalf("mgmt/guest assignments did not resolve: %+v", res.Problems)
	}
}

func selectorFor(b []host.Assignment, r host.Role) string {
	for _, a := range b {
		if a.Role == r {
			return a.Selector
		}
	}
	return ""
}
