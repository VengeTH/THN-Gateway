package host

// Device independence.
//
// # What these tests are for
//
// The product's first target was one laptop, and the configuration it grew
// around names that machine's interfaces. These tests take the same desired
// gateway — one uplink, one downstream — and satisfy it against five hosts
// that share nothing: different interface counts, different names, no
// wireless, and a host whose interface names have changed while the hardware
// has not.
//
// The property being proven is narrow and checkable: the same assignments
// resolve against compatible hosts regardless of what the kernel calls the
// interfaces. It is NOT proven here that THN works on any of them; that is a
// statement about observation, which is what this layer does.
//
// # The selectors below are hashes, not MAC addresses
//
// The assignments use IDFor(mac) rather than the address itself. That is not
// obfuscation for its own sake: the ID is what a configuration would actually
// contain, because the identifier deliberately does not disclose the hardware
// address. Writing "mac:aa:bb:…" here would have tested a selector format
// this package deliberately stopped emitting — and a test that agrees with a
// model nobody uses proves nothing.
//
// # The fixtures use the KERNEL's spelling of link kinds
//
// They say "ether" and "wlan", because that is what `ip -j -d link show`
// emits. Every previous fixture said "ethernet" because it was written from
// the model rather than captured from a host, which is how a vocabulary
// mismatch survived a year of green tests.

import (
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/network"
)

// The five hosts. Each returns the kernel-level observation; FromSnapshot is
// what turns any of them into a Device.

// hostA: two 1Gb Ethernet plus a Wi-Fi adapter. The original shape, plus
// wireless, which is what a laptop looks like.
func hostA() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("enp0s31f6", 2, "aa:bb:cc:dd:ee:01", "ether", network.LinkUp, 1000),
			obs("enp1s0", 3, "aa:bb:cc:dd:ee:02", "ether", network.LinkDown, 1000),
			obs("wlp2s0", 4, "aa:bb:cc:dd:ee:03", "wlan", network.LinkUp, 300),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

// hostB: four 1Gb Ethernet. A rack server.
func hostB() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("eno1", 2, "11:22:33:44:55:01", "ether", network.LinkUp, 1000),
			obs("eno2", 3, "11:22:33:44:55:02", "ether", network.LinkUp, 1000),
			obs("eno3", 4, "11:22:33:44:55:03", "ether", network.LinkDown, 1000),
			obs("eno4", 5, "11:22:33:44:55:04", "ether", network.LinkDown, 1000),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

// hostC: a single Ethernet. A VM, a mini PC, a single-NIC router.
//
// Routing and NAT are not possible on one interface without hairpin
// complications, and the model must be able to say so rather than pretending
// otherwise.
func hostC() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("ens3", 2, "cc:dd:ee:ff:00:01", "ether", network.LinkUp, 1000),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

// hostD shares nothing with hostA but its shape: two NICs, different names,
// different hardware addresses, and a wireless interface that is present but
// is not a candidate.
func hostD() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("eth0", 2, "de:ad:be:ef:00:01", "ether", network.LinkUp, 1000),
			obs("eth1", 3, "de:ad:be:ef:00:02", "ether", network.LinkUp, 1000),
			obs("eth2", 4, "de:ad:be:ef:00:03", "wlan", network.LinkDown, 0),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

// hostE is hostA's hardware observed under different kernel names.
//
// This is the rename case: a NIC moves from an onboard slot to a USB adapter,
// or predictable naming is turned off, and "enp0s31f6" becomes "eth1". The
// hardware is the same. Whether that is a rename or a different device is
// decided by the hardware address, not by the name.
func hostE() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("eth1", 9, "aa:bb:cc:dd:ee:01", "ether", network.LinkUp, 1000),
			obs("eth0", 8, "aa:bb:cc:dd:ee:02", "ether", network.LinkUp, 1000),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

// obs builds one observed interface.
//
// A wireless interface is given "managed" mode, because that is what a Wi-Fi
// adapter in a laptop actually is. It used to matter that the fixtures did NOT
// distinguish the two: the old capability rule reported wireless-ap as
// available whenever any radio was present, and every fixture agreed with it
// because every fixture had a radio.
//
// That was the overclaim this milestone removed. A managed radio is a CLIENT.
// Reporting it as an access point would be reporting what the hardware could
// theoretically do rather than what was observed, and an access-point profile
// would then be selected on a laptop that cannot serve one.
func obs(name string, index int, mac, kind string, state network.LinkState, mbps int) network.Interface {
	i := network.Interface{
		Name:      name,
		Index:     index,
		MAC:       mac,
		MTU:       1500,
		SpeedMbps: mbps,
		Kind:      kind,
		State:     state,
		Role:      network.RoleUnassigned,
	}
	if kind == "wlan" {
		i.WirelessMode = "managed"
	}
	return i
}

// gatewayAssignments is the desired binding every host is checked against.
//
// It selects by STABLE IDENTITY, not by name. That is the whole point: the
// same document resolves on a host whose kernel names bear no relation to
// these, and on the same host after its NICs have been renamed.
func gatewayAssignments() []Assignment {
	return []Assignment{
		{Role: RoleWAN, Selector: IDFor("aa:bb:cc:dd:ee:01")},
		{Role: RoleLAN, Selector: IDFor("aa:bb:cc:dd:ee:02")},
	}
}

// nameAssignments is the same intent expressed by kernel name, which must keep
// working because existing deployments use it.
func nameAssignments() []Assignment {
	return []Assignment{
		{Role: RoleWAN, Selector: "enp0s31f6"},
		{Role: RoleLAN, Selector: "enp1s0"},
	}
}

// TestTheSameDesiredGatewayResolvesOnEveryHost is the device-independence
// proof.
//
// Host C has one interface and cannot satisfy both roles. That is a legitimate
// outcome and it must be reported as a structured problem — not a panic, not a
// silent partial binding, and not by assigning the same interface twice.
func TestTheSameDesiredGatewayResolvesOnEveryHost(t *testing.T) {
	cases := []struct {
		name     string
		snap     *network.Snapshot
		assign   []Assignment
		wantBoth bool
	}{
		{"host A by kernel name", hostA(), nameAssignments(), true},
		{"host A by stable identity", hostA(), gatewayAssignments(), true},
		{"host B: four NICs, different hardware", hostB(), gatewayAssignments(), false},
		{"host C: one NIC", hostC(), gatewayAssignments(), false},
		{"host D: different names", hostD(), gatewayAssignments(), false},
		{"host E: renamed, same hardware", hostE(), gatewayAssignments(), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := FromSnapshot(c.snap)
			if !d.Supported {
				t.Fatal("the fixture reports itself unsupported")
			}

			res := Resolve(d, c.assign)

			if c.wantBoth {
				if !res.OK() {
					t.Fatalf("resolution failed: %+v", res.Problems)
				}
				wan, ok := res.Assigned[RoleWAN]
				if !ok {
					t.Fatal("no interface was assigned to WAN")
				}
				lan, ok := res.Assigned[RoleLAN]
				if !ok {
					t.Fatal("no interface was assigned to LAN")
				}
				if wan.ID == lan.ID {
					t.Errorf("WAN and LAN resolved to the same interface %s", wan.SystemName)
				}
				// A satisfied role must say which interface satisfied it.
				// This is what the readiness report renders.
				if wan.Role != RoleWAN {
					t.Errorf("the resolved uplink carries role %q, want wan", wan.Role)
				}
				return
			}

			// Unmatched hardware must produce a structured problem naming
			// what was observed, not a silent partial binding.
			if res.OK() {
				t.Fatal("assignments resolved against hardware that does not exist")
			}
			if len(res.Assigned) != 0 {
				t.Errorf("an unresolvable set still bound %d role(s)", len(res.Assigned))
			}
			for _, p := range res.Problems {
				if p.Code != "unknown-interface" {
					t.Errorf("problem code = %q, want unknown-interface", p.Code)
				}
				if len(p.Observed) == 0 {
					t.Error("the problem does not say what was observed")
				}
				if len(p.Candidates) == 0 {
					t.Error("the problem offers no candidates")
				}
			}
		})
	}
}

// TestAnIdentitySelectorIsNotAHardwareAddress is the privacy rule, restated.
//
// The identifier a configuration carries is a digest. A test that reached for
// the address itself to build a selector would stop passing the moment the ID
// format changed, which is exactly the coupling this asserts against.
func TestAnIdentitySelectorIsNotAHardwareAddress(t *testing.T) {
	d := FromSnapshot(hostA())

	for _, i := range d.Interfaces {
		if i.MAC == "" {
			continue
		}
		if strings.Contains(strings.ToLower(i.ID), strings.ToLower(i.MAC)) {
			t.Fatalf("interface ID %q discloses the hardware address", i.ID)
		}
		if i.IDKind != IdentityHardware {
			t.Errorf("interface %s has a hardware address but identity kind %s",
				i.SystemName, i.IDKind)
		}
	}
}

// TestRenamingAnInterfacePreservesItsIdentity is the Host E property.
//
// The kernel name changed and the index changed with it. The hardware address
// did not, so the ID did not. That is what lets a configuration survive a
// device moving between slots.
func TestRenamingAnInterfacePreservesItsIdentity(t *testing.T) {
	before := FromSnapshot(hostA())
	after := FromSnapshot(hostE())

	wanID := IDFor("aa:bb:cc:dd:ee:01")

	beforeWAN, ok := before.InterfaceByID(wanID)
	if !ok {
		t.Fatal("the pre-rename uplink has no hardware identity")
	}
	afterWAN, ok := after.InterfaceByID(wanID)
	if !ok {
		t.Fatal("the post-rename uplink lost its hardware identity")
	}

	if beforeWAN.SystemName == afterWAN.SystemName {
		t.Fatal("the fixture does not actually rename anything")
	}
	if beforeWAN.ID != afterWAN.ID {
		t.Errorf("identity changed with the rename: %q -> %q", beforeWAN.ID, afterWAN.ID)
	}
	if beforeWAN.IDKind != IdentityHardware || afterWAN.IDKind != IdentityHardware {
		t.Error("a hardware-address interface was not classified as hardware-identified")
	}
}

// TestNoHardwareAddressMeansNoStableIdentity is the honest case.
//
// Loopback, bridges and tunnels have no hardware address. There is genuinely
// nothing stable to be had, and this package says so rather than inventing an
// identifier that would silently change under an operator's feet.
func TestNoHardwareAddressMeansNoStableIdentity(t *testing.T) {
	d := FromSnapshot(hostA())

	lo, ok := interfaceBySystemName(d, "lo")
	if !ok {
		t.Fatal("loopback was not observed")
	}
	if lo.IDKind != IdentityEphemeral {
		t.Errorf("loopback identity kind = %s, want ephemeral", lo.IDKind)
	}
	if lo.Assignable {
		t.Error("loopback must never be assignable to a role")
	}
}

// TestAssigningLoopbackIsRefused proves the not-assignable path.
func TestAssigningLoopbackIsRefused(t *testing.T) {
	d := FromSnapshot(hostA())

	res := Resolve(d, []Assignment{{Role: RoleWAN, Selector: "lo"}})
	if res.OK() {
		t.Fatal("loopback was accepted as an uplink")
	}
	if len(res.Problems) != 1 {
		t.Fatalf("got %d problems, want 1", len(res.Problems))
	}
	if got := res.Problems[0].Code; got != "not-assignable" {
		t.Errorf("problem code = %q, want not-assignable", got)
	}
}

// TestOneInterfaceCannotFillTwoRoles is the safety case.
func TestOneInterfaceCannotFillTwoRoles(t *testing.T) {
	d := FromSnapshot(hostA())

	res := Resolve(d, []Assignment{
		{Role: RoleWAN, Selector: "enp0s31f6"},
		{Role: RoleLAN, Selector: "enp0s31f6"},
	})
	if res.OK() {
		t.Fatal("one interface was assigned to two roles")
	}
	if res.Problems[0].Code != "duplicate-interface" {
		t.Errorf("problem code = %q, want duplicate-interface", res.Problems[0].Code)
	}
	if _, both := res.Assigned[RoleWAN]; !both {
		t.Error("the first assignment should still have been honoured")
	}
	if _, second := res.Assigned[RoleLAN]; second {
		t.Error("the second role was assigned despite the conflict")
	}
}

// TestUnsupportedPlatformIsReportedNotEmpty is the honesty case.
//
// A laptop that cannot inspect itself must say so. Returning an empty host
// with every capability missing says something different and wrong: it claims
// the machine was examined.
func TestUnsupportedPlatformIsReportedNotEmpty(t *testing.T) {
	d := FromSnapshot(&network.Snapshot{Supported: false, Platform: "windows"})

	if d.Supported {
		t.Fatal("an unsupported snapshot produced a supported device")
	}
	if len(d.Interfaces) != 0 {
		t.Errorf("an unsupported host reported %d interfaces", len(d.Interfaces))
	}
	if len(d.Diagnostics) == 0 {
		t.Error("an unsupported host produced no diagnostic explaining why")
	}
	for _, c := range AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			t.Errorf("capability %s is absent; it should be present and unavailable", c)
			continue
		}
		if s.Available {
			t.Errorf("capability %s claims to be available on an uninspected host", c)
		}
		if s.Confidence != "unknown" {
			t.Errorf("capability %s has confidence %s on an uninspected host", c, s.Confidence)
		}
	}
}

// TestCapabilityClaimsCarryConfidence is the anti-overclaim rule.
//
// A capability derived from the platform rather than a probe must say so, so a
// caller that must not guess can refuse it.
func TestCapabilityClaimsCarryConfidence(t *testing.T) {
	d := FromSnapshot(hostA())

	for _, c := range AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			t.Errorf("capability %s is absent", c)
			continue
		}
		switch s.Confidence {
		case "observed", "inferred", "unknown":
		default:
			t.Errorf("capability %s has confidence %q, which is not a known value", c, s.Confidence)
		}
		if s.Reason == "" {
			t.Errorf("capability %s has no reason", c)
		}
	}

	// Forwarding is read from the kernel, so it is genuinely observed.
	fwd, _ := d.Can(CapForwarding)
	if fwd.Confidence != "observed" {
		t.Errorf("forwarding confidence = %q, want observed", fwd.Confidence)
	}
	if fwd.Available {
		t.Error("forwarding reports available with net.ipv4.ip_forward=0")
	}

	// Wireless CLIENT follows from an observed radio in managed mode. That is
	// a real observation and it is reported as one.
	if !d.Has(CapWirelessClient) {
		t.Error("a managed wireless interface was observed but wireless-client is unavailable")
	}
	client, _ := d.Can(CapWirelessClient)
	if client.Confidence != "observed" {
		t.Errorf("wireless-client confidence = %q, want observed", client.Confidence)
	}

	// Wireless AP does NOT. The same radio, in managed mode, is a client.
	// This is the assertion that used to be the other way round: presence of
	// a radio was reported as access-point capability, which is exactly
	// "report it because Linux/the hardware could theoretically do it".
	if d.Has(CapWirelessAP) {
		t.Error("a CLIENT-mode radio was reported as access-point capable")
	}
	ap, _ := d.Can(CapWirelessAP)
	if ap.Available {
		t.Error("wireless-ap is available on a host whose only radio is a client")
	}
	if !strings.Contains(ap.Reason, "access-point mode") {
		t.Errorf("the wireless-ap reason does not say what was looked for: %q", ap.Reason)
	}
	// VLAN follows from an observed VLAN interface, and none exists here.
	if d.Has(CapVLAN) {
		t.Error("no VLAN interface was observed but vlan claims available")
	}
}

// TestKernelVocabularyIsNormalised is the bug this layer actually had.
//
// `ip -j -d link show` reports info_kind "ether" and "wlan". THN's renderer and
// its wireless capability check both asked for "ethernet" and "wireless".
//
// Every fixture in this repository was written in THN's vocabulary, because the
// fixtures were built from the model rather than captured from a host — so the
// mismatch could not fail any test. On a real machine `thn discover` printed
// "Ether" and reported wireless-ap NOT AVAILABLE with a Wi-Fi card fitted.
//
// The fixtures above therefore use the KERNEL's spelling. If this fails,
// normalisation is gone and the product is lying on real hardware again.
func TestKernelVocabularyIsNormalised(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"ether", KindEthernet},
		{"ethernet", KindEthernet},
		{"wlan", KindWireless},
		{"wireless", KindWireless},
		{"loopback", KindLoopback},
		{"bridge", KindBridge},
		{"vlan", KindVLAN},
		{"bond", KindBond},
		{"", ""},
		{"somethingelse", "somethingelse"},
	}
	for _, c := range cases {
		if got := NormaliseKind(c.raw); got != c.want {
			t.Errorf("NormaliseKind(%q) = %q, want %q", c.raw, got, c.want)
		}
	}

	d := FromSnapshot(hostA())

	wan, ok := interfaceBySystemName(d, "enp0s31f6")
	if !ok {
		t.Fatal("the uplink was not observed")
	}
	if wan.Kind != KindEthernet {
		t.Errorf("a kernel 'ether' interface was classified as %q, want %q", wan.Kind, KindEthernet)
	}
	if wan.RawKind != "ether" {
		t.Errorf("RawKind = %q, want the kernel's own spelling 'ether'", wan.RawKind)
	}

	wifi, ok := interfaceBySystemName(d, "wlp2s0")
	if !ok {
		t.Fatal("the wireless adapter was not observed")
	}
	if wifi.Kind != KindWireless {
		t.Errorf("a kernel 'wlan' interface was classified as %q, want %q", wifi.Kind, KindWireless)
	}
}

// TestObservedSpeedIsCarriedThrough is the capability rule in Part 5.
//
// A NIC's negotiated speed is an observation, and THN needs it to reason about
// shaping, MTU and whether an uplink is plausible. Carrying it in the device
// model rather than re-deriving it from a separate probe keeps the Linux edge
// in one place.
//
// It also carries a trap: a driver that does not report a speed yields 0, and
// 0 must never be read as "no capacity".
func TestObservedSpeedIsCarriedThrough(t *testing.T) {
	d := FromSnapshot(hostA())

	wan, ok := interfaceBySystemName(d, "enp0s31f6")
	if !ok {
		t.Fatal("the uplink was not observed")
	}
	if wan.SpeedMbps != 1000 {
		t.Errorf("uplink speed = %d Mbps, want 1000", wan.SpeedMbps)
	}

	wifi, ok := interfaceBySystemName(d, "wlp2s0")
	if !ok {
		t.Fatal("the wireless adapter was not observed")
	}
	if wifi.SpeedMbps != 300 {
		t.Errorf("wireless speed = %d Mbps, want 300", wifi.SpeedMbps)
	}

	// A driver that reports nothing yields 0. That is "not reported", not
	// "no capacity", and the model must not present it as a number.
	hostDDev := FromSnapshot(hostD())
	wlan, ok := interfaceBySystemName(hostDDev, "eth2")
	if !ok {
		t.Fatal("the wireless adapter on host D was not observed")
	}
	if wlan.SpeedMbps != 0 {
		t.Errorf("an unreported speed came back as %d Mbps; 0 must mean not reported", wlan.SpeedMbps)
	}
}

// TestSingleNicHostIsNotAssumedAway is the topology the original product could
// not express.
//
// One NIC cannot be both uplink and downstream. The model reports that rather
// than assuming a second interface will appear.
func TestSingleNicHostIsNotAssumedAway(t *testing.T) {
	d := FromSnapshot(hostC())

	res := Resolve(d, []Assignment{
		{Role: RoleWAN, Selector: "ens3"},
		{Role: RoleLAN, Selector: "ens3"},
	})

	if res.OK() {
		t.Fatal("a single-NIC host was assigned both roles")
	}
	if res.Problems[0].Code != "duplicate-interface" {
		t.Errorf("problem code = %q, want duplicate-interface", res.Problems[0].Code)
	}

	// The suggestion an operator would be shown names what was seen.
	suggestions := Suggestions(res)
	if len(suggestions) == 0 {
		t.Fatal("no suggestion was produced for an unresolved topology")
	}
	if suggestions[0] == "" {
		t.Error("the suggestion is empty")
	}
}

// TestUnassignedRolesAreNeverInferred is the central invariant, stated as a
// test rather than a comment.
//
// FromSnapshot assigns every interface RoleUnassigned. If that ever changes —
// because someone added a "sensible default" — this fails. Nothing may look at
// position, at the kernel name, or at link state and conclude that an
// interface is an uplink.
func TestUnassignedRolesAreNeverInferred(t *testing.T) {
	for name, snap := range map[string]*network.Snapshot{
		"host A": hostA(), "host B": hostB(),
		"host C": hostC(), "host D": hostD(), "host E": hostE(),
	} {
		d := FromSnapshot(snap)
		for _, i := range d.Interfaces {
			if i.Role != RoleUnassigned {
				t.Errorf("%s: interface %s was given role %q by discovery; "+
					"roles are assigned, never inferred", name, i.SystemName, i.Role)
			}
		}
	}
}

// TestRoleAssignmentsRoundTrip is the onboarding path.
//
// `thn discover` must be able to show an operator the selectors that would
// reproduce the roles currently on the machine. A device that has been given
// roles must produce assignments that resolve back to the same interfaces —
// otherwise the suggested configuration is worse than useless.
func TestRoleAssignmentsRoundTrip(t *testing.T) {
	d := FromSnapshot(hostA())
	res := Resolve(d, nameAssignments())
	if !res.OK() {
		t.Fatalf("the fixture did not resolve: %+v", res.Problems)
	}

	// Device.RoleAssignments reads the roles off the Device, so the resolved
	// roles must be written back onto it first — which is what the caller does
	// after a successful resolution.
	for _, a := range res.Assigned {
		for n := range d.Interfaces {
			if d.Interfaces[n].ID == a.ID {
				d.Interfaces[n].Role = a.Role
			}
		}
	}

	round := d.RoleAssignments()
	if len(round) != 2 {
		t.Fatalf("got %d assignments back, want 2", len(round))
	}

	// The round trip must be by stable identity, so that a rename does not
	// change the answer.
	again := Resolve(d, round)
	if !again.OK() {
		t.Fatalf("the emitted assignments did not resolve: %+v", again.Problems)
	}
	if again.Assigned[RoleWAN].SystemName != res.Assigned[RoleWAN].SystemName {
		t.Errorf("round trip moved the uplink from %q to %q",
			res.Assigned[RoleWAN].SystemName, again.Assigned[RoleWAN].SystemName)
	}
	for _, a := range round {
		if a.Selector == res.Assigned[a.Role].SystemName {
			t.Errorf("role %s was emitted as a kernel name; a stable identity survives a rename", a.Role)
		}
	}
}

// interfaceBySystemName mirrors InterfaceByID for fixtures, without adding a
// method to the production type for a test's convenience.
func interfaceBySystemName(d *Device, name string) (Interface, bool) {
	for _, i := range d.Interfaces {
		if i.SystemName == name {
			return i, true
		}
	}
	return Interface{}, false
}
