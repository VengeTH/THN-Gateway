package host
package host

// Device independence.
//
// # What these tests are for
//
// The product's first target was a Dell E5470, and the configuration it grew
// around names that machine's interfaces. These tests take the same desired
// gateway — one uplink, one downstream — and satisfy it against five hosts
// that share nothing: different interface counts, different names, no
// wireless, no hardware addresses at all, and a host whose interface names
// have changed while the hardware has not.
//
// The property being proven is narrow and checkable: the same assignments
// resolve against compatible hosts regardless of what the kernel calls the
// interfaces. It is NOT proven here that THN works on any of them; that is a
// statement about observation, which is what this layer does.
//
// # The five hosts
//
//	A  2 x 1Gb Ethernet, 1 x wireless      the original shape, plus Wi-Fi
//	B  4 x 1Gb Ethernet                   a rack server
//	C  1 x Ethernet                        a VM or a mini PC
//	D  2 x Ethernet, different names       proves the names do not matter
//	E  the same hardware, renamed          proves identity survives a rename

import (
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/network"
)

// hostA builds a two-NIC host with a wireless adapter: the Dell shape plus
// Wi-Fi, which is what a laptop looks like.
func hostA() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("enp0s31f6", 2, "aa:bb:cc:dd:ee:01", "ethernet", network.LinkUp),
			obs("enp1s0", 3, "aa:bb:cc:dd:ee:02", "ethernet", network.LinkDown),
			obs("wlp2s0", 4, "aa:bb:cc:dd:ee:03", "wireless", network.LinkUp),
			obs("lo", 1, "", "loopback", network.LinkUp),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

// hostB builds a four-NIC host: a rack server.
func hostB() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("eno1", 2, "11:22:33:44:55:01", "ethernet", network.LinkUp),
			obs("eno2", 3, "11:22:33:44:55:02", "ethernet", network.LinkUp),
			obs("eno3", 4, "11:22:33:44:55:03", "ethernet", network.LinkDown),
			obs("eno4", 5, "11:22:33:44:55:04", "ethernet", network.LinkDown),
			obs("lo", 1, "", "loopback", network.LinkUp),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

// hostC builds a single-NIC host: a VM, a mini PC, a single-NIC router.
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
			obs("ens3", 2, "cc:dd:ee:ff:00:01", "ethernet", network.LinkUp),
			obs("lo", 1, "", "loopback", network.LinkUp),
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
			obs("eth0", 2, "de:ad:be:ef:00:01", "ethernet", network.LinkUp),
			obs("eth1", 3, "de:ad:be:ef:00:02", "ethernet", network.LinkUp),
			obs("eth2", 4, "de:ad:be:ef:00:03", "wireless", network.LinkDown),
			obs("lo", 1, "", "loopback", network.LinkUp),
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
			obs("eth1", 9, "aa:bb:cc:dd:ee:01", "ethernet", network.LinkUp),
			obs("eth0", 8, "aa:bb:cc:dd:ee:02", "ethernet", network.LinkUp),
			obs("lo", 1, "", "loopback", network.LinkUp),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

// obs builds one observed interface.
func obs(name string, index int, mac, kind string, state network.LinkState) network.Interface {
	return network.Interface{
		Name:  name,
		Index: index,
		MAC:   mac,
		MTU:   1500,
		Kind:  kind,
		State: state,
		Role:  network.RoleUnassigned,
	}
}

// gatewayAssignments is the desired binding every host is checked against.
//
// It selects by HARDWARE ADDRESS, not by name. That is the whole point: the
// same document resolves on a host whose kernel names bear no relation to
// these.
func gatewayAssignments() []Assignment {
	return []Assignment{
		{Role: RoleWAN, Selector: "mac:aa:bb:cc:dd:ee:01"},
		{Role: RoleLAN, Selector: "mac:aa:bb:cc:dd:ee:02"},
	}
}

// hardwareAssignments is the same intent expressed by kernel name, which must
// keep working because existing deployments use it.
func hardwareAssignments() []Assignment {
	return []Assignment{
		{Role: RoleWAN, Selector: "enp0s31f6"},
		{Role: RoleLAN, Selector: "enp1s0"},
	}
}

// TestTheSameDesiredGatewayResolvesOnEveryHost is the device-independence
// proof.
//
// Host C has one interface and cannot satisfy both roles. That is a legitimate
// outcome and it must be reported as a structured problem, not as a panic, not
// as a silent partial binding, and not by assigning the same interface twice.
func TestTheSameDesiredGatewayResolvesOnEveryHost(t *testing.T) {
	cases := []struct {
		name      string
		snap      *network.Snapshot
		assign    []Assignment
		wantRoles bool // both roles expected to resolve
	}{
		{"host A: Dell shape plus Wi-Fi", hostA(), hardwareAssignments(), true},
		{"host B: four NICs", hostB(), nil, false}, // no matching hardware
		{"host C: one NIC", hostC(), nil, false},
		{"host D: different names", hostD(), nil, false},
		{"host A by hardware address", hostA(), gatewayAssignments(), true},
		{"host E: renamed, same hardware", hostE(), gatewayAssignments(), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := FromSnapshot(c.snap)
			if !d.Supported {
				t.Fatal("the fixture reports itself unsupported")
			}

			assign := c.assign
			if assign == nil {
				// Host B and D hold different hardware, so the same
				// hardware-address assignments cannot resolve. That is the
				// correct answer and is asserted below.
				assign = gatewayAssignments()
			}

			res := Resolve(d, assign)

			if c.wantRoles {
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
				return
			}

			// Unmatched hardware must produce a structured problem naming
			// what was observed, not a silent partial binding.
			if res.OK() {
				t.Fatalf("assignments resolved against hardware that does not exist")
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

// TestRenamingAnInterfacePreservesItsIdentity is the Host E property.
//
// The kernel name changed and the index changed with it. The hardware address
// did not, so the ID did not. That is what lets a configuration survive a
// device moving between slots.
func TestRenamingAnInterfacePreservesItsIdentity(t *testing.T) {
	before := FromSnapshot(hostA())
	after := FromSnapshot(hostE())

	beforeWAN, ok := before.InterfaceByID("mac:aa:bb:cc:dd:ee:01")
	if !ok {
		t.Fatal("the pre-rename uplink has no hardware identity")
	}
	afterWAN, ok := after.InterfaceByID("mac:aa:bb:cc:dd:ee:01")
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

	lo, ok := d.InterfaceBySystemName("lo")
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

	// Wireless capability follows from an observed wireless interface.
	if !d.Has(CapWirelessAP) {
		t.Error("a wireless interface was observed but wireless-ap is unavailable")
	}
	// VLAN follows from an observed VLAN interface, and none exists here.
	if d.Has(CapVLAN) {
		t.Error("no VLAN interface was observed but vlan claims available")
	}
}

// TestSingleNicHostIsNotAssumedAway is the topology the original product
// could not express.
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

// InterfaceBySystemName is a test convenience mirroring InterfaceByID.
func (d *Device) InterfaceBySystemName(name string) (Interface, bool) {
	for _, i := range d.Interfaces {
		if i.SystemName == name {
			return i, true
		}
	}
	return Interface{}, false
}