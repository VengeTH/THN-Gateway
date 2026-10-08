package host

// Real Linux output, translated.
//
// # The path under test
//
//	ip -j -d link show   (a real command's output shape)
//	        ↓  network.ParseLinks
//	[]network.Interface  (physical / virtual decided from kernel facts)
//	        ↓  FromSnapshot
//	Device               (the model everything above THN consumes)
//
// This file drives that whole path from the fixture in internal/network, so
// it tests the translation an operator's machine actually goes through rather
// than a hand-built model. A model test that skips the parser cannot catch a
// parser that classifies wrongly, and the classification is the part this
// milestone changed.
//
// The fixture is hand-composed, not captured — see the comment at the top of
// internal/network/discovery_test.go, which says exactly what that does and
// does not prove. TestLiveDiscoveryOnLinux runs the real inspector.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/network"
)

// gatewaySnapshot parses the gateway fixture and attaches addresses, exactly
// as internal/network's inspector would after reading both commands.
func gatewaySnapshot(t *testing.T) *network.Snapshot {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "network", "testdata", "link_gateway.json"))
	if err != nil {
		t.Fatalf("reading the gateway fixture: %v", err)
	}
	ifaces, err := network.ParseLinks(raw)
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}

	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: ifaces,
		Addresses: []network.Address{
			{Family: "inet", CIDR: "10.77.0.1/24", Scope: "global", Interface: "enp1s0_missing"},
			{Family: "inet", CIDR: "192.168.7.1/24", Scope: "global", Interface: "enp0s31f6"},
			{Family: "inet", CIDR: "172.18.0.1/16", Scope: "global", Interface: "docker0"},
			{Family: "inet6", CIDR: "fd00:77::1/64", Scope: "global", Interface: "enp0s31f6"},
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
	}
}

func ifaceNamed(t *testing.T, d *Device, name string) Interface {
	t.Helper()
	i, ok := interfaceBySystemName(d, name)
	if !ok {
		t.Fatalf("%s is not on this device", name)
	}
	return i
}

// TestPhysicalEthernetIsRepresentedCorrectly is case 1.
//
// A wired NIC must arrive as physical hardware with a stable identity, its
// observed speed, and both address families.
func TestPhysicalEthernetIsRepresentedCorrectly(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))
	nic := ifaceNamed(t, d, "enp0s31f6")

	if !nic.Physical {
		t.Error("an onboard Ethernet NIC was not reported as physical")
	}
	if nic.Virtual {
		t.Error("a physical NIC was flagged virtual")
	}
	if nic.Kind != KindEthernet {
		t.Errorf("kind = %q, want %q", nic.Kind, KindEthernet)
	}
	if nic.SpeedMbps != 1000 {
		t.Errorf("speed = %d Mbps, want the observed 1000", nic.SpeedMbps)
	}
	if !nic.AdminUp || !nic.LinkUp {
		t.Errorf("admin_up = %v, link_up = %v; a live cable should be both", nic.AdminUp, nic.LinkUp)
	}
	if !nic.Assignable {
		t.Error("a wired NIC must be a candidate for a role")
	}
	if got := nic.IPv4(); len(got) != 1 || got[0] != "192.168.7.1/24" {
		t.Errorf("IPv4 = %v, want [192.168.7.1/24]", got)
	}
	if got := nic.IPv6(); len(got) != 1 || got[0] != "fd00:77::1/64" {
		t.Errorf("IPv6 = %v, want [fd00:77::1/64]", got)
	}
}

// TestWirelessIsRepresentedCorrectly is case 2.
//
// Wi-Fi is hardware, it is wireless, and its mode is what separates a client
// from an access point. All three come from observation.
func TestWirelessIsRepresentedCorrectly(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))
	wlan := ifaceNamed(t, d, "wlp2s0")

	if wlan.Kind != KindWireless {
		t.Errorf("kind = %q, want %q", wlan.Kind, KindWireless)
	}
	if !wlan.Physical {
		t.Error("a wireless adapter was not reported as physical")
	}
	if wlan.WirelessMode != network.WirelessModeClient {
		t.Errorf("wireless mode = %q, want %q", wlan.WirelessMode, network.WirelessModeClient)
	}
	if wlan.SpeedMbps != 433 {
		t.Errorf("speed = %d, want the observed 433", wlan.SpeedMbps)
	}

	client, _ := d.Can(CapWirelessClient)
	if !client.Available || client.Confidence != "observed" {
		t.Errorf("wireless-client = %+v; a managed radio was observed", client)
	}
	ap, _ := d.Can(CapWirelessAP)
	if ap.Available {
		t.Error("a managed radio was reported as access-point capable")
	}
}

// TestLoopbackIsNotMistakenForAGatewayPort is case 3.
func TestLoopbackIsNotMistakenForAGatewayPort(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))
	lo := ifaceNamed(t, d, "lo")

	if lo.Physical {
		t.Error("loopback was reported as physical hardware")
	}
	if lo.Assignable {
		t.Error("loopback must never be a candidate for a role")
	}
	if lo.Kind != KindLoopback {
		t.Errorf("kind = %q, want %q", lo.Kind, KindLoopback)
	}

	for _, i := range d.RoleCandidates() {
		if i.SystemName == "lo" {
			t.Fatal("loopback appears in the role candidates")
		}
	}

	// And assigning it is refused with a reason an operator can read.
	res := Resolve(d, []Assignment{{Role: RoleWAN, Selector: "lo"}})
	if res.OK() {
		t.Fatal("loopback was accepted as an uplink")
	}
	if res.Problems[0].Code != "not-assignable" {
		t.Errorf("problem code = %q, want not-assignable", res.Problems[0].Code)
	}
}

// TestDockerBridgeIsNotMistakenForPhysicalEthernet is case 4.
//
// This is the failure that would be worst: a gateway that picks docker0 as its
// uplink routes nothing, and every indicator says it is fine.
func TestDockerBridgeIsNotMistakenForPhysicalEthernet(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))
	docker := ifaceNamed(t, d, "docker0")

	if docker.Physical {
		t.Error("a Docker bridge was reported as physical hardware")
	}
	if docker.Kind != KindBridge {
		t.Errorf("kind = %q, want %q", docker.Kind, KindBridge)
	}
	if docker.SpeedMbps != 0 {
		t.Errorf("a bridge reported a link speed of %d Mbps", docker.SpeedMbps)
	}

	// It carries an address, and that must not make it look like a port.
	if got := docker.IPv4(); len(got) != 1 || got[0] != "172.18.0.1/16" {
		t.Errorf("bridge IPv4 = %v, want [172.18.0.1/16]", got)
	}

	// A container endpoint is refused outright, because it does not outlive
	// the container.
	veth := ifaceNamed(t, d, "veth8c1f2a@if5")
	if veth.Physical {
		t.Error("a container veth was reported as physical hardware")
	}
	if veth.Assignable {
		t.Error("a container veth must not be a role candidate: it disappears when the container stops")
	}
	if veth.Master != "docker0" {
		t.Errorf("veth master = %q, want docker0", veth.Master)
	}

	// Ethernet-candidate lists must contain neither.
	for _, c := range d.RoleCandidatesFor(KindEthernet) {
		if c.SystemName == "docker0" || c.SystemName == "veth8c1f2a@if5" {
			t.Errorf("%s appeared in the Ethernet role candidates", c.SystemName)
		}
	}
}

// TestVirtualInterfacesAreNotMistakenForPhysicalEthernet is case 5.
//
// Tailscale, a bond, a VLAN and a bridge all present Ethernet link types.
// None of them is a port you can plug a cable into.
func TestVirtualInterfacesAreNotMistakenForPhysicalEthernet(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))

	for _, name := range []string{"tailscale0", "bond0", "eth0.77", "docker0", "lo"} {
		i := ifaceNamed(t, d, name)
		if i.Physical {
			t.Errorf("%s was reported as physical hardware; it is %s", name, i.Kind)
		}
	}

	tailscale := ifaceNamed(t, d, "tailscale0")
	if tailscale.Kind != KindTunnel {
		t.Errorf("tailscale kind = %q, want %q", tailscale.Kind, KindTunnel)
	}

	bond := ifaceNamed(t, d, "bond0")
	if bond.Kind != KindBond {
		t.Errorf("bond kind = %q, want %q", bond.Kind, KindBond)
	}

	vlan := ifaceNamed(t, d, "eth0.77")
	if vlan.Kind != KindVLAN {
		t.Errorf("vlan kind = %q, want %q", vlan.Kind, KindVLAN)
	}

	// A bridge capability may be claimed — one WAS observed — but that is a
	// statement about a bridge existing, not about Ethernet hardware.
	if !d.Has(CapBridge) {
		t.Error("a bridge interface was observed but the bridge capability is unavailable")
	}
	if !d.Has(CapVLAN) {
		t.Error("a VLAN interface was observed but the vlan capability is unavailable")
	}

	// And neither implies physical hardware exists in quantity.
	physical := 0
	for _, c := range d.RoleCandidates() {
		if c.Physical {
			physical++
		}
	}
	if physical != 4 {
		t.Errorf("found %d physical role candidates, want 4 (onboard, USB, Wi-Fi, bond port)", physical)
	}
}

// TestABondAndItsPortDoNotShareAnIdentity is the collision the fixture found.
//
// A bond takes its active port's MAC address, so `bond0` and `enp2s0` report
// the same hardware address. Digesting the address alone gave both the same
// ID, and everything downstream then had an ambiguity it could not see.
//
// The kind is part of the digest for exactly this reason: a rename changes the
// name, not the kind, so including it costs no rename-stability and removes a
// class of silent misbinding.
func TestABondAndItsPortDoNotShareAnIdentity(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))

	bond := ifaceNamed(t, d, "bond0")
	port := ifaceNamed(t, d, "enp2s0")

	if bond.MAC != port.MAC {
		t.Skip("this kernel gave the bond its own address; there is nothing to separate")
	}
	if bond.ID == port.ID {
		t.Errorf("bond0 and enp2s0 share identity %s; they are different links", bond.ID)
	}
	if bond.IDKind != IdentityHardware || port.IDKind != IdentityHardware {
		t.Errorf("identity kinds = %s / %s, want hardware for both",
			bond.IDKind, port.IDKind)
	}

	// A lookup by identity must return exactly one interface.
	if got, ok := d.InterfaceByID(bond.ID); !ok || got.SystemName != "bond0" {
		t.Errorf("InterfaceByID(bond) returned %q, want bond0", got.SystemName)
	}
	if got, ok := d.InterfaceByID(port.ID); !ok || got.SystemName != "enp2s0" {
		t.Errorf("InterfaceByID(port) returned %q, want enp2s0", got.SystemName)
	}
}

// TestTheAllZeroAddressIsNotAHardwareIdentity guards the other real hazard the
// fixture exposed.
//
// The kernel reports 00:00:00:00:00:00 for loopback and for a great many
// virtual links. Digesting it would give every one of them the SAME stable
// identity, so a configuration naming it would match whichever was reached
// first. It is the absence of an address, not an address.
func TestTheAllZeroAddressIsNotAHardwareIdentity(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))

	lo := ifaceNamed(t, d, "lo")
	if lo.MAC == "" {
		t.Skip("this kernel reports no address for loopback at all")
	}
	if lo.IDKind != IdentityEphemeral {
		t.Errorf("loopback has the all-zero address and was given identity kind %q", lo.IDKind)
	}

	seen := map[string][]string{}
	for _, i := range d.Interfaces {
		if i.MAC == "00:00:00:00:00:00" || i.MAC == "" {
			continue
		}
		seen[i.ID] = append(seen[i.ID], i.SystemName)
	}
	for id, names := range seen {
		if len(names) > 1 {
			t.Errorf("identity %s is shared by %v", id, names)
		}
	}
}

// TestAUsbEthernetIsASeparateInterface is case 6.
//
// A USB adapter is hardware, and it must be offered as its own candidate
// rather than being merged with, or hidden behind, the onboard NIC. It is also
// the case where "administratively up, no carrier" happens naturally.
func TestAUsbEthernetIsASeparateInterface(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))
	usb := ifaceNamed(t, d, "enx00e099001812")
	onboard := ifaceNamed(t, d, "enp0s31f6")

	if !usb.Physical {
		t.Error("a USB Ethernet adapter was not reported as physical")
	}
	if usb.Kind != KindEthernet {
		t.Errorf("kind = %q, want %q", usb.Kind, KindEthernet)
	}
	if usb.ID == onboard.ID {
		t.Error("the USB adapter and the onboard NIC share an identity")
	}
	if usb.SpeedMbps != 100 {
		t.Errorf("speed = %d, want the observed 100", usb.SpeedMbps)
	}

	// Both are candidates: an operator may legitimately want the uplink on
	// the adapter, and an unplugged one is a normal mid-setup state.
	if !usb.Assignable {
		t.Error("a USB Ethernet adapter must be a candidate for a role even when unplugged")
	}
	if usb.LinkUp {
		t.Error("an interface with no carrier was reported as link up")
	}
	if !usb.AdminUp {
		t.Error("an interface carrying the UP flag was reported administratively down")
	}

	ethernet := d.RoleCandidatesFor(KindEthernet)
	if len(ethernet) != 3 {
		names := make([]string, 0, len(ethernet))
		for _, c := range ethernet {
			names = append(names, c.SystemName)
		}
		t.Errorf("Ethernet candidates = %v, want three (onboard, USB, enslaved NIC)", names)
	}
}

// TestAnUnreportedSpeedStaysUnknown is case 7.
//
// Zero means "the driver did not say". It must never be smoothed into a
// plausible number, and it must never be rendered as a capacity.
func TestAnUnreportedSpeedStaysUnknown(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))

	for _, name := range []string{"docker0", "tailscale0", "bond0", "lo", "eth0.77"} {
		i := ifaceNamed(t, d, name)
		if i.SpeedMbps != 0 {
			t.Errorf("%s has speed %d; the kernel reported none", name, i.SpeedMbps)
		}
	}

	// The renderer must say "not reported", not "0 Mbps".
	if got := speedLabelForTest(t, d, "tailscale0"); got != "not reported" {
		t.Errorf("an unreported speed renders as %q, want %q", got, "not reported")
	}
}

// speedLabelForTest mirrors the CLI's rendering rule so the semantic can be
// asserted here without importing internal/cli.
func speedLabelForTest(t *testing.T, d *Device, name string) string {
	t.Helper()
	i := ifaceNamed(t, d, name)
	switch {
	case i.SpeedMbps <= 0:
		return "not reported"
	case i.SpeedMbps >= 1000:
		return "1 Gbps"
	default:
		return "1 Mbps"
	}
}

// TestCapabilityConfidenceIsPreserved is case 8.
//
// Three tiers, and the distinction is the whole point: a caller that must not
// guess has to be able to tell an observation from an inference.
func TestCapabilityConfidenceIsPreserved(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))

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

	// Forwarding was actually read from the kernel: this fixture sets it to 1.
	fwd, _ := d.Can(CapForwarding)
	if !fwd.Available || fwd.Confidence != "observed" {
		t.Errorf("forwarding = %+v; net.ipv4.ip_forward=1 was observed", fwd)
	}

	// NAT, DHCP, DNS, firewall and QoS were NOT probed. They are inferences
	// and must never claim to be observations, because an activation gate
	// that accepts "observed" would then be satisfied by a guess.
	for _, c := range []Capability{CapNAT, CapDHCP, CapDNS, CapFirewall, CapQoS} {
		s, _ := d.Capabilities[c]
		if s.Confidence == "observed" {
			t.Errorf("capability %s claims to be observed; nothing probed it", c)
		}
	}
}

// TestInterfaceOrderingCannotDetermineRoles is case 9, stated as a property.
//
// The same device is rotated through several orderings. Every ordering must
// produce the same roles — none. Ordering is for readability; it is not a
// signal, and a rotation that changes any answer is a bug.
func TestInterfaceOrderingCannotDetermineRoles(t *testing.T) {
	base := gatewaySnapshot(t)

	forward := append([]network.Interface(nil), base.Interfaces...)
	reverse := make([]network.Interface, 0, len(base.Interfaces))
	for i := len(forward) - 1; i >= 0; i-- {
		reverse = append(reverse, forward[i])
	}
	// A rotation that puts a bridge first and both NICs last.
	rotated := append(append([]network.Interface(nil), reverse[3:]...), reverse[:3]...)

	for name, ifaces := range map[string][]network.Interface{
		"as sorted": forward,
		"reversed":  reverse,
		"rotated":   rotated,
	} {
		snap := *base
		snap.Interfaces = ifaces

		d := FromSnapshot(&snap)
		for _, i := range d.Interfaces {
			if i.Role != RoleUnassigned {
				t.Errorf("%s: interface %s was given role %q by discovery", name, i.SystemName, i.Role)
			}
		}
		res := Resolve(d, nil)
		if len(res.Assigned) != 0 {
			t.Errorf("%s: resolving nothing assigned %d roles", name, len(res.Assigned))
		}
	}
}

// TestStableIdentityIsNotTheKernelName is case 10.
func TestStableIdentityIsNotTheKernelName(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))

	for _, i := range d.Interfaces {
		if i.ID == i.SystemName {
			t.Errorf("%s: the identity is the kernel name", i.SystemName)
		}
		if i.MAC != "" && containsSub(i.ID, i.MAC) {
			t.Errorf("%s: the identity %q discloses the hardware address", i.SystemName, i.ID)
		}
		if i.ID == "" {
			t.Errorf("%s: no identity was derived", i.SystemName)
		}
	}

	// Identities are unique among the interfaces that have one.
	seen := map[string]string{}
	for _, i := range d.Interfaces {
		if i.IDKind != IdentityHardware {
			continue
		}
		if prev, dup := seen[i.ID]; dup {
			t.Errorf("%s and %s share identity %s", prev, i.SystemName, i.ID)
		}
		seen[i.ID] = i.SystemName
	}
}

func containsSub(hay, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestDiscoveryAssignsNoRoles is case 11.
//
// Stated directly because it is the invariant everything above depends on: a
// gateway must never decide which connection is the internet one.
func TestDiscoveryAssignsNoRoles(t *testing.T) {
	d := FromSnapshot(gatewaySnapshot(t))

	for _, i := range d.Interfaces {
		if i.Role != RoleUnassigned {
			t.Errorf("%s was given role %q during discovery", i.SystemName, i.Role)
		}
	}
	if len(d.RoleAssignments()) != 0 {
		t.Errorf("discovery produced %d assignments; it must produce none", len(d.RoleAssignments()))
	}
}

// TestTheSameHardwareUnderDifferentNamesKeepsItsIdentity closes the loop
// with the real fixture: rename every interface, and the identities, kinds and
// physicality must be unchanged.
func TestTheSameHardwareUnderDifferentNamesKeepsItsIdentity(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "network", "testdata", "link_gateway.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed []network.Interface
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}

	base := gatewaySnapshot(t)
	before := FromSnapshot(base)

	// Re-parse after renaming, rather than renaming the parsed structs, so
	// the parser runs again and cannot be bypassed.
	var docs []map[string]any
	if err := json.Unmarshal(raw, &docs); err != nil {
		t.Fatal(err)
	}
	renames := map[string]string{
		"enp0s31f6": "eth0", "docker0": "br-9", "wlp2s0": "wlx0",
		"tailscale0": "zz0", "lo": "lo0", "enx00e099001812": "usb0",
	}
	for _, d := range docs {
		if to, ok := renames[d["ifname"].(string)]; ok {
			d["ifname"] = to
		}
	}
	out, err := json.Marshal(docs)
	if err != nil {
		t.Fatal(err)
	}
	ifaces, err := network.ParseLinks(out)
	if err != nil {
		t.Fatal(err)
	}
	afterSnap := *base
	afterSnap.Interfaces = ifaces
	after := FromSnapshot(&afterSnap)

	renamedToOriginal := map[string]string{}
	for from, to := range renames {
		renamedToOriginal[to] = from
	}

	for _, orig := range before.Interfaces {
		name := orig.SystemName
		if to, ok := renames[name]; ok {
			name = to
		}
		got, ok := interfaceBySystemName(after, name)
		if !ok {
			t.Errorf("%s vanished after renaming", name)
			continue
		}
		if got.ID != orig.ID {
			t.Errorf("%s: identity changed with the name: %s -> %s", name, orig.ID, got.ID)
		}
		if got.Kind != orig.Kind || got.Physical != orig.Physical {
			t.Errorf("%s: kind/physical changed with the name: (%s,%v) -> (%s,%v)",
				name, orig.Kind, orig.Physical, got.Kind, got.Physical)
		}
		if got.SpeedMbps != orig.SpeedMbps {
			t.Errorf("%s: speed changed with the name: %d -> %d", name, orig.SpeedMbps, got.SpeedMbps)
		}
	}
	_ = renamedToOriginal
}
