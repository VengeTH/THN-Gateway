package network

// Reading a real gateway, off-line.
//
// # What this fixture is, honestly
//
// link_gateway.json is NOT a capture. It is hand-composed to the shape `ip -j
// -d link show` emits, using link.json — the real capture in this directory —
// as the template for structure, key names and value shapes.
//
// That is a weaker thing than a capture, and the difference is stated here
// rather than blurred:
//
//   - the KEYS and their JSON TYPES are taken from a real capture, so a decode
//     failure caused by a mistyped field is still a genuine risk being tested;
//   - the FIELD VALUES describe a plausible gateway and are invented. They are
//     deliberately NOT a description of any specific machine.
//
// What this file can prove: that the parser understands every link kind a
// Linux gateway presents, and that it classifies them without consulting a
// name. What it cannot prove: that a particular kernel emits exactly these
// keys. For that there is TestLiveDiscoveryOnLinux, which runs the real
// inspector, and which skips rather than lies when there is no Linux host.
//
// # The load-bearing property
//
// Every interface in this fixture is classified from what the kernel STATES
// about the link, never from what it is CALLED. The fixture is built so that
// a name-based classifier would get several of them wrong — which is the only
// way a test can distinguish "it classifies correctly" from "it classifies the
// way this file happens to be laid out".

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadGatewayFixture reads the composed gateway fixture.
func loadGatewayFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "link_gateway.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return raw
}

func parseGateway(t *testing.T) []Interface {
	t.Helper()
	ifaces, err := ParseLinks(loadGatewayFixture(t))
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}
	return ifaces
}

func byName(ifaces []Interface, name string) Interface {
	for _, i := range ifaces {
		if i.Name == name {
			return i
		}
	}
	return Interface{}
}

// TestEveryGatewayLinkKindIsClassifiedWithoutItsName is the central claim.
//
// The expectations are stated per interface with the REASON each was
// classified, so a failure says which rule broke rather than only which row.
func TestEveryGatewayLinkKindIsClassifiedWithoutItsName(t *testing.T) {
	ifaces := parseGateway(t)

	cases := []struct {
		name         string
		wantKind     string
		wantPhysical bool
		why          string
	}{
		{"enp0s31f6", "ether", true, "link_type ether with no virtual linkinfo kind"},
		{"enx00e099001812", "ether", true, "a USB adapter reports exactly like an onboard NIC"},
		{"wlp2s0", "wlan", true, "the kernel emits a wireless object for it"},
		{"lo", "loopback", false, "the LOOPBACK flag and link_type say so"},
		{"docker0", "bridge", false, "linkinfo.info_kind is bridge"},
		{"veth8c1f2a@if5", "veth", false, "linkinfo.info_kind is veth"},
		{"tailscale0", "tun", false, "linkinfo.info_kind is tun"},
		{"bond0", "bond", false, "linkinfo.info_kind is bond"},
		{"enp2s0", "ether", true, "a NIC enslaved into a bond is still hardware"},
		{"eth0.77", "vlan", false, "linkinfo.info_kind is vlan"},
	}

	for _, c := range cases {
		got := byName(ifaces, c.name)
		if got.Name == "" {
			t.Errorf("%s is missing from the fixture", c.name)
			continue
		}
		if got.Kind != c.wantKind {
			t.Errorf("%s: kind = %q, want %q (%s)", c.name, got.Kind, c.wantKind, c.why)
		}
		if got.Physical != c.wantPhysical {
			t.Errorf("%s: physical = %v, want %v (%s)", c.name, got.Physical, c.wantPhysical, c.why)
		}
	}
}

// TestANameAloneNeverDecidesTheKind is the property stated as a test.
//
// It re-parses the same fixture with every interface RENAMED — including
// deliberately misleading names — and requires an identical classification.
//
// If classification consulted the name at all, this fails. That is a stronger
// statement than any table of expected values, because it cannot be satisfied
// by a list that happens to match this file.
func TestANameAloneNeverDecidesTheKind(t *testing.T) {
	raw := loadGatewayFixture(t)

	var parsed []ipLinkJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("re-decoding fixture: %v", err)
	}

	// Names chosen to mislead in opposite directions: a bridge called
	// "enp0s31f6", a physical NIC called "docker0", a tunnel called "eth0".
	misleading := map[string]string{
		"enp0s31f6":       "zz0",
		"docker0":         "eth0",
		"tailscale0":      "br-abc",
		"wlp2s0":          "wlan9",
		"enx00e099001812": "veth0",
		"veth8c1f2a@if5":  "veth9",
		"bond0":           "wlp9s0",
		"eth0.77":         "tailscale9",
		"lo":              "eth9",
		"enp2s0":          "eno1",
	}

	before := map[string][2]any{}
	for _, p := range parsed {
		kind, physical, _ := classify(p)
		before[p.IfName] = [2]any{kind, physical}
	}

	for i := range parsed {
		if to, ok := misleading[parsed[i].IfName]; ok {
			parsed[i].IfName = to
		}
	}

	for _, p := range parsed {
		kind, physical, _ := classify(p)
		orig := misleadingInverse(misleading, p.IfName)
		want, ok := before[orig]
		if !ok {
			t.Fatalf("no original recorded for %q", orig)
		}
		if kind != want[0] || physical != want[1] {
			t.Errorf("%q (renamed from %q): got (%v, %v), want (%v, %v) — "+
				"classification must not depend on the interface name",
				p.IfName, orig, kind, physical, want[0], want[1])
		}
	}
}

// misleadingInverse maps a renamed interface back to its original name.
func misleadingInverse(m map[string]string, renamed string) string {
	for orig, to := range m {
		if to == renamed {
			return orig
		}
	}
	return renamed
}

// TestAdministrativeStateAndCarrierAreReportedSeparately is the distinction
// that a single "state" string throws away.
//
// The USB adapter in this fixture is the interesting one: administratively
// UP, operstate DOWN, and no LOWER_UP flag. That is "nobody plugged the cable
// in", which is a completely different problem from "the interface is off",
// and an operator debugging a gateway needs to be told which one it is.
func TestAdministrativeStateAndReportedCarrier(t *testing.T) {
	ifaces := parseGateway(t)

	usb := byName(ifaces, "enx00e099001812")
	if !usb.AdminUp {
		t.Error("an interface carrying the UP flag was reported administratively down")
	}
	if usb.Carrier {
		t.Error("an interface with no LOWER_UP flag was reported as having a carrier")
	}
	if usb.State != LinkDown {
		t.Errorf("USB adapter state = %q, want down", usb.State)
	}

	nic := byName(ifaces, "enp0s31f6")
	if !nic.AdminUp || !nic.Carrier {
		t.Errorf("a live NIC reported admin_up=%v carrier=%v", nic.AdminUp, nic.Carrier)
	}
	if nic.State != LinkUp {
		t.Errorf("live NIC state = %q, want up", nic.State)
	}

	// The kernel reports loopback operstate as UNKNOWN because it has no
	// carrier concept. Treating that as "down" would make every loopback
	// look broken.
	lo := byName(ifaces, "lo")
	if lo.Kind != "loopback" {
		t.Fatalf("lo kind = %q, want loopback", lo.Kind)
	}
	if lo.State != LinkUp {
		t.Errorf("loopback state = %q, want up: it has no carrier to report", lo.State)
	}
}

// TestLinkSpeedIsObservedOrAbsent is the anti-fabrication rule at the edge.
//
// Every NIC in the fixture reports a speed. The bridge and the tunnel report
// none, and must come back as zero — "not reported" — rather than 0 being
// smoothed into some plausible number or copied from a sibling.
func TestLinkSpeedIsObservedOrAbsent(t *testing.T) {
	ifaces := parseGateway(t)

	for name, want := range map[string]int{
		"enp0s31f6":       1000,
		"enx00e099001812": 100,
		"wlp2s0":          433,
		"enp2s0":          1000,
		"docker0":         0,
		"tailscale0":      0,
		"bond0":           0,
		"lo":              0,
		"eth0.77":         0,
	} {
		if got := byName(ifaces, name).SpeedMbps; got != want {
			t.Errorf("%s: speed = %d Mbps, want %d", name, got, want)
		}
	}
}

// TestEnslavementIsRecordedSeparatelyFromHardware keeps two different facts
// apart.
//
// A NIC inside a bond is physical hardware AND it currently belongs to
// something. Collapsing those into one answer would either hide the
// hardware or hide the membership.
func TestEnslavementIsRecordedSeparatelyFromHardware(t *testing.T) {
	ifaces := parseGateway(t)

	slave := byName(ifaces, "enp2s0")
	if !slave.Physical {
		t.Error("a NIC enslaved into a bond was not reported as physical")
	}
	if slave.Master != "bond0" {
		t.Errorf("enslaved NIC master = %q, want bond0", slave.Master)
	}

	master := byName(ifaces, "bond0")
	if master.Physical {
		t.Error("a bond was reported as physical hardware")
	}
	if master.Master != "" {
		t.Errorf("the bond itself reports a master of %q; it should have none", master.Master)
	}

	veth := byName(ifaces, "veth8c1f2a@if5")
	if veth.Master != "docker0" {
		t.Errorf("veth master = %q, want docker0", veth.Master)
	}

	// A `null` master must decode as absent, not as a failure. Real `ip`
	// emits it, and a mistyped field here would fail the WHOLE document and
	// leave THN reporting a gateway with no interfaces at all.
	if got := byName(ifaces, "docker0").Master; got != "" {
		t.Errorf("a null master decoded to %q, want empty", got)
	}
}

// TestWirelessModeIsReadFromTheKernel is the client-versus-access-point fact.
//
// One radio, two different capabilities. Telling them apart from the
// reported mode is the difference between reporting a capability and
// assuming one.
func TestWirelessModeIsReadFromTheKernel(t *testing.T) {
	ifaces := parseGateway(t)

	wlan := byName(ifaces, "wlp2s0")
	if wlan.Kind != "wlan" {
		t.Fatalf("wlp2s0 kind = %q, want wlan", wlan.Kind)
	}
	// The kernel says "managed". THN says "client". That translation happens at
	// this boundary, once, so that both wireless sources — this one and nl80211
	// via iw — hand the model the same word.
	if wlan.WirelessMode != WirelessModeClient {
		t.Errorf("wireless mode = %q, want %q (the kernel's \"managed\", normalised)",
			wlan.WirelessMode, WirelessModeClient)
	}
	if !wlan.Physical {
		t.Error("a wireless adapter was not reported as physical")
	}

	// Every non-wireless interface must have no mode at all.
	for _, i := range ifaces {
		if i.Kind == "wlan" {
			continue
		}
		if i.WirelessMode != "" {
			t.Errorf("%s is kind %q but carries wireless mode %q", i.Name, i.Kind, i.WirelessMode)
		}
	}
}

// TestAMalformedWirelessObjectCostsOneFieldAndNotTheHost is the robustness
// property the RawMessage declaration exists for.
//
// `ip` is not a stable interface. If the wireless object ever changes shape,
// THN must lose the MODE and keep every interface — not report a gateway
// with no interfaces at all, which is precisely the failure that a mistyped
// field in ipLinkJSON once caused.
func TestAMalformedWirelessObjectCostsOneFieldAndNotTheHost(t *testing.T) {
	raw := []byte(`[
	  {"ifname":"enp0s31f6","ifindex":2,"mtu":1500,"operstate":"UP",
	   "link_type":"ether","address":"aa:bb:cc:dd:ee:01",
	   "flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],
	   "linkinfo":{"info_kind":"ether"}},
	  {"ifname":"wlp2s0","ifindex":3,"mtu":1500,"operstate":"UP",
	   "link_type":"ether","address":"aa:bb:cc:dd:ee:03",
	   "flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],
	   "wireless":{"iftype":["unexpected","array"],"mode":42},
	   "linkinfo":{"info_kind":"ether"}}
	]`)

	ifaces, err := ParseLinks(raw)
	if err != nil {
		t.Fatalf("a malformed wireless object failed the whole parse: %v", err)
	}
	if len(ifaces) != 2 {
		t.Fatalf("got %d interfaces, want 2: a bad field must not cost the host", len(ifaces))
	}

	wlan := byName(ifaces, "wlp2s0")
	// Still correctly identified as wireless — that comes from the object's
	// PRESENCE, not its contents.
	if wlan.Kind != "wlan" {
		t.Errorf("a malformed wireless object lost the wireless classification: kind = %q", wlan.Kind)
	}
	// And the mode is simply unknown, which is the honest answer.
	if wlan.WirelessMode != "" {
		t.Errorf("a malformed wireless object produced mode %q; it should be unknown", wlan.WirelessMode)
	}
}

// TestTheRealCaptureStillParses is the regression guard on the fixture that
// actually came off a machine.
//
// link.json was captured, not composed. Every field added since must be
// optional, or this test would have failed when it was added.
func TestTheRealCaptureStillParses(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "link.json"))
	if err != nil {
		t.Fatalf("reading the real capture: %v", err)
	}

	ifaces, err := ParseLinks(raw)
	if err != nil {
		t.Fatalf("the real capture no longer parses: %v", err)
	}
	if len(ifaces) == 0 {
		t.Fatal("the real capture parsed to zero interfaces")
	}

	// Sanity-check that the additions took effect on real data, not only on
	// the composed fixture.
	lo := byName(ifaces, "lo")
	if lo.Kind != "loopback" {
		t.Errorf("the captured loopback was classified %q, want loopback", lo.Kind)
	}
	if lo.Physical {
		t.Error("the captured loopback was reported as physical")
	}
	if !lo.AdminUp {
		t.Error("the captured loopback was reported administratively down")
	}

	nic := byName(ifaces, "enp0s31f6")
	if !nic.Physical {
		t.Error("a captured onboard NIC was not reported as physical")
	}

	veth := byName(ifaces, "veth1234@if5")
	if veth.Physical {
		t.Error("a captured container veth was reported as physical hardware")
	}
}
