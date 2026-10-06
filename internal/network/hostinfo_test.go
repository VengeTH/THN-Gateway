package network

import (
	"strings"
	"testing"
)

// The three findings from the real gateway.
//
// # What was wrong, and what these tests exist to prevent
//
//	1. wlp2s0 was classified "Ethernet".
//	2. wireless-client was NOT AVAILABLE.
//	3. enp0s31f6 reported no link speed.
//
// All three had the same underlying cause, and it was not a parsing mistake.
//
// `ip -j -d link show` sources its `wireless` block from the Wireless
// Extensions ioctls. Current mac80211 drivers — iwlwifi, ath9k, ath11k,
// mt7921 — do not implement Wireless Extensions. `ip` therefore emits NO
// wireless object for a Wi-Fi adapter, and a Wi-Fi NIC became indistinguishable
// from a wired one.
//
// The speed gap has a different cause: `ip` emits `speed` only when it can
// query the driver, and never while there is no carrier.
//
// The tests below drive the enrichment seam directly, with an injected
// HostInfo. That is deliberate: the seam is where the correction happens, and
// a test that only exercised ParseLinks would never see it — which is exactly
// why the defect survived a full green suite in M3.

// # A host that looks like the real one to `ip`, and is not one.
//
// `ip` sees an Ethernet link with no wireless object, because that is all it
// can see on a mac80211 driver. The wireless truth arrives separately.

func dellLikeLinks() []Interface {
	return []Interface{
		{
			Name: "enp0s31f6", Index: 2, MAC: "aa:bb:cc:dd:ee:01", MTU: 1500,
			SpeedMbps: 0, // the finding: ip reported none
			State:     LinkUp, Kind: "ether", LinkType: "ether",
			Physical: true, AdminUp: true, Carrier: true,
		},
		{
			Name: "wlp2s0", Index: 3, MAC: "aa:bb:cc:dd:ee:03", MTU: 1500,
			State: LinkUp, Kind: "ether", LinkType: "ether", // the finding: "ether"
			Physical: true, AdminUp: true, Carrier: true,
		},
		{
			Name: "docker0", Index: 4, MAC: "02:42:8a:1b:2c:3d", MTU: 1500,
			State: LinkUp, Kind: "bridge", LinkType: "ether", Physical: false,
			AdminUp: true, Carrier: true,
		},
		{
			Name: "lo", Index: 1, MTU: 65536,
			State: LinkUp, Kind: "loopback", LinkType: "loopback",
		},
	}
}

type fakeHostInfo struct {
	speeds map[string]int
	modes  map[string]string
	known  bool
	descr  string
	probes []Probe
}

func (f fakeHostInfo) LinkSpeed(iface string) (int, bool) {
	v, ok := f.speeds[iface]
	return v, ok
}
func (f fakeHostInfo) WirelessMode(iface string) (string, bool) {
	if !f.known {
		return "", false
	}
	v, ok := f.modes[iface]
	return v, ok
}
func (f fakeHostInfo) Describe() string { return f.descr }

// Probes returns the records a test asked for, so a test can assert on the
// diagnostic side of a read without a sysfs fixture.
//
// Empty by default: the fake reports facts the test put in it, and inventing
// probe records for facts it was handed would make the probes untested.
func (f fakeHostInfo) Probes() []Probe {
	if f.probes == nil {
		return []Probe{}
	}
	return f.probes
}

// TestCaseAWirelessEvidenceExistsRegardlessOfName is Case A.
//
// The interface is called `net7` — nothing about that name suggests a radio,
// and a name-based classifier would call it Ethernet. nl80211 says it is
// wireless in managed mode, so it is wireless.
func TestCaseAWirelessEvidenceExistsRegardlessOfName(t *testing.T) {
	ifaces := []Interface{{
		Name: "net7", Index: 8, MAC: "de:ad:be:ef:00:01", MTU: 1500,
		State: LinkUp, Kind: "ether", LinkType: "ether",
		Physical: true, AdminUp: true, Carrier: true,
	}}

	info := fakeHostInfo{
		known: true,
		modes: map[string]string{"net7": WirelessModeClient},
		descr: "test",
	}

	var diags []Diagnostic
	enrichLinks(nil, ifaces, info, &diags)

	if ifaces[0].Kind != "wlan" {
		t.Errorf("kind = %q, want wlan: nl80211 says net7 is wireless", ifaces[0].Kind)
	}
	if !ifaces[0].Physical {
		t.Error("a wireless adapter was not reported as physical")
	}
	if ifaces[0].WirelessMode != WirelessModeClient {
		t.Errorf("wireless mode = %q, want %q", ifaces[0].WirelessMode, WirelessModeClient)
	}
}

// TestCaseAMisleadingNameIsNotWirelessEvidence is Case B.
//
// An interface called `wlp99s0` that no wireless source knows about stays
// Ethernet. This is the guard against "fixing" the real bug by pattern
// matching the name — which would create the opposite error, marking an
// Ethernet port as a radio because someone typed something suggestive.
func TestCaseAMisleadingNameIsNotWirelessEvidence(t *testing.T) {
	ifaces := []Interface{{
		Name: "wlp99s0", Index: 9, MAC: "de:ad:be:ef:00:02", MTU: 1500,
		State: LinkUp, Kind: "ether", LinkType: "ether",
		Physical: true, AdminUp: true, Carrier: true,
	}}

	info := fakeHostInfo{known: true, modes: map[string]string{}, descr: "test"}

	var diags []Diagnostic
	enrichLinks(nil, ifaces, info, &diags)

	if ifaces[0].Kind != "ether" {
		t.Errorf("kind = %q, want ether: no source reports wlp99s0 as wireless", ifaces[0].Kind)
	}
	if ifaces[0].WirelessMode != "" {
		t.Errorf("a non-wireless interface carries mode %q", ifaces[0].WirelessMode)
	}
}

// TestCaseCNoWirelessEvidenceMeansNotWireless is Case C.
func TestCaseCNoWirelessEvidenceMeansNotWireless(t *testing.T) {
	ifaces := []Interface{{
		Name: "eth0", Index: 2, MAC: "de:ad:be:ef:00:03", MTU: 1500,
		State: LinkUp, Kind: "ether", LinkType: "ether", Physical: true,
	}}

	// known=true, and the source was consulted and found nothing.
	info := fakeHostInfo{known: true, modes: map[string]string{}, descr: "test"}

	var diags []Diagnostic
	enrichLinks(nil, ifaces, info, &diags)

	if ifaces[0].Kind != "ether" {
		t.Errorf("kind = %q, want ether", ifaces[0].Kind)
	}
}

// TestAnUnavailableWirelessSourceClaimsNothing is the honesty case, and it is
// the one that matters most on a server without `iw` installed.
//
// known=false means the source was never consulted. That is NOT the same as
// "consulted, found none", and the enrichment must not turn the first into
// the second — nor into a wireless interface.
func TestAnUnavailableWirelessSourceClaimsNothing(t *testing.T) {
	ifaces := []Interface{{
		Name: "wlp2s0", Index: 3, MAC: "aa:bb:cc:dd:ee:03", MTU: 1500,
		State: LinkUp, Kind: "ether", LinkType: "ether", Physical: true,
	}}

	info := fakeHostInfo{known: false, descr: "no nl80211 on this host"}

	var diags []Diagnostic
	enrichLinks(nil, ifaces, info, &diags)

	if ifaces[0].Kind == "wlan" {
		t.Error("an interface was called wireless when no source was available to say so")
	}
}

// TestTheRealGatewayShapeIsCorrected covers all three findings at once, on a
// host shaped like the Dell as `ip` sees it.
func TestTheRealGatewayShapeIsCorrected(t *testing.T) {
	ifaces := dellLikeLinks()

	info := fakeHostInfo{
		known: true,
		modes: map[string]string{"wlp2s0": WirelessModeClient},
		speeds: map[string]int{
			"enp0s31f6": 1000,
			"wlp2s0":    433,
		},
		descr: "test",
	}

	var diags []Diagnostic
	enrichLinks(nil, ifaces, info, &diags)

	if got := findIface(ifaces, "wlp2s0"); got.Kind != "wlan" {
		t.Errorf("wlp2s0 kind = %q, want wlan", got.Kind)
	}
	if got := findIface(ifaces, "wlp2s0"); got.WirelessMode != WirelessModeClient {
		t.Errorf("wlp2s0 mode = %q, want %q", got.WirelessMode, WirelessModeClient)
	}
	if got := findIface(ifaces, "enp0s31f6"); got.SpeedMbps != 1000 {
		t.Errorf("enp0s31f6 speed = %d, want 1000 from /sys", got.SpeedMbps)
	}
	if got := findIface(ifaces, "wlp2s0"); got.SpeedMbps != 433 {
		t.Errorf("wlp2s0 speed = %d, want 433 from /sys", got.SpeedMbps)
	}

	// Virtual links must be untouched by wireless enrichment.
	if got := findIface(ifaces, "docker0"); got.Kind != "bridge" || got.Physical {
		t.Errorf("docker0 was changed: kind=%q physical=%v", got.Kind, got.Physical)
	}
	if got := findIface(ifaces, "lo"); got.Kind != "loopback" || got.Physical {
		t.Errorf("lo was changed: kind=%q physical=%v", got.Kind, got.Physical)
	}

	// The correction is worth telling the operator about: it is a change in
	// what THN believes, and silence would be unexplained.
	sawCorrection := false
	for _, d := range diags {
		if strings.Contains(d.Message, "wlp2s0") && d.Severity == "info" {
			sawCorrection = true
		}
	}
	if !sawCorrection {
		t.Errorf("no diagnostic recorded the wireless correction: %+v", diags)
	}
}

// TestAnObservedSpeedIsNeverOverwritten guards the merge direction.
//
// `ip` and sysfs disagree sometimes — during a renegotiation, or when one
// saw a different instant. The already-observed value is kept rather than
// averaged, and never replaced by the larger.
func TestAnObservedSpeedIsNeverOverwritten(t *testing.T) {
	ifaces := []Interface{{
		Name: "enp0s31f6", SpeedMbps: 10000, Kind: "ether", Physical: true,
	}}
	info := fakeHostInfo{
		known:  true,
		speeds: map[string]int{"enp0s31f6": 1000},
		descr:  "test",
	}

	var diags []Diagnostic
	enrichLinks(nil, ifaces, info, &diags)

	if ifaces[0].SpeedMbps != 10000 {
		t.Errorf("speed = %d; an observed value was overwritten by a second source", ifaces[0].SpeedMbps)
	}
}

func findIface(ifaces []Interface, name string) Interface {
	for _, i := range ifaces {
		if i.Name == name {
			return i
		}
	}
	return Interface{}
}

// # Parsing `iw dev` — the nl80211 source.

const iwDevManaged = `phy#0
	Interface wlp2s0
		ifindex 3
		wdev 0x100000001
		addr 11:22:33:44:55:66
		ssid NotARealNetwork
		type managed
		wiphy 0
		channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
`

const iwDevMixed = `command failed: No such device (-19)
phy#0
	Interface wlp2s0
		ifindex 3
		wdev 0x100000001
		type managed
	Interface wlp2s1
		ifindex 4
		wdev 0x100000002
		type AP
	Interface wlp2s2
		ifindex 5
		wdev 0x100000003
		type monitor
	Interface mon0
		ifindex 6
		wdev 0x100000004
`

func TestParseWirelessInterfacesReadsModes(t *testing.T) {
	got := ParseWirelessInterfaces(iwDevMixed)

	cases := map[string]string{
		"wlp2s0": WirelessModeClient,
		"wlp2s1": WirelessModeAP,
		"wlp2s2": WirelessModeMonitor,
		"mon0":   "unknown", // listed, so wireless; but no `type` line
	}
	for name, want := range cases {
		if got[name] != want {
			t.Errorf("%s: mode = %q, want %q", name, got[name], want)
		}
	}

	// An interface iw does not list is not wireless, and must be absent.
	if _, present := got["enp0s31f6"]; present {
		t.Error("an interface iw never listed was reported as wireless")
	}
}

func TestParseWirelessInterfacesToleratesAWrongPhyTypeLine(t *testing.T) {
	// `iw phy` output describes the PHY itself with a bare `type:` line.
	// Attributing that to whichever interface preceded it would be a silent
	// misattribution, so a type line with no open Interface block is ignored.
	in := "phy#0\n\ttype monitor\n\tInterface wlp2s0\n\t\tifindex 3\n\t\ttype managed\n"

	got := ParseWirelessInterfaces(in)
	if got["wlp2s0"] != WirelessModeClient {
		t.Errorf("wlp2s0 = %q, want %q", got["wlp2s0"], WirelessModeClient)
	}
}

func TestNormaliseWirelessModeIsTotalAndConservative(t *testing.T) {
	cases := map[string]string{
		"managed": WirelessModeClient,
		"station": WirelessModeClient,
		"AP":      WirelessModeAP,
		"__ap":    WirelessModeAP,
		"master":  WirelessModeAP,
		"monitor": WirelessModeMonitor,
		"mesh":    WirelessModeMesh,
		"adhoc":   WirelessModeAdhoc,
		"":        "unknown",
		"banana":  "unknown",
	}
	for in, want := range cases {
		if got := NormaliseWirelessMode(in); got != want {
			t.Errorf("NormaliseWirelessMode(%q) = %q, want %q", in, got, want)
		}
	}

	// The critical property: an unrecognised mode must not become the
	// nearest thing THN does recognise. That is how a monitor ends up
	// reported as a client.
	if got := NormaliseWirelessMode("something-new"); got != "unknown" {
		t.Errorf("an unknown mode became %q; it must stay unknown", got)
	}
}

// # Parsing the sysfs speed attribute.

func TestParseSpeedFileKeepsUnknownUnknown(t *testing.T) {
	cases := []struct {
		in     string
		want   int
		wantOK bool
	}{
		{"1000\n", 1000, true},
		{"100\n", 100, true},
		{"54\n", 54, true},
		{"2500\n", 2500, true},
		{"-1\n", 0, false}, // the kernel's "the driver does not know"
		{"", 0, false},
		{"\n", 0, false},
		{"garbage\n", 0, false},
		{"0\n", 0, false},
		{"-5\n", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseSpeedFile(c.in)
		if ok != c.wantOK || got != c.want {
			t.Errorf("ParseSpeedFile(%q) = (%d, %v), want (%d, %v)",
				c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestParseWirelessStatusIsWeakerThanNl80211(t *testing.T) {
	// WEXT reports association, not mode. It establishes "station", and
	// only that.
	if mode, ok := ParseWirelessStatus("associated\n"); !ok || mode != WirelessModeClient {
		t.Errorf("ParseWirelessStatus(associated) = (%q, %v)", mode, ok)
	}
	if _, ok := ParseWirelessStatus("banana\n"); ok {
		t.Error("ParseWirelessStatus accepted an unrecognised status")
	}
	if _, ok := ParseWirelessStatus(""); ok {
		t.Error("ParseWirelessStatus accepted an empty file")
	}
}

func TestSafeIfaceNameRejectsPathTraversal(t *testing.T) {
	// Interface names come from the kernel, so this is defence in depth.
	// It is cheap and it makes an observed name structurally incapable of
	// escaping the sysfs root.
	bad := []string{"", ".", "..", "../speed", "a/b", `a\b`, "with space", "tab\there", "del\x7f"}
	for _, name := range bad {
		if safeIfaceName(name) {
			t.Errorf("safeIfaceName(%q) = true; it must be false", name)
		}
	}
	for _, name := range []string{"eth0", "wlp2s0", "enx00e099001812", "veth8c1f2a@if5", "bond0"} {
		if !safeIfaceName(name) {
			t.Errorf("safeIfaceName(%q) = false; a real interface name must be accepted", name)
		}
	}
}
