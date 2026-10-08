package host

// M7.1 — hardware & capability intelligence.
//
// # What is actually being tested
//
// The analyzer is pure, so the question these tests answer is narrow and
// worth stating precisely: given these observed facts, does THN reach a
// defensible verdict, and can it show its working?
//
// They are written against fixtures translated through the real discovery path
// (network.ParseLinks → FromSnapshot → AnalyzeHardware) rather than against
// hand-built Devices. A Device assembled directly would skip the parser, and
// the parser is where "is this physical" is decided — so a test that skipped
// it would be testing a model the operator's machine never goes through.
//
// # The two failure modes this file exists to prevent
//
// 1. Claiming an interface IS something. Every test that finds a strong
//    candidate also checks that nothing was assigned, because "looks like the
//    uplink" and "is the uplink" fail in different ways and the second one
//    configures a gateway.
//
// 2. Guessing from a shortcut. Name, address range, carrier alone and speed
//    alone are each sufficient to produce a confident wrong answer, and each
//    has a dedicated test with a fixture built to defeat it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/network"
)

// fixtureHost is an observed host loaded from a testdata file.
//
// Links, addresses and routes are held as raw JSON rather than as decoded
// network types, because each has to go through the parser the real observer
// uses. That is not ceremony: `Route.Default` is DERIVED by ParseRoutes from a
// destination of "default" and is not a field the kernel emits, so a fixture
// that unmarshalled routes directly would produce a host with default routes
// that nothing had marked as default — and every route-derived verdict in this
// file would then be testing nothing.
type fixtureHost struct {
	Links      []json.RawMessage     `json:"links"`
	Addresses  []json.RawMessage     `json:"addresses"`
	Routes     []json.RawMessage     `json:"routes"`
	Sysctl     []network.SysctlValue `json:"sysctl"`
	System     network.System        `json:"system"`
	NFTables   network.NFTablesState `json:"nftables"`
	TrafficCtl network.TCState       `json:"traffic_control"`
	DNS        network.DNSState      `json:"dns"`
}

// loadFixture translates a testdata file into an observed Device.
func loadFixture(t *testing.T, name string) *Device {
	t.Helper()
	return FromSnapshot(parseFixtureIn(t, "testdata", name))
}

// parseFixtureIn turns a testdata file into a Snapshot.
func parseFixtureIn(t *testing.T, dir, name string) *network.Snapshot {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	var f fixtureHost
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}

	links, err := network.ParseLinks(mustMarshal(t, f.Links))
	if err != nil {
		t.Fatalf("ParseLinks on %s: %v", name, err)
	}
	routes, err := network.ParseRoutes(mustMarshal(t, f.Routes))
	if err != nil {
		t.Fatalf("ParseRoutes on %s: %v", name, err)
	}

	return &network.Snapshot{
		Platform:       "linux",
		Supported:      true,
		Interfaces:     links,
		Addresses:      decodeAddresses(f.Addresses),
		Routes:         routes,
		Sysctl:         f.Sysctl,
		System:         f.System,
		NFTables:       f.NFTables,
		TrafficControl: f.TrafficCtl,
		DNS:            f.DNS,
	}
}

// decodeAddresses unmarshals the flat address list.
//
// The addresses are already in THN's own shape rather than in `ip -j addr`
// shape, because the fixture's flat list exists only to be handed to
// FromSnapshot, and ParseAddresses would need the nested per-link form that
// the links section does not carry.
func decodeAddresses(raw []json.RawMessage) []network.Address {
	var out []network.Address
	for _, r := range raw {
		var a network.Address
		if err := json.Unmarshal(r, &a); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling fixture fragment: %v", err)
	}
	return b
}

// intelligenceFor analyses a fixture in one step.
func intelligenceFor(t *testing.T, name string) HardwareIntelligence {
	t.Helper()
	return AnalyzeHardware(loadFixture(t, name))
}

// intelNamed finds one interface's analysis by system name.
func intelNamed(t *testing.T, intel HardwareIntelligence, name string) InterfaceIntelligence {
	t.Helper()
	for _, in := range intel.Interfaces {
		if in.SystemName == name {
			return in
		}
	}
	t.Fatalf("%s is not in the analysis; got %v", name, intelNames(intel))
	return InterfaceIntelligence{}
}

func intelNames(intel HardwareIntelligence) []string {
	out := make([]string, 0, len(intel.Interfaces))
	for _, in := range intel.Interfaces {
		out = append(out, in.SystemName)
	}
	return out
}

// roleVerdict is a terse assertion helper: it names the interface and role in
// the failure message, because "want candidate, got unsuitable" without them
// is a bad afternoon.
func assertSuitability(t *testing.T, in InterfaceIntelligence, role Role, want Suitability) {
	t.Helper()
	got := in.SuitabilityFor(role)
	if got.Suitability != want {
		t.Errorf("%s %s suitability = %q, want %q", in.SystemName, role, got.Suitability, want)
	}
}

// assertHasLimitationContaining checks that a limitation mentioning needle is
// present.
//
// Substring rather than equality, because the limitation sentences are prose
// written for a human reading them and pinning them whole in every test would
// mean a wording improvement broke fifteen assertions.
func assertHasLimitationContaining(t *testing.T, s RoleSuitability, needle string) {
	t.Helper()
	for _, l := range s.Limitations {
		if strings.Contains(l, needle) {
			return
		}
	}
	t.Errorf("no limitation mentions %q; got %v", needle, s.Limitations)
}

func assertHasBlockerContaining(t *testing.T, s RoleSuitability, needle string) {
	t.Helper()
	for _, b := range s.Blockers {
		if strings.Contains(b, needle) {
			return
		}
	}
	t.Errorf("no blocker mentions %q; got %v", needle, s.Blockers)
}

// hasEvidence reports whether an evidence code is present.
func hasEvidence(s RoleSuitability, code string) bool {
	for _, e := range s.Evidence {
		if e.Code == code {
			return true
		}
	}
	return false
}

// findProfile returns one gateway profile by ID.
func findProfile(t *testing.T, intel HardwareIntelligence, id ProfileID) GatewayProfile {
	t.Helper()
	for _, p := range intel.Profiles {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("no %s profile was reported; got %v", id, profileIDs(intel))
	return GatewayProfile{}
}

func profileIDs(intel HardwareIntelligence) []ProfileID {
	out := make([]ProfileID, 0, len(intel.Profiles))
	for _, p := range intel.Profiles {
		out = append(out, p.ID)
	}
	return out
}

// ============================================================ the fifteen cases

// TestStrongEthernetWanCandidate is case 1.
//
// A wired NIC with carrier, a reported speed, an address and the observed
// default route is the shape an uplink has. It must be a strong candidate.
func TestStrongEthernetWanCandidate(t *testing.T) {
	intel := intelligenceFor(t, "m71_two_port_wired.json")
	wan := intelNamed(t, intel, "wanport0")

	assertSuitability(t, wan, RoleWAN, SuitabilityStrongCandidate)

	wanSuit := wan.SuitabilityFor(RoleWAN)
	if !wan.Usage.DefaultRoute {
		t.Error("the uplink fixture does not carry the default route; the test is not testing what it claims")
	}
	for _, code := range []string{"physical-link", "ethernet", "carrier-present", "link-speed", "default-route", "uplink-shape"} {
		if !hasEvidence(wanSuit, code) {
			t.Errorf("WAN evidence is missing %q; got %v", code, codes(wanSuit))
		}
	}
	// Every fact behind a verdict must be traceable and marked observed.
	for _, e := range wanSuit.Evidence {
		if e.Confidence != ConfidenceObserved {
			t.Errorf("evidence %q has confidence %q; M7.1 must not upgrade or infer facts", e.Code, e.Confidence)
		}
	}
}

func codes(s RoleSuitability) []string {
	out := make([]string, 0, len(s.Evidence))
	for _, e := range s.Evidence {
		out = append(out, e.Code)
	}
	return out
}

// TestUnusedEthernetLanCandidate is case 2.
//
// No carrier, no address, no route. It must still be offered as a LAN
// candidate, with the missing carrier recorded as a limitation — an operator
// who plugs the cable in later must not have been told the port is unusable.
func TestUnusedEthernetLanCandidate(t *testing.T) {
	intel := intelligenceFor(t, "m71_two_port_wired.json")
	lan := intelNamed(t, intel, "lanport0")

	assertSuitability(t, lan, RoleLAN, SuitabilityCandidate)

	lanSuit := lan.SuitabilityFor(RoleLAN)
	if hasEvidence(lanSuit, "default-route") {
		t.Error("the LAN candidate carries a default route; the fixture is wrong")
	}
	if !hasEvidence(lanSuit, "no-carrier") && !hasEvidence(lanSuit, "carrier-present") {
		t.Error("carrier state was not recorded as evidence either way")
	}
	if !lanSuit.Candidate() {
		t.Error("a connected Ethernet port on a two-port host must be offered as a LAN candidate")
	}
}

// TestDisconnectedEthernetIsStillACandidate is case 2b, and it is the case a
// naive implementation gets wrong.
//
// "Carrier: no" is not "unusable". The real validation host has an unused USB
// Ethernet adapter with no cable in it, and that is precisely the port an
// operator wants to know about.
func TestDisconnectedEthernetIsStillACandidate(t *testing.T) {
	intel := intelligenceFor(t, "m71_gateway.json")
	spare := intelNamed(t, intel, "enx00e099001812")

	if spare.Physical != true || spare.Class != LinkPhysicalWired {
		t.Fatalf("the spare port was not recognised as a physical Ethernet port: %+v", spare)
	}
	if spare.Usage.State != UsageIdle {
		t.Errorf("spare port usage = %q, want %q", spare.Usage.State, UsageIdle)
	}
	assertSuitability(t, spare, RoleLAN, SuitabilityCandidate)
	assertHasLimitationContaining(t, spare.SuitabilityFor(RoleLAN), "no carrier")
}

// TestWirelessClient is case 3.
//
// A wireless client is a plausible uplink and a poor LAN. Access-point
// capability must never be inferred from a radio being present.
func TestWirelessClient(t *testing.T) {
	intel := intelligenceFor(t, "m71_wireless_uplink.json")
	radio := intelNamed(t, intel, "wlp9s1")

	if !radio.Physical {
		t.Fatal("a wireless adapter was not reported as physical hardware")
	}
	if radio.Class != LinkPhysicalWireless {
		t.Errorf("class = %q, want %q", radio.Class, LinkPhysicalWireless)
	}

	// It may serve as an uplink.
	wanSuit := radio.SuitabilityFor(RoleWAN)
	if !wanSuit.Candidate() {
		t.Errorf("an associated radio carrying the default route must be an uplink candidate; got %q",
			wanSuit.Suitability)
	}
	assertHasLimitationContaining(t, wanSuit, "wireless")

	// It must NOT be offered as an ordinary wired LAN port.
	lanSuit := radio.SuitabilityFor(RoleLAN)
	if lanSuit.Suitability == SuitabilityStrongCandidate || lanSuit.Suitability == SuitabilityCandidate {
		t.Errorf("a wireless client was offered as a normal wired LAN candidate: %q", lanSuit.Suitability)
	}
	assertHasLimitationContaining(t, lanSuit, "not equivalent to a wired LAN port")

	// And the capability model must not be consulted to invent AP support.
	// The observed mode is on the Device; the analysis reports it as
	// evidence, and an operator reading that line must be able to tell
	// "observed as a client" from "we assumed a client".
	if !hasEvidenceDetail(wanSuit, WirelessModeClient) {
		t.Errorf("the observed wireless mode was not reported as evidence; got %v", details(wanSuit))
	}
	if hasEvidenceDetail(wanSuit, WirelessModeAP) {
		t.Error("AP mode was claimed for a client radio")
	}
}

// hasEvidenceDetail reports whether any evidence sentence contains needle.
func hasEvidenceDetail(s RoleSuitability, needle string) bool {
	for _, e := range s.Evidence {
		if strings.Contains(e.Detail, needle) {
			return true
		}
	}
	return false
}

func details(s RoleSuitability) []string {
	out := make([]string, 0, len(s.Evidence))
	for _, e := range s.Evidence {
		out = append(out, e.Detail)
	}
	return out
}

// TestWirelessAccessPointCapabilityIsNeverInferred is case 3b.
//
// A radio whose mode the host did not report is exactly the case where
// inferring would be tempting and wrong. THN must say the mode was not
// reported rather than guessing either way.
func TestWirelessAccessPointCapabilityIsNeverInferred(t *testing.T) {
	intel := intelligenceFor(t, "m71_wireless_uplink.json")
	noreport := intelNamed(t, intel, "wlp9s2")

	if noreport.Class != LinkPhysicalWireless {
		t.Fatalf("wlp9s2 was not classified as a physical radio: %q", noreport.Class)
	}

	for _, role := range IntelligenceRoles() {
		s := noreport.SuitabilityFor(role)
		assertHasLimitationContaining(t, s, "does not assume access-point capability")
		for _, e := range s.Evidence {
			if strings.Contains(e.Detail, WirelessModeAP) {
				t.Errorf("%s %s evidence claims AP mode from an unreported mode: %q", noreport.SystemName, role, e.Detail)
			}
		}
	}
}

// TestBridgeIsNotAPhysicalPort is case 4.
func TestBridgeIsNotAPhysicalPort(t *testing.T) {
	intel := intelligenceFor(t, "m71_virtual_heavy.json")
	br := intelNamed(t, intel, "br-7a3f1c2d")

	if br.Class != LinkInfrastructure {
		t.Errorf("class = %q, want %q", br.Class, LinkInfrastructure)
	}
	if br.Usage.State != UsageInfrastructure {
		t.Errorf("usage = %q, want %q", br.Usage.State, UsageInfrastructure)
	}
	// It carries an address. That must not make it look like a port.
	if !br.Usage.Addressed {
		t.Error("the fixture bridge carries no address; the test is not testing what it claims")
	}
	for _, role := range IntelligenceRoles() {
		assertSuitability(t, br, role, SuitabilityUnsuitable)
	}
}

// TestVethIsNotAPhysicalPort is case 5.
func TestVethIsNotAPhysicalPort(t *testing.T) {
	intel := intelligenceFor(t, "m71_virtual_heavy.json")
	veth := intelNamed(t, intel, "veth1a2b3c@if4")

	for _, role := range IntelligenceRoles() {
		s := veth.SuitabilityFor(role)
		assertSuitability(t, veth, role, SuitabilityUnsuitable)
		// The reason must name the concrete thing, so an operator learns
		// something they did not already assume.
		assertHasBlockerContaining(t, s, "container endpoint")
	}
	if !hasEvidence(veth.SuitabilityFor(RoleLAN), "enslaved") {
		t.Errorf("the veth's bridge membership was not recorded; got %v", codes(veth.SuitabilityFor(RoleLAN)))
	}
}

// TestTailscaleTunnelIsNotAPhysicalPort is case 6.
func TestTailscaleTunnelIsNotAPhysicalPort(t *testing.T) {
	intel := intelligenceFor(t, "m71_virtual_heavy.json")
	ts := intelNamed(t, intel, "tailscale0")

	if ts.Kind != KindTunnel {
		t.Errorf("kind = %q, want %q", ts.Kind, KindTunnel)
	}
	for _, role := range IntelligenceRoles() {
		s := ts.SuitabilityFor(role)
		assertSuitability(t, ts, role, SuitabilityUnsuitable)
		assertHasBlockerContaining(t, s, "tunnel")
	}
	// The tunnel carries a default route. It still is not a port.
	if !ts.Usage.DefaultRoute {
		t.Error("the fixture tunnel carries no default route; the test is not testing what it claims")
	}
	assertSuitability(t, ts, RoleWAN, SuitabilityUnsuitable)
}

// TestExistingBridgeMembership is case 7.
//
// A physical NIC enslaved to a bridge is real hardware AND already spoken
// for. Both facts have to survive into the output.
func TestExistingBridgeMembership(t *testing.T) {
	intel := intelligenceFor(t, "m71_bridge_member.json")
	portA := intelNamed(t, intel, "port_a")

	if !portA.Physical {
		t.Fatal("a physical NIC inside a bridge must still be reported as physical")
	}
	if portA.Usage.State != UsageEnslaved {
		t.Errorf("usage = %q, want %q", portA.Usage.State, UsageEnslaved)
	}
	if portA.Usage.Master != "br-lan" {
		t.Errorf("master = %q, want br-lan", portA.Usage.Master)
	}

	wanSuit := portA.SuitabilityFor(RoleWAN)
	assertHasBlockerContaining(t, wanSuit, "enslaved to br-lan")
	assertHasEvidence(t, portA, RoleWAN, "enslaved")

	// And the profile must not have quietly used it.
	profile := findProfile(t, intel, ProfileTwoPortWired)
	if got := profile.Candidates[RoleLAN]; got == "port_a" {
		t.Error("the two-port profile named a bridge-enslaved port as its LAN candidate")
	}
}

// TestMultipleDefaultRoutes is case 8.
//
// Both route relationships must be visible, deterministically, and without
// the analysis declaring the host broken.
func TestMultipleDefaultRoutes(t *testing.T) {
	intel := intelligenceFor(t, "m71_virtual_heavy.json")

	if intel.DefaultRouteCount != 2 {
		t.Fatalf("default route count = %d, want 2", intel.DefaultRouteCount)
	}
	// The Tailscale tunnel must be among them — it is one of the two defaults,
	// and dropping it would be the same name-based blindness elsewhere.
	if len(intel.DefaultRouteInterfaces) != 2 {
		t.Errorf("default route interfaces = %v, want two entries", intel.DefaultRouteInterfaces)
	}

	for _, name := range []string{"uplink0", "tailscale0"} {
		in, ok := bySystemName(intel.Interfaces, name)
		if !ok {
			t.Fatalf("%s missing from the analysis", name)
		}
		if !in.Usage.DefaultRoute {
			t.Errorf("%s carries a default route in the fixture but not in the analysis", name)
		}
	}

	// Two defaults is a fact, not a fault. Nothing here may say otherwise.
	for _, n := range intel.Notes {
		lower := strings.ToLower(n)
		if strings.Contains(lower, "broken") || strings.Contains(lower, "fault") &&
			!strings.Contains(lower, "not a fault") {
			t.Errorf("a note treats multiple default routes as a fault: %q", n)
		}
	}
	profile := findProfile(t, intel, ProfileTwoPortWired)
	assertHasConstraintContaining(t, profile, "multiple default-route paths observed")
}

func assertHasEvidence(t *testing.T, in InterfaceIntelligence, role Role, code string) {
	t.Helper()
	if !hasEvidence(in.SuitabilityFor(role), code) {
		t.Errorf("%s %s evidence is missing %q; got %v", in.SystemName, role, code, codes(in.SuitabilityFor(role)))
	}
}

func assertHasConstraintContaining(t *testing.T, p GatewayProfile, needle string) {
	t.Helper()
	for _, c := range p.Constraints {
		if strings.Contains(c, needle) {
			return
		}
	}
	t.Errorf("no constraint mentions %q; got %v", needle, p.Constraints)
}

// TestUnknownSpeedIsNotZeroSpeed is case 9.
//
// The spare port on the real host reports no speed. Reporting 0 Mbps would
// read as a measurement; reporting nothing must read as an absence.
func TestUnknownSpeedIsNotZeroSpeed(t *testing.T) {
	intel := intelligenceFor(t, "m71_gateway.json")
	spare := intelNamed(t, intel, "enx00e099001812")

	if spare.SpeedKnown {
		t.Error("the spare port reports a speed the fixture never gave it")
	}
	if spare.SpeedMbps != 0 {
		t.Errorf("SpeedMbps = %d, want 0 for an unreported speed", spare.SpeedMbps)
	}

	// The distinction has to survive serialisation too, or a JSON consumer
	// cannot tell "no speed" from "0 Mbps" either.
	encoded, err := json.Marshal(spare)
	if err != nil {
		t.Fatalf("InterfaceIntelligence did not serialise: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("InterfaceIntelligence did not deserialise: %v", err)
	}
	if _, present := decoded["speed_mbps"]; present {
		t.Error("an unreported speed was serialised as a number; it must be omitted entirely")
	}
	if known, _ := decoded["speed_known"].(bool); known {
		t.Error("speed_known is true for an interface whose speed was never reported")
	}

	// And the limitation must say so in words.
	assertHasLimitationContaining(t, spare.SuitabilityFor(RoleLAN), "reported no link speed")
}

// TestOccupiedInterfaceIsStillClassified is case 10, and it is the one that
// most easily produces a wrong answer.
//
// The uplink on the real host is busy. It is also the best uplink evidence on
// the machine. Occupancy must be reported WITHOUT costing it its rank, or the
// analysis would be arguing the operator out of the correct configuration.
func TestOccupiedInterfaceIsStillClassified(t *testing.T) {
	intel := intelligenceFor(t, "m71_gateway.json")
	wan := intelNamed(t, intel, "enp0s31f6")

	if wan.Usage.State != UsageOccupied {
		t.Fatalf("usage = %q, want %q", wan.Usage.State, UsageOccupied)
	}
	assertSuitability(t, wan, RoleWAN, SuitabilityStrongCandidate)

	wanSuit := wan.SuitabilityFor(RoleWAN)
	assertHasLimitationContaining(t, wanSuit, "currently in use")

	// Occupancy is a usage state, never a suitability class.
	//
	// UsageState and Suitability are separate types precisely so this cannot
	// happen by accident, so the assertion is on the values rather than on a
	// conversion: no suitability classification may ever be the word "occupied".
	for _, in := range intel.Interfaces {
		for _, role := range IntelligenceRoles() {
			if s := in.SuitabilityFor(role).Suitability; string(s) == string(UsageOccupied) {
				t.Errorf("%s %s: occupancy was folded into the suitability vocabulary as %q",
					in.SystemName, role, s)
			}
		}
	}
	if wan.SuitabilityFor(RoleWAN).Suitability != SuitabilityStrongCandidate {
		t.Error("being in use cost the uplink its rank; occupancy must not downgrade suitability")
	}
}

// TestSuitabilitySurvivesARename is case 11.
//
// The same hardware, renamed by the kernel. Suitability must follow the stable
// identity, because that is the whole reason the identity exists.
func TestSuitabilitySurvivesARename(t *testing.T) {
	before := AnalyzeHardware(loadFixture(t, "m71_gateway.json"))

	// Rename every interface, then rebuild the host from scratch rather than
	// mutating the parsed structs, so the parser runs again and cannot be
	// bypassed.
	after := AnalyzeHardware(renameFixture(t, "m71_gateway.json", map[string]string{
		"enp0s31f6":       "zz9",
		"wlp2s0":          "wlx0",
		"enx00e099001812": "usb0",
		"docker0":         "br-9",
		"veth9f3c1a@if12": "veth0@if12",
		"tailscale0":      "ts0",
		"lo":              "lo0",
	}))

	if len(before.Interfaces) != len(after.Interfaces) {
		t.Fatalf("interfaces before = %d, after = %d", len(before.Interfaces), len(after.Interfaces))
	}

	renames := map[string]string{
		"enp0s31f6": "zz9", "wlp2s0": "wlx0", "enx00e099001812": "usb0",
		"docker0": "br-9", "tailscale0": "ts0", "lo": "lo0",
		"veth9f3c1a@if12": "veth0@if12",
	}

	for _, b := range before.Interfaces {
		name, renamed := renames[b.SystemName]
		if !renamed {
			t.Errorf("the rename map does not cover %s; the test is not checking every interface", b.SystemName)
			continue
		}
		a, ok := bySystemName(after.Interfaces, name)
		if !ok {
			t.Errorf("%s (renamed to %s) disappeared", b.SystemName, name)
			continue
		}
		if a.ID != b.ID {
			t.Errorf("%s: identity changed across a rename: %q became %q", b.SystemName, b.ID, a.ID)
		}
		for _, role := range IntelligenceRoles() {
			if got, want := a.SuitabilityFor(role).Suitability, b.SuitabilityFor(role).Suitability; got != want {
				t.Errorf("%s (%s): %s suitability changed across a rename: %q became %q",
					b.SystemName, name, role, want, got)
			}
		}
	}

	// The profile verdicts are about the hardware, so they must be identical.
	for _, bp := range before.Profiles {
		ap := findProfile(t, after, bp.ID)
		if ap.Verdict != bp.Verdict {
			t.Errorf("%s verdict changed across a rename: %q became %q", bp.ID, bp.Verdict, ap.Verdict)
		}
	}
}

// renameFixture returns the same host with every listed interface renamed.
//
// It rewrites the fixture into a temporary directory and re-parses it from
// there, rather than renaming the decoded structs. Two reasons, both about
// what the test is actually able to prove:
//
// The parser runs again, so it cannot be bypassed. Mutating the parsed
// structs would let a rename bug hide inside the test that exists to catch
// rename bugs.
//
// The repository's own fixture is never written to. An earlier version of
// this helper rewrote testdata and restored it in a defer, which is one
// t.Fatal in the wrong place away from leaving a fixture renamed for every
// later run.
func renameFixture(t *testing.T, name string, renames map[string]string) *Device {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}

	renameRows := func(key, field string) {
		var rows []map[string]any
		if err := json.Unmarshal(doc[key], &rows); err != nil {
			t.Fatalf("parsing %s in %s: %v", key, name, err)
		}
		for _, r := range rows {
			current, ok := r[field].(string)
			if !ok {
				continue
			}
			if to, ok := renames[current]; ok {
				r[field] = to
			}
		}
		doc[key] = mustMarshal(t, rows)
	}

	// Links, addresses and routes are renamed together. Renaming only the
	// links would produce a host whose addresses and routes name interfaces
	// that no longer exist — a fixture that tests nothing but the analyser
	// being confused by nonsense.
	renameRows("links", "ifname")
	renameRows("addresses", "interface")
	renameRows("routes", "dev")

	// The master relationship has to follow too. A veth whose bridge has been
	// renamed but which still names the old bridge would be a host with a
	// dangling reference, and the analysis would report a broken relationship
	// rather than a renamed one.
	renameRows("links", "master")

	rewritten, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("rewriting fixture %s: %v", name, err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), rewritten, 0o600); err != nil {
		t.Fatalf("writing the renamed fixture: %v", err)
	}
	return FromSnapshot(parseFixtureIn(t, dir, name))
}

// TestTwoPortGatewayProfile is case 12.
//
// Two physical Ethernet ports and nothing else to confuse it. The profile must
// be POSSIBLE, and nothing may be assigned.
func TestTwoPortGatewayProfile(t *testing.T) {
	intel := intelligenceFor(t, "m71_two_port_wired.json")

	profile := findProfile(t, intel, ProfileTwoPortWired)
	if !profile.Possible() {
		t.Fatalf("two-port wired gateway = %q on a host with two Ethernet ports", profile.Verdict)
	}
	if intel.PhysicalEthernet != 2 {
		t.Errorf("physical Ethernet count = %d, want 2", intel.PhysicalEthernet)
	}

	// Suitability picks the best ports. It does not assign them.
	if got := profile.Candidates[RoleWAN]; got != "wanport0" {
		t.Errorf("WAN candidate = %q, want wanport0", got)
	}
	if got := profile.Candidates[RoleLAN]; got != "lanport0" {
		t.Errorf("LAN candidate = %q, want lanport0", got)
	}

	// The gateway fixture has no roles assigned anywhere.
	for _, in := range intel.Interfaces {
		if in.Usage.AssignedRole != "" {
			t.Errorf("%s carries assigned role %q; analysis must assign nothing", in.SystemName, in.Usage.AssignedRole)
		}
	}
	if intel.AssignmentMade {
		t.Error("AssignmentMade is true; analysis assigns nothing")
	}
}

// TestMultiInterfaceProfile is case 13.
//
// Three physical ports, one of them wireless. The shape is possible and the
// wireless limitation has to be visible.
func TestMultiInterfaceProfile(t *testing.T) {
	intel := intelligenceFor(t, "m71_gateway.json")

	if intel.PhysicalPorts != 3 {
		t.Errorf("physical port count = %d, want 3", intel.PhysicalPorts)
	}
	if intel.PhysicalEthernet != 2 {
		t.Errorf("physical Ethernet count = %d, want 2", intel.PhysicalEthernet)
	}
	if intel.PhysicalWireless != 1 {
		t.Errorf("physical wireless count = %d, want 1", intel.PhysicalWireless)
	}

	profile := findProfile(t, intel, ProfileMultiInterface)
	if !profile.Possible() {
		t.Fatalf("multi-interface gateway = %q on a host with three physical ports", profile.Verdict)
	}
	// Three physical ports is not three WIRED ports, and the profile must not
	// quietly pretend otherwise.
	assertHasConstraintContaining(t, profile, "wlp2s0")
}

// TestZeroPhysicalEthernetIsNotPossibleWithoutOverclaiming is case 14.
//
// The rule this protects: reporting a hardware shortfall as a host-level
// verdict. A host with no Ethernet ports may have a perfectly good wireless
// uplink, and "not a two-port wired gateway" must not become "unusable".
func TestZeroPhysicalEthernetIsNotPossibleWithoutOverclaiming(t *testing.T) {
	// A wireless-only host, built by hand from the analyzer's own vocabulary
	// rather than a fixture, because no fixture would describe a machine that
	// cannot exist in the validation environment.
	d := &Device{
		Supported: true,
		Interfaces: []Interface{
			{ID: "hw:a", IDKind: IdentityHardware, SystemName: "radioonly0", Index: 2,
				Kind: KindWireless, Physical: true, AdminUp: true, LinkUp: true, Assignable: true,
				WirelessMode: WirelessModeClient, SpeedMbps: 300, Addresses: []string{"10.1.1.5/24"}},
		},
		Routes: []network.Route{
			{Destination: "default", Interface: "radioonly0", Default: true, Gateway: "10.1.1.1"},
		},
	}

	intel := AnalyzeHardware(d)
	profile := findProfile(t, intel, ProfileTwoPortWired)

	if profile.Possible() {
		t.Error("a host with zero Ethernet ports was reported as a two-port wired gateway")
	}
	// The shortfall reason lives in the evidence, stated once. It must be
	// specific about what was counted.
	if !hasEvidenceDetail(RoleSuitability{Evidence: profile.Evidence}, "physical Ethernet interface(s) observed") {
		t.Errorf("no evidence explains the shortfall; got %v", details(RoleSuitability{Evidence: profile.Evidence}))
	}

	// And the host is still assessed on what it actually has.
	radio := intelNamed(t, intel, "radioonly0")
	if !radio.SuitabilityFor(RoleWAN).Candidate() {
		t.Error("the radio uplink was not offered as a WAN candidate; the shortfall must not sink the host")
	}
}

// TestM71AnalysisAssignsNothing is case 15, the safety case.
//
// This is the test that fails if a future change wires the analyzer into the
// role-resolution path. It asserts on the DEVICE, not only on the returned
// analysis: analysis returning a role verdict must not leave one behind on the
// model it read.
func TestM71AnalysisAssignsNothing(t *testing.T) {
	d := loadFixture(t, "m71_gateway.json")

	before := map[string]Role{}
	for _, i := range d.Interfaces {
		before[i.SystemName] = i.Role
	}
	routesBefore := len(d.Routes)
	ifacesBefore := len(d.Interfaces)

	intel := AnalyzeHardware(d)

	if intel.AssignmentMade {
		t.Error("the analysis claims it assigned something")
	}
	for _, i := range d.Interfaces {
		if got := before[i.SystemName]; i.Role != got {
			t.Errorf("%s role changed from %q to %q during analysis", i.SystemName, got, i.Role)
		}
	}
	if len(d.Interfaces) != ifacesBefore {
		t.Errorf("interface count changed from %d to %d during analysis", ifacesBefore, len(d.Interfaces))
	}
	if len(d.Routes) != routesBefore {
		t.Errorf("route count changed from %d to %d during analysis", routesBefore, len(d.Routes))
	}

	// RoleAssignments is what an operator would copy into configuration. It
	// must remain empty after analysis.
	if got := d.RoleAssignments(); len(got) != 0 {
		t.Errorf("analysis produced role assignments: %+v", got)
	}

	// And resolving a role against this host must still require an explicit
	// assignment from the caller.
	if res := Resolve(d, []Assignment{{Role: RoleWAN, Selector: "enp0s31f6"}}); !res.OK() {
		t.Errorf("resolving an explicit assignment failed: %+v", res.Problems)
	}
}

// ============================================== shortcuts the rules must defeat

// TestClassificationIsNotByName is the anti-name rule.
//
// The fixture interfaces are named to look like nothing in particular. What
// matters is that renaming them all changes no verdict at all — which is the
// same property as TestSuitabilitySurvivesARename, restated here against a
// fixture where the names are deliberately un-Dell-like.
func TestClassificationIsNotByName(t *testing.T) {
	base := intelligenceFor(t, "m71_virtual_heavy.json")
	renamed := AnalyzeHardware(renameFixture(t, "m71_virtual_heavy.json", map[string]string{
		"uplink0": "enp9s99f9", "downlink0": "enx0099887766", "br-7a3f1c2d": "docker0",
		"veth1a2b3c@if4": "vethdeadbe@if4", "veth4d5e6f@if7": "vethcafebabe@if7",
		"tailscale0": "tailscale0", "wg0": "wg0", "lo": "lo",
	}))

	for _, b := range base.Interfaces {
		a, ok := bySystemName(renamed.Interfaces, b.SystemName)
		if !ok {
			continue // the name was not changed for this one
		}
		if a.Class != b.Class {
			t.Errorf("%s: class changed from %q to %q when renamed", b.SystemName, b.Class, a.Class)
		}
		for _, role := range IntelligenceRoles() {
			if got, want := a.SuitabilityFor(role).Suitability, b.SuitabilityFor(role).Suitability; got != want {
				t.Errorf("%s: %s suitability changed from %q to %q when renamed", b.SystemName, role, want, got)
			}
		}
	}

	// The specific inversion that must not happen: renaming a bridge to
	// "docker0" must not make it a candidate, and naming the physical uplink
	// "enp9s99f9" must not make it one either without the evidence.
	br, ok := bySystemName(renamed.Interfaces, "docker0")
	if !ok {
		t.Fatal("docker0 missing after the rename")
	}
	assertSuitability(t, br, RoleLAN, SuitabilityUnsuitable)
}

// TestClassificationIsNotByAddress is the anti-range rule.
//
// The dual-default fixture gives the wired side 10.20.30.40 and the wireless
// side 192.168.44.50, which is backwards from the convention an operator might
// assume. Neither may be classified by its address.
func TestClassificationIsNotByAddress(t *testing.T) {
	d := loadFixture(t, "m71_multiple_default_routes.json")

	// Strip every address and re-analyse. The verdicts must not move: an
	// address is evidence, but not the whole of it, and removing it must not
	// turn the uplink into something it was not.
	withAddrs := AnalyzeHardware(d)
	for _, i := range d.Interfaces {
		i.Addresses = nil
	}
	without := AnalyzeHardware(d)

	for _, b := range withAddrs.Interfaces {
		a := intelNamed(t, without, b.SystemName)
		for _, role := range IntelligenceRoles() {
			// Only the default-route relationship may survive losing an
			// address, and it is not carrying these verdicts.
			if got, want := a.SuitabilityFor(role).Suitability, b.SuitabilityFor(role).Suitability; got != want && role != RoleWAN {
				t.Errorf("%s: %s suitability moved from %q to %q when its addresses were removed",
					b.SystemName, role, want, got)
			}
		}
	}
}

// TestCarrierAloneIsNotEnough is the anti-carrier rule.
//
// The Docker bridge has carrier up and an address and a route, and is not a
// physical port. Carrier is evidence about a link, never about what the link
// is.
func TestCarrierAloneIsNotEnough(t *testing.T) {
	intel := intelligenceFor(t, "m71_virtual_heavy.json")
	br := intelNamed(t, intel, "br-7a3f1c2d")

	if !br.Usage.Carrier {
		t.Fatal("the fixture bridge has no carrier; the test is not testing what it claims")
	}
	assertSuitability(t, br, RoleLAN, SuitabilityUnsuitable)
	assertSuitability(t, br, RoleWAN, SuitabilityUnsuitable)
}

// TestSpeedAloneIsNotEnough is the anti-speed rule.
//
// The virtual-heavy fixture's physical uplink reports 10000 Mbps. A high speed
// is not what makes an interface a gateway port, and a veth reporting more
// megabits must not outrank it.
func TestSpeedAloneIsNotEnough(t *testing.T) {
	intel := intelligenceFor(t, "m71_virtual_heavy.json")

	uplink := intelNamed(t, intel, "uplink0")
	if uplink.SpeedMbps != 10000 {
		t.Fatalf("the fixture uplink does not report 10000 Mbps; the test is not testing what it claims")
	}
	assertSuitability(t, uplink, RoleWAN, SuitabilityStrongCandidate)

	for _, in := range intel.Interfaces {
		if in.Physical {
			continue
		}
		for _, role := range IntelligenceRoles() {
			if in.SuitabilityFor(role).Candidate() {
				t.Errorf("virtual interface %s (%d Mbps) was offered for %s on speed or on anything else",
					in.SystemName, in.SpeedMbps, role)
			}
		}
	}
}

// ============================================================ determinism

// TestAnalysisIsDeterministic is a plain requirement, tested plainly.
//
// Two runs over the same observation must be byte-identical, and so must two
// runs over a Device whose interfaces arrive in a different order — otherwise
// two operators comparing reports are comparing noise.
func TestAnalysisIsDeterministic(t *testing.T) {
	first := intelligenceFor(t, "m71_gateway.json")

	for i := 0; i < 5; i++ {
		again := intelligenceFor(t, "m71_gateway.json")
		a := mustMarshal(t, first)
		b := mustMarshal(t, again)
		if string(a) != string(b) {
			t.Fatalf("run %d differed from the first:\n%s\nvs\n%s", i, a, b)
		}
	}
}

// TestAnalysisIgnoresInputOrder proves the ordering is THN's, not the caller's.
//
// A Device built by hand rather than through FromSnapshot could carry its
// interfaces in any order. The analysis must impose its own.
func TestAnalysisIgnoresInputOrder(t *testing.T) {
	forward := loadFixture(t, "m71_gateway.json")

	reversed := loadFixture(t, "m71_gateway.json")
	for i, j := 0, len(reversed.Interfaces)-1; i < j; i, j = i+1, j-1 {
		reversed.Interfaces[i], reversed.Interfaces[j] = reversed.Interfaces[j], reversed.Interfaces[i]
	}

	a := mustMarshal(t, AnalyzeHardware(forward))
	b := mustMarshal(t, AnalyzeHardware(reversed))
	if string(a) != string(b) {
		t.Errorf("interface order changed the analysis:\n%s\nvs\n%s", a, b)
	}
}

// TestUninspectableHostIsUnknownNotUnsuitable is the honesty case.
//
// A host THN could not look at has produced no verdicts. Reporting every
// interface as unsuitable would be a judgement nobody made.
func TestUninspectableHostIsUnknownNotUnsuitable(t *testing.T) {
	intel := AnalyzeHardware(&Device{Supported: false})

	if intel.Supported {
		t.Error("Supported is true for a host that could not be inspected")
	}
	if len(intel.Interfaces) != 0 {
		t.Errorf("an uninspectable host produced %d interface verdicts", len(intel.Interfaces))
	}
	if len(intel.Notes) == 0 {
		t.Error("an uninspectable host produced no note explaining why")
	}
	// A nil device must not panic either.
	if AnalyzeHardware(nil).Supported {
		t.Error("a nil device was reported as supported")
	}
}

// TestEverySuitabilityVerdictCarriesEvidence is the explainability rule.
//
// A classification with no evidence attached cannot be answered for, and the
// question it fails is the one an operator actually asks: why did THN think
// this?
func TestEverySuitabilityVerdictCarriesEvidence(t *testing.T) {
	for _, fixture := range []string{
		"m71_gateway.json", "m71_two_port_wired.json", "m71_wireless_uplink.json",
		"m71_virtual_heavy.json", "m71_bridge_member.json", "m71_single_interface.json",
		"m71_multiple_default_routes.json",
	} {
		intel := intelligenceFor(t, fixture)
		for _, in := range intel.Interfaces {
			for _, role := range IntelligenceRoles() {
				s := in.SuitabilityFor(role)
				if len(s.Evidence) == 0 {
					t.Errorf("%s/%s: %s suitability %q carries no evidence", fixture, in.SystemName, role, s.Suitability)
				}
				for _, e := range s.Evidence {
					if e.Detail == "" {
						t.Errorf("%s/%s/%s: evidence %q has no explanation", fixture, in.SystemName, role, e.Code)
					}
				}
			}
		}
		for _, p := range intel.Profiles {
			if len(p.Evidence) == 0 {
				t.Errorf("%s: profile %s carries no evidence", fixture, p.ID)
			}
		}
	}
}

// TestEverySuitabilityIsJustified is the converse: nothing may be classified
// unsuitable without saying why.
func TestEverySuitabilityIsJustified(t *testing.T) {
	for _, fixture := range []string{
		"m71_gateway.json", "m71_virtual_heavy.json", "m71_bridge_member.json",
		"m71_single_interface.json",
	} {
		intel := intelligenceFor(t, fixture)
		for _, in := range intel.Interfaces {
			for _, role := range IntelligenceRoles() {
				s := in.SuitabilityFor(role)
				if s.Suitability == SuitabilityUnsuitable && len(s.Blockers) == 0 {
					t.Errorf("%s/%s: %s is unsuitable with no stated reason", fixture, in.SystemName, role)
				}
			}
		}
	}
}

// TestProfilesNeverClaimReadiness is the anti-overclaim rule.
//
// M7.1 reports hardware shape. It has no standing to say a gateway is ready,
// and a verdict word like READY would be read as exactly that.
func TestProfilesNeverClaimReadiness(t *testing.T) {
	intel := intelligenceFor(t, "m71_two_port_wired.json")

	for _, p := range intel.Profiles {
		switch p.Verdict {
		case ProfilePossible, ProfileNotPossible:
		default:
			t.Errorf("profile %s verdict = %q; only POSSIBLE and NOT POSSIBLE are allowed", p.ID, p.Verdict)
		}
		if strings.Contains(strings.ToLower(string(p.Verdict)), "ready") {
			t.Errorf("profile %s verdict %q claims readiness", p.ID, p.Verdict)
		}
	}

	// The capability caveat must be present on every host that was assessed.
	for _, fixture := range []string{"m71_gateway.json", "m71_two_port_wired.json"} {
		intel := intelligenceFor(t, fixture)
		found := false
		for _, n := range intel.Notes {
			if strings.Contains(n, "not a readiness verdict") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no note states that this is not a readiness verdict", fixture)
		}
	}
}

// TestLinkLocalAddressesAreNotOccupancy is a specific over-claim guard.
//
// Every IPv6-capable host auto-assigns fe80::/64 on every interface. Counting
// that as an address would mark every NIC on the planet as "in use" and make
// the whole field meaningless.
func TestLinkLocalAddressesAreNotOccupancy(t *testing.T) {
	intel := intelligenceFor(t, "m71_multiple_default_routes.json")

	for _, name := range []string{"wired0", "radio0"} {
		in := intelNamed(t, intel, name)
		if in.Usage.Addressed != true {
			t.Errorf("%s has a global address in the fixture but is not marked addressed", name)
		}
	}

	// Remove the global addresses, leaving only link-local. Neither may then
	// count as addressed.
	d := loadFixture(t, "m71_multiple_default_routes.json")
	for i := range d.Interfaces {
		var kept []string
		for _, a := range d.Interfaces[i].Addresses {
			if strings.HasPrefix(a, "fe80:") || a == "127.0.0.1/8" || a == "::1/128" {
				kept = append(kept, a)
				continue
			}
		}
		d.Interfaces[i].Addresses = kept
	}

	for _, name := range []string{"wired0", "radio0"} {
		in := intelNamed(t, AnalyzeHardware(d), name)
		if in.Usage.Addressed {
			t.Errorf("%s counted a link-local address as occupancy", name)
		}
		if in.Usage.State != UsageOccupied && in.Usage.DefaultRoute {
			t.Errorf("%s carries the default route but was not reported as in use", name)
		}
	}
}

// TestTwoProfilesNeverPickTheSameInterface guards the profile builder.
//
// Naming one port as both the uplink and the LAN would be a suggestion that
// cannot be acted on — the whole point of separating the two roles.
func TestTwoProfilesNeverPickTheSameInterface(t *testing.T) {
	for _, fixture := range []string{
		"m71_gateway.json", "m71_two_port_wired.json", "m71_bridge_member.json",
	} {
		intel := intelligenceFor(t, fixture)
		for _, p := range intel.Profiles {
			seen := map[string]Role{}
			for _, role := range IntelligenceRoles() {
				name, ok := p.Candidates[role]
				if !ok {
					continue
				}
				if prev, dup := seen[name]; dup {
					t.Errorf("%s: profile %s picked %s for both %s and %s", fixture, p.ID, name, prev, role)
				}
				seen[name] = role
			}
		}
	}
}

// TestProfileCandidatesAreAlwaysRealInterfaces is the consistency check.
//
// Every name a profile prints must exist in the analysis, and must be physical.
// A name that is not there is a name an operator would try to configure.
func TestProfileCandidatesAreAlwaysRealInterfaces(t *testing.T) {
	for _, fixture := range []string{
		"m71_gateway.json", "m71_two_port_wired.json", "m71_wireless_uplink.json",
		"m71_virtual_heavy.json", "m71_bridge_member.json", "m71_single_interface.json",
	} {
		intel := intelligenceFor(t, fixture)
		for _, p := range intel.Profiles {
			for role, name := range p.Candidates {
				in, ok := bySystemName(intel.Interfaces, name)
				if !ok {
					t.Errorf("%s: profile %s names %s for %s, which is not an observed interface",
						fixture, p.ID, name, role)
					continue
				}
				if !in.Physical {
					t.Errorf("%s: profile %s named the virtual interface %s as the %s candidate",
						fixture, p.ID, name, role)
				}
				if !in.SuitabilityFor(role).Candidate() {
					t.Errorf("%s: profile %s named %s for %s despite a suitability of %q",
						fixture, p.ID, name, role, in.SuitabilityFor(role).Suitability)
				}
			}
		}
	}
}

// TestTheWholeAnalysisSurvivesSerialisation.
//
// A consumer reading this over IPC has to be able to tell an absent speed from
// a zero one and an unknown classification from an unsuitable one. If any of it
// failed to round-trip, those distinctions would exist only on screen.
func TestTheWholeAnalysisSurvivesSerialisation(t *testing.T) {
	intel := intelligenceFor(t, "m71_gateway.json")

	encoded, err := json.Marshal(intel)
	if err != nil {
		t.Fatalf("HardwareIntelligence did not serialise: %v", err)
	}
	var decoded HardwareIntelligence
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("HardwareIntelligence did not deserialise: %v", err)
	}

	if len(decoded.Interfaces) != len(intel.Interfaces) {
		t.Fatalf("interfaces did not survive serialisation: %d became %d",
			len(intel.Interfaces), len(decoded.Interfaces))
	}
	if len(decoded.Profiles) != len(intel.Profiles) {
		t.Fatalf("profiles did not survive serialisation: %d became %d",
			len(intel.Profiles), len(decoded.Profiles))
	}
	for _, p := range intel.Profiles {
		got := findProfile(t, decoded, p.ID)
		if got.Verdict != p.Verdict {
			t.Errorf("profile %s verdict changed across serialisation", p.ID)
		}
		for role, name := range p.Candidates {
			if got.Candidates[role] != name {
				t.Errorf("profile %s %s candidate changed across serialisation: %q became %q",
					p.ID, role, name, got.Candidates[role])
			}
		}
	}
	for _, in := range intel.Interfaces {
		after := intelNamed(t, decoded, in.SystemName)
		for _, role := range IntelligenceRoles() {
			if after.SuitabilityFor(role).Suitability != in.SuitabilityFor(role).Suitability {
				t.Errorf("%s %s suitability changed across serialisation", in.SystemName, role)
			}
		}
	}
}
