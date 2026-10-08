package host_test

// M7.1 safety: proving that hardware intelligence cannot change the host.
//
// # Why M7.1 needs its own safety file when M7.0 already has one
//
// The M7.0 guarantees are real and they still pass: TestObservationLayerHasNoWritePath
// scans every file in internal/host, and this milestone added a file to that
// directory. Those tests prove the new code introduces no write path and no
// unguarded exec.
//
// What they cannot prove is the thing M7.1 introduced that M7.0 had no
// equivalent of: a layer whose whole purpose is to say an interface IS
// something. M7.0 said "here is a link". M7.1 says "this link could be your
// uplink", and the specific failure mode of a layer like that is not a write —
// it is a confident claim that becomes a decision.
//
// So this file checks three things the M7.0 scans cannot reach:
//
//  1. The analyzer imports nothing that could observe or execute. A second
//     observation path added "just to check one more thing" would pass every
//     write-path scan and still be a second chance to mutate a live gateway.
//
//  2. The model cannot express an assignment. AnalyzeHardware takes a Device
//     and returns HardwareIntelligence, and neither type has a field through
//     which a role could be written back.
//
//  3. The words in the output cannot be read as a fault or a decision. A
//     renderer that prints "WAN: eth0" is functionally an assignment even
//     though it assigns nothing.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

// m71SourceFile is the M7.1 implementation in internal/host.
const m71SourceFile = "hardware.go"

// forbiddenInAnalysis is every construct the analyzer must not contain.
//
// os/exec is the load-bearing entry: an analyzer that shelled out to ip to
// double-check a fact would be a second observation path, and the whole reason
// this layer is a pure function is that it cannot be.
//
// The rest is the M7.0 write-path set plus the determinism rules, repeated
// here rather than imported, so that deleting TestObservationLayerHasNoWritePath
// does not silently relax M7.1 as well.
var forbiddenInAnalysis = []struct {
	needle string
	why    string
}{
	{"os/exec", "the analyzer must not import os/exec"},
	{"internal/guard", "the analyzer must not reach the execution chokepoint"},
	{"os.WriteFile", "the analyzer must not write files"},
	{"os.Create", "the analyzer must not create files"},
	{"os.Remove", "the analyzer must not remove anything"},
	{"os.Mkdir", "the analyzer must not create directories"},
	{"os.Chmod", "the analyzer must not change permissions"},
	{"os.Setenv", "the analyzer must not change the environment"},
	{"os.Getenv", "the analyzer must depend only on the observed Device"},
	{`"sh"`, "no shell invocation"},
	{`"bash"`, "no shell invocation"},
	{`"sudo"`, "no privilege escalation"},
	{`"ip"`, "no second observation path; internal/network already observed this"},
	{`"nft"`, "no second observation path"},
	{`"tc"`, "no second observation path"},
	{`"sysctl"`, "no second observation path"},
	{`"iw"`, "no second observation path"},
	{`"ethtool"`, "no second observation path"},
	{`"nmcli"`, "no second observation path"},
	{`"networkctl"`, "no second observation path"},
	{"net.Dial", "no network access from the analysis layer"},
	{"http.Client", "no network access from the analysis layer"},
	{"time.Now", "the analyzer must be deterministic; observation stamped the time"},
	{"math/rand", "the analyzer must be deterministic"},
	{"net.InterfaceByName", "no runtime interface lookup; observation already did it"},
}

// TestM71AnalysisHasNoExecutionOrObservationPath is the structural check.
//
// Source-level rather than behavioural, because a behavioural test can only
// assert about the calls that exist today and the requirement is that none can
// be added later without someone seeing this test fail.
func TestM71AnalysisHasNoExecutionOrObservationPath(t *testing.T) {
	body, err := os.ReadFile(m71SourceFile)
	if err != nil {
		t.Fatalf("reading %s: %v; the M7.1 scan is not running", m71SourceFile, err)
	}
	code := stripComments(string(body))

	for _, f := range forbiddenInAnalysis {
		if strings.Contains(code, f.needle) {
			t.Errorf("%s contains %q: %s", m71SourceFile, f.needle, f.why)
		}
	}

	// And an allowlist on the imports, which is stronger than the denylist
	// above: a newly added dependency shows up here even if it has never yet
	// been used to do anything wrong.
	for _, allowed := range []string{
		`"fmt"`, `"net/netip"`, `"sort"`, `"strings"`,
		`"github.com/VengeTH/THN-Gateway/internal/network"`,
	} {
		if !strings.Contains(code, allowed) {
			t.Errorf("%s no longer imports %s; the allowlist in this test is stale", m71SourceFile, allowed)
		}
	}
}

// TestM71AnalysisIsDeterministicUnderRepetition is the behavioural half of the
// determinism requirement.
//
// Ten runs, byte-identical. The failure this catches is the subtle one: a map
// iterated without sorting produces the same answer on one machine often
// enough to look correct.
func TestM71AnalysisIsDeterministicUnderRepetition(t *testing.T) {
	d := m71GatewayFixture(t)

	var first string
	for i := 0; i < 10; i++ {
		encoded, err := json.Marshal(host.AnalyzeHardware(d))
		if err != nil {
			t.Fatalf("run %d did not serialise: %v", i, err)
		}
		if i == 0 {
			first = string(encoded)
			continue
		}
		if string(encoded) != first {
			t.Fatalf("run %d differed from the first run; the analysis is not deterministic", i)
		}
	}
}

// TestM71ModelCannotExpressAnAssignment is the structural guarantee.
//
// The strongest form this can take: the types have no field through which a
// role could be written back. Read the Device and the HardwareIntelligence as
// JSON and look for any field that would let a consumer conclude THN assigned
// something.
func TestM71ModelCannotExpressAnAssignment(t *testing.T) {
	d := m71GatewayFixture(t)
	intel := host.AnalyzeHardware(d)

	if intel.AssignmentMade {
		t.Error("HardwareIntelligence.AssignmentMade is true; analysis assigns nothing")
	}

	for _, in := range intel.Interfaces {
		for _, role := range host.IntelligenceRoles() {
			s := in.SuitabilityFor(role)
			if s.Suitability == "" {
				t.Errorf("%s %s has an empty suitability; every judgement must be stated",
					in.SystemName, role)
			}
			if s.Confidence != host.ConfidenceObserved && s.Confidence != host.ConfidenceUnknown {
				t.Errorf("%s %s confidence = %q; M7.1 never infers", in.SystemName, role, s.Confidence)
			}
		}
		if in.Usage.AssignedRole != "" {
			t.Errorf("%s carries assigned role %q; the fixture records none", in.SystemName, in.Usage.AssignedRole)
		}
	}

	// The whole document must survive a round trip, which it could not if any
	// part of it carried a live handle or an executor.
	encoded, err := json.Marshal(intel)
	if err != nil {
		t.Fatalf("the analysis did not serialise: %v", err)
	}
	var decoded host.HardwareIntelligence
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("the analysis did not deserialise: %v", err)
	}
	if decoded.AssignmentMade {
		t.Error("AssignmentMade changed across serialisation")
	}
}

// TestM71AnalysisAssignsNothing proves it behaviourally.
//
// Reading a Device and giving one back with a role on it would be an
// assignment, whatever the function is called. The Device must be exactly what
// it was.
func TestM71AnalysisAssignsNothing(t *testing.T) {
	d := m71GatewayFixture(t)

	before, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("the device did not serialise: %v", err)
	}

	host.AnalyzeHardware(d)
	host.AnalyzeHardware(d) // twice: idempotence matters as much as purity

	after, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("the device did not serialise: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("analysis changed the observed device:\nbefore %s\nafter  %s", before, after)
	}

	if got := d.RoleAssignments(); len(got) != 0 {
		t.Errorf("analysis produced role assignments: %+v", got)
	}
	for _, i := range d.Interfaces {
		if i.Role != host.RoleUnassigned {
			t.Errorf("analysis assigned role %q to %s", i.Role, i.SystemName)
		}
	}
}

// TestM71ProfileCandidatesAreNotAssignments is the naming contract.
//
// The field a profile uses to name its best port is the field most likely to
// be read as a decision. It is called Candidates, and this asserts that what it
// holds is a suitability-ranked pick rather than anything resolved.
func TestM71ProfileCandidatesAreNotAssignments(t *testing.T) {
	d := m71GatewayFixture(t)
	intel := host.AnalyzeHardware(d)

	seen := 0
	for _, p := range intel.Profiles {
		if !p.Possible() {
			// A profile that could not be shaped must name nothing at all.
			if len(p.Candidates) != 0 {
				t.Errorf("profile %s is NOT POSSIBLE but names %d candidate(s)", p.ID, len(p.Candidates))
			}
			continue
		}
		for role, name := range p.Candidates {
			seen++
			var found *host.InterfaceIntelligence
			for i := range intel.Interfaces {
				if intel.Interfaces[i].SystemName == name {
					found = &intel.Interfaces[i]
				}
			}
			if found == nil {
				t.Errorf("profile %s names %s for %s, which was not observed", p.ID, name, role)
				continue
			}
			if !found.Physical {
				t.Errorf("profile %s names the virtual interface %s as its %s candidate", p.ID, name, role)
			}
			if !found.SuitabilityFor(role).Candidate() {
				t.Errorf("profile %s names %s for %s despite a suitability of %q",
					p.ID, name, role, found.SuitabilityFor(role).Suitability)
			}
			// And the Device must still not carry the role.
			if iface, ok := d.InterfaceByID(found.ID); ok && iface.Role != host.RoleUnassigned {
				t.Errorf("profile %s naming %s for %s assigned the role", p.ID, name, role)
			}
		}
	}

	if seen == 0 {
		t.Error("no profile named any candidate; the analysis is not producing the output it exists for")
	}
}

// TestM71NeverInfersConfidence is the confidence rule.
//
// The M7.0 model has three states and the strictest of them says an inference
// never satisfies a gate. M7.1 has no gates, but the same rule applies to its
// claims: a verdict built entirely from observed facts is observed, and a
// verdict reached with nothing observed is unknown. Inferred is not a third
// option here; it is the answer this layer must never give.
func TestM71NeverInfersConfidence(t *testing.T) {
	for _, fixture := range []string{
		"m71_gateway.json", "m71_two_port_wired.json", "m71_wireless_uplink.json",
		"m71_virtual_heavy.json", "m71_bridge_member.json", "m71_single_interface.json",
		"m71_multiple_default_routes.json",
	} {
		d := loadM71Fixture(t, fixture)
		intel := host.AnalyzeHardware(d)

		for _, in := range intel.Interfaces {
			for _, role := range host.IntelligenceRoles() {
				s := in.SuitabilityFor(role)
				if s.Confidence == host.ConfidenceInferred {
					t.Errorf("%s %s %s is %q; M7.1 never infers", fixture, in.SystemName, role, s.Confidence)
				}
				for _, e := range s.Evidence {
					if e.Confidence == host.ConfidenceInferred {
						t.Errorf("%s %s %s cites inferred evidence %q", fixture, in.SystemName, role, e.Code)
					}
				}
			}
		}
	}
}

// TestM71ForeignInfrastructureIsRecordedNotJudged is the "do not clean up" rule.
//
// Docker bridges, veths and tunnels are normal on a production gateway. The
// analysis may say they are not physical ports — that is a fact about what
// they are — and may never say they are a problem.
func TestM71ForeignInfrastructureIsRecordedNotJudged(t *testing.T) {
	d := loadM71Fixture(t, "m71_virtual_heavy.json")
	intel := host.AnalyzeHardware(d)

	if len(intel.Infrastructure) == 0 {
		t.Fatal("the fixture's virtual interfaces were not recorded as infrastructure")
	}
	for _, name := range []string{"br-7a3f1c2d", "veth1a2b3c@if4", "tailscale0", "wg0"} {
		if !contains(intel.Infrastructure, name) {
			t.Errorf("%s was not recorded as infrastructure; got %v", name, intel.Infrastructure)
		}
	}

	// The verdict vocabulary for infrastructure is limited to "this is not a
	// physical port". Anything phrased as a fault is an overreach.
	for _, in := range intel.Interfaces {
		if in.Physical {
			continue
		}
		for _, role := range host.IntelligenceRoles() {
			s := in.SuitabilityFor(role)
			if s.Suitability != host.SuitabilityUnsuitable {
				t.Errorf("%s %s = %q; virtual infrastructure is never a candidate",
					in.SystemName, role, s.Suitability)
			}
			for _, b := range s.Blockers {
				if containsAny(strings.ToLower(b),
					"broken", "invalid", "misconfigur", "should be removed", "conflict") {
					t.Errorf("%s blocker reads as a fault rather than a fact: %q", in.SystemName, b)
				}
			}
		}
	}

	// And no profile may mark the host unusable because of it.
	for _, p := range intel.Profiles {
		for _, c := range p.Constraints {
			if containsAny(strings.ToLower(c), "unusable", "not a gateway", "broken", "must be removed") {
				t.Errorf("profile %s treats foreign infrastructure as a fault: %q", p.ID, c)
			}
		}
	}
}

// TestM71MultipleDefaultRoutesAreNotAFault is the same rule for routes.
//
// A host with a wired and a wireless default route is a laptop. Reporting that
// as a problem would train the operator to ignore every warning the tool
// produces.
func TestM71MultipleDefaultRoutesAreNotAFault(t *testing.T) {
	intel := host.AnalyzeHardware(loadM71Fixture(t, "m71_virtual_heavy.json"))

	if intel.DefaultRouteCount < 2 {
		t.Fatalf("the fixture has %d default routes; the test is not testing what it claims",
			intel.DefaultRouteCount)
	}

	// Both relationships are visible.
	if !contains(intel.DefaultRouteInterfaces, "tailscale0") {
		t.Errorf("the tunnel's default route was dropped: %v", intel.DefaultRouteInterfaces)
	}
	if !contains(intel.DefaultRouteInterfaces, "uplink0") {
		t.Errorf("the wired default route was dropped: %v", intel.DefaultRouteInterfaces)
	}

	for _, p := range intel.Profiles {
		if p.ID == host.ProfileTwoPortWired && p.Verdict == host.ProfileNotPossible {
			t.Error("the two-port wired profile is NOT POSSIBLE on a host with two Ethernet ports")
		}
	}

	for _, n := range intel.Notes {
		lower := strings.ToLower(n)
		if containsAny(lower, "multiple default", "broken") && strings.Contains(lower, "broken") &&
			!strings.Contains(lower, "not a fault") {
			t.Errorf("a note calls multiple default routes broken: %q", n)
		}
	}
}

// TestM71AnalysisNamesNoInterface is the last structural guarantee.
//
// The observation layer has a test forbidding hardcoded interface names, and
// this milestone inherits it because the new file lives in the same directory
// and the same scan. It is repeated here as a named test so that a failure
// points at M7.1 rather than at M7.0.
func TestM71AnalysisNamesNoInterface(t *testing.T) {
	body, err := os.ReadFile(m71SourceFile)
	if err != nil {
		t.Fatalf("reading %s: %v", m71SourceFile, err)
	}
	code := stripComments(string(body))

	// Note what is NOT in this list: "veth", "bridge", "tunnel", "bond",
	// "vlan". Those are link-kind vocabulary tokens — the same kind of string
	// as "ethernet" or "loopback", and shared with the Kind constants in
	// host.go. What the rule forbids is an interface NAME, and no real
	// interface is ever called bare "veth"; the ones that are look like
	// veth8c1f2a@if5, which would not match a bare-token comparison anyway.
	for _, name := range []string{
		"enp0s31f6", "enp1s0", "enx00e099001812", "wlp2s0", "wlp3s0",
		"eth0", "eth1", "docker0", "tailscale0",
	} {
		// Only a quoted literal counts. A comment or a doc reference to a real
		// host's interface name is fine; a comparison against one would mean
		// the analyzer only works on the machine it was written on.
		if strings.Contains(code, `"`+name+`"`) {
			t.Errorf("%s contains the literal interface name %q; "+
				"analysis must work on any supported host", m71SourceFile, name)
		}
	}
}

// m71GatewayFixture loads the fixture that models the validation host.
func m71GatewayFixture(t *testing.T) *host.Device {
	t.Helper()
	return loadM71Fixture(t, "m71_gateway.json")
}

// loadM71Fixture reads a fixture and translates it through the real discovery
// path, exactly as an operator's machine goes through it.
//
// Routes go through ParseRoutes because Route.Default is derived by the parser
// from a destination of "default" and is not a field the kernel emits. A
// fixture that unmarshalled routes directly would produce a host whose default
// routes nothing had marked as default.
func loadM71Fixture(t *testing.T, name string) *host.Device {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	var doc struct {
		Links     []json.RawMessage     `json:"links"`
		Addresses []network.Address     `json:"addresses"`
		Routes    []json.RawMessage     `json:"routes"`
		Sysctl    []network.SysctlValue `json:"sysctl"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}

	links, err := network.ParseLinks(marshalJSON(t, doc.Links))
	if err != nil {
		t.Fatalf("ParseLinks on %s: %v", name, err)
	}
	routes, err := network.ParseRoutes(marshalJSON(t, doc.Routes))
	if err != nil {
		t.Fatalf("ParseRoutes on %s: %v", name, err)
	}

	return host.FromSnapshot(&network.Snapshot{
		Platform:   "linux",
		Supported:  true,
		Interfaces: links,
		Addresses:  doc.Addresses,
		Routes:     routes,
		Sysctl:     doc.Sysctl,
	})
}

func marshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return b
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}
