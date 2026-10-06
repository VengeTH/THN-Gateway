package cli

// M7.1 CLI acceptance: `thn host --analyze`.
//
// # What these tests are protecting
//
// The flag is the whole user-visible surface of M7.1, and there are exactly
// three ways it can be wrong in a way the analyzer tests cannot see:
//
//  1. It is accepted and ignored. A flag that parses, exits 0, and prints
//     nothing is indistinguishable from a flag that is not implemented, and an
//     operator who sees "no analysis section" concludes the tool does not do
//     analysis.
//
//  2. It changes the verdict. If --analyze moved a readiness status or an exit
//     code, then a CI job and an operator looking at the same host would get
//     different answers depending on which one asked for detail. That is the
//     OBSERVED/ASSIGNED line being crossed through the output, which is why
//     TestAnalyzeDoesNotChangeTheVerdict is here and not merely implied.
//
//  3. It breaks the existing output. `thn host` with no flags is consumed by
//     monitoring agents and CI jobs. M7.1 had better not have changed what
//     they see, which is why TestHostWithoutAnalyzeIsUnchanged exists.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/network"
)

// analysisDevice builds a two-port wired gateway: one port carrying the
// default route, one spare with no carrier.
//
// Built through network.Snapshot and host.FromSnapshot for the same reason the
// M7.0 fixtures are: the translation decides physicality, and a Device
// assembled by hand would skip it.
func analysisDevice() *host.Device {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		System: network.System{
			PrettyName:   "Ubuntu 24.04.4 LTS",
			Kernel:       "6.8.0-142-generic",
			Architecture: "amd64",
			Hostname:     "analysis-host",
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
		Interfaces: []network.Interface{
			{Name: "lo", Index: 1, Kind: "loopback", AdminUp: true,
				State: network.LinkUp, MTU: 65536},
			{Name: "uplink0", Index: 2, MAC: "3c:ec:ef:aa:00:01", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkUp,
				MTU: 1500, SpeedMbps: 1000},
			// No speed reported: the spare port's driver does not report one,
			// and rendering that as 0 Mbps would read as a measurement.
			{Name: "spare0", Index: 3, MAC: "3c:ec:ef:aa:00:02", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkDown,
				MTU: 1500},
		},
		Addresses: []network.Address{
			{Family: "inet", CIDR: "127.0.0.1/8", Interface: "lo"},
			{Family: "inet", CIDR: "203.0.113.20/24", Interface: "uplink0"},
		},
		Routes: []network.Route{
			{Destination: "default", Gateway: "203.0.113.1", Interface: "uplink0",
				Protocol: "dhcp", Default: true},
		},
	}
	return host.FromSnapshot(snap)
}

// renderHostWith renders a host with or without the analysis.
func renderHostWith(t *testing.T, d *host.Device, analyze bool) string {
	t.Helper()
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})
	var intel host.HardwareIntelligence
	if analyze {
		intel = host.AnalyzeHardware(d)
	}
	return RenderHost(d, false, ready, intel, analyze)
}

// TestAnalyzeFlagParses is the acceptance case.
//
// It goes through parseHostOptions because that is the only place the flag can
// be wired to nothing while still parsing cleanly.
func TestAnalyzeFlagParses(t *testing.T) {
	opts, err := parseHostOptions([]string{"--analyze"})
	if err != nil {
		t.Fatalf("thn host --analyze: unexpected parse error: %v", err)
	}
	if !opts.Analyze {
		t.Error("--analyze parsed to false")
	}

	// And it must default to off, or every existing consumer of `thn host`
	// would silently start rendering a section they did not ask for.
	plain, err := parseHostOptions(nil)
	if err != nil {
		t.Fatalf("thn host: unexpected parse error: %v", err)
	}
	if plain.Analyze {
		t.Error("--analyze defaulted to true; it must be opt-in")
	}

	// And it must compose with the other flags rather than replacing them.
	both, err := parseHostOptions([]string{"--analyze", "--requires", "3", "--mac"})
	if err != nil {
		t.Fatalf("combined flags: unexpected parse error: %v", err)
	}
	if !both.Analyze || both.Requires != 3 || !both.ShowMAC {
		t.Errorf("combined flags parsed as %+v; --analyze must not displace the others", both)
	}
}

// TestAnalyzeRendersTheSuitabilitySection is the primary acceptance case.
//
// The section has to exist and has to contain the answers an operator is
// looking for, not just a heading.
func TestAnalyzeRendersTheSuitabilitySection(t *testing.T) {
	out := renderHostWith(t, analysisDevice(), true)

	for _, want := range []string{
		"Hardware suitability",
		"uplink0",
		"spare0",
		"2 physical port(s)",
		"Gateway profiles",
		"Two-port wired gateway",
		"POSSIBLE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("analysis output is missing %q:\n%s", want, out)
		}
	}
}

// TestAnalyzeExplainsTheUplink is the explainability case.
//
// An operator must be able to ask "why does THN think this is a good WAN
// candidate?" and get an answer in the output. This asserts the specific
// observed facts, not just that some prose appeared.
func TestAnalyzeExplainsTheUplink(t *testing.T) {
	out := renderHostWith(t, analysisDevice(), true)
	uplink := interfaceSection(t, out, "uplink0")

	if !strings.Contains(uplink, "strong candidate") {
		t.Errorf("the default-route uplink was not reported as a strong candidate:\n%s", uplink)
	}
	for _, want := range []string{
		"physical Ethernet",    // what it is
		"a carrier is present", // link state
		"1000 Mbps",            // observed speed
		"an observed default route uses this interface", // routing evidence
	} {
		if !strings.Contains(uplink, want) {
			t.Errorf("uplink0 evidence is missing %q:\n%s", want, uplink)
		}
	}

	// Occupancy is reported as current state, separately from suitability.
	if !strings.Contains(uplink, "in use") {
		t.Errorf("uplink0 occupancy was not reported as current state:\n%s", uplink)
	}
}

// TestAnalyzeReportsUnknownSpeedHonestly is the no-invention case.
//
// spare0 has no speed in the fixture, and rendering "0 Mbps" would read as a
// measurement rather than an absence of one.
func TestAnalyzeReportsUnknownSpeedHonestly(t *testing.T) {
	out := renderHostWith(t, analysisDevice(), true)
	spare := interfaceSection(t, out, "spare0")

	if strings.Contains(spare, "0 Mbps") {
		t.Errorf("an unreported link speed was rendered as 0 Mbps:\n%s", spare)
	}
	if !strings.Contains(spare, "speed unknown") {
		t.Errorf("the spare port does not say its speed is unknown:\n%s", spare)
	}
	// And it must still be offered: no carrier is a limitation, not a verdict.
	if !strings.Contains(spare, "candidate") {
		t.Errorf("a spare port with no cable in it was not offered as a candidate:\n%s", spare)
	}
	if !strings.Contains(spare, "no carrier is present") {
		t.Errorf("the missing carrier was not stated as a limitation:\n%s", spare)
	}
}

// TestAnalyzeNeverAssignsARole is the safety case, in the output.
//
// A role name may appear only in a candidate position or a suitability
// verdict. "WAN: uplink0" would read as a decision, and would be one.
func TestAnalyzeNeverAssignsARole(t *testing.T) {
	out := renderHostWith(t, analysisDevice(), true)

	if !strings.Contains(out, "Suitability is not assignment") {
		t.Errorf("the analysis does not state that suitability is not assignment:\n%s", out)
	}

	verdicts := []string{"strong candidate", "candidate", "limited candidate",
		"unsuitable", "unknown", "observed", "inferred"}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, role := range []string{"WAN", "LAN", "MGMT"} {
			if !strings.HasPrefix(trimmed, role+" ") {
				continue
			}
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, role))
			if strings.HasPrefix(rest, "candidate:") {
				continue
			}
			matched := false
			for _, v := range verdicts {
				if rest == v || strings.HasPrefix(rest, v+" ") {
					matched = true
				}
			}
			if !matched {
				t.Errorf("a role appears in a form that reads as a decision: %q", trimmed)
			}
		}
	}
}

// TestAnalyzeDoesNotChangeTheVerdict is case 2 from the file comment.
//
// Adding analysis must not move readiness. A CI job and an operator asking for
// detail have to get the same answer.
func TestAnalyzeDoesNotChangeTheVerdict(t *testing.T) {
	d := analysisDevice()
	plain := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})

	// Evaluating readiness after running the analysis must give the identical
	// verdict. The analyzer has no parameter through which it could change
	// readiness, and this proves it did not reach around one.
	host.AnalyzeHardware(d)
	after := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})

	if plain.Status != after.Status {
		t.Errorf("readiness changed after analysis: %s became %s", plain.Status, after.Status)
	}
	if plain.Blocked != after.Blocked || len(plain.Findings) != len(after.Findings) {
		t.Error("readiness findings changed after analysis")
	}
	if got := d.RoleAssignments(); len(got) != 0 {
		t.Errorf("analysis produced role assignments: %+v", got)
	}
}

// TestHostWithoutAnalyzeIsUnchanged is case 3 from the file comment.
//
// Everything the existing report prints has to still print, and none of the
// analysis vocabulary may appear.
func TestHostWithoutAnalyzeIsUnchanged(t *testing.T) {
	out := renderHostWith(t, analysisDevice(), false)

	for _, absent := range []string{
		"Hardware suitability", "Gateway profiles", "strong candidate",
		"candidate", "POSSIBLE", "Suitability is not assignment",
	} {
		if strings.Contains(out, absent) {
			t.Errorf("the plain report contains %q:\n%s", absent, out)
		}
	}

	// And the M7.0 content is all still there, because the flag is additive.
	for _, present := range []string{"Platform", "Interfaces", "Capabilities",
		"Readiness", "STATUS:", "Current network remains untouched"} {
		if !strings.Contains(out, present) {
			t.Errorf("the plain report is missing %q:\n%s", present, out)
		}
	}
}

// TestAnalyzeHelpDocumentsTheFlag is the discoverability case.
//
// A flag that is implemented but unlisted is the same defect from an
// operator's side as one that is not implemented.
func TestAnalyzeHelpDocumentsTheFlag(t *testing.T) {
	env, out, errOut := newTestEnv("host", "--help")

	if got := Run(env); got != ExitOK {
		t.Fatalf("thn host --help exited %d, want %d; stderr: %s", got, ExitOK, errOut.String())
	}
	text := out.String()
	for _, want := range []string{"--analyze", "--requires", "--mac", "--json"} {
		if !strings.Contains(text, want) {
			t.Errorf("thn host --help does not document %s:\n%s", want, text)
		}
	}
	// The help has to be honest about what the flag does, because "analyze"
	// is exactly the sort of word an operator will read as "decide".
	if !strings.Contains(text, "not assignment") {
		t.Errorf("the help does not distinguish suitability from assignment:\n%s", text)
	}
}

// interfaceSection returns the rendered block for one interface.
//
// Scoped by indentation rather than by substring, so an assertion about one
// interface cannot pass on another's text.
func interfaceSection(t *testing.T, out, name string) string {
	t.Helper()

	var block []string
	inBlock := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "  "+name+"  [") {
			inBlock = true
			block = append(block, line)
			continue
		}
		if !inBlock {
			continue
		}
		if strings.HasPrefix(line, "  Gateway profiles") {
			break
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "      ") {
			break
		}
		block = append(block, line)
	}
	if len(block) == 0 {
		t.Fatalf("no rendered section for %s:\n%s", name, out)
	}
	return strings.Join(block, "\n")
}

// --------------------------------------------------- machine-readable output

// TestAnalyzeJSONExposesStructuredSuitability is the automation case.
//
// The JSON has to be structured. A consumer that has to parse prose to find
// out whether an interface is a WAN candidate has no consumer at all.
func TestAnalyzeJSONExposesStructuredSuitability(t *testing.T) {
	d := analysisDevice()
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})

	out := hostJSON(d, false, ready, 2, host.AnalyzeHardware(d), true)
	decoded := decodeHostJSON(t, out)

	hardware, ok := decoded["hardware"].(map[string]any)
	if !ok {
		t.Fatal("the JSON report has no hardware block")
	}

	// The top-level promises a consumer relies on.
	for key, want := range map[string]any{
		"assignment_made":      false,
		"network_untouched":    true,
		"is_readiness_verdict": false,
	} {
		if got := hardware[key]; got != want {
			t.Errorf("hardware.%s = %v, want %v", key, got, want)
		}
	}
	// Compared after the round trip, which is where JSON numbers become
	// float64. A consumer reads the decoded document, not the Go value, so the
	// decoded form is what has to be right.
	if got := jsonNumber(t, hardware["physical_ethernet"]); got != 2 {
		t.Errorf("hardware.physical_ethernet = %v, want 2", got)
	}

	// Find the uplink interface and read its WAN verdict as a value.
	uplink := jsonInterface(t, hardware, "uplink0")

	suit, _ := uplink["suitability"].(map[string]any)
	wan, _ := suit["wan"].(map[string]any)
	if wan == nil {
		t.Fatalf("uplink0 has no wan suitability: %v", suit)
	}
	if got := wan["classification"]; got != string(host.SuitabilityStrongCandidate) {
		t.Errorf("uplink0 wan classification = %v, want strong_candidate", got)
	}
	if got := wan["confidence"]; got != string(host.ConfidenceObserved) {
		t.Errorf("uplink0 wan confidence = %v, want observed", got)
	}
	if got := wan["candidate"]; got != true {
		t.Errorf("uplink0 wan candidate = %v, want true", got)
	}

	// The evidence must be structured too: codes a program can match on, and
	// at least the default-route code, which is the fact the verdict rests on.
	var sawDefaultRoute bool
	for _, e := range wan["evidence"].([]any) {
		if e.(map[string]any)["code"] == "default-route" {
			sawDefaultRoute = true
		}
	}
	if !sawDefaultRoute {
		t.Errorf("uplink0 wan evidence has no default-route code: %v", wan["evidence"])
	}
}

func decodeHostJSON(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("the report did not serialise: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("the report did not deserialise: %v", err)
	}
	return decoded
}

func jsonInterface(t *testing.T, hardware map[string]any, name string) map[string]any {
	t.Helper()
	for _, i := range hardware["interfaces"].([]any) {
		m := i.(map[string]any)
		if m["system_name"] == name {
			return m
		}
	}
	t.Fatalf("%s is missing from hardware.interfaces", name)
	return nil
}

// TestAnalyzeJSONKeepsUnknownSpeedAbsent is the no-invention case, in JSON.
//
// A consumer reading speed_mbps must never see a zero that means "nobody
// reported this".
func TestAnalyzeJSONKeepsUnknownSpeedAbsent(t *testing.T) {
	d := analysisDevice()
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})
	out := hostJSON(d, false, ready, 2, host.AnalyzeHardware(d), true)

	hardware := decodeHostJSON(t, out)["hardware"].(map[string]any)
	spare := jsonInterface(t, hardware, "spare0")

	if _, present := spare["speed_mbps"]; present {
		t.Errorf("spare0 reported a speed of %v; the fixture never gave it one", spare["speed_mbps"])
	}
	if known, _ := spare["speed_known"].(bool); known {
		t.Error("spare0 speed_known is true; the fixture never gave it a speed")
	}
}

// TestJSONOmitsHardwareWhenNotRequested keeps the two shapes distinguishable.
//
// A consumer needs to tell "not asked for" from "asked for, nothing to say".
func TestJSONOmitsHardwareWhenNotRequested(t *testing.T) {
	d := analysisDevice()
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})

	without := hostJSON(d, false, ready, 2, host.HardwareIntelligence{}, false)
	if _, present := without["hardware"]; present {
		t.Error("the hardware block appeared without --analyze")
	}

	// The observation itself is unchanged by the flag, so a consumer of the
	// existing fields sees the same values either way.
	with := hostJSON(d, false, ready, 2, host.AnalyzeHardware(d), true)
	for _, key := range []string{"interfaces", "capabilities", "readiness", "routes"} {
		if mustJSON(t, without[key]) != mustJSON(t, with[key]) {
			t.Errorf("%q changed when --analyze was added", key)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return string(b)
}

// jsonNumber reads a whole number out of a decoded JSON document.
//
// encoding/json decodes every number into float64, so a consumer reading the
// document sees a float — and a test asserting on the Go int would be
// asserting on something no consumer can observe.
func jsonNumber(t *testing.T, v any) int {
	t.Helper()
	n, ok := v.(float64)
	if !ok {
		t.Fatalf("value %#v is %T, want a JSON number", v, v)
	}
	return int(n)
}

// TestAnalysisRenderingIsDeterministic guards the report itself.
//
// An operator comparing two runs is comparing the host, not the difference
// between two orderings.
func TestAnalysisRenderingIsDeterministic(t *testing.T) {
	first := renderHostWith(t, analysisDevice(), true)
	for i := 0; i < 5; i++ {
		if again := renderHostWith(t, analysisDevice(), true); again != first {
			t.Fatalf("run %d rendered differently:\n%s\nvs\n%s", i, first, again)
		}
	}
}

// TestAnalysisOfAnUninspectableHostStillRenders is the honesty case, in the
// CLI. An unsupported host must produce a clear explanation, not an empty
// section and not a panic.
func TestAnalysisOfAnUninspectableHostStillRenders(t *testing.T) {
	out := renderHostWith(t, &host.Device{Supported: false}, true)

	if !strings.Contains(out, "could not be inspected") {
		t.Errorf("an uninspectable host produced no explanation:\n%s", out)
	}
	if strings.Contains(out, "strong candidate") || strings.Contains(out, "POSSIBLE") {
		t.Errorf("an uninspectable host produced a suitability verdict:\n%s", out)
	}
}

// TestVirtualInterfacesAreNotOfferedInTheCLIRenderer closes the loop.
//
// The analyzer tests prove the model refuses to offer a Docker bridge. This
// proves the thing an operator actually reads does not either.
func TestVirtualInterfacesAreNotOfferedInTheCLIRenderer(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "lo", Index: 1, Kind: "loopback", AdminUp: true, State: network.LinkUp},
			{Name: "uplink0", Index: 2, MAC: "3c:ec:ef:bb:00:01", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkUp,
				SpeedMbps: 1000},
			{Name: "spare0", Index: 3, MAC: "3c:ec:ef:bb:00:02", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkDown},
			{Name: "docker0", Index: 4, MAC: "02:42:aa:bb:cc:01", Kind: "bridge",
				LinkType: "ether", AdminUp: true, State: network.LinkUp},
			{Name: "veth1@if4", Index: 5, MAC: "11:22:33:44:55:66", Kind: "veth",
				LinkType: "ether", AdminUp: true, State: network.LinkUp, Master: "docker0"},
			{Name: "tailscale0", Index: 6, Kind: "tun", LinkType: "none",
				AdminUp: true, State: network.LinkUp},
		},
		Addresses: []network.Address{
			{Family: "inet", CIDR: "203.0.113.20/24", Interface: "uplink0"},
			{Family: "inet", CIDR: "172.20.0.1/16", Interface: "docker0"},
		},
		Routes: []network.Route{
			{Destination: "default", Gateway: "203.0.113.1", Interface: "uplink0", Default: true},
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
	}

	out := renderHostWith(t, host.FromSnapshot(snap), true)

	for _, name := range []string{"docker0", "veth1@if4", "tailscale0", "lo"} {
		section := interfaceSection(t, out, name)
		if !strings.Contains(section, "unsuitable") {
			t.Errorf("%s was not reported as unsuitable in the rendered output:\n%s", name, section)
		}
	}

	// And none of them may appear as a profile candidate.
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "candidate:") {
			continue
		}
		for _, name := range []string{"docker0", "veth1@if4", "tailscale0", "lo"} {
			if strings.Contains(line, name) {
				t.Errorf("a virtual interface was named as a profile candidate: %q",
					strings.TrimSpace(line))
			}
		}
	}
}
