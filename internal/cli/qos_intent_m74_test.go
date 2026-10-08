package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
	"github.com/VengeTH/THN-Gateway/internal/planner"
)

func qosServiceConfig() config.Config {
	cfg := config.Defaults()
	cfg.Gateway.Name = "m74-qos"
	cfg.Gateway.Enabled = true
	cfg.Gateway.Generation = 7
	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "enp1s0"
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.NAT.Enabled = true
	cfg.NAT.Masquerade.Enabled = true
	cfg.NAT.Masquerade.Outbound = "wan"
	cfg.DHCP.Enabled = true
	cfg.DHCP.Ranges = []config.DHCPRangeConfig{
		{Start: "10.77.0.100", End: "10.77.0.250"},
	}
	cfg.DNS.Enabled = true
	cfg.DNS.Upstream = append([]string(nil), cfg.Network.DNS...)
	cfg.QoS.Enabled = true
	cfg.QoS.Algorithm = "cake"
	cfg.QoS.Interface = "enp0s31f6"
	cfg.QoS.DownloadKbps = 100_000
	cfg.QoS.UploadKbps = 20_000
	cfg.QoS.OverheadPercent = 10
	cfg.Firewall.AdminSources = []string{"192.168.77.0/24"}
	return cfg
}

// TestValidateReportsGatewayDHCPDNSAndQoSSeparately asserts that `thn validate`
// presents four distinct, understandable intent sections.
func TestValidateReportsGatewayDHCPDNSAndQoSSeparately(t *testing.T) {
	path := writeIntentConfig(t, qosServiceConfig())

	stdout, stderr, _ := runGateCLI(t, "validate", path)

	for _, want := range []string{"Gateway intent:", "DHCP intent:", "DNS intent:", "QoS intent:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("`thn validate` did not report %q:\n%s\n%s", want, stdout, stderr)
		}
	}

	// QoS section must show the requested shaping parameters and evidence.
	if !strings.Contains(stdout, "cake") {
		t.Errorf("the QoS section must mention cake:\n%s", stdout)
	}
	if !strings.Contains(stdout, "100000kbit/s") {
		t.Errorf("the QoS section must show the download rate:\n%s", stdout)
	}
	if !strings.Contains(stdout, "20000kbit/s") {
		t.Errorf("the QoS section must show the upload rate:\n%s", stdout)
	}
}

// TestConfigValidateDelegatesToSamePipelineWithQoS asserts that `thn config validate`
// and `thn validate` produce identical verdicts for QoS as well as the other intents.
func TestConfigValidateDelegatesToSamePipelineWithQoS(t *testing.T) {
	path := writeIntentConfig(t, qosServiceConfig())

	a, _, _ := runGateCLI(t, "validate", path)
	b, _, _ := runGateCLI(t, "config", "validate", path)

	for _, section := range []string{"Gateway intent:", "DHCP intent:", "DNS intent:", "QoS intent:"} {
		if x, y := intentVerdict(a, section), intentVerdict(b, section); x != y {
			t.Errorf("%s: `thn validate` said %q but `thn config validate` said %q", section, x, y)
		}
	}
}

// TestValidateQoSUnknownCapabilityIsPending pins the M7.4 capability rule:
// with no live observation, QoS is PENDING because CAKE availability is unknown,
// but it is NEVER treated as unavailable or failing the static gate.
func TestValidateQoSUnknownCapabilityIsPending(t *testing.T) {
	path := writeIntentConfig(t, qosServiceConfig())

	stdout, _, code := runGateCLI(t, "validate", path)

	if code != ExitOK {
		t.Fatalf("`thn validate` must pass for a valid QoS config; got exit code %d:\n%s", code, stdout)
	}

	verdict := intentVerdict(stdout, "QoS intent:")
	if verdict != "PENDING" {
		t.Errorf("QoS intent verdict = %q, want PENDING (CAKE unknown)", verdict)
	}

	// Plain English explanation that CAKE availability was not established without host observation.
	if !strings.Contains(stdout, "CAKE availability was not established") && !strings.Contains(stdout, "qos-cake-unknown") {
		t.Errorf("expected explanation that CAKE is unknown in output:\n%s", stdout)
	}

	// Must NOT report CAKE unavailable.
	if strings.Contains(stdout, "qos-cake-unavailable") || strings.Contains(stdout, "qos-algorithm-unavailable") {
		t.Errorf("QoS must not claim CAKE is unavailable:\n%s", stdout)
	}
}

// TestValidateJSONExposesAllFourIndependently asserts that JSON output exposes
// gateway, dhcp, dns, and qos independently.
func TestValidateJSONExposesAllFourIndependently(t *testing.T) {
	path := writeIntentConfig(t, qosServiceConfig())

	stdout, stderr, _ := runGateCLI(t, "validate", "--json", path)

	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("validate --json is not valid JSON: %v\n%s\n%s", err, stdout, stderr)
	}

	for _, key := range []string{"gateway", "dhcp", "dns", "qos"} {
		sec, ok := doc[key].(map[string]any)
		if !ok {
			t.Fatalf("JSON has no %q object; keys: %v", key, keysOf(doc))
		}
		if _, ok := sec["verdict"].(string); !ok {
			t.Errorf("%q has no string \"verdict\"; keys: %v", key, keysOf(sec))
		}
	}
}

// TestValidateQoSRoleConflictIsBlocked asserts that setting QoS interface to LAN
// blocks QoS intent with qos-wan-conflict.
func TestValidateQoSRoleConflictIsBlocked(t *testing.T) {
	cfg := qosServiceConfig()
	cfg.QoS.Interface = "lan"

	path := writeIntentConfig(t, cfg)
	stdout, _, code := runGateCLI(t, "validate", path)

	if code == ExitOK {
		t.Errorf("a document with QoS on LAN must not pass the gate:\n%s", stdout)
	}
	if !strings.Contains(stdout, "qos-wan-conflict") {
		t.Errorf("expected finding code qos-wan-conflict:\n%s", stdout)
	}
	if !strings.Contains(stdout, "QoS intent: BLOCKED") {
		t.Errorf("expected QoS intent: BLOCKED:\n%s", stdout)
	}
}

// TestValidateQoSMissingRateIsBlocked asserts that missing rate blocks the gate.
func TestValidateQoSMissingRateIsBlocked(t *testing.T) {
	cfg := qosServiceConfig()
	cfg.QoS.DownloadKbps = 0
	cfg.QoS.UploadKbps = 0

	path := writeIntentConfig(t, cfg)
	stdout, _, code := runGateCLI(t, "validate", path)

	if code == ExitOK {
		t.Errorf("a document with zero rates must not pass the gate:\n%s", stdout)
	}
	if !strings.Contains(stdout, "qos-rate-missing") {
		t.Errorf("expected finding code qos-rate-missing:\n%s", stdout)
	}
	if !strings.Contains(stdout, "QoS intent: BLOCKED") {
		t.Errorf("expected QoS intent: BLOCKED:\n%s", stdout)
	}
}

// TestValidateUnresolvedWANExplainsDependency asserts that when WAN cannot be
// resolved, QoS reports qos-wan-unresolved rather than claiming CAKE is unavailable.
func TestValidateUnresolvedWANExplainsDependency(t *testing.T) {
	cfg := qosServiceConfig()
	cfg.Network.WAN = "hw:99notattached"
	cfg.QoS.Interface = ""

	path := writeIntentConfig(t, cfg)
	stdout, _, _ := runGateCLI(t, "validate", path)

	if !strings.Contains(stdout, "qos-wan-unresolved") {
		t.Errorf("expected qos-wan-unresolved when WAN is unresolved:\n%s", stdout)
	}
	if strings.Contains(stdout, "qos-cake-unavailable") || strings.Contains(stdout, "qos-algorithm-unavailable") {
		t.Errorf("unresolved WAN must not blame CAKE availability:\n%s", stdout)
	}
}

// TestPlanJSONExposesAllFourIndependently asserts that `thn plan --json` exposes
// all four intent reports alongside the plan.
func TestPlanJSONExposesAllFourIndependently(t *testing.T) {
	path := writeIntentConfig(t, qosServiceConfig())

	stdout, stderr, _ := runGateCLI(t, "plan", "--json", path)

	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("plan --json is not valid JSON: %v\n%s\n%s", err, stdout, stderr)
	}

	for _, key := range []string{"gateway", "dhcp", "dns", "qos"} {
		sec, ok := doc[key].(map[string]any)
		if !ok {
			t.Fatalf("JSON has no %q object; keys: %v", key, keysOf(doc))
		}
		if _, ok := sec["verdict"].(string); !ok {
			t.Errorf("%q has no string \"verdict\"; keys: %v", key, keysOf(sec))
		}
	}
}

// TestPlanDescribesQoSIntentWithoutFakeCommands is the regression test required
// by Section 32: planning output must not contain invented implementation commands.
func TestPlanDescribesQoSIntentWithoutFakeCommands(t *testing.T) {
	path := writeIntentConfig(t, qosServiceConfig())

	stdout, stderr, _ := runGateCLI(t, "plan", path)

	if !strings.Contains(stdout, "cake") {
		t.Errorf("`thn plan` must describe the requested QoS algorithm:\n%s\n%s", stdout, stderr)
	}

	// Must NOT contain invented implementation commands.
	for _, forbidden := range []string{
		"tc qdisc add",
		"tc qdisc replace",
		"tc qdisc del",
		"modprobe sch_cake",
		"systemctl",
		"apt-get",
	} {
		if strings.Contains(stdout, forbidden) {
			t.Errorf("`thn plan` rendered %q, which claims an implementation exists:\n%s",
				forbidden, stdout)
		}
	}
}

// TestPlanStepCarriesNoCommandsForQoS asserts that the planner's qos-intent step
// has Commands == nil, RequiresRoot == false, and Reversible == "not-applied".
func TestPlanStepCarriesNoCommandsForQoS(t *testing.T) {
	d := desired.FromConfig(qosServiceConfig())

	p := planner.Build(diff.Result{}, planner.Options{
		Generation: 7,
		Source:     "test",
		Desired:    d,
	})

	found := false
	for _, s := range p.Steps {
		if s.ID == "qos-intent" {
			found = true
			if len(s.Commands) != 0 {
				t.Errorf("step %s carries commands %v; M7.4 must not fake tc implementation", s.ID, s.Commands)
			}
			if s.RequiresRoot {
				t.Errorf("step %s claims to need root; nothing is applied", s.ID)
			}
			if s.Reversible != "not-applied" {
				t.Errorf("step %s Reversible = %q, want not-applied", s.ID, s.Reversible)
			}
		}
	}

	if !found {
		t.Errorf("plan does not contain qos-intent step; steps: %v", stepIDs(p))
	}
}

// TestQoSPlanActionNoopVsUpdate asserts that matching observed discipline produces
// ActionNoop while differing discipline produces ActionUpdate.
func TestQoSPlanActionNoopVsUpdate(t *testing.T) {
	d := desired.FromConfig(qosServiceConfig())

	// Host with CAKE already attached -> NOOP
	devCake := &host.Device{
		TrafficControl: network.TCState{
			Checked:      true,
			Available:    true,
			CakeObserved: true,
			Qdiscs:       []network.Qdisc{{Kind: "cake", Device: "enp0s31f6"}},
		},
		Capabilities: map[host.Capability]host.CapabilityState{
			host.CapCake: {Available: true, Confidence: host.ConfidenceObserved},
		},
	}

	pNoop := planner.Build(diff.Result{}, planner.Options{
		Generation: 7,
		Source:     "test",
		Desired:    d,
		Device:     devCake,
	})

	for _, s := range pNoop.Steps {
		if s.ID == "qos-intent" {
			if s.Action != planner.ActionNoop {
				t.Errorf("expected ActionNoop when CAKE is already attached, got %s", s.Action)
			}
		}
	}

	// Host with fq_codel attached -> UPDATE
	devFq := &host.Device{
		TrafficControl: network.TCState{
			Checked:      true,
			Available:    true,
			CakeObserved: false,
			Qdiscs:       []network.Qdisc{{Kind: "fq_codel", Device: "enp0s31f6"}},
		},
		Capabilities: map[host.Capability]host.CapabilityState{
			host.CapCake: {Available: false, Confidence: host.ConfidenceUnknown},
		},
	}

	pUpdate := planner.Build(diff.Result{}, planner.Options{
		Generation: 7,
		Source:     "test",
		Desired:    d,
		Device:     devFq,
	})

	for _, s := range pUpdate.Steps {
		if s.ID == "qos-intent" {
			if s.Action != planner.ActionUpdate {
				t.Errorf("expected ActionUpdate when host has different discipline, got %s", s.Action)
			}
		}
	}
}

// TestQoSChangesChangeDesiredDigest asserts content-addressed digest sensitivity
// to all QoS parameters.
func TestQoSChangesChangeDesiredDigest(t *testing.T) {
	base := desired.FromConfig(qosServiceConfig())
	baseDigest := planner.ComputeDesiredDigest(base)

	// Changing download rate
	cfgDown := qosServiceConfig()
	cfgDown.QoS.DownloadKbps = 200_000
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgDown)) == baseDigest {
		t.Error("changing download rate did not change the desired digest")
	}

	// Changing upload rate
	cfgUp := qosServiceConfig()
	cfgUp.QoS.UploadKbps = 50_000
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgUp)) == baseDigest {
		t.Error("changing upload rate did not change the desired digest")
	}

	// Changing algorithm
	cfgAlg := qosServiceConfig()
	cfgAlg.QoS.Algorithm = "fq_codel"
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgAlg)) == baseDigest {
		t.Error("changing QoS algorithm did not change the desired digest")
	}

	// Changing enablement
	cfgOff := qosServiceConfig()
	cfgOff.QoS.Enabled = false
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgOff)) == baseDigest {
		t.Error("turning QoS off did not change the desired digest")
	}

	// Changing overhead
	cfgOver := qosServiceConfig()
	cfgOver.QoS.OverheadPercent = 15
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgOver)) == baseDigest {
		t.Error("changing overhead percent did not change the desired digest")
	}
}

// TestQoSPlanIsDeterministic asserts that repeated planning of the same QoS
// configuration produces identical plan IDs and steps.
func TestQoSPlanIsDeterministic(t *testing.T) {
	d := desired.FromConfig(qosServiceConfig())

	first := planner.Build(diff.Result{}, planner.Options{Generation: 7, Source: "test", Desired: d})
	for i := 0; i < 5; i++ {
		got := planner.Build(diff.Result{}, planner.Options{Generation: 7, Source: "test", Desired: d})
		if got.ID != first.ID {
			t.Fatalf("run %d: plan ID = %s, want %s", i, got.ID, first.ID)
		}
		if len(got.Steps) != len(first.Steps) {
			t.Fatalf("run %d: %d steps, want %d", i, len(got.Steps), len(first.Steps))
		}
	}
}

// TestQoSUnmanagedQdiscPreservedInStep asserts that unmanaged queue disciplines
// are noted as observed and not adopted by THN.
func TestQoSUnmanagedQdiscPreservedInStep(t *testing.T) {
	d := desired.FromConfig(qosServiceConfig())
	dev := &host.Device{
		TrafficControl: network.TCState{
			Checked:      true,
			Available:    true,
			CakeObserved: false,
			Qdiscs:       []network.Qdisc{{Kind: "fq_codel", Device: "enp0s31f6"}},
		},
	}

	p := planner.Build(diff.Result{}, planner.Options{
		Generation: 7,
		Source:     "test",
		Desired:    d,
		Device:     dev,
	})

	found := false
	for _, s := range p.Steps {
		if s.ID == "qos-intent" {
			found = true
			if !strings.Contains(s.Current, "fq_codel") || !strings.Contains(s.Current, "not adopted by THN") {
				t.Errorf("step current = %q, want unmanaged fq_codel noted", s.Current)
			}
		}
	}
	if !found {
		t.Error("qos-intent step not found")
	}
}

// TestM74SafetyInvariants asserts that shaping intent did not become a way to
// change a host.
func TestM74SafetyInvariants(t *testing.T) {
	assertActivationRemainsGated(t, "adding QoS intent")
}

// TestM74ValidationAndPlanningDoNotMutate asserts that neither validate nor plan
// attempts live mutation or requires privileges.
func TestM74ValidationAndPlanningDoNotMutate(t *testing.T) {
	path := writeIntentConfig(t, qosServiceConfig())

	for _, args := range [][]string{
		{"validate", path},
		{"config", "validate", path},
		{"plan", path},
		{"config", "plan", path},
	} {
		if _, stderr, _ := runGateCLI(t, args...); strings.Contains(stderr, "permission denied") {
			t.Errorf("`thn %s` required privileges:\n%s", strings.Join(args, " "), stderr)
		}
	}
}
