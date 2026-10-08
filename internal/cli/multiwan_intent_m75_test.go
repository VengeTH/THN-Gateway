package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
	"github.com/VengeTH/THN-Gateway/internal/planner"
)

func multiWANServiceConfig() config.Config {
	cfg := config.Defaults()
	cfg.Gateway.Name = "m75-multiwan"
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
	cfg.Firewall.AdminSources = []string{"192.168.77.0/24"}

	cfg.MultiWAN = config.MultiWANConfig{
		Enabled: true,
		Mode:    "load_balance",
		Policy:  "default",
		Members: []config.WANMemberConfig{
			{
				ID:        "pldt",
				Interface: "enp0s31f6",
				Weight:    2,
				Priority:  100,
				Enabled:   true,
			},
			{
				ID:        "converge",
				Interface: "enx00e099001812",
				Weight:    1,
				Priority:  100,
				Enabled:   true,
			},
		},
		HealthCheck: config.WANHealthCheckConfig{
			Target:   "1.1.1.1",
			Interval: 10 * time.Second,
			Timeout:  2 * time.Second,
		},
	}
	return cfg
}

// -----------------------------------------------------------------------------
// Integration Tests
// -----------------------------------------------------------------------------

// TestValidateReportsAllFiveIntentsSeparately asserts that `thn validate`
// presents Gateway, DHCP, DNS, QoS and Multi-WAN intent sections.
func TestValidateReportsAllFiveIntentsSeparately(t *testing.T) {
	path := writeIntentConfig(t, multiWANServiceConfig())

	stdout, stderr, _ := runGateCLI(t, "validate", path)

	for _, want := range []string{"Gateway intent:", "DHCP intent:", "DNS intent:", "QoS intent:", "Multi-WAN intent:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("`thn validate` did not report %q:\n%s\n%s", want, stdout, stderr)
		}
	}

	// Multi-WAN section must show mode and members.
	if !strings.Contains(stdout, "load_balance") {
		t.Errorf("the Multi-WAN section must report load_balance mode:\n%s", stdout)
	}
	if !strings.Contains(stdout, "pldt") || !strings.Contains(stdout, "converge") {
		t.Errorf("the Multi-WAN section must show member IDs:\n%s", stdout)
	}
}

// TestConfigValidateDelegatesToSamePipelineWithMultiWAN asserts that
// `thn config validate` agrees with `thn validate`.
func TestConfigValidateDelegatesToSamePipelineWithMultiWAN(t *testing.T) {
	path := writeIntentConfig(t, multiWANServiceConfig())

	a, _, _ := runGateCLI(t, "validate", path)
	b, _, _ := runGateCLI(t, "config", "validate", path)

	for _, section := range []string{"Gateway intent:", "DHCP intent:", "DNS intent:", "QoS intent:", "Multi-WAN intent:"} {
		if x, y := intentVerdict(a, section), intentVerdict(b, section); x != y {
			t.Errorf("%s: `thn validate` said %q but `thn config validate` said %q", section, x, y)
		}
	}
}

// TestValidateJSONExposesAllFiveIndependently asserts that `--json` exposes
// gateway, dhcp, dns, qos, and multi_wan independently.
func TestValidateJSONExposesAllFiveIndependently(t *testing.T) {
	path := writeIntentConfig(t, multiWANServiceConfig())

	stdout, stderr, _ := runGateCLI(t, "validate", "--json", path)

	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("validate --json is not valid JSON: %v\n%s\n%s", err, stdout, stderr)
	}

	for _, key := range []string{"gateway", "dhcp", "dns", "qos", "multi_wan"} {
		sec, ok := doc[key].(map[string]any)
		if !ok {
			t.Fatalf("JSON has no %q object; keys: %v", key, keysOf(doc))
		}
		if _, ok := sec["verdict"].(string); !ok {
			t.Errorf("%q has no string \"verdict\"; keys: %v", key, keysOf(sec))
		}
	}
}

// TestPlanJSONExposesAllFiveIndependently asserts that `thn plan --json` exposes
// all five intent reports alongside the plan.
func TestPlanJSONExposesAllFiveIndependently(t *testing.T) {
	path := writeIntentConfig(t, multiWANServiceConfig())

	stdout, stderr, _ := runGateCLI(t, "plan", "--json", path)

	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("plan --json is not valid JSON: %v\n%s\n%s", err, stdout, stderr)
	}

	for _, key := range []string{"gateway", "dhcp", "dns", "qos", "multi_wan"} {
		sec, ok := doc[key].(map[string]any)
		if !ok {
			t.Fatalf("JSON has no %q object; keys: %v", key, keysOf(doc))
		}
		if _, ok := sec["verdict"].(string); !ok {
			t.Errorf("%q has no string \"verdict\"; keys: %v", key, keysOf(sec))
		}
	}
}

// -----------------------------------------------------------------------------
// Desired State Tests (Section 44: 1-7)
// -----------------------------------------------------------------------------

// TestDesiredStateCarriesMultiWAN asserts that desired state contains mode,
// policy, and members.
func TestDesiredStateCarriesMultiWAN(t *testing.T) {
	cfg := multiWANServiceConfig()
	d := desired.FromConfig(cfg)

	if !d.MultiWAN.Enabled {
		t.Error("MultiWAN must be enabled in desired state")
	}
	if d.MultiWAN.Mode != "load_balance" {
		t.Errorf("mode = %q, want load_balance", d.MultiWAN.Mode)
	}
	if len(d.MultiWAN.Members) != 2 {
		t.Fatalf("members count = %d, want 2", len(d.MultiWAN.Members))
	}
	if d.MultiWAN.Members[0].ID != "converge" || d.MultiWAN.Members[1].ID != "pldt" {
		t.Errorf("members not deterministically sorted by ID: %v", d.MultiWAN.Members)
	}
}

// TestMultiWANChangesAffectDigest asserts that changing any Multi-WAN parameter
// alters the content-addressed desired digest.
func TestMultiWANChangesAffectDigest(t *testing.T) {
	base := desired.FromConfig(multiWANServiceConfig())
	baseDigest := planner.ComputeDesiredDigest(base)

	// Mode change
	cfgMode := multiWANServiceConfig()
	cfgMode.MultiWAN.Mode = "failover"
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgMode)) == baseDigest {
		t.Error("changing Multi-WAN mode did not change the desired digest")
	}

	// Weight change
	cfgWeight := multiWANServiceConfig()
	cfgWeight.MultiWAN.Members[0].Weight = 5
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgWeight)) == baseDigest {
		t.Error("changing member weight did not change the desired digest")
	}

	// Priority change
	cfgPrio := multiWANServiceConfig()
	cfgPrio.MultiWAN.Members[0].Priority = 50
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgPrio)) == baseDigest {
		t.Error("changing member priority did not change the desired digest")
	}

	// Member ID change
	cfgID := multiWANServiceConfig()
	cfgID.MultiWAN.Members[0].ID = "isp-primary"
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgID)) == baseDigest {
		t.Error("changing member ID did not change the desired digest")
	}

	// Health check target change
	cfgTarget := multiWANServiceConfig()
	cfgTarget.MultiWAN.HealthCheck.Target = "8.8.8.8"
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgTarget)) == baseDigest {
		t.Error("changing health check target did not change the desired digest")
	}

	// Multi-WAN off
	cfgOff := multiWANServiceConfig()
	cfgOff.MultiWAN.Enabled = false
	if planner.ComputeDesiredDigest(desired.FromConfig(cfgOff)) == baseDigest {
		t.Error("turning Multi-WAN off did not change the desired digest")
	}
}

// TestDesiredStateGenerationIsDeterministic asserts identical digests across repeated runs.
func TestDesiredStateGenerationIsDeterministic(t *testing.T) {
	cfg := multiWANServiceConfig()
	first := planner.ComputeDesiredDigest(desired.FromConfig(cfg))
	for i := 0; i < 5; i++ {
		got := planner.ComputeDesiredDigest(desired.FromConfig(cfg))
		if got != first {
			t.Fatalf("run %d produced different digest: got %s, want %s", i, got, first)
		}
	}
}

// -----------------------------------------------------------------------------
// Planner Tests (Section 44: 1-9)
// -----------------------------------------------------------------------------

// TestPlanDescribesMultiWANWithoutFakeCommands is the regression test ensuring
// planning output contains NO invented implementation commands.
func TestPlanDescribesMultiWANWithoutFakeCommands(t *testing.T) {
	path := writeIntentConfig(t, multiWANServiceConfig())

	stdout, stderr, _ := runGateCLI(t, "plan", path)

	if !strings.Contains(stdout, "load_balance") {
		t.Errorf("`thn plan` must describe the requested mode:\n%s\n%s", stdout, stderr)
	}

	// Must NOT contain invented implementation commands.
	for _, forbidden := range []string{
		"ip rule add",
		"ip rule del",
		"ip route add",
		"ip route del",
		"ip route replace",
		"nft add",
		"nft delete",
		"modprobe",
		"systemctl",
		"apt-get",
	} {
		if strings.Contains(stdout, forbidden) {
			t.Errorf("`thn plan` rendered %q, which claims an applier exists:\n%s", forbidden, stdout)
		}
	}
}

// TestPlanStepCarriesNoCommandsForMultiWAN asserts that the planner's
// multi-wan-intent step carries Commands == nil and Reversible == "not-applied".
func TestPlanStepCarriesNoCommandsForMultiWAN(t *testing.T) {
	d := desired.FromConfig(multiWANServiceConfig())

	p := planner.Build(diff.Result{}, planner.Options{
		Generation: 7,
		Source:     "test",
		Desired:    d,
	})

	found := false
	for _, s := range p.Steps {
		if s.ID == "multi-wan-intent" {
			found = true
			if len(s.Commands) != 0 {
				t.Errorf("step %s carries commands %v; M7.5 must not fake routing commands", s.ID, s.Commands)
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
		t.Errorf("plan does not contain multi-wan-intent step; steps: %v", stepIDs(p))
	}
}

// TestSingleMatchingWANProducesNoopAction asserts that an already matched
// single WAN uplink results in ActionNoop.
func TestSingleMatchingWANProducesNoopAction(t *testing.T) {
	cfg := config.Defaults()
	cfg.Network.WAN = "enp0s31f6"
	d := desired.FromConfig(cfg)

	dev := &host.Device{
		Supported: true,
		Routes: []network.Route{
			{Destination: "default", Gateway: "192.168.1.1", Interface: "enp0s31f6"},
		},
	}

	p := planner.Build(diff.Result{}, planner.Options{
		Generation: 1,
		Source:     "test",
		Desired:    d,
		Device:     dev,
	})

	for _, s := range p.Steps {
		if s.ID == "multi-wan-intent" {
			if s.Action != planner.ActionNoop {
				t.Errorf("matching single WAN should produce ActionNoop, got %s", s.Action)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Safety Tests (Section 44: 1-9)
// -----------------------------------------------------------------------------

// TestM75SafetyInvariants asserts that multi-WAN intent did not become a way
// to change a host.
func TestM75SafetyInvariants(t *testing.T) {
	assertActivationRemainsGated(t, "adding Multi-WAN intent")
}

// TestM75ValidationAndPlanningDoNotMutate asserts that neither validate nor plan
// attempts live mutation or requires privileges.
func TestM75ValidationAndPlanningDoNotMutate(t *testing.T) {
	path := writeIntentConfig(t, multiWANServiceConfig())

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
