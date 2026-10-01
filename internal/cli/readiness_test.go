package cli

// `thn readiness` — the operator-facing view of activation.Evaluate.
//
// The command exists because the gates had no operator-facing surface: an
// operator could only learn what was blocking them by running `thn activate`
// and reading a refusal that never named the gates.
//
// These tests pin the three properties that make the report trustworthy: it
// agrees with Evaluate, it says plainly that the build is the blocker, and it
// cannot claim the network was touched.

import (
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/config"
)

// completeGatewayConfig is the canonical deployable document.
//
// It is the same shape the repository's example configuration uses: both
// interfaces identified, NAT scoped to the LAN, a pool and resolvers inside
// the LAN, administration restricted to the LAN. It is deliberately complete
// apart from facts only the host can supply.
func completeGatewayConfig() config.Config {
	cfg := config.Defaults()
	cfg.Gateway.Name = "thn-gateway"
	cfg.Gateway.Generation = 1

	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "enp1s0"
	cfg.Network.LANPrefix = "192.168.1.1/24"
	cfg.Network.MTU = 1500
	cfg.Network.DNS = []string{"1.1.1.1", "9.9.9.9"}

	cfg.NAT.Enabled = true
	// LAN only: masquerading from the WAN is a routing loop and the static
	// layer refuses to name the WAN here.
	cfg.NAT.Interfaces = []string{"enp1s0"}
	// Masquerade states its outbound explicitly. Leaving it unset is now an
	// error, because the rendered rule would otherwise apply to every
	// interface including the LAN.
	cfg.NAT.Masquerade.Enabled = true
	cfg.NAT.Masquerade.Outbound = "wan"

	cfg.Firewall.Enabled = true
	cfg.Firewall.Backend = "nftables"
	cfg.Firewall.DefaultInboundPolicy = "drop"

	cfg.DHCP.Enabled = true
	cfg.DHCP.Authoritative = true
	cfg.DHCP.Domain = "lan.home"
	cfg.DHCP.Ranges = []config.DHCPRangeConfig{
		{Start: "192.168.1.100", End: "192.168.1.250"},
	}

	cfg.DNS.Enabled = true
	cfg.DNS.LocalDomain = "lan.home"

	return cfg
}

// TestReadinessNamesTheBlockingGates is the command's reason for existing.
func TestReadinessNamesTheBlockingGates(t *testing.T) {
	_, path := loadTopology(t, completeGatewayConfig())

	stdout, stderr, code := runGateCLI(t, "readiness", path)

	if code == ExitOK {
		t.Fatalf("readiness reported success on a build with no apply path\n%s", stdout)
	}

	// The two words an operator needs, in capitals.
	if !strings.Contains(stdout, "BLOCKED") {
		t.Errorf("output does not say BLOCKED:\n%s", stdout)
	}
	if strings.Contains(stdout, "READY\n") {
		t.Errorf("output contains READY on a blocked gateway:\n%s", stdout)
	}

	// Every blocking gate must be listed by name.
	for _, want := range []string{"apply-path-available", "physical-presence"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output does not name the blocking gate %q:\n%s\nstderr:\n%s", want, stdout, stderr)
		}
	}
}

// TestReadinessSaysTheBuildIsTheBlocker is the most useful sentence it prints.
//
// Without this an operator reads "BLOCKED: apply-path-available" and goes
// looking for a setting that does not exist.
func TestReadinessSaysTheBuildIsTheBlocker(t *testing.T) {
	_, path := loadTopology(t, completeGatewayConfig())

	stdout, _, _ := runGateCLI(t, "readiness", path)

	if !strings.Contains(stdout, "blocked by the BUILD") {
		t.Errorf("output does not attribute the blocking to the build:\n%s", stdout)
	}
	if !strings.Contains(stdout, "No setting changes it") {
		t.Errorf("output does not say the blocker is not configurable:\n%s", stdout)
	}
}

// TestReadinessAgreesWithValidateOnConfigValidity is the anti-divergence check.
//
// If readiness reports config-valid while `thn validate` reports an error, an
// operator is being told two different things about the same document, and
// readiness is the one they would act on.
func TestReadinessAgreesWithValidateOnConfigValidity(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*config.Config)
	}{
		{"valid", func(*config.Config) {}},
		{"pool outside the LAN", func(c *config.Config) {
			c.DHCP.Ranges = []config.DHCPRangeConfig{{Start: "192.168.2.10", End: "192.168.2.100"}}
		}},
		{"reversed pool", func(c *config.Config) {
			c.DHCP.Ranges = []config.DHCPRangeConfig{{Start: "192.168.1.250", End: "192.168.1.10"}}
		}},
		{"cross-subnet pool", func(c *config.Config) {
			c.DHCP.Ranges = []config.DHCPRangeConfig{{Start: "192.168.1.250", End: "192.168.2.10"}}
		}},
		{"no LAN interface", func(c *config.Config) { c.Network.LAN = "" }},
		{"NAT names the WAN", func(c *config.Config) {
			c.NAT.Interfaces = []string{"enp0s31f6"}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := completeGatewayConfig()
			tc.mut(&cfg)
			_, path := loadTopology(t, cfg)

			_, _, validateCode := runGateCLI(t, "validate", path)
			stdout, _, _ := runGateCLI(t, "readiness", path)

			gateBlocked := strings.Contains(stdout, "BLOCK  config-valid")
			validateFailed := validateCode != ExitOK

			if gateBlocked != validateFailed {
				t.Errorf("validate says failed=%v but readiness reports config-valid blocked=%v\n%s",
					validateFailed, gateBlocked, stdout)
			}
		})
	}
}

// TestReadinessNeverClaimsItTouchedTheNetwork is the safety assertion.
func TestReadinessNeverClaimsItTouchedTheNetwork(t *testing.T) {
	_, path := loadTopology(t, completeGatewayConfig())

	stdout, _, code := runGateCLI(t, "readiness", path)
	if code == ExitOK {
		t.Fatalf("readiness reported success:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Current network remains untouched") {
		t.Errorf("output does not state that the network is untouched:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Can apply:      false") {
		t.Errorf("output does not report CanApply false:\n%s", stdout)
	}
}

// TestReadinessIsACommandThatExists registers it in the dispatch table and
// gives it the tier the other read-only lifecycle commands have.
func TestReadinessIsACommandThatExists(t *testing.T) {
	cmd, ok := commands["readiness"]
	if !ok {
		t.Fatal("readiness is not in the command table")
	}
	if cmd.Tier != TierPure {
		t.Errorf("readiness tier = %q, want %q", cmd.Tier, TierPure)
	}
	if cmd.Summary == "" {
		t.Error("readiness has no summary; it would be undiscoverable in `thn help`")
	}
}

// TestReadinessJSONCarriesTheGates checks the machine-readable path.
//
// A CI check that cannot read which gate blocked cannot automate "is this
// deployable yet", which is the whole reason to have the command.
func TestReadinessJSONCarriesTheGates(t *testing.T) {
	_, path := loadTopology(t, completeGatewayConfig())

	doc, code := runGateJSON(t, "readiness", path)
	if code == ExitOK {
		t.Fatal("readiness reported success on a build with no apply path")
	}

	if got := jsonString(t, doc, "readiness"); got != "BLOCKED" {
		t.Errorf("readiness = %q, want BLOCKED", got)
	}
	if jsonBool(t, doc, "can_apply") {
		t.Error("can_apply is true; this build must not be able to apply")
	}
	if !jsonBool(t, doc, "network_untouched") {
		t.Error("network_untouched is false")
	}

	blocking, ok := doc["blocking"].([]any)
	if !ok {
		t.Fatalf("blocking is %T, want an array", doc["blocking"])
	}
	if len(blocking) == 0 {
		t.Error("blocking is empty on a blocked gateway")
	}
	if !jsonBool(t, doc, "all_gates_satisfied") {
		// Expected; asserted so the field is known to exist.
		t.Log("all_gates_satisfied is false, as expected for this build")
	}

	gates, ok := doc["gates"].([]any)
	if !ok {
		t.Fatalf("gates is %T, want an array", doc["gates"])
	}
	if len(gates) != 7 {
		t.Errorf("gates has %d entries, want 7", len(gates))
	}
}

// TestReadinessVerdictWordsAreDistinct guards the one function the whole
// command's meaning rests on.
func TestReadinessVerdictWordsAreDistinct(t *testing.T) {
	if got := readinessVerdict(true); got != "READY" {
		t.Errorf("readinessVerdict(true) = %q, want READY", got)
	}
	if got := readinessVerdict(false); got != "BLOCKED" {
		t.Errorf("readinessVerdict(false) = %q, want BLOCKED", got)
	}
}

// TestBlockingAdviceDistinguishesBuildFromConfiguration checks the advice
// tracks what actually blocked.
func TestBlockingAdviceDistinguishesBuildFromConfiguration(t *testing.T) {
	buildBlocked := blockingAdvice([]string{"apply-path-available", "physical-presence"})
	if !strings.Contains(buildBlocked, "BUILD") {
		t.Errorf("advice for a build block does not mention the build: %q", buildBlocked)
	}

	configBlocked := blockingAdvice([]string{"config-valid", "lan-identified"})
	if strings.Contains(configBlocked, "BUILD") {
		t.Errorf("advice for a configuration block blames the build: %q", configBlocked)
	}
	if !strings.Contains(configBlocked, "configuration") {
		t.Errorf("advice for a configuration block does not mention the configuration: %q", configBlocked)
	}
}

// TestReadinessNeverReportsReadyInThisBuild is the milestone's invariant.
//
// A test that asserted READY would require a build with an apply path, which
// is the next milestone. Until then this asserts the opposite, so that when
// that milestone lands the test has to be changed deliberately.
func TestReadinessNeverReportsReadyInThisBuild(t *testing.T) {
	_, path := loadTopology(t, completeGatewayConfig())

	stdout, _, _ := runGateCLI(t, "readiness", path)

	if strings.Contains(stdout, "Verdict:        READY") {
		t.Fatalf("readiness reported READY; this build has no apply path\n%s", stdout)
	}
	if activation.CanApply() {
		t.Error("CanApply() is true; the milestone requires it to remain false")
	}
}
