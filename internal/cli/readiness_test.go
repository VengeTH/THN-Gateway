package cli

// `thn readiness` — the operator-facing view of activation.Evaluate.
//
// The command exists because the gates had no operator-facing surface: an
// operator could only learn what was blocking them by running `thn activate`
// and reading a refusal that never named the gates.
//
// These tests pin the three properties that make the report trustworthy: it
// names the blocking gates, it says what would unblock each of them, and it
// cannot claim the network was touched.
//
// Note what it does NOT assert: that the build is the blocker. That was true
// while this build had no apply path, and it stopped being true when the
// production path landed. A readiness report that blamed the build would now
// send an operator to rebuild software rather than to plug in a LAN cable.

import (
	"strings"
	"testing"

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

// TestReadinessNeverClaimsItTouchedTheNetwork is the contract an operator
// decides whether to be afraid by, so it is asserted first and separately.
func TestReadinessNeverClaimsItTouchedTheNetwork(t *testing.T) {
	_, path := loadTopology(t, completeGatewayConfig())

	stdout, _, code := runGateCLI(t, "readiness", path)
	if code == ExitOK {
		t.Fatalf("readiness reported success:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Current network remains untouched") {
		t.Errorf("output does not state that the network is untouched:\n%s", stdout)
	}
}

// TestReadinessSaysWhatWouldUnblockEachGate is what makes a blocked report
// usable rather than merely discouraging.
//
// Each blocking gate gets its own remedy, and the advice must not blame the
// build for a condition the operator can fix by plugging in a cable.
func TestReadinessSaysWhatWouldUnblockEachGate(t *testing.T) {
	advice := blockingAdvice([]string{
		"physical-presence", "lan-identified", "management-safety",
		"subsystems-executable", "recoverable",
	})

	for _, want := range []string{
		"physical-presence", "role assignment", "management-safety",
		"subsystems", "recoverable",
	} {
		if !strings.Contains(advice, want) {
			t.Errorf("advice does not cover %q:\n%s", want, advice)
		}
	}
}

// TestReadinessNamesAnApplyPathBuildProblemSeparately covers the one blocking
// condition no configuration can fix. It must be distinguishable, because the
// remedy for it is entirely different.
func TestReadinessNamesAnApplyPathBuildProblemSeparately(t *testing.T) {
	advice := blockingAdvice([]string{"apply-path-available"})
	if !strings.Contains(advice, "build") {
		t.Errorf("advice for a build block does not name the build: %q", advice)
	}
	if !strings.Contains(advice, "no configuration changes it") {
		t.Errorf("advice for a build block does not say it is not configurable: %q", advice)
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
	if !jsonBool(t, doc, "can_apply") {
		t.Error("can_apply is false; this build contains a production apply path " +
			"and must report it truthfully")
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
	if jsonBool(t, doc, "all_gates_satisfied") {
		t.Error("all_gates_satisfied is true without physical presence")
	}

	// The full production gate set, not the shorter readiness subset. An
	// operator reading this is reading what will gate the apply.
	gates, ok := doc["gates"].([]any)
	if !ok {
		t.Fatalf("gates is %T, want an array", doc["gates"])
	}
	if len(gates) != 13 {
		t.Errorf("gates has %d entries, want the full production set of 13", len(gates))
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

// TestBlockingAdviceIsNeverEmpty covers the degenerate case where nothing
// recognised is blocking. Silence would be worse than useless: an operator
// would conclude there is nothing to do rather than that THN did not
// recognise the condition.
func TestBlockingAdviceIsNeverEmpty(t *testing.T) {
	if got := blockingAdvice([]string{"something-unrecognised"}); strings.TrimSpace(got) == "" {
		t.Error("blockingAdvice returned nothing for an unrecognised gate")
	}
	if got := blockingAdvice(nil); strings.TrimSpace(got) == "" {
		t.Error("blockingAdvice returned nothing for an empty gate list")
	}
}

// TestReadinessNeverReportsReadyWithoutPhysicalPresence is the invariant.
//
// Readiness cannot confirm that a human is standing at the device, so it can
// never reach READY. An operator who reads READY and walks away has been told
// something the command has no way of knowing.
func TestReadinessNeverReportsReadyWithoutPhysicalPresence(t *testing.T) {
	_, path := loadTopology(t, completeGatewayConfig())

	stdout, _, _ := runGateCLI(t, "readiness", path)

	if strings.Contains(stdout, "Verdict:        READY") {
		t.Fatalf("readiness reported READY; presence cannot be confirmed remotely:\n%s", stdout)
	}
	if !strings.Contains(stdout, "physical-presence") {
		t.Errorf("readiness did not name the presence gate as blocking:\n%s", stdout)
	}
	if !strings.Contains(stdout, "confirm-present") {
		t.Errorf("readiness did not say how presence is confirmed:\n%s", stdout)
	}
}
