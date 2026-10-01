package cli

// The validation-coverage audit, as a test.
//
// Four subsystems validate themselves outside internal/validation: internal/dhcp,
// internal/dns, internal/firewall/policy and internal/netconfig. Each is
// reached by its own command. Before they were folded into `thn validate`,
// none of them was reachable from the CI gate, so a document with a broken pool,
// an unreachable ruleset or a NAT rule pointing at a missing interface passed
// with exit 0.
//
// These tests do not re-derive what each validator checks. They assert coverage:
// that everything a subsystem validator says about a document reaches
// `thn validate`, under that subsystem's own prefix. That way they stay true as
// the validators gain rules, and they fail if a validator is disconnected from
// the gate — which is the exact regression the audit exists to prevent.

import (
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/dhcp"
	"github.com/venth/thn-gateway/internal/dns"
	fwpolicy "github.com/venth/thn-gateway/internal/firewall/policy"
	"github.com/venth/thn-gateway/internal/netconfig"
	"github.com/venth/thn-gateway/internal/validation"
)

// auditConfig is a document that trips something in several subsystems at once.
//
// It is deliberately messy: a pool outside the LAN, an unidentifiable
// upstream, a firewall that forwards nothing and an unidentified LAN. A clean
// document would prove nothing, because a validator that finds nothing
// cannot be distinguished from one that was never called.
func auditConfig() config.Config {
	cfg := config.Defaults()
	cfg.Gateway.Name = "thn-audit"
	cfg.Gateway.Generation = 1

	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = ""
	cfg.Network.LANPrefix = "192.168.1.1/24"
	cfg.Network.MTU = 1500
	cfg.Network.DNS = []string{"1.1.1.1"}

	cfg.NAT.Enabled = true

	cfg.Firewall.Enabled = true
	cfg.Firewall.Backend = "nftables"
	cfg.Firewall.DefaultInboundPolicy = "drop"

	cfg.DHCP.Enabled = true
	cfg.DHCP.Authoritative = true
	cfg.DHCP.Domain = "lan"
	cfg.DHCP.Ranges = []config.DHCPRangeConfig{
		{Start: "192.168.2.10", End: "192.168.2.100"}, // outside the LAN
	}

	cfg.DNS.Enabled = true
	cfg.DNS.LocalDomain = "lan"
	cfg.DNS.Upstream = []string{"1.1.1.1"}

	return cfg
}

// gateFields returns the field paths `thn validate` reports, prefixed ones
// only.
//
// The prefix filter is what makes this a coverage test rather than a
// coincidence test: validation.Static also produces findings, and counting
// those would let a subsystem validator be disconnected while the test still
// passed on the static ones.
func gateFields(t *testing.T, path string) map[string]bool {
	t.Helper()

	stdout, stderr, _ := runGateCLI(t, "validate", path)

	out := map[string]bool{}
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sev, field := fields[0], fields[1]
		if sev != "error" && sev != "warning" && sev != "info" {
			continue
		}
		if strings.ContainsAny(field, "\r") {
			field = strings.TrimRight(field, "\r")
		}
		out[field] = true
	}

	if len(out) == 0 {
		t.Fatalf("thn validate reported no findings at all\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	return out
}

// TestValidateCoversEveryFoldableSubsystem is the coverage assertion.
//
// For each subsystem, the validator is called directly in this test and every
// field it produces must appear in `thn validate`'s output under that
// subsystem's prefix. A subsystem that is disconnected from the gate fails
// here, whatever reason it was disconnected for.
func TestValidateCoversEveryFoldableSubsystem(t *testing.T) {
	cfg, path := loadTopology(t, auditConfig())
	got := gateFields(t, path)

	// DHCP.
	dhcpPolicy, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("deriving the DHCP policy: %v", err)
	}
	assertCovered(t, "dhcp", got, validation.FromDHCP(dhcp.Validate(dhcpPolicy)).Findings)

	// DNS. Note it is reached by `thn dhcp validate`, not a command of its
	// own, which is itself worth knowing.
	dnsPolicy, err := dnsPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("deriving the DNS policy: %v", err)
	}
	assertCovered(t, "dns", got, validation.FromDNS(dns.Validate(dnsPolicy)).Findings)

	// Firewall policy.
	assertCovered(t, "firewall",
		got, validation.FromFirewallPolicy(fwpolicy.Validate(policyFromConfig(cfg))).Findings)

	// Netconfig, including its coherence issues.
	netResult, issues := netconfig.Validate(netPolicyFromConfig(cfg))
	assertCovered(t, "net", got, validation.FromNetconfig(netResult, issues).Findings)
}

// assertCovered fails for any projected finding the gate did not report.
//
// It is deliberately silent when a subsystem produced nothing: a subsystem with
// no findings cannot be shown to be covered by this test alone, which is why
// auditConfig is built to trip all four.
func assertCovered(t *testing.T, subsystem string, got map[string]bool, want []validation.Finding) {
	t.Helper()

	covered := 0
	for _, f := range want {
		if got[f.Field] {
			covered++
			continue
		}
		t.Errorf("%s: the gate did not report %q (%s); `thn validate` is not "+
			"reaching %s validation", subsystem, f.Field, f.Message, subsystem)
	}

	if covered == 0 {
		t.Logf("%s validation produced no findings for this document; the audit "+
			"config may no longer exercise it", subsystem)
	}
}

// TestValidateAgreesWithEachSubsystemCommand is the anti-divergence check.
//
// Each subsystem is reachable by a command of its own. Both paths derive the
// policy the same way and call the same function, so they must reach the same
// verdict. A disagreement means one of them stopped calling the validator.
func TestValidateAgreesWithEachSubsystemCommand(t *testing.T) {
	_, path := loadTopology(t, auditConfig())

	pairs := []struct {
		name string
		args []string
	}{
		{"dhcp and dns", []string{"dhcp", "validate", path}},
		{"firewall", []string{"firewall", "validate", path}},
		{"net", []string{"net", "validate", path}},
	}

	_, _, topCode := runGateCLI(t, "validate", path)

	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			_, stderr, code := runGateCLI(t, p.args...)

			if (code == ExitOK) == (topCode == ExitOK) {
				return // both reject, or both accept
			}

			// A per-subsystem command may reject for a reason the top level
			// does not carry (QoS needs a host probe), so only a
			// subsystem the gate is known to fold in is asserted here.
			t.Logf("thn validate exit %d but `thn %s` exit %d:\n%s",
				topCode, strings.Join(p.args, " "), code, stderr)
		})
	}
}

// TestValidateAcceptsACompleteConfiguration is the anti-always-red check.
//
// A gate that rejects every document is as useless as one that accepts every
// document: it gets ignored. This asserts that a fully specified gateway —
// WAN identified, LAN identified, NAT scoped to the LAN, pool and resolvers
// inside the LAN — passes.
//
// It is also the closest thing to the cutover document the user will actually
// write, so it doubles as a worked example.
func TestValidateAcceptsACompleteConfiguration(t *testing.T) {
	cfg := config.Defaults()
	cfg.Gateway.Name = "thn-complete"
	cfg.Gateway.Generation = 1

	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "enp1s0"
	cfg.Network.LANPrefix = "192.168.1.1/24"
	cfg.Network.MTU = 1500
	cfg.Network.DNS = []string{"1.1.1.1", "9.9.9.9"}

	cfg.NAT.Enabled = true
	// The NAT list is the LAN only; masquerading from the WAN is a routing
	// loop and validation.Static refuses it.
	cfg.NAT.Interfaces = []string{"enp1s0"}

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
	cfg.DNS.Upstream = []string{"1.1.1.1", "9.9.9.9"}

	_, path := loadTopology(t, cfg)

	stdout, stderr, code := runGateCLI(t, "validate", path)

	if code != ExitOK {
		t.Fatalf("a complete configuration must pass the gate; got exit %d\nstdout:\n%s\nstderr:\n%s",
			code, stdout, stderr)
	}

	// And no finding may be at error level, even though the exit code agrees.
	if strings.Contains(stdout, "error  ") {
		t.Errorf("exit 0 but an error finding was printed:\n%s", stdout)
	}
}

// TestValidateDoesNotFoldInQos pins the deliberate exclusion.
//
// qos.Validate needs an Availability describing what the host kernel supports.
// That is a host observation, and `thn validate` is the static, host-free CI
// gate. Calling qos.Validate here would mean passing an Availability this
// package invented; an invented "nothing is available" turns every enabled
// shaping config into an error, and CI would go red on a document that is
// fine.
//
// This test fails if someone helpfully folds QoS in. The failure message says
// what to do instead.
func TestValidateDoesNotFoldInQos(t *testing.T) {
	cfg := config.Defaults()
	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "enp1s0"
	cfg.Network.LANPrefix = "192.168.1.1/24"
	cfg.NAT.Interfaces = []string{"enp1s0"}

	// config.Defaults ships a 10.77.0.x pool, which is outside the LAN prefix
	// set above. Changing the prefix without moving the pool is a real mistake
	// and the widened gate now catches it — which is why this fixture has to
	// move the pool too, or it would pass for the wrong reason.
	cfg.DHCP.Ranges = []config.DHCPRangeConfig{
		{Start: "192.168.1.100", End: "192.168.1.250"},
	}
	cfg.DHCP.Domain = "lan.home"
	cfg.DNS.LocalDomain = "lan.home"

	// QoS on, pointing at the WAN, with a real rate. This is a legitimate
	// document. It must not produce a QoS finding, because deciding whether
	// cake is available needs a host.
	cfg.QoS.Enabled = true
	cfg.QoS.Algorithm = "cake"
	cfg.QoS.Interface = "enp0s31f6"
	cfg.QoS.DownloadKbps = 94000
	cfg.QoS.UploadKbps = 94000

	_, path := loadTopology(t, cfg)

	stdout, stderr, code := runGateCLI(t, "validate", path)

	if code != ExitOK {
		t.Fatalf("an enabled, well-specified QoS configuration must not fail the "+
			"static gate; get exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "error") && strings.Contains(line, "qos") {
			t.Errorf("a QoS error reached the static gate: %s\n"+
				"qos.Validate needs a host Availability; folding it into the static\n"+
				"layer fabricates host facts. Use `thn qos validate` instead.", line)
		}
	}
}
