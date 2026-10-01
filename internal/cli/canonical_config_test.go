package cli

// The canonical gateway configuration.
//
// configs/gateway.yaml is the document an operator is most likely to copy, and
// it is the one the readiness milestone is judged on. It used to describe NAT
// and LAN-to-WAN forwarding with no LAN interface, which `thn validate` now
// correctly rejects — so it had become an example of an invalid configuration
// shipped in the repository.
//
// These tests pin both halves of that: the canonical document validates clean,
// and documents built from the same shape with one thing wrong still fail. A
// test that only asserted the first would pass if validation were weakened; one
// that only asserted the second would pass if the example were broken.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/config"
)

// canonicalConfigPath locates configs/gateway.yaml from this package.
func canonicalConfigPath(t *testing.T) string {
	t.Helper()

	path := filepath.Join("..", "..", "configs", "gateway.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the canonical configuration is missing: %v", err)
	}
	return path
}

// TestTheCanonicalConfigurationValidates is the milestone's headline claim.
func TestTheCanonicalConfigurationValidates(t *testing.T) {
	path := canonicalConfigPath(t)

	stdout, stderr, code := runGateCLI(t, "validate", path)

	if code != ExitOK {
		t.Fatalf("configs/gateway.yaml must validate, got exit %d\nstdout:\n%s\nstderr:\n%s",
			code, stdout, stderr)
	}
	if strings.Contains(stdout, "error  ") {
		t.Errorf("exit 0 but an error finding was printed:\n%s", stdout)
	}
}

// TestTheCanonicalConfigurationIsInternallyCoherent checks the properties the
// example is meant to demonstrate, rather than only that the validator agrees.
//
// A file can validate because a rule happens to be lenient. These assert the
// document says what a deployable gateway says.
func TestTheCanonicalConfigurationIsInternallyCoherent(t *testing.T) {
	cfg, err := config.Load(canonicalConfigPath(t))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	if cfg.Network.LAN == "" {
		t.Error("network.lan is empty; the example describes NAT and forwarding with nowhere to serve them")
	}
	if cfg.Network.LANPrefix == "" {
		t.Error("network.lan_prefix is empty")
	}
	if cfg.NAT.Enabled && len(cfg.NAT.Interfaces) == 0 {
		t.Error("NAT is enabled with no interface")
	}
	for _, i := range cfg.NAT.Interfaces {
		if i == cfg.Network.WAN {
			t.Errorf("nat.interfaces names the WAN (%s); that is a routing loop", i)
		}
	}
	if len(cfg.Firewall.AdminSources) == 0 {
		t.Error("firewall.admin_sources is empty; the example would ship an unrestricted SSH rule")
	}
	if !cfg.DHCP.Enabled || len(cfg.DHCP.Ranges) == 0 {
		t.Error("DHCP is enabled but no pool is configured")
	}
	if !cfg.DNS.Enabled {
		t.Error("DNS is disabled")
	}
}

// TestTheCanonicalConfigurationHasNoOpenAdminRule guards the specific finding
// this milestone was asked to resolve.
//
// Before firewall.admin_sources existed the policy could model, validate and
// render an admin source restriction, but no document could carry one, so the
// emitted SSH rule was always open and validation warned on every run.
func TestTheCanonicalConfigurationHasNoOpenAdminRule(t *testing.T) {
	path := canonicalConfigPath(t)

	stdout, _, code := runGateCLI(t, "validate", path)
	if code != ExitOK {
		t.Fatalf("validate failed: %s", stdout)
	}
	if strings.Contains(stdout, "firewall.admin.source") {
		t.Errorf("the canonical configuration still warns about an open admin source:\n%s", stdout)
	}
}

// TestTheTwoResolverFieldsAgree pins a known ambiguity.
//
// The document has two keys that both describe upstream resolvers:
// network.dns and dns.upstream. Only network.dns reaches the DNS policy —
// dnsPolicyFromConfig reads cfg.Network.DNS and never looks at
// cfg.DNS.Upstream — so dns.upstream is currently INERT. Editing it changes
// nothing about the rendered dnsmasq configuration.
//
// The canonical document sets both to the same values, so it is correct either
// way, but an operator who edits only dns.upstream would see no effect and no
// warning. Deciding which key is authoritative is a design change and is
// deliberately not made here; this test records the current behaviour so the
// change is deliberate when it happens.
func TestTheTwoResolverFieldsAgree(t *testing.T) {
	cfg := mustLoadCanonical(t)

	if len(cfg.Network.DNS) == 0 {
		t.Fatal("network.dns is empty; the DNS policy takes its resolvers from here")
	}
	if len(cfg.DNS.Upstream) == 0 {
		t.Error("dns.upstream is empty; it is inert but should not be misleadingly blank")
	}

	// Today they must at least not disagree, because only one is honoured.
	if len(cfg.DNS.Upstream) != len(cfg.Network.DNS) {
		t.Errorf("network.dns has %d entries and dns.upstream has %d; "+
			"only network.dns is honoured, so a disagreement is silently ignored",
			len(cfg.Network.DNS), len(cfg.DNS.Upstream))
		return
	}
	for i := range cfg.Network.DNS {
		if cfg.Network.DNS[i] != cfg.DNS.Upstream[i] {
			t.Errorf("network.dns[%d] = %q but dns.upstream[%d] = %q; only network.dns is honoured",
				i, cfg.Network.DNS[i], i, cfg.DNS.Upstream[i])
		}
	}
}

// TestTheCanonicalConfigurationStillRejectsBreakage is the negative half.
//
// Each row takes the canonical document and breaks exactly one thing. If any
// of these passed, the canonical document could be damaged without anything
// noticing.
func TestTheCanonicalConfigurationStillRejectsBreakage(t *testing.T) {
	base := mustLoadCanonical(t)

	cases := []struct {
		name string
		mut  func(*config.Config)
	}{
		{"no LAN interface", func(c *config.Config) { c.Network.LAN = "" }},
		{"no WAN interface", func(c *config.Config) { c.Network.WAN = "" }},
		{"reversed DHCP range", func(c *config.Config) {
			c.DHCP.Ranges = []config.DHCPRangeConfig{{Start: "10.77.0.250", End: "10.77.0.100"}}
		}},
		{"DHCP range outside the LAN", func(c *config.Config) {
			c.DHCP.Ranges = []config.DHCPRangeConfig{{Start: "192.168.2.10", End: "192.168.2.100"}}
		}},
		{"cross-subnet DHCP range", func(c *config.Config) {
			c.DHCP.Ranges = []config.DHCPRangeConfig{{Start: "10.77.0.250", End: "10.78.0.10"}}
		}},
		{"DHCP network address", func(c *config.Config) {
			c.DHCP.Ranges = []config.DHCPRangeConfig{{Start: "10.77.0.0", End: "10.77.0.100"}}
		}},
		{"DHCP broadcast address", func(c *config.Config) {
			c.DHCP.Ranges = []config.DHCPRangeConfig{{Start: "10.77.0.100", End: "10.77.0.255"}}
		}},
		{"invalid DNS upstream", func(c *config.Config) { c.Network.DNS = []string{"not-an-ip"} }},
		{"invalid firewall backend", func(c *config.Config) { c.Firewall.Backend = "iptables" }},
		{"NAT names the WAN", func(c *config.Config) {
			c.NAT.Interfaces = []string{c.Network.WAN}
		}},
		{"invalid admin source", func(c *config.Config) {
			c.Firewall.AdminSources = []string{"not-a-prefix"}
		}},
		{"zero lease time", func(c *config.Config) { c.DHCP.LeaseTime = 0 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mut(&cfg)

			_, path := loadTopology(t, cfg)

			stdout, stderr, code := runGateCLI(t, "validate", path)
			if code == ExitOK {
				t.Fatalf("%s was accepted; the canonical document must not be able to "+
					"absorb this:\n%s", tc.name, stdout)
			}
			if code != ExitProblems {
				t.Errorf("exit %d; a rejected configuration must exit %d, not %d",
					code, ExitProblems, code)
			}
			if !strings.Contains(stdout, "error") {
				t.Errorf("exit %d but no error finding was printed:\nstdout:\n%s\nstderr:\n%s",
					code, stdout, stderr)
			}
		})
	}
}

// mustLoadCanonical loads configs/gateway.yaml.
func mustLoadCanonical(t *testing.T) config.Config {
	t.Helper()

	cfg, err := config.Load(canonicalConfigPath(t))
	if err != nil {
		t.Fatalf("loading configs/gateway.yaml: %v", err)
	}
	return cfg
}
