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

	"github.com/VengeTH/THN-Gateway/internal/config"
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

// TestTheTwoResolverFieldsAgree pins the ambiguity that has been closed, and
// pins it in both directions.
//
// The document has two keys that both describe upstream resolvers:
// network.dns and dns.upstream. For a while only network.dns reached the DNS
// policy — dnsPolicyFromConfig read cfg.Network.DNS and never looked at
// cfg.DNS.Upstream — so editing dns.upstream changed nothing about the
// rendered dnsmasq configuration, and said nothing either.
//
// The resolution is now explicit and is asserted here rather than described in
// a comment, because a comment is what let it drift in the first place:
//
//	dns.upstream    AUTHORITATIVE for the DNS service
//	network.dns     the fallback, used only when dns.upstream is empty
//	both set, equal     warning — redundant but harmless
//	both set, different ERROR — the document contradicts itself
//
// The canonical document sets both to the same values, so it is correct under
// either rule and produces no warning.
func TestTheTwoResolverFieldsAgree(t *testing.T) {
	cfg := mustLoadCanonical(t)

	if len(cfg.DNS.Upstream) == 0 {
		t.Error("dns.upstream is empty; it is the authoritative field for the DNS service")
	}
	if len(cfg.Network.DNS) == 0 {
		t.Error("network.dns is empty; it is the documented fallback")
	}
	if len(cfg.DNS.Upstream) != len(cfg.Network.DNS) {
		t.Fatalf("network.dns has %d entries and dns.upstream has %d; "+
			"they disagree, which validation reports as an error",
			len(cfg.Network.DNS), len(cfg.DNS.Upstream))
	}
	for i := range cfg.Network.DNS {
		if cfg.Network.DNS[i] != cfg.DNS.Upstream[i] {
			t.Errorf("network.dns[%d] = %q but dns.upstream[%d] = %q; they disagree",
				i, cfg.Network.DNS[i], i, cfg.DNS.Upstream[i])
		}
	}
}

// TestDNSUpstreamIsTheAuthoritativeField is the positive half: the key that
// used to be inert must now actually reach the rendered policy.
//
// If this ever inverts again, an operator edits dns.upstream, sees no effect
// and no warning, and has no reason to suspect the field they are editing.
// That is the exact failure this milestone closed, so it gets a test rather
// than a paragraph.
func TestDNSUpstreamIsTheAuthoritativeField(t *testing.T) {
	cfg := mustLoadCanonical(t)

	// Change ONLY dns.upstream. The DNS policy must follow it.
	cfg.DNS.Upstream = []string{"9.9.9.10", "1.0.0.1"}
	// Silence the disagreement check so this test measures the policy and not
	// the conflict rule.
	cfg.Network.DNS = nil

	p, err := dnsPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("dnsPolicyFromConfig: %v", err)
	}

	for _, got := range p.Upstream {
		if got.String() != "9.9.9.10" && got.String() != "1.0.0.1" {
			t.Fatalf("the DNS policy took upstream %v, which is neither dns.upstream entry", got)
		}
	}
	if len(p.Upstream) != 2 {
		t.Fatalf("the DNS policy has %d upstreams, want 2", len(p.Upstream))
	}

	// And with dns.upstream empty, the documented fallback takes over.
	fallback := mustLoadCanonical(t)
	fallback.DNS.Upstream = nil
	fp, err := dnsPolicyFromConfig(fallback)
	if err != nil {
		t.Fatalf("dnsPolicyFromConfig with no dns.upstream: %v", err)
	}
	if len(fp.Upstream) == 0 {
		t.Error("with dns.upstream empty the policy took no resolvers; network.dns should be the fallback")
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
