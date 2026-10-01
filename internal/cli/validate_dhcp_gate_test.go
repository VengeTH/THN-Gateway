package cli

// The DHCP range matrix, run through `thn validate`.
//
// internal/dhcp owns the range arithmetic and has its own exhaustive matrix
// over every prefix length. This file is not a second copy of it. It exists
// for one narrower reason:
//
//   `thn validate` is the documented CI gate. Before this change it never
//   called dhcp.Validate, so a configuration whose pool ran off the end of
//   the LAN produced "no findings" and exit 0 from the gate. The arithmetic
//   could be correct and still never run.
//
// So these tests assert reachability, not arithmetic. Each one fails if DHCP
// validation is removed from, or disconnected from, `thn validate` — which is
// a different and much cheaper failure to detect than a cross-subnet pool
// shipping to a gateway.

import (
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/dhcp"
)

// dhcpGateCase is one row of the top-level DHCP matrix.
type dhcpGateCase struct {
	name string

	// lan is network.lan_prefix. The gateway address is derived from it by
	// dhcpPolicyFromConfig, exactly as the real CLI derives it.
	lan string

	start string
	end   string

	// wantErr is a field path that must appear among the findings of BOTH
	// commands, or "" when the configuration must be accepted.
	wantErr string

	note string
}

// dhcpGateMatrix covers the range shapes the brief names.
//
// Every row is a document that `thn validate` must judge correctly. The
// `wantErr` paths are the unprefixed ones internal/dhcp produces; the top
// level namespaces them, which the assertions below account for.
var dhcpGateMatrix = []dhcpGateCase{
	{
		name: "valid interior", lan: "192.168.1.1/24",
		start: "192.168.1.10", end: "192.168.1.200",
		note: "the ordinary case; both commands must accept it",
	},
	{
		name: "reversed", lan: "192.168.1.1/24",
		start: "192.168.1.200", end: "192.168.1.10",
		wantErr: "ranges[0]",
		note:    "start above end",
	},
	{
		name: "outside LAN", lan: "192.168.1.1/24",
		start: "192.168.2.10", end: "192.168.2.100",
		wantErr: "ranges[0].start",
		note:    "a different /24 entirely",
	},
	{
		name: "cross-subnet", lan: "192.168.1.1/24",
		start: "192.168.1.250", end: "192.168.2.10",
		wantErr: "ranges[0].end",
		note:    "the defect that used to pass the gate",
	},
	{
		name: "network address", lan: "192.168.1.1/24",
		start: "192.168.1.0", end: "192.168.1.0",
		wantErr: "ranges[0].start",
		note:    "the network address is not assignable",
	},
	{
		name: "broadcast address", lan: "192.168.1.1/24",
		start: "192.168.1.255", end: "192.168.1.255",
		wantErr: "ranges[0].end",
		note:    "the broadcast address is not assignable",
	},
	{
		name: "whole subnet", lan: "192.168.1.1/24",
		start: "192.168.1.0", end: "192.168.1.255",
		wantErr: "ranges[0].start",
		note:    "both endpoints are unassignable; the network address is reported first",
	},
}

// dhcpGateConfig builds a configuration document for one row.
//
// The document is COMPLETE apart from the pool: WAN identified, LAN
// identified, NAT scoped to the LAN. That matters because the gate validates
// every subsystem, not just DHCP. An earlier version of this fixture left the
// LAN unidentified, and every row of the matrix then failed for an unrelated
// netconfig coherence error rather than for its pool — which is the gate
// working, but it made the matrix assert the wrong thing.
//
// It goes through config.Defaults rather than a literal document so the matrix
// tracks the shipped defaults, and it writes and reloads the file so the CLI
// sees the same normalised document an operator would.
func dhcpGateConfig(t *testing.T, c dhcpGateCase) (config.Config, string) {
	t.Helper()

	cfg := config.Defaults()
	cfg.Gateway.Name = "thn-dhcp-gate"
	cfg.Gateway.Generation = 1

	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "enp1s0"
	cfg.Network.LANPrefix = c.lan
	cfg.Network.MTU = 1500

	cfg.NAT.Enabled = true
	cfg.NAT.Masquerade.Enabled = true
	cfg.NAT.Masquerade.Outbound = "wan"
	// LAN only: masquerading from the WAN is a routing loop and the static
	// layer refuses to name the WAN here.
	cfg.NAT.Interfaces = []string{"enp1s0"}
	cfg.NAT.Masquerade.Enabled = true
	cfg.NAT.Masquerade.Outbound = "wan"

	cfg.Firewall.Enabled = true
	cfg.Firewall.Backend = "nftables"
	cfg.Firewall.DefaultInboundPolicy = "drop"

	cfg.DHCP.Enabled = true
	cfg.DHCP.Authoritative = true
	cfg.DHCP.Domain = "lan.home"
	cfg.DHCP.Ranges = []config.DHCPRangeConfig{
		{Start: c.start, End: c.end},
	}

	cfg.DNS.Enabled = true
	cfg.DNS.LocalDomain = "lan.home"

	return loadTopology(t, cfg)
}

// TestValidateJudgesDHCPRanges is the core assertion: the CI gate reaches the
// DHCP validator and reaches the right verdict.
func TestValidateJudgesDHCPRanges(t *testing.T) {
	for _, c := range dhcpGateMatrix {
		t.Run(c.name, func(t *testing.T) {
			_, path := dhcpGateConfig(t, c)

			stdout, stderr, code := runGateCLI(t, "validate", path)

			if c.wantErr == "" {
				if code != ExitOK {
					t.Fatalf("expected %s to be accepted, got exit %d\nstdout:\n%s\nstderr:\n%s",
						c.note, code, stdout, stderr)
				}
				return
			}

			if code == ExitOK {
				t.Fatalf("expected %s to be rejected, got exit 0\nstdout:\n%s", c.note, stdout)
			}
			if code != ExitProblems {
				t.Fatalf("expected exit %d for a validation finding, got %d", ExitProblems, code)
			}

			// The field path must survive. A generic "invalid configuration"
			// would satisfy the exit code and tell an operator nothing.
			namespaced := "dhcp." + c.wantErr
			if !strings.Contains(stdout, namespaced) {
				t.Errorf("expected a finding at %q, got:\n%s", namespaced, stdout)
			}
		})
	}
}

// TestValidateAndDHCPValidateAgree is the anti-divergence check.
//
// The two commands derive the DHCP policy the same way and call the same
// validator, so they must reach the same verdict on the same document. If this
// ever fails, one of them has stopped calling internal/dhcp — which is the
// only way these two can disagree, and the exact regression the milestone
// exists to prevent.
func TestValidateAndDHCPValidateAgree(t *testing.T) {
	for _, c := range dhcpGateMatrix {
		t.Run(c.name, func(t *testing.T) {
			_, path := dhcpGateConfig(t, c)

			_, _, topCode := runGateCLI(t, "validate", path)
			_, _, svcCode := runGateCLI(t, "dhcp", "validate", path)

			if (topCode == ExitOK) != (svcCode == ExitOK) {
				t.Errorf("the two commands disagree on %s (%s):\n"+
					"  thn validate       exit %d\n"+
					"  thn dhcp validate  exit %d",
					c.note, c.ranges(), topCode, svcCode)
			}
		})
	}
}

// ranges renders the row's pool for a message.
func (c dhcpGateCase) ranges() string {
	return c.start + " - " + c.end
}

// TestValidateDoesNotSilentlyBypassDHCP is the regression the milestone is
// about, stated as an invariant rather than as a list of cases.
//
// The check is deliberately not "the matrix above passes". It asks a
// structural question that a matrix cannot: for an arbitrary pool, does the
// verdict `thn validate` reaches always equal the verdict dhcp.Validate
// reaches? If the gate is ever disconnected from internal/dhcp, this fails on
// the first row rather than waiting for someone to notice that a cross-subnet
// pool shipped.
func TestValidateDoesNotSilentlyBypassDHCP(t *testing.T) {
	pools := [][2]string{
		{"192.168.1.10", "192.168.1.200"},
		{"192.168.1.200", "192.168.1.10"},
		{"192.168.2.10", "192.168.2.100"},
		{"192.168.1.250", "192.168.2.10"},
		{"192.168.1.0", "192.168.1.0"},
		{"192.168.1.255", "192.168.1.255"},
		{"192.168.1.0", "192.168.1.255"},
		{"10.77.0.100", "10.77.0.250"},
		{"10.0.0.0", "255.255.255.255"},
		{"255.255.255.255", "0.0.0.0"},
		{"192.168.1.1", "192.168.1.1"},
		{"10.77.0.1", "10.77.0.1"},
	}

	for _, p := range pools {
		t.Run(p[0]+"-"+p[1], func(t *testing.T) {
			// A complete document apart from the pool. Leaving the LAN
			// unidentified would make the gate reject every row for an
			// unrelated netconfig coherence error, and the test would pass
			// for entirely the wrong reason.
			cfg := config.Defaults()
			cfg.Network.WAN = "enp0s31f6"
			cfg.Network.LAN = "enp1s0"
			cfg.Network.LANPrefix = "192.168.1.1/24"
			cfg.Network.MTU = 1500
			cfg.NAT.Enabled = true
			cfg.NAT.Masquerade.Enabled = true
			cfg.NAT.Masquerade.Outbound = "wan"
			cfg.NAT.Interfaces = []string{"enp1s0"}
			cfg.NAT.Masquerade.Enabled = true
			cfg.NAT.Masquerade.Outbound = "wan"
			cfg.Firewall.Enabled = true
			cfg.Firewall.Backend = "nftables"
			cfg.Firewall.DefaultInboundPolicy = "drop"
			cfg.DHCP.Enabled = true
			cfg.DHCP.Authoritative = true
			cfg.DHCP.Domain = "lan.home"
			cfg.DHCP.Ranges = []config.DHCPRangeConfig{{Start: p[0], End: p[1]}}
			cfg.DNS.Enabled = true
			cfg.DNS.LocalDomain = "lan.home"

			loaded, path := loadTopology(t, cfg)

			// What internal/dhcp says, computed directly.
			policy, err := dhcpPolicyFromConfig(loaded)
			if err != nil {
				t.Fatalf("deriving the DHCP policy: %v", err)
			}
			wantValid := dhcp.Validate(policy).Valid

			// What the gate says.
			_, _, code := runGateCLI(t, "validate", path)
			gotValid := code == ExitOK

			if gotValid != wantValid {
				t.Errorf("the CI gate and dhcp.Validate disagree on %s-%s:\n"+
					"  thn validate     %s\n"+
					"  dhcp.Validate    %s\n"+
					"The gate is either not calling internal/dhcp, or is answering a\n"+
					"different question from it.",
					p[0], p[1], verdict(gotValid), verdict(wantValid))
			}
		})
	}
}

func verdict(ok bool) string {
	if ok {
		return "accept"
	}
	return "reject"
}

// TestValidateJSONPreservesDHCPFindings checks the machine-readable path.
//
// A finding that renders correctly as text but is dropped from --json is a
// finding a CI check cannot see, which is the same class of bug as the gate
// not calling the validator at all.
func TestValidateJSONPreservesDHCPFindings(t *testing.T) {
	for _, c := range dhcpGateMatrix {
		if c.wantErr == "" {
			continue // only rejections are asserted here
		}
		t.Run(c.name, func(t *testing.T) {
			_, path := dhcpGateConfig(t, c)

			doc, code := runGateJSON(t, "validate", path)

			if code == ExitOK {
				t.Fatalf("expected a nonzero exit for %s", c.note)
			}
			if jsonBool(t, doc, "valid") {
				t.Error("--json reports valid=true for a configuration with a rejected pool")
			}

			findings := jsonFindings(t, doc)
			want := "dhcp." + c.wantErr

			for _, f := range findings {
				if f["field"] == want {
					if f["severity"] != "error" {
						t.Errorf("finding %q has severity %v, want error", want, f["severity"])
					}
					if msg, _ := f["message"].(string); strings.TrimSpace(msg) == "" {
						t.Errorf("finding %q carries no message; it was flattened", want)
					}
					if f["layer"] != string("static") {
						t.Errorf("finding %q has layer %v, want static", want, f["layer"])
					}
					return
				}
			}

			t.Errorf("no finding at %q in --json output; got %v", want, findingFields(findings))
		})
	}
}

// jsonFindings extracts the findings array from a validation document.
func jsonFindings(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()

	raw, ok := doc["findings"].([]any)
	if !ok {
		t.Fatalf("the output has no findings array; keys are %v", keysOf(doc))
	}

	out := make([]map[string]any, 0, len(raw))
	for _, v := range raw {
		f, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("a finding is %T, want an object", v)
		}
		out = append(out, f)
	}
	return out
}

// findingFields renders the field paths of a finding set for a message.
func findingFields(findings []map[string]any) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		field, _ := f["field"].(string)
		out = append(out, field)
	}
	return out
}
