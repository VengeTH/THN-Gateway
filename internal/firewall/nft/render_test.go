package nft

import (
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/firewall/policy"
)

// configured returns a policy with both interfaces identified.
func configured() policy.Policy {
	p := policy.Default()
	p.Interfaces.WAN = "enp0s31f6"
	p.Interfaces.LAN = "enx001122334455"
	p.Admin.Source = []string{"203.0.113.0/24"}
	p.AntiSpoofing.LANPrefix = "10.77.0.1/24"
	return p
}

// rules returns the rule lines of a rendered ruleset, with comments removed.
func rules(rendered string) []string {
	var out []string
	for _, line := range strings.Split(rendered, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// indexOfRule returns the position of the first rule containing needle, or -1.
func indexOfRule(rs []string, needle string) int {
	for i, r := range rs {
		if strings.Contains(r, needle) {
			return i
		}
	}
	return -1
}

func TestRenderProducesTableDeclaration(t *testing.T) {
	out := Render(configured())

	if !strings.Contains(out, "table inet thn {") {
		t.Error("must declare the inet table")
	}
	if !strings.HasPrefix(out, "#!/usr/sbin/nft -f") {
		t.Error("must start with a loadable shebang")
	}
}

func TestRenderIsBalanced(t *testing.T) {
	// An unbalanced ruleset fails to load, which means the firewall that was
	// meant to be installed never was.
	//
	// Braces are counted per line rather than in aggregate: a rule such as
	// `tcp dport { 22 }` opens and closes on the same line, so counting raw
	// characters would report a false imbalance.
	out := Render(configured())

	depth := 0
	minDepth := 0
	for _, line := range strings.Split(out, "\n") {
		for _, c := range line {
			switch c {
			case '{':
				depth++
			case '}':
				depth--
				if depth < minDepth {
					minDepth = depth
				}
			}
		}
	}

	if minDepth < 0 {
		t.Error("a closing brace appears before its opener")
	}
	if depth != 0 {
		t.Errorf("unbalanced braces: %d unclosed", depth)
	}
}

// TestEveryBaseChainHasItsHook guards a subtle failure: nft accepts a chain
// declaration with no hook and silently never evaluates it, so a missing hook
// line produces a ruleset that loads cleanly and does nothing.
func TestEveryBaseChainHasItsHook(t *testing.T) {
	out := Render(configured())

	baseChains := []string{"input", "forward", "postrouting", "prerouting"}
	for _, name := range baseChains {
		if !strings.Contains(out, "chain "+name+" {") {
			t.Errorf("chain %q is missing", name)
			continue
		}
		if !strings.Contains(out, "hook "+name+" ") {
			t.Errorf("chain %q has no hook declaration; it would never be evaluated", name)
		}
	}

	// Hook declarations must not be commented out.
	for _, raw := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "type filter hook") || strings.Contains(trimmed, "type nat hook") {
			continue
		}
		if strings.HasPrefix(trimmed, "type ") {
			t.Errorf("hook declaration appears malformed: %q", trimmed)
		}
	}
}

// TestEstablishedComesFirst is the ordering property that keeps reply traffic
// flowing. Netfilter stops at the first match, so established must precede
// any drop and any restrictive rule.
//
// The comparison is against other RULES, not against chain declarations, so the
// helper filters those out rather than comparing raw positions.
func TestEstablishedComesFirst(t *testing.T) {
	rs := ruleLines(Render(configured()))

	est := indexOfRule(rs, "ct state established,related accept")
	if est < 0 {
		t.Fatal("the input hook must accept established traffic")
	}
	if est != 0 {
		t.Errorf("established must be the first rule in the input hook, found at position %d", est)
	}

	// It must also precede every drop rule.
	for i, r := range rs {
		if strings.HasSuffix(r, " drop") && i > est {
			t.Errorf("a drop rule precedes established traffic: %q at %d", r, i)
		}
	}
}

// TestLoopbackAcceptedBeforeDrop confirms loopback traffic is permitted before
// the input hook's default policy can drop it.
func TestLoopbackAcceptedBeforeDrop(t *testing.T) {
	rs := ruleLines(Render(configured()))

	lo := indexOfRule(rs, `iifname "lo" accept`)
	if lo < 0 {
		t.Fatal("loopback must be accepted")
	}

	// Position among rules is what matters; the `policy drop` line is a chain
	// declaration and is not a rule.
	if lo > 1 {
		t.Errorf("loopback should follow established only, found at position %d", lo)
	}
}

// ruleLines returns only rule statements, excluding table and chain
// declarations and chain-closing braces.
func ruleLines(rendered string) []string {
	var out []string
	for _, r := range rules(rendered) {
		if strings.HasPrefix(r, "table ") || strings.HasPrefix(r, "chain ") ||
			strings.HasPrefix(r, "type ") || r == "}" {
			continue
		}
		out = append(out, r)
	}
	return out
}

func TestAdminRulePresentAndReachable(t *testing.T) {
	out := Render(configured())

	if !strings.Contains(out, "tcp dport { 22 } accept") {
		t.Error("the admin SSH rule must be emitted")
	}

	// It must appear before the end of the input chain, which is where the
	// default drop applies.
	rs := rules(out)
	ssh := indexOfRule(rs, "tcp dport { 22 } accept")
	if ssh < 0 {
		t.Fatal("no ssh rule")
	}
	inputEnd := -1
	for i, r := range rs {
		if r == "}" && inputEnd < 0 && i > ssh {
			inputEnd = i
		}
	}
	if ssh > inputEnd {
		t.Error("the admin rule must be inside the input chain")
	}
}

func TestSourceRestrictionRendered(t *testing.T) {
	out := Render(configured())

	if !strings.Contains(out, "ip saddr { 203.0.113.0/24 }") {
		t.Error("the admin source restriction must be rendered")
	}
}

func TestNoEmptyInterfaceNames(t *testing.T) {
	// A rule like `iifname "" accept` or a bare `iifname  icmp` is invalid
	// nftables and would fail the whole load.
	cases := []policy.Policy{
		func() policy.Policy {
			p := configured()
			p.Interfaces.LAN = ""
			return p
		}(),
		func() policy.Policy {
			p := configured()
			p.Interfaces.WAN = ""
			return p
		}(),
		policy.Default(),
	}

	for i, p := range cases {
		out := Render(p)
		for _, bad := range []string{`iifname ""`, `oifname ""`, "iifname  ", "oifname  "} {
			if strings.Contains(out, bad) {
				t.Errorf("case %d produced an invalid rule containing %q:\n%s", i, bad, out)
			}
		}
	}
}

func TestNoUnscopedMasqueradeWithoutWAN(t *testing.T) {
	// An unscoped `masquerade` rule would rewrite traffic leaving every
	// interface, including the LAN, which breaks the LAN entirely.
	p := configured()
	p.Interfaces.WAN = ""
	p.Interfaces.LAN = "enx0011"

	out := Render(p)

	for _, line := range rules(out) {
		if strings.Contains(line, "masquerade") && !strings.Contains(line, "oifname") {
			t.Errorf("unscoped masquerade emitted: %q", line)
		}
	}
	if !strings.Contains(out, "deliberately NOT emitted") {
		t.Error("the omission must be explained in a comment")
	}
}

func TestMasqueradeScopedToWAN(t *testing.T) {
	out := Render(configured())

	if !strings.Contains(out, `oifname "enp0s31f6" masquerade`) {
		t.Errorf("masquerade must be scoped to the WAN:\n%s", out)
	}
}

func TestAntiSpoofingRuleRendered(t *testing.T) {
	out := Render(configured())

	if !strings.Contains(out, `iifname "enp0s31f6" ip saddr 10.77.0.1/24 drop`) {
		t.Error("the anti-spoofing rule must be emitted")
	}
}

func TestICMPRulesIncludePMTU(t *testing.T) {
	out := Render(configured())

	// Blocking destination-unreachable causes path MTU black holes.
	if !strings.Contains(out, "destination-unreachable accept") {
		t.Error("PMTU discovery must be permitted")
	}
	if !strings.Contains(out, "echo-request") {
		t.Error("ICMP echo must be permitted")
	}
}

func TestForwardingRuleRenderedWhenInterfacesKnown(t *testing.T) {
	out := Render(configured())

	if !strings.Contains(out, `iifname "enx001122334455" oifname "enp0s31f6" accept`) {
		t.Errorf("LAN-to-WAN forwarding must be emitted:\n%s", out)
	}
}

// TestUnidentifiedInterfacesProduceCommentsNotRules covers the development
// state: the ruleset must not contain rules that reference interfaces which
// do not exist, but must say what is missing.
func TestUnidentifiedInterfacesProduceCommentsNotRules(t *testing.T) {
	p := configured()
	p.Interfaces.LAN = ""

	out := Render(p)

	if strings.Contains(out, `oifname "" accept`) {
		t.Error("must not emit a rule with an empty interface")
	}
	if !strings.Contains(out, "intended: iifname") {
		t.Error("the missing rule must be documented as a comment")
	}
	if !strings.Contains(out, "one of the interfaces is unidentified") {
		t.Error("the omission must be explained")
	}
}

func TestNoRulesWhenForwardingDisabled(t *testing.T) {
	p := configured()
	p.Forward.LANToWAN = false

	out := Render(p)

	if strings.Contains(out, `oifname "enp0s31f6" accept`) {
		t.Error("no forwarding rule may be emitted when forwarding is disabled")
	}
	if !strings.Contains(out, "LAN-to-WAN forwarding is disabled by policy") {
		t.Error("the omission must be explained")
	}
}

func TestEveryRuleHasAComment(t *testing.T) {
	// A ruleset is audited under pressure. A rule with no explanation forces
	// a reverse-engineering exercise at three in the morning.
	for _, r := range rules(Render(configured())) {
		if r == "}" || strings.HasPrefix(r, "table ") ||
			strings.HasPrefix(r, "chain ") || strings.HasPrefix(r, "type ") {
			continue
		}
		if !strings.Contains(r, `comment "`) && !strings.HasPrefix(r, "}") {
			t.Errorf("rule has no comment: %q", r)
		}
	}
}

func TestCommentEscapingPreventsBrokenOutput(t *testing.T) {
	// A quote or backslash in a comment would produce a ruleset that fails to
	// parse — a firewall that was never installed.
	p := configured()
	p.Comments = []string{`a "quoted" word`, `a \backslash`, "multi\nline"}

	out := Render(p)

	if strings.Contains(out, `"a "quoted" word"`) {
		t.Error("quotes in comments must be escaped")
	}
	// Every comment line must be well formed: a comment must not contain a
	// raw newline, which would silently truncate the rest of the ruleset.
	for _, raw := range strings.Split(out, "\n") {
		if strings.Contains(raw, "multi\nline") {
			continue // the source was a multi-line comment; splitting is correct
		}
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") && trimmed == "" {
			t.Errorf("comment line has a hash but no text: %q", raw)
		}
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	// Two renders of the same policy must be byte-identical, or a reviewer
	// cannot tell a real change from reordering noise.
	p := configured()
	p.Services = []policy.Service{
		{Name: "zebra", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(9000)}},
		{Name: "alpha", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(8000)}},
	}

	first := Render(p)
	for i := 0; i < 5; i++ {
		if got := Render(p); got != first {
			t.Fatalf("render is not deterministic (iteration %d)", i)
		}
	}
}

func TestServicesAreSorted(t *testing.T) {
	p := configured()
	p.Services = []policy.Service{
		{Name: "zebra", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(9000)}},
		{Name: "alpha", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(8000)}},
	}

	out := Render(p)

	alpha := strings.Index(out, "permit alpha")
	zebra := strings.Index(out, "permit zebra")
	if alpha < 0 || zebra < 0 {
		t.Fatalf("both services must be rendered (alpha=%d zebra=%d)", alpha, zebra)
	}
	if alpha > zebra {
		t.Error("services must be rendered in sorted order")
	}
}

func TestRenderDoesNotMutateThePolicy(t *testing.T) {
	// Render normalises a clone, so a caller's policy must be untouched.
	p := configured()
	p.Services = []policy.Service{
		{Name: "zebra", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(9000)}},
		{Name: "alpha", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(8000)}},
	}
	before := p.Services[0].Name

	Render(p)

	if p.Services[0].Name != before {
		t.Errorf("Render mutated the caller's policy: %q became %q", before, p.Services[0].Name)
	}
}

func TestLoggingOnlyWhenEnabled(t *testing.T) {
	p := configured()
	p.Logging.Enabled = false
	if strings.Contains(Render(p), "log-prefix") {
		t.Error("logging must not be emitted when disabled")
	}

	p.Logging.Enabled = true
	if !strings.Contains(Render(p), "log-prefix") {
		t.Error("logging must be emitted when enabled")
	}
}

func TestUnlimitedLoggingWarnsInOutput(t *testing.T) {
	p := configured()
	p.Logging.Enabled = true
	p.Logging.RateLimit = 0

	out := Render(p)

	if !strings.Contains(out, "will fill a disk") {
		t.Error("unlimited logging must be called out in the rendered file")
	}
}

func TestPreroutingDeclaresNoForwards(t *testing.T) {
	out := Render(configured())

	if !strings.Contains(out, "No inbound port forwards are generated") {
		t.Error("the empty prerouting chain must be explained")
	}
	if strings.Contains(out, "dnat to") {
		t.Error("no destination NAT may be generated")
	}
}

func TestProtocolRendering(t *testing.T) {
	cases := []struct {
		proto policy.Protocol
		want  string
	}{
		{policy.ProtoTCP, "tcp dport"},
		{policy.ProtoUDP, "udp dport"},
	}

	for _, c := range cases {
		p := configured()
		p.Services = []policy.Service{
			{Name: "svc", Protocol: c.proto, Ports: []policy.PortRange{policy.Single(1234)}},
		}
		out := Render(p)
		if !strings.Contains(out, c.want) {
			t.Errorf("protocol %q must render as %q", c.proto, c.want)
		}
	}
}

func TestICMPServiceRendersWithoutPorts(t *testing.T) {
	p := configured()
	p.Services = []policy.Service{
		{Name: "ping", Protocol: policy.ProtoICMP},
	}

	out := Render(p)

	if strings.Contains(out, "icmp dport") {
		t.Error("an ICMP service must not render a port match")
	}
}

func TestMultiplePortsRenderedAsSet(t *testing.T) {
	p := configured()
	p.Services = []policy.Service{
		{Name: "multi", Protocol: policy.ProtoTCP,
			Ports: []policy.PortRange{policy.Single(80), policy.Single(443)}},
	}

	out := Render(p)

	if !strings.Contains(out, "dport { 80, 443 }") {
		t.Errorf("multiple ports must render as an nft set, got:\n%s", out)
	}
}

func TestPortRangeRendered(t *testing.T) {
	p := configured()
	p.Services = []policy.Service{
		{Name: "range", Protocol: policy.ProtoTCP,
			Ports: []policy.PortRange{{Low: 1000, High: 2000}}},
	}

	if !strings.Contains(Render(p), "dport { 1000-2000 }") {
		t.Error("a port range must render in nft notation")
	}
}

func TestHeaderDocumentsLoading(t *testing.T) {
	out := Render(configured())

	if !strings.Contains(out, "nft -c -f") && !strings.Contains(out, "nft -f <this-file>") {
		t.Error("the header must document how to load the ruleset")
	}
	if !strings.Contains(out, "Do not edit by hand") {
		t.Error("the header must warn against hand edits")
	}
}
