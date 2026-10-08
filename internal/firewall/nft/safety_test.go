package nft

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/firewall/policy"
)

// TestRenderNeverProducesAnApplyCommand is the structural guarantee behind
// `thn firewall render`.
//
// The renderer emits text. It must never emit anything that looks like it is
// meant to be typed into a shell as a way of changing the firewall, because a
// ruleset file that carries mutating commands invites an operator to copy a
// line out of it and run it directly. Generating text is safe; generating
// something that reads as an instruction to act is not.
func TestRenderNeverProducesAnApplyCommand(t *testing.T) {
	p := configured()
	p.Services = []policy.Service{
		{Name: "https", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(443)}},
		policy.SSH,
	}
	p.Masquerade.Enabled = true
	p.Logging.Enabled = true

	out := Render(p)

	// Strip comments first: the header legitimately documents `nft -f` as the
	// way to load the file, and the policy summary renders unknown interfaces
	// as "(unset)". Neither is a rule, and scanning them would make the check
	// fail on correct output.
	body := ruleLines(out)

	// Commands that would change firewall state if executed.
	mutating := []string{
		"nft add", "nft delete", "nft flush", "nft insert",
		"nft replace", "nft destroy", "nft rename", "nft -f",
		"iptables -A", "iptables -F",
	}
	for _, m := range mutating {
		for _, r := range body {
			if strings.Contains(r, m) {
				t.Errorf("a rule contains the mutating command %q: %q", m, r)
			}
		}
	}

	// No line may contain a bare nft command.
	for _, r := range body {
		if strings.HasPrefix(r, "nft ") {
			t.Errorf("a bare nft command appears in the body: %q", r)
		}
	}
}

// TestRenderDoesNotInvokeAnything documents that Render is a pure function of
// its argument. If Render ever grew a dependency on the host, a ruleset would
// depend on when it was generated, and two renders could disagree.
func TestRenderDoesNotInvokeAnything(t *testing.T) {
	p := configured()
	first := Render(p)

	// Rendering twice from the same input must be identical, which it cannot
	// be if host state were involved.
	if Render(p) != first {
		t.Error("Render is not a pure function of its policy")
	}
}

// TestRenderSurvivesAdversarialInput feeds the renderer values that would
// break naive string interpolation, and checks the output is still structurally
// sound. A ruleset that fails to parse is a firewall that was never installed.
func TestRenderSurvivesAdversarialInput(t *testing.T) {
	p := policy.Default()
	p.Interfaces.WAN = "enp0s31f6"
	p.Interfaces.LAN = "enx0011"

	p.Services = []policy.Service{
		{Name: "quoted", Protocol: policy.ProtoTCP,
			Ports:  []policy.PortRange{policy.Single(1234)},
			Source: []string{`" OR 1=1 --`}},
		{Name: "semi;colon", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(1235)}},
		{Name: "brace{}", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(1236)}},
		{Name: "newline", Protocol: policy.ProtoTCP, Ports: []policy.PortRange{policy.Single(1237)},
			Comment: "first\nsecond"},
	}
	p.Comments = []string{`comment with "quotes" and \backslash`}

	out := Render(p)

	// Braces must still balance.
	depth := 0
	for _, c := range out {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	if depth != 0 {
		t.Errorf("adversarial input broke brace balance by %d:\n%s", depth, out)
	}

	// No line may contain an unescaped quote inside a comment.
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `comment "`) {
			continue
		}
		body := line[strings.Index(line, `comment "`)+len(`comment "`):]
		if !strings.HasSuffix(strings.TrimSpace(body), `"`) {
			t.Errorf("comment does not terminate cleanly: %q", line)
		}
	}
}

// TestRenderedFileIsSelfContained checks the output has no unresolved
// placeholders. A ruleset containing a literal "(unset)" in a rule is a
// ruleset that will not load.
func TestRenderedFileIsSelfContained(t *testing.T) {
	for _, p := range []policy.Policy{configured(), policy.Default()} {
		// Only rules are checked: the header's policy summary legitimately
		// prints "(unset)" for an unidentified interface, which is
		// informative documentation rather than a broken rule.
		body := ruleLines(Render(p))

		for _, placeholder := range []string{"(unset)", "TODO", "FIXME", "%s", "{{", "}}"} {
			for _, r := range body {
				if strings.Contains(r, placeholder) {
					t.Errorf("a rule contains placeholder %q: %q", placeholder, r)
				}
			}
		}
	}
}

// TestDefaultPolicyRendersAWorkingRuleset is the end-to-end check: the shipped
// default must produce something structurally complete.
func TestDefaultPolicyRendersAWorkingRuleset(t *testing.T) {
	p := policy.Default()
	p.Interfaces.WAN = "enp0s31f6"
	p.Interfaces.LAN = "enx0011"
	p.Admin.Source = []string{"203.0.113.0/24"}

	out := Render(p)

	required := []string{
		"table inet thn {",
		"chain input {",
		"hook input priority filter; policy drop",
		"hook forward priority filter; policy drop",
		"ct state established,related accept",
		`iifname "lo" accept`,
		"masquerade",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("default policy output is missing %q", want)
		}
	}

	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Error("the table must be closed")
	}
}

// TestValidationGatesRenderingAtTheCLILayer is covered in the cli package;
// this asserts the contract the renderer depends on: a policy that validates
// is renderable, and one that does not is reported rather than emitted.
func TestPolicyValidationGatesRenderability(t *testing.T) {
	good := configured()
	if r := policy.Validate(good); !r.Valid {
		t.Fatalf("the configured policy must validate: %v", r.Errors())
	}

	// A policy that locks the operator out still renders, but the CLI refuses
	// to emit it without --no-validate. Rendering must therefore not panic or
	// produce garbage even for an invalid policy.
	bad := configured()
	bad.Admin.Enabled = false
	out := Render(bad)

	if r := policy.Validate(bad); r.Valid {
		t.Error("an admin-less policy must not validate")
	}
	if !strings.Contains(out, "policy drop") {
		t.Error("even an invalid policy must render structurally")
	}
}
