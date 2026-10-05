package lab

// Parser tests for THN's own nftables table.
//
// # Why these exist
//
// The live NAT assertion failed on a table that was demonstrably correct: the
// gateway had translated 10.77.0.100 to 10.77.250.1, which only a working
// masquerade rule can do. The parser had failed to read it and reported the
// absence of a rule that the kernel was enforcing.
//
// A parser that is only ever run against a live gateway is a parser whose
// failures arrive as evidence about the product. These tests run the parser
// against captured payloads on every platform, so a change in how a rule is
// recognised is caught here rather than in a lab three in the morning.
//
// # What they do not do
//
// They do not assert a single exact JSON spelling. nftables has emitted NAT
// statements both nested under "nat" and as a top-level "masq" key, and which
// one a given release produces is a property of that release rather than
// something this repository should pin. The tests cover every spelling the
// parser accepts, and each way a rule can be wrong.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// nftRule is one rule as nftables reports it in JSON.
//
// The single parser for THN's own table. Anything that needs to know what a
// rule says reads it through here rather than re-deriving the schema, so a
// change in how nft renders rules is fixed in one place.
//
// It is declared outside a //go:build linux file so the parser can be
// exercised on every platform.
type nftRule struct {
	Family string    `json:"family"`
	Table  string    `json:"table"`
	Chain  string    `json:"chain"`
	Exprs  []nftExpr `json:"expr"`
}

type nftExpr struct {
	Match *nftMatch `json:"match"`
	Nat   *nftNat   `json:"nat"`

	// Masq and Masquerade carry the NAT statement as a top-level key on the
	// rule rather than nested under "nat".
	//
	// Kept alongside Nat rather than instead of it because which spelling a
	// given nftables release emits for a rule it just installed is not
	// something to assert in advance — it is the kind of detail that differs
	// between versions. Recognising the statement by its presence and then
	// classifying it is what lets the test be right about masquerade and honest
	// about anything it did not recognise.
	Masq       *json.RawMessage `json:"masq"`
	Masquerade *json.RawMessage `json:"masquerade"`
}

type nftMatch struct {
	Left  nftOperand `json:"left"`
	Right string     `json:"right"`
}

type nftOperand struct {
	Meta *struct {
		Key string `json:"key"`
	} `json:"meta"`
}

type nftNat struct {
	Type string `json:"type"`
}

// natType reports the NAT statement this expression carries: which key spelled
// it, and what type it claimed to be.
//
// Both halves are returned so a diagnostic can say "there was a NAT statement
// under `nat` and it said `snat`" instead of the far less useful "no
// masquerade rule found".
func (e nftExpr) natType() (spelling, natType string, ok bool) {
	switch {
	case e.Nat != nil:
		return "nat", e.Nat.Type, true
	case e.Masquerade != nil:
		return "masquerade", "masquerade", true
	case e.Masq != nil:
		return "masq", "masquerade", true
	}
	return "", "", false
}

// isMasqueradeType reports whether a NAT statement type is masquerade.
//
// `masquerade` is the canonical spelling and `masq` the abbreviation nft
// accepts on input. `snat` and `dnat` are source and destination translation
// and are deliberately not included: a rule doing either is not masquerading,
// and accepting it would let the assertion pass on the wrong behaviour.
func isMasqueradeType(natType string) bool {
	switch strings.ToLower(natType) {
	case "masquerade", "masq":
		return true
	}
	return false
}

// masqueradeOn reports whether this rule masquerades, and which interface it
// is restricted to.
//
// Structured rather than textual, because nft renders the rule as
// `oifname "thnwan0" masquerade` — quoted — so a text search for
// `oifname thnwan0` cannot match a rule that is present and correct. That is
// not cosmetic: the assertion exists to prove masquerade is attached to the
// WAN interface *specifically*, and only the parse can say so.
func (r nftRule) masqueradeOn() (bool, string) {
	masquerade := false
	iface := ""

	for _, e := range r.Exprs {
		if _, natType, ok := e.natType(); ok && isMasqueradeType(natType) {
			masquerade = true
		}
		if e.Match != nil && e.Match.Left.Meta != nil && e.Match.Left.Meta.Key == "oifname" {
			iface = e.Match.Right
		}
	}
	return masquerade, iface
}

// LeftMetaKey reports which kernel key a match compares.
//
// A match without a meta key — a payload comparison, say — is reported as
// unknown rather than silently treated as an interface test.
func (m nftMatch) LeftMetaKey() string {
	if m.Left.Meta == nil {
		return "<payload>"
	}
	return m.Left.Meta.Key
}

// isGatewayMasquerade reports whether this rule is *the* gateway masquerade:
// a masquerade, in THN's own table, in the postrouting chain, bound to iface.
//
// One definition of what the NAT assertion accepts, shared by the live
// assertion and by the tests below. When the predicate lived only inside the
// test body, the tests could not exercise it — which is how a rule in the wrong
// chain could be indistinguishable from one in the right chain at the point
// where it mattered.
func (r nftRule) isGatewayMasquerade(iface string) bool {
	masquerade, bound := r.masqueradeOn()
	return masquerade && r.Table == "thn" && r.Chain == "postrouting" && bound == iface
}

// describe renders one rule for a failure message.
func (r nftRule) describe() string {
	masquerade, iface := r.masqueradeOn()

	var parts []string
	for i, e := range r.Exprs {
		switch {
		case e.Match != nil:
			parts = append(parts, fmt.Sprintf("expr[%d]=match(%s=%q)", i, e.Match.LeftMetaKey(), e.Match.Right))
		default:
			spelling, natType, ok := e.natType()
			if ok {
				parts = append(parts, fmt.Sprintf("expr[%d]=%s(type=%q)", i, spelling, natType))
				continue
			}
			parts = append(parts, fmt.Sprintf("expr[%d]=<unrecognised>", i))
		}
	}

	return fmt.Sprintf("family=%s table=%s chain=%s exprs=%d masquerade=%t oifname=%q [%s]",
		r.Family, r.Table, r.Chain, len(r.Exprs), masquerade, iface,
		strings.Join(parts, " "))
}

// ruleJSON builds the nft JSON document for a set of rules.
//
// Shaped like real output: a metainfo element, a table element, chain elements
// and rule elements, each a separate entry in the "nftables" array.
func ruleJSON(rules ...string) string {
	body := `{"metainfo":{"version":"1.0.6","json_schema_version":1}},` +
		`{"table":{"family":"inet","name":"thn"}}`
	for _, r := range rules {
		body += `,` + r
	}
	return `{"nftables":[` + body + `]}`
}

// masqueradeRuleJSON renders one postrouting masquerade rule.
func masqueradeRuleJSON(family, table, chain, iface string) string {
	rule := `{"rule":{"family":"` + family + `","table":"` + table + `","chain":"` + chain + `",` +
		`"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"` + iface + `"}},` +
		`{"nat":{"type":"masquerade"}}]}}`
	return rule
}

// parseRules runs the document through the same decoder the harness uses.
func parseRules(t *testing.T, raw string) []nftRule {
	t.Helper()

	var doc struct {
		Nftables []struct {
			Rule *nftRule `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decoding captured nft JSON: %v\n%s", err, raw)
	}

	var rules []nftRule
	for _, item := range doc.Nftables {
		if item.Rule != nil {
			rules = append(rules, *item.Rule)
		}
	}
	return rules
}

// TestMasqueradeRuleIsDetected is the positive case: the rule THN installs for
// the lab's WAN interface must be recognised, bound to the right interface.
func TestMasqueradeRuleIsDetected(t *testing.T) {
	for _, spelling := range []struct {
		name string
		expr string
	}{
		{
			name: "NAT statement nested under nat",
			expr: `{"nat":{"type":"masquerade"}}`,
		},
		{
			name: "NAT statement spelled masq",
			expr: `{"masq":{}}`,
		},
		{
			name: "NAT statement spelled masquerade",
			expr: `{"masquerade":{}}`,
		},
	} {
		t.Run(spelling.name, func(t *testing.T) {
			raw := `{"nftables":[` +
				`{"table":{"family":"inet","name":"thn"}},` +
				`{"rule":{"family":"inet","table":"thn","chain":"postrouting","expr":[` +
				`{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"thnwan0"}},` +
				spelling.expr + `]}}` + `]}`

			rules := parseRules(t, raw)
			if len(rules) != 1 {
				t.Fatalf("parsed %d rules, want 1", len(rules))
			}

			masquerade, iface := rules[0].masqueradeOn()
			if !masquerade {
				t.Errorf("masquerade not detected in %s", spelling.name)
			}
			if iface != GatewayWANInterface {
				t.Errorf("oifname = %q, want %s", iface, GatewayWANInterface)
			}
			if rules[0].Table != "thn" || rules[0].Chain != "postrouting" {
				t.Errorf("rule read as table=%q chain=%q, want thn/postrouting",
					rules[0].Table, rules[0].Chain)
			}
			if !rules[0].isGatewayMasquerade(GatewayWANInterface) {
				t.Errorf("the rule THN installs is not accepted as the gateway masquerade: %s",
					rules[0].describe())
			}
		})
	}
}

// TestMasqueradeRuleIsRejected covers every way a rule can be wrong. Each case
// must be refused, because the assertion exists to prove a specific rule is
// present — a parser that accepts anything is not an assertion.
func TestMasqueradeRuleIsRejected(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "a rule with no NAT statement at all",
			raw: ruleJSON(
				`{"rule":{"family":"inet","table":"thn","chain":"forward","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"thnlan0"}},{"accept":null}]}}`),
		},
		{
			name: "masquerade in the wrong chain",
			raw:  ruleJSON(masqueradeRuleJSON("inet", "thn", "input", GatewayWANInterface)),
		},
		{
			name: "masquerade belonging to another table",
			raw:  ruleJSON(masqueradeRuleJSON("inet", "someone_elses", "postrouting", GatewayWANInterface)),
		},
		{
			name: "source NAT is not masquerade",
			raw: ruleJSON(
				`{"rule":{"family":"inet","table":"thn","chain":"postrouting","expr":[{"nat":{"type":"snat"}}]}}`),
		},
		{
			name: "destination NAT is not masquerade",
			raw: ruleJSON(
				`{"rule":{"family":"inet","table":"thn","chain":"postrouting","expr":[{"nat":{"type":"dnat"}}]}}`),
		},
		{
			name: "masquerade bound to a different interface",
			raw:  ruleJSON(masqueradeRuleJSON("inet", "thn", "postrouting", "eth0")),
		},
		{
			name: "masquerade with no interface condition",
			raw: ruleJSON(
				`{"rule":{"family":"inet","table":"thn","chain":"postrouting","expr":[{"nat":{"type":"masquerade"}}]}}`),
		},
		{
			name: "an empty document",
			raw:  `{"nftables":[]}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rules := parseRules(t, c.raw)

			for _, r := range rules {
				if r.isGatewayMasquerade(GatewayWANInterface) {
					t.Errorf("rule accepted as the gateway masquerade but should not be: %s", r.describe())
				}
			}
		})
	}
}

// TestExactlyOneMasqueradeIsAccepted pins the count the assertion enforces.
//
// Not decoration: a table with two masquerade rules behaves differently from
// one with a single rule, and an assertion that only asks "is there one" would
// pass on both.
func TestExactlyOneMasqueradeIsAccepted(t *testing.T) {
	raw := ruleJSON(
		masqueradeRuleJSON("inet", "thn", "postrouting", GatewayWANInterface),
		masqueradeRuleJSON("inet", "thn", "postrouting", GatewayLANInterface),
	)

	accepted := 0
	for _, r := range parseRules(t, raw) {
		if r.isGatewayMasquerade(GatewayWANInterface) {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("accepted %d masquerade rules for %s, want exactly 1", accepted, GatewayWANInterface)
	}
}

// TestMalformedPayloadIsAnErrorNotAnAbsence is the defect that made this whole
// investigation necessary.
//
// A payload the parser cannot read must surface as a parse failure. Reporting
// it as "zero rules" turns the test's own inability to read the kernel into a
// claim that the kernel has no rule — which is a statement about THN's NAT,
// derived entirely from the harness.
func TestMalformedPayloadIsAnErrorNotAnAbsence(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"truncated document", `{"nftables":[{"rule":{}}`},
		{"wrong top-level shape", `[{"rule":{"chain":"postrouting"}}]`},
		{"not json at all", `Error: syntax error, unexpected $`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var doc struct {
				Nftables []struct {
					Rule *nftRule `json:"rule"`
				} `json:"nftables"`
			}
			if err := json.Unmarshal([]byte(c.raw), &doc); err == nil {
				t.Errorf("decoding %q succeeded; the parser must report malformed input", c.raw)
			}
		})
	}
}

// TestNATStatementDiagnosticsSpellOutWhatTheySaw keeps the failure message
// honest: it has to distinguish "no NAT statement here" from "a NAT statement
// here that said something else".
func TestNATStatementDiagnosticsSpellOutWhatTheySaw(t *testing.T) {
	raw := `{"nftables":[` +
		`{"rule":{"family":"inet","table":"thn","chain":"postrouting","expr":[` +
		`{"nat":{"type":"snat"}},{"masq":{}}]}}` + `]}`

	rules := parseRules(t, raw)
	if len(rules) != 1 {
		t.Fatalf("parsed %d rules, want 1", len(rules))
	}

	var seen []string
	for _, e := range rules[0].Exprs {
		if spelling, natType, ok := e.natType(); ok {
			seen = append(seen, spelling+"="+natType)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("NAT statements seen = %v, want two", seen)
	}

	masquerade, _ := rules[0].masqueradeOn()
	if !masquerade {
		t.Error("a rule carrying a masq statement was not recognised as masquerade")
	}

	if got := rules[0].describe(); got == "" {
		t.Error("describe returned nothing; a failure message needs it")
	}
}
