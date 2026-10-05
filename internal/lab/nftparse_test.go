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
	"strconv"
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

	// NAT statements are identified by the key being PRESENT, not by a
	// non-nil pointer.
	//
	// nft renders a masquerade as `{"masquerade": null}` — a member whose
	// value is null. encoding/json turns a JSON null into a nil pointer before
	// the field's type is ever consulted, so a `*json.RawMessage` field makes
	// that statement indistinguishable from an absent one. The live gateway's
	// masquerade rule did exactly that: it read as an unrecognised expression,
	// and the NAT assertion reported a missing rule that was enforcing
	// translation at the time.
	//
	// json.RawMessage as a value keeps the literal bytes, so the key present
	// with a null value decodes to the four bytes `null` and len() answers the
	// question. Measured, not assumed: a pointer form yields nil for the same
	// input, a value form yields len 4.
	Nat        json.RawMessage `json:"nat"`
	Masq       json.RawMessage `json:"masq"`
	Masquerade json.RawMessage `json:"masquerade"`
}

// nftMatch is one comparison within a rule.
//
// # Right is raw JSON, and that is not laziness
//
// `right` is polymorphic. The same field holds a plain string for an interface
// name:
//
//	"right": "thnwan0"
//
// a list for a connection-state test, which is what the live gateway's
// `ct state established,related` rule emits:
//
//	"right": ["established", "related"]
//
// and an object for a prefix:
//
//	"right": {"prefix": {"addr": "10.77.0.0", "len": 24}}
//
// Declaring it `string` made the whole document undecodable. `encoding/json`
// fails the entire unmarshal on the first type mismatch, so one perfectly
// valid connection-state expression in the `forward` chain meant zero rules
// were read from the table — and the NAT assertion, which asked what the
// `postrouting` chain contained, was told the kernel had no masquerade rule at
// all while it was enforcing one.
//
// Left stays typed: the assertions need the meta key to identify an interface
// comparison, and there is no reason to give that up.
type nftMatch struct {
	Op    string          `json:"op"`
	Left  nftOperand      `json:"left"`
	Right json.RawMessage `json:"right"`
}

// rightString returns the match's right-hand value when it is a JSON string.
//
// False for a list, an object, an absent value or null — none of which are
// interface names. That is not an error: those are valid nft expressions the
// parser read correctly and simply has nothing to extract.
func (m nftMatch) rightString() (string, bool) {
	if len(m.Right) == 0 {
		return "", false
	}
	// `null` must be refused explicitly. encoding/json accepts it for a string
	// and leaves the value empty, so it would otherwise report an empty
	// interface name as though one had been read.
	if trimmed := strings.TrimSpace(string(m.Right)); trimmed == "" || trimmed == "null" {
		return "", false
	}
	var s string
	if err := json.Unmarshal(m.Right, &s); err != nil {
		return "", false
	}
	return s, true
}

// rightValue renders the right-hand value for a diagnostic.
//
// Strings are quoted so an empty one is visible; anything else is shown as the
// JSON nft actually produced, which is the only useful thing to print when the
// question is "why did this not parse as expected".
func (m nftMatch) rightValue() string {
	if len(m.Right) == 0 {
		return "<absent>"
	}
	if s, ok := m.rightString(); ok {
		return strconv.Quote(s)
	}
	raw := strings.TrimSpace(string(m.Right))
	const max = 72
	if len(raw) > max {
		return raw[:max] + "..."
	}
	return raw
}

type nftOperand struct {
	Meta *struct {
		Key string `json:"key"`
	} `json:"meta"`
}

type nftNat struct {
	Type string `json:"type"`
}

// nftStatement is a NAT expression, and how it was spelled.
type nftStatement struct {
	// Key is the JSON member that carried it.
	Key string
	// Type is the translation it performs. For a key that names the
	// translation directly — `masq`, `masquerade` — that is the name. For
	// `nat` it is the `type` inside the object, and "" when nft gave none.
	Type string
	// Raw is the member's value, including a JSON null.
	Raw json.RawMessage
}

// natType reports the NAT statement this expression carries: which key spelled
// it, and what type it claimed to be.
//
// Both halves are returned so a diagnostic can say "there was a NAT statement
// under `nat` and it said `snat`" instead of the far less useful "no
// masquerade rule found".
func (e nftExpr) natType() (spelling, natType string, ok bool) {
	s := e.natStatement()
	if s == nil {
		return "", "", false
	}
	return s.Key, s.Type, true
}

// natStatement identifies the NAT statement in this expression, if there is one.
//
// Ordered rather than merged: a rule carries at most one, and naming the key
// that spelled it is what makes a diagnostic actionable.
func (e nftExpr) natStatement() *nftStatement {
	for _, c := range []nftStatement{
		{Key: "nat", Type: natTypeOf(e.Nat), Raw: e.Nat},
		{Key: "masquerade", Type: "masquerade", Raw: e.Masquerade},
		{Key: "masq", Type: "masquerade", Raw: e.Masq},
	} {
		if len(c.Raw) > 0 {
			return &c
		}
	}
	return nil
}

// natTypeOf reads the `type` of a `nat` statement object.
//
// "" when the object is null, empty, or states no type. A caller treats that as
// "a NAT statement whose type was not stated", which is deliberately not
// masquerade: a statement the parser could not read must not be counted as the
// one the assertion is looking for.
func natTypeOf(raw json.RawMessage) string {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return ""
	}
	var n nftNat
	if err := json.Unmarshal(raw, &n); err != nil {
		return ""
	}
	return n.Type
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
	bound := ""

	for _, e := range r.Exprs {
		if _, natType, ok := e.natType(); ok && isMasqueradeType(natType) {
			masquerade = true
		}
		// Only a comparison of the oifname meta key whose right-hand value is
		// an actual string identifies an interface. A list or an object there
		// is valid nft JSON the parser has read correctly and has no interface
		// name to report.
		if e.Match != nil && e.Match.LeftMetaKey() == "oifname" {
			if iface, ok := e.Match.rightString(); ok {
				bound = iface
			}
		}
	}
	return masquerade, bound
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
			parts = append(parts, fmt.Sprintf("expr[%d]=match(%s op=%s right=%s)",
				i, e.Match.LeftMetaKey(), e.Match.Op, e.Match.rightValue()))
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

// op reports the comparison operator, or "" when the match has none.
func (m nftMatch) op() string { return m.Op }

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

// liveTableJSON is the nft JSON for the table THN installs on the disposable
// lab gateway, transcribed from a real `nft -j list table inet thn` on Ubuntu.
//
// It is reproduced whole rather than trimmed to the masquerade rule on purpose.
// The failure was never in reading the masquerade rule — it was that one
// connection-state expression in the `forward` chain aborted the decode of the
// entire document, so a table with all three chains present reported zero
// rules. A fixture containing only the rule the assertion cares about cannot
// reproduce that, and would have passed while the bug was live.
//
// It carries each shape of `match.right` the live table contains:
//
//	rule A  "right": ["established","related"]   the connection-state test
//	rule B  "right": "lo"                        an interface, as a string
//	rule C  "right": "thnwan0"                   the masquerade's interface
//	rule D  "right": {"prefix":{"addr":..,"len":24}}   the LAN subnet match
const liveTableJSON = `{"nftables":[
{"metainfo":{"version":"1.0.6","release_name":"Dave Théron","json_schema_version":1}},
{"table":{"family":"inet","name":"thn","handle":253}},
{"chain":{"family":"inet","table":"thn","name":"input","handle":254,"type":"filter","hook":"input","priority":0,"policy":"drop"}},
{"chain":{"family":"inet","table":"thn","name":"forward","handle":255,"type":"filter","hook":"forward","priority":0,"policy":"drop"}},
{"chain":{"family":"inet","table":"thn","name":"postrouting","handle":256,"type":"nat","hook":"postrouting","priority":100,"policy":"accept"}},

{"rule":{"family":"inet","table":"thn","chain":"input","handle":257,"expr":[
  {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},
  {"accept":null}]}},

{"rule":{"family":"inet","table":"thn","chain":"input","handle":258,"expr":[
  {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},
  {"accept":null}]}},

{"rule":{"family":"inet","table":"thn","chain":"input","handle":259,"expr":[
  {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"thnlan0"}},
  {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.77.0.0","len":24}}}},
  {"accept":null}]}},

{"rule":{"family":"inet","table":"thn","chain":"forward","handle":260,"expr":[
  {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},
  {"accept":null}]}},

{"rule":{"family":"inet","table":"thn","chain":"forward","handle":261,"expr":[
  {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lo"}},
  {"accept":null}]}},

{"rule":{"family":"inet","table":"thn","chain":"forward","handle":262,"expr":[
  {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"thnlan0"}},
  {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"thnwan0"}},
  {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.77.0.0","len":24}}}},
  {"accept":null}]}},

{"rule":{"family":"inet","table":"thn","chain":"postrouting","handle":263,"expr":[
  {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"thnwan0"}},
  {"masquerade":null}]}}
]}`

// liveMasqueradeJSON is the exact expression nft emits for the gateway's
// masquerade, captured from the disposable lab:
//
//	{"masquerade": null}
//
// The null is not incidental. It is how nft spells a statement that carries no
// operand, and it is precisely what defeated a pointer-typed field: the decoder
// turns a JSON null into a nil pointer, so the statement became
// indistinguishable from an absent one and the rule read as
// `expr[1]=<unrecognised>` while the kernel was translating traffic with it.
const liveMasqueradeJSON = `{"masquerade": null}`

// TestLiveTableParses is the regression test for the parser bug itself.
//
// Before the fix this failed to decode at all:
//
//	json: cannot unmarshal array into Go struct field
//	nftMatch.nftables.rule.expr.match.right of type string
//
// and every assertion that reads THN's table saw zero rules.
func TestLiveTableParses(t *testing.T) {
	rules := parseRules(t, liveTableJSON)

	if len(rules) == 0 {
		t.Fatal("the live table parsed as zero rules; every rule must be read")
	}

	byChain := map[string]int{}
	for _, r := range rules {
		byChain[r.Chain]++
	}
	for chain, want := range map[string]int{"input": 3, "forward": 3, "postrouting": 1} {
		if byChain[chain] != want {
			t.Errorf("chain %s has %d rules, want %d", chain, byChain[chain], want)
		}
	}

	// Every shape of `right` in the live table must be readable, and the counts
	// are the fixture's own. They are asserted rather than assumed so that a
	// change to the fixture cannot quietly stop covering a shape — and they are
	// what the fixture contains, not what a rough reading suggests: six string
	// matches, not seven.
	var list, str, prefix, masquerade int
	for _, r := range rules {
		for _, e := range r.Exprs {
			if _, _, ok := e.natType(); ok {
				masquerade++
			}
			if e.Match == nil {
				continue
			}
			if e.Match.op() == "in" {
				list++
				continue
			}
			if _, ok := e.Match.rightString(); ok {
				str++
			} else if len(e.Match.Right) > 0 {
				prefix++
			}
		}
	}

	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"connection-state matches with a list right", list, 2},
		{"interface matches with a string right", str, 6},
		{"subnet matches with an object right", prefix, 2},
		{"NAT statements", masquerade, 1},
	} {
		if c.got != c.want {
			t.Errorf("read %d %s, want %d", c.got, c.name, c.want)
		}
	}
}

// TestLiveMasqueradeExpressionIsDetected is the focused regression for the
// live representation, isolated from the rest of the table.
//
// `{"masquerade": null}` is a JSON member whose value is null. encoding/json
// turns a JSON null into a nil pointer before the field's type is consulted, so
// the pointer-typed field this parser originally used could not tell that
// statement from an absent key — and the rule that was translating the
// gateway's traffic read as `expr[1]=<unrecognised>`.
func TestLiveMasqueradeExpressionIsDetected(t *testing.T) {
	var expr nftExpr
	if err := json.Unmarshal([]byte(liveMasqueradeJSON), &expr); err != nil {
		t.Fatalf("decoding %s: %v", liveMasqueradeJSON, err)
	}

	spelling, natType, ok := expr.natType()
	if !ok {
		t.Fatalf("no NAT statement recognised in %s", liveMasqueradeJSON)
	}
	if spelling != "masquerade" {
		t.Errorf("statement spelled %q, want %q", spelling, "masquerade")
	}
	if natType != "masquerade" {
		t.Errorf("statement type %q, want %q", natType, "masquerade")
	}
	if !isMasqueradeType(natType) {
		t.Errorf("%q was not classified as masquerade", natType)
	}

	// The member's value is preserved, null included, so a diagnostic can show
	// what the kernel actually said.
	if got := strings.TrimSpace(string(expr.Masquerade)); got != "null" {
		t.Errorf("raw statement value = %q, want %q", got, "null")
	}
}

// TestNatMemberWithNoTypeIsNotMasquerade keeps the fail-closed direction.
//
// A `nat` statement the parser could not read a type from is not counted as
// masquerade. Counting it would let the assertion pass on a statement it does
// not understand.
func TestNatMemberWithNoTypeIsNotMasquerade(t *testing.T) {
	for _, raw := range []string{`{"nat": null}`, `{"nat": {}}`, `{"nat": {"type": ""}}`} {
		var expr nftExpr
		if err := json.Unmarshal([]byte(raw), &expr); err != nil {
			t.Fatalf("decoding %s: %v", raw, err)
		}
		_, natType, ok := expr.natType()
		if !ok {
			t.Errorf("%s: statement not recognised at all, want it recognised with no type", raw)
			continue
		}
		if isMasqueradeType(natType) {
			t.Errorf("%s: a statement with no type was accepted as masquerade", raw)
		}
	}
}

// TestLiveTableYieldsTheGatewayMasquerade is the end of the chain the parser
// exists to serve: from the complete live document, the postrouting masquerade
// bound to the WAN interface must still be identified.
func TestLiveTableYieldsTheGatewayMasquerade(t *testing.T) {
	accepted := 0
	for _, r := range parseRules(t, liveTableJSON) {
		if r.isGatewayMasquerade(GatewayWANInterface) {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("the live table yielded %d gateway masquerade rules, want exactly 1", accepted)
	}
}

// TestMatchRightShapesAreClassifiedNotRejected pins the classification: a
// non-string `right` is a value the parser has read, not a failure.
func TestMatchRightShapesAreClassifiedNotRejected(t *testing.T) {
	cases := []struct {
		name   string
		right  string
		want   string
		wantOK bool
	}{
		{"interface name", `"thnwan0"`, "thnwan0", true},
		{"connection state list", `["established","related"]`, "", false},
		{"subnet prefix", `{"prefix":{"addr":"10.77.0.0","len":24}}`, "", false},
		{"numeric port", `18080`, "", false},
		{"null", `null`, "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := nftMatch{Op: "==", Left: nftOperand{}, Right: json.RawMessage(c.right)}

			got, ok := m.rightString()
			if ok != c.wantOK || got != c.want {
				t.Errorf("rightString() = (%q, %v), want (%q, %v)", got, ok, c.want, c.wantOK)
			}
			if m.rightValue() == "" {
				t.Error("rightValue() rendered nothing; diagnostics need it")
			}
		})
	}

	// An absent right is valid too: some matches carry no value at all.
	absent := nftMatch{Op: "!="}
	if _, ok := absent.rightString(); ok {
		t.Error("an absent right must not report a string")
	}
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
			// The live representation, and the one that broke: a member whose
			// value is null.
			name: "NAT statement spelled masquerade with a null value",
			expr: liveMasqueradeJSON,
		},
		{
			name: "NAT statement spelled masq with a null value",
			expr: `{"masq": null}`,
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
