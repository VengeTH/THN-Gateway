package validation_test

// The validation matrix: what every prefix, address and gateway value actually
// does, at both layers, and the guarantee that none of them can take the
// process down.
//
// Two things are being defended here.
//
// The first is panic-freedom. internal/validation once computed
// `1 << (32 - bits)` for the usable-host count, so every IPv6 prefix — every
// perfectly ordinary fd00::/64 — produced a negative shift count and killed
// the process. `thn validate` crashed on valid input. A validator that dies on
// input is worse than one that rejects it, because the operator sees a stack
// trace instead of an answer, and the crash is indistinguishable from the tool
// being broken.
//
// The second is that the two layers agree. internal/config holds structural
// rules and internal/validation holds deployment policy, and validation.Static
// is built on top of config.Validate. That layering means they cannot disagree
// about validity, and the cross-layer check below is what keeps that true as
// rules are added.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/validation"
)

// writeFile writes a document for the loader tests.
func writeFile(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), 0o600)
}

// assertNoPanic fails the test if fn panics.
//
// The requirement is that invalid input produces a validation result, never a
// process panic. Asserting that a call returns an error does not prove it:
// the same call can return an error on one input and abort on another.
func assertNoPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIC in %s: %v", what, r)
		}
	}()
	fn()
}

// verdict is the expected outcome for one matrix row.
type verdict struct {
	// invalid means both layers must report at least one error.
	invalid bool

	// field is the field expected to carry that error. Optional: some rows
	// only care about the verdict.
	field string
}

// matrixCase is one row of the validation matrix.
type matrixCase struct {
	name string

	// lanPrefix is assigned to cfg.Network.LANPrefix. An empty string is a
	// real input, not "leave it alone", so it is stated explicitly.
	lanPrefix string

	// upstream is assigned to cfg.Network.UpstreamGateway; empty means unset.
	upstream string

	// lan identifies the downstream interface; empty means not identified.
	lan string

	want verdict

	// note records the policy reason, so the table explains itself.
	note string
}

// matrix is the validation matrix for the network addressing rules.
//
// Policy, stated once so the table below reads against it:
//
//   - LANPrefix is the address THN would place on the LAN interface, so host
//     bits are expected and required. 10.77.0.1/24 is the canonical value.
//   - Loopback, unspecified and multicast LAN addresses are errors: none of
//     them is a network a LAN can be built on.
//   - A public LAN address is legal and routes, so it warns.
//   - "Too narrow" is an IPv4-only judgement and a warning, never an error.
//     /64 is an ordinary IPv6 LAN size.
//   - An upstream gateway inside the LAN is an error in both layers.
//   - An absent LAN prefix is pending, not broken.
var matrix = []matrixCase{
	// ---------------------------------------------------- IPv4, valid
	{name: "ipv4 normal private lan", lanPrefix: "10.77.0.1/24", note: "the canonical value"},
	{name: "ipv4 gateway address with host bits", lanPrefix: "10.77.0.1/16", note: "host bits are expected"},
	{name: "ipv4 network address", lanPrefix: "10.77.0.0/24", note: "a masked network address is also accepted"},
	{name: "ipv4 192.168 lan", lanPrefix: "192.168.1.1/24"},
	{name: "ipv4 172.16 lan", lanPrefix: "172.16.0.1/20"},
	{name: "ipv4 /8 boundary", lanPrefix: "10.0.0.0/8"},
	{name: "ipv4 /16 boundary", lanPrefix: "10.77.0.0/16"},

	// -------------------------------------------------- IPv4, malformed
	{name: "ipv4 missing prefix length", lanPrefix: "10.77.0.1", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 not an address", lanPrefix: "not-an-ip/24", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 octet out of range", lanPrefix: "10.77.0.256/24", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 prefix length out of range", lanPrefix: "10.77.0.1/33", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 negative prefix length", lanPrefix: "10.77.0.1/-1", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 non-numeric prefix length", lanPrefix: "10.77.0.1/abc", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 empty address", lanPrefix: "/24", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 only a prefix length", lanPrefix: "24", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 whitespace padded", lanPrefix: " 10.77.0.1/24 ", note: "Normalize trims before validation"},

	// ------------------------------------------------ IPv4, not routable
	{name: "ipv4 loopback", lanPrefix: "127.0.0.1/8", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 unspecified", lanPrefix: "0.0.0.0/0", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 multicast", lanPrefix: "224.0.0.0/4", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv4 link-local", lanPrefix: "169.254.1.1/16", note: "legal; warns as not-private-or-ULA"},

	// ------------------------------------------ IPv4 boundaries and width
	{name: "ipv4 /29 boundary", lanPrefix: "10.77.0.1/29", note: "at the policy threshold: valid, warns"},
	{name: "ipv4 /30", lanPrefix: "10.77.0.1/30", note: "narrow: valid, warns"},
	{name: "ipv4 /31", lanPrefix: "10.77.0.1/31", note: "narrow: valid, warns"},
	{name: "ipv4 /32", lanPrefix: "10.77.0.1/32", note: "a single address: valid, warns"},
	{name: "ipv4 /1", lanPrefix: "10.77.0.1/1", note: "valid, not private: warns"},
	{name: "ipv4 /0", lanPrefix: "10.77.0.1/0", note: "valid, not private: warns"},

	// ------------------------------------------------------ IPv6, valid
	{name: "ipv6 unique-local lan", lanPrefix: "fd00::1/64", note: "the ordinary IPv6 LAN size"},
	{name: "ipv6 unique-local /48", lanPrefix: "fd00::1/48"},
	{name: "ipv6 /127", lanPrefix: "fd00::1/127", note: "narrow, but narrowness is an IPv4 judgement"},
	{name: "ipv6 /128", lanPrefix: "fd00::1/128"},
	{name: "ipv6 /0", lanPrefix: "fd00::1/0", note: "the boundary that used to panic"},
	{name: "ipv6 /32", lanPrefix: "fd00::1/32"},
	{name: "ipv6 network address", lanPrefix: "fd00::/64"},
	{name: "ipv6 link-local", lanPrefix: "fe80::1/64", note: "legal; warns as not-ULA"},

	// --------------------------------------------- IPv6, malformed input
	{name: "ipv6 malformed", lanPrefix: "fd00::zz/64", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv6 missing prefix length", lanPrefix: "fd00::1", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv6 prefix length out of range", lanPrefix: "fd00::1/129", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv6 unspecified", lanPrefix: "::/0", want: verdict{invalid: true, field: "network.lan_prefix"}},
	{name: "ipv6 loopback", lanPrefix: "::1/128", want: verdict{invalid: true, field: "network.lan_prefix"}},

	// ------------------------------------------------ family mismatches
	// netip rejects a prefix length *greater* than the address length but
	// accepts a shorter one, so the two directions of this mismatch do not
	// behave alike. That asymmetry is the standard library's, not a rule THN
	// invented, and rejecting the accepted case would be inventing policy.
	// fd00::1/24 masks to fd00::/24, which is a legitimate — if unusual —
	// unique-local network, so accepting it is defensible.
	{name: "ipv4 address with v6 prefix length", lanPrefix: "10.77.0.1/64",
		want: verdict{invalid: true, field: "network.lan_prefix"},
		note: "bits 64 exceed an IPv4 address's 32; netip rejects this"},
	{name: "ipv6 address with v4 prefix length", lanPrefix: "fd00::1/24",
		note: "bits 24 are within an IPv6 address's 128, so netip accepts it; masks to fd00::/24"},
	{name: "ipv4-mapped ipv6 lan", lanPrefix: "::ffff:10.77.0.1/120", note: "parses; not treated as an IPv4 LAN"},

	// ---------------------------------------------------- empty / absent
	{name: "empty lan prefix", lanPrefix: "", note: "pending, not invalid: the LAN interface may not be known yet"},
	{name: "empty lan prefix with lan identified", lanPrefix: "", lan: "enx001122334455", note: "pending, not invalid"},

	// ------------------------------------------------------- the gateway
	{name: "gateway outside lan", lanPrefix: "10.77.0.1/24", upstream: "203.0.113.1"},
	{name: "gateway inside lan", lanPrefix: "10.77.0.1/24", upstream: "10.77.0.99",
		want: verdict{invalid: true, field: "network.upstream_gateway"}, note: "a routing loop"},
	{name: "gateway is the lan address itself", lanPrefix: "10.77.0.1/24", upstream: "10.77.0.1",
		want: verdict{invalid: true, field: "network.upstream_gateway"}},
	{name: "gateway malformed", lanPrefix: "10.77.0.1/24", upstream: "not-an-ip",
		want: verdict{invalid: true, field: "network.upstream_gateway"}},
	{name: "gateway empty", lanPrefix: "10.77.0.1/24", upstream: "", note: "not configured; nothing to check"},
	{name: "gateway outside ipv6 lan", lanPrefix: "fd00::1/64", upstream: "2001:db8::1"},
	{name: "gateway inside ipv6 lan", lanPrefix: "fd00::1/64", upstream: "fd00::5",
		want: verdict{invalid: true, field: "network.upstream_gateway"}},
	{name: "gateway family differs from lan", lanPrefix: "10.77.0.1/24", upstream: "fd00::1",
		note: "not inside the IPv4 LAN, so not reported; a dual-stack deployment"},
	{name: "gateway family differs from ipv6 lan", lanPrefix: "fd00::1/64", upstream: "10.77.0.1",
		note: "not inside the IPv6 LAN, so not reported"},
	{name: "gateway with no lan prefix", lanPrefix: "", upstream: "203.0.113.1", note: "no LAN, nothing to be inside"},
}

// build turns a matrix row into a configuration document.
func build(c matrixCase) config.Config {
	cfg := config.Defaults()
	cfg.Network.LANPrefix = c.lanPrefix
	cfg.Network.UpstreamGateway = c.upstream
	cfg.Network.LAN = c.lan
	// Normalize is what Load does, so trimming happens exactly as it does in
	// production rather than being skipped here.
	_ = cfg.Normalize()
	return cfg
}

// TestTheValidationMatrix walks every row through both layers.
//
// Each row is checked three ways: the composite verdict, the field carrying
// any error, and the promise that nothing panics. All three matter — a layer
// can get the verdict right and still name the wrong field, which sends an
// operator to edit a setting that was fine.
func TestTheValidationMatrix(t *testing.T) {
	for _, c := range matrix {
		t.Run(c.name, func(t *testing.T) {
			cfg := build(c)

			var (
				static  validation.Result
				struct_ config.ValidationResult
			)

			assertNoPanic(t, "validation.Static", func() { static = validation.Static(cfg) })
			assertNoPanic(t, "config.Validate", func() { struct_ = cfg.Validate() })

			if c.want.invalid && static.Valid {
				t.Errorf("expected an invalid configuration, got a valid one\nnote: %s", c.note)
			}
			if !c.want.invalid && !static.Valid {
				t.Errorf("expected a valid configuration, got errors: %v\nnote: %s", static.Errors(), c.note)
			}

			if c.want.field != "" {
				if !hasError(static, c.want.field) {
					t.Errorf("expected an error on %s, got %v\nnote: %s",
						c.want.field, static.Errors(), c.note)
				}
				if !hasField(struct_, c.want.field, config.SeverityError) {
					t.Errorf("config.Validate did not agree on %s; it produced %v\nnote: %s",
						c.want.field, struct_.Findings, c.note)
				}
			}

			// The property the layering exists to guarantee.
			if static.Valid != !struct_.HasErrors() {
				t.Errorf("the layers disagree about validity: validation=%v config=%v\nnote: %s",
					static.Valid, struct_.HasErrors(), c.note)
			}
		})
	}
}

// TestTheTwoLayersNeverDisagreeAboutValidity is the cross-layer invariant on
// its own, stated without the rest of the matrix so a failure names itself.
//
// internal/validation.Static is built by running config.Validate and then adding
// findings, so it cannot report a configuration valid that the lower layer
// rejected. If this ever fails, the layering has been broken and one of the two
// paths the CLI can take is lying.
func TestTheTwoLayersNeverDisagreeAboutValidity(t *testing.T) {
	for _, c := range matrix {
		cfg := build(c)

		assertNoPanic(t, "comparison for "+c.name, func() {
			lower := cfg.Validate()
			upper := validation.Static(cfg)

			if upper.Valid == lower.HasErrors() {
				t.Errorf("%s: validation.Static.Valid=%v but config.Validate.HasErrors()=%v",
					c.name, upper.Valid, lower.HasErrors())
			}
		})
	}
}

// TestNarrowPrefixesWarnRatherThanError records the policy boundary.
//
// A /32 LAN is one address and is not a usable network, but refusing it would
// be inventing a requirement the project does not have. It warns, in both
// layers, and stays valid.
func TestNarrowPrefixesWarnRatherThanError(t *testing.T) {
	for _, prefix := range []string{"10.77.0.1/30", "10.77.0.1/31", "10.77.0.1/32"} {
		t.Run(prefix, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Network.LANPrefix = prefix
			_ = cfg.Normalize()

			res := validation.Static(cfg)

			if !res.Valid {
				t.Errorf("%s made the configuration invalid: %v", prefix, res.Errors())
			}
			if !hasFinding(res, "network.lan_prefix", validation.SeverityWarning) {
				t.Errorf("%s did not warn about the number of usable addresses: %v", prefix, res.Warnings())
			}
		})
	}
}

// TestIPv6IsNeverJudgedTooNarrow is the regression guard for the negative
// shift, stated as behaviour rather than as "does not panic".
//
// The narrowness rule counts IPv4 host addresses. Applied to IPv6 it either
// panics on the shift or reports every /64 as impossibly small. Either way the
// operator is told their perfectly ordinary IPv6 LAN is broken.
func TestIPv6IsNeverJudgedTooNarrow(t *testing.T) {
	for _, prefix := range []string{
		"fd00::1/48", "fd00::1/56", "fd00::1/64", "fd00::1/96", "fd00::1/112", "fd00::1/120",
	} {
		t.Run(prefix, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Network.LANPrefix = prefix
			_ = cfg.Normalize()

			assertNoPanic(t, "validation of "+prefix, func() {
				res := validation.Static(cfg)

				if !res.Valid {
					t.Errorf("%s made the configuration invalid: %v", prefix, res.Errors())
				}
				for _, f := range res.Warnings() {
					if f.Field == "network.lan_prefix" &&
						strings.Contains(f.Message, "usable host") {
						t.Errorf("%s was reported as having too few usable host addresses: %s",
							prefix, f.Message)
					}
				}
			})
		})
	}
}

// TestAnEmptyLANPrefixStaysPending is the "invalid versus incomplete" line.
//
// Turning a legitimate development state into an error would make an operator
// unable to run `thn validate` on a gateway whose downstream NIC has not been
// chosen. It must be reported, and reported as a warning.
func TestAnEmptyLANPrefixStaysPending(t *testing.T) {
	for _, lan := range []string{"", "enx001122334455"} {
		t.Run("lan="+lan, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Network.LANPrefix = ""
			cfg.Network.LAN = lan
			_ = cfg.Normalize()

			assertNoPanic(t, "validation with no LAN prefix", func() {
				res := validation.Static(cfg)

				if !res.Valid {
					t.Errorf("an absent LAN address must not be an error: %v", res.Errors())
				}
				if !hasFinding(res, "network.lan_prefix", validation.SeverityWarning) {
					t.Errorf("an absent LAN address must still be reported: %v", res.Warnings())
				}
			})
		})
	}
}

// ------------------------------------------------------- panic-freedom

// TestValidationNeverPanicsOnHostileInput is the blanket guarantee.
//
// Deliberately nasty rather than merely invalid: the point is not that these
// are rejected, it is that the validator returns a verdict for every one of
// them instead of unwinding the stack.
func TestValidationNeverPanicsOnHostileInput(t *testing.T) {
	hostile := []string{
		"", " ", "/", "//", "///", ":", "::", ":::", "::::",
		"0", "0.0", "0.0.0", "0.0.0.0", "0.0.0.0/0",
		"255.255.255.255", "255.255.255.255/32", "256", "256.256.256.256/24",
		"1.2.3.4/-0", "1.2.3.4/+24", "1.2.3.4/024", "1.2.3.4/ 24", "1.2.3.4/24 ",
		"1.2.3.4/999999999999999999999", "1.2.3.4/0x18",
		"fd00::/0", "fd00::/1", "fd00::/128", "fd00::/129", "fd00::/256",
		"::/0", "::1/0", "::ffff:0:0/0", "::ffff:10.77.0.1/128",
		"fe80::1%eth0/64", "fe80::1%eth0",
		"10.77.0.1-10.77.0.5/24", "10.77.0.1,10.77.0.2/24",
		"10.77.0.1/24/24", "10.77.0.1//24", "10.77.0.1/24\n",
		"\n10.77.0.1/24", "\t10.77.0.1/24", "10.77.0.1 /24", "10.77.0.1/ 24",
		strings.Repeat("1", 4096), strings.Repeat("1.", 2048),
		strings.Repeat("f", 4096) + "::1/64",
		strings.Repeat("0", 200) + "::1/64",
		"0.0.0.0/0", "::/0", "224.0.0.0/4", "ff00::/8", "127.0.0.1/8",
		"169.254.0.1/16", "100.64.0.1/10", "192.0.2.1/24", "198.51.100.1/24",
	}

	for _, prefix := range hostile {
		t.Run(safeName(prefix), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Network.LANPrefix = prefix
			cfg.Network.UpstreamGateway = prefix

			assertNoPanic(t, "hostile input "+safeName(prefix), func() {
				_ = cfg.Normalize()
				res := validation.Static(cfg)

				// A verdict, not a crash. Whether it is valid or not is the
				// matrix's business, not this test's.
				if res.Valid && res.ErrorCount > 0 {
					t.Errorf("the result contradicts itself: Valid with %d errors", res.ErrorCount)
				}
				if !res.Valid && res.ErrorCount == 0 {
					t.Errorf("the result contradicts itself: invalid with no errors")
				}
			})
		})
	}
}

// TestValidationNeverPanicsOnMalformedDocuments goes through the loader, so
// YAML parsing is inside the guarantee as well as the rules.
func TestValidationNeverPanicsOnMalformedDocuments(t *testing.T) {
	dir := t.TempDir()

	documents := map[string]string{
		"empty":                "",
		"only whitespace":      "   \n\t\n",
		"unclosed list":        "network:\n  wan: [unclosed\n",
		"tab indentation":      "network:\n\twan: eth0\n",
		"duplicate keys":       "network:\n  wan: a\nnetwork:\n  wan: b\n",
		"wrong types":          "network:\n  wan: [1,2,3]\n  mtu: \"not a number\"\n",
		"unknown key":          "network:\n  wn: typo\n",
		"scalar for mapping":   "network: just-a-string\n",
		"null network":         "network: null\n",
		"nested nonsense":      "network:\n  lan_prefix:\n    deep:\n      deeper: [[[\n",
		"binary garbage":       "\x00\x01\x02\x03\xff\xfe\n",
		"very long scalar":     "network:\n  wan: " + strings.Repeat("x", 100000) + "\n",
		"many list entries":    "network:\n  dns:\n" + strings.Repeat("    - 1.1.1.1\n", 5000),
		"leading document sep": "---\nnetwork:\n  wan: eth0\n",
		"two documents":        "network:\n  wan: a\n---\nnetwork:\n  wan: b\n",
	}

	for name, body := range documents {
		t.Run(name, func(t *testing.T) {
			path := dir + "/" + name + ".yaml"
			if err := writeFile(path, body); err != nil {
				t.Fatal(err)
			}

			assertNoPanic(t, "loading and validating "+name, func() {
				cfg, err := config.Load(path)
				if err != nil {
					// Rejecting a malformed document is the correct outcome;
					// the guarantee is only that it arrives here.
					return
				}
				_ = validation.Static(cfg)
			})
		})
	}
}

// --------------------------------------------------------- the fuzz test

// FuzzValidationNeverPanics is the property test for the same guarantee.
//
// The matrix and the hostile list are inputs someone chose. This one is not:
// anything at all can be written into a LAN prefix or a gateway, and none of it
// may take the process down. Seeds carry the cases that have bitten before, so
// a regression is found without waiting for the fuzzer to rediscover it.
func FuzzValidationNeverPanics(f *testing.F) {
	seeds := []string{
		"10.77.0.1/24", "10.77.0.1/32", "10.77.0.1/33", "fd00::1/64",
		"fd00::1/128", "fd00::1/129", "::/0", "0.0.0.0/0", "127.0.0.1/8",
		"224.0.0.0/4", "169.254.0.1/16", "::ffff:10.77.0.1/120", "",
		"fe80::1%eth0/64", "10.77.0.1/-1", "/", "::", "1.2.3.4/999999",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, prefix string) {
		cfg := config.Defaults()
		cfg.Network.LANPrefix = prefix
		cfg.Network.UpstreamGateway = prefix
		_ = cfg.Normalize()

		// The invariant under test: a verdict, never a crash.
		_ = validation.Static(cfg)

		// And the result must be internally coherent, since a validator that
		// reports "invalid" with no errors has failed just as hard as one that
		// crashed.
		res := validation.Static(cfg)
		if res.Valid != (res.ErrorCount == 0) {
			t.Fatalf("incoherent result for %q: Valid=%v ErrorCount=%d",
				prefix, res.Valid, res.ErrorCount)
		}
	})
}

// ---------------------------------------------------------------- helpers

func hasError(r validation.Result, field string) bool {
	for _, f := range r.Findings {
		if f.Field == field && f.Severity == validation.SeverityError {
			return true
		}
	}
	return false
}

func hasFinding(r validation.Result, field string, sev validation.Severity) bool {
	for _, f := range r.Findings {
		if f.Field == field && f.Severity == sev {
			return true
		}
	}
	return false
}

func hasField(v config.ValidationResult, field string, sev config.Severity) bool {
	for _, f := range v.Findings {
		if f.Field == field && f.Severity == sev {
			return true
		}
	}
	return false
}

// safeName keeps a subtest name usable for pathological inputs.
func safeName(s string) string {
	if s == "" {
		return "empty"
	}
	if len(s) > 32 {
		s = s[:32]
	}

	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '/' || r == '\\':
			b.WriteByte('_')
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteByte('_')
		case r < 0x20 || r == 0x7f:
			b.WriteByte('.')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
