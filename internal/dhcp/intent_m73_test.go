package dhcp

// Acceptance tests for M7.3 — DHCP intent.
//
// The range arithmetic itself is already covered exhaustively by
// range_matrix_test.go and arithmetic_test.go. This file is not a second copy
// of that coverage. It tests what is NEW in M7.3 and nothing else: the intent
// model, its attachment to the logical LAN role, the dependency ordering, and
// determinism.
//
// Where a row here touches the pool, it is to prove the intent layer inherits
// the existing rules rather than reimplementing them.

import (
	"net/netip"
	"testing"
	"time"
)

// resolvedLAN builds a resolved LAN role for a given prefix.
func resolvedLAN(prefix string) LANRole {
	return LANRole{
		Selector:  "hw:2c88",
		Declared:  true,
		Resolved:  true,
		Interface: "enx00e099001812",
		StableID:  "hw:2c88",
		Prefix:    prefix,
	}
}

// goodPolicy is a coherent DHCP policy for the given LAN.
func goodPolicy(prefix string) Policy {
	p, _ := netip.ParsePrefix(prefix)
	return Policy{
		Enabled:        true,
		Interface:      "enx00e099001812",
		LANPrefix:      p,
		Authoritative:  true,
		LeaseTime:      12 * time.Hour,
		Domain:         "lan",
		GatewayAddress: p.Addr(),
		Ranges: []Range{{
			Start: netip.MustParseAddr("10.77.0.100"),
			End:   netip.MustParseAddr("10.77.0.250"),
		}},
	}
}

// intentCodes returns the finding codes in a report, in order.
func intentCodes(r Report) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

// hasCode reports whether a report carries a code.
func hasCode(r Report, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// TestIntentDHCPDisabled: a document that declines DHCP is valid, not broken.
func TestIntentDHCPDisabled(t *testing.T) {
	in := FromPolicy(Policy{Enabled: false}, LANRole{})
	rep := ValidateIntent(in)

	if rep.Verdict != VerdictValid {
		t.Errorf("verdict = %s, want VALID: declining DHCP is a decision, not an error", rep.Verdict)
	}
	if !hasCode(rep, CodeDisabled) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeDisabled)
	}
	// The absent LAN must not be reported: the operator was not asked for one.
	if hasCode(rep, CodeLANMissing) {
		t.Errorf("a disabled DHCP must not demand a LAN; findings = %v", intentCodes(rep))
	}
}

// TestIntentValidPool: the ordinary case validates.
func TestIntentValidPool(t *testing.T) {
	in := FromPolicy(goodPolicy("10.77.0.1/24"), resolvedLAN("10.77.0.1/24"))
	rep := ValidateIntent(in)

	if rep.Verdict != VerdictValid {
		t.Errorf("verdict = %s, want VALID; findings = %v", rep.Verdict, intentCodes(rep))
	}
	if len(rep.Blocking()) != 0 {
		t.Errorf("a valid configuration must not block: %v", intentCodes(rep))
	}
}

// TestIntentMissingLAN: DHCP was asked for with no LAN at all.
func TestIntentMissingLAN(t *testing.T) {
	rep := ValidateIntent(FromPolicy(goodPolicy("10.77.0.1/24"), LANRole{}))

	if rep.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want BLOCKED: DHCP with no LAN cannot be built", rep.Verdict)
	}
	if !hasCode(rep, CodeLANMissing) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeLANMissing)
	}
	// The dependency edge: with no LAN the pool cannot be judged at all, so
	// the pool must NOT be reported as the problem.
	if hasCode(rep, CodeRangeOutsideLAN) {
		t.Errorf("with no LAN the pool cannot be judged; findings = %v", intentCodes(rep))
	}
}

// TestIntentUnresolvedLAN: a named but unattached LAN is pending, not blocked.
//
// This is the distinction M7.2 established for roles, preserved here for DHCP:
// unresolved means the cable is not plugged in, which more configuration will
// not fix.
func TestIntentUnresolvedLAN(t *testing.T) {
	lan := resolvedLAN("10.77.0.1/24")
	lan.Resolved = false
	lan.Interface = ""
	lan.StableID = ""

	rep := ValidateIntent(FromPolicy(goodPolicy("10.77.0.1/24"), lan))

	if rep.Verdict != VerdictPending {
		t.Errorf("verdict = %s, want PENDING: an unattached LAN is incomplete, not malformed", rep.Verdict)
	}
	if !hasCode(rep, CodeLANUnresolved) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeLANUnresolved)
	}
	if hasCode(rep, CodeLANMissing) {
		t.Errorf("a named LAN is not a missing LAN; findings = %v", intentCodes(rep))
	}
}

// TestIntentLANWithoutAddress: a LAN role with no address cannot host a pool.
func TestIntentLANWithoutAddress(t *testing.T) {
	rep := ValidateIntent(FromPolicy(goodPolicy("10.77.0.1/24"), resolvedLAN("")))

	if rep.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want BLOCKED: there is no subnet a pool could belong to", rep.Verdict)
	}
	if !hasCode(rep, CodeLANAddressMissing) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeLANAddressMissing)
	}
}

// TestIntentMissingRanges: DHCP on with no pool.
func TestIntentMissingRanges(t *testing.T) {
	p := goodPolicy("10.77.0.1/24")
	p.Ranges = nil

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))

	if !hasCode(rep, CodeRangeMissing) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeRangeMissing)
	}
}

// TestIntentReversedRange: start above end.
func TestIntentReversedRange(t *testing.T) {
	p := goodPolicy("10.77.0.1/24")
	p.Ranges = []Range{{
		Start: netip.MustParseAddr("10.77.0.250"),
		End:   netip.MustParseAddr("10.77.0.100"),
	}}

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))

	if rep.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want BLOCKED", rep.Verdict)
	}
	if !hasCode(rep, CodeRangeReversed) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeRangeReversed)
	}
}

// TestIntentInvalidRangeBounds: a bound that is not an address.
func TestIntentInvalidRangeBounds(t *testing.T) {
	p := goodPolicy("10.77.0.1/24")
	p.Ranges = []Range{{
		Start: netip.Addr{},
		End:   netip.MustParseAddr("10.77.0.250"),
	}}

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))

	if !hasCode(rep, CodeRangeInvalid) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeRangeInvalid)
	}
}

// TestIntentPoolOutsideLAN: the milestone's worked example, rejected.
//
//	LAN:  10.77.0.1/24
//	DHCP: 10.88.0.100 - 10.88.0.250
func TestIntentPoolOutsideLAN(t *testing.T) {
	p := goodPolicy("10.77.0.1/24")
	p.Ranges = []Range{{
		Start: netip.MustParseAddr("10.88.0.100"),
		End:   netip.MustParseAddr("10.88.0.250"),
	}}

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))

	if rep.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want BLOCKED: a pool on another network is unroutable", rep.Verdict)
	}
	if !hasCode(rep, CodeRangeOutsideLAN) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeRangeOutsideLAN)
	}
}

// TestIntentPoolCrossesSubnetBoundary: the start is inside, the end is not.
//
// This is the defect that used to pass a start-only check, and it is why both
// endpoints are verified rather than only the lower one.
func TestIntentPoolCrossesSubnetBoundary(t *testing.T) {
	p := goodPolicy("10.77.0.1/24")
	p.Ranges = []Range{{
		Start: netip.MustParseAddr("10.77.0.250"),
		End:   netip.MustParseAddr("10.78.0.10"),
	}}

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))

	if !hasCode(rep, CodeRangeOutsideLAN) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeRangeOutsideLAN)
	}
}

// TestIntentPoolIncludesGateway: a pool containing the gateway's own address.
func TestIntentPoolIncludesGateway(t *testing.T) {
	p := goodPolicy("10.77.0.1/24")
	p.Ranges = []Range{{
		Start: netip.MustParseAddr("10.77.0.1"),
		End:   netip.MustParseAddr("10.77.0.250"),
	}}

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))

	if !hasCode(rep, CodeRangeIncludesGateway) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeRangeIncludesGateway)
	}
}

// TestIntentSingleAddressPool: start == end is a one-address pool.
//
// The milestone asks this be accepted if the existing model allows it, and the
// existing model does: validateRanges rejects only start > end.
func TestIntentSingleAddressPool(t *testing.T) {
	p := goodPolicy("10.77.0.1/24")
	p.Ranges = []Range{{
		Start: netip.MustParseAddr("10.77.0.200"),
		End:   netip.MustParseAddr("10.77.0.200"),
	}}

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))

	if hasCode(rep, CodeRangeReversed) {
		t.Errorf("a one-address pool must not be reported as reversed; findings = %v", intentCodes(rep))
	}
	if rep.Verdict == VerdictBlocked {
		t.Errorf("a one-address pool inside the LAN must not block; findings = %v", intentCodes(rep))
	}
}

// TestIntentNonSlash24LAN: subnet correctness must use CIDR semantics.
//
// The milestone names this explicitly: /8, /16, /25, /26, /27 and /28 must all
// work and /24 must not be hard-coded.
func TestIntentNonSlash24LAN(t *testing.T) {
	cases := []struct {
		lan       string
		start     string
		end       string
		wantValid bool
		note      string
	}{
		{"10.77.0.1/8", "10.77.0.100", "10.77.0.250", true, "/8 LAN"},
		{"172.16.5.1/16", "172.16.5.100", "172.16.5.250", true, "/16 LAN"},
		{"192.168.1.1/24", "192.168.1.100", "192.168.1.250", true, "/24 LAN"},
		{"192.168.1.1/25", "192.168.1.100", "192.168.1.120", true, "/25 LAN, pool in the lower half"},
		{"192.168.1.129/26", "192.168.1.130", "192.168.1.190", true, "/26 LAN"},
		{"192.168.1.193/27", "192.168.1.194", "192.168.1.220", true, "/27 LAN"},
		{"192.168.1.225/28", "192.168.1.226", "192.168.1.238", true, "/28 LAN"},
		{"192.168.1.1/25", "192.168.1.130", "192.168.1.200", false, "pool starts outside a /25"},
		{"10.77.0.1/8", "192.168.1.100", "192.168.1.250", false, "pool outside a /8"},
	}

	for _, c := range cases {
		t.Run(c.note, func(t *testing.T) {
			p, err := netip.ParsePrefix(c.lan)
			if err != nil {
				t.Fatalf("bad test LAN %q: %v", c.lan, err)
			}

			pol := Policy{
				Enabled:        true,
				Interface:      "enx00e099001812",
				LANPrefix:      p,
				LeaseTime:      12 * time.Hour,
				GatewayAddress: p.Addr(),
				Ranges: []Range{{
					Start: netip.MustParseAddr(c.start),
					End:   netip.MustParseAddr(c.end),
				}},
			}

			rep := ValidateIntent(FromPolicy(pol, resolvedLAN(c.lan)))

			gotValid := !hasCode(rep, CodeRangeOutsideLAN) && !hasCode(rep, CodeRangeIncludesGateway)
			if gotValid != c.wantValid {
				t.Errorf("%s with pool %s-%s: valid = %t, want %t; findings = %v",
					c.lan, c.start, c.end, gotValid, c.wantValid, intentCodes(rep))
			}
		})
	}
}

// TestIntentRouterDerivedFromLAN: the advertised router is the LAN address.
//
// The milestone forbids a second source of truth for the gateway's LAN
// address, so the intent derives it and never accepts it separately.
func TestIntentRouterDerivedFromLAN(t *testing.T) {
	in := FromPolicy(goodPolicy("10.77.0.1/24"), resolvedLAN("10.77.0.1/24"))

	if got := in.AdvertisedRouter(); got != "10.77.0.1" {
		t.Errorf("advertised router = %q, want 10.77.0.1 (the declared LAN address)", got)
	}
	if in.Gateway != netip.MustParseAddr("10.77.0.1") {
		t.Errorf("gateway = %v, want 10.77.0.1", in.Gateway)
	}
}

// TestIntentRouterAbsentWithoutLAN: no LAN address means no router claim.
func TestIntentRouterAbsentWithoutLAN(t *testing.T) {
	in := FromPolicy(goodPolicy("10.77.0.1/24"), resolvedLAN(""))

	if got := in.AdvertisedRouter(); got != "" {
		t.Errorf("advertised router = %q, want empty: no LAN address means nothing to advertise", got)
	}
}

// TestIntentStableLANIdentity: renaming the kernel interface must not change
// the intent.
//
// This is the milestone's central device-independence claim: the document
// names hw:�, and the kernel name is an observation about this machine now.
func TestIntentStableLANIdentity(t *testing.T) {
	before := resolvedLAN("10.77.0.1/24")

	// The same link, observed under a different kernel name.
	after := before
	after.Interface = "eno1"

	a := ValidateIntent(FromPolicy(goodPolicy("10.77.0.1/24"), before))
	b := ValidateIntent(FromPolicy(goodPolicy("10.77.0.1/24"), after))

	if a.Verdict != b.Verdict {
		t.Errorf("verdict changed with the kernel name: %s vs %s", a.Verdict, b.Verdict)
	}
	if len(a.Findings) != len(b.Findings) {
		t.Errorf("finding count changed with the kernel name: %d vs %d",
			len(a.Findings), len(b.Findings))
	}

	ia := FromPolicy(goodPolicy("10.77.0.1/24"), before)
	ib := FromPolicy(goodPolicy("10.77.0.1/24"), after)
	if ia.LAN.StableID != ib.LAN.StableID {
		t.Errorf("stable ID changed with the kernel name: %q vs %q", ia.LAN.StableID, ib.LAN.StableID)
	}
}

// TestIntentDeterministicReport: the same intent always yields the same report.
//
// Determinism is what makes a CI log diffable, so it is asserted rather than
// assumed.
func TestIntentDeterministicReport(t *testing.T) {
	p := goodPolicy("10.77.0.1/24")
	p.Ranges = []Range{
		{Start: netip.MustParseAddr("10.77.0.100"), End: netip.MustParseAddr("10.77.0.150")},
		{Start: netip.MustParseAddr("10.77.0.200"), End: netip.MustParseAddr("10.77.0.250")},
	}

	first := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))
	for i := 0; i < 8; i++ {
		got := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))

		if got.Verdict != first.Verdict {
			t.Fatalf("run %d: verdict = %s, want %s", i, got.Verdict, first.Verdict)
		}
		if len(got.Findings) != len(first.Findings) {
			t.Fatalf("run %d: %d findings, want %d", i, len(got.Findings), len(first.Findings))
		}
		for j := range got.Findings {
			if got.Findings[j] != first.Findings[j] {
				t.Fatalf("run %d, finding %d: %+v, want %+v", i, j, got.Findings[j], first.Findings[j])
			}
		}
	}
}

// TestIntentDoesNotMutateInput: validating must not rewrite the intent.
func TestIntentDoesNotMutateInput(t *testing.T) {
	in := FromPolicy(goodPolicy("10.77.0.1/24"), resolvedLAN("10.77.0.1/24"))

	before := in
	_ = ValidateIntent(in)

	if in.Enabled != before.Enabled ||
		len(in.Ranges) != len(before.Ranges) ||
		in.Gateway != before.Gateway ||
		in.LAN.Selector != before.LAN.Selector {
		t.Errorf("ValidateIntent mutated its input:\n before %+v\n after  %+v", before, in)
	}
}

// TestIntentReusesPolicyRules: the intent layer inherits, it does not
// reimplement.
//
// A duplicated implementation is how two layers reach different conclusions
// about the same pool. This asserts the policy's own finding reaches the
// intent report unchanged.
func TestIntentReusesPolicyRules(t *testing.T) {
	p := goodPolicy("10.77.0.1/24")
	p.Ranges = []Range{{
		Start: netip.MustParseAddr("10.88.0.100"),
		End:   netip.MustParseAddr("10.88.0.250"),
	}}

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24")))

	want := Validate(p)
	if len(want.Errors()) == 0 {
		t.Fatal("test setup: the policy validator found nothing to project")
	}

	found := false
	for _, f := range rep.Findings {
		for _, w := range want.Errors() {
			if f.Message == w.Message {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("intent report did not carry the policy's finding; got %v", intentCodes(rep))
	}
}

// TestIntentAdvertisedDNSIsDataNotService: DHCP advertising DNS does not
// create a DNS service.
//
// The milestone insists these stay separate concepts. Advertising an address
// to clients is a DHCP option; it does not mean this machine serves names.
func TestIntentAdvertisedDNSIsDataNotService(t *testing.T) {
	in := FromPolicy(goodPolicy("10.77.0.1/24"), resolvedLAN("10.77.0.1/24"))
	in.AdvertisedDNS = []netip.Addr{netip.MustParseAddr("10.77.0.1")}

	rep := ValidateIntent(in)

	if rep.Verdict != VerdictValid {
		t.Errorf("advertising a resolver must not affect the DHCP verdict; got %s, findings %v",
			rep.Verdict, intentCodes(rep))
	}
	if len(in.AdvertisedDNS) != 1 {
		t.Errorf("advertised DNS was dropped: %v", in.AdvertisedDNS)
	}
}
