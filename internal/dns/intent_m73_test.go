package dns

// Acceptance tests for M7.3 — DNS intent.
//
// internal/dns/model_test.go already covers the policy validator. This file
// tests what is NEW: the intent model, the separation between "run a resolver"
// and "forward to an upstream", and the upstream source precedence rule that
// M3/M4 established and M7.3 must not regress.

import (
	"net/netip"
	"testing"
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

// goodPolicy is a coherent DNS policy for the given LAN.
func goodPolicy() Policy {
	p, _ := netip.ParsePrefix("10.77.0.1/24")
	return Policy{
		Enabled:              true,
		Interface:            "enx00e099001812",
		ListenAddress:        p.Addr(),
		Upstream:             []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9")},
		LocalDomain:          "lan",
		RejectUnmappedBlocks: true,
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

// TestIntentDNSDisabled: declining a DNS service is valid, not broken.
func TestIntentDNSDisabled(t *testing.T) {
	p := Policy{Enabled: false}
	rep := ValidateIntent(FromPolicy(p, LANRole{}, ResolveUpstream(nil, nil)))

	if rep.Verdict != VerdictValid {
		t.Errorf("verdict = %s, want VALID: declining DNS is a decision, not an error", rep.Verdict)
	}
	if !hasCode(rep, CodeDisabled) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeDisabled)
	}
	// A disabled service must not demand a LAN or an upstream.
	if hasCode(rep, CodeLANMissing) || hasCode(rep, CodeUpstreamMissing) {
		t.Errorf("a disabled DNS must not demand dependencies; findings = %v", intentCodes(rep))
	}
}

// TestIntentValidIPv4Upstreams: the ordinary case validates.
func TestIntentValidIPv4Upstreams(t *testing.T) {
	dec := ResolveUpstream([]string{"1.1.1.1", "9.9.9.9"}, nil)
	rep := ValidateIntent(FromPolicy(goodPolicy(), resolvedLAN("10.77.0.1/24"), dec))

	if rep.Verdict != VerdictValid {
		t.Errorf("verdict = %s, want VALID; findings = %v", rep.Verdict, intentCodes(rep))
	}
}

// TestIntentValidIPv6Upstreams: IPv6 resolvers are allowed.
//
// The milestone says DNS should support IPv6 upstreams if the configuration
// model permits them. It does — the field is a list of address strings.
func TestIntentValidIPv6Upstreams(t *testing.T) {
	p := goodPolicy()
	p.Upstream = []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}

	dec := ResolveUpstream([]string{"2606:4700:4700::1111"}, nil)
	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24"), dec))

	if rep.Verdict != VerdictValid {
		t.Errorf("verdict = %s, want VALID for an IPv6 upstream; findings = %v", rep.Verdict, intentCodes(rep))
	}
}

// TestIntentNoUpstreamDeclared: an empty list is a blocking finding, and the
// milestone forbids silently defaulting one.
func TestIntentNoUpstreamDeclared(t *testing.T) {
	p := goodPolicy()
	p.Upstream = nil

	dec := ResolveUpstream(nil, nil)
	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24"), dec))

	if rep.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want BLOCKED: DNS with no resolver answers nothing", rep.Verdict)
	}
	if !hasCode(rep, CodeUpstreamMissing) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeUpstreamMissing)
	}
	// Nothing was invented to fill the gap.
	if len(dec.List) != 0 {
		t.Errorf("ResolveUpstream invented resolvers: %v", dec.List)
	}
}

// TestIntentInvalidUpstream: a resolver that cannot be one.
func TestIntentInvalidUpstream(t *testing.T) {
	p := goodPolicy()
	p.Upstream = []netip.Addr{netip.Addr{}}

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24"),
		ResolveUpstream([]string{"1.1.1.1"}, nil)))

	if !hasCode(rep, CodeUpstreamInvalid) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeUpstreamInvalid)
	}
}

// TestIntentDuplicateUpstream: the same resolver listed twice is a warning.
func TestIntentDuplicateUpstream(t *testing.T) {
	p := goodPolicy()
	p.Upstream = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.1.1.1")}

	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24"),
		ResolveUpstream([]string{"1.1.1.1", "1.1.1.1"}, nil)))

	if !hasCode(rep, CodeUpstreamDuplicate) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeUpstreamDuplicate)
	}
	// A duplicate is a typo, not a broken network: it must not block.
	if rep.Verdict == VerdictBlocked {
		t.Errorf("a duplicate resolver must not block; verdict = %s", rep.Verdict)
	}
}

// TestUpstreamPrecedenceCanonicalOnly: dns.upstream alone is used.
func TestUpstreamPrecedenceCanonicalOnly(t *testing.T) {
	d := ResolveUpstream([]string{"1.1.1.1", "9.9.9.9"}, nil)

	if d.Source != SourceCanonical {
		t.Errorf("source = %q, want %q", d.Source, SourceCanonical)
	}
	if len(d.List) != 2 {
		t.Errorf("list = %v, want the two dns.upstream entries", d.List)
	}
	if d.Conflict {
		t.Error("conflict must not be reported when only one field was declared")
	}
}

// TestUpstreamPrecedenceFallbackOnly: network.dns alone is the fallback.
func TestUpstreamPrecedenceFallbackOnly(t *testing.T) {
	d := ResolveUpstream(nil, []string{"8.8.8.8"})

	if d.Source != SourceFallback {
		t.Errorf("source = %q, want %q", d.Source, SourceFallback)
	}
	if len(d.List) != 1 || d.List[0] != "8.8.8.8" {
		t.Errorf("list = %v, want [8.8.8.8]", d.List)
	}
	if d.Conflict {
		t.Error("conflict must not be reported when only one field was declared")
	}
}

// TestUpstreamPrecedenceBothEqual: equal values are accepted, not a conflict.
//
// This is the milestone's "equal values should not create false conflicts".
func TestUpstreamPrecedenceBothEqual(t *testing.T) {
	d := ResolveUpstream([]string{"1.1.1.1"}, []string{"1.1.1.1"})

	if d.Conflict {
		t.Error("identical resolver lists must not conflict")
	}
	if !d.Agree {
		t.Error("identical resolver lists must be reported as agreeing")
	}
	if !d.BothDeclared {
		t.Error("bothDeclared must be true when both fields are set")
	}
	// Order is not significant.
	d2 := ResolveUpstream([]string{"1.1.1.1", "9.9.9.9"}, []string{"9.9.9.9", "1.1.1.1"})
	if d2.Conflict {
		t.Error("resolver order must not be treated as disagreement")
	}
}

// TestUpstreamPrecedenceBothDiffer: differing values are a structured conflict.
func TestUpstreamPrecedenceBothDiffer(t *testing.T) {
	d := ResolveUpstream([]string{"1.1.1.1"}, []string{"8.8.8.8"})

	if !d.Conflict {
		t.Error("differing resolver lists must conflict")
	}
	if d.Agree {
		t.Error("differing resolver lists must not be reported as agreeing")
	}

	rep := ValidateIntent(FromPolicy(goodPolicy(), resolvedLAN("10.77.0.1/24"), d))

	if rep.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want BLOCKED: a document that disagrees with itself has no answer", rep.Verdict)
	}
	if !hasCode(rep, CodeUpstreamConflict) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeUpstreamConflict)
	}
}

// TestUpstreamPrecedenceNeither: nothing is invented when nothing is declared.
func TestUpstreamPrecedenceNeither(t *testing.T) {
	d := ResolveUpstream(nil, nil)

	if d.Source != "" {
		t.Errorf("source = %q, want empty when neither field is declared", d.Source)
	}
	if len(d.List) != 0 {
		t.Errorf("list = %v, want empty: THN must not invent a resolver", d.List)
	}
	if d.BothDeclared || d.Conflict || d.Agree {
		t.Errorf("neither declared must not be both/agree/conflict: %+v", d)
	}
}

// TestIntentServiceIsSeparateFromUpstream: running a resolver and forwarding
// to one are different decisions.
//
// The milestone is explicit that these must not be conflated, and this is the
// assertion that they are not: an intent can want the service without
// upstreams, or upstreams without the service.
func TestIntentServiceIsSeparateFromUpstream(t *testing.T) {
	// Upstreams declared, service off.
	pOff := goodPolicy()
	pOff.Enabled = false

	off := FromPolicy(pOff, resolvedLAN("10.77.0.1/24"),
		ResolveUpstream([]string{"1.1.1.1"}, nil))
	if off.Enabled {
		t.Error("service must be off when the document turned it off")
	}
	if len(off.Upstream) == 0 {
		t.Error("upstreams must still be readable when the service is off")
	}
	if rep := ValidateIntent(off); rep.Verdict != VerdictValid {
		t.Errorf("a disabled service with upstreams must be valid; got %s (%v)", rep.Verdict, intentCodes(rep))
	}

	// Service on, no upstreams.
	pOn := goodPolicy()
	pOn.Upstream = nil

	on := FromPolicy(pOn, resolvedLAN("10.77.0.1/24"), ResolveUpstream(nil, nil))
	if !on.Enabled {
		t.Error("service must be on when the document turned it on")
	}
	if len(on.Upstream) != 0 {
		t.Errorf("no upstream was declared, so none may appear: %v", on.Upstream)
	}
}

// TestIntentMissingLAN: DNS with no LAN cannot be served.
func TestIntentMissingLAN(t *testing.T) {
	rep := ValidateIntent(FromPolicy(goodPolicy(), LANRole{},
		ResolveUpstream([]string{"1.1.1.1"}, nil)))

	if rep.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want BLOCKED: DNS with no LAN cannot be served", rep.Verdict)
	}
	if !hasCode(rep, CodeLANMissing) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeLANMissing)
	}
	// The dependency edge: no LAN means there is nowhere to listen, so the
	// resolver list must not be reported as the problem.
	if hasCode(rep, CodeUpstreamMissing) {
		t.Errorf("with no LAN the resolvers cannot be judged; findings = %v", intentCodes(rep))
	}
}

// TestIntentUnresolvedLAN: a named but unattached LAN is pending.
func TestIntentUnresolvedLAN(t *testing.T) {
	lan := resolvedLAN("10.77.0.1/24")
	lan.Resolved = false
	lan.Interface = ""
	lan.StableID = ""

	rep := ValidateIntent(FromPolicy(goodPolicy(), lan,
		ResolveUpstream([]string{"1.1.1.1"}, nil)))

	if rep.Verdict != VerdictPending {
		t.Errorf("verdict = %s, want PENDING: an unattached LAN is incomplete, not malformed", rep.Verdict)
	}
	if !hasCode(rep, CodeLANUnresolved) {
		t.Errorf("findings = %v, want %s", intentCodes(rep), CodeLANUnresolved)
	}
}

// TestIntentListenAddressFromLAN: the listen address derives from the LAN.
func TestIntentListenAddressFromLAN(t *testing.T) {
	in := FromPolicy(goodPolicy(), resolvedLAN("10.77.0.1/24"),
		ResolveUpstream([]string{"1.1.1.1"}, nil))

	if in.Listen() != "10.77.0.1" {
		t.Errorf("listen = %q, want 10.77.0.1 (the declared LAN address)", in.Listen())
	}

	// No LAN address means no claim about where it would listen.
	none := FromPolicy(goodPolicy(), resolvedLAN(""),
		ResolveUpstream([]string{"1.1.1.1"}, nil))
	if none.Listen() != "" {
		t.Errorf("listen = %q, want empty when there is no LAN address", none.Listen())
	}
}

// TestIntentConflictBlocksUpstreamChoice: a conflicted document records no
// upstream, rather than silently picking one.
func TestIntentConflictBlocksUpstreamChoice(t *testing.T) {
	d := ResolveUpstream([]string{"1.1.1.1"}, []string{"8.8.8.8"})
	in := FromPolicy(goodPolicy(), resolvedLAN("10.77.0.1/24"), d)

	if in.UpstreamConflict == nil {
		t.Fatal("the intent must carry the conflict as data, not resolve it")
	}
	if len(in.UpstreamConflict.Canonical) != 1 || in.UpstreamConflict.Canonical[0] != "1.1.1.1" {
		t.Errorf("canonical = %v, want [1.1.1.1]", in.UpstreamConflict.Canonical)
	}
	if len(in.UpstreamConflict.Fallback) != 1 || in.UpstreamConflict.Fallback[0] != "8.8.8.8" {
		t.Errorf("fallback = %v, want [8.8.8.8]", in.UpstreamConflict.Fallback)
	}
}

// TestIntentDeterministicReport: the same intent always yields the same report.
func TestIntentDeterministicReport(t *testing.T) {
	p := goodPolicy()
	d := ResolveUpstream([]string{"1.1.1.1", "9.9.9.9"}, nil)

	first := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24"), d))
	for i := 0; i < 8; i++ {
		got := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24"), d))

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
	d := ResolveUpstream([]string{"1.1.1.1"}, nil)
	in := FromPolicy(goodPolicy(), resolvedLAN("10.77.0.1/24"), d)

	before := in
	_ = ValidateIntent(in)

	if in.Enabled != before.Enabled ||
		len(in.Upstream) != len(before.Upstream) ||
		in.ListenAddress != before.ListenAddress ||
		in.UpstreamSource != before.UpstreamSource {
		t.Errorf("ValidateIntent mutated its input:\n before %+v\n after  %+v", before, in)
	}
}

// TestIntentOffline: validation resolves nothing and queries nothing.
//
// A CI job with no network must reach the same verdict as one on the gateway,
// so this layer is structurally incapable of asking about reachability.
func TestIntentOffline(t *testing.T) {
	// A resolver that certainly does not resolve. If any part of validation
	// performed a lookup, the run would be slow, flaky or fail.
	p := goodPolicy()
	p.Upstream = []netip.Addr{netip.MustParseAddr("192.0.2.222")} // TEST-NET-1

	dec := ResolveUpstream([]string{"192.0.2.222"}, nil)
	rep := ValidateIntent(FromPolicy(p, resolvedLAN("10.77.0.1/24"), dec))

	if rep.Verdict == VerdictBlocked {
		t.Errorf("an unreachable resolver must not block: reachability is not this layer's question; findings = %v",
			intentCodes(rep))
	}
}
