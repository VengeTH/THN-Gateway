package dns

import (
	"net/netip"
	"testing"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// valid returns a policy that passes every check.
func valid() Policy {
	return Policy{
		Enabled:              true,
		Interface:            "enx001122334455",
		ListenAddress:        mustAddr("10.77.0.1"),
		Upstream:             []netip.Addr{mustAddr("1.1.1.1"), mustAddr("9.9.9.9")},
		LocalDomain:          "lan",
		CacheSize:            1000,
		RejectUnmappedBlocks: true,
	}
}

func hasError(r Result, field string) bool {
	for _, f := range r.Findings {
		if f.Field == field && f.Severity == SeverityError {
			return true
		}
	}
	return false
}

func hasFinding(r Result, field string, sev Severity) bool {
	for _, f := range r.Findings {
		if f.Field == field && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestValidPolicyPasses(t *testing.T) {
	r := Validate(valid())
	if !r.Valid {
		t.Errorf("a valid policy must pass, got: %v", r.Errors())
	}
}

// TestNoUpstreamIsError covers the most consequential mistake here: dnsmasq
// starts happily and answers nothing, so the LAN looks like it has a working
// network that cannot resolve anything.
func TestNoUpstreamIsError(t *testing.T) {
	p := valid()
	p.Upstream = nil

	r := Validate(p)

	if r.Valid {
		t.Fatal("a policy with no upstream must be rejected")
	}
	if !hasError(r, "upstream") {
		t.Errorf("expected an error on upstream, got %v", r.Errors())
	}
}

// TestLoopbackResolverIsError covers the forwarding loop that presents as
// every query timing out.
func TestLoopbackResolverIsError(t *testing.T) {
	p := valid()
	p.Upstream = []netip.Addr{mustAddr("127.0.0.1")}

	r := Validate(p)

	if !hasError(r, "upstream[0]") {
		t.Error("a loopback resolver would forward queries to itself")
	}
}

func TestUnspecifiedResolverIsError(t *testing.T) {
	p := valid()
	p.Upstream = []netip.Addr{mustAddr("0.0.0.0")}

	if !hasError(Validate(p), "upstream[0]") {
		t.Error("the unspecified address is not a resolver")
	}
}

func TestMulticastResolverIsError(t *testing.T) {
	p := valid()
	p.Upstream = []netip.Addr{mustAddr("224.0.0.1")}

	if !hasError(Validate(p), "upstream[0]") {
		t.Error("a multicast address is not a resolver")
	}
}

func TestPrivateResolverWarns(t *testing.T) {
	// A resolver on the LAN is a legitimate design (a Pi-hole), but it is
	// usually a typo when the gateway itself is meant to be the resolver.
	p := valid()
	p.Upstream = []netip.Addr{mustAddr("10.0.0.53")}

	r := Validate(p)

	if !r.Valid {
		t.Error("a private resolver is legal")
	}
	if !hasFinding(r, "upstream[0]", SeverityWarning) {
		t.Error("a private resolver must warn")
	}
}

func TestTinyCacheWarns(t *testing.T) {
	p := valid()
	p.CacheSize = 10

	if !hasFinding(Validate(p), "cache_size", SeverityWarning) {
		t.Error("a tiny cache misses constantly and should warn")
	}
}

func TestNegativeCacheIsError(t *testing.T) {
	p := valid()
	p.CacheSize = -1

	if !hasError(Validate(p), "cache_size") {
		t.Error("a negative cache size must be rejected")
	}
}

func TestRecordWithNoAddressIsError(t *testing.T) {
	p := valid()
	p.LocalRecords = []Record{{Hostname: "nas"}}

	if !hasError(Validate(p), "local_records[0].address") {
		t.Error("a record with no address must be rejected")
	}
}

func TestRecordPointingAtUnspecifiedIsError(t *testing.T) {
	// Answering with 0.0.0.0 is worse than not answering.
	p := valid()
	p.LocalRecords = []Record{{Hostname: "nas", Address: mustAddr("0.0.0.0")}}

	if !hasError(Validate(p), "local_records[0].address") {
		t.Error("a record pointing at the unspecified address must be rejected")
	}
}

func TestDuplicateRecordNameIsError(t *testing.T) {
	// A name may only resolve one way; two records means the answer depends on
	// file order.
	p := valid()
	p.LocalRecords = []Record{
		{Hostname: "nas", Address: mustAddr("10.77.0.10")},
		{Hostname: "nas", Address: mustAddr("10.77.0.11")},
	}

	if !hasError(Validate(p), "local_records[1].hostname") {
		t.Error("a duplicated name must be rejected")
	}
}

func TestInvalidHostnameIsError(t *testing.T) {
	cases := []string{"", "-leading", "trailing-", "has space", "has_underscore", "has.dot"}

	for _, h := range cases {
		p := valid()
		p.LocalRecords = []Record{{Hostname: h, Address: mustAddr("10.77.0.10")}}

		if !hasError(Validate(p), "local_records[0].hostname") {
			t.Errorf("hostname %q must be rejected", h)
		}
	}
}

func TestValidHostnameAccepted(t *testing.T) {
	for _, h := range []string{"nas", "my-nas", "nas01", "a"} {
		p := valid()
		p.LocalRecords = []Record{{Hostname: h, Address: mustAddr("10.77.0.10")}}

		if !Validate(p).Valid {
			t.Errorf("hostname %q must be accepted", h)
		}
	}
}

func TestQueryLoggingIsInformational(t *testing.T) {
	p := valid()
	p.LogQueries = true

	r := Validate(p)

	if !r.Valid {
		t.Error("query logging is a choice, not a fault")
	}
	if !hasFinding(r, "log_queries", SeverityInfo) {
		t.Error("continuous disk writes must be flagged")
	}
}

func TestDisabledDNSIsInformational(t *testing.T) {
	p := valid()
	p.Enabled = false
	p.Upstream = nil

	r := Validate(p)

	if !r.Valid {
		t.Error("a disabled DNS server must not fail validation")
	}
}

func TestInvalidLocalDomainIsError(t *testing.T) {
	p := valid()
	p.LocalDomain = "has space"

	if !hasError(Validate(p), "local_domain") {
		t.Error("a domain with whitespace must be rejected")
	}
}

func TestValidationIsDeterministic(t *testing.T) {
	p := valid()
	p.Upstream = []netip.Addr{mustAddr("127.0.0.1"), mustAddr("0.0.0.0")}

	first := Validate(p)
	for i := 0; i < 5; i++ {
		next := Validate(p)
		if len(next.Findings) != len(first.Findings) {
			t.Fatalf("finding count varies: %d then %d", len(first.Findings), len(next.Findings))
		}
		for j := range next.Findings {
			if next.Findings[j].Field != first.Findings[j].Field {
				t.Fatalf("finding order varies at %d", j)
			}
		}
	}
}

func TestRecordFQDN(t *testing.T) {
	rec := Record{Hostname: "nas"}

	if got := rec.FQDN("lan"); got != "nas.lan" {
		t.Errorf("FQDN = %q, want nas.lan", got)
	}
	if got := rec.FQDN(""); got != "nas" {
		t.Errorf("FQDN with no domain = %q, want nas", got)
	}
}

func TestNormaliseSortsForDeterministicRendering(t *testing.T) {
	p := valid()
	p.Upstream = []netip.Addr{mustAddr("9.9.9.9"), mustAddr("1.1.1.1")}
	p.LocalRecords = []Record{
		{Hostname: "zebra", Address: mustAddr("10.77.0.12")},
		{Hostname: "alpha", Address: mustAddr("10.77.0.10")},
	}

	p.Normalise()

	if p.Upstream[0].String() != "1.1.1.1" {
		t.Errorf("upstreams must be sorted, got %s first", p.Upstream[0])
	}
	if p.LocalRecords[0].Hostname != "alpha" {
		t.Errorf("records must be sorted, got %s first", p.LocalRecords[0].Hostname)
	}
}

func TestCloneIsDeep(t *testing.T) {
	p := valid()
	p.LocalRecords = []Record{{Hostname: "nas", Address: mustAddr("10.77.0.10")}}

	c := p.Clone()
	c.Upstream[0] = mustAddr("8.8.8.8")
	c.LocalRecords[0].Hostname = "changed"

	if p.Upstream[0].String() != "1.1.1.1" {
		t.Error("Clone must not share the upstream slice")
	}
	if p.LocalRecords[0].Hostname != "nas" {
		t.Error("Clone must not share the records slice")
	}
}
