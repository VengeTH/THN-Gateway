package dhcp

import (
	"net/netip"
	"testing"
	"time"
)

func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// gateway returns a valid policy for 10.77.0.1/24.
func gateway() Policy {
	return Policy{
		Enabled:        true,
		Interface:      "enx001122334455",
		LANPrefix:      mustPrefix("10.77.0.1/24"),
		Authoritative:  true,
		LeaseTime:      12 * time.Hour,
		Domain:         "lan",
		GatewayAddress: mustAddr("10.77.0.1"),
		Ranges: []Range{
			{Start: mustAddr("10.77.0.100"), End: mustAddr("10.77.0.250")},
		},
	}
}

// rng builds a Range from two addresses, so table-driven tests do not have to
// supply the netmask field.
func rng(start, end string) Range {
	return Range{Start: mustAddr(start), End: mustAddr(end)}
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

// TestRangeSizeCountsAddresses covers a bug that reported a 151-address pool
// as holding 2 addresses, because a three-way comparison was used where a
// numeric distance was needed.
func TestRangeSizeCountsAddresses(t *testing.T) {
	cases := []struct {
		name string
		r    Range
		want int
	}{
		{"single", rng("10.0.0.1", "10.0.0.1"), 1},
		{"pair", rng("10.0.0.1", "10.0.0.2"), 2},
		{"pool", rng("10.77.0.100", "10.77.0.250"), 151},
		{"subnet", rng("10.0.0.0", "10.0.0.255"), 256},
		{"inverted", rng("10.0.0.10", "10.0.0.1"), 0},
		{"invalid", Range{}, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.Size(); got != c.want {
				t.Errorf("Size = %d, want %d", got, c.want)
			}
		})
	}
}

func TestTotalAddressesSubtractsOverlaps(t *testing.T) {
	p := Policy{Ranges: []Range{
		rng("10.0.0.10", "10.0.0.20"), // 11
		rng("10.0.0.15", "10.0.0.25"), // overlaps by 6
	}}

	// 11 + 11 - 6 = 16
	if got := p.TotalAddresses(); got != 16 {
		t.Errorf("TotalAddresses = %d, want 16", got)
	}
}

func TestTotalAddressesOnDisjointPools(t *testing.T) {
	p := Policy{Ranges: []Range{
		rng("10.0.0.1", "10.0.0.10"), // 10
		rng("10.0.1.1", "10.0.1.10"), // 10
	}}

	if got := p.TotalAddresses(); got != 20 {
		t.Errorf("TotalAddresses = %d, want 20", got)
	}
}

func TestDerivePool(t *testing.T) {
	pools := DerivePool(mustPrefix("10.77.0.1/24"), 100, 150)
	if len(pools) != 1 {
		t.Fatalf("got %d pools, want 1", len(pools))
	}
	if pools[0].Start.String() != "10.77.0.100" {
		t.Errorf("start = %s, want 10.77.0.100", pools[0].Start)
	}
	if pools[0].End.String() != "10.77.0.249" {
		t.Errorf("end = %s, want 10.77.0.249 (100 + 150 - 1)", pools[0].End)
	}
}

func TestDerivePoolClampsToNetwork(t *testing.T) {
	// Asking for more addresses than the network holds must not produce a
	// range that escapes it.
	pools := DerivePool(mustPrefix("10.77.0.0/28"), 8, 100)

	if len(pools) != 1 {
		t.Fatalf("got %d pools, want 1", len(pools))
	}
	if !mustPrefix("10.77.0.0/28").Contains(pools[0].End) {
		t.Errorf("pool end %s escapes the /28", pools[0].End)
	}
}

func TestDerivePoolRejectsIPv6(t *testing.T) {
	// An IPv6 "pool" is meaningless without SLAAC, which is a different
	// mechanism with different rules.
	if got := DerivePool(mustPrefix("2001:db8::/64"), 100, 150); got != nil {
		t.Errorf("DerivePool must not fabricate an IPv6 pool, got %v", got)
	}
}

func TestValidGatewayPasses(t *testing.T) {
	r := Validate(gateway())
	if !r.Valid {
		t.Errorf("a valid gateway must pass, got: %v", r.Errors())
	}
}

// TestPoolContainingGatewayIsError covers the duplicate-address case: a pool
// that eventually hands out the gateway's own address.
func TestPoolContainingGatewayIsError(t *testing.T) {
	p := gateway()
	p.Ranges = []Range{rng("10.77.0.1", "10.77.0.50")}

	if !hasError(Validate(p), "ranges[0]") {
		t.Error("a pool containing the gateway's own address must be an error")
	}
}

// TestPoolOutsideLANIsError covers the failure a client experiences: an
// unroutable address that looks like a working configuration.
func TestPoolOutsideLANIsError(t *testing.T) {
	p := gateway()
	p.Ranges = []Range{rng("192.168.50.10", "192.168.50.20")}

	r := Validate(p)

	if r.Valid {
		t.Fatal("a pool outside the LAN must be rejected")
	}
	if !hasError(r, "ranges[0].start") {
		t.Errorf("expected an error on ranges[0].start, got %v", r.Findings)
	}
}

func TestOverlappingPoolsAreError(t *testing.T) {
	p := gateway()
	p.Ranges = []Range{
		rng("10.77.0.100", "10.77.0.200"),
		rng("10.77.0.150", "10.77.0.250"),
	}

	if !hasError(Validate(p), "ranges[1]") {
		t.Error("overlapping pools must be rejected")
	}
}

func TestInvertedPoolIsError(t *testing.T) {
	p := gateway()
	p.Ranges = []Range{rng("10.77.0.250", "10.77.0.100")}

	if !hasError(Validate(p), "ranges[0]") {
		t.Error("an inverted pool must be rejected")
	}
}

func TestZeroLeaseTimeIsError(t *testing.T) {
	p := gateway()
	p.LeaseTime = 0

	if !hasError(Validate(p), "lease_time") {
		t.Error("a zero lease time would expire every address immediately")
	}
}

func TestVeryShortLeaseTimeIsError(t *testing.T) {
	p := gateway()
	p.LeaseTime = 30 * time.Second

	if !hasError(Validate(p), "lease_time") {
		t.Error("a 30 second lease would break any client that sleeps")
	}
}

func TestLongLeaseTimeWarns(t *testing.T) {
	p := gateway()
	p.LeaseTime = 30 * 24 * time.Hour

	if !hasFinding(Validate(p), "lease_time", SeverityWarning) {
		t.Error("a 30 day lease delays reclaiming abandoned addresses and should warn")
	}
}

func TestNoPoolsWarns(t *testing.T) {
	p := gateway()
	p.Ranges = nil

	if !hasFinding(Validate(p), "ranges", SeverityWarning) {
		t.Error("no pools means no addresses served")
	}
}

func TestInvalidMACIsError(t *testing.T) {
	p := gateway()
	p.Reservations = []Reservation{{MAC: "not-a-mac"}}

	if !hasError(Validate(p), "reservations[0].mac") {
		t.Error("an invalid MAC must be rejected")
	}
}

func TestDuplicateReservationMACIsError(t *testing.T) {
	p := gateway()
	p.Reservations = []Reservation{
		{MAC: "aa:bb:cc:dd:ee:ff"},
		{MAC: "AA:BB:CC:DD:EE:FF"}, // same, different case
	}

	if !hasError(Validate(p), "reservations[1].mac") {
		t.Error("a MAC may only be reserved once, case-insensitively")
	}
}

func TestReservationOutsideLANIsError(t *testing.T) {
	p := gateway()
	p.Reservations = []Reservation{{MAC: "aa:bb:cc:dd:ee:ff", Address: mustAddr("192.168.9.9")}}

	if !hasError(Validate(p), "reservations[0].address") {
		t.Error("a reserved address outside the LAN would be unroutable")
	}
}

func TestReservationInsideLANAccepted(t *testing.T) {
	p := gateway()
	p.Reservations = []Reservation{{
		MAC:      "aa:bb:cc:dd:ee:ff",
		Address:  mustAddr("10.77.0.10"),
		Hostname: "nas",
	}}

	r := Validate(p)
	if !r.Valid {
		t.Errorf("a reservation inside the LAN must pass, got: %v", r.Errors())
	}
}

func TestDisabledDHCPIsInformationalNotError(t *testing.T) {
	p := gateway()
	p.Enabled = false
	p.Ranges = nil
	p.LeaseTime = 0

	r := Validate(p)

	if !r.Valid {
		t.Error("a disabled DHCP server must not fail validation")
	}
	if !hasFinding(r, "enabled", SeverityInfo) {
		t.Error("disabling DHCP must be reported")
	}
}

func TestValidationIsDeterministic(t *testing.T) {
	p := gateway()
	p.Ranges = []Range{rng("192.168.1.1", "192.168.1.5")}

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

func TestResultErr(t *testing.T) {
	p := gateway()
	p.Ranges = []Range{rng("192.168.1.1", "192.168.1.5")}

	if err := Validate(p).Err(); err == nil {
		t.Error("Err must report the first error finding")
	}
	if err := Validate(gateway()).Err(); err != nil {
		t.Errorf("a valid policy must produce no error, got %v", err)
	}
}

// --- leases ---

func TestLeaseStatusAndRemaining(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	active := Lease{Address: mustAddr("10.77.0.101"), Expiry: now.Add(time.Hour)}
	if !active.Active(now) || active.Expired(now) {
		t.Error("a lease within its window must be active")
	}
	if got := active.Remaining(now); got != time.Hour {
		t.Errorf("Remaining = %v, want 1h", got)
	}
	if got := active.Status(now); got != StatusActive {
		t.Errorf("Status = %q, want active", got)
	}

	expired := Lease{Address: mustAddr("10.77.0.102"), Expiry: now.Add(-time.Hour)}
	if expired.Active(now) {
		t.Error("a lease past its window must not be active")
	}
	// Remaining is clamped at zero rather than going negative: a negative
	// duration is almost never what an operator wants to read.
	if got := expired.Remaining(now); got != 0 {
		t.Errorf("Remaining for an expired lease = %v, want 0", got)
	}
	if got := expired.Status(now); got != StatusExpired {
		t.Errorf("Status = %q, want expired", got)
	}
}

func TestLeaseWithInvalidAddressIsInvalid(t *testing.T) {
	l := Lease{Expiry: time.Now().Add(time.Hour)}
	if got := l.Status(time.Now()); got != StatusInvalid {
		t.Errorf("Status = %q, want invalid", got)
	}
}

func TestSummariseCounts(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	leases := []Lease{
		{MAC: "aa:bb:cc:dd:ee:01", Address: mustAddr("10.77.0.101"), Expiry: now.Add(time.Hour), DeviceID: "dev_1"},
		{MAC: "aa:bb:cc:dd:ee:02", Address: mustAddr("10.77.0.102"), Expiry: now.Add(2 * time.Hour)},
		{MAC: "aa:bb:cc:dd:ee:03", Address: mustAddr("10.77.0.103"), Expiry: now.Add(-time.Hour)},
	}

	reserved := map[string]bool{"aa:bb:cc:dd:ee:01": true}

	s := Summarise(leases, 151, now, reserved)

	if s.Total != 3 {
		t.Errorf("Total = %d, want 3", s.Total)
	}
	if s.Active != 2 {
		t.Errorf("Active = %d, want 2", s.Active)
	}
	if s.Expired != 1 {
		t.Errorf("Expired = %d, want 1", s.Expired)
	}
	if s.Reserved != 1 {
		t.Errorf("Reserved = %d, want 1", s.Reserved)
	}
	if s.Uncorrelated != 2 {
		t.Errorf("Uncorrelated = %d, want 2", s.Uncorrelated)
	}
	if s.AddressesInUse != 3 {
		t.Errorf("AddressesInUse = %d, want 3", s.AddressesInUse)
	}
	if s.PoolCapacity != 151 {
		t.Errorf("PoolCapacity = %d, want 151", s.PoolCapacity)
	}
	if s.ShortestRemaining != time.Hour {
		t.Errorf("ShortestRemaining = %v, want 1h", s.ShortestRemaining)
	}
}

func TestNormaliseMACIsLowercase(t *testing.T) {
	if got := NormalisedMAC("  AA:BB:CC:DD:EE:FF "); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("NormalisedMAC = %q, want lowercase and trimmed", got)
	}
}

func TestSortLeases(t *testing.T) {
	leases := []Lease{
		{Address: mustAddr("10.77.0.103")},
		{Address: mustAddr("10.77.0.101")},
		{Address: mustAddr("10.77.0.102")},
	}

	SortLeases(leases)

	for i, want := range []string{"10.77.0.101", "10.77.0.102", "10.77.0.103"} {
		if leases[i].Address.String() != want {
			t.Errorf("position %d = %s, want %s", i, leases[i].Address, want)
		}
	}
}

func TestIsValidMAC(t *testing.T) {
	cases := []struct {
		mac  string
		want bool
	}{
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee", false},
		{"aa:bb:cc:dd:ee:ff:00", false},
		{"gg:bb:cc:dd:ee:ff", false},
		{"aabbccddeeff", false},
		{"", false},
	}

	for _, c := range cases {
		if got := isValidMAC(c.mac); got != c.want {
			t.Errorf("isValidMAC(%q) = %v, want %v", c.mac, got, c.want)
		}
	}
}
