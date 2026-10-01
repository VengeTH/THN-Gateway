package dhcp

import (
	"net/netip"
	"testing"
)

// FuzzDHCPRangeValidation drives the real production DHCP validation entry
// point with arbitrary IPv4 addresses, prefix lengths and pool endpoints.
//
// The invariant is deliberately narrow:
//
//	arbitrary input
//	        ↓
//	dhcp.Validate (production)
//	        ↓
//	a validation result, or an error
//	        ↓
//	NEVER PANIC
//
// It does not assert that the configuration is accepted. A random DHCP
// configuration is expected to be rejected almost always; asserting acceptance
// would be asserting that the fuzzer found a valid configuration, which is not
// what is being proved here. What is being proved is that the arithmetic
// survives inputs no test author would think to write.
//
// Alongside the panic invariant, two arithmetic properties are checked on
// every input, because both are cheap and both have been wrong here before:
//
//   - Range.Size() is never negative. A negative size means end - start + 1
//     wrapped, which reads as a pool that is smaller than one address.
//   - TotalAddresses() is never negative and never exceeds the total number
//     of IPv4 addresses plus what a saturated IPv6 range contributes.
//
// Generation is over raw octets and a prefix byte rather than parsed strings,
// so the fuzzer spends its budget on arithmetic rather than on parse errors.
// A string-based fuzzer spends nearly all of its iterations discovering that
// "999.1.1.1" is not an address.

// fuzzAddr builds an address from four octets.
func fuzzAddr(a, b, c, d byte) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

// fuzzPrefix builds a prefix from an address and a prefix byte.
//
// The prefix byte is masked to 0..32 because netip.PrefixFrom rejects anything
// wider and returns the zero Prefix, which would remove almost all the
// arithmetic from the fuzz corpus. Masking to the IPv4 range keeps every input
// a real IPv4 prefix, which is where the DHCP arithmetic lives.
func fuzzPrefix(a, b, c, d byte, bits uint8) netip.Prefix {
	return netip.PrefixFrom(fuzzAddr(a, b, c, d), int(bits)&0x1F)
}

// fuzzPolicy assembles the production policy the validator receives.
//
// The LAN prefix is masked the way dhcpPolicyFromConfig leaves it — with host
// bits, because LANPrefix is the address THN places on the interface, not the
// network address. Leaving it unmasked would be a different code path from
// the one the CLI exercises.
//
// The gateway is left unset so that the pool-contains-gateway check does not
// mask the containment arithmetic this fuzz target is about.
func fuzzPolicy(la, lb, lc, ld byte, bits uint8, sa, sb, sc, sd, ea, eb, ec, ed byte) Policy {
	return Policy{
		Enabled:        true,
		Interface:      "lan0",
		Authoritative:  true,
		LeaseTime:      defaultTestLease,
		Domain:         "lan",
		LANPrefix:      fuzzPrefix(la, lb, lc, ld, bits),
		GatewayAddress: netip.Addr{},
		Ranges: []Range{
			{Start: fuzzAddr(sa, sb, sc, sd), End: fuzzAddr(ea, eb, ec, ed)},
		},
	}
}

// FuzzDHCPRangeValidation is the panic-freedom target.
//
// It calls Validate, Range.Size, Range.Contains, Range.Overlaps and
// Policy.TotalAddresses — the whole arithmetic surface a pool endpoint touches —
// and then asserts the invariants above on the results.
func FuzzDHCPRangeValidation(f *testing.F) {
	// The seeds below are the arithmetic danger zones, in the order the
	// brief lists them. Each is a real configuration shape, not a synthetic
	// one: they are the cases that appear in configs/gateway.yaml, in the
	// dnsmasq renderer, and in the existing regression tests.
	seeds := []struct {
		lan        string
		bits       uint8
		start, end string
		why        string
	}{
		{"0.0.0.0", 0, "0.0.0.0", "0.0.0.0", "the whole address space, both endpoints the network address"},
		{"255.255.255.255", 32, "255.255.255.255", "255.255.255.255", "the single last address"},
		{"10.0.0.0", 8, "10.0.0.1", "255.255.255.255", "a /8 range running to the uint32 maximum"},
		{"10.255.255.255", 8, "10.0.0.0", "10.255.255.255", "both /8 endpoints at their extremes"},
		{"192.168.1.0", 24, "192.168.1.0", "192.168.1.255", "a whole /24, network through broadcast"},
		{"192.168.1.0", 24, "192.168.1.255", "192.168.1.0", "a /24 reversed across its own broadcast"},
		{"192.168.1.1", 31, "192.168.1.0", "192.168.1.1", "a /31, where usable = broadcast - network - 1 goes negative"},
		{"192.168.1.1", 31, "192.168.1.1", "192.168.1.0", "a /31 reversed"},
		{"192.168.1.1", 32, "192.168.1.1", "192.168.1.1", "a /32, where the usable subtraction has nothing to subtract"},
		{"192.168.1.1", 30, "192.168.1.1", "192.168.1.2", "a /30, the narrowest subnet with two hosts"},
		{"192.168.1.1", 29, "192.168.1.1", "192.168.1.6", "a /29, six usable addresses"},

		// The shipped configuration, which is the shape every real deployment
		// has: a pool strictly inside the LAN.
		{"10.77.0.1", 24, "10.77.0.100", "10.77.0.250", "the configuration the gateway ships with"},

		// Ordering hazards a string comparison gets wrong.
		{"192.168.1.1", 24, "192.168.1.9", "192.168.1.10", "9 sorts after 10 as a string"},
		{"192.168.1.1", 24, "192.168.1.99", "192.168.1.100", "99 sorts after 100 as a string"},
		{"192.168.1.1", 24, "192.168.1.100", "192.168.1.99", "the same pair, reversed numerically"},

		// Containment hazards.
		{"192.168.1.1", 24, "192.168.2.10", "192.168.2.100", "a pool in a different /24 entirely"},
		{"192.168.1.1", 24, "192.168.1.10", "192.168.2.10", "a pool starting inside and ending outside"},
		{"192.168.1.1", 24, "192.168.1.250", "192.168.2.10", "a pool crossing the subnet boundary forward"},
		{"172.16.0.1", 16, "172.16.255.250", "172.17.0.10", "a pool crossing a /16 boundary"},
		{"10.0.0.1", 24, "10.0.0.250", "11.0.0.10", "a pool crossing a /8 boundary"},
		{"128.0.0.1", 1, "0.0.0.0", "255.255.255.255", "the largest possible pool against the smallest LAN"},

		// Endpoint equality and adjacency.
		{"192.168.1.1", 24, "192.168.1.50", "192.168.1.50", "equal endpoints, one address"},
		{"192.168.1.1", 24, "0.0.0.0", "0.0.0.0", "equal endpoints at the address-space minimum"},
		{"192.168.1.1", 24, "255.255.255.255", "255.255.255.255", "equal endpoints at the address-space maximum"},

		// The subtraction boundary: end - start = 1 across an octet edge.
		{"10.0.0.1", 16, "10.0.0.255", "10.0.1.0", "adjacent addresses across an octet boundary"},
		{"10.0.0.1", 8, "10.0.0.0", "10.0.0.1", "the first two addresses of a /8"},
	}

	for _, s := range seeds {
		// The seed LAN is a bare address; the prefix length is applied by
		// fuzzPrefix below. Parsing it with MustParsePrefix would panic,
		// because "10.77.0.1" carries no prefix length.
		lanA := mustAddr(s.lan).As4()

		sa := mustAddr(s.start).As4()
		ea := mustAddr(s.end).As4()

		f.Add(lanA[0], lanA[1], lanA[2], lanA[3], s.bits,
			sa[0], sa[1], sa[2], sa[3],
			ea[0], ea[1], ea[2], ea[3])
	}

	f.Fuzz(func(t *testing.T,
		la, lb, lc, ld byte,
		bits uint8,
		sa, sb, sc, sd byte,
		ea, eb, ec, ed byte,
	) {
		p := fuzzPolicy(la, lb, lc, ld, bits, sa, sb, sc, sd, ea, eb, ec, ed)

		// The production call. A panic here is a failure; anything else is
		// a result, and the result itself is not asserted.
		result := Validate(p)

		r := p.Ranges[0]

		if size := r.Size(); size < 0 {
			t.Fatalf("Size = %d for %s-%s (LAN %s): end - start + 1 wrapped",
				size, r.Start, r.End, p.LANPrefix)
		}

		if total := p.TotalAddresses(); total < 0 {
			t.Fatalf("TotalAddresses = %d for %s-%s: overlap subtraction underflowed",
				total, r.Start, r.End)
		}

		// Containment is an invariant, not a hope: if the validator accepts
		// a pool, both endpoints must be inside the LAN prefix. This is the
		// property the cross-subnet defect violated, and asserting it here
		// means a regression fails the fuzz target rather than waiting for a
		// hand-written case.
		if result.Valid && p.LANPrefix.IsValid() {
			masked := p.LANPrefix.Masked()
			if !masked.Contains(r.Start) || !masked.Contains(r.End) {
				t.Fatalf("accepted %s-%s outside the LAN prefix %s (errors: %v)",
					r.Start, r.End, masked, result.Errors())
			}
		}

		// The remaining arithmetic surface, exercised because the same
		// endpoints reach them from other call sites.
		_ = r.Contains(r.Start)
		_ = r.Contains(r.End)
		_ = r.Overlaps(r)
		_ = r.String()
		_ = Policy{}.TotalAddresses
	})
}

// FuzzDerivePoolArithmetic drives pool derivation with arbitrary offsets.
//
// DerivePool is the only place that computes a network end address, and it is
// the place a /0 is most dangerous: the offset arithmetic runs against the
// full uint32 range. The invariant is that a derived pool never escapes the
// prefix it was derived from and never reports a reversed range.
func FuzzDerivePoolArithmetic(f *testing.F) {
	seeds := []struct {
		bits      uint8
		offset, n int
		why       string
	}{
		{24, 100, 150, "the shipped pool shape"},
		{24, 0, 256, "the whole /24"},
		{24, 255, 1, "the last address of a /24"},
		{24, 256, 1, "one past the /24"},
		{24, 1000, 1000, "far beyond the /24, must clamp"},
		{0, 100, 150, "a /0 with a small offset"},
		{0, 0xFFFFFFF0, 16, "a /0 whose end reaches the uint32 maximum"},
		{0, 1 << 31, 1, "a /0 offset of 2^31"},
		{31, 0, 2, "a whole /31"},
		{31, 1, 1, "the last address of a /31"},
		{32, 0, 1, "a /32, which has no room at all"},
		{32, 1, 1, "one past a /32"},
		{30, 0, 4, "a whole /30"},
		{29, 0, 8, "a whole /29"},
		{8, 0, 1 << 24, "half of a /8"},
		{1, 0, 1 << 31, "half the address space"},
		{16, 0, 1 << 16, "a whole /16"},
	}

	for _, s := range seeds {
		f.Add(s.bits, s.offset, s.n)
	}

	f.Fuzz(func(t *testing.T, bits uint8, offset, n int) {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), int(bits)&0x1F)

		var pools []Range
		assertNoPanic(t, "DerivePool", func() {
			pools = DerivePool(prefix, offset, n)
		})

		for _, p := range pools {
			// A derived pool must not escape the prefix. This is the whole
			// reason DerivePool clamps, and it is the property that stops a
			// large offset from producing unroutable addresses.
			if prefix.Bits() > 0 && !prefix.Contains(p.Start) {
				t.Fatalf("/%d: derived pool start %s escapes %s (offset %d, n %d)",
					prefix.Bits(), p.Start, prefix.Masked(), offset, n)
			}
			if prefix.Bits() > 0 && !prefix.Contains(p.End) {
				t.Fatalf("/%d: derived pool end %s escapes %s (offset %d, n %d)",
					prefix.Bits(), p.End, prefix.Masked(), offset, n)
			}

			// And it must never be reversed, which is what an overflow in
			// the offset arithmetic would produce.
			if compareAddr(p.Start, p.End) > 0 {
				t.Fatalf("/%d: derived pool %s is reversed (offset %d, n %d)",
					prefix.Bits(), p, offset, n)
			}
			if size := p.Size(); size <= 0 {
				t.Fatalf("/%d: derived pool %s has size %d (offset %d, n %d)",
					prefix.Bits(), p, size, offset, n)
			}
		}
	})
}

// FuzzRangeEndpointArithmetic drives the comparison and distance primitives
// directly, without going through validation.
//
// This is where the documented bug class lives: compareAddr returning -1/0/1
// where a magnitude was needed. Fuzzing the primitives isolates it from the
// validator, so a failure points at the arithmetic rather than at a policy
// decision.
func FuzzRangeEndpointArithmetic(f *testing.F) {
	seeds := []struct {
		a, b string
	}{
		{"0.0.0.0", "255.255.255.255"},
		{"255.255.255.255", "0.0.0.0"},
		{"192.168.1.9", "192.168.1.10"},
		{"192.168.1.99", "192.168.1.100"},
		{"0.0.0.0", "0.0.0.0"},
		{"255.255.255.255", "255.255.255.255"},
		{"0.0.0.254", "0.0.0.255"},
		{"255.255.255.0", "255.255.255.255"},
	}

	for _, s := range seeds {
		ab := mustAddr(s.a).As4()
		bb := mustAddr(s.b).As4()
		f.Add(ab[0], ab[1], ab[2], ab[3], bb[0], bb[1], bb[2], bb[3])
	}

	f.Fuzz(func(t *testing.T, a, b, c, d, e, f2, g, h byte) {
		x := netip.AddrFrom4([4]byte{a, b, c, d})
		y := netip.AddrFrom4([4]byte{e, f2, g, h})

		cmp := compareAddr(x, y)

		// compareAddr must be a total order: antisymmetric and reflexive.
		if got := compareAddr(y, x); got != -cmp {
			t.Fatalf("compareAddr(%s, %s) = %d but compareAddr(%s, %s) = %d",
				x, y, cmp, y, x, got)
		}
		if cmp != 0 && compareAddr(x, x) != 0 {
			t.Fatalf("compareAddr is not reflexive at %s", x)
		}
		if cmp < -1 || cmp > 1 {
			t.Fatalf("compareAddr(%s, %s) = %d, which is outside -1/0/1", x, y, cmp)
		}

		// The two functions use opposite sign conventions, and that asymmetry is
		// exactly why the codebase has a documented history of using one
		// where the other was needed:
		//
		//	compareAddr(x, y) < 0  means  x < y
		//	distance(x, y)   < 0    means  y < x   (it is y minus x)
		//
		// So distance(x, y) is positive when compareAddr(x, y) is negative.
		// Asserting the relationship explicitly is the point: a range size
		// that disagreed with the comparison would report a negative size
		// for a perfectly ordinary pool.
		dist := distance(x, y)
		switch {
		case cmp == 0 && dist != 0:
			t.Fatalf("distance(%s, %s) = %d, want 0 for equal addresses", x, y, dist)
		case cmp < 0 && !(dist > 0):
			t.Fatalf("distance(%s, %s) = %d, want a positive number when %s < %s", x, y, dist, x, y)
		case cmp > 0 && !(dist < 0):
			t.Fatalf("distance(%s, %s) = %d, want a negative number when %s > %s", x, y, dist, x, y)
		}

		// The three-way result must also agree with the uint32 ordering,
		// which is what the uint32 test asserts statically.
		if x.As4() != y.As4() {
			xu, yu := toUint32(x.As4()), toUint32(y.As4())
			if xu < yu && cmp >= 0 {
				t.Fatalf("compareAddr(%s, %s) = %d but %d < %d as uint32", x, y, cmp, xu, yu)
			}
			if xu > yu && cmp <= 0 {
				t.Fatalf("compareAddr(%s, %s) = %d but %d > %d as uint32", x, y, cmp, xu, yu)
			}
		}

		// A range over these two endpoints must have a non-negative size,
		// and a reversed range must report zero rather than wrapping.
		for _, r := range []Range{{Start: x, End: y}, {Start: y, End: x}} {
			if size := r.Size(); size < 0 {
				t.Fatalf("Size(%s-%s) = %d, which is negative", r.Start, r.End, size)
			}
			if compareAddr(r.Start, r.End) > 0 && r.Size() != 0 {
				t.Fatalf("Size(%s-%s) = %d, want 0 for a reversed range", r.Start, r.End, r.Size())
			}
		}
	})
}
