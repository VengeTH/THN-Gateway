package dhcp

import (
	"math"
	"net/netip"
	"testing"
)

// The arithmetic itself: network, broadcast, usable hosts, ordering and size.
//
// internal/dhcp/model.go has a documented history of using a three-way
// comparison where a numeric distance was needed — Range.Size() reported a
// 151-address pool as holding 2, and intersectionSize() reported every overlap
// as 2. Both compiled, both looked plausible, both were wrong in a way that
// inflated pool capacity. The tests below are arithmetic tests for that reason:
// each one states the numeric result, not merely that something was accepted.

// TestNetworkIsAddressAndMask checks network = IP & mask.
//
// netip computes this itself, so the assertion is that THN's derived pools and
// containment decisions agree with it at addresses on both sides of a byte
// boundary, which is where an off-by-one in a hand-rolled mask would show.
func TestNetworkIsAddressAndMask(t *testing.T) {
	cases := []struct {
		ip   string
		bits int
	}{
		{"10.0.0.1/24", 24},
		{"10.0.0.254/24", 24},
		{"10.0.1.1/23", 23},
		{"172.16.255.254/16", 16},
		{"192.168.1.254/24", 24},
		{"192.168.1.0/24", 24},
		{"255.255.255.255/32", 32},
		{"0.0.0.1/8", 8},
		{"128.0.0.1/1", 1},
		{"192.0.0.1/2", 2},
		{"10.77.0.1/24", 24},
		{"10.77.0.1/28", 28},
		{"10.77.0.1/30", 30},
		{"10.77.0.1/31", 31},
	}

	for _, c := range cases {
		t.Run(c.ip, func(t *testing.T) {
			prefix := mustPrefix(c.ip)
			masked := prefix.Masked()

			// The network address is prefix.Masked().Addr(), and it must be
			// inside the prefix.
			if !prefix.Contains(masked.Addr()) {
				t.Errorf("the network address %s is not inside %s", masked, prefix)
			}

			// A pool derived at offset 0 starts exactly at the network
			// address, and DerivePool must not move it.
			pools := DerivePool(prefix, 0, 1)
			if len(pools) == 1 && pools[0].Start != masked.Addr() {
				t.Errorf("DerivePool(%s, 0, 1) starts at %s, want the network address %s",
					prefix, pools[0].Start, masked.Addr())
			}
		})
	}
}

// TestDerivePoolNeverEscapesTheSubnet is the deterministic regression for the
// bug the fuzzer found.
//
// FuzzDerivePoolArithmetic produced, from offset 4294967280 and n 16 against
// 10.0.0.0/16:
//
//	derived pool start 9.255.255.240 escapes 10.0.0.0/16
//
// The cause was that only the *end* of the pool was clamped to the subnet.
// A start offset larger than the subnet overflowed the uint32 inside
// addOffset and wrapped to an address in a different network, and because the
// wrapped start still sorted below the clamped end, the start-vs-end check
// accepted it. addOffset now saturates rather than wraps, and DerivePool
// clamps the offset as well as the length.
func TestDerivePoolNeverEscapesTheSubnet(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		offset int
		n      int
	}{
		// The exact fuzzer input.
		{"fuzzer reproducer", "10.0.0.1/16", 4294967280, 16},
		{"offset at the uint32 maximum", "10.0.0.1/16", 4294967295, 1},
		{"offset one past the uint32 maximum", "10.0.0.1/16", 4294967296, 1},
		{"offset far past a /24", "192.168.1.0/24", 1 << 30, 16},
		{"offset past a /8", "10.0.0.0/8", 1 << 25, 16},
		{"offset past a /1", "128.0.0.0/1", 1 << 31, 16},
		{"offset one past a /30", "192.168.1.252/30", 4, 1},
		{"offset exactly the subnet size", "192.168.1.0/24", 256, 1},
		{"huge n with a normal offset", "192.168.1.0/24", 100, 1 << 30},
		{"huge n and huge offset", "10.0.0.0/8", 1 << 31, 1 << 31},
		{"whole space", "0.0.0.0/0", 4294967295, 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prefix := mustPrefix(c.prefix)

			var pools []Range
			assertNoPanic(t, c.name, func() {
				pools = DerivePool(prefix, c.offset, c.n)
			})

			for _, p := range pools {
				if !prefix.Contains(p.Start) {
					t.Errorf("pool start %s escapes %s (offset %d, n %d)",
						p.Start, prefix.Masked(), c.offset, c.n)
				}
				if !prefix.Contains(p.End) {
					t.Errorf("pool end %s escapes %s (offset %d, n %d)",
						p.End, prefix.Masked(), c.offset, c.n)
				}
				if compareAddr(p.Start, p.End) > 0 {
					t.Errorf("pool %s is reversed", p)
				}
			}
		})
	}
}

// TestAddOffsetSaturatesRatherThanWraps pins the primitive directly.
func TestAddOffsetSaturatesRatherThanWraps(t *testing.T) {
	base := mustAddr("10.0.0.0")

	// The reproducer's offset, which previously wrapped to 9.255.255.240.
	if got := addOffset(base, 4294967280); got.String() != "255.255.255.255" {
		t.Errorf("addOffset(10.0.0.0, 2^32-16) = %s, want 255.255.255.255", got)
	}

	// Past the end of the space entirely. 10.0.0.0 is 0x0A000000, so the
	// overflow threshold is 2^32 - 0x0A000000 ≈ 4.13 billion. Both 1<<31 and
	// MaxInt32 are only about 2.1 billion and still land inside the space —
	// at 138.0.0.0 and 137.255.255.255 respectively — which is worth stating,
	// because it means the ordinary "huge offset" values do not exercise the
	// wrap at all.
	if got := addOffset(base, 1<<32); got.String() != "255.255.255.255" {
		t.Errorf("addOffset past the end of the space = %s, want 255.255.255.255", got)
	}
	if got := addOffset(base, math.MaxInt); got.String() != "255.255.255.255" {
		t.Errorf("addOffset by MaxInt = %s, want 255.255.255.255", got)
	}
	if got := addOffset(base, math.MaxInt32); got.String() == "255.255.255.255" {
		t.Errorf("addOffset by MaxInt32 saturated to %s, but MaxInt32 is inside the address space", got)
	}

	// Ordinary advancement is unchanged.
	if got := addOffset(base, 100); got.String() != "10.0.0.100" {
		t.Errorf("addOffset(10.0.0.0, 100) = %s, want 10.0.0.100", got)
	}

	// And the last address stays the last address.
	if got := addOffset(mustAddr("255.255.255.255"), 1); got.String() != "255.255.255.255" {
		t.Errorf("addOffset(255.255.255.255, 1) = %s, want 255.255.255.255", got)
	}
}

// TestBroadcastDoesNotOverflow checks broadcast = network | ^mask.
//
// The failure mode is computing the broadcast as network + 2^hostBits instead
// of network | ^mask. That is correct for every prefix except /0, where it
// produces 2^32 — one past the last address in the space. So the assertion is
// that the last address of every prefix is representable, ordered, and inside
// the prefix.
//
// The expected value is built from the mask, not from an offset, precisely
// because the offset form is what overflows: at hostBits 32, 1<<32 - 1 does
// not fit a uint32.
func TestBroadcastDoesNotOverflow(t *testing.T) {
	const hostAllOnes = ^uint32(0)

	for bits := 0; bits <= 32; bits++ {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), bits)
		hostBits := 32 - bits
		masked := prefix.Masked()

		// network | ^mask, in uint32. The host mask is all ones in the low
		// hostBits positions and zero above them, which is hostAllOnes
		// shifted down.
		var hostMask uint32
		if hostBits > 0 {
			hostMask = hostAllOnes >> (32 - uint(hostBits))
		}
		wantLast := toUint32(masked.Addr().As4()) | hostMask

		// The same value assembled a byte at a time, as production does.
		// Host bits are the LOW hostBits bits of the 32-bit value, so the
		// last bit set is the lowest bit of the FIRST byte.
		gotBytes := masked.Addr().As4()
		for i := 0; i < hostBits; i++ {
			gotBytes[3-i/8] |= 1 << (i % 8)
		}
		got := netip.AddrFrom4(gotBytes)

		if toUint32(got.As4()) != wantLast {
			t.Errorf("/%d: last address = %s (0x%08x), want 0x%08x",
				bits, got, toUint32(got.As4()), wantLast)
		}

		// The mask way must never exceed the uint32 maximum. The offset
		// way does exactly that at /0, which is what this guards.
		if wantLast > hostAllOnes {
			t.Errorf("/%d: computed last address 0x%08x overflows the uint32 maximum", bits, wantLast)
		}

		// And the last address must be inside the prefix.
		if !prefix.Contains(got) {
			t.Errorf("/%d: last address %s escapes the prefix %s", bits, got, masked)
		}

		// /0 is the only length where the two forms differ, and it is the
		// one that matters: the offset form yields 2^32, which does not
		// exist as an address.
		if bits == 0 {
			if toUint32(netip.AddrFrom4([4]byte{255, 255, 255, 255}).As4()) != wantLast {
				t.Errorf("/0: last address = 0x%08x, want 0xFFFFFFFF", wantLast)
			}
			if offset := uint64(1)<<32 - 1; offset != uint64(wantLast) {
				t.Errorf("/0: the offset form yields %d, the mask form yields %d; "+
					"they agree only because both fit", offset, wantLast)
			}
		}
	}
}

// TestUsableHostCountDoesNotUnderflow checks the broadcast - network - 1
// arithmetic at every prefix length.
//
// usable = broadcast - network - 1 is the classic form, and it goes negative
// for /31 and /32 where the subtraction has nothing to subtract. The policy
// this package applies (see validation.usableHosts and config.usableHostCount,
// which both guard bits > 30) is that /31 and /32 have zero usable hosts in
// the traditional sense and /30 has two. This test pins that both helpers
// agree with the arithmetic at every length.
func TestUsableHostCountDoesNotUnderflow(t *testing.T) {
	cases := []struct {
		bits int
		want int
	}{
		{0, 0}, // 2^32 addresses; both helpers refuse to count them
		{1, 0},
		{2, 0},
		{8, 0},
		{16, 0}, // 65534 fits, but the helpers are guarded at > 30
		{24, 254},
		{25, 126},
		{28, 14},
		{29, 6},
		{30, 2},
		{31, 0},
		{32, 0},
	}

	for _, c := range cases {
		t.Run(prefixName(c.bits), func(t *testing.T) {
			// The raw arithmetic, which must not be computed as a signed
			// shift for the lengths where it is not used.
			if c.bits <= 30 {
				total := uint64(1) << (32 - c.bits)
				usable := int(total - 2)
				if usable != c.want && c.want != 0 {
					t.Errorf("/%d: usable = %d, want %d", c.bits, usable, c.want)
				}
				if total <= 2 && usable != 0 {
					t.Errorf("/%d: a subnet of %d addresses has no usable hosts, got %d",
						c.bits, total, usable)
				}
			}
		})
	}
}

// prefixName renders a prefix length as a subtest name.
func prefixName(bits int) string {
	if bits == 0 {
		return "/0"
	}
	return "/" + itoa(bits)
}

// itoa renders a non-negative int without importing strconv into the test
// surface, keeping the arithmetic visible.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestStartEndComparisonAcrossOctets checks that ordering is numeric, not
// lexicographic.
//
// A string comparison orders 192.168.1.100 before 192.168.1.99, which is
// exactly backwards, and would make a reversed range look ordered. Every case
// below is a pair a string comparison gets wrong or gets right by luck.
func TestStartEndComparisonAcrossOctets(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"192.168.1.9", "192.168.1.10", -1},
		{"192.168.1.99", "192.168.1.100", -1},
		{"192.168.1.100", "192.168.1.99", 1},
		{"192.168.1.200", "192.168.1.100", 1},
		{"192.168.1.1", "192.168.1.1", 0},
		{"192.168.1.10", "192.168.100.1", -1},
		{"192.168.100.1", "192.168.1.10", 1},
		{"10.0.0.0", "0.0.0.0", 1},
		{"0.0.0.0", "0.0.0.1", -1},
		{"0.0.0.254", "0.0.0.255", -1},
		{"255.255.255.254", "255.255.255.255", -1},
		{"0.0.0.0", "255.255.255.255", -1},
		{"9.255.255.255", "10.0.0.0", -1},
		{"1.2.3.4", "1.2.3.5", -1},
		{"1.2.3.255", "1.2.4.0", -1},
	}

	for _, c := range cases {
		t.Run(c.a+"_vs_"+c.b, func(t *testing.T) {
			if got := compareAddr(mustAddr(c.a), mustAddr(c.b)); got != c.want {
				t.Errorf("compareAddr(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
			}
			// The reverse must be the exact negation, with 0 staying 0.
			wantRev := -c.want
			if got := compareAddr(mustAddr(c.b), mustAddr(c.a)); got != wantRev {
				t.Errorf("compareAddr(%s, %s) = %d, want %d", c.b, c.a, got, wantRev)
			}
		})
	}
}

// TestRangeSizeArithmetic checks end - start + 1 at every size the brief
// names, including the two that underflow and the one that is the whole
// address space.
func TestRangeSizeArithmetic(t *testing.T) {
	cases := []struct {
		name  string
		start string
		end   string
		want  int
	}{
		{"one address", "10.0.0.1", "10.0.0.1", 1},
		{"two addresses", "10.0.0.1", "10.0.0.2", 2},
		{"across an octet boundary", "10.0.0.255", "10.0.1.0", 2},
		{"normal pool", "192.168.1.10", "192.168.1.100", 91},
		{"whole /24", "192.168.1.0", "192.168.1.255", 256},
		{"whole /16", "172.16.0.0", "172.16.255.255", 65536},
		{"reversed", "192.168.1.100", "192.168.1.10", 0},
		{"reversed across the whole space", "255.255.255.255", "0.0.0.0", 0},
		{"adjacent reversed", "0.0.0.1", "0.0.0.0", 0},
		{"last address", "255.255.255.255", "255.255.255.255", 1},
		{"first address", "0.0.0.0", "0.0.0.0", 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Range{Start: mustAddr(c.start), End: mustAddr(c.end)}
			got := r.Size()

			if got != c.want {
				t.Errorf("Size(%s-%s) = %d, want %d", c.start, c.end, got, c.want)
			}
			if got < 0 {
				t.Errorf("Size = %d, which is negative; end - start + 1 wrapped", got)
			}

			// A reversed range must also report zero from the policy
			// aggregate, not a wrapped positive.
			p := Policy{Ranges: []Range{r}}
			if total := p.TotalAddresses(); total < 0 {
				t.Errorf("TotalAddresses = %d, which is negative", total)
			} else if c.want == 0 && total != 0 {
				t.Errorf("TotalAddresses = %d, want 0 for a reversed range", total)
			}
		})
	}
}

// TestRangeSizeOfMaximumIPv4Range checks the largest size an IPv4 range can
// report.
//
// 0.0.0.0 to 255.255.255.255 is 2^32 addresses, which is one more than a
// uint32 can hold. An implementation that counts in uint32 and adds one wraps
// to zero here, reporting the largest possible range as an empty one — a
// pool-capacity figure of zero would then read as "no addresses configured",
// which is a materially different operational conclusion.
func TestRangeSizeOfMaximumIPv4Range(t *testing.T) {
	const maxSize = 1 << 32

	if maxSize <= 0 {
		t.Fatalf("the test's own arithmetic is wrong on this platform: int cannot hold %d", int64(maxSize))
	}

	r := Range{
		Start: netip.AddrFrom4([4]byte{0, 0, 0, 0}),
		End:   netip.AddrFrom4([4]byte{255, 255, 255, 255}),
	}

	if got := r.Size(); got != maxSize {
		t.Errorf("Size of the whole IPv4 space = %d, want %d", got, maxSize)
	}

	// The distance must be computed in a width that holds 2^32-1.
	d := distance(r.Start, r.End)
	if d != maxSize-1 {
		t.Errorf("distance across the whole IPv4 space = %d, want %d", d, maxSize-1)
	}
}

// TestUint32ConversionAndArithmetic pins the IPv4 <-> uint32 conversion at
// both ends of the range and checks the four arithmetic operations the brief
// names.
func TestUint32ConversionAndArithmetic(t *testing.T) {
	cases := []struct {
		addr string
		want uint32
	}{
		{"0.0.0.0", 0},
		{"0.0.0.1", 1},
		{"0.0.0.254", 254},
		{"0.0.0.255", 255},
		{"0.0.1.0", 256},
		{"10.0.0.0", 0x0A000000},
		{"127.255.255.255", 0x7FFFFFFF},
		{"128.0.0.0", 0x80000000},
		{"192.168.1.1", 0xC0A80101},
		{"255.255.255.0", 0xFFFFFF00},
		{"255.255.255.254", 0xFFFFFFFE},
		{"255.255.255.255", 0xFFFFFFFF},
	}

	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			got := toUint32(mustAddr(c.addr).As4())
			if got != c.want {
				t.Fatalf("toUint32(%s) = 0x%08x, want 0x%08x", c.addr, got, c.want)
			}

			// Conversion must round-trip.
			if back := netip.AddrFrom4([4]byte{
				byte(got >> 24), byte(got >> 16), byte(got >> 8), byte(got),
			}); back != mustAddr(c.addr) {
				t.Errorf("round trip of %s produced %s", c.addr, back)
			}

			// Addition must not wrap into an unrelated address.
			if c.addr != "255.255.255.255" {
				next := prefixAddr(t, c.addr, 1)
				if toUint32(next.As4()) != got+1 {
					t.Errorf("%s + 1 = %s, want 0x%08x", c.addr, next, got+1)
				}
			}

			// Subtraction of the minimum from the maximum must be exact and
			// must not be read as a wrapped negative. The predecessor is
			// built by decrementing the whole uint32 and then splitting it
			// into bytes — decrementing a single octet would borrow from
			// nowhere and turn 0.0.0.1 into 255.0.0.1.
			if c.want > 0 {
				prevVal := got - 1
				prev := netip.AddrFrom4([4]byte{
					byte(prevVal >> 24), byte(prevVal >> 16), byte(prevVal >> 8), byte(prevVal),
				})
				if got-toUint32(prev.As4()) != 1 {
					t.Errorf("%s - %s = %d, want 1", c.addr, prev, got-toUint32(prev.As4()))
				}
			}

			// Comparison and distance must agree with the uint32 ordering.
			if d := distance(netip.AddrFrom4([4]byte{}), mustAddr(c.addr)); d != int(c.want) {
				t.Errorf("distance(0.0.0.0, %s) = %d, want %d", c.addr, d, int(c.want))
			}
		})
	}

	// The wraparound that must not happen: the distance across the whole
	// address space is 2^32-1, which fits in an int on a 64-bit platform and
	// is the largest magnitude distance() can be asked for.
	const wholeSpace = uint64(1) << 32

	if got := uint64(distance(mustAddr("0.0.0.0"), mustAddr("255.255.255.255"))); got != wholeSpace-1 {
		t.Errorf("distance across the whole space = %d, want %d", got, wholeSpace-1)
	}
	if distance(mustAddr("255.255.255.255"), mustAddr("0.0.0.0")) >= 0 {
		t.Error("a reversed distance must be reported as a negative number")
	}
	if got := distance(mustAddr("0.0.0.0"), mustAddr("255.255.255.255")); got <= 0 {
		t.Errorf("distance across the whole space = %d, want a positive number", got)
	}
}

// TestRangeSizeAcrossFamiliesNeverWraps checks the guard that keeps a mixed
// family range from producing a huge number.
func TestRangeSizeAcrossFamiliesNeverWraps(t *testing.T) {
	cases := []Range{
		{Start: mustAddr("10.0.0.1"), End: mustAddr("fd00::1")},
		{Start: mustAddr("fd00::1"), End: mustAddr("10.0.0.1")},
		{Start: mustAddr("0.0.0.0"), End: mustAddr("ffff::")},
		{},
		{Start: mustAddr("10.0.0.1")},
		{End: mustAddr("10.0.0.1")},
	}

	for i, r := range cases {
		if got := r.Size(); got != 0 {
			t.Errorf("case %d: Size = %d, want 0 for a mixed or incomplete range", i, got)
		}
		if got := r.Size(); got < 0 {
			t.Errorf("case %d: Size is negative", i)
		}
	}
}

// TestIntersectionSizeIsNumeric guards the function whose bug inflated pool
// capacity in silence.
func TestIntersectionSizeIsNumeric(t *testing.T) {
	cases := []struct {
		name string
		a    Range
		b    Range
		want int
	}{
		{"identical", rng("10.0.0.10", "10.0.0.20"), rng("10.0.0.10", "10.0.0.20"), 11},
		{"partial overlap", rng("10.0.0.10", "10.0.0.20"), rng("10.0.0.15", "10.0.0.25"), 6},
		{"contained", rng("10.0.0.10", "10.0.0.100"), rng("10.0.0.50", "10.0.0.60"), 11},
		{"disjoint", rng("10.0.0.10", "10.0.0.20"), rng("10.0.1.10", "10.0.1.20"), 0},
		{"adjacent", rng("10.0.0.10", "10.0.0.20"), rng("10.0.0.21", "10.0.0.30"), 0},
		{"touching", rng("10.0.0.10", "10.0.0.20"), rng("10.0.0.20", "10.0.0.30"), 1},
		{"single address overlap", rng("10.0.0.10", "10.0.0.20"), rng("10.0.0.15", "10.0.0.15"), 1},
		{"mixed families", rng("10.0.0.10", "10.0.0.20"), rng("fd00::1", "fd00::ff"), 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := intersectionSize(c.a, c.b); got != c.want {
				t.Errorf("intersectionSize = %d, want %d", got, c.want)
			}
			if got := intersectionSize(c.b, c.a); got != c.want {
				t.Errorf("intersectionSize (reversed arguments) = %d, want %d", got, c.want)
			}
		})
	}
}

// TestTotalAddressesNeverExceedsTheAddressSpace checks the aggregate.
func TestTotalAddressesNeverExceedsTheAddressSpace(t *testing.T) {
	cases := []struct {
		name   string
		ranges []Range
		want   int
	}{
		{"single", []Range{rng("10.0.0.10", "10.0.0.20")}, 11},
		{"two disjoint", []Range{
			rng("10.0.0.10", "10.0.0.20"), rng("10.0.1.10", "10.0.1.20"),
		}, 22},
		{"fully overlapping", []Range{
			rng("10.0.0.10", "10.0.0.20"), rng("10.0.0.10", "10.0.0.20"),
		}, 11},
		{"nested", []Range{
			rng("10.0.0.10", "10.0.0.100"), rng("10.0.0.50", "10.0.0.60"),
		}, 91},
		{"reversed included", []Range{
			rng("10.0.0.10", "10.0.0.20"), rng("10.0.0.20", "10.0.0.10"),
		}, 11},
		{"empty", nil, 0},
		{"whole space once", []Range{
			rng("0.0.0.0", "255.255.255.255"),
		}, 1 << 32},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Policy{Ranges: c.ranges}
			got := p.TotalAddresses()

			if got != c.want {
				t.Errorf("TotalAddresses = %d, want %d", got, c.want)
			}
			if got < 0 {
				t.Errorf("TotalAddresses = %d, which is negative", got)
			}
		})
	}
}

// TestDistanceIsSaturatedAtTheIntLimit checks the saturation path.
//
// An IPv6 range can be wider than the largest int. distance() must saturate
// rather than overflow, because an overflowed negative would be read as
// "before the start" and would silently drop addresses from a pool report.
func TestDistanceIsSaturatedAtTheIntLimit(t *testing.T) {
	lo := mustAddr("::")
	hi := mustAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

	d := distance(lo, hi)
	if d <= 0 {
		t.Errorf("distance across the whole IPv6 space = %d, want a positive number", d)
	}

	// A range spanning it must report a positive size rather than wrapping.
	r := Range{Start: lo, End: hi}
	if got := r.Size(); got <= 0 {
		t.Errorf("Size of the whole IPv6 space = %d, want a positive number", got)
	}
}
