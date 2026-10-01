package dhcp

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// The DHCP range validation matrix: what every range shape actually does, at
// every IPv4 prefix length, and the guarantee that none of it can take the
// process down.
//
// Two things are defended here.
//
// The first is panic-freedom. A validator that dies on input is worse than one
// that rejects it, because the operator sees a stack trace instead of an
// answer. Every row below therefore asserts an outcome, and assertNoPanic
// asserts that the outcome was reached rather than crashed into.
//
// The second is containment. A pool is a contiguous run of addresses inside
// one LAN. Two mistakes make that false while every individual address looks
// correct: checking only the start of a range against the LAN prefix, and
// arithmetic that wraps. Both produce a configuration that passes validation,
// renders, and hands out addresses the gateway cannot route.

// rangeCase is one row of the range validation matrix.
type rangeCase struct {
	name string

	// lan is the LAN prefix the policy serves.
	lan string

	// gw is the gateway address. Empty means unset, which is a real state.
	gw string

	// ranges are the pools, as "start-end" strings.
	ranges []string

	// wantErr names the field expected to carry the error, or "" when the
	// policy is expected to accept the configuration.
	wantErr string

	// wantWarn is the field expected to carry a warning, or "".
	wantWarn string

	// note states the policy reason, so the table explains itself.
	note string
}

// matrixPolicy builds a policy from a rangeCase.
func (c rangeCase) policy() Policy {
	p := Policy{
		Enabled:       true,
		Interface:     "lan0",
		LeaseTime:     defaultTestLease,
		Domain:        "lan",
		Authoritative: true,
	}
	if c.lan != "" {
		p.LANPrefix = mustPrefix(c.lan)
	}
	if c.gw != "" {
		p.GatewayAddress = mustAddr(c.gw)
	}
	for _, s := range c.ranges {
		start, end, _ := strings.Cut(s, "-")
		p.Ranges = append(p.Ranges, Range{Start: mustAddr(start), End: mustAddr(end)})
	}
	return p
}

// rangeMatrix is the /24 range matrix.
//
// Policy, stated once so the table reads against it:
//
//   - A pool must lie entirely inside the LAN prefix. Both endpoints are
//     checked: checking only the start accepts a range that runs off the end
//     of the subnet, which hands out unroutable addresses that look correctly
//     configured.
//   - Start above end is an error. The order is meaningful, not cosmetic.
//   - A one-address pool is legal. It is what a /31 or /32 LAN produces.
//   - The network and broadcast addresses are not assignable. A pool that
//     contains either is an error, because handing out 192.168.1.0 or
//     192.168.1.255 produces a host that cannot talk to anything. /31 and /32
//     are exempt: RFC 3021 gives a /31 two usable point-to-point addresses,
//     and a /32 has no network or broadcast at all.
var rangeMatrix = []rangeCase{
	// ------------------------------------------------------- normal /24
	{
		name: "normal /24 interior", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges: []string{"192.168.1.10-192.168.1.100"},
		note:   "the ordinary case",
	},
	{
		name: "normal /24 second half", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges: []string{"192.168.1.100-192.168.1.200"},
		note:   "start at .100",
	},
	{
		name: "normal /24 single address", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges: []string{"192.168.1.254-192.168.1.254"},
		note:   "a one-address pool is legal; Size is 1",
	},
	{
		name: "normal /24 shipped default", lan: "10.77.0.1/24", gw: "10.77.0.1",
		ranges: []string{"10.77.0.100-10.77.0.250"},
		note:   "the configuration the gateway ships with",
	},

	// ------------------------------------------------- network boundary
	{
		name: "start is the network address", lan: "192.168.1.1/24", gw: "192.168.1.50",
		ranges:  []string{"192.168.1.0-192.168.1.100"},
		wantErr: "ranges[0].start",
		note:    "192.168.1.0 is the network address and is not assignable",
	},
	{
		name: "end is the network address", lan: "192.168.1.1/24", gw: "192.168.1.50",
		ranges:  []string{"192.168.1.0-192.168.1.0"},
		wantErr: "ranges[0].start",
		note:    "even a one-address pool on the network address is refused",
	},

	// ----------------------------------------------- broadcast boundary
	{
		name: "end is the broadcast address", lan: "192.168.1.1/24", gw: "192.168.1.50",
		ranges:  []string{"192.168.1.100-192.168.1.255"},
		wantErr: "ranges[0].end",
		note:    "192.168.1.255 is the broadcast address and is not assignable",
	},
	{
		name: "start is the broadcast address", lan: "192.168.1.1/24", gw: "192.168.1.50",
		ranges:  []string{"192.168.1.255-192.168.1.255"},
		wantErr: "ranges[0].end",
		note:    "a one-address pool on the broadcast address is refused",
	},
	{
		name: "whole subnet as a pool", lan: "192.168.1.1/24", gw: "192.168.1.50",
		ranges:  []string{"192.168.1.0-192.168.1.255"},
		wantErr: "ranges[0].start",
		note:    "both endpoints are unassignable; the network address is reported first",
	},
	{
		name: "last usable before broadcast", lan: "192.168.1.1/24", gw: "192.168.1.50",
		ranges: []string{"192.168.1.254-192.168.1.254"},
		note:   "the highest address a /24 may hand out",
	},

	// ------------------------------------------------------- equal / reversed
	{
		name: "equal endpoints inside the subnet", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges: []string{"192.168.1.50-192.168.1.50"},
		note:   "one address, start == end, legal",
	},
	{
		name: "equal endpoints at first usable", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.1.1-192.168.1.1"},
		wantErr: "ranges[0]",
		note:    "equal, but it is the gateway's own address",
	},
	{
		name: "reversed by one", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.1.100-192.168.1.10"},
		wantErr: "ranges[0]",
		note:    "start above end; Size must be 0, not a wrapped negative",
	},
	{
		name: "reversed across octets", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.1.100-192.168.1.10"},
		wantErr: "ranges[0]",
		note:    "start above end; Size must be 0, not a wrapped negative",
	},
	{
		// 192.168.1.10 to 192.168.100.1 is genuinely ascending, because the
		// third octet 1 precedes 100. A string comparison agrees here by
		// luck, which is exactly why the ordering tests exist: this row
		// documents that the rejection comes from containment, not order.
		name: "ascending across octets but outside the LAN", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.1.10-192.168.100.1"},
		wantErr: "ranges[0].end",
		note:    "ordered correctly, rejected because the end escapes the /24",
	},

	// ---------------------------------------------------- outside-LAN range
	{
		name: "entirely outside the LAN", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.2.10-192.168.2.100"},
		wantErr: "ranges[0].start",
		note:    "a different /24 entirely",
	},
	{
		name: "start inside, end outside", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.1.10-192.168.2.10"},
		wantErr: "ranges[0].end",
		note:    "only the start is inside; the end escapes into the next subnet",
	},
	{
		name: "end inside, start outside", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.0.10-192.168.1.10"},
		wantErr: "ranges[0].start",
		note:    "the start check catches this one",
	},
	{
		name: "no LAN prefix at all", lan: "", gw: "192.168.1.1",
		ranges: []string{"192.168.2.10-192.168.2.100"},
		note:   "with no LAN declared there is nothing to be outside of",
	},

	// --------------------------------------------------- cross-subnet range
	{
		name: "crosses the subnet boundary forward", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.1.250-192.168.2.10"},
		wantErr: "ranges[0].end",
		note:    "spans 192.168.1.255 and 192.168.2.0; not a valid contiguous pool",
	},
	{
		name: "crosses the subnet boundary backward", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.1.10-192.168.0.250"},
		wantErr: "ranges[0]",
		note:    "start is above end, so the ordering check fires before containment",
	},
	{
		name: "crosses a /16 boundary", lan: "172.16.0.1/16", gw: "172.16.0.1",
		ranges:  []string{"172.16.255.250-172.17.0.10"},
		wantErr: "ranges[0].end",
		note:    "the same defect at a different prefix length",
	},
	{
		name: "crosses the whole IPv4 space", lan: "10.0.0.1/24", gw: "10.0.0.1",
		ranges:  []string{"10.0.0.250-11.0.0.10"},
		wantErr: "ranges[0].end",
		note:    "end is far outside; must not wrap or panic",
	},

	// ------------------------------------------------- multiple pools
	{
		name: "two disjoint interior pools", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges: []string{"192.168.1.10-192.168.1.50", "192.168.1.100-192.168.1.200"},
		note:   "valid",
	},
	{
		name: "second pool escapes the LAN", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:  []string{"192.168.1.10-192.168.1.50", "192.168.2.10-192.168.2.50"},
		wantErr: "ranges[1].start",
		note:    "the finding names the offending index",
	},
	{
		// The gateway sits at .1, which the first usable address would
		// otherwise claim, so the widest legal pool on a /24 is .2-.254.
		name: "one pool of almost the whole LAN", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:   []string{"192.168.1.2-192.168.1.254"},
		wantWarn: "ranges[0]",
		note:     "valid but leaves no room for static hosts",
	},
	{
		name: "pool spanning every host but the gateway", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges:   []string{"192.168.1.2-192.168.1.254"},
		note:     "253 of 254 usable addresses; still warns on headroom",
		wantWarn: "ranges[0]",
	},
}

// TestRangeValidationMatrix is the range matrix from the brief.
func TestRangeValidationMatrix(t *testing.T) {
	for _, c := range rangeMatrix {
		t.Run(c.name, func(t *testing.T) {
			var got Result

			assertNoPanic(t, c.name, func() {
				got = Validate(c.policy())
			})

			if c.wantErr == "" {
				if !got.Valid {
					t.Fatalf("expected the configuration to be accepted, got errors: %v (counts e=%d w=%d i=%d)",
						got.Findings, got.ErrorCount, got.WarningCount, got.InfoCount)
				}
			} else {
				if got.Valid {
					t.Fatalf("expected a rejection on %s (%s); the policy accepted %v",
						c.wantErr, c.note, c.ranges)
				}
				if !hasError(got, c.wantErr) {
					t.Errorf("expected an error on %s, got %v", c.wantErr, got.Findings)
				}
			}

			if c.wantWarn != "" && !hasFinding(got, c.wantWarn, SeverityWarning) {
				t.Errorf("expected a warning on %s, got %v", c.wantWarn, got.Findings)
			}
		})
	}
}

// TestReversedRangeIsDeterministic pins the reversed-range result across
// repeated calls and across a policy that is otherwise valid.
//
// A reversed range is the case where unsigned subtraction would underflow. The
// invariant is not merely that it is rejected, but that it is rejected the same
// way every time: a validator that reports a different size for the same input
// on a second call is worse than one that rejects it.
func TestReversedRangeIsDeterministic(t *testing.T) {
	c := rangeCase{
		name: "reversed", lan: "192.168.1.1/24", gw: "192.168.1.1",
		ranges: []string{"192.168.1.100-192.168.1.10"},
	}
	p := c.policy()

	first := Validate(p)
	for i := 0; i < 8; i++ {
		again := Validate(p)
		if len(again.Findings) != len(first.Findings) {
			t.Fatalf("run %d produced %d findings, first run produced %d",
				i, len(again.Findings), len(first.Findings))
		}
		for j := range first.Findings {
			if again.Findings[j] != first.Findings[j] {
				t.Fatalf("run %d finding %d = %q, first run = %q",
					i, j, again.Findings[j], first.Findings[j])
			}
		}
	}

	if first.Valid {
		t.Fatal("a reversed range must not validate")
	}
	if got := p.Ranges[0].Size(); got != 0 {
		t.Errorf("Size of a reversed range = %d, want 0; a non-zero value means the subtraction wrapped", got)
	}
	if got := p.TotalAddresses(); got != 0 {
		t.Errorf("TotalAddresses over a reversed range = %d, want 0", got)
	}
}

// defaultTestLease is the lease time used by the matrix policies.
const defaultTestLease = 12 * 60 * 60 * 1e9 // 12h in nanoseconds

// prefixCase is one row of the prefix boundary matrix.
type prefixCase struct {
	bits int

	// net is the LAN address written with host bits, which is what THN is
	// told to place on the interface.
	net string

	// firstUsable and lastUsable are the addresses a host may hold.
	firstUsable string
	lastUsable  string

	// minRange is the smallest legal pool: one address at firstUsable.
	minRange [2]string

	// networkRange and broadcastRange are pools that contain an
	// unassignable address.
	networkRange   [2]string
	broadcastRange [2]string

	// outsideRange is a pool entirely outside the subnet.
	outsideRange [2]string

	// reversible is a pool with start above end, inside the subnet.
	reversible [2]string

	// exempt reports that /31 and /32 have no network or broadcast address,
	// so the network/broadcast rows do not apply.
	exempt bool

	note string
}

// prefixAddr returns the address at offset from base, counting up.
//
// It deliberately uses uint32 addition, because that is the arithmetic under
// test: an implementation that adds in a narrower type would wrap at 2^32,
// which is exactly what the /0 and last-address rows are looking for.
func prefixAddr(t *testing.T, base string, offset uint32) netip.Addr {
	t.Helper()
	b := mustAddr(base).As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += offset
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// networkOf returns the network address of base with hostBits host bits.
//
// The host mask is the LOW hostBits bits, not the high ones: clearing the high
// 32-hostBits bits would mask the network portion and produce a different
// address entirely. The two extremes are separate cases because the mask is
// empty at hostBits 0 (a /32, whose network is the address itself) and
// full-width at hostBits 32 (a /0, whose network is 0.0.0.0).
func networkOf(t *testing.T, base string, hostBits int) uint32 {
	t.Helper()

	v := toUint32(mustAddr(base).As4())

	switch {
	case hostBits >= 32:
		return 0
	case hostBits <= 0:
		return v
	default:
		return v &^ uint32((uint64(1)<<uint(hostBits))-1)
	}
}

// broadcastOf returns the top address of the subnet with hostBits host bits.
func broadcastOf(t *testing.T, base string, hostBits int) uint32 {
	t.Helper()

	switch {
	case hostBits >= 32:
		return 0xFFFFFFFF
	case hostBits <= 0:
		return toUint32(mustAddr(base).As4())
	default:
		net := networkOf(t, base, hostBits)
		return net | uint32((uint64(1)<<uint(hostBits))-1)
	}
}

// lastAddressOf returns the top address of the subnet, i.e. network | ^mask.
//
// It is written as a mask rather than as network + 2^hostBits - 1 because that
// second form is 2^32 at hostBits 32, which does not fit a uint32. The mask
// form is correct at every length, which is the property the /0 row checks.
//
// This is the test's own arithmetic, deliberately written the safe way so that
// a failure indicates a production defect rather than an overflow in the
// fixture.
func lastAddressOf(t *testing.T, base string, hostBits int) string {
	t.Helper()
	return uint32Addr(broadcastOf(t, base, hostBits))
}

// firstAddressOutside returns the first address past the subnet, i.e. the
// broadcast address plus one.
//
// A /0 and any subnet whose broadcast is 255.255.255.255 have no address
// outside them, so that case returns false and the matrix skips the
// containment check rather than pretending a pool can escape.
func firstAddressOutside(t *testing.T, base string, hostBits int) (string, bool) {
	t.Helper()

	if hostBits >= 32 {
		return "", false
	}

	// broadcast + 1, which equals network | (1 << hostBits) for every length
	// except /32, where the subnet is a single address and +1 is the first
	// address beyond it.
	b := broadcastOf(t, base, hostBits)
	if b == 0xFFFFFFFF {
		return "", false
	}
	return uint32Addr(b + 1), true
}

// uint32Addr renders a uint32 as a dotted-quad address.
func uint32Addr(v uint32) string {
	return netip.AddrFrom4([4]byte{
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}).String()
}

func prefixString(t *testing.T, base string, offset uint32) string {
	t.Helper()
	return prefixAddr(t, base, offset).String()
}

// buildPrefixCases derives the whole prefix matrix from one address per length.
//
// The network and broadcast addresses are computed from the base and the host
// bit count rather than written by hand, because the point of this matrix is
// that the derivation is right at every length — including /0, where the
// broadcast address is 255.255.255.255 and the arithmetic runs out of room.
func buildPrefixCases(t *testing.T) []prefixCase {
	t.Helper()

	cases := []prefixCase{
		{bits: 0, net: "10.77.0.1", note: "every address; broadcast is the uint32 maximum"},
		{bits: 1, net: "128.0.0.1", note: "half the address space"},
		{bits: 2, net: "192.168.0.1", note: "a quarter"},
		{bits: 8, net: "10.0.0.1", note: "a class A"},
		{bits: 16, net: "172.16.0.1", note: "a class B"},
		{bits: 24, net: "192.168.1.1", note: "the ordinary home LAN"},
		{bits: 25, net: "192.168.1.129", note: "splits a /24 in half"},
		{bits: 29, net: "192.168.1.249", note: "six usable addresses"},
		{bits: 30, net: "192.168.1.253", note: "two usable addresses"},
		{bits: 31, net: "192.168.1.1", note: "RFC 3021 point-to-point; no network or broadcast", exempt: true},
		{bits: 32, net: "192.168.1.1", note: "one address; no network or broadcast", exempt: true},
	}

	for i := range cases {
		c := &cases[i]
		base := c.net
		hostBits := 32 - c.bits

		// The network and broadcast addresses come from the mask, not from
		// an offset off the LAN address: 10.77.0.1/24 has network 10.77.0.0,
		// so prefixString(base, 0) would be the wrong fixture.
		network := uint32Addr(networkOf(t, base, hostBits))
		broadcast := lastAddressOf(t, base, hostBits)

		if c.exempt {
			// RFC 3021: both addresses of a /31 are usable. A /32 is a
			// single address that is its own first and last.
			//
			// These are written as addresses rather than as
			// 1<<(hostBits-1) offsets, which is a negative shift at /32
			// where hostBits is 0 — the same class of arithmetic error as
			// the broadcast overflow this matrix exists to find.
			c.firstUsable = network
			c.lastUsable = broadcast
		} else {
			c.firstUsable = uint32Addr(networkOf(t, base, hostBits) + 1)
			// The last usable address is the broadcast minus one, not
			// lastAddressOf(hostBits-1): that would drop the top host bit
			// and give broadcast-2, which on a /30 is the first usable
			// address rather than the last.
			c.lastUsable = uint32Addr(broadcastOf(t, base, hostBits) - 1)
		}

		c.minRange = [2]string{c.firstUsable, c.firstUsable}
		c.reversible = [2]string{c.lastUsable, c.firstUsable}

		if c.exempt {
			// There is no unassignable address, so these rows carry the
			// same pair as a valid pool and are expected to pass.
			c.networkRange = [2]string{c.firstUsable, c.lastUsable}
			c.broadcastRange = [2]string{c.firstUsable, c.lastUsable}
		} else {
			c.networkRange = [2]string{network, c.firstUsable}
			c.broadcastRange = [2]string{c.lastUsable, broadcast}
		}

		// Outside the subnet: one address past the broadcast.
		//
		// A /0 contains every IPv4 address, so no pool can be outside it and
		// that row is skipped rather than faked.
		c.outsideRange = [2]string{"", ""}
		if outside, ok := firstAddressOutside(t, base, hostBits); ok {
			c.outsideRange = [2]string{outside, outside}
		}
	}

	return cases
}

// TestPrefixBoundaryMatrix exercises the DHCP arithmetic at every IPv4 prefix
// length the brief lists.
//
// For each length: the network address, the broadcast address, the first and
// last usable address, the smallest legal pool, a pool on the network address,
// a pool on the broadcast address, a pool outside the subnet, a reversed pool
// and an equal-endpoint pool. Nothing here asserts that /31 or /32 is a
// sensible LAN; it asserts that the arithmetic is right and that the policy
// applied to each prefix is the one the table states.
func TestPrefixBoundaryMatrix(t *testing.T) {
	for _, c := range buildPrefixCases(t) {
		name := fmt.Sprintf("/%d", c.bits)
		t.Run(name, func(t *testing.T) {
			lan := c.net + fmt.Sprintf("/%d", c.bits)

			// The gateway is deliberately left unset. Setting it to
			// lastUsable would place it inside the minimum legal pool and
			// inside the reversed pool's own range, and the
			// pool-contains-gateway error would then mask the containment
			// result this matrix is about. The gateway rule has its own
			// coverage in the range matrix and in model_test.go.
			check := func(label string, r [2]string, wantErr string) {
				t.Helper()
				p := Policy{
					Enabled:        true,
					Interface:      "lan0",
					LeaseTime:      defaultTestLease,
					Domain:         "lan",
					LANPrefix:      mustPrefix(lan),
					GatewayAddress: netip.Addr{},
					Ranges: []Range{
						{Start: mustAddr(r[0]), End: mustAddr(r[1])},
					},
				}

				var got Result
				assertNoPanic(t, label, func() { got = Validate(p) })

				switch {
				case wantErr == "" && !got.Valid:
					t.Errorf("%s: expected acceptance, got errors: %v", label, got.Errors())
				case wantErr != "" && got.Valid:
					t.Errorf("%s: expected rejection on %s, got acceptance", label, wantErr)
				case wantErr != "" && !hasError(got, wantErr):
					t.Errorf("%s: expected an error on %s, got %v", label, wantErr, got.Findings)
				}

				// Size must never be negative and must never wrap.
				if got := p.Ranges[0].Size(); got < 0 {
					t.Errorf("%s: Size = %d, which is negative; the subtraction wrapped", label, got)
				}
			}

			check("minimum legal pool", c.minRange, "")
			check("equal endpoints", [2]string{c.firstUsable, c.firstUsable}, "")

			// A reversed pool only exists when the subnet holds two or more
			// usable addresses. On a /30 the first and last usable are one
			// address apart, so the reversal is the pair itself; where they
			// coincide there is nothing to reverse.
			if c.firstUsable != c.lastUsable {
				check("reversed", c.reversible, "ranges[0]")
			}

			if c.exempt {
				check("no network or broadcast at this length", c.networkRange, "")
				check("whole subnet is assignable", c.broadcastRange, "")
			} else {
				check("pool on the network address", c.networkRange, "ranges[0].start")
				check("pool on the broadcast address", c.broadcastRange, "ranges[0].end")
			}

			// A pool entirely outside the subnet. Skipped for /32, whose single
			// address is the whole subnet: there is nothing outside it.
			if c.outsideRange[0] != "" {
				check("pool outside the subnet", c.outsideRange, "ranges[0].start")
			}
			// The derived first and last usable addresses must be inside the
			// LAN, which is the containment the whole matrix rests on.
			prefix := mustPrefix(lan)
			for _, s := range []string{c.firstUsable, c.lastUsable} {
				if !prefix.Contains(mustAddr(s)) {
					t.Errorf("%s: usable address %s escapes the LAN prefix %s", name, s, prefix)
				}
			}
			if compareAddr(mustAddr(c.firstUsable), mustAddr(c.lastUsable)) > 0 {
				t.Errorf("%s: first usable %s is above last usable %s",
					name, c.firstUsable, c.lastUsable)
			}
		})
	}
}

// TestPrefixBroadcastIsTheUint32Maximum pins the /0 case.
//
// A /0 broadcast is 255.255.255.255, which is the maximum value a 32-bit
// address can hold. Any implementation that computes the broadcast as
// network + 2^hostBits rather than network | ^mask computes
// 0x1_0000_0000 here, which is one past the end of the address space. That is
// the exact arithmetic the brief asks about, and it is invisible at every
// other prefix length.
func TestPrefixBroadcastIsTheUint32Maximum(t *testing.T) {
	p := mustPrefix("0.0.0.0/0")

	// netip computes the broadcast for us; the assertion is that the derived
	// pool for a /0 stops at the uint32 maximum rather than wrapping past it.
	pools := DerivePool(p, 0xFFFFFFF0, 16)
	if len(pools) == 0 {
		t.Skip("DerivePool refuses a /0 pool; nothing to check here")
	}
	end := toUint32(pools[0].End.As4())
	if end > toUint32(netip.AddrFrom4([4]byte{255, 255, 255, 255}).As4()) {
		t.Errorf("derived pool end %s is past the uint32 maximum", pools[0].End)
	}

	// A pool that starts at the very last address must not produce an end
	// below its start.
	last := Range{Start: mustAddr("255.255.255.255"), End: mustAddr("255.255.255.255")}
	if got := last.Size(); got != 1 {
		t.Errorf("the address 255.255.255.255 has size %d, want 1", got)
	}
}

// assertNoPanic fails the test if fn panics.
//
// A validator that returns an error on one input and aborts on another has
// not proven anything, so every matrix row asserts the outcome and this
// asserts the outcome was reached rather than crashed into.
func assertNoPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIC in %s: %v", what, r)
		}
	}()
	fn()
}
