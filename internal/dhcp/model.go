// Package dhcp declares THN's address-assignment intent and models the
// leases it observes.
//
// # Leases are not devices
//
// A lease is temporary: a MAC address holds an address for a bounded time and
// may hold a different one after renewal. A device is persistent. Collapsing
// the two produces a model where an IP address is treated as a device
// identity, which is wrong the moment a phone changes networks and makes it
// impossible to answer "which device was that?".
//
// So the two are separate types. A Lease records one address assignment for one
// hardware address over one window of time. A Device (see internal/identity)
// records a persistent identity that leases attach to.
//
// # THN observes, it does not allocate
//
// The backing server issues and reclaims leases. THN reads what it issued,
// normalises it, persists it and correlates it with device identity. It does
// not implement a DHCP server, allocate addresses, reassign them, or delete
// leases aggressively — those operations belong to the server, and
// duplicating them would create two sources of truth about who holds what.
//
// # Backend independence
//
// The models here carry no dnsmasq concepts. The backend that produced a lease
// is recorded as an opaque source, so replacing dnsmasq with Kea does not
// change the types that the rest of THN uses.
package dhcp

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// LeaseStatus is a lease's lifecycle state.
type LeaseStatus string

const (
	// StatusActive means the lease is within its validity window.
	StatusActive LeaseStatus = "active"
	// StatusExpired means the lease's window has passed.
	StatusExpired LeaseStatus = "expired"
	// StatusReserved means the address is pinned by a reservation and the
	// server may hand it out to the reserved device only.
	StatusReserved LeaseStatus = "reserved"
	// StatusInvalid means the lease could not be parsed or is inconsistent,
	// such as an address outside its own pool.
	StatusInvalid LeaseStatus = "invalid"
)

// Lease is one address assignment observed from the backing server.
type Lease struct {
	// MAC is the hardware address, normalised to lowercase colon form.
	MAC string `json:"mac"`

	// Address is the assigned address.
	Address netip.Addr `json:"address"`

	// Hostname is the name the client reported. Empty when the client sent
	// none, which is common and not itself a fault.
	Hostname string `json:"hostname,omitempty"`

	// ClientID is the DHCP client identifier. Some clients send this in
	// preference to their MAC, and it is a stronger identity where present.
	ClientID string `json:"client_id,omitempty"`

	// VendorClass is the option 43 vendor class.
	VendorClass string `json:"vendor_class,omitempty"`

	// Start is when the lease began.
	Start time.Time `json:"lease_start"`

	// Expiry is when the lease ends.
	Expiry time.Time `json:"lease_expiry"`

	// Source records which backend reported this lease, so that a lease set
	// can be attributed after a backend change.
	Source string `json:"source,omitempty"`

	// DeviceID is the persistent identity this lease was correlated to. It is
	// empty when no device is known for the MAC, which is a normal state and
	// not an error.
	DeviceID string `json:"device_id,omitempty"`

	// FirstSeen is when THN first recorded this lease.
	FirstSeen time.Time `json:"first_seen,omitempty"`
}

// Active reports whether the lease is within its validity window at now.
func (l Lease) Active(now time.Time) bool {
	return now.Before(l.Expiry)
}

// Expired reports whether the lease has passed its window at now.
func (l Lease) Expired(now time.Time) bool { return !l.Active(now) }

// Remaining returns how long the lease has left. It is zero for an expired
// lease rather than negative, because a negative duration is almost never
// what a caller wants to render.
func (l Lease) Remaining(now time.Time) time.Duration {
	if d := l.Expiry.Sub(now); d > 0 {
		return d
	}
	return 0
}

// Status returns the lease's lifecycle state at now.
func (l Lease) Status(now time.Time) LeaseStatus {
	switch {
	case !l.Address.IsValid():
		return StatusInvalid
	case l.Expired(now):
		return StatusExpired
	default:
		return StatusActive
	}
}

// NormalisedMAC returns the MAC in lowercase colon form.
//
// dnsmasq and most tools emit uppercase; storing mixed-case forms would make
// every correlation a case-insensitive comparison and every lookup ambiguous.
func NormalisedMAC(mac string) string {
	return strings.ToLower(strings.TrimSpace(mac))
}

// Range is one address pool.
type Range struct {
	// Start is the first address.
	Start netip.Addr `json:"start"`
	// End is the last address, inclusive.
	End netip.Addr `json:"end"`
	// Netmask optionally overrides the netmask derived from the LAN prefix.
	Netmask netip.Addr `json:"netmask,omitempty"`
}

// Contains reports whether an address falls in the range.
func (r Range) Contains(addr netip.Addr) bool {
	if !r.Start.IsValid() || !r.End.IsValid() || !addr.IsValid() {
		return false
	}
	// Comparing as 4-byte values is correct for IPv4 pools and avoids the
	// unsigned subtraction that would wrap for IPv6.
	if r.Start.Is4() != addr.Is4() {
		return false
	}
	return compareAddr(addr, r.Start) >= 0 && compareAddr(addr, r.End) <= 0
}

// Size returns the number of addresses in the range.
//
// This computes a numeric distance, not a comparison: a compare function that
// returns -1/0/1 would make every multi-address range report a size of 1 or
// 2, which is wrong in a way that looks plausible in a pool-capacity report.
func (r Range) Size() int {
	if !r.Start.IsValid() || !r.End.IsValid() {
		return 0
	}
	if r.Start.Is4() != r.End.Is4() {
		return 0
	}
	if compareAddr(r.End, r.Start) < 0 {
		return 0
	}
	return distance(r.Start, r.End) + 1
}

// distance returns how many addresses separate a and b, or -1 when they are
// in different families.
func distance(a, b netip.Addr) int {
	if a.Is4() != b.Is4() {
		return -1
	}

	limit := uint64(^uint(0) >> 1)

	if a.Is4() {
		return int(toUint32(b.As4())) - int(toUint32(a.As4()))
	}

	// IPv6: compare as two 64-bit halves to stay within int range.
	ah, bh := a.As16(), b.As16()
	lo := uint64(ah[0])<<56 | uint64(ah[1])<<48 | uint64(ah[2])<<40 | uint64(ah[3])<<32 |
		uint64(ah[4])<<24 | uint64(ah[5])<<16 | uint64(ah[6])<<8 | uint64(ah[7])
	hi := uint64(bh[0])<<56 | uint64(bh[1])<<48 | uint64(bh[2])<<40 | uint64(bh[3])<<32 |
		uint64(bh[4])<<24 | uint64(bh[5])<<16 | uint64(bh[6])<<8 | uint64(bh[7])

	if hi >= lo {
		// A saturated result is fine: an IPv6 pool larger than the int range
		// does not need an exact count.
		if d := hi - lo; d < limit {
			return int(d)
		}
		return int(limit)
	}
	if d := lo - hi; d < limit {
		return -int(d)
	}
	return -int(limit)
}

// toUint32 renders an IPv4 address as a 32-bit value.
func toUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// compareAddr compares two addresses of the same family.
func compareAddr(a, b netip.Addr) int {
	ab, bb := a.As16(), b.As16()
	for i := range ab {
		if ab[i] != bb[i] {
			if ab[i] < bb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Overlaps reports whether two ranges share any address.
func (r Range) Overlaps(o Range) bool {
	return r.Contains(o.Start) || r.Contains(o.End) ||
		o.Contains(r.Start) || o.Contains(r.End)
}

// String renders the range.
func (r Range) String() string {
	if !r.Start.IsValid() || !r.End.IsValid() {
		return "(invalid)"
	}
	return fmt.Sprintf("%s-%s", r.Start, r.End)
}

// Reservation pins an address to a hardware address.
type Reservation struct {
	// MAC is the hardware address to match.
	MAC string `json:"mac"`
	// Address is the pinned address. Empty means the server may assign any.
	Address netip.Addr `json:"address,omitempty"`
	// Hostname is the name to report.
	Hostname string `json:"hostname,omitempty"`
	// LeaseTime overrides the pool default.
	LeaseTime time.Duration `json:"lease_time,omitempty"`
}

// Policy is the desired DHCP configuration, independent of any backend.
type Policy struct {
	// Enabled reports whether addresses should be served on the LAN.
	Enabled bool `json:"enabled"`

	// Interface is the interface the server listens on.
	Interface string `json:"interface,omitempty"`

	// LANPrefix is the network the server serves, used for validation and for
	// the netmask.
	LANPrefix netip.Prefix `json:"lan_prefix,omitempty"`

	// Authoritative declares this server authoritative for the LAN.
	//
	// Without it a client that cannot reach this server falls back to
	// another, so a device could obtain an address from the upstream and
	// bypass this gateway entirely.
	Authoritative bool `json:"authoritative"`

	// LeaseTime is the default lease duration.
	LeaseTime time.Duration `json:"lease_time"`

	// Ranges are the address pools.
	Ranges []Range `json:"ranges,omitempty"`

	// Reservations pin addresses to devices.
	Reservations []Reservation `json:"reservations,omitempty"`

	// LeaseMax caps concurrent leases. Zero leaves the server default.
	LeaseMax int `json:"lease_max"`

	// Domain is the local domain advertised via option 15.
	Domain string `json:"domain,omitempty"`

	// GatewayAddress is this host's address, sent as option 3.
	GatewayAddress netip.Addr `json:"gateway_address,omitempty"`

	// Backend locates the backing server's files.
	Backend BackendConfig `json:"backend"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty"`
}

// BackendConfig locates the backing server's files.
type BackendConfig struct {
	// Name identifies the backend, recorded on leases for attribution.
	Name string `json:"name"`
	// ConfigFile is the file THN generates for the server.
	ConfigFile string `json:"config_file,omitempty"`
	// LeaseFile is the file the server writes and THN reads.
	LeaseFile string `json:"lease_file,omitempty"`
}

// Default returns a policy with one pool derived from a LAN prefix.
//
// A pool of .100 through .250 leaves the first hundred addresses free for
// static hosts and for the gateway itself, which is the convention on a home
// network and leaves room for the gateway's own address to move.
func Default(lanPrefix netip.Prefix, gateway netip.Addr, iface string) Policy {
	p := Policy{
		Enabled:        true,
		Interface:      iface,
		LANPrefix:      lanPrefix.Masked(),
		Authoritative:  true,
		LeaseTime:      12 * time.Hour,
		LeaseMax:       0,
		Domain:         "lan",
		GatewayAddress: gateway,
		Backend: BackendConfig{
			Name:       "dnsmasq",
			ConfigFile: "/etc/thn/dnsmasq.conf",
			LeaseFile:  "/var/lib/thn/dnsmasq.leases",
		},
	}

	if lanPrefix.IsValid() {
		p.Ranges = DerivePool(lanPrefix, 100, 150)
	}

	return p
}

// DerivePool returns a pool of n addresses starting at offset from the
// prefix's base address.
//
// The pool is clamped to the prefix so a request for more addresses than the
// network holds does not produce a range that escapes it — which would hand
// out addresses the gateway cannot route.
func DerivePool(prefix netip.Prefix, offset, n int) []Range {
	if !prefix.IsValid() || n <= 0 || offset < 0 {
		return nil
	}

	base := prefix.Masked().Addr()
	if !base.Is4() {
		// IPv6 pools are not derived automatically: a /64 holds so many
		// addresses that a "pool" would be meaningless without SLAAC, which
		// is a different mechanism with different rules.
		return nil
	}

	bits := prefix.Bits()
	hostBits := 32 - bits
	if hostBits == 0 {
		return nil // a /32 has no room for a pool
	}

	start := addOffset(base, offset)
	end := addOffset(base, offset+n-1)

	// Clamp to the end of the network.
	last := addOffset(base, (1<<hostBits)-1)
	if compareAddr(end, last) > 0 {
		end = last
	}
	if compareAddr(start, end) > 0 {
		return nil
	}

	return []Range{{Start: start, End: end}}
}

// addOffset returns an IPv4 address advanced by n.
func addOffset(a netip.Addr, n int) netip.Addr {
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += uint32(n)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Normalise sorts the policy's collections for deterministic rendering.
func (p *Policy) Normalise() {
	sort.SliceStable(p.Ranges, func(i, j int) bool {
		return compareAddr(p.Ranges[i].Start, p.Ranges[j].Start) < 0
	})
	sort.SliceStable(p.Reservations, func(i, j int) bool {
		return p.Reservations[i].MAC < p.Reservations[j].MAC
	})
}

// TotalAddresses returns the number of addresses across all pools, after
// removing overlaps between them.
func (p Policy) TotalAddresses() int {
	total := 0
	counted := make([]Range, 0, len(p.Ranges))

	for _, r := range p.Ranges {
		if r.Size() == 0 {
			continue
		}
		// Subtract any address already covered by an accepted range.
		overlap := 0
		for _, c := range counted {
			overlap += intersectionSize(r, c)
		}
		total += r.Size() - overlap
		counted = append(counted, r)
	}
	return total
}

// intersectionSize returns how many addresses two ranges share.
//
// This uses distance, not compareAddr. A three-way comparison would return 1
// for any two distinct addresses, so every intersection would be reported as
// two addresses wide regardless of its real size — which silently inflates the
// pool capacity and hides the overlap it was meant to detect.
func intersectionSize(a, b Range) int {
	lo, hi := a.Start, a.End
	if compareAddr(b.Start, lo) > 0 {
		lo = b.Start
	}
	if compareAddr(b.End, hi) < 0 {
		hi = b.End
	}
	if compareAddr(lo, hi) > 0 {
		return 0
	}
	return distance(lo, hi) + 1
}

// String renders a one-line summary.
func (p Policy) String() string {
	return fmt.Sprintf("dhcp on %s: %d pool(s) of %d address(es), %d reservation(s), lease %s, authoritative=%t",
		orNone(p.Interface), len(p.Ranges), p.TotalAddresses(),
		len(p.Reservations), p.LeaseTime, p.Authoritative)
}

// orNone renders an empty string as a placeholder.
func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// Summary renders lease statistics for an operator.
type Summary struct {
	// Total is the number of leases observed.
	Total int `json:"total"`
	// Active counts leases within their window.
	Active int `json:"active"`
	// Expired counts leases past their window.
	Expired int `json:"expired"`
	// Reserved counts leases whose address is pinned.
	Reserved int `json:"reserved"`
	// Uncorrelated counts leases with no known device identity. A rising
	// count means THN has seen hardware it does not recognise, which is the
	// first signal of an unexpected device on the network.
	Uncorrelated int `json:"uncorrelated"`
	// AddressesInUse is the number of distinct addresses held.
	AddressesInUse int `json:"addresses_in_use"`
	// PoolCapacity is the total number of pool addresses.
	PoolCapacity int `json:"pool_capacity"`
	// PoolUtilisation is AddressesInUse / PoolCapacity, as a percentage.
	PoolUtilisation float64 `json:"pool_utilisation_percent"`
	// ShortestRemaining is the lease closest to expiry.
	ShortestRemaining time.Duration `json:"shortest_remaining"`
}

// Summarise computes statistics over a lease set at now.
//
// reservedMACs identifies leases whose address is pinned by a reservation.
// A summary computed without it reports zero reserved rather than guessing.
func Summarise(leases []Lease, poolCapacity int, now time.Time, reservedMACs map[string]bool) Summary {
	s := Summary{Total: len(leases), PoolCapacity: poolCapacity}

	seen := make(map[netip.Addr]bool, len(leases))
	for _, l := range leases {
		switch l.Status(now) {
		case StatusActive:
			s.Active++
		case StatusExpired:
			s.Expired++
		}
		if l.Address.IsValid() {
			seen[l.Address] = true
		}
		if l.DeviceID == "" {
			s.Uncorrelated++
		}
		if reservedMACs[NormalisedMAC(l.MAC)] {
			s.Reserved++
		}
		if d := l.Remaining(now); d > 0 && (s.ShortestRemaining == 0 || d < s.ShortestRemaining) {
			s.ShortestRemaining = d
		}
	}

	s.AddressesInUse = len(seen)

	if poolCapacity > 0 {
		s.PoolUtilisation = float64(s.AddressesInUse) / float64(poolCapacity) * 100
	}

	return s
}

// SortLeases orders leases by address, which is how an operator reads them.
func SortLeases(leases []Lease) {
	sort.SliceStable(leases, func(i, j int) bool {
		return compareAddr(leases[i].Address, leases[j].Address) < 0
	})
}
