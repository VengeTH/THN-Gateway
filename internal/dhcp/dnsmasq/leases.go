package dnsmasq

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/dhcp"
)

// BackendName identifies this backend on the leases it reports.
const BackendName = "dnsmasq"

// ParseError describes a malformed lease file line.
//
// The parser records an error per bad line rather than aborting, because a
// lease file is append-only and a single truncated line — which happens when
// dnsmasq is killed mid-write — must not make the whole file unreadable. The
// error is surfaced so the operator knows part of the table was skipped.
type ParseError struct {
	// Line is the one-based line number.
	Line int `json:"line"`
	// Content is the offending line.
	Content string `json:"content"`
	// Message describes the problem.
	Message string `json:"message"`
}

// ParseResult is the outcome of parsing a lease file.
type ParseResult struct {
	// Leases are the successfully parsed leases, in file order.
	Leases []dhcp.Lease `json:"leases"`
	// Errors are the malformed lines that were skipped.
	Errors []ParseError `json:"errors,omitempty"`
	// Lines is the number of non-empty lines read.
	Lines int `json:"lines"`
	// Skipped is the number of lines that could not be parsed.
	Skipped int `json:"skipped"`
}

// ParseLeases reads dnsmasq's lease file format.
//
// The format is one lease per line, space separated:
//
//	<expiry> <mac> <address> <hostname> <client-id>
//
// A zero expiry means the lease does not expire, which dnsmasq uses for
// static configuration. An absent hostname or client id is written as "*".
//
// ParseLeases never fails on a bad line: it records the problem and continues.
// A lease file is appended to while dnsmasq runs, so the last line is
// routinely partial, and refusing to read the file because of it would mean
// THN sees no leases at all rather than all but one.
func ParseLeases(content string, source string) ParseResult {
	var res ParseResult

	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		res.Lines++

		lease, err := parseLine(trimmed, source)
		if err != nil {
			res.Errors = append(res.Errors, ParseError{
				Line:    i + 1,
				Content: trimmed,
				Message: err.Error(),
			})
			res.Skipped++
			continue
		}

		res.Leases = append(res.Leases, *lease)
	}

	return res
}

// parseLine parses one lease file line.
func parseLine(line, source string) (*dhcp.Lease, error) {
	// dnsmasq separates fields with a single space, but a hostname may
	// itself contain no spaces, so a plain SplitN is sufficient and more
	// robust than expecting an exact field count.
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil, fmt.Errorf("expected at least 3 fields (expiry, mac, address), got %d", len(fields))
	}

	expiry, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("expiry %q is not a unix timestamp", fields[0])
	}

	mac := dhcp.NormalisedMAC(fields[1])
	if !isValidMAC(mac) {
		return nil, fmt.Errorf("MAC %q is not a valid hardware address", fields[1])
	}

	addr, err := netip.ParseAddr(fields[2])
	if err != nil {
		return nil, fmt.Errorf("address %q is not valid", fields[2])
	}

	l := &dhcp.Lease{
		MAC:     mac,
		Address: addr,
		Source:  source,
	}

	// A zero expiry means the lease never lapses.
	if expiry == 0 {
		l.Start = time.Time{}
		l.Expiry = time.Unix(1<<40, 0).UTC() // far future, effectively infinite
	} else {
		l.Expiry = time.Unix(expiry, 0).UTC()
		// dnsmasq does not record the start time, only the expiry. Deriving
		// it from the configured lease time is approximate, so it is left
		// zero rather than guessed: an invented start time would be
		// indistinguishable from a real one once stored.
		l.Start = time.Time{}
	}

	if len(fields) >= 4 && fields[3] != "*" && fields[3] != "" {
		l.Hostname = fields[3]
	}
	if len(fields) >= 5 && fields[4] != "*" && fields[4] != "" {
		l.ClientID = fields[4]
	}

	return l, nil
}

// isValidMAC reports whether s is a valid colon-separated MAC address.
func isValidMAC(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i := 0; i < 17; i++ {
		if i%3 == 2 {
			if s[i] != ':' {
				return false
			}
			continue
		}
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// FormatLease renders a lease back into dnsmasq's file format.
//
// This exists so that a round trip can be verified: writing what was parsed
// and re-parsing it must produce the same leases. It is also what a future
// lease writer would use, though this build has none.
func FormatLease(l dhcp.Lease) string {
	hostname := l.Hostname
	if hostname == "" {
		hostname = "*"
	}
	clientID := l.ClientID
	if clientID == "" {
		clientID = "*"
	}

	expiry := int64(0)
	if !l.Expiry.IsZero() {
		expiry = l.Expiry.Unix()
		// An expiry beyond the representable range means "infinite", which
		// dnsmasq writes as zero.
		if expiry > 1<<40 {
			expiry = 0
		}
	}

	addr := ""
	if l.Address.IsValid() {
		addr = l.Address.String()
	}

	return fmt.Sprintf("%d %s %s %s %s", expiry, dhcp.NormalisedMAC(l.MAC), addr, hostname, clientID)
}

// FormatLeases renders a lease set in file format, one per line.
func FormatLeases(leases []dhcp.Lease) string {
	var b strings.Builder
	for _, l := range leases {
		b.WriteString(FormatLease(l))
		b.WriteString("\n")
	}
	return b.String()
}

// Reconcile compares an observed lease set against a previously known set and
// reports what changed.
//
// This is what makes lease synchronisation useful rather than merely
// repetitive: it answers "what is new, what has expired, what moved" without
// THN having to keep every historical lease forever.
type Reconciliation struct {
	// Added are leases not in the previous set.
	Added []dhcp.Lease `json:"added"`
	// Gone are leases in the previous set that are no longer present.
	Gone []dhcp.Lease `json:"gone"`
	// Moved are leases whose address changed for the same hardware address.
	Moved []MovedLease `json:"moved,omitempty"`
	// Unchanged counts leases present in both sets with the same address.
	Unchanged int `json:"unchanged"`
}

// MovedLease records one hardware address changing its address.
type MovedLease struct {
	// MAC is the hardware address.
	MAC string `json:"mac"`
	// From is the previous address.
	From netip.Addr `json:"from"`
	// To is the current address.
	To netip.Addr `json:"to"`
	// Hostname is the name reported, when known.
	Hostname string `json:"hostname,omitempty"`
}

// Reconcile compares previous and current lease sets.
//
// A lease that changed address is reported as Moved rather than as one
// addition and one removal, because "this phone got a new address" and "this
// phone and that laptop appeared" are very different things to an operator.
func Reconcile(previous, current []dhcp.Lease) Reconciliation {
	var r Reconciliation

	prevByMAC := make(map[string]dhcp.Lease, len(previous))
	for _, l := range previous {
		prevByMAC[dhcp.NormalisedMAC(l.MAC)] = l
	}

	curByMAC := make(map[string]bool, len(current))

	for _, l := range current {
		mac := dhcp.NormalisedMAC(l.MAC)
		curByMAC[mac] = true

		prev, existed := prevByMAC[mac]
		switch {
		case !existed:
			r.Added = append(r.Added, l)
		case prev.Address != l.Address:
			r.Moved = append(r.Moved, MovedLease{
				MAC:      mac,
				From:     prev.Address,
				To:       l.Address,
				Hostname: l.Hostname,
			})
		default:
			r.Unchanged++
		}
	}

	for _, l := range previous {
		if !curByMAC[dhcp.NormalisedMAC(l.MAC)] {
			r.Gone = append(r.Gone, l)
		}
	}

	return r
}

// ReservedMACs returns the set of hardware addresses pinned by reservations.
func ReservedMACs(reservations []dhcp.Reservation) map[string]bool {
	out := make(map[string]bool, len(reservations))
	for _, r := range reservations {
		out[dhcp.NormalisedMAC(r.MAC)] = true
	}
	return out
}
