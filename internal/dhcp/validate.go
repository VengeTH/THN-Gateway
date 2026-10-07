package dhcp

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Severity classifies a validation finding.
type Severity string

const (
	// SeverityError means the policy must not be rendered.
	SeverityError Severity = "error"
	// SeverityWarning means it is renderable but likely wrong.
	SeverityWarning Severity = "warning"
	// SeverityInfo is informational, typically the development state.
	SeverityInfo Severity = "info"
)

// rank orders severities for sorting.
func (s Severity) rank() int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

// Finding is a single validation result.
type Finding struct {
	// Field is the dotted path of the offending setting.
	Field string `json:"field"`

	// Code is the stable, machine-readable reason.
	//
	// Field alone is not sufficient to tell two findings apart: "ranges[0]"
	// is produced by a reversed pool, an overlapping pool and a pool that
	// contains the gateway's own address, and an operator or a UI that wants
	// to react to one of those specifically cannot. The code is the
	// vocabulary a consumer dispatches on; Message is free to be reworded.
	//
	// Empty where this package has not yet classified the finding. Callers
	// must treat an empty code as "unclassified", never as a match.
	Code string `json:"code,omitempty"`

	// Severity classifies the finding.
	Severity Severity `json:"severity"`
	// Message describes the problem.
	Message string `json:"message"`
	// Hint suggests a correction.
	Hint string `json:"hint,omitempty"`
}

// String renders a finding for terminal output.
func (f Finding) String() string {
	s := fmt.Sprintf("[%s] %s: %s", f.Severity, f.Field, f.Message)
	if f.Hint != "" {
		s += " (" + f.Hint + ")"
	}
	return s
}

// Result aggregates the findings of a validation pass.
type Result struct {
	// Findings are all results, sorted by severity.
	Findings []Finding `json:"findings"`
	// Valid reports that no error-level finding was raised.
	Valid bool `json:"valid"`
	// ErrorCount, WarningCount and InfoCount summarise the findings.
	ErrorCount   int `json:"error_count"`
	WarningCount int `json:"warning_count"`
	InfoCount    int `json:"info_count"`
}

// Finding codes.
//
// These are the stable, machine-readable reasons a DHCP intent is not
// satisfied. They are a vocabulary, not sentences: a UI groups on them, a CI
// log greps them, and a future automated remediation dispatches on them. The
// human text beside them is free to be reworded; these are not.
const (
	// CodeDisabled means the document does not ask for DHCP.
	CodeDisabled = "dhcp-disabled"

	// CodeLANMissing means DHCP was requested with no LAN to serve.
	CodeLANMissing = "dhcp-lan-missing"

	// CodeLANUnresolved means the LAN role is written down but matches no
	// observed interface.
	//
	// Unresolved is pending, not broken: the interface may simply not be
	// attached yet. See gateway.CodeRoleUnresolved for the same distinction
	// applied one layer up.
	CodeLANUnresolved = "dhcp-lan-unresolved"

	// CodeLANAddressMissing means DHCP was requested but the LAN has no
	// address, so there is no subnet a pool could belong to.
	CodeLANAddressMissing = "dhcp-lan-address-missing"

	// CodeRangeMissing means DHCP is enabled with no pool to hand out.
	CodeRangeMissing = "dhcp-range-missing"

	// CodeRangeInvalid means a pool bound is not a usable address, or the two
	// bounds are of different address families.
	CodeRangeInvalid = "dhcp-range-invalid"

	// CodeRangeReversed means a pool's start is above its end.
	CodeRangeReversed = "dhcp-range-reversed"

	// CodeRangeOutsideLAN means a pool leaves the LAN subnet.
	CodeRangeOutsideLAN = "dhcp-range-outside-lan"

	// CodeRangeIncludesGateway means a pool contains the gateway's own
	// address, which would eventually be handed to a client.
	CodeRangeIncludesGateway = "dhcp-range-includes-gateway"

	// CodeLeaseInvalid means the lease time or cap cannot be honoured.
	CodeLeaseInvalid = "dhcp-lease-invalid"

	// CodeDomainInvalid means the advertised local domain is not a name.
	CodeDomainInvalid = "dhcp-domain-invalid"

	// CodeReservationInvalid means a reservation cannot be honoured.
	CodeReservationInvalid = "dhcp-reservation-invalid"

	// CodeRangeOverlap means two pools would hand out the same address.
	CodeRangeOverlap = "dhcp-range-overlap"

	// CodeInterfaceMissing means DHCP is enabled with no interface to serve.
	CodeInterfaceMissing = "dhcp-interface-missing"
)

// add appends a finding.
func (r *Result) add(field string, sev Severity, msg, hint string) {
	r.Findings = append(r.Findings, Finding{Field: field, Severity: sev, Message: msg, Hint: hint})
}

// addC appends a finding carrying a stable classification code.
func (r *Result) addC(code, field string, sev Severity, msg, hint string) {
	r.Findings = append(r.Findings, Finding{Field: field, Code: code, Severity: sev, Message: msg, Hint: hint})
}

// errorf appends an error finding.
func (r *Result) errorf(field, msg, hint string) { r.add(field, SeverityError, msg, hint) }

// errorc appends an error finding carrying a stable classification code.
func (r *Result) errorc(code, field, msg, hint string) {
	r.addC(code, field, SeverityError, msg, hint)
}

// warnf appends a warning finding.
func (r *Result) warnf(field, msg, hint string) { r.add(field, SeverityWarning, msg, hint) }

// warnc appends a warning finding carrying a stable classification code.
func (r *Result) warnc(code, field, msg, hint string) {
	r.addC(code, field, SeverityWarning, msg, hint)
}

// infof appends an informational finding.
func (r *Result) infof(field, msg, hint string) { r.add(field, SeverityInfo, msg, hint) }

// infoc appends an informational finding carrying a stable classification code.
func (r *Result) infoc(code, field, msg, hint string) {
	r.addC(code, field, SeverityInfo, msg, hint)
}

// Errors returns the error-level findings.
func (r Result) Errors() []Finding { return r.bySeverity(SeverityError) }

// bySeverity returns findings of one severity.
func (r Result) bySeverity(s Severity) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

// Error is the first error-level finding as a Go error, or nil.
func (r Result) Err() error {
	if f := r.firstError(); f != nil {
		return fmt.Errorf("%s: %s", f.Field, f.Message)
	}
	return nil
}

// firstError returns the first error finding, or nil.
func (r Result) firstError() *Finding {
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			g := f
			return &g
		}
	}
	return nil
}

// finalise counts, sorts and sets Valid.
func (r *Result) finalise() {
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityError:
			r.ErrorCount++
		case SeverityWarning:
			r.WarningCount++
		default:
			r.InfoCount++
		}
	}
	r.Valid = r.ErrorCount == 0

	// Sorting by severity keeps the reason for a refusal at the top of the
	// output, which is the first thing an operator reads.
	for i := 1; i < len(r.Findings); i++ {
		for j := i; j > 0 && r.Findings[j].Severity.rank() < r.Findings[j-1].Severity.rank(); j-- {
			r.Findings[j], r.Findings[j-1] = r.Findings[j-1], r.Findings[j]
		}
	}
}

// Validate checks a DHCP policy for renderability.
//
// The checks concentrate on the failures that would be discovered by clients
// rather than by THN: a pool outside the LAN prefix hands out unroutable
// addresses, and an omitted router option leaves clients with no gateway. Both
// look like a working server and produce a broken network.
func Validate(p Policy) Result {
	var r Result

	validateBasics(&r, p)
	validateRanges(&r, p)
	validateReservations(&r, p)

	r.finalise()
	return r
}

// validateBasics checks the policy's overall shape.
func validateBasics(r *Result, p Policy) {
	if !p.Enabled {
		r.infoc(CodeDisabled, "enabled",
			"DHCP is disabled; clients on the LAN would have to be configured statically", "")
		return
	}

	if p.Interface == "" {
		r.infoc(CodeInterfaceMissing, "interface",
			"no interface is configured, so the server would listen on every interface including the WAN",
			"set the interface once the LAN is identified")
	}

	switch {
	case p.LeaseTime == 0:
		r.errorc(CodeLeaseInvalid, "lease_time", "the lease time must be set",
			"use 12h; a zero lease time would expire every address immediately")
	case p.LeaseTime < 5*time.Minute:
		r.errorc(CodeLeaseInvalid, "lease_time",
			fmt.Sprintf("a lease time of %s is too short to be usable", p.LeaseTime),
			"use at least 5m; clients that sleep would lose their address")
	case p.LeaseTime > 7*24*time.Hour:
		r.warnc(CodeLeaseInvalid, "lease_time",
			fmt.Sprintf("a lease time of %s delays reclaiming abandoned addresses by up to that long", p.LeaseTime),
			"24h to 48h is typical on a home network")
	}

	if p.LeaseMax < 0 {
		r.errorc(CodeLeaseInvalid, "lease_max", "the lease cap must not be negative", "use 0 for the server default")
	}

	if p.Domain != "" {
		if strings.ContainsAny(p.Domain, " \t/") {
			r.errorc(CodeDomainInvalid, "domain",
				fmt.Sprintf("the local domain %q contains characters a DNS name cannot", p.Domain), "")
		} else if !strings.Contains(p.Domain, ".") {
			r.infoc(CodeDomainInvalid, "domain",
				fmt.Sprintf("the local domain %q is a single label; clients will send unqualified queries for it", p.Domain), "")
		}
	}
}

// validateRanges checks the address pools.
func validateRanges(r *Result, p Policy) {
	if !p.Enabled {
		return
	}

	if len(p.Ranges) == 0 {
		r.warnc(CodeRangeMissing, "ranges",
			"no address pools are configured, so the server would hand out no addresses",
			"add a range inside the LAN prefix")
		return
	}

	seen := make([]Range, 0, len(p.Ranges))

	for i, rg := range p.Ranges {
		field := fmt.Sprintf("ranges[%d]", i)

		if !rg.Start.IsValid() || !rg.End.IsValid() {
			r.errorc(CodeRangeInvalid, field, "the pool bounds must be valid IP addresses", "")
			continue
		}

		if rg.Start.Is4() != rg.End.Is4() {
			r.errorc(CodeRangeInvalid, field, "the pool spans two address families", "")
			continue
		}

		if compareAddr(rg.Start, rg.End) > 0 {
			r.errorc(CodeRangeReversed, field,
				fmt.Sprintf("the pool start %s is above its end %s", rg.Start, rg.End),
				"the start must be the lower address")
			continue
		}

		// A pool outside the LAN prefix hands out addresses the gateway
		// cannot route, so clients would configure successfully and then
		// fail every connection.
		//
		// Both endpoints are checked. Checking only the start accepts a pool
		// whose end has run off the far edge of the subnet — 192.168.1.250 to
		// 192.168.2.10 passes a start-only check, spans the broadcast and the
		// next network address, and would hand a client an address on a
		// network the gateway does not route.
		if p.LANPrefix.IsValid() {
			masked := p.LANPrefix.Masked()

			if !masked.Contains(rg.Start) {
				r.errorc(CodeRangeOutsideLAN, field+".start",
					fmt.Sprintf("the pool starts at %s, outside the LAN prefix %s", rg.Start, masked),
					"place the pool inside the LAN network")
				continue
			}
			if !masked.Contains(rg.End) {
				r.errorc(CodeRangeOutsideLAN, field+".end",
					fmt.Sprintf("the pool ends at %s, outside the LAN prefix %s", rg.End, masked),
					"a pool must lie entirely inside the LAN network")
				continue
			}

			// The network and broadcast addresses are not assignable. A pool
			// containing either produces a host that cannot reach anything,
			// and it looks correctly configured on the client.
			//
			// A /31 and a /32 are exempt: RFC 3021 gives a /31 two usable
			// point-to-point addresses, and a /32 has no network or broadcast
			// address at all.
			if p.LANPrefix.Addr().Is4() && p.LANPrefix.Bits() <= 30 {
				hostBits := 32 - p.LANPrefix.Bits()
				network := masked.Addr()
				broadcast := addOffset(network, (1<<hostBits)-1)

				if rg.Start == network {
					r.errorc(CodeRangeOutsideLAN, field+".start",
						fmt.Sprintf("the pool starts at %s, which is the network address of %s", rg.Start, masked),
						"begin the pool at the first host address")
					continue
				}
				if rg.End == broadcast {
					r.errorc(CodeRangeOutsideLAN, field+".end",
						fmt.Sprintf("the pool ends at %s, which is the broadcast address of %s", rg.End, masked),
						"end the pool at the last host address")
					continue
				}
			}
		}

		// A pool that contains the gateway's own address would eventually
		// hand the gateway's address to a client, which is a duplicate
		// address conflict and is genuinely disruptive.
		if p.GatewayAddress.IsValid() && rg.Contains(p.GatewayAddress) {
			r.errorc(CodeRangeIncludesGateway, field,
				fmt.Sprintf("the pool %s contains the gateway's own address %s", rg.String(), p.GatewayAddress),
				"exclude the gateway address from the pool")
		}

		for _, other := range seen {
			if rg.Overlaps(other) {
				r.errorc(CodeRangeOverlap, field,
					fmt.Sprintf("the pool overlaps %s", other.String()),
					"pools must be disjoint; an overlap would let the server hand out the same address twice")
			}
		}
		seen = append(seen, rg)

		// A pool that leaves too little headroom in a small network is worth
		// flagging, because there will be nowhere to put a static host. The
		// threshold is deliberately generous: a /24 with 151 dynamic
		// addresses leaves 103 spare, which is normal and must not warn.
		//
		// usableHosts is computed with the same guarded helper the config and
		// validation layers use, rather than as 1<<hostBits - 2 inline. That
		// expression is -1 at /32 and 0 at /31, which produced a warning
		// reading "the pool holds 1 of -1 usable addresses".
		if rg.Start.Is4() && p.LANPrefix.IsValid() && p.LANPrefix.Addr().Is4() {
			hostBits := 32 - p.LANPrefix.Bits()
			usable := usableHosts(hostBits)
			if size := rg.Size(); usable > 0 && size > 0 && size*10 > usable*9 {
				r.warnc(CodeRangeMissing, field,
					fmt.Sprintf("the pool holds %d of %d usable addresses in %s, leaving little room for static hosts",
						size, usable, p.LANPrefix.Masked()),
					"narrow the range, or use a larger LAN prefix")
			}
		}
	}

	// Reserving every address would starve clients.
	if total := p.TotalAddresses(); total > 0 && p.LeaseMax > 0 && p.LeaseMax > total {
		r.warnc(CodeLeaseInvalid, "lease_max",
			fmt.Sprintf("the lease cap (%d) exceeds the pool size (%d), so it has no effect", p.LeaseMax, total), "")
	}
}

// validateReservations checks the pinned addresses.
func validateReservations(r *Result, p Policy) {
	if !p.Enabled {
		if len(p.Reservations) > 0 {
			r.infof("reservations",
				"reservations are configured but DHCP is disabled, so they will have no effect", "")
		}
		return
	}

	seenMAC := map[string]int{}

	for i, res := range p.Reservations {
		field := fmt.Sprintf("reservations[%d]", i)

		if !isValidMAC(res.MAC) {
			r.errorc(CodeReservationInvalid, field+".mac",
				fmt.Sprintf("%q is not a valid MAC address", res.MAC),
				"write it as AA:BB:CC:DD:EE:FF")
			continue
		}

		mac := NormalisedMAC(res.MAC)
		if prev, dup := seenMAC[mac]; dup {
			r.errorc(CodeReservationInvalid, field+".mac",
				fmt.Sprintf("MAC %s is already reserved at index %d", mac, prev),
				"a device may only be reserved once")
		}
		seenMAC[mac] = i

		// A reservation outside the LAN would hand out an unroutable
		// address even though it looks deliberately pinned.
		if res.Address.IsValid() {
			if !res.Address.Is4() {
				r.warnc(CodeReservationInvalid, field+".address",
					fmt.Sprintf("the reserved address %s is IPv6; dnsmasq reserves are IPv4", res.Address), "")
			} else if p.LANPrefix.IsValid() && !p.LANPrefix.Masked().Contains(res.Address) {
				r.errorc(CodeReservationInvalid, field+".address",
					fmt.Sprintf("the reserved address %s is outside the LAN prefix %s", res.Address, p.LANPrefix.Masked()),
					"reserve an address inside the LAN network")
			} else if !inAnyPool(p.Ranges, res.Address) {
				r.warnc(CodeReservationInvalid, field+".address",
					fmt.Sprintf("the reserved address %s is not inside any pool", res.Address),
					"the reservation still works, but it takes an address the pool would not otherwise hand out")
			}
		}

		if res.Hostname != "" && !isValidHostname(res.Hostname) {
			r.warnc(CodeReservationInvalid, field+".hostname",
				fmt.Sprintf("the hostname %q is not a valid DNS label", res.Hostname), "")
		}

		if res.LeaseTime < 0 {
			r.errorc(CodeReservationInvalid, field+".lease_time", "the lease override must not be negative", "")
		} else if res.LeaseTime > 0 && res.LeaseTime < 5*time.Minute {
			r.warnc(CodeReservationInvalid, field+".lease_time",
				fmt.Sprintf("a lease of %s is short enough that a sleeping device would lose it", res.LeaseTime), "")
		}
	}
}

// inAnyPool reports whether an address falls in any pool.
func inAnyPool(ranges []Range, addr netip.Addr) bool {
	for _, r := range ranges {
		if r.Contains(addr) {
			return true
		}
	}
	return false
}

// isValidMAC reports whether s is a valid colon-separated MAC address.
func isValidMAC(s string) bool {
	mac := NormalisedMAC(s)
	if len(mac) != 17 {
		return false
	}
	for i, c := range mac {
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// isHexDigit reports whether c is a lowercase hexadecimal digit.
func isHexDigit(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// isValidHostname reports whether s is a valid DNS label.
func isValidHostname(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
