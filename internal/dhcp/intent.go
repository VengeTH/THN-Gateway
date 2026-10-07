// Package-level M7.3 additions: DHCP intent and its report.
//
// # What this file adds to the package
//
// internal/dhcp already owned the DHCP *policy*: the document-shaped struct
// carrying the pools, the lease time, the domain and the backend. That is the
// right model for "what a dnsmasq config should say", and it stays exactly
// where it is.
//
// What it had no answer for is the question the operator actually asks:
// "should THN hand out addresses on this LAN, and can that pool be built from
// the LAN I declared?" Those are different questions. The policy answers the
// first from the document alone. The second needs the LAN *role* — resolved
// or not — which lives in internal/gateway.
//
// So this file adds the intent layer above the policy:
//
//	policy (document)  ─┐
//	                    ├─→ Intent ─→ Report  (VALID | PENDING | BLOCKED)
//	LAN role (resolved) ┘
//
// # Why DHCP hangs off the LAN role and not an interface name
//
// DHCP hands addresses to clients that can only reach them if the gateway
// holds the matching address on the same link. Tying DHCP to enx00e099001812
// would make the pool's correctness depend on a kernel name that changes when
// a NIC moves slots. So the intent takes the LAN's stable identity and its
// prefix, and the pool is validated against those. The resolved kernel name is
// carried alongside as an observation, never as the identity.
//
// # Determinism
//
// Validate is pure and total. It sorts its findings, never mutates its
// inputs, and returns the same report for the same intent every time. Two
// runs diff cleanly, which is what makes a CI log readable.
//
// # What this file does not do
//
// It starts nothing. No lease is written, no port is bound, no backend is
// invoked. Describing the DHCP behaviour a machine should have is a different
// act from giving it that behaviour, and only the first is implemented.
package dhcp

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Verdict is the overall outcome of checking a DHCP intent.
//
// The three values are the same three internal/gateway uses, and mean the
// same thing:
//
//	VALID    the intent is complete and internally consistent
//	PENDING  coherent but incomplete; more of the document will finish it
//	BLOCKED  the intent cannot be built as written
type Verdict string

const (
	// VerdictValid means every part of the DHCP intent was satisfied.
	VerdictValid Verdict = "VALID"

	// VerdictBlocked means DHCP cannot be built as configured. More
	// configuration will not fix it: the pool is wrong, or the gateway is
	// advertising an address the clients must not be given.
	VerdictBlocked Verdict = "BLOCKED"

	// VerdictPending means the intent is coherent but incomplete. This is the
	// normal state while THN is developed against hardware that is not
	// attached.
	VerdictPending Verdict = "PENDING"
)

// LANRole is the logical LAN the DHCP service attaches to.
//
// It is the intersection of gateway.RoleIntent and the observed interface:
// what the operator named, and what that name currently resolves to. Keeping
// the two apart is the point — a document that names hw:… must keep naming
// it even when the machine calls that link enx00e099001812.
type LANRole struct {
	// Selector is what the operator wrote: a stable ID, a kernel name, or a
	// role name delegating to a stored assignment.
	Selector string `json:"selector,omitempty"`

	// Declared reports whether the operator named a LAN at all.
	Declared bool `json:"declared"`

	// Resolved reports whether the selector matched an observed interface.
	//
	// Unresolved is pending, not broken: the cable may not be plugged in yet,
	// and the operator may already have written the right identity.
	Resolved bool `json:"resolved"`

	// Interface is the observed kernel name, empty when unresolved.
	Interface string `json:"interface,omitempty"`

	// StableID is the observed rename-stable identity, empty when unresolved.
	StableID string `json:"stable_id,omitempty"`

	// Prefix is the LAN address as written, e.g. "10.77.0.1/24".
	//
	// Empty means no address has been chosen. It is reported as pending
	// rather than defaulted, because a default that silently supplies an
	// address hides an absent decision.
	Prefix string `json:"prefix,omitempty"`
}

// Intent is the canonical statement of what this machine should hand out.
//
// Device-independent by construction: the only interface reference is the LAN
// role's stable identity, and every address is derived from the declared LAN
// prefix rather than from an interface name.
type Intent struct {
	// Enabled is the explicit statement that THN should serve addresses.
	//
	// When false, every other field is inert and Validate reports only that
	// DHCP is not wanted. Declining to run DHCP is a decision, not an
	// omission, and must not be reported as an error.
	Enabled bool `json:"enabled"`

	// LAN is the downstream segment DHCP serves.
	LAN LANRole `json:"lan"`

	// Prefix is the LAN subnet the pool must belong to, parsed from
	// LAN.Prefix. Invalid when the address is absent or unparseable.
	Prefix netip.Prefix `json:"-"`

	// Gateway is the address advertised as the client's default route.
	//
	// It is derived from the declared LAN address and never configured
	// separately, so there is exactly one source of truth for "the address
	// the gateway holds on its LAN". Invalid when no LAN address is known.
	Gateway netip.Addr `json:"-"`

	// Ranges are the pools, in declaration order.
	//
	// Declaration order is preserved rather than sorted because the order is
	// the operator's written intent and range[0] means something to them.
	// Determinism does not require reordering here; it requires that the
	// order not depend on map iteration.
	Ranges []Range `json:"ranges,omitempty"`

	// LeaseTime is the default lease duration.
	LeaseTime time.Duration `json:"lease_time,omitempty"`

	// Authoritative marks the server authoritative for the LAN.
	Authoritative bool `json:"authoritative"`

	// Domain is the local domain advertised via DHCP option 15.
	Domain string `json:"domain,omitempty"`

	// AdvertisedDNS are the resolvers DHCP hands to clients.
	//
	// This is the boundary between the DHCP and DNS domains: DHCP decides
	// what a client is *told*, and DNS decides what THN *does* when queried.
	// A client resolving through the gateway does not require THN to run a
	// resolver of its own, so these are carried as data and never imply that
	// a DNS service exists.
	AdvertisedDNS []netip.Addr `json:"advertised_dns,omitempty"`

	// Policy is the document-shaped model the rest of the package consumes.
	//
	// It is derived here rather than stored, so the two can never disagree
	// about what the document said.
	Policy Policy `json:"-"`
}

// Report is the outcome of validating a DHCP intent against a host.
type Report struct {
	// Intent is what was checked.
	Intent Intent `json:"intent"`

	// Verdict is the overall outcome.
	Verdict Verdict `json:"verdict"`

	// Summary is the one-line human explanation.
	Summary string `json:"summary"`

	// Findings is everything the check established, blocking first.
	//
	// Each finding keeps the code from the package's finding vocabulary, so
	// a consumer that already dispatches on dhcp-range-outside-lan sees the
	// same word whether the finding came from Validate(Policy) or from
	// ValidateIntent(Intent).
	Findings []Finding `json:"findings"`
}

// Blocking returns the findings that prevent the intent being satisfied.
func (r Report) Blocking() []Finding {
	return r.bySeverity(SeverityError)
}

// Warnings returns the findings that do not block.
func (r Report) Warnings() []Finding {
	return r.bySeverity(SeverityWarning)
}

func (r Report) bySeverity(s Severity) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

// FromPolicy derives DHCP intent from the document-shaped policy and the LAN
// role it attaches to.
//
// This is the only place a policy becomes intent. Everything downstream —
// validation, desired state, the planner — consumes Intent, so the rules for
// reading a document live in exactly one function.
//
// The pool arithmetic is NOT re-derived here. The policy already carries the
// declared pools, and Validate(Policy) already checks them with full /8
// through /32 correctness. Re-implementing that would create a second answer
// to "is this pool valid", and the two would eventually disagree — which is
// the failure this package's existing tests were written to prevent.
func FromPolicy(p Policy, lan LANRole) Intent {
	in := Intent{
		Enabled:       p.Enabled,
		LAN:           lan,
		Ranges:        append([]Range(nil), p.Ranges...),
		LeaseTime:     p.LeaseTime,
		Authoritative: p.Authoritative,
		Domain:        p.Domain,
	}

	// The gateway address is derived from the declared LAN address and only
	// from it. DHCP has no separate router option in the configuration model
	// and this layer does not invent one: two sources of truth for "the
	// gateway's LAN address" is how a pool ends up advertising a router the
	// machine does not hold.
	if prefix, err := netip.ParsePrefix(lan.Prefix); err == nil {
		in.Prefix = prefix
		in.Gateway = prefix.Addr()
	}

	in.Policy = p
	// The policy's own view of the LAN is replaced with the role-resolved
	// one, so the two models cannot disagree about which network is served.
	in.Policy.LANPrefix = prefixOrZero(in.Prefix)
	if in.Gateway.IsValid() {
		in.Policy.GatewayAddress = in.Gateway
	}
	if lan.Selector != "" {
		in.Policy.Interface = lan.Selector
	}

	return in
}

// prefixOrZero returns prefix, or the zero prefix when it is invalid.
func prefixOrZero(p netip.Prefix) netip.Prefix {
	if !p.IsValid() {
		return netip.Prefix{}
	}
	return p
}

// ValidateIntent checks a DHCP intent.
//
// Pure and total: it never returns an error, never mutates the intent, and
// returns the same report for the same inputs every time.
//
// The dependency order is the point. Gateway intent establishes the LAN;
// DHCP can only be checked once the LAN exists. So when the LAN is absent or
// unresolved this reports THAT, and stops — rather than reporting a dozen
// consequences. "DHCP pool is invalid" is not useful when the real problem is
// that there is no LAN to be invalid against.
func ValidateIntent(in Intent) Report {
	rep := Report{Intent: in}

	// A document that does not want DHCP is not an invalid DHCP. It is a
	// different, valid thing, and reporting its absent LAN as an error would
	// punish the operator for declining to configure a service.
	if !in.Enabled {
		rep.Findings = append(rep.Findings, Finding{
			Field:    "enabled",
			Code:     CodeDisabled,
			Severity: SeverityInfo,
			Message:  "this document does not ask for DHCP; its LAN and pools are not required",
			Hint:     "set dhcp.enabled to true to have this machine hand out addresses",
		})
		rep.Verdict = VerdictValid
		rep.Summary = "DHCP not requested"
		return rep
	}

	rep.Findings = append(rep.Findings, checkLANBinding(in)...)

	// Everything below depends on a resolved LAN with an address. If the
	// dependency is missing, the finding above already said so, and adding
	// pool findings now would only bury it.
	if readyForPools(in) {
		// The pool rules live in Validate(Policy) and are reused verbatim.
		// They are the same rules the renderer and `thn dhcp validate` apply,
		// so the intent layer and the backend cannot disagree about a pool.
		for _, f := range Validate(in.Policy).Findings {
			rep.Findings = append(rep.Findings, f)
		}
	}

	sortFindings(rep.Findings)
	rep.Verdict = verdictOf(rep.Findings)
	rep.Summary = summarise(rep)
	return rep
}

// readyForPools reports whether the LAN is resolved well enough to judge a
// pool against.
//
// Two conditions, both required: the LAN must resolve, because a pool's
// correctness is relative to a link, and it must have an address, because a
// pool's correctness is relative to a subnet. Neither is inferable from the
// document alone.
func readyForPools(in Intent) bool {
	return in.LAN.Declared && in.LAN.Resolved && in.Prefix.IsValid()
}

// checkLANBinding reports what the intent depends on before pools mean
// anything.
//
// This is the dependency edge the milestone asks for. When the LAN cannot be
// used, this says so in terms of the LAN, and the pool checks are skipped —
// so the operator is told the real problem instead of being told their pool
// is wrong.
func checkLANBinding(in Intent) []Finding {
	var out []Finding

	switch {
	case !in.LAN.Declared:
		out = append(out, Finding{
			Field:    "lan",
			Code:     CodeLANMissing,
			Severity: SeverityError,
			Message:  "DHCP is enabled but no LAN interface is configured, so there is no network to hand out addresses on",
			Hint:     "run `thn discover` to see this host's interfaces, then set network.lan",
		})
		// No pool can be judged without a LAN at all.
		return out
	case !in.LAN.Resolved:
		out = append(out, Finding{
			Field:    "lan",
			Code:     CodeLANUnresolved,
			Severity: SeverityWarning,
			Message: fmt.Sprintf(
				"the LAN selector %q has not been resolved against a host; "+
					"DHCP cannot be checked against a link that is not identified yet",
				in.LAN.Selector),
			Hint: "run `thn validate --live` on the gateway, or attach the LAN",
		})
	}

	if !in.Prefix.IsValid() {
		out = append(out, Finding{
			Field:    "lan_prefix",
			Code:     CodeLANAddressMissing,
			Severity: SeverityError,
			Message:  "DHCP is enabled but the LAN has no address, so there is no subnet an address pool could belong to",
			Hint:     "set network.lan_prefix to the address this machine should hold, e.g. 10.77.0.1/24",
		})
	}

	return out
}

// sortFindings orders findings deterministically.
//
// Determinism is not cosmetic here: a CI log that reorders between runs cannot
// be diffed, and two identical runs producing two different documents is the
// behaviour this repository treats as a defect everywhere else.
func sortFindings(in []Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() < b.Severity.rank()
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		return a.Code < b.Code
	})
}

// verdictOf reduces findings to a verdict.
func verdictOf(findings []Finding) Verdict {
	pending := false
	for _, f := range findings {
		switch f.Severity {
		case SeverityError:
			return VerdictBlocked
		case SeverityWarning:
			pending = true
		}
	}
	if pending {
		return VerdictPending
	}
	return VerdictValid
}

// summarise renders the one-line verdict explanation.
func summarise(rep Report) string {
	switch rep.Verdict {
	case VerdictValid:
		return "the requested DHCP service can be built from this configuration"
	case VerdictPending:
		return fmt.Sprintf("DHCP is incomplete: %d warning(s), nothing blocking", len(rep.Warnings()))
	default:
		return fmt.Sprintf("DHCP cannot be built as configured: %d blocking finding(s)",
			len(rep.Blocking()))
	}
}

// Summary renders the intent for a human, for `thn validate` and `thn plan`.
func (in Intent) Summary() string {
	var b strings.Builder

	fmt.Fprintf(&b, "DHCP:    %s\n", enabledLabel(in.Enabled))
	fmt.Fprintf(&b, "LAN:     %s\n", describeLAN(in.LAN))
	fmt.Fprintf(&b, "Subnet:  %s\n", orNone(in.Subnet()))
	fmt.Fprintf(&b, "Advertise router: %s\n", orNone(in.AdvertisedRouter()))
	fmt.Fprintf(&b, "Ranges:  %s\n", describeRanges(in.Ranges))
	fmt.Fprintf(&b, "Lease:   %s\n", describeLease(in.LeaseTime))
	if len(in.AdvertisedDNS) > 0 {
		fmt.Fprintf(&b, "DNS:     %s (advertised to clients)\n", strings.Join(addrStrings(in.AdvertisedDNS), ", "))
	}

	return b.String()
}

// Subnet returns the LAN subnet as text, or "" when unknown.
func (in Intent) Subnet() string {
	if !in.Prefix.IsValid() {
		return ""
	}
	return in.Prefix.Masked().String()
}

// AdvertisedRouter returns the address DHCP would advertise as the default
// route, or "" when no LAN address is known.
//
// It is derived from the declared LAN address, which is what makes the pool
// and the router advertisement necessarily agree.
func (in Intent) AdvertisedRouter() string {
	if !in.Gateway.IsValid() {
		return ""
	}
	return in.Gateway.String()
}

// TotalAddresses returns how many addresses the pools would hand out.
func (in Intent) TotalAddresses() int { return in.Policy.TotalAddresses() }

// enabledLabel renders the enabled state.
func enabledLabel(on bool) string {
	if on {
		return "requested"
	}
	return "not requested"
}

// describeLAN renders the LAN binding, separating what was asked for from
// what was observed.
func describeLAN(lan LANRole) string {
	switch {
	case !lan.Declared:
		return "not configured"
	case !lan.Resolved:
		return fmt.Sprintf("%s (unresolved)", lan.Selector)
	default:
		return fmt.Sprintf("%s -> %s [%s]", lan.Selector, orNone(lan.Interface), orNone(lan.StableID))
	}
}

// describeRanges renders the pools.
func describeRanges(ranges []Range) string {
	if len(ranges) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, r.String())
	}
	return strings.Join(out, ", ")
}

// describeLease renders the lease duration.
func describeLease(d time.Duration) string {
	if d == 0 {
		return "(unset)"
	}
	return d.String()
}

// addrStrings renders addresses for display.
func addrStrings(in []netip.Addr) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.String())
	}
	return out
}
