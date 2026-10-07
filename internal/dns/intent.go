// Package-level M7.3 additions: DNS intent and its report.
//
// # What this file adds to the package
//
// internal/dns already owned the DNS *policy*: the document-shaped struct
// carrying the listen address, the upstream resolvers and the local records.
// That model stays exactly where it is; it is what a dnsmasq config is built
// from and it is still built from.
//
// What this file adds is the intent above it, and it separates two things the
// policy treats as one field list:
//
//	"THN runs a DNS service on the LAN"   → Intent.Enabled
//	"THN forwards queries to 1.1.1.1"     → Intent.Upstream
//
// These are genuinely different decisions. A gateway may forward to an
// upstream without serving anyone (it is a client, not a server); it may serve
// local names with no upstream at all; and conflating the two is how a host
// ends up either answering nothing or resolving nothing, both of which look
// like a working network that cannot resolve names.
//
// # The upstream source rule
//
// A document can name resolvers twice:
//
//	dns.upstream    the resolvers the DNS SERVICE forwards to
//	network.dns     the resolvers the HOST itself uses
//
// Both are legitimate and neither is deprecated. They are not different
// VALUES though: a document that sets them to different resolvers describes a
// machine whose own queries go one way and whose clients' queries go another,
// and nothing downstream could act on the difference.
//
// So dns.upstream is canonical for the service, network.dns is the fallback
// for documents that predate it, equal values are accepted, and differing
// values are a conflict. This is the precedence internal/cli already applied
// when building the policy; it is stated here, in the domain, as a single
// function so the intent, the policy and the validator cannot each hold their
// own opinion about which field wins.
//
// # Determinism
//
// ValidateIntent is pure and total. It never resolves a name, never performs
// a query, never contacts a resolver, and returns the same report for the
// same intent every time. Validation of DNS configuration must work in an
// air-gapped CI job, so "is this resolver reachable" is not a question this
// layer is allowed to ask.
//
// # What this file does not do
//
// It starts nothing. No resolver is bound, /etc/resolv.conf is untouched,
// systemd-resolved is untouched. Describing the DNS behaviour a machine
// should have is a different act from giving it that behaviour, and only the
// first is implemented.
package dns

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Verdict is the overall outcome of checking a DNS intent.
//
// The three values are the same three internal/gateway uses, and mean the
// same thing:
//
//	VALID    the intent is complete and internally consistent
//	PENDING  coherent but incomplete; more of the document will finish it
//	BLOCKED  the intent cannot be built as written
type Verdict string

const (
	// VerdictValid means every part of the DNS intent was satisfied.
	VerdictValid Verdict = "VALID"

	// VerdictBlocked means DNS cannot be built as written. More configuration
	// will not fix it: the two resolver fields disagree, or a named resolver
	// cannot be one.
	VerdictBlocked Verdict = "BLOCKED"

	// VerdictPending means the intent is coherent but incomplete.
	VerdictPending Verdict = "PENDING"
)

// LANRole is the logical LAN the DNS service attaches to.
//
// It mirrors gateway.RoleIntent: what the operator named, kept separate from
// what that name currently resolves to.
type LANRole struct {
	// Selector is what the operator wrote.
	Selector string `json:"selector,omitempty"`

	// Declared reports whether the operator named a LAN at all.
	Declared bool `json:"declared"`

	// Resolved reports whether the selector matched an observed interface.
	Resolved bool `json:"resolved"`

	// Interface is the observed kernel name, empty when unresolved.
	Interface string `json:"interface,omitempty"`

	// StableID is the observed rename-stable identity, empty when unresolved.
	StableID string `json:"stable_id,omitempty"`

	// Prefix is the LAN address as written, e.g. "10.77.0.1/24".
	Prefix string `json:"prefix,omitempty"`
}

// UpstreamDecision is the outcome of applying the upstream source rule.
//
// It reports which field supplied the resolvers and whether the two fields
// disagreed, so a caller can explain the answer instead of merely producing
// it. Silently preferring one is the failure this exists to prevent: editing
// dns.upstream once changed nothing and nothing said so.
type UpstreamDecision struct {
	// List is the resolver set to use, in the order it was declared.
	List []string `json:"list,omitempty"`

	// Source names the field that supplied List: "dns.upstream",
	// "network.dns", or "" when neither was declared.
	Source string `json:"source,omitempty"`

	// Canonical and Fallback are the two declared fields, verbatim.
	//
	// Both are carried so the conflict message can show the operator what
	// each field actually said, rather than only that they differ.
	Canonical []string `json:"canonical,omitempty"`
	Fallback  []string `json:"fallback,omitempty"`

	// BothDeclared reports whether both fields were set.
	BothDeclared bool `json:"both_declared"`

	// Agree reports whether both were set and name the same resolvers.
	//
	// Order is not significant: a document that lists the same resolvers in a
	// different order has not disagreed with itself.
	Agree bool `json:"agree"`

	// Conflict reports whether both were set and name different resolvers.
	Conflict bool `json:"conflict"`
}

// ResolveUpstream applies the canonical upstream precedence rule.
//
// The rule, stated once:
//
//	only dns.upstream   → use it
//	only network.dns    → use it (the fallback for documents predating the
//	                      canonical field)
//	neither             → none; THN does not invent a resolver
//	both, equal         → accept, and report which field was canonical
//	both, differing     → conflict; there is no single answer to use
//
// The "neither" case is deliberately empty rather than defaulted. Silently
// prepopulating 1.1.1.1 would mean an operator who never chose a resolver
// ends up with queries leaving their network, and nothing in the document
// would say so.
func ResolveUpstream(canonical, fallback []string) UpstreamDecision {
	d := UpstreamDecision{
		Canonical: append([]string(nil), canonical...),
		Fallback:  append([]string(nil), fallback...),
	}

	d.BothDeclared = len(canonical) > 0 && len(fallback) > 0

	switch {
	case len(canonical) > 0:
		d.List = append([]string(nil), canonical...)
		d.Source = SourceCanonical
	case len(fallback) > 0:
		d.List = append([]string(nil), fallback...)
		d.Source = SourceFallback
	}

	if d.BothDeclared {
		d.Agree = sameSet(canonical, fallback)
		d.Conflict = !d.Agree
	}

	return d
}

// Upstream source names. These are the configuration field paths, and they
// appear verbatim in findings so an operator is pointed at the line to edit.
const (
	// SourceCanonical is dns.upstream, authoritative for the DNS service.
	SourceCanonical = "dns.upstream"

	// SourceFallback is network.dns, the host's own resolver list, used for
	// the service only when dns.upstream is absent.
	SourceFallback = "network.dns"
)

// sameSet reports whether two string lists contain the same values with the
// same multiplicities, ignoring order.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

// Intent is the canonical statement of what this machine should resolve
// names with, and whether it should resolve them for LAN clients at all.
//
// Device-independent by construction: the only interface reference is the LAN
// role's stable identity, and the listen address is derived from the declared
// LAN address rather than from an interface name.
type Intent struct {
	// Enabled is the explicit statement that THN should serve DNS on the LAN.
	//
	// It is read from the document and never inferred from the presence of
	// upstream resolvers: a host that forwards queries to 1.1.1.1 is a DNS
	// *client*, which says nothing about whether it should be a resolver for
	// anyone else. When false, every other field is inert.
	Enabled bool `json:"enabled"`

	// LAN is the downstream segment DNS is served on.
	LAN LANRole `json:"lan"`

	// ListenAddress is the address the service would answer on.
	//
	// Derived from the declared LAN address. Empty means the gateway's own
	// LAN address, and it is left empty rather than defaulted because a
	// default would hide an absent decision about the LAN address.
	ListenAddress netip.Addr `json:"-"`

	// Upstream are the resolvers queries are forwarded to, in declaration
	// order.
	//
	// Explicit rather than inherited: inheriting them from the uplink would
	// make THN's DNS behaviour depend on the upstream's DHCP, and would hide
	// a misconfiguration that sent queries somewhere unintended.
	Upstream []netip.Addr `json:"upstream,omitempty"`

	// UpstreamSource names the field that supplied Upstream.
	UpstreamSource string `json:"upstream_source,omitempty"`

	// UpstreamConflict reports that the two resolver fields were both
	// declared and disagree.
	//
	// When set, the intent is blocked. Silently choosing one would mean the
	// document described two machines and THN picked one of them.
	UpstreamConflict *UpstreamConflict `json:"upstream_conflict,omitempty"`

	// LocalDomain is the domain served for local names.
	LocalDomain string `json:"local_domain,omitempty"`

	// LocalRecords are additional names served for local addresses.
	LocalRecords []Record `json:"local_records,omitempty"`

	// CacheSize is the number of answers cached. Zero uses the backend default.
	CacheSize int `json:"cache_size,omitempty"`

	// LogQueries records every query.
	//
	// Off by default: it is the most useful setting for security work and
	// one of the fastest ways to fill a small filesystem.
	LogQueries bool `json:"log_queries"`

	// NoIPv6 answers AAAA queries with no answer.
	NoIPv6 bool `json:"no_ipv6"`

	// Policy is the document-shaped model the rest of the package consumes.
	Policy Policy `json:"-"`
}

// UpstreamConflict describes a disagreement between the two resolver fields.
type UpstreamConflict struct {
	// Canonical is dns.upstream, verbatim.
	Canonical []string `json:"canonical,omitempty"`

	// Fallback is network.dns, verbatim.
	Fallback []string `json:"fallback,omitempty"`
}

// Report is the outcome of validating a DNS intent.
type Report struct {
	// Intent is what was checked.
	Intent Intent `json:"intent"`

	// Verdict is the overall outcome.
	Verdict Verdict `json:"verdict"`

	// Summary is the one-line human explanation.
	Summary string `json:"summary"`

	// Findings is everything the check established, blocking first.
	//
	// Findings carry the same codes this package's policy validator emits, so
	// a consumer dispatching on dns-upstream-conflict sees one vocabulary
	// whichever layer produced the finding.
	Findings []Finding `json:"findings"`
}

// Blocking returns the findings that prevent the intent being satisfied.
func (r Report) Blocking() []Finding { return r.bySeverity(SeverityError) }

// Warnings returns the findings that do not block.
func (r Report) Warnings() []Finding { return r.bySeverity(SeverityWarning) }

func (r Report) bySeverity(s Severity) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

// FromPolicy derives DNS intent from the document-shaped policy, the LAN role
// it serves, and the outcome of the upstream source rule.
//
// This is the only place a policy becomes intent. Everything downstream —
// validation, desired state, the planner — consumes Intent, so the rules for
// reading a document live in exactly one function.
//
// The upstream conflict is carried as data rather than raised here, because
// the caller has to decide what to do about it and a constructor cannot ask a
// question. ValidateIntent reports it.
func FromPolicy(p Policy, lan LANRole, up UpstreamDecision) Intent {
	in := Intent{
		Enabled:        p.Enabled,
		LAN:            lan,
		Upstream:       append([]netip.Addr(nil), p.Upstream...),
		UpstreamSource: up.Source,
		LocalDomain:    p.LocalDomain,
		LocalRecords:   cloneRecords(p.LocalRecords),
		CacheSize:      p.CacheSize,
		LogQueries:     p.LogQueries,
		NoIPv6:         p.NoIPv6,
	}

	if prefix, err := netip.ParsePrefix(lan.Prefix); err == nil {
		in.ListenAddress = prefix.Addr()
	}

	if up.Conflict {
		in.UpstreamConflict = &UpstreamConflict{
			Canonical: append([]string(nil), up.Canonical...),
			Fallback:  append([]string(nil), up.Fallback...),
		}
	}

	in.Policy = p
	// The policy's view of the LAN is replaced with the role-resolved one so
	// the two models cannot disagree about which network is served.
	in.Policy.Interface = lan.Selector
	if in.ListenAddress.IsValid() {
		in.Policy.ListenAddress = in.ListenAddress
	}
	// The upstream list is replaced with the decision's, because the policy
	// was built before the conflict was known and must not appear to have
	// silently resolved one.
	if len(up.List) > 0 {
		in.Policy.Upstream = append([]netip.Addr(nil), in.Upstream...)
	} else {
		in.Policy.Upstream = nil
	}

	return in
}

// cloneRecords deep-copies a record slice.
func cloneRecords(in []Record) []Record {
	if in == nil {
		return nil
	}
	out := make([]Record, len(in))
	for i, r := range in {
		out[i] = r
		if r.Aliases != nil {
			out[i].Aliases = append([]string(nil), r.Aliases...)
		}
	}
	return out
}

// ValidateIntent checks a DNS intent.
//
// Pure, total and offline: no name is resolved, no query is sent, and no
// resolver is contacted. Reachability is deliberately not checked here — a CI
// job with no network must reach the same verdict as one on the gateway.
func ValidateIntent(in Intent) Report {
	rep := Report{Intent: in}

	// A document that does not want a DNS service is not an invalid DNS
	// service. It is a different, valid thing.
	if !in.Enabled {
		rep.Findings = append(rep.Findings, Finding{
			Field:    "enabled",
			Code:     CodeDisabled,
			Severity: SeverityInfo,
			Message:  "this document does not ask for a DNS service; its resolvers are not required",
			Hint:     "set dns.enabled to true to have this machine resolve names for the LAN",
		})
		rep.Verdict = VerdictValid
		rep.Summary = "DNS not requested"
		return rep
	}

	rep.Findings = append(rep.Findings, checkUpstreamConflict(in)...)

	// checkLANBinding appends what it found to the intent's report. The
	// caller passes them in so the findings land in one deterministic list
	// rather than being returned and merged by hand at each call site.
	found := checkLANBinding(in)
	rep.Findings = append(rep.Findings, found...)
	lanReady := len(blockingFindings(found)) == 0

	// Everything below depends on a usable LAN. When it is missing the
	// finding above already said so, and adding consequences would bury it.
	if lanReady {
		// The policy rules are reused verbatim rather than reimplemented, so
		// the intent layer and `thn dhcp validate` cannot reach different
		// conclusions about the same document.
		for _, f := range Validate(in.Policy).Findings {
			rep.Findings = append(rep.Findings, f)
		}
	}

	sortFindings(rep.Findings)
	rep.Verdict = verdictOf(rep.Findings)
	rep.Summary = summarise(rep)
	return rep
}

// checkLANBinding reports what the intent depends on, and whether the
// resolvers can be judged yet.
//
// The LAN is what DNS is served ON. A resolver with nowhere to listen cannot
// answer anyone, so this is checked before the resolvers: reporting "no
// upstream resolvers" when the real problem is that there is no LAN to serve
// would point the operator at the wrong field.
func checkLANBinding(in Intent) []Finding {
	var out []Finding

	switch {
	case !in.LAN.Declared:
		out = append(out, Finding{
			Field:    "lan",
			Code:     CodeLANMissing,
			Severity: SeverityError,
			Message:  "DNS is enabled but no LAN interface is configured, so there is no network to serve names on",
			Hint:     "run `thn discover` to see this host's interfaces, then set network.lan",
		})
		return out
	case !in.LAN.Resolved:
		out = append(out, Finding{
			Field:    "lan",
			Code:     CodeLANUnresolved,
			Severity: SeverityWarning,
			Message: fmt.Sprintf(
				"the LAN selector %q has not been resolved against a host; "+
					"DNS cannot be checked against a link that is not identified yet",
				in.LAN.Selector),
			Hint: "run `thn validate --live` on the gateway, or attach the LAN",
		})
	}

	if !in.ListenAddress.IsValid() {
		out = append(out, Finding{
			Field:    "lan_prefix",
			Code:     CodeLANAddressMissing,
			Severity: SeverityError,
			Message:  "DNS is enabled but the LAN has no address, so there is nowhere for the resolver to listen",
			Hint:     "set network.lan_prefix to the address this machine should hold, e.g. 10.77.0.1/24",
		})
	}

	return out
}

// blockingFindings returns the error-severity entries.
func blockingFindings(in []Finding) []Finding {
	var out []Finding
	for _, f := range in {
		if f.Severity == SeverityError {
			out = append(out, f)
		}
	}
	return out
}

// checkUpstreamConflict reports the two resolver fields disagreeing.
//
// This is checked before anything else because it invalidates the resolver
// list itself: if the document has two different answers, every downstream
// question about "which resolvers" has no answer to work from.
func checkUpstreamConflict(in Intent) []Finding {
	if in.UpstreamConflict == nil {
		return nil
	}

	c := in.UpstreamConflict
	return []Finding{{
		Field:    SourceCanonical,
		Code:     CodeUpstreamConflict,
		Severity: SeverityError,
		Message: fmt.Sprintf(
			"%s (%s) and %s (%s) name different resolvers; "+
				"this document describes two different machines and THN will not pick one for you",
			SourceCanonical, strings.Join(c.Canonical, ", "),
			SourceFallback, strings.Join(c.Fallback, ", ")),
		Hint: SourceCanonical + " is authoritative for the DNS service; make " +
			SourceFallback + " match it, or remove it",
	}}
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
		return "the requested DNS service can be built from this configuration"
	case VerdictPending:
		return fmt.Sprintf("DNS is incomplete: %d warning(s), nothing blocking", len(rep.Warnings()))
	default:
		return fmt.Sprintf("DNS cannot be built as configured: %d blocking finding(s)",
			len(rep.Blocking()))
	}
}

// UpstreamStrings renders the upstreams as strings.
func (in Intent) UpstreamStrings() []string {
	out := make([]string, 0, len(in.Upstream))
	for _, u := range in.Upstream {
		out = append(out, u.String())
	}
	return out
}

// Summary renders the intent for a human, for `thn validate` and `thn plan`.
func (in Intent) Summary() string {
	var b strings.Builder

	fmt.Fprintf(&b, "DNS:     %s\n", enabledLabel(in.Enabled))
	fmt.Fprintf(&b, "LAN:     %s\n", describeLAN(in.LAN))
	fmt.Fprintf(&b, "Listen:  %s\n", orNone(in.Listen()))
	fmt.Fprintf(&b, "Upstream: %s\n", describeUpstream(in))
	if in.LocalDomain != "" {
		fmt.Fprintf(&b, "Domain:  %s (served locally)\n", in.LocalDomain)
	}

	return b.String()
}

// Listen returns the listen address as text, or "" when none is known.
func (in Intent) Listen() string {
	if !in.ListenAddress.IsValid() {
		return ""
	}
	return in.ListenAddress.String()
}

// describeUpstream renders the upstream resolvers and where they came from.
//
// The source is shown because it is the answer to the question an operator
// actually has after editing a resolver: "why is it still using that one?".
func describeUpstream(in Intent) string {
	if in.UpstreamConflict != nil {
		return fmt.Sprintf("CONFLICT: %s (%s) vs %s (%s)",
			SourceCanonical, strings.Join(in.UpstreamConflict.Canonical, ", "),
			SourceFallback, strings.Join(in.UpstreamConflict.Fallback, ", "))
	}
	if len(in.Upstream) == 0 {
		return "(none declared; no resolver will be used)"
	}
	return fmt.Sprintf("%s (from %s)", strings.Join(in.UpstreamStrings(), ", "),
		orNone(in.UpstreamSource))
}

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
