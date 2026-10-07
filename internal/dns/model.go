package dns

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Policy is the desired DNS configuration.
type Policy struct {
	// Enabled reports whether THN should serve DNS on the LAN.
	Enabled bool `json:"enabled"`

	// Interface is the interface the server listens on.
	Interface string `json:"interface,omitempty"`

	// ListenAddress is the address the server binds to. Empty means the
	// gateway's own LAN address.
	ListenAddress netip.Addr `json:"listen_address,omitempty"`

	// Upstream are the resolvers queries are forwarded to.
	//
	// These are explicit rather than inherited: inheriting them from the
	// uplink would make THN's DNS behaviour depend on the upstream's DHCP,
	// and would hide a misconfiguration that sent queries somewhere
	// unintended.
	Upstream []netip.Addr `json:"upstream,omitempty"`

	// LocalDomain is the domain served for local names. Names in this domain
	// are answered locally and never forwarded.
	LocalDomain string `json:"local_domain,omitempty"`

	// LocalRecords are additional names THN serves.
	LocalRecords []Record `json:"local_records,omitempty"`

	// CacheSize is the number of answers cached. Zero uses the backend default.
	CacheSize int `json:"cache_size"`

	// LogQueries records every query.
	//
	// This is the most useful setting for security work and one of the
	// fastest ways to fill a small filesystem: a busy household makes tens of
	// thousands of queries a day. It is off by default for that reason.
	LogQueries bool `json:"log_queries"`

	// NoIPv6 answers AAAA queries with no answer.
	//
	// Useful while IPv6 is not configured: a working AAAA record for a path
	// that does not work yet sends clients down a route that fails slowly
	// rather than letting them fall back to IPv4 immediately.
	NoIPv6 bool `json:"no_ipv6"`

	// RejectUnmappedBlocks answers queries for addresses that have no local
	// mapping, which is what a gateway should do to avoid becoming a DNS
	// rebinding proxy.
	RejectUnmappedBlocks bool `json:"reject_unmapped_blocks"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty"`
}

// Record is a name THN serves for a local address.
type Record struct {
	// Hostname is the name to serve, without the domain suffix.
	Hostname string `json:"hostname"`
	// Address is the address it resolves to.
	Address netip.Addr `json:"address"`
	// Aliases are additional names for the same address.
	Aliases []string `json:"aliases,omitempty"`
}

// FQDN renders the record's primary name with the local domain appended.
func (r Record) FQDN(domain string) string {
	if domain == "" {
		return r.Hostname
	}
	if strings.HasSuffix(r.Hostname, ".") {
		return r.Hostname + domain
	}
	return r.Hostname + "." + domain
}

// Default returns a policy serving the LAN from this host.
func Default(iface string, gateway netip.Addr) Policy {
	return Policy{
		Enabled:       true,
		Interface:     iface,
		ListenAddress: gateway,
		Upstream: []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("9.9.9.9"),
		},
		LocalDomain:          "lan",
		LocalRecords:         []Record{},
		CacheSize:            1000,
		LogQueries:           false,
		NoIPv6:               false,
		RejectUnmappedBlocks: true,
	}
}

// Clone returns a deep copy.
//
// The renderer normalises a clone, so without this a caller could have its
// policy reordered underneath a render in progress.
func (p Policy) Clone() Policy {
	out := p

	if p.Upstream != nil {
		out.Upstream = append([]netip.Addr(nil), p.Upstream...)
	}
	if p.LocalRecords != nil {
		out.LocalRecords = make([]Record, len(p.LocalRecords))
		for i, r := range p.LocalRecords {
			out.LocalRecords[i] = r
			if r.Aliases != nil {
				out.LocalRecords[i].Aliases = append([]string(nil), r.Aliases...)
			}
		}
	}
	if p.Comments != nil {
		out.Comments = append([]string(nil), p.Comments...)
	}

	return out
}

// Normalise sorts the policy's collections for deterministic rendering.
func (p *Policy) Normalise() {
	sort.SliceStable(p.Upstream, func(i, j int) bool {
		return p.Upstream[i].Compare(p.Upstream[j]) < 0
	})
	sort.SliceStable(p.LocalRecords, func(i, j int) bool {
		return p.LocalRecords[i].Hostname < p.LocalRecords[j].Hostname
	})
	for i := range p.LocalRecords {
		sort.Strings(p.LocalRecords[i].Aliases)
	}
}

// UpstreamStrings renders the upstreams as strings.
func (p Policy) UpstreamStrings() []string {
	out := make([]string, 0, len(p.Upstream))
	for _, u := range p.Upstream {
		out = append(out, u.String())
	}
	return out
}

// String renders a one-line summary.
func (p Policy) String() string {
	return fmt.Sprintf("dns on %s: %d upstream(s), domain %s, %d local record(s), cache %d, logging=%t",
		orNone(p.Interface), len(p.Upstream), orNone(p.LocalDomain),
		len(p.LocalRecords), p.CacheSize, p.LogQueries)
}

// orNone renders an empty string as a placeholder.
func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// Severity classifies a validation finding.
type Severity string

const (
	// SeverityError means the policy must not be rendered.
	SeverityError Severity = "error"
	// SeverityWarning means it is renderable but likely wrong.
	SeverityWarning Severity = "warning"
	// SeverityInfo is informational.
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
	// Field alone cannot separate the upstream findings from one another:
	// "upstream[0]" is produced by an unparseable address, an unspecified
	// address and a loopback address, which are different mistakes with
	// different fixes. The code is the vocabulary a consumer dispatches on;
	// Message is free to be reworded.
	//
	// Empty where this package has not yet classified the finding.
	Code string `json:"code,omitempty"`

	// Severity classifies the finding.
	Severity Severity `json:"severity"`
	// Message describes the problem.
	Message string `json:"message"`
	// Hint suggests a correction.
	Hint string `json:"hint,omitempty"`
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
// These are the stable, machine-readable reasons a DNS intent is not
// satisfied. They are a vocabulary, not sentences.
const (
	// CodeDisabled means the document does not ask for a DNS service.
	CodeDisabled = "dns-disabled"

	// CodeLANMissing means DNS was requested with no LAN to serve.
	CodeLANMissing = "dns-lan-missing"

	// CodeLANUnresolved means the LAN role is written down but matches no
	// observed interface.
	CodeLANUnresolved = "dns-lan-unresolved"

	// CodeLANAddressMissing means DNS was requested but the LAN has no
	// address to listen on.
	CodeLANAddressMissing = "dns-lan-address-missing"

	// CodeUpstreamMissing means DNS is enabled with no resolver to forward
	// to, so every query would fail.
	CodeUpstreamMissing = "dns-upstream-missing"

	// CodeUpstreamInvalid means a named resolver cannot be one.
	CodeUpstreamInvalid = "dns-upstream-invalid"

	// CodeUpstreamDuplicate means the same resolver is listed more than
	// once.
	CodeUpstreamDuplicate = "dns-upstream-duplicate"

	// CodeUpstreamConflict means dns.upstream and network.dns were both
	// declared and disagree.
	//
	// Both are authoritative and both name resolvers, so a document that
	// disagrees with itself has no single answer to use. Preferring one
	// silently is what made this invisible before: editing dns.upstream did
	// nothing and said nothing.
	CodeUpstreamConflict = "dns-upstream-conflict"

	// CodeCacheInvalid means the cache size cannot be honoured.
	CodeCacheInvalid = "dns-cache-invalid"

	// CodeDomainInvalid means the local domain is not a DNS name.
	CodeDomainInvalid = "dns-domain-invalid"

	// CodeRecordInvalid means a local record cannot be served.
	CodeRecordInvalid = "dns-record-invalid"
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

	for i := 1; i < len(r.Findings); i++ {
		for j := i; j > 0 && r.Findings[j].Severity.rank() < r.Findings[j-1].Severity.rank(); j-- {
			r.Findings[j], r.Findings[j-1] = r.Findings[j-1], r.Findings[j]
		}
	}
}

// Errors returns the error-level findings.
func (r Result) Errors() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			out = append(out, f)
		}
	}
	return out
}

// Validate checks a DNS policy for renderability.
//
// The checks concentrate on failure modes a client experiences rather than THN:
// an empty upstream list means every query fails, and an upstream that is
// unreachable or on the LAN itself produces timeouts rather than errors.
func Validate(p Policy) Result {
	var r Result

	if !p.Enabled {
		r.infoc(CodeDisabled, "enabled",
			"DNS is disabled; clients would have to be pointed at an external resolver", "")
		r.finalise()
		return r
	}

	// An empty upstream list is the most consequential mistake here: dnsmasq
	// starts happily and answers nothing, and the LAN appears to have a
	// working network that cannot resolve anything.
	if len(p.Upstream) == 0 {
		r.errorc(CodeUpstreamMissing, "upstream",
			"no upstream resolvers are configured, so every query would fail",
			"set dns.upstream to at least one resolver")
	}

	// seen lets a repeated resolver be reported rather than silently
	// forwarded to twice. It is not an error: listing 1.1.1.1 twice is a
	// harmless typo, not a broken network. But it is worth saying, because
	// the operator almost certainly meant to list a second resolver.
	seen := make(map[netip.Addr]int, len(p.Upstream))

	for i, u := range p.Upstream {
		field := fmt.Sprintf("upstream[%d]", i)

		if u.IsValid() {
			if prev, dup := seen[u]; dup {
				r.warnc(CodeUpstreamDuplicate, field,
					fmt.Sprintf("resolver %s is already listed at index %d", u, prev),
					"list each resolver once; a duplicate is forwarded to twice")
			}
			seen[u] = i
		}

		switch {
		case !u.IsValid():
			r.errorc(CodeUpstreamInvalid, field, "the resolver address is not valid", "")
		case u.IsUnspecified():
			r.errorc(CodeUpstreamInvalid, field,
				"the unspecified address is not a resolver",
				"use a real resolver such as 1.1.1.1")
		case u.IsMulticast():
			r.errorc(CodeUpstreamInvalid, field, "a multicast address is not a resolver", "")
		case u.IsLoopback():
			// Pointing dnsmasq at itself creates a forwarding loop that
			// presents as every query timing out.
			r.errorc(CodeUpstreamInvalid, field,
				fmt.Sprintf("resolver %s is a loopback address, which would forward queries to itself", u),
				"point at an external resolver, or omit upstream entirely to serve only local names")
		case u.IsPrivate():
			// Not fatal: a resolver on the LAN is a legitimate design, such
			// as a Pi-hole. But it deserves a warning because it is usually a
			// typo when the gateway itself is meant to be the resolver.
			r.warnc(CodeUpstreamInvalid, field,
				fmt.Sprintf("resolver %s is a private address; THN will forward queries to the LAN", u),
				"that is correct only if another host on the LAN is intended to serve DNS")
		case u.IsLinkLocalUnicast():
			r.warnc(CodeUpstreamInvalid, field,
				fmt.Sprintf("resolver %s is a link-local address with a limited lifetime", u), "")
		}
	}

	if p.CacheSize < 0 {
		r.errorc(CodeCacheInvalid, "cache_size", "the cache size must not be negative", "use 0 for the backend default")
	} else if p.CacheSize > 0 && p.CacheSize < 100 {
		r.warnc(CodeCacheInvalid, "cache_size",
			fmt.Sprintf("a cache of %d answers is very small and will miss constantly", p.CacheSize),
			"1000 is a reasonable starting point")
	}

	if p.LocalDomain != "" && strings.ContainsAny(p.LocalDomain, " \t/:") {
		r.errorc(CodeDomainInvalid, "local_domain",
			fmt.Sprintf("the local domain %q contains characters a DNS name cannot", p.LocalDomain), "")
	}

	validateRecords(&r, p)

	if p.LogQueries {
		r.infoc(CodeCacheInvalid, "log_queries",
			"query logging is enabled; this writes to disk continuously and is the fastest way to fill a small filesystem",
			"keep it on only while investigating")
	}

	r.finalise()
	return r
}

// validateRecords checks the locally served names.
func validateRecords(r *Result, p Policy) {
	seen := map[string]int{}

	for i, rec := range p.LocalRecords {
		field := fmt.Sprintf("local_records[%d]", i)

		if rec.Hostname == "" {
			r.errorc(CodeRecordInvalid, field+".hostname", "the record needs a hostname", "")
			continue
		}

		if !isValidLabel(rec.Hostname) {
			r.errorc(CodeRecordInvalid, field+".hostname",
				fmt.Sprintf("%q is not a valid DNS label", rec.Hostname),
				"use letters, digits and dashes; it must start with a letter or digit")
		}

		if prev, dup := seen[rec.Hostname]; dup {
			r.errorc(CodeRecordInvalid, field+".hostname",
				fmt.Sprintf("the name %q is already defined at index %d", rec.Hostname, prev),
				"a name may only resolve one way; add the address as an alias instead")
		}
		seen[rec.Hostname] = i

		switch {
		case !rec.Address.IsValid():
			r.errorc(CodeRecordInvalid, field+".address", "the record needs a valid address", "")
		case rec.Address.IsUnspecified():
			r.errorc(CodeRecordInvalid, field+".address",
				"a record pointing at the unspecified address would answer with 0.0.0.0",
				"use the address of the host this name refers to")
		case rec.Address.IsMulticast():
			r.errorc(CodeRecordInvalid, field+".address", "a record must not point at a multicast address", "")
		}

		for j, alias := range rec.Aliases {
			if alias == rec.Hostname {
				r.warnc(CodeRecordInvalid, fmt.Sprintf("%s.aliases[%d]", field, j),
					fmt.Sprintf("the alias %q repeats the record's own name", alias), "")
			}
			if !isValidLabel(alias) {
				r.errorc(CodeRecordInvalid, fmt.Sprintf("%s.aliases[%d]", field, j),
					fmt.Sprintf("%q is not a valid DNS label", alias), "")
			}
		}
	}
}

// isValidLabel reports whether s is a valid DNS label.
func isValidLabel(s string) bool {
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
