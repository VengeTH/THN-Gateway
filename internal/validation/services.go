// Package-level integration of subsystem validators into the combined result.
//
// # Why this file exists
//
// internal/validation is documented as "the only place validation rules live",
// and `thn validate` is the documented CI gate. DHCP validation does not live
// here: it lives in internal/dhcp, which owns the range arithmetic and the
// pool policy, and which `thn dhcp validate` has always called directly.
//
// That ownership is correct and is not being moved. What was missing was any
// path from `thn validate` to it, which meant a configuration document with a
// pool that runs off the end of the LAN passed the CI gate with exit 0. The
// gate reported that the document was fine, because the gate had never asked
// the component that knows.
//
// So this file carries findings in. It copies nothing. internal/dhcp still
// decides what a valid pool is; this only reshapes what it already decided so
// that `thn validate` and `thn dhcp validate` cannot disagree about a pool,
// and both can only disagree by forgetting to call dhcp.Validate.

package validation

import "github.com/venth/thn-gateway/internal/dhcp"

// DHCPFieldPrefix namespaces a DHCP finding in the combined result.
//
// Every other subsystem in a combined finding is already namespaced —
// network.lan_prefix, firewall.backend, nat.interfaces[0] — so a bare
// "ranges[0]" would be ambiguous against dns or firewall findings. The
// unprefixed path is still reachable: `thn dhcp validate` prints
// "ranges[0].end", and the prefixed form contains it as a substring, so a CI
// log grep for either matches.
const DHCPFieldPrefix = "dhcp."

// FromDHCP projects a DHCP validation result into this package's model.
//
// Severity is carried across one-for-one and the field path is preserved
// apart from the namespace prefix, so "ranges[0].end" becomes
// "dhcp.ranges[0].end" and nothing is flattened into a generic message. A
// caller that needs the unprefixed path calls internal/dhcp directly, which
// is what `thn dhcp validate` does.
//
// The result is finalised, so it is internally coherent on its own and can be
// printed or serialised without being merged first.
func FromDHCP(r dhcp.Result) Result {
	out := Result{
		Findings: make([]Finding, 0, len(r.Findings)),
		Layers:   []Layer{LayerStatic},
	}

	for _, f := range r.Findings {
		out.Findings = append(out.Findings, Finding{
			// DHCP is checked against the document alone. No host
			// observation changes whether a pool is inside the LAN, so
			// these findings are static even under `thn validate --live`.
			Layer:    LayerStatic,
			Field:    DHCPFieldPrefix + f.Field,
			Severity: fromDHCPSeverity(f.Severity),
			Message:  f.Message,
			Hint:     f.Hint,
		})
	}

	out.finalise()
	return out
}

// fromDHCPSeverity maps a DHCP severity onto this package's.
//
// The mapping is total, and the fallback is deliberately an error rather than
// a drop: silently discarding a finding this package does not recognise would
// turn a refusal into a passing document, which is the failure mode this whole
// change exists to prevent. Failing closed is the right direction for an
// unknown value.
//
// Every constant the DHCP package defines is mapped explicitly, including
// SeverityInfo. Mapping it via the fallback would be a quiet way to turn
// every informational DHCP note into an error and fail every document that
// has a domain name but no interface yet.
func fromDHCPSeverity(s dhcp.Severity) Severity {
	switch s {
	case dhcp.SeverityError:
		return SeverityError
	case dhcp.SeverityWarning:
		return SeverityWarning
	case dhcp.SeverityInfo:
		return SeverityInfo
	default:
		return SeverityError
	}
}

// Merge folds another result's findings into this one and recounts.
//
// It builds a fresh Result rather than appending to the receiver, because
// finalise adds to the existing counts rather than resetting them: merging in
// place would count every finding the receiver already had a second time, and
// report an error count of two for one DHCP error.
//
// The layer set is the union, in order, so the caller still reports which
// passes ran.
func (r Result) Merge(other Result) Result {
	merged := Result{
		Findings: append(append([]Finding{}, r.Findings...), other.Findings...),
		Layers:   mergeLayers(r.Layers, other.Layers),
	}
	merged.finalise()
	return merged
}

// mergeLayers unions two layer sets, preserving order and dropping repeats.
func mergeLayers(a, b []Layer) []Layer {
	out := make([]Layer, 0, len(a)+len(b))
	seen := make(map[Layer]bool, len(a)+len(b))

	for _, l := range append(append([]Layer{}, a...), b...) {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
