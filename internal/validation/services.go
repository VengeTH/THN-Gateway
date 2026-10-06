// Package-level integration of subsystem validators into the combined result.
//
// # Why this file exists
//
// internal/validation is documented as "the only place validation rules live",
// and `thn validate` is the documented CI gate. Four subsystems validate
// themselves somewhere other than here: internal/dhcp, internal/dns,
// internal/firewall/policy and internal/netconfig. Each owns its own rules,
// and each is reached only by its own command — `thn dhcp validate`,
// `thn firewall validate`, `thn net validate`.
//
// That ownership is correct and is not being moved. What was missing was any
// path from `thn validate` to them, which meant a document with a pool that
// runs off the end of the LAN, a ruleset that cannot be reached, or a NAT
// rule pointing at an interface that does not exist all passed the CI gate
// with exit 0. The gate reported the document was fine, because the gate had
// never asked the components that know.
//
// So this file carries findings in. It copies nothing. Each subsystem still
// decides what is valid; this only reshapes what it already decided so that
// `thn validate` and the per-subsystem commands cannot disagree, and they can
// only disagree by forgetting to call the subsystem validator.
//
// # What is deliberately NOT folded in
//
// internal/qos is not here. qos.Validate takes an Availability describing what
// the host kernel supports, which is a host observation. Calling it from the
// static layer would mean passing an Availability this package invented, and
// an invented "nothing available" turns every enabled shaping config into an
// error. `thn validate` must stay deterministic and host-free to be a CI
// gate, so QoS keeps its own command and says so rather than guessing.

package validation

import (
	"strings"

	"github.com/venth/thn-gateway/internal/dhcp"
	"github.com/venth/thn-gateway/internal/dns"
	fwpolicy "github.com/venth/thn-gateway/internal/firewall/policy"
	"github.com/venth/thn-gateway/internal/gateway"
	"github.com/venth/thn-gateway/internal/netconfig"
)

// Subsystem field prefixes.
//
// Every folded subsystem's findings are namespaced so that a reader — and a CI
// log grep — can tell which component produced a finding. Every other field in
// a combined result is already namespaced this way (network.lan_prefix,
// firewall.backend, nat.interfaces[0]), so this makes DHCP's bare "ranges[0]"
// consistent with the rest rather than inventing a second convention.
//
// The prefix is prepended, never substituted: "ranges[0].end" becomes
// "dhcp.ranges[0].end", which still contains the original as a substring, so a
// grep for either form matches.
const (
	DHCPFieldPrefix     = "dhcp."
	DNSFieldPrefix      = "dns."
	FirewallFieldPrefix = "firewall."
	NetFieldPrefix      = "net."
	GatewayFieldPrefix  = "gateway."
)

// FromGateway projects a gateway intent report into this package's model.
//
// The layer is chosen by what the finding was decided against, not by which
// package produced it. A role that resolved on this host was decided against
// the host; a malformed LAN address was decided against the document. Filing
// both as static would make `thn validate --live` report a resolved role as
// though no host had been consulted.
func FromGateway(r gateway.Report, live bool) Result {
	layer := LayerStatic
	if live {
		layer = LayerLive
	}

	in := make([]subsystemFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		in = append(in, subsystemFinding{
			field:    f.Code,
			severity: gatewaySeverity(f.Severity),
			message:  gatewayMessage(f),
			hint:     f.Hint,
		})
	}

	// projectResult hardcodes LayerStatic because every subsystem folded so
	// far checks the document against itself. This one does not, so its
	// layer is corrected afterwards rather than by teaching projectResult
	// about an exception.
	out := projectResult(GatewayFieldPrefix, in)
	for i := range out.Findings {
		out.Findings[i].Layer = layer
	}
	out.finalise()
	return out
}

// gatewaySeverity maps the gateway vocabulary onto this package's.
func gatewaySeverity(s gateway.Severity) string {
	switch s {
	case gateway.SeverityBlocking:
		return "error"
	case gateway.SeverityWarning:
		return "warning"
	default:
		return "info"
	}
}

// gatewayMessage renders a gateway finding as one sentence.
//
// The role, the selector and the resolved identity are folded into the text
// rather than dropped, because that is the difference between "the LAN is
// unresolved" and "the LAN selector hw:2c88 resolves to enx0011, which is a
// container bridge". Only the message carries them — the structured fields
// remain on gateway.Finding for JSON consumers — so the two cannot drift.
func gatewayMessage(f gateway.Finding) string {
	var b strings.Builder
	b.WriteString(f.Message)

	var facts []string
	if f.Role != "" {
		facts = append(facts, "role "+string(f.Role))
	}
	if f.Selector != "" {
		facts = append(facts, "selector "+f.Selector)
	}
	if f.Interface != "" {
		facts = append(facts, "interface "+f.Interface)
	}
	if f.StableID != "" {
		facts = append(facts, "stable id "+f.StableID)
	}
	if len(facts) > 0 {
		b.WriteString(" (")
		b.WriteString(strings.Join(facts, ", "))
		b.WriteString(")")
	}
	if len(f.Candidates) > 0 {
		b.WriteString(" candidates: " + strings.Join(f.Candidates, ", "))
	}

	return b.String()
}

// subsystemFinding is the shape every subsystem validator's finding shares.
//
// All four subsystems declare these same fields and use the same three
// severity strings. Modelling that once, rather than four times with four
// slightly different projections, is what keeps them from drifting: a change
// to how findings are carried has one place to change.
type subsystemFinding struct {
	field    string
	severity string
	message  string
	hint     string
}

// projectResult turns a subsystem's findings into this package's model.
//
// Nothing is flattened. The message and hint are carried across verbatim and
// the field path is preserved behind the prefix, because an operator told
// "dhcp.ranges[0].end" knows exactly which line to edit and an operator told
// "invalid configuration" does not.
func projectResult(prefix string, in []subsystemFinding) Result {
	out := Result{
		Findings: make([]Finding, 0, len(in)),
		Layers:   []Layer{LayerStatic},
	}

	for _, f := range in {
		out.Findings = append(out.Findings, Finding{
			// Each subsystem checks the document against itself. No host
			// observation changes whether a pool escapes the LAN or a
			// masquerade rule names a missing interface, so these are
			// static even under `thn validate --live`.
			Layer:    LayerStatic,
			Field:    prefix + f.field,
			Severity: severityOf(f.severity),
			Message:  f.message,
			Hint:     f.hint,
		})
	}

	out.finalise()
	return out
}

// severityOf maps the shared severity vocabulary onto this package's.
//
// The four subsystems all use the strings "error", "warning" and "info", so
// one mapping serves all of them and there is a single place where a value
// can be mishandled.
//
// Every value is enumerated explicitly and the fallback is an error rather
// than a drop. An earlier version of this file mapped error and warning by
// type and let info fall through to the fail-closed default; every
// configuration with a single-label domain and no configured interface then
// failed the gate with two phantom errors. Fail-closed is right for a value
// nobody recognises and wrong for one merely unlisted, so the enumeration must
// stay exhaustive.
func severityOf(s string) Severity {
	switch s {
	case "error":
		return SeverityError
	case "warning":
		return SeverityWarning
	case "info":
		return SeverityInfo
	default:
		return SeverityError
	}
}

// FromDHCP projects a DHCP validation result into this package's model.
//
// The result is finalised, so it is internally coherent on its own and can be
// printed or serialised without being merged first.
func FromDHCP(r dhcp.Result) Result {
	in := make([]subsystemFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		in = append(in, subsystemFinding{f.Field, string(f.Severity), f.Message, f.Hint})
	}
	return projectResult(DHCPFieldPrefix, in)
}

// FromDNS projects a DNS validation result into this package's model.
func FromDNS(r dns.Result) Result {
	in := make([]subsystemFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		in = append(in, subsystemFinding{f.Field, string(f.Severity), f.Message, f.Hint})
	}
	return projectResult(DNSFieldPrefix, in)
}

// FromFirewallPolicy projects a firewall policy result into this package's
// model.
func FromFirewallPolicy(r fwpolicy.Result) Result {
	in := make([]subsystemFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		in = append(in, subsystemFinding{f.Field, string(f.Severity), f.Message, f.Hint})
	}
	return projectResult(FirewallFieldPrefix, in)
}

// FromNetconfig projects a netconfig result, including its cross-subsystem
// coherence issues, into this package's model.
//
// Coherence issues are included because they are the failure worth surfacing:
// a policy can be internally valid in each of routing, NAT and forwarding and
// still be wrong in combination. They are reported as errors, which is what
// they mean.
func FromNetconfig(r netconfig.Result, issues []netconfig.CoherenceIssue) Result {
	in := make([]subsystemFinding, 0, len(r.Findings)+len(issues))
	for _, f := range r.Findings {
		in = append(in, subsystemFinding{f.Field, string(f.Severity), f.Message, f.Hint})
	}
	for _, c := range issues {
		in = append(in, subsystemFinding{
			field:    "coherence." + c.Subsystems,
			severity: "error",
			message:  c.Message,
			hint:     "the subsystems are each individually valid but disagree with each other",
		})
	}
	return projectResult(NetFieldPrefix, in)
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
