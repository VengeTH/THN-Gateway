package netconfig

import (
	"fmt"
	"sort"
	"strings"
)

// Severity classifies a validation finding.
type Severity string

const (
	// SeverityError means the policy must not be rendered or acted on.
	SeverityError Severity = "error"
	// SeverityWarning means the policy is usable but suspect.
	SeverityWarning Severity = "warning"
	// SeverityInfo is informational, typically the expected development state.
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
	// Severity classifies the finding.
	Severity Severity `json:"severity"`
	// Message describes the problem.
	Message string `json:"message"`
	// Hint suggests a correction, when there is an obvious one.
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
	// Coherent reports whether the three subsystems agree with each other.
	// A policy can be internally valid in each subsystem and still be
	// incoherent between them, which is the failure worth surfacing.
	Coherent bool `json:"coherent"`
}

// add appends a finding.
func (r *Result) add(field string, sev Severity, msg, hint string) {
	r.Findings = append(r.Findings, Finding{Field: field, Severity: sev, Message: msg, Hint: hint})
}

// errorf appends an error finding.
func (r *Result) errorf(field, msg, hint string) { r.add(field, SeverityError, msg, hint) }

// warnf appends a warning finding.
func (r *Result) warnf(field, msg, hint string) { r.add(field, SeverityWarning, msg, hint) }

// infof appends an informational finding.
func (r *Result) infof(field, msg, hint string) { r.add(field, SeverityInfo, msg, hint) }

// Errors returns the error-level findings.
func (r Result) Errors() []Finding { return r.bySeverity(SeverityError) }

// Warnings returns the warning-level findings.
func (r Result) Warnings() []Finding { return r.bySeverity(SeverityWarning) }

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

// CoherenceIssue is a disagreement between subsystems.
type CoherenceIssue struct {
	// Subsystems names the subsystems involved.
	Subsystems string `json:"subsystems"`
	// Message describes the disagreement.
	Message string `json:"message"`
}

// Validate checks a policy for internal validity and cross-subsystem
// coherence.
//
// The two are separate because they fail differently. An invalid policy has a
// mistake in one place. An incoherent policy is individually correct in each
// subsystem and wrong in combination — a gateway with NAT enabled and no LAN,
// or forwarding rules for interfaces that do not exist.
func Validate(p Policy) (Result, []CoherenceIssue) {
	var r Result

	validateStructure(&r, p)
	validateRouting(&r, p)
	validateNAT(&r, p)
	validateForwarding(&r, p)

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

	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity.rank() < b.Severity.rank()
		}
		return a.Field < b.Field
	})

	issues := checkCoherence(p)
	r.Coherent = len(issues) == 0

	return r, issues
}

// validateStructure checks the policy's overall shape.
func validateStructure(r *Result, p Policy) {
	if p.Version != PolicyVersion {
		r.errorf("version",
			fmt.Sprintf("unsupported policy version %d", p.Version),
			"this build produces version "+itoa(PolicyVersion))
	}

	if p.Interfaces.WAN != "" && p.Interfaces.LAN != "" &&
		p.Interfaces.WAN == p.Interfaces.LAN {
		r.errorf("interfaces.lan",
			fmt.Sprintf("the WAN and LAN are both %q", p.Interfaces.WAN),
			"they must be different interfaces")
	}

	for _, iface := range []struct{ field, name string }{
		{"interfaces.wan", p.Interfaces.WAN},
		{"interfaces.lan", p.Interfaces.LAN},
	} {
		if iface.name == "" {
			continue
		}
		isSelector := strings.HasPrefix(iface.name, "hw:") || strings.HasPrefix(iface.name, "ephemeral:")
		if !isSelector && len(iface.name) > 15 {
			r.errorf(iface.field,
				fmt.Sprintf("interface name %q exceeds the 15 characters Linux permits", iface.name), "")
		}
		if strings.ContainsAny(iface.name, " \t\n") {
			r.errorf(iface.field,
				fmt.Sprintf("interface name %q contains whitespace", iface.name), "")
		}
	}
}

// validateRouting checks the routing table.
func validateRouting(r *Result, p Policy) {
	rt := p.Routing

	if !rt.Enabled {
		r.infof("routing.enabled",
			"routing is disabled; this device is a bridge, not a gateway", "")
		return
	}

	if !rt.IPv4Enabled && !rt.IPv6Enabled {
		r.errorf("routing.ipv4_enabled",
			"neither IPv4 nor IPv6 routing is enabled, so no traffic can be forwarded",
			"enable at least one")
	}

	if rt.IPv6Enabled && !rt.AcceptRA {
		r.warnf("routing.accept_ra",
			"IPv6 routing is enabled but router advertisements are not accepted",
			"without accepting RAs the host learns no IPv6 default route or address")
	}

	if rt.AcceptRA && rt.IPv6Enabled {
		r.warnf("routing.accept_ra",
			"accepting IPv6 router advertisements lets an upstream choose this host's addresses and routes",
			"this is normal for a residential gateway, but be aware it is unauthenticated")
	}

	// Routes.
	seen := map[string]int{}
	for i, route := range rt.Routes {
		field := fmt.Sprintf("routing.routes[%d]", i)

		if !route.Destination.IsValid() {
			r.errorf(field+".destination", "the destination prefix is not valid", "")
			continue
		}

		if route.Interface == "" {
			r.errorf(field+".interface",
				"a route must name its egress interface",
				"set the interface this route leaves through")
		}

		if route.Metric < 0 {
			r.errorf(field+".metric", "the metric must not be negative", "use 0 for the default")
		}

		if route.NextHop.IsValid() {
			// A next hop must be outside the destination network, otherwise
			// the route is a forwarding loop.
			if route.Destination.Contains(route.NextHop) {
				r.errorf(field+".next_hop",
					fmt.Sprintf("the next hop %s is inside the destination %s, which would loop",
						route.NextHop, route.Destination),
					"point the next hop at a router on the adjacent network")
			}
			if route.Source.IsValid() && route.Source.IsUnspecified() {
				r.errorf(field+".source", "the source address must not be unspecified", "")
			}
		}

		key := route.Destination.String()
		if prev, dup := seen[key]; dup {
			// Duplicate prefixes are legal only if their metrics differ,
			// because the metric is what disambiguates them.
			if rt.Routes[prev].Metric == route.Metric {
				r.errorf(field+".destination",
					fmt.Sprintf("destination %s is already defined at index %d with the same metric",
						key, prev),
					"give the routes different metrics, or remove the duplicate")
			} else {
				r.infof(field+".destination",
					fmt.Sprintf("destination %s is also defined at index %d with a different metric, which is a valid failover pair",
						key, prev), "")
			}
		}
		seen[key] = i
	}

	// Default route.
	if rt.DefaultGateway.IsValid() && rt.DefaultGatewayInterface == "" {
		r.errorf("routing.default_gateway_interface",
			fmt.Sprintf("a default gateway (%s) is set but no egress interface is named", rt.DefaultGateway),
			"set routing.default_gateway_interface")
	}
	if rt.DefaultGatewayInterface != "" && !rt.DefaultGateway.IsValid() && p.Interfaces.WAN == "" {
		r.infof("routing.default_gateway_interface",
			fmt.Sprintf("a default route via %s is configured but no gateway address is set; the uplink may supply it over DHCP",
				rt.DefaultGatewayInterface), "")
	}

	if rt.DefaultMetric < 0 {
		r.errorf("routing.default_metric", "the default metric must not be negative", "")
	}

	// A default gateway inside the LAN prefix would send traffic back down
	// the segment it came from.
	if rt.DefaultGateway.IsValid() && len(rt.Routes) > 0 {
		for _, route := range rt.Routes {
			if route.Interface == p.Interfaces.LAN && route.Destination.Contains(rt.DefaultGateway) {
				r.errorf("routing.default_gateway",
					fmt.Sprintf("the default gateway %s is inside the LAN network %s",
						rt.DefaultGateway, route.Destination),
					"the default route must leave through the WAN")
			}
		}
	}
}

// validateNAT checks address translation.
func validateNAT(r *Result, p Policy) {
	n := p.NAT

	if !n.Enabled {
		// The cross-subsystem consequence is reported by checkCoherence,
		// which owns cross-cutting findings. Duplicating it here would
		// report the same problem twice with different wording.
		return
	}

	switch n.Mode {
	case NATMasquerade:
		if n.OutInterface == "" {
			r.warnf("nat.out_interface",
				"masquerading has no egress interface, so it would apply to every interface including the LAN",
				"set nat.out_interface to the WAN")
		} else if n.OutInterface == p.Interfaces.LAN && p.Interfaces.LAN != "" {
			r.errorf("nat.out_interface",
				fmt.Sprintf("masquerading is scoped to the LAN interface (%s)", n.OutInterface),
				"set it to the WAN")
		}
		if n.SNATAddress.IsValid() {
			r.warnf("nat.snat_address",
				"a static SNAT address is set but the mode is masquerade, so it will be ignored",
				"set nat.mode to snat, or remove the address")
		}

	case NATSNAT:
		if !n.SNATAddress.IsValid() && !n.SNATPrefix.IsValid() {
			r.errorf("nat.snat_address",
				"SNAT requires a translation address or prefix",
				"set nat.snat_address")
		}
		if n.OutInterface == "" {
			r.warnf("nat.out_interface",
				"SNAT has no egress interface, so it would match traffic leaving any interface",
				"set nat.out_interface to the WAN")
		}

	case NATNone:
		r.warnf("nat.mode",
			"NAT is enabled but the mode is \"none\", which translates nothing",
			"set nat.mode to masquerade or snat, or disable NAT")

	default:
		r.errorf("nat.mode",
			fmt.Sprintf("unknown NAT mode %q", n.Mode),
			"supported modes are none, masquerade and snat")
	}

	if n.InInterface != "" && n.InInterface != p.Interfaces.LAN && p.Interfaces.LAN != "" {
		r.warnf("nat.in_interface",
			fmt.Sprintf("NAT ingress is restricted to %q, which is not the configured LAN (%s)",
				n.InInterface, p.Interfaces.LAN),
			"LAN traffic will not be translated")
	}
}

// validateForwarding checks the forwarding configuration.
func validateForwarding(r *Result, p Policy) {
	f := p.Forwarding

	// Forwarding enabled with no rules at all is a kernel setting that looks
	// meaningful but drops everything.
	if (f.IPv4Enabled || f.IPv6Enabled) && len(f.Rules) == 0 {
		r.warnf("forwarding.rules",
			"forwarding is enabled in the kernel but no forwarding rules are defined, so every forwarded packet is dropped",
			"add a lan-to-wan rule")
	}

	if !f.IPv4Enabled && !f.IPv6Enabled {
		r.warnf("forwarding.ipv4_enabled",
			"neither IPv4 nor IPv6 forwarding is enabled; the kernel will drop every forwarded packet",
			"enable forwarding, or this device does not route")
	}

	seen := map[ForwardDirection]bool{}
	for i, rule := range f.Rules {
		field := fmt.Sprintf("forwarding.rules[%d]", i)

		switch rule.Direction {
		case LANToWAN, WANToLAN, LANToLAN, WANToWAN:
		default:
			r.errorf(field+".direction",
				fmt.Sprintf("unknown forwarding direction %q", rule.Direction),
				"valid directions are lan-to-wan, wan-to-lan, lan-to-lan and wan-to-wan")
		}

		switch rule.Action {
		case "accept", "drop", "reject":
		default:
			r.errorf(field+".action",
				fmt.Sprintf("unknown action %q", rule.Action),
				"valid actions are accept, drop and reject")
		}

		if seen[rule.Direction] {
			r.warnf(field+".direction",
				fmt.Sprintf("direction %s is defined more than once; only the most specific match is used",
					rule.Direction),
				"remove the earlier rule")
		}
		seen[rule.Direction] = true

		for j, src := range rule.Source {
			if !src.IsValid() {
				r.errorf(fmt.Sprintf("%s.source[%d]", field, j),
					fmt.Sprintf("%q is not a valid prefix", src), "")
			}
			if src.Bits() == 0 {
				r.warnf(fmt.Sprintf("%s.source[%d]", field, j),
					fmt.Sprintf("source %s matches every address, making the rule equivalent to having no source restriction", src), "")
			}
		}
		for j, dst := range rule.Destination {
			if !dst.IsValid() {
				r.errorf(fmt.Sprintf("%s.destination[%d]", field, j),
					fmt.Sprintf("%q is not a valid prefix", dst), "")
			}
		}
	}

	if f.IPv6Enabled && !p.Routing.IPv6Enabled {
		r.warnf("forwarding.ipv6_enabled",
			"IPv6 forwarding is enabled but IPv6 routing is not",
			"enable routing.ipv6_enabled, or disable IPv6 forwarding")
	}
}

// checkCoherence looks for disagreements between subsystems.
//
// This is where the failures that matter actually live. Each subsystem can be
// individually valid while the combination can never work, and no amount of
// per-subsystem validation catches that.
func checkCoherence(p Policy) []CoherenceIssue {
	var issues []CoherenceIssue

	issue := func(subsystems, msg string) {
		issues = append(issues, CoherenceIssue{Subsystems: subsystems, Message: msg})
	}

	routing, nat, fwd := p.Routing, p.NAT, p.Forwarding

	// NAT requires a LAN to translate. Without one there is nothing to
	// masquerade, and an unscoped rule would translate the wrong traffic.
	if nat.Enabled && p.Interfaces.LAN == "" {
		issue("nat+interfaces",
			"NAT is enabled but no LAN interface is identified; there is no downstream traffic to translate, and an unscoped masquerade rule would rewrite traffic leaving every interface")
	}

	// Forwarding rules referencing interfaces that are not configured can
	// never match, which is a silent failure: the gateway looks configured
	// and simply carries no traffic.
	if fwd.HasRule(LANToWAN) && p.Interfaces.LAN == "" {
		issue("forwarding+interfaces",
			"LAN-to-WAN forwarding is configured but no LAN interface is identified; the rule cannot match any packet")
	}
	if fwd.HasRule(WANToLAN) && p.Interfaces.WAN == "" {
		issue("forwarding+interfaces",
			"WAN-to-LAN forwarding is configured but no WAN interface is identified; the rule cannot match any packet")
	}

	// Accepting LAN-to-WAN without NAT produces a gateway whose clients have
	// an interface that appears to work and cannot reach anything.
	accepts := func(d ForwardDirection) bool {
		rule, ok := fwd.RuleFor(d)
		return ok && rule.Action == "accept"
	}
	if accepts(LANToWAN) && !nat.Enabled {
		issue("forwarding+nat",
			"LAN-to-WAN traffic is accepted but NAT is disabled; the upstream will drop return traffic to unroutable source addresses")
	}

	// Routes through an interface that does not exist are dead entries.
	for i, route := range routing.Routes {
		if route.Interface == "" {
			continue
		}
		role := p.Interfaces.RoleOf(route.Interface)
		if role == RoleUnknown {
			issue("routing+interfaces",
				fmt.Sprintf("routing.routes[%d] uses interface %q, which is neither the WAN nor the LAN", i, route.Interface))
		}
	}

	// A default route through the LAN sends internet traffic back down the
	// segment it came from.
	if routing.DefaultGatewayInterface != "" && routing.DefaultGatewayInterface == p.Interfaces.LAN && p.Interfaces.LAN != "" {
		issue("routing+interfaces",
			fmt.Sprintf("the default route exits through the LAN interface (%s), so traffic would loop back down the downstream segment",
				p.Interfaces.LAN))
	}

	// Routes for the same network as the default route make the default
	// unreachable through those interfaces.
	if routing.DefaultGatewayInterface != "" {
		for i, route := range routing.Routes {
			if route.Interface == routing.DefaultGatewayInterface && route.Destination.Bits() == 0 {
				issue("routing",
					fmt.Sprintf("routing.routes[%d] is a default route via %s, duplicating routing.default_gateway_interface",
						i, route.Interface))
			}
		}
	}

	// Forwarding enabled with no rules: the kernel would drop everything that
	// reaches the forward chain.
	if (fwd.IPv4Enabled || fwd.IPv6Enabled) && len(fwd.Rules) == 0 {
		issue("forwarding",
			"forwarding is enabled in the kernel but no forwarding rules are defined, so every forwarded packet meets the default drop")
	}

	// Routing enabled but forwarding disabled: the kernel will not route.
	if routing.IPv4Enabled && !fwd.IPv4Enabled {
		issue("routing+forwarding",
			"IPv4 routing is configured but kernel forwarding is disabled; no IPv4 packet will be forwarded regardless of the rules")
	}

	return issues
}

// RuleFor2 returns the action of a direction's rule, or "" when none exists.
// It exists so the NAT validator can ask the question without unpacking a
// two-value return in a boolean context.
func (f Forwarding) RuleFor2(d ForwardDirection) string {
	rule, ok := f.RuleFor(d)
	if !ok {
		return ""
	}
	return rule.Action
}

// itoa renders an int without importing strconv at the call site.
func itoa(n int) string { return fmt.Sprintf("%d", n) }
