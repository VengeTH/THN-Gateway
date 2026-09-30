package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Severity classifies a validation finding.
type Severity string

const (
	// SeverityError means the policy must not be rendered into something an
	// operator would deploy.
	SeverityError Severity = "error"
	// SeverityWarning means the policy is renderable but carries a risk the
	// operator should know about.
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
	// Reachable reports whether the admin path survives the policy. This is
	// the field that matters most: a policy that is valid but unreachable
	// still bricks an unattended device.
	Reachable bool `json:"admin_reachable"`
	// Trace explains how the admin path is decided, rule by rule, so an
	// operator can audit the conclusion rather than trust it.
	Trace []string `json:"admin_trace,omitempty"`
}

// add appends a finding.
func (r *Result) add(field string, sev Severity, msg, hint string) {
	r.Findings = append(r.Findings, Finding{Field: field, Severity: sev, Message: msg, Hint: hint})
}

// errorf appends an error finding.
func (r *Result) errorf(field, msg, hint string) {
	r.add(field, SeverityError, msg, hint)
}

// warnf appends a warning finding.
func (r *Result) warnf(field, msg, hint string) {
	r.add(field, SeverityWarning, msg, hint)
}

// infof appends an informational finding.
func (r *Result) infof(field, msg, hint string) {
	r.add(field, SeverityInfo, msg, hint)
}

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

// hasError reports whether field carries an error-level finding.
func (r Result) hasError(field string) bool {
	for _, f := range r.Findings {
		if f.Field == field && f.Severity == SeverityError {
			return true
		}
	}
	return false
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

	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity.rank() < b.Severity.rank()
		}
		return a.Field < b.Field
	})
}

// Validate checks a policy for internal consistency and deployability.
//
// The checks fall into three groups:
//
//	Structural   the policy is well-formed: actions, hooks, protocols and
//	             ports are values the renderer understands.
//	Safety       the policy does something actively dangerous, such as
//	             permitting ICMP nowhere or forwarding nothing.
//	Reachability the operator can still reach the device afterwards.
//
// Reachability is checked separately because it is the failure that matters
// most: a structurally perfect policy that drops SSH still locks an
// unattended operator out, and the ruleset gives no hint that it did.
func Validate(p Policy) Result {
	var r Result

	validateStructural(&r, p)
	validateSafety(&r, p)
	r.Reachable, r.Trace = checkReachability(p)
	validateReachabilityFindings(&r, p)

	r.finalise()
	return r
}

// validateStructural checks the policy is well-formed.
func validateStructural(r *Result, p Policy) {
	switch p.Version {
	case PolicyVersion:
	case "":
		r.errorf("version", "policy version must be set",
			"set it to "+PolicyVersion)
	default:
		r.errorf("version",
			fmt.Sprintf("unknown policy version %q", p.Version),
			"this build produces version "+PolicyVersion)
	}

	switch p.Family {
	case "inet", "ip", "ip6":
	case "":
		r.errorf("family", "address family must be set",
			"use \"inet\" to cover both IPv4 and IPv6 in one table")
	default:
		r.errorf("family",
			fmt.Sprintf("unsupported address family %q", p.Family),
			"supported families are inet, ip and ip6")
	}

	if p.Table == "" {
		r.errorf("table", "table name must be set", "use \"thn\"")
	}
	if strings.ContainsAny(p.Table, " \t\n") {
		r.errorf("table",
			fmt.Sprintf("table name %q contains whitespace", p.Table),
			"nftables table names cannot contain spaces")
	}

	validateService(r, "admin.service", p.Admin.Enabled, p.Admin.Service)
	for i, s := range p.Services {
		validateService(r, fmt.Sprintf("services[%d]", i), true, s)
	}

	// Duplicate service names would make the rendered ruleset ambiguous.
	seen := map[string]int{}
	if p.Admin.Enabled && p.Admin.Service.Name != "" {
		seen[p.Admin.Service.Name] = -1
	}
	for i, s := range p.Services {
		if prev, ok := seen[s.Name]; ok {
			other := "admin.service"
			if prev >= 0 {
				other = fmt.Sprintf("services[%d]", prev)
			}
			r.errorf(fmt.Sprintf("services[%d]", i),
				fmt.Sprintf("service name %q is already defined at %s", s.Name, other),
				"give each service a distinct name")
			continue
		}
		seen[s.Name] = i
	}

	// Overlapping admin and added service ports are a real hazard: the
	// narrower rule wins, and the operator may not notice which.
	for i, s := range p.Services {
		if !p.Admin.Enabled || s.Name == p.Admin.Service.Name {
			continue
		}
		if overlap, ok := portOverlap(s.Ports, p.Admin.Service.Ports); ok {
			r.warnf(fmt.Sprintf("services[%d]", i),
				fmt.Sprintf("service %q uses port %s, which the admin service also uses",
					s.Name, overlap),
				"remove the duplicate port so the admin rule cannot be shadowed")
		}
	}

	for _, src := range append(append([]string(nil), p.Admin.Source...), sourcesOf(p.Services)...) {
		if _, err := netip.ParsePrefix(src); err != nil {
			r.errorf("source",
				fmt.Sprintf("%q is not a valid CIDR prefix", src),
				"write sources as networks, for example 203.0.113.0/24")
		}
	}
}

// validateService checks one service definition.
func validateService(r *Result, field string, active bool, s Service) {
	if s.Name == "" {
		if active {
			r.errorf(field, "service name must be set", "")
		}
		return
	}
	if strings.ContainsAny(s.Name, " \t\n\"") {
		r.errorf(field,
			fmt.Sprintf("service name %q contains characters nftables cannot represent", s.Name),
			"use letters, digits and dashes")
	}

	switch s.Protocol {
	case ProtoAll, ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6, ProtoESP, ProtoAH:
	case "":
		if active {
			r.errorf(field,
				fmt.Sprintf("service %q has no protocol", s.Name),
				"specify tcp or udp")
		}
	default:
		r.errorf(field,
			fmt.Sprintf("service %q has unsupported protocol %q", s.Name, s.Protocol),
			"supported protocols are tcp, udp, icmp, icmpv6, esp and ah")
	}

	// ICMP has no ports, so declaring them is a mistake worth reporting.
	if s.Protocol == ProtoICMP || s.Protocol == ProtoICMPv6 {
		if len(s.Ports) > 0 {
			r.warnf(field,
				fmt.Sprintf("service %q is ICMP but declares ports %s; ICMP has no ports",
					s.Name, joinPorts(s.Ports)),
				"remove the ports")
		}
		return
	}

	if len(s.Ports) == 0 {
		if active {
			r.errorf(field,
				fmt.Sprintf("service %q has no ports", s.Name),
				"declare at least one port or range")
		}
		return
	}

	for _, pr := range s.Ports {
		if pr.Low < 1 || pr.High > 65535 {
			r.errorf(field,
				fmt.Sprintf("service %q has port range %s outside 1-65535", s.Name, pr),
				"use valid transport ports")
			continue
		}
		if pr.Low > pr.High {
			r.errorf(field,
				fmt.Sprintf("service %q has inverted port range %s", s.Name, pr),
				"the low port must not exceed the high port")
		}
	}
}

// validateSafety checks for policies that are renderable but wrong.
func validateSafety(r *Result, p Policy) {
	// Blocking ICMP entirely causes path MTU black holes. This is the single
	// most common way a hand-written gateway ruleset breaks a network while
	// appearing correct.
	if !p.ICMP.AllowWAN && !p.ICMP.AllowLAN {
		r.errorf("icmp",
			"ICMP is blocked on every interface",
			"ICMP carries path MTU discovery; blocking it causes traffic to black hole silently")
	} else if !p.ICMP.AllowForward {
		r.warnf("icmp.allow_forward",
			"ICMP is not permitted across the gateway",
			"blocked PMTU discovery can stall traffic between the LAN and the internet")
	}

	if p.ICMP.RateLimitEcho < 0 {
		r.errorf("icmp.rate_limit_echo",
			"the echo rate limit must not be negative", "use 0 to disable the limit")
	}

	// A gateway that forwards nothing is a router, not a gateway.
	if !p.Forward.LANToWAN {
		r.errorf("forward.lan_to_wan",
			"the policy does not permit LAN-to-WAN traffic",
			"a gateway exists to forward this traffic; without it the LAN has no internet access")
	}

	if p.Forward.WANToLAN {
		r.warnf("forward.wan_to_lan",
			"the policy permits unsolicited inbound traffic from the internet to the LAN",
			"this exposes every device on the LAN; add explicit services instead")
	}

	// Masquerading without a LAN is unverifiable, and without an outbound
	// interface it would masquerade onto the wrong link.
	if p.Masquerade.Enabled && p.Masquerade.OutInterface == "" {
		r.warnf("masquerade.out_interface",
			"masquerading is enabled without an outbound interface, so it would apply to any interface",
			"set out_interface to the WAN")
	}

	if p.AntiSpoofing.Enabled && p.AntiSpoofing.LANPrefix == "" {
		r.warnf("anti_spoofing.lan_prefix",
			"anti-spoofing is enabled but no LAN prefix is configured, so nothing can be checked",
			"set lan_prefix, or disable anti-spoofing")
	}

	if p.Logging.Enabled {
		switch {
		case p.Logging.RateLimit < 0:
			r.errorf("logging.rate_limit",
				"the log rate limit must not be negative", "use 0 for unlimited")
		case p.Logging.RateLimit == 0:
			r.warnf("logging.rate_limit",
				"logging is enabled with no rate limit, which will fill a disk on a busy link",
				"set a rate limit, or disable logging")
		}
		if p.Logging.LogLimit < 0 {
			r.errorf("logging.log_limit",
				"the log limit must not be negative", "")
		}
	}

	if p.Interfaces.WAN != "" && p.Interfaces.LAN != "" &&
		p.Interfaces.WAN == p.Interfaces.LAN {
		r.errorf("interfaces.lan",
			fmt.Sprintf("the WAN and LAN are both %q", p.Interfaces.WAN),
			"they must be different interfaces")
	}

	if p.Interfaces.WAN == "" {
		r.infof("interfaces.wan",
			"no WAN interface is configured, so the rendered ruleset will not filter WAN traffic",
			"set interfaces.wan once the uplink is identified")
	}
	if p.Interfaces.LAN == "" {
		r.infof("interfaces.lan",
			"no LAN interface is configured, so the rendered ruleset will not filter LAN traffic",
			"set interfaces.lan once the downstream interface is identified")
	}
}

// checkReachability determines whether the admin path survives the policy.
//
// The evaluation mirrors the emitted rules rather than reimplementing them, so
// that the conclusion cannot drift from the ruleset. It walks the input hook
// as the renderer will: established traffic, loopback, ICMP, then services,
// then the default policy.
func checkReachability(p Policy) (bool, []string) {
	var trace []string

	// No WAN interface means nothing can reach the device from the WAN at all.
	if !p.Admin.Enabled {
		trace = append(trace, "admin access is disabled: the policy permits no WAN administration")
		return false, trace
	}
	if p.Interfaces.WAN == "" {
		trace = append(trace,
			"no WAN interface is configured: a packet arriving on the WAN cannot match any interface rule, "+
				"but it also cannot reach the input hook, so this is not a lockout")
		return true, trace
	}

	// Established traffic is accepted before any service rules, so return
	// traffic always works regardless of which service matched.
	trace = append(trace,
		"ct state established,related is accepted first: an admin session already open would survive")

	reachable := p.Admin.Service.Protocol != "" && len(p.Admin.Service.Ports) > 0
	if reachable {
		trace = append(trace, fmt.Sprintf(
			"service %q accepts %s/%s on the WAN",
			p.Admin.Service.Name, p.Admin.Service.Protocol, joinPorts(p.Admin.Service.Ports)))
	} else {
		trace = append(trace,
			"the admin service has no protocol or no ports, so no accept rule can be emitted for it")
	}

	// A service whose ports fail structural validation cannot be rendered, so
	// it cannot rescue reachability.
	if reachable {
		for _, pr := range p.Admin.Service.Ports {
			if pr.Low < 1 || pr.High > 65535 || pr.Low > pr.High {
				reachable = false
				trace = append(trace,
					fmt.Sprintf("admin port range %s is not renderable, so the rule will not be emitted", pr))
				break
			}
		}
	}

	if reachable {
		trace = append(trace, "the input hook default policy does not drop reachable admin traffic")
	}

	return reachable, trace
}

// validateReachabilityFindings reports the reachability outcome.
func validateReachabilityFindings(r *Result, p Policy) {
	reachable, trace := checkReachability(p)

	if !reachable {
		r.errorf("admin",
			"the rendered ruleset would leave the device unreachable from the WAN",
			"enable admin access with a usable service, or accept that the device is only reachable from the LAN")
		for _, line := range trace {
			r.infof("admin.trace", line, "")
		}
		return
	}

	// An admin path open to the whole internet is a real risk even though it
	// works, so it is reported without being refused.
	if len(p.Admin.Source) == 0 {
		r.warnf("admin.source",
			"administration is permitted from any source address",
			"restrict it to a known network, or use a key-only login with a rate limit")
	}
	for _, s := range p.Admin.Source {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		if prefix.Bits() < 16 {
			r.warnf("admin.source",
				fmt.Sprintf("administration is permitted from %s, which is a very large network", s),
				"narrow it to the network you actually administer from")
		}
	}
}

// sourcesOf collects every source restriction across services.
func sourcesOf(services []Service) []string {
	var out []string
	for _, s := range services {
		out = append(out, s.Source...)
	}
	return out
}

// portOverlap returns the first overlapping port between two lists.
func portOverlap(a, b []PortRange) (string, bool) {
	for _, x := range a {
		for _, y := range b {
			if x.Low <= y.High && y.Low <= x.High {
				return x.String(), true
			}
		}
	}
	return "", false
}
