// Package validation checks a THN configuration for coherence and, when a
// host observation is supplied, for compatibility with the machine it is
// intended to run on.
//
// # Two layers, one ruleset
//
//	Static  checks the document against itself: schema version, field types,
//	        ranges, address and prefix validity, internal consistency between
//	        fields. Needs no host, so it runs in CI and on a laptop.
//	Live    additionally checks the document against an observed host: does
//	        the configured WAN exist, is the LAN attached, are the required
//	        kernel capabilities present.
//
// The split is what allows `thn validate` to be a CI gate: a configuration
// that fails static validation will fail on any host, so catching it before
// the change is merged is strictly better than catching it on the gateway.
//
// # Shared by construction
//
// This package is the only place validation rules live. The CLI, thnd and any
// future dashboard all call it, so "CI passed" means something specific and
// checkable rather than "the laptop agreed".
package validation

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/schema"
)

// Severity classifies a finding.
type Severity string

const (
	// SeverityError means the configuration must not be used.
	SeverityError Severity = "error"
	// SeverityWarning means it is usable but likely wrong.
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

// Layer names the validation pass that produced a finding.
type Layer string

const (
	// LayerStatic is document-only validation.
	LayerStatic Layer = "static"
	// LayerLive is validation against an observed host.
	LayerLive Layer = "live"
)

// Finding is a single validation result.
type Finding struct {
	// Layer names the pass that produced this finding.
	Layer Layer `json:"layer"`
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
	s := fmt.Sprintf("[%s] %s %s: %s", f.Severity, f.Layer, f.Field, f.Message)
	if f.Hint != "" {
		s += " (" + f.Hint + ")"
	}
	return s
}

// Result aggregates the findings of a validation run.
type Result struct {
	// Findings are all results, sorted by severity.
	Findings []Finding `json:"findings"`
	// Layers records which passes ran.
	Layers []Layer `json:"layers"`
	// Valid reports that no error-level finding was raised.
	Valid bool `json:"valid"`
	// ErrorCount, WarningCount and InfoCount summarise the findings.
	ErrorCount   int `json:"error_count"`
	WarningCount int `json:"warning_count"`
	InfoCount    int `json:"info_count"`
}

// add appends a finding.
func (r *Result) add(layer Layer, field string, sev Severity, msg, hint string) {
	r.Findings = append(r.Findings, Finding{
		Layer: layer, Field: field, Severity: sev, Message: msg, Hint: hint,
	})
}

// errorf appends an error finding.
func (r *Result) errorf(layer Layer, field, msg, hint string) {
	r.add(layer, field, SeverityError, msg, hint)
}

// warnf appends a warning finding.
func (r *Result) warnf(layer Layer, field, msg, hint string) {
	r.add(layer, field, SeverityWarning, msg, hint)
}

// infof appends an informational finding.
func (r *Result) infof(layer Layer, field, msg, hint string) {
	r.add(layer, field, SeverityInfo, msg, hint)
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

// firstError returns the first error finding, or nil.
func (r Result) firstError() *Finding {
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			f := f
			return &f
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

	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity.rank() < b.Severity.rank()
		}
		if a.Layer != b.Layer {
			return a.Layer < b.Layer
		}
		return a.Field < b.Field
	})
}

// Static validates a configuration document without touching a host.
//
// This is the CI gate. It must be deterministic and side-effect free: the same
// document always produces the same findings, on any machine, with no network.
func Static(cfg config.Config) Result {
	var r Result
	r.Layers = []Layer{LayerStatic}

	// Schema version. The config package already rejects unknown versions at
	// load; this repeats the check so that a programmatically-constructed
	// Config is validated on the same terms.
	if err := schema.CheckVersion(cfg.SchemaVersion); err != nil {
		r.errorf(LayerStatic, "schema_version", err.Error(),
			"upgrade thn rather than editing the document")
	}

	// Delegate to the configuration package's own field-level checks so that
	// the two never disagree about what is valid.
	for _, f := range cfg.Validate().Findings {
		sev := SeverityInfo
		switch f.Severity {
		case config.SeverityError:
			sev = SeverityError
		case config.SeverityWarning:
			sev = SeverityWarning
		}
		r.add(LayerStatic, f.Field, sev, f.Message, "")
	}

	validateAddressing(&r, cfg)
	validateServices(&r, cfg)
	validateCoherence(&r, cfg)

	r.finalise()
	return r
}

// validateAddressing checks addresses, prefixes and MTU.
func validateAddressing(r *Result, cfg config.Config) {
	// WAN interface name.
	if cfg.Network.WAN != "" {
		if msg := checkInterfaceName(cfg.Network.WAN); msg != "" {
			r.errorf(LayerStatic, "network.wan", msg,
				"interface names cannot contain spaces and are limited to 15 characters")
		}
	}

	// LAN interface name.
	if cfg.Network.LAN != "" {
		if msg := checkInterfaceName(cfg.Network.LAN); msg != "" {
			r.errorf(LayerStatic, "network.lan", msg,
				"interface names cannot contain spaces and are limited to 15 characters")
		}
	}

	// LAN prefix.
	if cfg.Network.LANPrefix != "" {
		prefix, err := netip.ParsePrefix(cfg.Network.LANPrefix)

		switch {
		case err != nil:
			r.errorf(LayerStatic, "network.lan_prefix",
				fmt.Sprintf("%q is not a valid CIDR prefix", cfg.Network.LANPrefix),
				"write it as an address and prefix length, for example 10.77.0.1/24")

		case prefix.Addr().IsLoopback():
			r.errorf(LayerStatic, "network.lan_prefix",
				"the LAN prefix must not be a loopback address",
				"use a private range such as 10.77.0.1/24")

		case prefix.Addr().IsUnspecified():
			r.errorf(LayerStatic, "network.lan_prefix",
				"the LAN prefix must not be the unspecified address",
				"use a private range such as 10.77.0.1/24")

		case prefix.Addr().IsMulticast():
			r.errorf(LayerStatic, "network.lan_prefix",
				"the LAN prefix must not be a multicast address", "")

		case !isPrivateOrUla(prefix.Addr()):
			r.warnf(LayerStatic, "network.lan_prefix",
				fmt.Sprintf("%s is a public address; a LAN is normally a private range", prefix),
				"use 10.x, 172.16-31.x or 192.168.x")

		// A narrow prefix is an IPv4 concept. /64 is the ordinary IPv6 LAN size, and
		// "how many host addresses does this prefix have" is not a question that
		// has a useful answer at v6 scale.
		case prefix.Addr().Is4() && prefix.Bits() > 29:
			r.warnf(LayerStatic, "network.lan_prefix",
				fmt.Sprintf("%s leaves only %d usable host addresses", prefix, usableHosts(prefix.Bits())),
				"a /29 or smaller is rarely enough for a household LAN")
		}
	}

	// MTU.
	switch {
	case cfg.Network.MTU != 0 && cfg.Network.MTU < 576:
		r.errorf(LayerStatic, "network.mtu",
			fmt.Sprintf("MTU %d is below the IPv4 minimum", cfg.Network.MTU),
			"576 is the smallest value the IPv4 specification permits")
	case cfg.Network.MTU != 0 && cfg.Network.MTU > 9000:
		r.errorf(LayerStatic, "network.mtu",
			fmt.Sprintf("MTU %d exceeds the common maximum", cfg.Network.MTU),
			"9000 is the largest value typically supported by Ethernet")
	}

	// Upstream gateway must not lie inside the LAN prefix, which would make
	// the default route point at the downstream segment.
	if cfg.Network.UpstreamGateway != "" && cfg.Network.LANPrefix != "" {
		gw, gwErr := netip.ParseAddr(cfg.Network.UpstreamGateway)
		prefix, pErr := netip.ParsePrefix(cfg.Network.LANPrefix)

		if gwErr == nil && pErr == nil && prefix.Contains(gw) {
			r.errorf(LayerStatic, "network.upstream_gateway",
				fmt.Sprintf("the upstream gateway %s is inside the LAN prefix %s", gw, prefix),
				"the default route must leave through the WAN, not back into the LAN")
		}
	}
}

// validateServices checks resolver, firewall and QoS settings.
func validateServices(r *Result, cfg config.Config) {
	// Resolvers.
	for i, s := range cfg.Network.DNS {
		field := fmt.Sprintf("network.dns[%d]", i)

		addr, err := netip.ParseAddr(s)
		if err != nil {
			r.errorf(LayerStatic, field,
				fmt.Sprintf("%q is not a valid IP address", s), "")
			continue
		}
		if addr.IsUnspecified() {
			r.errorf(LayerStatic, field,
				"a resolver must not be the unspecified address", "")
		}
		if addr.IsMulticast() {
			r.errorf(LayerStatic, field,
				"a resolver must not be a multicast address", "")
		}
	}

	// A missing LAN prefix used to be reported here, but only when resolvers
	// happened to be configured. It is now an unconditional
	// network.lan_prefix warning from config.Validate, so an operator who had
	// cleared both fields is told something rather than nothing.

	// Firewall.
	switch cfg.Firewall.Backend {
	case "nftables":
	case "":
		if cfg.Firewall.Enabled {
			r.errorf(LayerStatic, "firewall.backend",
				"firewall.backend must be set when the firewall is enabled",
				"set it to nftables")
		}
	default:
		r.errorf(LayerStatic, "firewall.backend",
			fmt.Sprintf("%q is not a supported firewall backend", cfg.Firewall.Backend),
			"the only supported backend is nftables")
	}

	// QoS.
	if cfg.QoS.Enabled {
		switch cfg.QoS.Algorithm {
		case "cake":
		case "":
			r.errorf(LayerStatic, "qos.algorithm",
				"qos.algorithm must be set when QoS is enabled", "set it to cake")
		default:
			r.errorf(LayerStatic, "qos.algorithm",
				fmt.Sprintf("%q is not a supported shaping algorithm", cfg.QoS.Algorithm),
				"the only supported algorithm is cake")
		}

		if cfg.QoS.DownloadKbps <= 0 {
			r.errorf(LayerStatic, "qos.download_kbps",
				"the download rate must be positive when QoS is enabled",
				"set it to the rate your uplink actually provides")
		}
		if cfg.QoS.UploadKbps <= 0 {
			r.errorf(LayerStatic, "qos.upload_kbps",
				"the upload rate must be positive when QoS is enabled",
				"set it to the rate your uplink actually provides")
		}
		if cfg.QoS.DownloadKbps > 0 && cfg.QoS.UploadKbps > cfg.QoS.DownloadKbps {
			r.warnf(LayerStatic, "qos.upload_kbps",
				fmt.Sprintf("the upload rate (%d kbps) exceeds the download rate (%d kbps), which is unusual for a WAN uplink",
					cfg.QoS.UploadKbps, cfg.QoS.DownloadKbps), "")
		}
	}
}

// validateCoherence checks rules that span more than one subsystem.
//
// These are the checks that catch a configuration which is individually valid
// but collectively nonsensical — the ones that would otherwise only be
// discovered on the gateway.
func validateCoherence(r *Result, cfg config.Config) {
	// The physical-presence gate is the single most important safety
	// property in the system, so disabling it is an error rather than a
	// warning even though the configuration schema permits the key.
	if !cfg.Activation.RequirePhysicalPresence {
		r.errorf(LayerStatic, "activation.require_physical_presence",
			"the physical-presence gate must not be disabled",
			"THN is developed remotely against an unattended device, so remote root access must not by itself permit activation")
	}

	// A drop-by-default firewall with NAT disabled leaves the LAN unable to
	// reach the internet: outbound traffic is allowed but return traffic is
	// not, so the LAN appears to have a network but cannot use it.
	if cfg.Firewall.Enabled && cfg.Firewall.DefaultInboundPolicy == "drop" && !cfg.NAT.Enabled {
		r.warnf(LayerStatic, "firewall.default_inbound_policy",
			"a drop-by-default firewall with NAT disabled will leave the LAN unable to reach the internet",
			"enable NAT, or set the inbound policy to accept")
	}

	// QoS shaping the LAN interface is pointless: shaping is applied to the
	// egress device, and LAN egress is not the constrained link.
	if cfg.QoS.Enabled && cfg.QoS.Interface != "" && cfg.QoS.Interface == cfg.Network.LAN {
		r.warnf(LayerStatic, "qos.interface",
			fmt.Sprintf("qos.interface is the LAN interface (%s); shaping is meaningful on the uplink only",
				cfg.Network.LAN),
			"set qos.interface to the WAN interface")
	}

	// Masquerading from the WAN is a routing loop.
	for i, iface := range cfg.NAT.Interfaces {
		if iface != "" && iface == cfg.Network.WAN {
			r.errorf(LayerStatic, fmt.Sprintf("nat.interfaces[%d]", i),
				fmt.Sprintf("cannot masquerade traffic from the WAN interface (%s)", iface),
				"list the LAN interface instead")
		}
	}

	// Everything requested, nothing identifiable to request it on.
	if cfg.NAT.Enabled && cfg.Network.LAN == "" && len(cfg.NAT.Interfaces) == 0 {
		r.infof(LayerStatic, "nat.interfaces",
			"NAT is enabled but no LAN interface has been identified; this is expected during remote development",
			"set network.lan once the downstream interface is known")
	}

	if cfg.QoS.Enabled && cfg.QoS.Interface == "" {
		r.infof(LayerStatic, "qos.interface",
			"QoS is enabled but no shaping interface has been identified",
			"set qos.interface once the uplink is known")
	}
}

// Live validates a configuration against an observed host.
//
// This is the pass that answers "will this actually work on this machine?".
// It requires an observation, which is why it is separate: the static pass
// must run in CI where no host exists.
func Live(cfg config.Config, obs diff.Observed, d diff.Result) Result {
	var r Result
	r.Layers = []Layer{LayerLive}

	if !obs.Supported {
		r.warnf(LayerLive, "",
			fmt.Sprintf("host inspection is not available on %s, so only the static checks could run", hostLabel(obs)),
			"run thn validate --live on the gateway itself for the full check")
		r.finalise()
		return r
	}

	// The configured WAN must actually exist on this host.
	if cfg.Network.WAN == "" {
		r.errorf(LayerLive, "network.wan", "no WAN interface is configured", "")
	} else {
		if obs.WANName != cfg.Network.WAN && !hasInterface(obs, cfg.Network.WAN) {
			r.errorf(LayerLive, "network.wan",
				fmt.Sprintf("the configured WAN interface %s does not exist on this host", cfg.Network.WAN),
				"check the name, or run thn status to list the interfaces present")
		} else if !obs.WANUp {
			r.warnf(LayerLive, "network.wan",
				fmt.Sprintf("the WAN interface %s is administratively down", cfg.Network.WAN), "")
		}
	}

	// The configured LAN must be attached. This is informational rather than
	// an error: not being attached is the expected development state.
	if cfg.Network.LAN == "" {
		r.infof(LayerLive, "network.lan",
			"no LAN interface has been identified in the configuration",
			"set network.lan once the downstream interface is attached")
	} else if !obs.LANPresent || obs.LANName != cfg.Network.LAN {
		r.infof(LayerLive, "network.lan",
			fmt.Sprintf("the configured LAN interface %s is not attached to this host", cfg.Network.LAN),
			"attach the interface, or correct the name")
	} else if !obs.LANUp {
		r.warnf(LayerLive, "network.lan",
			fmt.Sprintf("the LAN interface %s has no carrier", cfg.Network.LAN), "")
	}

	// A blocked diff means the configuration cannot be reconciled here at
	// all, which is worth surfacing at the validation layer too.
	for _, c := range d.ByKind(diff.KindBlocked) {
		r.errorf(LayerLive, c.Field, c.Reason, "")
	}

	// Forwarding must be readable before it can be checked.
	if !obs.IPv4ForwardingKnown {
		r.warnf(LayerLive, "addressing.ipv4_forwarding",
			"IPv4 forwarding could not be read on this host",
			"THN needs permission to read net.ipv4.ip_forward")
	}

	// Firewall capability: if a firewall is wanted, the tooling must exist.
	if cfg.Firewall.Enabled && !obs.FirewallActive {
		r.warnf(LayerLive, "firewall.enabled",
			"the configuration requires a firewall but no ruleset is present on this host",
			"install nftables before activation")
	}

	r.finalise()
	return r
}

// Combined runs both layers and merges the results.
//
// The static layer always runs. The live layer runs only when an observation
// was supplied, because fabricating one would defeat the purpose.
func Combined(cfg config.Config, obs *diff.Observed, d diff.Result) Result {
	static := Static(cfg)
	if obs == nil {
		return static
	}

	live := Live(cfg, *obs, d)
	merged := Result{
		Findings: append(static.Findings, live.Findings...),
		Layers:   []Layer{LayerStatic, LayerLive},
	}
	merged.finalise()
	return merged
}

// checkInterfaceName returns a message when an interface name is implausible.
func checkInterfaceName(name string) string {
	if len(name) > 15 {
		return fmt.Sprintf("interface name %q is longer than the 15 characters Linux permits", name)
	}
	if strings.ContainsAny(name, " \t\n") {
		return fmt.Sprintf("interface name %q contains whitespace", name)
	}
	if strings.Contains(name, "/") {
		return fmt.Sprintf("interface name %q contains a path separator", name)
	}
	return ""
}

// isPrivateOrUla reports whether an address is in a private or unique-local
// range.
func isPrivateOrUla(addr netip.Addr) bool {
	if addr.IsPrivate() {
		return true
	}
	if addr.Is6() {
		// fc00::/7 is unique-local.
		b := addr.As16()
		return b[0]&0xfe == 0xfc
	}
	return false
}

// usableHosts returns the number of usable host addresses in a prefix.
//
// IPv4 only, and defensively so: it was written before IPv6 LAN prefixes were
// exercised, and 1 << (32-bits) with bits above 32 is a negative shift, which
// takes the process down rather than returning a wrong number.
func usableHosts(bits int) int {
	if bits > 30 || bits < 0 {
		return 0
	}
	total := uint64(1) << (32 - bits)
	if total <= 2 {
		return 0
	}
	return int(total - 2)
}

// hasInterface reports whether the observation saw the named interface.
func hasInterface(obs diff.Observed, name string) bool {
	return (obs.WANPresent && obs.WANName == name) ||
		(obs.LANPresent && obs.LANName == name)
}

// hostLabel renders a host for a finding message.
func hostLabel(obs diff.Observed) string {
	if obs.HostName != "" {
		return obs.HostName
	}
	return "this host"
}
