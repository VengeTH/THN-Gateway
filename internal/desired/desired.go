package desired

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/host"
)

// Role classifies an interface's purpose.
type Role string

const (
	// RoleWAN is the uplink toward the internet.
	RoleWAN Role = "wan"
	// RoleLAN is the downstream segment THN serves.
	RoleLAN Role = "lan"
	// RoleMGMT is an administrative path.
	RoleMGMT Role = "mgmt"
	// RoleGuest is an untrusted downstream network.
	RoleGuest Role = "guest"
	// RoleDMZ is a semi-exposed downstream network.
	RoleDMZ Role = "dmz"
	// RoleUnassigned means no role has been chosen.
	RoleUnassigned Role = "unassigned"
)

// String renders the role.
func (r Role) String() string { return string(r) }

// Interface is the desired state of one interface.
type Interface struct {
	// Name is the kernel interface name. Empty when not yet identified.
	Name string `json:"name,omitempty"`
	// Role is what the interface is for.
	Role Role `json:"role"`
	// Addresses are the addresses that should be present, in CIDR form.
	Addresses []string `json:"addresses"`
	// MTU is the desired MTU. Zero means "leave alone".
	MTU int `json:"mtu,omitempty"`
	// Up requests the link to be administratively up.
	Up bool `json:"up"`
	// Present reports whether the interface has been identified at all.
	//
	// This is the field that distinguishes "not attached" from "not
	// configured", and it is what lets the diff report Pending rather than
	// proposing a change to an interface that does not exist.
	Present bool `json:"present"`
	// Reason explains why the interface is absent, for operator display.
	Reason string `json:"reason,omitempty"`
}

// Addressing is the desired routing and forwarding state.
type Addressing struct {
	// DefaultGateway is the next hop for the default route.
	DefaultGateway string `json:"default_gateway,omitempty"`
	// UpstreamPresent reports whether a default gateway was configured.
	UpstreamPresent bool `json:"upstream_present"`
	// IPv4Forwarding requests IPv4 forwarding.
	IPv4Forwarding bool `json:"ipv4_forwarding"`
	// IPv6Forwarding requests IPv6 forwarding.
	IPv6Forwarding bool `json:"ipv6_forwarding"`
}

// NAT is the desired masquerading state.
type NAT struct {
	// Enabled reports whether masquerading is wanted.
	Enabled bool `json:"enabled"`
	// Interfaces are the interfaces to masquerade traffic from.
	Interfaces []string `json:"interfaces,omitempty"`
	// Resolved reports whether at least one masquerade interface was
	// determined. When false the NAT block is pending, not empty.
	Resolved bool `json:"resolved"`
}

// Firewall is the desired filtering state.
type Firewall struct {
	// Enabled reports whether filtering is wanted.
	Enabled bool `json:"enabled"`
	// Backend is the filtering implementation.
	Backend string `json:"backend,omitempty"`
	// DefaultInboundPolicy is the base policy for unmatched traffic.
	DefaultInboundPolicy string `json:"default_inbound_policy,omitempty"`
	// AllowEstablished permits return traffic.
	AllowEstablished bool `json:"allow_established"`
	// AllowLoopback permits loopback traffic.
	AllowLoopback bool `json:"allow_loopback"`
}

// QoS is the desired shaping state.
type QoS struct {
	// Enabled reports whether shaping is wanted.
	Enabled bool `json:"enabled"`
	// Resolved reports whether the shaping target was determined.
	Resolved bool `json:"resolved"`
	// Algorithm is the shaping algorithm.
	Algorithm string `json:"algorithm,omitempty"`
	// Interface is the device to shape.
	Interface string `json:"interface,omitempty"`
	// DownloadKbps is the shaped download rate.
	DownloadKbps int `json:"download_kbps,omitempty"`
	// UploadKbps is the shaped upload rate.
	UploadKbps int `json:"upload_kbps,omitempty"`
}

// DNS is the desired resolver state.
type DNS struct {
	// Servers is the resolver set.
	Servers []string `json:"servers,omitempty"`
	// Present reports whether a resolver set was configured.
	Present bool `json:"present"`
}

// State is the complete desired state of the gateway.
type State struct {
	// Name is the logical gateway name.
	Name string `json:"name"`
	// Generation is the configuration generation this state derives from.
	Generation uint64 `json:"generation"`
	// SchemaVersion is the configuration schema version.
	SchemaVersion int `json:"schema_version"`

	// WAN is the desired uplink interface.
	WAN Interface `json:"wan"`
	// LAN is the desired downstream interface.
	LAN Interface `json:"lan"`
	// Addressing is the desired routing and forwarding state.
	Addressing Addressing `json:"addressing"`
	// NAT is the desired masquerading state.
	NAT NAT `json:"nat"`
	// Firewall is the desired filtering state.
	Firewall Firewall `json:"firewall"`
	// QoS is the desired shaping state.
	QoS QoS `json:"qos"`
	// DNS is the desired resolver state.
	DNS DNS `json:"dns"`
}

// FromConfig resolves configuration intent into desired state.
//
// This is the only place that turns operator intent into a target. Everything
// downstream — validation, diff, planning — consumes State and never Config,
// so the resolution rules live in exactly one function.
func FromConfig(cfg config.Config) State {
	return FromConfigWithResolution(cfg, host.Resolution{})
}

// FromConfigWithResolution resolves configuration intent into desired state
// using resolved role assignments from the host discovery layer.
func FromConfigWithResolution(cfg config.Config, res host.Resolution) State {
	s := State{
		Name:          cfg.Gateway.Name,
		Generation:    cfg.Gateway.Generation,
		SchemaVersion: cfg.SchemaVersion,
	}

	// --- Interfaces ---

	if iface, ok := res.Assigned[host.RoleWAN]; ok {
		s.WAN = Interface{
			Name:      iface.SystemName,
			Role:      RoleWAN,
			MTU:       cfg.Network.MTU,
			Up:        true,
			Present:   true,
			Addresses: []string{},
		}
	} else if cfg.Network.WAN != "" && !strings.HasPrefix(cfg.Network.WAN, "hw:") && !strings.HasPrefix(cfg.Network.WAN, "ephemeral:") && cfg.Network.WAN != string(host.RoleWAN) {
		s.WAN = Interface{
			Name:      cfg.Network.WAN,
			Role:      RoleWAN,
			MTU:       cfg.Network.MTU,
			Up:        true,
			Present:   true,
			Addresses: []string{},
		}
	} else {
		s.WAN = Interface{
			Role:      RoleWAN,
			MTU:       cfg.Network.MTU,
			Up:        true,
			Present:   false,
			Addresses: []string{},
			Reason:    "no WAN interface is configured",
		}
		for _, p := range res.Problems {
			if p.Role == host.RoleWAN {
				s.WAN.Reason = p.Message
				break
			}
		}
	}

	if iface, ok := res.Assigned[host.RoleLAN]; ok {
		s.LAN = Interface{
			Name:      iface.SystemName,
			Role:      RoleLAN,
			MTU:       cfg.Network.MTU,
			Up:        true,
			Present:   true,
			Addresses: []string{},
		}
		if cfg.Network.LANPrefix != "" {
			s.LAN.Addresses = []string{cfg.Network.LANPrefix}
		} else {
			s.LAN.Reason = "the LAN interface is identified but has no address configured"
		}
	} else if cfg.Network.LAN != "" && !strings.HasPrefix(cfg.Network.LAN, "hw:") && !strings.HasPrefix(cfg.Network.LAN, "ephemeral:") && cfg.Network.LAN != string(host.RoleLAN) {
		s.LAN = Interface{
			Name:      cfg.Network.LAN,
			Role:      RoleLAN,
			MTU:       cfg.Network.MTU,
			Up:        true,
			Present:   true,
			Addresses: []string{},
		}
		switch {
		case cfg.Network.LANPrefix == "":
			s.LAN.Reason = "the LAN interface is identified but has no address configured"
		default:
			s.LAN.Addresses = []string{cfg.Network.LANPrefix}
		}
	} else {
		s.LAN = Interface{
			Role:      RoleLAN,
			MTU:       cfg.Network.MTU,
			Up:        true,
			Present:   false,
			Addresses: []string{},
			Reason:    "no LAN interface has been identified",
		}
		for _, p := range res.Problems {
			if p.Role == host.RoleLAN {
				s.LAN.Reason = p.Message
				break
			}
		}
	}

	// --- Addressing ---

	s.Addressing = Addressing{
		DefaultGateway:  cfg.Network.UpstreamGateway,
		UpstreamPresent: cfg.Network.UpstreamGateway != "",
		IPv4Forwarding:  true,
		IPv6Forwarding:  true,
	}

	// --- NAT ---

	s.NAT = NAT{
		Enabled:    cfg.NAT.Enabled,
		Interfaces: append([]string(nil), cfg.NAT.Interfaces...),
	}
	// NAT resolves only once a concrete masquerade interface is known. With
	// NAT on but no interface, the block is pending rather than empty: the
	// operator asked for NAT and has not yet said over which interface.
	if s.NAT.Enabled {
		switch {
		case len(s.NAT.Interfaces) > 0:
			s.NAT.Resolved = true
		case s.LAN.Present && s.LAN.Name != "":
			s.NAT.Interfaces = []string{s.LAN.Name}
			s.NAT.Resolved = true
		case cfg.Network.LAN != "" && !strings.HasPrefix(cfg.Network.LAN, "hw:") && !strings.HasPrefix(cfg.Network.LAN, "ephemeral:") && cfg.Network.LAN != string(host.RoleLAN):
			s.NAT.Interfaces = []string{cfg.Network.LAN}
			s.NAT.Resolved = true
		default:
			s.NAT.Resolved = false
		}
	}

	// --- Firewall ---

	s.Firewall = Firewall{
		Enabled:              cfg.Firewall.Enabled,
		Backend:              cfg.Firewall.Backend,
		DefaultInboundPolicy: cfg.Firewall.DefaultInboundPolicy,
		AllowEstablished:     true,
		AllowLoopback:        true,
	}
	if s.Firewall.DefaultInboundPolicy == "" {
		s.Firewall.DefaultInboundPolicy = "drop"
	}

	// --- QoS ---

	s.QoS = QoS{
		Enabled:      cfg.QoS.Enabled,
		Algorithm:    cfg.QoS.Algorithm,
		Interface:    cfg.QoS.Interface,
		DownloadKbps: cfg.QoS.DownloadKbps,
		UploadKbps:   cfg.QoS.UploadKbps,
	}
	if s.QoS.Interface == "" && s.WAN.Present && s.WAN.Name != "" {
		s.QoS.Interface = s.WAN.Name
	}
	if !s.QoS.Enabled {
		// QoS off is a resolved state, not a pending one.
		s.QoS.Resolved = true
	} else {
		s.QoS.Resolved = s.QoS.Interface != "" &&
			s.QoS.DownloadKbps > 0 &&
			s.QoS.UploadKbps > 0 &&
			s.QoS.Algorithm != ""
	}

	// --- DNS ---

	s.DNS = DNS{
		Servers: append([]string(nil), cfg.Network.DNS...),
		Present: len(cfg.Network.DNS) > 0,
	}

	return s
}

// Pending lists the subsystems whose desired state cannot yet be determined,
// with the reason. This is what `thn plan` shows as outstanding work, and what
// the diff reports as Pending rather than as a change.
func (s State) Pending() map[string]string {
	out := map[string]string{}

	if !s.WAN.Present {
		out["wan"] = s.WAN.Reason
	}
	if !s.LAN.Present || len(s.LAN.Addresses) == 0 {
		reason := s.LAN.Reason
		if reason == "" {
			reason = "the LAN interface has no desired address"
		}
		out["lan"] = reason
	}
	if s.NAT.Enabled && !s.NAT.Resolved {
		out["nat"] = "NAT is enabled but no masquerade interface has been determined"
	}
	if s.QoS.Enabled && !s.QoS.Resolved {
		out["qos"] = "QoS is enabled but the interface or rates are incomplete"
	}

	return out
}

// Ready reports whether every desired subsystem is fully determined.
//
// A false here does not make the configuration invalid — it is the normal
// state during remote development. It means the plan cannot be complete yet.
func (s State) Ready() bool { return len(s.Pending()) == 0 }

// Interface returns the desired state for a role.
func (s State) Interface(r Role) Interface {
	if r == RoleLAN {
		return s.LAN
	}
	return s.WAN
}

// Summary renders a compact human-readable description, used by `thn plan`
// and `thn status`.
func (s State) Summary() string {
	var b strings.Builder

	fmt.Fprintf(&b, "gateway:  %s (generation %d)\n", s.Name, s.Generation)
	fmt.Fprintf(&b, "WAN:      %s\n", describeInterface(s.WAN))
	fmt.Fprintf(&b, "LAN:      %s\n", describeInterface(s.LAN))
	fmt.Fprintf(&b, "forward:  ipv4=%t ipv6=%t\n", s.Addressing.IPv4Forwarding, s.Addressing.IPv6Forwarding)
	fmt.Fprintf(&b, "NAT:      %s\n", describeNAT(s.NAT))
	fmt.Fprintf(&b, "firewall: %s\n", describeFirewall(s.Firewall))
	fmt.Fprintf(&b, "QoS:      %s\n", describeQoS(s.QoS))
	fmt.Fprintf(&b, "DNS:      %s\n", describeDNS(s.DNS))

	return b.String()
}

// describeInterface renders an interface's desired state.
func describeInterface(i Interface) string {
	if !i.Present {
		return fmt.Sprintf("not configured (%s)", i.Reason)
	}
	addrs := "no address"
	if len(i.Addresses) > 0 {
		addrs = strings.Join(i.Addresses, ", ")
	}
	return fmt.Sprintf("%s [%s, %s]", i.Name, addrs, linkState(i.Up))
}

// linkState renders a link's desired state.
func linkState(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

// describeNAT renders NAT's desired state.
func describeNAT(n NAT) string {
	if !n.Enabled {
		return "disabled"
	}
	if !n.Resolved {
		return "enabled (pending: no masquerade interface)"
	}
	return fmt.Sprintf("masquerade from %s", strings.Join(n.Interfaces, ", "))
}

// describeFirewall renders the firewall's desired state.
func describeFirewall(f Firewall) string {
	if !f.Enabled {
		return "disabled"
	}
	return fmt.Sprintf("enabled (%s, default %s)", f.Backend, f.DefaultInboundPolicy)
}

// describeQoS renders QoS's desired state.
func describeQoS(q QoS) string {
	if !q.Enabled {
		return "disabled"
	}
	if !q.Resolved {
		return "enabled (pending: interface or rates incomplete)"
	}
	return fmt.Sprintf("enabled (%s on %s, %d/%d kbps)",
		q.Algorithm, q.Interface, q.DownloadKbps, q.UploadKbps)
}

// describeDNS renders the resolver's desired state.
func describeDNS(d DNS) string {
	if !d.Present {
		return "not configured"
	}
	return strings.Join(d.Servers, ", ")
}

// Prefixes returns the desired LAN prefixes parsed as network prefixes.
func (s State) Prefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, c := range s.LAN.Addresses {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("desired LAN address %q is not a valid prefix: %w", c, err)
		}
		out = append(out, p)
	}
	return out, nil
}
