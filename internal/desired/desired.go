package desired

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/dhcp"
	"github.com/venth/thn-gateway/internal/dns"
	"github.com/venth/thn-gateway/internal/gateway"
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

	// StableID is the rename-stable identity of this interface.
	//
	// It is carried alongside Name rather than instead of it because Name is
	// what every renderer and every downstream comparison already uses, and
	// StableID is what makes the desired state survive a NIC moving slots.
	// A document keyed on Name alone describes one machine; a document keyed
	// on StableID describes the same link on every machine it appears in.
	//
	// Empty when the interface could not be resolved, or when the host
	// reported no hardware address to derive one from.
	StableID string `json:"stable_id,omitempty"`

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

	// Role is the logical role shaping attaches to, normally "wan".
	//
	// Shaping belongs on the link facing the bottleneck, and for a gateway
	// that is the uplink. Carrying the role rather than only a kernel name is
	// what lets this stay device-independent.
	Role string `json:"role,omitempty"`

	// StableID is the rename-stable identity of that interface.
	//
	// Carried beside Interface rather than instead of it, for the reason
	// every other block in this model does the same: the kernel name is what
	// the host calls it today, and the stable ID is what survives a NIC
	// moving slots.
	StableID string `json:"stable_id,omitempty"`

	// DownloadKbps is the shaped download rate.
	DownloadKbps int `json:"download_kbps,omitempty"`
	// UploadKbps is the shaped upload rate.
	UploadKbps int `json:"upload_kbps,omitempty"`

	// OverheadPercent is the framing overhead compensation applied.
	OverheadPercent int `json:"overhead_percent,omitempty"`
}

// DNS is the desired resolver state.
type DNS struct {
	// Servers is the resolver set.
	Servers []string `json:"servers,omitempty"`
	// Present reports whether a resolver set was configured.
	Present bool `json:"present"`

	// Service is the desired DNS *service* state.
	//
	// It is kept separate from Servers above because they answer different
	// questions. Servers is what THIS HOST should query; Service is what
	// clients should query THIS HOST for. Collapsing them is how a gateway
	// ends up forwarding to itself, or how an operator edits dns.upstream
	// and watches nothing change.
	Service DNSService `json:"service"`
}

// DNSService is the desired state of the DNS service THN offers to the LAN.
//
// It is implementation-independent on purpose. Nothing here names dnsmasq,
// Unbound or systemd-resolved, because this layer describes the behaviour the
// operator asked for, and choosing the process that provides it is a separate
// decision that this milestone deliberately does not make.
type DNSService struct {
	// Enabled is the explicit request for a LAN DNS service.
	Enabled bool `json:"enabled"`

	// LANSelector is what the operator wrote for the LAN, verbatim.
	//
	// Carried beside the resolved name so a plan can say "the document asked
	// for hw:…, and this host calls that enx00e099001812".
	LANSelector string `json:"lan_selector,omitempty"`

	// Interface is the observed kernel name the LAN role resolved to.
	Interface string `json:"interface,omitempty"`

	// StableID is the rename-stable identity of that interface.
	StableID string `json:"stable_id,omitempty"`

	// ListenAddress is the address the service should answer on.
	ListenAddress string `json:"listen_address,omitempty"`

	// Upstream are the resolvers queries are forwarded to, sorted.
	//
	// Sorted because the digest is content-addressed: two documents listing
	// the same resolvers in a different order describe the same machine and
	// must produce the same digest and the same plan ID.
	Upstream []string `json:"upstream,omitempty"`

	// UpstreamSource names the field the resolvers came from:
	// "dns.upstream" or "network.dns".
	UpstreamSource string `json:"upstream_source,omitempty"`

	// LocalDomain is the domain served for local names.
	LocalDomain string `json:"local_domain,omitempty"`

	// Resolved reports whether the service can be placed.
	//
	// False means pending, not empty: the operator asked for DNS and has not
	// yet said on what link it should listen.
	Resolved bool `json:"resolved"`
}

// DHCP is the desired DHCP service state.
//
// Like DNSService, it names no implementation. Describing which addresses
// should be handed out is separable from which program hands them out, and
// only the first is modelled here.
type DHCP struct {
	// Enabled is the explicit request for a LAN DHCP service.
	Enabled bool `json:"enabled"`

	// LANSelector is what the operator wrote for the LAN, verbatim.
	LANSelector string `json:"lan_selector,omitempty"`

	// Interface is the observed kernel name the LAN role resolved to.
	Interface string `json:"interface,omitempty"`

	// StableID is the rename-stable identity of that interface.
	StableID string `json:"stable_id,omitempty"`

	// Subnet is the LAN network the pool belongs to, in CIDR form.
	Subnet string `json:"subnet,omitempty"`

	// Router is the address advertised to clients as their default route.
	//
	// Derived from the LAN address, so there is one source of truth for the
	// gateway's LAN address rather than two that can disagree.
	Router string `json:"router,omitempty"`

	// Ranges are the address pools, as "start-end" strings, in declaration
	// order.
	Ranges []string `json:"ranges,omitempty"`

	// LeaseTime is the default lease duration, rendered for display.
	LeaseTime string `json:"lease_time,omitempty"`

	// Domain is the local domain advertised to clients.
	Domain string `json:"domain,omitempty"`

	// Authoritative marks the server authoritative for the LAN.
	Authoritative bool `json:"authoritative"`

	// AdvertisedDNS are the resolvers handed to DHCP clients, sorted.
	AdvertisedDNS []string `json:"advertised_dns,omitempty"`

	// Resolved reports whether the service can be placed.
	Resolved bool `json:"resolved"`
}

// GatewayIntent is the statement of intent the desired state was built from.
//
// It is carried inside State rather than alongside it so that a desired state
// is self-describing: anything holding a State can say what was actually
// asked for, rather than having to be handed the configuration separately and
// risk answering about a different document than the one it was built from.
type GatewayIntent struct {
	// Enabled reports whether a gateway was requested at all.
	//
	// This is the difference between "this host could be a gateway" and "this
	// host should be one". Nothing infers it from hardware: it is read from
	// the document or it is not there.
	Enabled bool `json:"enabled"`

	// WANSelector and LANSelector are what the operator wrote, verbatim.
	//
	// They are kept in the desired state beside the resolved names because a
	// plan that cannot say "the document asked for hw:…, and this host calls
	// that enp0s31f6" cannot explain itself to the operator who has to decide
	// whether to apply it.
	WANSelector string `json:"wan_selector,omitempty"`
	LANSelector string `json:"lan_selector,omitempty"`
}

// State is the complete desired state of the gateway.
type State struct {
	// Name is the logical gateway name.
	Name string `json:"name"`
	// Generation is the configuration generation this state derives from.
	Generation uint64 `json:"generation"`
	// SchemaVersion is the configuration schema version.
	SchemaVersion int `json:"schema_version"`

	// Intent is the gateway intent this state was derived from.
	Intent GatewayIntent `json:"intent"`

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

	// DHCP is the desired DHCP service state.
	DHCP DHCP `json:"dhcp"`
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
	// Gateway intent is resolved once, here, and everything below reads it.
	//
	// It is built before any field is assigned because two of the things it
	// decides — whether the roles are required at all, and what forwarding
	// is wanted — change what the rest of the state should be. Deriving them
	// from the raw configuration instead would mean reading the document a
	// second time with a second set of rules, and the two answers would
	// eventually disagree.
	in := gateway.FromConfig(cfg, res)

	s := State{
		Name:          cfg.Gateway.Name,
		Generation:    cfg.Gateway.Generation,
		SchemaVersion: cfg.SchemaVersion,
		Intent: GatewayIntent{
			Enabled:     in.Enabled,
			WANSelector: in.Roles[host.RoleWAN].Selector,
			LANSelector: in.Roles[host.RoleLAN].Selector,
		},
	}

	// A gateway that was not requested has no roles to fill. The roles are
	// left absent rather than resolved, because reporting "the WAN is
	// enp0s31f6" for a document that asked for no gateway would be exactly
	// the inference this layer exists to avoid.
	if !in.Enabled {
		s.WAN = Interface{
			Role:      RoleWAN,
			MTU:       cfg.Network.MTU,
			Addresses: []string{},
			Reason:    "gateway.enabled is false; no gateway was requested",
		}
		s.LAN = Interface{
			Role:      RoleLAN,
			MTU:       cfg.Network.MTU,
			Addresses: []string{},
			Reason:    "gateway.enabled is false; no gateway was requested",
		}
		s.Addressing = Addressing{}
		s.NAT = NAT{Enabled: false, Interfaces: []string{}, Resolved: true}
		s.Firewall = Firewall{Backend: cfg.Firewall.Backend}
		s.QoS = QoS{}
		s.DNS = DNS{
			Servers: append([]string(nil), cfg.Network.DNS...),
			Present: false,
			// A document that asked for no gateway has no LAN to serve DNS
			// on. The service block is reported as not requested rather than
			// empty, so "declined" and "configured but unresolved" stay
			// distinguishable downstream.
			Service: DNSService{Enabled: cfg.DNS.Enabled, Resolved: true},
		}
		// Same reasoning for DHCP: not requested is a decision, and reporting
		// it as "pending" would tell the operator to go and do something they
		// deliberately chose not to do.
		s.DHCP = DHCP{
			Enabled:       cfg.DHCP.Enabled,
			Authoritative: cfg.DHCP.Authoritative,
			LeaseTime:     cfg.DHCP.LeaseTime.String(),
			Domain:        cfg.DHCP.Domain,
			Resolved:      true,
		}
		return s
	}

	// --- Interfaces ---

	if iface, ok := res.Assigned[host.RoleWAN]; ok {
		s.WAN = Interface{
			Name:      iface.SystemName,
			StableID:  iface.ID,
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
			StableID:  iface.ID,
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

	//
	// Forwarding is taken from the intent, not hardcoded.
	//
	// It was previously a literal `true`, which meant every desired state
	// ever produced asked for IPv4 forwarding regardless of what the
	// document said — and, more importantly, meant there was nowhere for an
	// operator to say they did not want it. A bridge and a router are
	// different machines described by the same document before this change.
	s.Addressing = Addressing{
		DefaultGateway:  cfg.Network.UpstreamGateway,
		UpstreamPresent: cfg.Network.UpstreamGateway != "",
		IPv4Forwarding:  in.Routing.IPv4Forwarding,
		IPv6Forwarding:  in.Routing.IPv6Forwarding,
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
		Enabled:         cfg.QoS.Enabled,
		Algorithm:       cfg.QoS.Algorithm,
		Interface:       cfg.QoS.Interface,
		DownloadKbps:    cfg.QoS.DownloadKbps,
		UploadKbps:      cfg.QoS.UploadKbps,
		OverheadPercent: cfg.QoS.OverheadPercent,
		Role:            "wan",
	}

	// The shaping interface is the resolved WAN, and the stable identity
	// comes from gateway intent rather than from a second resolution.
	//
	// An explicit qos.interface is preserved, because an operator who named
	// a device explicitly has said something the role model does not. But the
	// role and its stable ID are always recorded, so the desired state can
	// still explain which link it means.
	wan := in.Roles[host.RoleWAN]
	s.QoS.Role = string(host.RoleWAN)
	s.QoS.StableID = wan.StableID
	if s.QoS.Interface == "" && s.WAN.Present && s.WAN.Name != "" {
		s.QoS.Interface = s.WAN.Name
	}
	if s.QoS.Interface != "" && wan.Resolved {
		// Only trust the stable ID when the role actually resolved: pairing
		// an explicit kernel name with an unrelated role's identity would
		// describe a link that does not exist.
		s.QoS.StableID = wan.StableID
	}

	if !s.QoS.Enabled {
		// QoS off is a resolved state, not a pending one.
		s.QoS.Resolved = true
	} else {
		isConflict := (s.WAN.Present && s.LAN.Present && s.WAN.Name != "" && s.WAN.Name == s.LAN.Name) ||
			strings.EqualFold(cfg.QoS.Interface, "lan") ||
			(s.LAN.Name != "" && cfg.QoS.Interface == s.LAN.Name)
		s.QoS.Resolved = !isConflict &&
			s.QoS.Interface != "" &&
			s.QoS.DownloadKbps > 0 &&
			s.QoS.UploadKbps > 0 &&
			s.QoS.Algorithm != ""
	}

	// --- DNS ---

	s.DNS = DNS{
		Servers: append([]string(nil), cfg.Network.DNS...),
		Present: len(cfg.Network.DNS) > 0,
	}

	s.DNS.Service = dnsServiceState(cfg, in, s.LAN)

	// --- DHCP ---

	s.DHCP = dhcpServiceState(cfg, in, s.LAN)

	return s
}

// dnsServiceState projects DNS service intent into desired state.
//
// The upstream source rule is applied here rather than being re-derived: dns
// .upstream is canonical for the service and network.dns is the fallback,
// exactly as dns.ResolveUpstream decides. Applying it twice would mean two
// answers to "which resolvers", and the one recorded in the desired digest
// would be whichever disagreed with the report the operator was shown.
//
// A conflict is recorded as a conflict here rather than resolved. The desired
// state says what the document asked for; picking one of two disagreeing
// answers would put a choice into the content-addressed identity of a machine
// nobody has described.
func dnsServiceState(cfg config.Config, in gateway.Intent, lan Interface) DNSService {
	svc := DNSService{
		Enabled:        cfg.DNS.Enabled,
		LANSelector:    lanSelector(in),
		Interface:      lan.Name,
		StableID:       lan.StableID,
		LocalDomain:    cfg.DNS.LocalDomain,
		UpstreamSource: "",
	}

	dec := dns.ResolveUpstream(cfg.DNS.Upstream, cfg.Network.DNS)
	svc.UpstreamSource = dec.Source

	// Only the canonical source feeds the service. When the two fields
	// disagree, nothing is recorded as upstream: the operator is told which
	// resolver is live only after they resolve the conflict themselves.
	if dec.Source == dns.SourceFallback && dec.Conflict {
		svc.Upstream = nil
	} else {
		upstreams := make([]string, 0, len(dec.List))
		for _, u := range dec.List {
			if addr, err := netip.ParseAddr(u); err == nil {
				upstreams = append(upstreams, addr.String())
			}
		}
		// Sorted so that two documents naming the same resolvers in a
		// different order produce the same digest and the same plan ID.
		sort.Strings(upstreams)
		svc.Upstream = upstreams
	}

	if cfg.Network.LANPrefix != "" {
		if prefix, err := netip.ParsePrefix(cfg.Network.LANPrefix); err == nil {
			svc.ListenAddress = prefix.Addr().String()
		}
	}

	// A service with somewhere to listen and somewhere to forward to can be
	// placed. When it is off, that IS the resolved state.
	svc.Resolved = !svc.Enabled || (svc.ListenAddress != "" && svc.Interface != "")

	return svc
}

// dhcpServiceState projects DHCP intent into desired state.
//
// The pool and the advertised router both come from the LAN, never from an
// interface name: the router is the declared LAN address, and the pool is
// validated against the LAN subnet. That is what makes the desired state
// survive a NIC moving slots — the stable identity carries across, and the
// address does not depend on which enx… the kernel currently calls it.
func dhcpServiceState(cfg config.Config, in gateway.Intent, lan Interface) DHCP {
	dh := DHCP{
		Enabled:       cfg.DHCP.Enabled,
		LANSelector:   lanSelector(in),
		Interface:     lan.Name,
		StableID:      lan.StableID,
		LeaseTime:     cfg.DHCP.LeaseTime.String(),
		Domain:        cfg.DHCP.Domain,
		Authoritative: cfg.DHCP.Authoritative,
	}

	var prefix netip.Prefix
	if cfg.Network.LANPrefix != "" {
		prefix, _ = netip.ParsePrefix(cfg.Network.LANPrefix)
	}
	if prefix.IsValid() {
		dh.Subnet = prefix.Masked().String()
		// The router advertisement is the LAN address. There is no separate
		// DHCP router option in the configuration model and this layer does
		// not invent one: two sources of truth for the gateway's LAN address
		// is how a pool ends up advertising a router the machine does not
		// hold.
		dh.Router = prefix.Addr().String()
	}

	dh.Ranges = desiredDHCPRanges(cfg, prefix)

	dh.Resolved = !dh.Enabled || (dh.Interface != "" && dh.Subnet != "" && len(dh.Ranges) > 0)

	return dh
}

// desiredDHCPRanges renders the configured pools for the desired state.
//
// The derivation matches what internal/cli's policy translator does: an
// explicit range is used as written, and a document that asks for DHCP with a
// usable LAN but names no pool gets the conventional pool. Both paths are
// deterministic, and both are expressed in the intent's terms rather than in
// the backend's, so a future backend cannot change what THN wants.
func desiredDHCPRanges(cfg config.Config, prefix netip.Prefix) []string {
	var out []string

	for _, rg := range cfg.DHCP.Ranges {
		start, err1 := netip.ParseAddr(rg.Start)
		end, err2 := netip.ParseAddr(rg.End)
		if err1 != nil || err2 != nil {
			// An unparseable bound is reported by validation with the field
			// path that names it. The desired state records the shape it was
			// given rather than inventing an address for it, so the digest
			// still changes when the operator edits the broken value.
			out = append(out, fmt.Sprintf("%s-%s", rg.Start, rg.End))
			continue
		}
		out = append(out, fmt.Sprintf("%s-%s", start, end))
	}

	if len(out) == 0 && cfg.DHCP.Enabled && prefix.IsValid() {
		for _, r := range dhcp.DerivePool(prefix, 100, 150) {
			out = append(out, r.String())
		}
	}

	return out
}

// lanSelector returns what the operator wrote for the LAN, verbatim.
func lanSelector(in gateway.Intent) string {
	return in.Roles[host.RoleLAN].Selector
}

// Pending lists the subsystems whose desired state cannot yet be determined,
// with the reason. This is what `thn plan` shows as outstanding work, and what
// the diff reports as Pending rather than as a change.
func (s State) Pending() map[string]string {
	out := map[string]string{}

	// A document that did not ask for a gateway has nothing outstanding.
	// Reporting its roles as pending would be the inverse error: treating a
	// deliberate decision as an unfinished one.
	if !s.Intent.Enabled {
		return out
	}

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
	// DHCP and DNS are reported as pending only when they were asked for.
	// A service the operator declined is not outstanding work, and listing it
	// as pending would tell them to go and configure something they chose not
	// to.
	if s.DHCP.Enabled && !s.DHCP.Resolved {
		out["dhcp"] = "DHCP is enabled but the LAN or its address pool is not yet determined"
	}
	if s.DNS.Service.Enabled && !s.DNS.Service.Resolved {
		out["dns"] = "DNS is enabled but the LAN or its listen address is not yet determined"
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
	if !s.Intent.Enabled {
		fmt.Fprintf(&b, "          not requested (gateway.enabled is false)\n")
	}
	fmt.Fprintf(&b, "WAN:      %s\n", describeInterface(s.WAN))
	fmt.Fprintf(&b, "LAN:      %s\n", describeInterface(s.LAN))
	fmt.Fprintf(&b, "forward:  ipv4=%t ipv6=%t\n", s.Addressing.IPv4Forwarding, s.Addressing.IPv6Forwarding)
	fmt.Fprintf(&b, "NAT:      %s\n", describeNAT(s.NAT))
	fmt.Fprintf(&b, "firewall: %s\n", describeFirewall(s.Firewall))
	fmt.Fprintf(&b, "QoS:      %s\n", describeQoS(s.QoS))
	fmt.Fprintf(&b, "DNS:      %s\n", describeDNS(s.DNS))
	fmt.Fprintf(&b, "DNS svc:  %s\n", describeDNSService(s.DNS.Service))
	fmt.Fprintf(&b, "DHCP:     %s\n", describeDHCP(s.DHCP))

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

	// Both directions are named. "download" means internet to LAN and
	// "upload" means LAN to internet, and an operator reading only the words
	// would otherwise have to guess which way round the link is being capped.
	out := fmt.Sprintf("enabled (%s on %s [%s], download %dkbit/s internet-to-LAN, upload %dkbit/s LAN-to-internet)",
		q.Algorithm, q.Interface, orNoneStr(q.StableID),
		q.DownloadKbps, q.UploadKbps)

	return out
}

// describeDNS renders the resolver's desired state.
func describeDNS(d DNS) string {
	if !d.Present {
		return "not configured"
	}
	return strings.Join(d.Servers, ", ")
}

// describeDNSService renders the desired DNS *service*.
//
// It is a separate line from the resolver set because it is a separate
// decision. The line above is "what this host should query"; this one is
// "what clients should query this host for". Merging them would hide exactly
// the edit that has historically done nothing.
func describeDNSService(d DNSService) string {
	if !d.Enabled {
		return "not requested"
	}
	if !d.Resolved {
		return fmt.Sprintf("requested (pending: no LAN or listen address; source %s)",
			orNoneStr(d.UpstreamSource))
	}
	out := fmt.Sprintf("on %s", orNoneStr(d.ListenAddress))
	if len(d.Upstream) > 0 {
		out += fmt.Sprintf(" -> %s", strings.Join(d.Upstream, ", "))
	} else {
		out += " (no upstream declared)"
	}
	return out
}

// describeDHCP renders the desired DHCP service.
//
// The router is shown alongside the pool deliberately: an operator reading
// "pool 10.77.0.100-10.77.0.250" has no way to know the clients will be told
// 10.77.0.1 is their gateway unless both are stated.
func describeDHCP(d DHCP) string {
	if !d.Enabled {
		return "not requested"
	}
	if !d.Resolved {
		return "requested (pending: the LAN or its address pool is not yet determined)"
	}

	out := fmt.Sprintf("on %s (%s)", orNoneStr(d.Interface), orNoneStr(d.Subnet))
	if len(d.Ranges) > 0 {
		out += fmt.Sprintf(" pool %s", strings.Join(d.Ranges, ", "))
	}
	if d.Router != "" {
		out += fmt.Sprintf(" router %s", d.Router)
	}
	if len(d.AdvertisedDNS) > 0 {
		out += fmt.Sprintf(" DNS %s", strings.Join(d.AdvertisedDNS, ", "))
	}
	return out
}

// orNoneStr renders an empty string as an explicit absence.
func orNoneStr(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
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
