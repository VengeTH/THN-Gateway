package netconfig

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// PolicyVersion is the policy shape this build produces.
const PolicyVersion = 1

// Interfaces names the interfaces the configuration assigns roles to.
type Interfaces struct {
	// WAN is the uplink.
	WAN string `json:"wan"`
	// LAN is the downstream segment.
	LAN string `json:"lan"`
	// Loopback is the loopback interface.
	Loopback string `json:"loopback"`
}

// Role is an interface's role in forwarding decisions.
type Role string

const (
	// RoleWAN is the uplink.
	RoleWAN Role = "wan"
	// RoleLAN is the downstream segment.
	RoleLAN Role = "lan"
	// RoleLoopback is the local host.
	RoleLoopback Role = "loopback"
	// RoleUnknown is an interface with no assigned role.
	RoleUnknown Role = "unknown"
)

// RoleOf returns the role assigned to an interface name.
func (i Interfaces) RoleOf(name string) Role {
	switch {
	case i.WAN != "" && name == i.WAN:
		return RoleWAN
	case i.LAN != "" && name == i.LAN:
		return RoleLAN
	case i.Loopback != "" && name == i.Loopback:
		return RoleLoopback
	default:
		return RoleUnknown
	}
}

// Route is one routing table entry.
type Route struct {
	// Destination is the network this route covers.
	Destination netip.Prefix `json:"destination"`

	// NextHop is the gateway address, empty for a directly connected route.
	NextHop netip.Addr `json:"next_hop,omitempty"`

	// Interface is the egress interface. Required: a route with no interface
	// is not installable and is reported by validation.
	Interface string `json:"interface"`

	// Metric is the route preference. Lower wins.
	Metric int `json:"metric"`

	// Scope narrows where the route applies: link, host or global.
	Scope string `json:"scope,omitempty"`

	// Source is the preferred source address (prefsrc), used by the kernel
	// when originating traffic rather than forwarding it.
	Source netip.Addr `json:"source,omitempty"`

	// Table is the routing table name. Empty means "main".
	Table string `json:"table,omitempty"`

	// Protocol is the origin: static, dhcp or kernel.
	Protocol string `json:"protocol,omitempty"`

	// Comment documents why the route exists.
	Comment string `json:"comment,omitempty"`
}

// Routing is the desired routing table.
type Routing struct {
	// Enabled reports whether THN manages routing at all. A gateway without
	// routing is a bridge, which is a legitimate but very different device.
	Enabled bool `json:"enabled"`

	// IPv4Enabled reports whether IPv4 routing is configured.
	IPv4Enabled bool `json:"ipv4_enabled"`

	// IPv6Enabled reports whether IPv6 routing is configured.
	IPv6Enabled bool `json:"ipv6_enabled"`

	// Routes are the explicitly configured routes.
	Routes []Route `json:"routes,omitempty"`

	// DefaultGateway is the next hop for the default route, empty when the
	// uplink learns its own.
	DefaultGateway netip.Addr `json:"default_gateway,omitempty"`

	// DefaultGatewayInterface is the egress interface for the default route.
	DefaultGatewayInterface string `json:"default_gateway_interface,omitempty"`

	// DefaultMetric is the metric for the default route.
	DefaultMetric int `json:"default_metric,omitempty"`

	// AcceptRA reports whether IPv6 router advertisements are accepted, which
	// is required for IPv6 connectivity but also allows an upstream to
	// choose this host's addresses and routes.
	AcceptRA bool `json:"accept_ra"`

	// Table is the routing table name used for the managed routes.
	Table string `json:"table,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty"`
}

// NATMode is how outbound traffic is translated.
type NATMode string

const (
	// NATNone performs no translation.
	NATNone NATMode = "none"
	// NATMasquerade rewrites the source address to the egress interface's.
	NATMasquerade NATMode = "masquerade"
	// NATSNAT performs static source translation to a fixed address.
	NATSNAT NATMode = "snat"
)

// NAT is the desired address translation.
type NAT struct {
	// Enabled reports whether translation is configured.
	Enabled bool `json:"enabled"`

	// Mode is the translation method.
	Mode NATMode `json:"mode"`

	// OutInterface is the interface traffic must leave through. Required for
	// masquerade: an unscoped rule would rewrite traffic leaving every
	// interface, including the LAN.
	OutInterface string `json:"out_interface,omitempty"`

	// InInterface restricts which ingress traffic is translated. Empty means
	// any, which is almost never correct on a multi-homed gateway.
	InInterface string `json:"in_interface,omitempty"`

	// SNATAddress is the fixed source address for NATSNAT.
	SNATAddress netip.Addr `json:"snat_address,omitempty"`

	// SNATPrefix is the source prefix for NATSNAT.
	SNATPrefix netip.Prefix `json:"snat_prefix,omitempty"`

	// Comment documents the choice.
	Comment string `json:"comment,omitempty"`
}

// ForwardDirection names a permitted forwarding path.
type ForwardDirection string

const (
	// LANToWAN is LAN clients reaching the internet.
	LANToWAN ForwardDirection = "lan-to-wan"
	// WANToLAN is the internet reaching the LAN unsolicited.
	WANToLAN ForwardDirection = "wan-to-lan"
	// LANToLAN is traffic between two LAN segments.
	LANToLAN ForwardDirection = "lan-to-lan"
	// WANToWAN is transit traffic.
	WANToWAN ForwardDirection = "wan-to-wan"
)

// ForwardRule permits or denies one forwarding direction.
type ForwardRule struct {
	// Direction is the path this rule governs.
	Direction ForwardDirection `json:"direction"`

	// Action is "accept" or "drop".
	Action string `json:"action"`

	// Source restricts the source networks. Empty means any.
	Source []netip.Prefix `json:"source,omitempty"`

	// Destination restricts the destination networks. Empty means any.
	Destination []netip.Prefix `json:"destination,omitempty"`

	// Comment documents why the rule exists.
	Comment string `json:"comment,omitempty"`
}

// Forwarding is the desired packet forwarding configuration.
type Forwarding struct {
	// IPv4Enabled requests IPv4 packet forwarding. Without it the kernel
	// drops every forwarded IPv4 packet regardless of the rules below.
	IPv4Enabled bool `json:"ipv4_enabled"`

	// IPv6Enabled requests IPv6 packet forwarding.
	IPv6Enabled bool `json:"ipv6_enabled"`

	// Rules are the forwarding decisions, evaluated in order.
	Rules []ForwardRule `json:"rules,omitempty"`

	// DropInvalid drops packets failing conntrack.
	DropInvalid bool `json:"drop_invalid"`

	// AntiSpoofing drops packets claiming a LAN source address on the WAN.
	AntiSpoofing bool `json:"anti_spoofing"`

	// Comment documents the choice.
	Comment string `json:"comment,omitempty"`
}

// Policy is the complete data-plane intent.
type Policy struct {
	// Version identifies the policy shape.
	Version int `json:"version"`

	// Interfaces names the roles.
	Interfaces Interfaces `json:"interfaces"`

	// LocalAddresses are the gateway's own addresses, across every
	// interface.
	//
	// They are needed because a packet addressed to the gateway does not
	// traverse the forward chain at all: it is delivered locally and
	// filtered by the input chain instead. Without this list the data
	// plane cannot tell "this packet is for me" from "this packet is for
	// a client", and reports a client's ping to the gateway as dropped by
	// the forward chain's default policy. That is the opposite of what
	// the rendered ruleset does, which accepts LAN ICMP on the input
	// chain — a gateway that simulates as unreachable to its own clients.
	//
	// An empty list means the gateway has no known address, so nothing is
	// recognised as local and every destination is treated as forwarded.
	// That is the conservative direction: a packet wrongly treated as
	// forwarded is a less harmful wrong answer than one wrongly dropped.
	LocalAddresses []netip.Addr `json:"local_addresses,omitempty"`

	// Routing is the desired routing table.
	Routing Routing `json:"routing"`

	// NAT is the desired translation.
	NAT NAT `json:"nat"`

	// Forwarding is the desired forwarding configuration.
	Forwarding Forwarding `json:"forwarding"`
}

// Default returns a policy for a gateway with neither interface identified.
//
// The defaults are the smallest set that makes a gateway work: forward
// LAN-to-WAN, masquerade outbound traffic, and rely on the kernel default
// route learned from the uplink. Every interface name is empty because at this
// stage the hardware has not been identified, and validation reports that as
// informational rather than blocking.
func Default() Policy {
	return Policy{
		Version: PolicyVersion,
		Interfaces: Interfaces{
			WAN:      "",
			LAN:      "",
			Loopback: "lo",
		},
		Routing: Routing{
			Enabled:                 true,
			IPv4Enabled:             true,
			IPv6Enabled:             false,
			DefaultMetric:           100,
			AcceptRA:                false,
			Table:                   "main",
			Routes:                  []Route{},
			DefaultGateway:          netip.Addr{},
			DefaultGatewayInterface: "",
		},
		NAT: NAT{
			Enabled:      true,
			Mode:         NATMasquerade,
			OutInterface: "",
			Comment:      "LAN traffic is source-NATed to the WAN address on the way out",
		},
		Forwarding: Forwarding{
			IPv4Enabled:  true,
			IPv6Enabled:  false,
			DropInvalid:  true,
			AntiSpoofing: true,
			Rules: []ForwardRule{
				{
					Direction: LANToWAN,
					Action:    "accept",
					Comment:   "the purpose of a gateway: LAN clients reaching the internet",
				},
				{
					Direction: WANToLAN,
					Action:    "drop",
					Comment:   "unsolicited inbound traffic is not permitted",
				},
			},
		},
	}
}

// Clone returns a deep copy, so that a render cannot be affected by a caller
// mutating the policy concurrently.
func (p Policy) Clone() Policy {
	out := p

	// Every slice is copied rather than shared. A shallow copy of a
	// slice shares its backing array, so an append on the clone would
	// write into the original — and the original is frequently the
	// caller's policy, which must not be mutated by a render or a
	// simulation.
	if p.LocalAddresses != nil {
		out.LocalAddresses = append([]netip.Addr(nil), p.LocalAddresses...)
	}

	out.Routing.Routes = make([]Route, len(p.Routing.Routes))
	copy(out.Routing.Routes, p.Routing.Routes)

	if p.Routing.Comments != nil {
		out.Routing.Comments = append([]string(nil), p.Routing.Comments...)
	}

	out.Forwarding.Rules = make([]ForwardRule, len(p.Forwarding.Rules))
	for i, r := range p.Forwarding.Rules {
		out.Forwarding.Rules[i] = r
		if r.Source != nil {
			out.Forwarding.Rules[i].Source = append([]netip.Prefix(nil), r.Source...)
		}
		if r.Destination != nil {
			out.Forwarding.Rules[i].Destination = append([]netip.Prefix(nil), r.Destination...)
		}
	}

	return out
}

// Normalize sorts the policy's collections so that rendering is
// deterministic.
//
// Routes are sorted by destination then metric, because that is also the order
// in which they must be installed for the kernel to prefer them: two identical
// prefixes with different metrics are only meaningful in that order.
func (p *Policy) Normalize() {
	sort.SliceStable(p.Routing.Routes, func(i, j int) bool {
		a, b := p.Routing.Routes[i], p.Routing.Routes[j]
		if a.Destination.String() != b.Destination.String() {
			return a.Destination.String() < b.Destination.String()
		}
		return a.Metric < b.Metric
	})

	for i := range p.Routing.Routes {
		if p.Routing.Routes[i].Protocol == "" {
			p.Routing.Routes[i].Protocol = "static"
		}
		if p.Routing.Routes[i].Scope == "" {
			p.Routing.Routes[i].Scope = scopeFor(p.Routing.Routes[i])
		}
	}

	for i := range p.Forwarding.Rules {
		sort.SliceStable(p.Forwarding.Rules[i].Source, func(a, b int) bool {
			return p.Forwarding.Rules[i].Source[a].String() < p.Forwarding.Rules[i].Source[b].String()
		})
		sort.SliceStable(p.Forwarding.Rules[i].Destination, func(a, b int) bool {
			return p.Forwarding.Rules[i].Destination[a].String() < p.Forwarding.Rules[i].Destination[b].String()
		})
	}
}

// scopeFor derives a route scope from its shape.
func scopeFor(r Route) string {
	switch {
	case r.Destination.Bits() == r.Destination.Addr().BitLen():
		return "host"
	case r.NextHop.IsValid() && r.NextHop.IsLinkLocalUnicast():
		return "link"
	case r.Destination.Bits() >= r.Destination.Addr().BitLen()-8:
		return "link"
	default:
		return "global"
	}
}

// String renders a one-line summary of the policy.
func (p Policy) String() string {
	return fmt.Sprintf(
		"policy %d: wan=%s lan=%s routing=%t(v4=%t v6=%t routes=%d nat=%s(%s) forwarding=v4:%t rules=%d",
		p.Version, orNone(p.Interfaces.WAN), orNone(p.Interfaces.LAN),
		p.Routing.Enabled, p.Routing.IPv4Enabled, p.Routing.IPv6Enabled,
		len(p.Routing.Routes), natModeLabel(p.NAT), natTargetLabel(p.NAT),
		p.Forwarding.IPv4Enabled, len(p.Forwarding.Rules))
}

// orNone renders an empty string as a placeholder.
func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// natModeLabel renders the NAT mode.
func natModeLabel(n NAT) string {
	if !n.Enabled {
		return "off"
	}
	if n.Mode == "" {
		return "(unset)"
	}
	return string(n.Mode)
}

// natTargetLabel renders the NAT target interface or address.
func natTargetLabel(n NAT) string {
	switch {
	case n.Mode == NATSNAT && n.SNATAddress.IsValid():
		return n.SNATAddress.String()
	case n.OutInterface != "":
		return n.OutInterface
	default:
		return "unscoped"
	}
}

// HasRule reports whether a forwarding direction has an explicit rule.
func (f Forwarding) HasRule(d ForwardDirection) bool {
	for _, r := range f.Rules {
		if r.Direction == d {
			return true
		}
	}
	return false
}

// RuleFor returns the rule governing a direction.
func (f Forwarding) RuleFor(d ForwardDirection) (ForwardRule, bool) {
	for _, r := range f.Rules {
		if r.Direction == d {
			return r, true
		}
	}
	return ForwardRule{}, false
}

// RuleForPair returns the most specific rule matching a source and
// destination, preferring rules whose source and destination restrictions
// narrow the match.
//
// Order matters here: a rule with no restrictions matches everything, so it
// must be evaluated last or it would shadow the specific rules an operator
// wrote to carve out an exception.
func (f Forwarding) RuleForPair(src, dst netip.Addr) (ForwardRule, bool) {
	var best ForwardRule
	bestScore := -1
	found := false

	for _, r := range f.Rules {
		score, ok := matchScore(r, src, dst)
		if !ok {
			continue
		}
		if !found || score > bestScore {
			best, bestScore, found = r, score, true
		}
	}
	return best, found
}

// matchScore reports whether a rule matches a packet, and how specifically.
func matchScore(r ForwardRule, src, dst netip.Addr) (int, bool) {
	// A rule with no source or destination restriction matches any packet,
	// which is the least specific case.
	if len(r.Source) == 0 && len(r.Destination) == 0 {
		return 0, true
	}

	score := 0
	if len(r.Source) > 0 {
		if !anyContains(r.Source, src) {
			return 0, false
		}
		score += len(r.Source)
	}
	if len(r.Destination) > 0 {
		if !anyContains(r.Destination, dst) {
			return 0, false
		}
		score += len(r.Destination)
	}
	return score, true
}

// anyContains reports whether any prefix in the list contains addr.
func anyContains(list []netip.Prefix, addr netip.Addr) bool {
	for _, p := range list {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// PrefixList renders a prefix list for display.
func PrefixList(list []netip.Prefix) string {
	if len(list) == 0 {
		return "any"
	}
	parts := make([]string, len(list))
	for i, p := range list {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}
