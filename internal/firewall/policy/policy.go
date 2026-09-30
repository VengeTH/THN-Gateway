package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Action is what a rule does when it matches.
type Action string

const (
	// ActionAccept allows the packet and stops evaluating.
	ActionAccept Action = "accept"
	// ActionDrop discards the packet silently.
	ActionDrop Action = "drop"
	// ActionReject discards the packet and sends an ICMP error, which tells
	// the client immediately rather than making it wait for a timeout.
	ActionReject Action = "reject"
	// ActionLog continues evaluation while recording the match.
	ActionLog Action = "log"
	// ActionQueue hands the packet to the traffic shaper.
	ActionQueue Action = "queue"
)

// Valid reports whether an action is one THN emits.
func (a Action) Valid() bool {
	switch a {
	case ActionAccept, ActionDrop, ActionReject, ActionLog, ActionQueue:
		return true
	}
	return false
}

// Protocol is an IP protocol.
type Protocol string

const (
	// ProtoAll matches every protocol.
	ProtoAll Protocol = "all"
	// ProtoTCP is the TCP protocol.
	ProtoTCP Protocol = "tcp"
	// ProtoUDP is the UDP protocol.
	ProtoUDP Protocol = "udp"
	// ProtoICMP is ICMPv4.
	ProtoICMP Protocol = "icmp"
	// ProtoICMPv6 is ICMPv6, which also carries neighbour discovery.
	ProtoICMPv6 Protocol = "icmpv6"
	// ProtoESP is IPsec.
	ProtoESP Protocol = "esp"
	// ProtoAH is IPsec authentication header.
	ProtoAH Protocol = "ah"
)

// Valid reports whether a protocol is one THN emits.
func (p Protocol) Valid() bool {
	switch p {
	case ProtoAll, ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6, ProtoESP, ProtoAH:
		return true
	}
	return false
}

// Hook is a netfilter hook a chain attaches to.
type Hook string

const (
	// HookInput is the packet arriving at this host.
	HookInput Hook = "input"
	// HookForward is the packet routed through this host.
	HookForward Hook = "forward"
	// HookOutput is the packet originating at this host.
	HookOutput Hook = "output"
	// HookPostrouting is the packet leaving this host.
	HookPostrouting Hook = "postrouting"
	// HookPrerouting is the packet arriving before routing decisions.
	HookPrerouting Hook = "prerouting"
)

// Valid reports whether a hook is one THN attaches to.
func (h Hook) Valid() bool {
	switch h {
	case HookInput, HookForward, HookOutput, HookPostrouting, HookPrerouting:
		return true
	}
	return false
}

// PortRange is an inclusive transport port range.
type PortRange struct {
	// Low is the first port in the range.
	Low int `json:"low"`
	// High is the last port. Equal to Low for a single port.
	High int `json:"high"`
}

// Single builds a single-port range.
func Single(port int) PortRange { return PortRange{Low: port, High: port} }

// IsSingle reports whether the range covers exactly one port.
func (p PortRange) IsSingle() bool { return p.Low == p.High }

// String renders the range in nftables notation.
func (p PortRange) String() string {
	if p.IsSingle() {
		return fmt.Sprintf("%d", p.Low)
	}
	return fmt.Sprintf("%d-%d", p.Low, p.High)
}

// Service is a named, permitted inbound connection.
type Service struct {
	// Name identifies the service in rendered output and diagnostics.
	Name string `json:"name"`
	// Ports are the transport ports the service listens on.
	Ports []PortRange `json:"ports"`
	// Protocol is the transport protocol.
	Protocol Protocol `json:"protocol"`
	// Source restricts which networks may connect. An empty list means any
	// source, which is only appropriate for loopback and admin services that
	// carry their own authentication.
	Source []string `json:"source,omitempty"`
	// Comment documents why the rule exists.
	Comment string `json:"comment,omitempty"`
}

// Well-known service definitions.
//
// These are convenience constructors, not policy. A caller may define any
// service; these simply avoid repeating port numbers and give the rendered
// output a recognisable name.
var (
	// SSH is remote administration.
	SSH = Service{
		Name: "ssh", Ports: []PortRange{Single(22)}, Protocol: ProtoTCP,
		Comment: "remote administration; the ruleset is unusable without this",
	}
	// HTTPS is a web interface.
	HTTPS = Service{
		Name: "https", Ports: []PortRange{Single(443)}, Protocol: ProtoTCP,
		Comment: "management web interface",
	}
	// DHCPv4Client is the DHCP client used to obtain a WAN address.
	DHCPv4Client = Service{
		Name: "dhcp-client", Ports: []PortRange{Single(68)}, Protocol: ProtoUDP,
		Comment: "DHCP client on the WAN; without it an upstream will not issue an address",
	}
	// DHCPv6Client is the DHCPv6 client used to obtain a WAN address.
	DHCPv6Client = Service{
		Name: "dhcpv6-client", Ports: []PortRange{Single(546)}, Protocol: ProtoUDP,
		Comment: "DHCPv6 client on the WAN",
	}
	// DNSResponder serves DNS to the LAN.
	DNSResponder = Service{
		Name: "dns", Ports: []PortRange{Single(53)}, Protocol: ProtoUDP,
		Comment: "DNS resolver for LAN clients",
	}
	// NTPClient synchronises the clock.
	NTPClient = Service{
		Name: "ntp", Ports: []PortRange{Single(123)}, Protocol: ProtoUDP,
		Comment: "clock synchronisation",
	}
	// Wireguard is an overlay VPN.
	Wireguard = Service{
		Name: "wireguard", Ports: []PortRange{Single(51820)}, Protocol: ProtoUDP,
		Comment: "overlay VPN",
	}
)

// AdminAccess describes how the operator reaches this host.
//
// This is the single most important field in the policy for safety reasons. A
// ruleset generated without a verified admin path is a ruleset that can lock
// the operator out of an unattended device, so validation checks that a
// matching accept rule exists before the policy is considered usable.
type AdminAccess struct {
	// Enabled reports whether admin access from the WAN is permitted at all.
	Enabled bool `json:"enabled"`
	// Service is the service used for administration, normally SSH.
	Service Service `json:"service"`
	// Source restricts administration to these source networks. An empty
	// list means any source, which is recorded as a risk finding rather than
	// refused, because an operator on a dynamic address may have no choice.
	Source []string `json:"source,omitempty"`
	// Comment documents the access method.
	Comment string `json:"comment,omitempty"`
}

// Interfaces names the interfaces the policy treats as WAN and LAN.
type Interfaces struct {
	// WAN is the uplink interface.
	WAN string `json:"wan"`
	// LAN is the downstream interface.
	LAN string `json:"lan"`
	// Loopback is the loopback interface name.
	Loopback string `json:"loopback"`
}

// ICMP describes how control traffic is treated.
//
// ICMP cannot simply be dropped on a gateway. It carries path MTU discovery,
// and a router that blocks PMTU blackholes any traffic whose packets exceed
// the path MTU — a failure that presents as an intermittent hang rather than
// an error, and is notoriously hard to diagnose from the client side.
type ICMP struct {
	// AllowWAN permits ICMP echo to the host from the WAN.
	AllowWAN bool `json:"allow_wan"`
	// AllowLAN permits ICMP echo to the host from the LAN.
	AllowLAN bool `json:"allow_lan"`
	// AllowForward permits ICMP across the gateway.
	AllowForward bool `json:"allow_forward"`
	// RateLimitEcho caps echo requests, in packets per second. Zero disables
	// the limit.
	RateLimitEcho int `json:"rate_limit_echo,omitempty"`
	// Comment documents the choice.
	Comment string `json:"comment,omitempty"`
}

// Forward describes traffic routed across the gateway.
type Forward struct {
	// LANToWAN permits traffic from the LAN to the internet. This is the
	// behaviour a gateway exists to provide.
	LANToWAN bool `json:"lan_to_wan"`
	// WANToLAN permits unsolicited inbound traffic from the internet to the
	// LAN. Almost never wanted on a home gateway.
	WANToLAN bool `json:"wan_to_lan"`
	// LANToLAN permits traffic between two LAN interfaces.
	LANToLAN bool `json:"lan_to_lan"`
	// RejectInvalid drops packets that fail conntrack rather than accepting
	// or dropping silently, which makes spoofing attempts visible.
	RejectInvalid bool `json:"reject_invalid"`
}

// Masquerade describes source NAT for traffic leaving the WAN.
type Masquerade struct {
	// Enabled reports whether outbound LAN traffic is source-NATed.
	Enabled bool `json:"enabled"`
	// OutInterface is the interface traffic must leave through. Empty means
	// any interface, which is almost never what is wanted on a gateway.
	OutInterface string `json:"out_interface,omitempty"`
	// Comment documents the choice.
	Comment string `json:"comment,omitempty"`
}

// Logging describes what the ruleset records.
type Logging struct {
	// Enabled reports whether rules log matches.
	Enabled bool `json:"enabled"`
	// RateLimit caps log entries per second. Unlimited logging on a busy
	// link will fill a disk, so this is capped by default.
	RateLimit int `json:"rate_limit,omitempty"`
	// LogLimit is the number of entries the kernel retains.
	LogLimit int `json:"log_limit,omitempty"`
}

// AntiSpoofing describes source-address validation.
type AntiSpoofing struct {
	// Enabled drops packets arriving on the WAN that claim a source address
	// from the LAN prefix.
	Enabled bool `json:"enabled"`
	// LANPrefix is the prefix that must not appear on the WAN.
	LANPrefix string `json:"lan_prefix,omitempty"`
}

// Policy is the complete firewall intent.
type Policy struct {
	// Version identifies the policy shape, and is written into the rendered
	// ruleset so a deployed file can be traced back to the policy that
	// produced it.
	Version string `json:"version"`

	// Family is the nftables address family: "inet", "ip" or "ip6". "inet"
	// handles both IPv4 and IPv6 in one table.
	Family string `json:"family"`

	// Table is the nftables table name.
	Table string `json:"table"`

	// Interfaces names the roles.
	Interfaces Interfaces `json:"interfaces"`

	// Admin is the administration path. Checked by validation before render.
	Admin AdminAccess `json:"admin"`

	// ICMP describes control traffic.
	ICMP ICMP `json:"icmp"`

	// Forward describes routed traffic.
	Forward Forward `json:"forward"`

	// Masquerade describes source NAT.
	Masquerade Masquerade `json:"masquerade"`

	// AntiSpoofing describes source validation.
	AntiSpoofing AntiSpoofing `json:"anti_spoofing"`

	// Services are additional inbound services exposed to the WAN.
	Services []Service `json:"services,omitempty"`

	// Logging describes recorded matches.
	Logging Logging `json:"logging"`

	// Comments are emitted verbatim near the top of the file.
	Comments []string `json:"comments,omitempty"`
}

// PolicyVersion is the policy shape this build produces.
const PolicyVersion = "1"

// Default returns a policy for a gateway with the WAN named and the LAN not
// yet identified.
//
// The defaults are deliberately conservative: only established traffic and
// ICMP are permitted from the WAN, and the LAN is left forwardable so that a
// gateway which has been configured but not yet attached still passes traffic
// rather than blackholing a network that is already running.
func Default() Policy {
	return Policy{
		Version: PolicyVersion,
		Family:  "inet",
		Table:   "thn",
		Interfaces: Interfaces{
			WAN:      "",
			LAN:      "",
			Loopback: "lo",
		},
		Admin: AdminAccess{
			Enabled: true,
			Service: SSH,
		},
		ICMP: ICMP{
			AllowWAN:      true,
			AllowLAN:      true,
			AllowForward:  true,
			RateLimitEcho: 10,
			Comment:       "ICMP carries path MTU discovery; blocking it causes silent black holes",
		},
		Forward: Forward{
			LANToWAN:      true,
			WANToLAN:      false,
			LANToLAN:      false,
			RejectInvalid: true,
		},
		Masquerade: Masquerade{
			Enabled: true,
		},
		AntiSpoofing: AntiSpoofing{
			Enabled: true,
		},
		Logging: Logging{
			Enabled:   false,
			RateLimit: 5,
			LogLimit:  1000,
		},
	}
}

// Clone returns a deep copy.
//
// Callers mutate policies while assembling them, and handing the renderer a
// copy keeps a policy from changing underneath a render in progress.
func (p Policy) Clone() Policy {
	out := p

	if p.Admin.Service.Ports != nil {
		out.Admin.Service.Ports = append([]PortRange(nil), p.Admin.Service.Ports...)
	}
	if p.Admin.Source != nil {
		out.Admin.Source = append([]string(nil), p.Admin.Source...)
	}
	if p.Services != nil {
		out.Services = make([]Service, len(p.Services))
		for i, s := range p.Services {
			out.Services[i] = s
			if s.Ports != nil {
				out.Services[i].Ports = append([]PortRange(nil), s.Ports...)
			}
			if s.Source != nil {
				out.Services[i].Source = append([]string(nil), s.Source...)
			}
		}
	}
	if p.Comments != nil {
		out.Comments = append([]string(nil), p.Comments...)
	}

	return out
}

// WithService appends a service and returns the policy, for chaining.
func (p Policy) WithService(s Service) Policy {
	p.Services = append(p.Services, s)
	return p
}

// AllInboundServices returns the admin service followed by any additional
// services, de-duplicated by name.
//
// Admin comes first deliberately: if the admin service and an added service
// share a port, the admin path must win, because losing it locks the
// operator out.
func (p Policy) AllInboundServices() []Service {
	seen := map[string]bool{}
	var out []Service

	if p.Admin.Enabled && p.Admin.Service.Name != "" {
		out = append(out, p.Admin.Service)
		seen[p.Admin.Service.Name] = true
	}

	for _, s := range p.Services {
		if seen[s.Name] {
			continue
		}
		seen[s.Name] = true
		out = append(out, s)
	}

	return out
}

// Normalize sorts services by name so that rendering is deterministic.
//
// Determinism matters more than it might appear: two renders of the same
// policy must produce byte-identical output, or a reviewer cannot tell a real
// change from reordering noise.
func (p *Policy) Normalize() {
	sort.SliceStable(p.Services, func(i, j int) bool {
		return p.Services[i].Name < p.Services[j].Name
	})

	for i := range p.Services {
		sort.SliceStable(p.Services[i].Ports, func(a, b int) bool {
			return p.Services[i].Ports[a].Low < p.Services[i].Ports[b].Low
		})
	}

	// Comments are deliberately NOT sorted. They are ordered prose rendered
	// into the ruleset header, and sorting them would scramble sentences that
	// were written to read in sequence.
}

// String renders a one-line summary of the policy.
func (p Policy) String() string {
	return fmt.Sprintf("policy %s (%s table %s): wan=%s lan=%s admin=%t wan-in=%t lan-to-wan=%t nat=%t",
		p.Version, p.Family, p.Table, orNone(p.Interfaces.WAN), orNone(p.Interfaces.LAN),
		p.Admin.Enabled, p.Admin.Enabled, p.Forward.LANToWAN, p.Masquerade.Enabled)
}

// orNone renders an empty string as a placeholder.
func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// joinPorts renders a port list for diagnostics.
func joinPorts(ports []PortRange) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}
