// Package network implements read-only inspection of host network state.
//
// # Observe only
//
// This package reads. It contains no code that changes an address, a route, a
// link state or a firewall rule, and every external command it runs is
// validated by internal/guard before execution. That is what makes
// `thn network inspect` safe to run against a real gateway from a laptop a
// long way away.
//
// # Two observation strategies
//
// Linux is the primary target and is observed through the iproute2/nftables/
// tc tooling via guard. Everywhere else — a developer laptop, a CI runner —
// there is nothing to inspect, so the package reports an explicit
// "unsupported platform" rather than inventing plausible data. Reporting
// nothing is more useful than reporting something false, because a plan built
// on invented interface state is worse than no plan.
//
// # Degradation is normal
//
// On a gateway under development the LAN interface is typically absent. Every
// inspection therefore returns partial results plus explicit diagnostics rather
// than an error, so that `thn status` still tells the operator what it can see.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/guard"
)

// LinkState is the administrative/operational state of an interface.
type LinkState string

const (
	// LinkUp means the interface is administratively up and carrier present.
	LinkUp LinkState = "up"
	// LinkDown means the interface is administratively up but has no carrier.
	LinkDown LinkState = "down"
	// LinkUnknown means the state could not be determined.
	LinkUnknown LinkState = "unknown"
)

// Address is an address assigned to an interface.
type Address struct {
	// Family is "inet" or "inet6".
	Family string `json:"family"`
	// Address is the CIDR form, e.g. "10.77.0.1/24".
	CIDR string `json:"cidr"`
	// Scope is the address scope reported by the kernel.
	Scope string `json:"scope,omitempty"`
	// Interface is the interface name.
	Interface string `json:"interface"`
}

// Interface is an observed network interface.
type Interface struct {
	// Name is the kernel interface name, e.g. "enp0s31f6".
	Name string `json:"name"`
	// Index is the kernel interface index.
	Index int `json:"index"`
	// MAC is the hardware address, empty for loopback and virtual links.
	MAC string `json:"mac,omitempty"`
	// MTU is the interface MTU.
	MTU int `json:"mtu"`
	// State is the observed link state.
	State LinkState `json:"state"`
	// Kind classifies the interface, e.g. "ethernet", "loopback", "vlan".
	Kind string `json:"kind"`
	// Flags are the kernel's interface flags, e.g. "BROADCAST,MULTICAST".
	Flags []string `json:"flags,omitempty"`
	// Addresses are the addresses assigned to this interface.
	Addresses []Address `json:"addresses,omitempty"`
	// Role is "wan", "lan" or "unassigned", derived from configuration.
	Role string `json:"role"`
}

// Route is an observed routing table entry.
type Route struct {
	// Destination is the prefix in CIDR form.
	Destination string `json:"destination"`
	// Gateway is the next hop, empty for a directly connected route.
	Gateway string `json:"gateway,omitempty"`
	// Interface is the outgoing interface.
	Interface string `json:"interface,omitempty"`
	// Protocol is the routing protocol that installed the route.
	Protocol string `json:"protocol,omitempty"`
	// Scope is the route scope.
	Scope string `json:"scope,omitempty"`
	// Metric is the route metric.
	Metric int `json:"metric,omitempty"`
	// Default marks the default route.
	Default bool `json:"default,omitempty"`
}

// Neighbour is an observed ARP/NDP entry.
type Neighbour struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	LinkLayer string `json:"link_layer,omitempty"`
	State     string `json:"state,omitempty"`
}

// SysctlValue is a read-only kernel tunable observation.
type SysctlValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	// Error records why the value could not be read, if it could not be.
	Error string `json:"error,omitempty"`
}

// Snapshot is a complete read-only view of host network state.
type Snapshot struct {
	// CapturedAt is when the observation was taken.
	CapturedAt time.Time `json:"captured_at"`
	// Platform is the runtime GOOS the observation came from.
	Platform string `json:"platform"`
	// Supported reports whether host inspection is available here.
	Supported bool `json:"supported"`
	// Interfaces are the observed interfaces, sorted by name.
	Interfaces []Interface `json:"interfaces"`
	// Addresses are all observed addresses, flattened.
	Addresses []Address `json:"addresses"`
	// Routes are the observed routes.
	Routes []Route `json:"routes"`
	// Neighbours are observed ARP/NDP entries.
	Neighbours []Neighbour `json:"neighbours"`
	// Sysctl holds kernel tunables relevant to gateway operation.
	Sysctl []SysctlValue `json:"sysctl"`
	// Diagnostics records what could not be observed and why.
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// Diagnostic is an inspection finding.
type Diagnostic struct {
	// Subject is what the diagnostic concerns.
	Subject string `json:"subject"`
	// Message describes the finding.
	Message string `json:"message"`
	// Severity is "info", "warning" or "error".
	Severity string `json:"severity"`
}

// Role constants used in Snapshot.
const (
	RoleWAN        = "wan"
	RoleLAN        = "lan"
	RoleUnassigned = "unassigned"
)

// relevantSysctls are the kernel tunables that determine whether a host can
// route and forward. They are read with `sysctl -n`, never written.
var relevantSysctls = []string{
	"net.ipv4.ip_forward",
	"net.ipv4.conf.all.forwarding",
	"net.ipv6.conf.all.forwarding",
	"net.ipv4.conf.all.rp_filter",
}

// relevantNFPackages are the nftables tables THN would plan against.
var relevantNFPackages = []string{"ip", "ip6", "inet"}

// InterfaceRoles names the interfaces THN considers assigned to a role.
type InterfaceRoles struct {
	// WAN is the uplink interface name.
	WAN string
	// LAN is the downstream interface name.
	LAN string
}

// Inspector captures a read-only snapshot of host network state.
type Inspector interface {
	// Inspect returns a snapshot. It does not return an error for partial
	// results: missing interfaces and unavailable tools are recorded as
	// diagnostics on the snapshot.
	Inspect(ctx context.Context) (*Snapshot, error)
}

// NewInspector returns an Inspector for the current platform.
func NewInspector() Inspector { return &inspector{} }

// inspector reads host state through guard-approved commands.
type inspector struct{}

// Inspect gathers a snapshot.
//
// A non-Linux host yields a snapshot with Supported=false and an explanatory
// diagnostic. That is the correct answer on a developer machine: THN has
// nothing to observe, and pretending otherwise would let a plan be generated
// against fiction.
func (i *inspector) Inspect(ctx context.Context) (*Snapshot, error) {
	snap := &Snapshot{
		CapturedAt: time.Now().UTC(),
		Platform:   goos,
	}

	if !supported {
		snap.Supported = false
		snap.Diagnostics = append(snap.Diagnostics, Diagnostic{
			Subject:  "platform",
			Severity: "warning",
			Message: fmt.Sprintf(
				"network inspection is only supported on Linux; this host is %s, so no host interfaces, addresses or routes were read",
				goos),
		})
		return snap, nil
	}

	snap.Supported = true

	links, diag := ipLinks(ctx)
	snap.Interfaces = links
	snap.Diagnostics = append(snap.Diagnostics, diag...)

	addrs, diag := ipAddresses(ctx)
	snap.Addresses = addrs
	snap.Diagnostics = append(snap.Diagnostics, diag...)

	routes, diag := ipRoutes(ctx)
	snap.Routes = routes
	snap.Diagnostics = append(snap.Diagnostics, diag...)

	neigh, diag := ipNeighbours(ctx)
	snap.Neighbours = neigh
	snap.Diagnostics = append(snap.Diagnostics, diag...)

	snap.Sysctl = readSysctls(ctx)

	attachAddresses(snap)
	return snap, nil
}

// ipLinks reads interface state via `ip -j -d link show`.
func ipLinks(ctx context.Context) ([]Interface, []Diagnostic) {
	out, err := guard.Exec(ctx, "ip", "-j", "-d", "link", "show")
	if err != nil {
		return nil, []Diagnostic{{
			Subject:  "interfaces",
			Severity: "error",
			Message:  fmt.Sprintf("could not read interfaces via ip: %v", err),
		}}
	}

	var raw []ipLinkJSON
	if err := json.Unmarshal([]byte(out.Stdout), &raw); err != nil {
		return nil, []Diagnostic{{
			Subject:  "interfaces",
			Severity: "error",
			Message:  fmt.Sprintf("could not parse ip link output: %v", err),
		}}
	}

	ifaces := make([]Interface, 0, len(raw))
	for _, r := range raw {
		ifaces = append(ifaces, Interface{
			Name:  r.IfName,
			Index: r.IfIndex,
			MAC:   r.Address,
			MTU:   r.MTU,
			State: linkStateFromOperstate(r.Operstate),
			Kind:  r.LinkInfo.InfoKind,
			Flags: r.Flags,
			Role:  RoleUnassigned,
		})
	}
	sort.Slice(ifaces, func(a, b int) bool { return ifaces[a].Name < ifaces[b].Name })
	return ifaces, nil
}

// linkStateFromOperstate maps a kernel operstate onto THN's link state.
func linkStateFromOperstate(s string) LinkState {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "UP":
		return LinkUp
	case "DOWN", "LOWERLAYERDOWN", "TESTING", "DORMANT":
		return LinkDown
	default:
		return LinkUnknown
	}
}

// ipAddresses reads addresses via `ip -j addr show`.
func ipAddresses(ctx context.Context) ([]Address, []Diagnostic) {
	out, err := guard.Exec(ctx, "ip", "-j", "addr", "show")
	if err != nil {
		return nil, []Diagnostic{{
			Subject:  "addresses",
			Severity: "error",
			Message:  fmt.Sprintf("could not read addresses via ip: %v", err),
		}}
	}

	var raw []ipAddrJSON
	if err := json.Unmarshal([]byte(out.Stdout), &raw); err != nil {
		return nil, []Diagnostic{{
			Subject:  "addresses",
			Severity: "error",
			Message:  fmt.Sprintf("could not parse ip addr output: %v", err),
		}}
	}

	var addrs []Address
	for _, r := range raw {
		for _, a := range r.AddrInfo {
			if a.Family != "inet" && a.Family != "inet6" {
				continue
			}
			addrs = append(addrs, Address{
				Family:    a.Family,
				CIDR:      fmt.Sprintf("%s/%d", a.Local, a.PrefixLen),
				Scope:     a.Scope,
				Interface: r.IfName,
			})
		}
	}
	sort.Slice(addrs, func(a, b int) bool { return addrs[a].CIDR < addrs[b].CIDR })
	return addrs, nil
}

// ipRoutes reads the routing table via `ip -j route show`.
func ipRoutes(ctx context.Context) ([]Route, []Diagnostic) {
	out, err := guard.Exec(ctx, "ip", "-j", "route", "show")
	if err != nil {
		return nil, []Diagnostic{{
			Subject:  "routes",
			Severity: "error",
			Message:  fmt.Sprintf("could not read routes via ip: %v", err),
		}}
	}

	var raw []ipRouteJSON
	if err := json.Unmarshal([]byte(out.Stdout), &raw); err != nil {
		return nil, []Diagnostic{{
			Subject:  "routes",
			Severity: "error",
			Message:  fmt.Sprintf("could not parse ip route output: %v", err),
		}}
	}

	var routes []Route
	for _, r := range raw {
		dest := r.Destination
		if dest == "" || dest == "default" {
			dest = "default"
		}
		routes = append(routes, Route{
			Destination: dest,
			Gateway:     r.Gateway,
			Interface:   r.Dev,
			Protocol:    r.Protocol,
			Scope:       r.Scope,
			Metric:      r.Metric,
			Default:     dest == "default",
		})
	}
	sort.Slice(routes, func(a, b int) bool {
		if routes[a].Default != routes[b].Default {
			return routes[a].Default // default route first
		}
		return routes[a].Destination < routes[b].Destination
	})
	return routes, nil
}

// ipNeighbours reads the neighbour table via `ip -j neigh show`.
func ipNeighbours(ctx context.Context) ([]Neighbour, []Diagnostic) {
	out, err := guard.Exec(ctx, "ip", "-j", "neigh", "show")
	if err != nil {
		// A missing neighbour table is not interesting on its own.
		return nil, nil
	}

	var raw []ipNeighJSON
	if err := json.Unmarshal([]byte(out.Stdout), &raw); err != nil {
		return nil, nil
	}

	var n []Neighbour
	for _, r := range raw {
		n = append(n, Neighbour{
			Interface: r.Dev,
			Address:   r.Dst,
			LinkLayer: r.Lladdr,
			State:     strings.Join(r.State, ","),
		})
	}
	return n, nil
}

// readSysctls reads gateway-relevant tunables with `sysctl -n`. Each key is
// read independently so that one missing key does not hide the others.
func readSysctls(ctx context.Context) []SysctlValue {
	out := make([]SysctlValue, 0, len(relevantSysctls))
	for _, key := range relevantSysctls {
		v := SysctlValue{Key: key}
		res, err := guard.Exec(ctx, "sysctl", "-n", key)
		if err != nil {
			v.Error = err.Error()
			v.Value = "unknown"
		} else {
			v.Value = strings.TrimSpace(res.Stdout)
		}
		out = append(out, v)
	}
	return out
}

// attachAddresses nests the flat address list onto its interfaces.
func attachAddresses(snap *Snapshot) {
	byName := make(map[string]*Interface, len(snap.Interfaces))
	for i := range snap.Interfaces {
		byName[snap.Interfaces[i].Name] = &snap.Interfaces[i]
	}
	for _, a := range snap.Addresses {
		if iface, ok := byName[a.Interface]; ok {
			iface.Addresses = append(iface.Addresses, a)
		}
	}
}

// ApplyRoles annotates interfaces with the WAN and LAN roles implied by
// configuration, so that callers can render status without re-deriving them.
func ApplyRoles(snap *Snapshot, roles InterfaceRoles) {
	for i := range snap.Interfaces {
		switch {
		case roles.WAN != "" && snap.Interfaces[i].Name == roles.WAN:
			snap.Interfaces[i].Role = RoleWAN
		case roles.LAN != "" && snap.Interfaces[i].Name == roles.LAN:
			snap.Interfaces[i].Role = RoleLAN
		default:
			snap.Interfaces[i].Role = RoleUnassigned
		}
	}
}

// Interface returns the named interface, or nil when it is not present.
func (s *Snapshot) Interface(name string) *Interface {
	if name == "" {
		return nil
	}
	for i := range s.Interfaces {
		if s.Interfaces[i].Name == name {
			return &s.Interfaces[i]
		}
	}
	return nil
}

// DefaultRoute returns the observed default route, or nil.
func (s *Snapshot) DefaultRoute() *Route {
	for i := range s.Routes {
		if s.Routes[i].Default {
			return &s.Routes[i]
		}
	}
	return nil
}

// SysctlValue returns the observed value of a tunable and whether it was
// read successfully.
func (s *Snapshot) SysctlValue(key string) (string, bool) {
	for _, v := range s.Sysctl {
		if v.Key == key {
			return v.Value, v.Error == ""
		}
	}
	return "", false
}

// IPForwardingEnabled reports whether the kernel is forwarding IPv4. It is
// the single most important observable when checking whether a gateway would
// actually route once configured.
func (s *Snapshot) IPForwardingEnabled() bool {
	v, ok := s.SysctlValue("net.ipv4.ip_forward")
	return ok && v == "1"
}

// MarshalJSON is provided so a snapshot can be stored verbatim in the state
// database and returned unchanged over IPC.
func (s *Snapshot) MarshalJSON() ([]byte, error) {
	type alias Snapshot
	return json.Marshal((*alias)(s))
}
