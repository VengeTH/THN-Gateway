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

	"github.com/VengeTH/THN-Gateway/internal/guard"
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
	// Name is the kernel interface name as the host reports it, e.g. "eth0" or
	// "enp1s0". It is an OBSERVATION and is expected to change; nothing above
	// this layer may use it as an identity.
	Name string `json:"name"`
	// Index is the kernel interface index.
	Index int `json:"index"`
	// MAC is the hardware address, empty for loopback and virtual links.
	MAC string `json:"mac,omitempty"`
	// MTU is the interface MTU.
	MTU int `json:"mtu"`
	// SpeedMbps is the negotiated link speed in Mbps, 0 when the driver did
	// not report one.
	//
	// Zero means "not reported". It does NOT mean the link is unusable, and
	// a planner must not treat it as a zero-capacity interface.
	SpeedMbps int `json:"speed_mbps,omitempty"`
	// State is the observed link state.
	State LinkState `json:"state"`
	// Kind classifies the interface, e.g. "ether", "wlan", "loopback", "vlan".
	//
	// This is the KERNEL's vocabulary, normalised only as far as `classify`
	// needs to. internal/host translates it into THN's own vocabulary, because
	// the kernel says "ether" and "wlan" where THN says "ethernet" and
	// "wireless".
	Kind string `json:"kind"`
	// LinkType is the kernel's link_type, e.g. "ether", "loopback", "ppp".
	LinkType string `json:"link_type,omitempty"`
	// Physical reports whether this link is real hardware.
	//
	// It is an observation derived from what the kernel reports — no virtual
	// link kind and an Ethernet link type — and never from the name. It is
	// the field that keeps a Docker bridge, a Tailscale tunnel or a container
	// veth from ever being offered to an operator as a gateway port.
	Physical bool `json:"physical"`
	// AdminUp reports the administrative state: whether the interface has
	// been brought up. Distinct from State, which also reflects carrier.
	AdminUp bool `json:"admin_up"`
	// Carrier reports whether a physical carrier is present.
	Carrier bool `json:"carrier"`
	// Master names the bond or bridge this interface is enslaved to.
	Master string `json:"master,omitempty"`
	// WirelessMode is the wireless operating mode: "managed" for a client,
	// "ap" for an access point, "monitor" for a capture interface.
	//
	// Empty on every non-wireless interface. It is the difference between a
	// wireless NIC that can be a CLIENT and one that can be an ACCESS POINT,
	// which are different capabilities on the same hardware.
	WirelessMode string `json:"wireless_mode,omitempty"`
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
	// System identifies the running system: distribution, version, kernel.
	//
	// Distinct from Platform above, which is the bare GOOS string this
	// struct already used to carry. Both exist because they answer different
	// questions: Platform answers "was this observed somewhere useful?", and
	// System answers "what machine is this?".
	System System `json:"system"`
	// NFTables is what nftables this host exposes. Observed, never modified.
	NFTables NFTablesState `json:"nftables"`
	// TrafficControl is what traffic control this host exposes.
	TrafficControl TCState `json:"traffic_control"`
	// DNS is how this host resolves names.
	DNS DNSState `json:"dns"`
	// Diagnostics records what could not be observed and why.
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`

	// Probes records every external observation this snapshot made, and what
	// each one concluded.
	//
	// Diagnostics is for things that are wrong. Probes is for how each
	// question was answered, including when the answer was "the probe did not
	// run" — which produces no diagnostic, because nothing failed, and which
	// is exactly the case an operator needs explained.
	//
	// Every entry answers the same questions: what was probed, with what,
	// whether it executed, at which stage it stopped, and why.
	Probes []Probe `json:"probes,omitempty"`
}

// ProbeFor returns the probe for a subsystem and operation.
//
// The lookup is by exact operation because several subsystems probe more than
// once — traffic control runs one query and asks two questions about it — and
// an operator reading a report needs the record for the question they are
// actually asking about.
//
// The second return is false when no such probe ran, which is deliberately
// not the same as a zero Probe: a missing record means "this was never
// asked", and a zero record with an empty subsystem would mean nothing at all.
func (s *Snapshot) ProbeFor(subsystem, operation string) (Probe, bool) {
	for _, p := range s.Probes {
		if p.Subsystem == subsystem && p.Operation == operation {
			return p, true
		}
	}
	return Probe{}, false
}

// FailedProbes returns the probes that did not reach a conclusion.
//
// NotChecked is included, and that is the point: a probe that never ran has
// established nothing about the host, so listing it here is correct rather
// than pedantic. It is the entry an operator most needs to find, because it
// is invisible everywhere else.
func (s *Snapshot) FailedProbes() []Probe {
	out := make([]Probe, 0, len(s.Probes))
	for _, p := range s.Probes {
		if !p.Outcome.OK() {
			out = append(out, p)
		}
	}
	return out
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
func NewInspector() Inspector { return &inspector{info: newHostInfo(context.Background())} }

// inspector reads host state through guard-approved commands.
//
// info supplies the facts `ip` is not authoritative about — wireless
// classification and link speed. It is a field so tests can inject a source
// and exercise the enrichment without a Linux host; production uses the live
// one.
type inspector struct{ info HostInfo }

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
		Probes:     []Probe{},
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
		// Recorded rather than left empty. An unsupported platform produced no
		// failures — nothing ran — and an empty probe list would read as
		// "nothing went wrong", which is a different and wrong answer.
		snap.Probes = append(snap.Probes, NotChecked("platform", "host-network-inspection"))
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

	// Last, and deliberately so: fold in the facts `ip` is not authoritative
	// about. Running it after attachAddresses means every source describes
	// the same instant, and running it after ParseLinks means the
	// enrichment operates on a complete link list.
	enrichLinks(ctx, snap.Interfaces, i.info, &snap.Diagnostics)

	// Every read the host-facts source made, with its cause. Collected after
	// enrichLinks because that is what triggers them, and before the
	// subsystem probes so the list reads in the order the facts were gathered.
	if i.info != nil {
		snap.Probes = append(snap.Probes, i.info.Probes()...)
	}

	// Subsystem availability. Every call below is read-only: `nft list`,
	// `tc show`, and a file read. They are gathered last so that the cheap
	// interface facts are already in hand if a slower tool is slow.
	snap.System = readSystem()
	snap.NFTables = ObserveNFTables(ctx)
	snap.TrafficControl = ObserveTrafficControl(ctx)
	snap.DNS = ObserveDNS()

	// The subsystem probes are appended last because that is when they were
	// run. Each state carries its own Probe too — the field next to the
	// capability it explains — and this list is the single place a report
	// can enumerate them all in the order they happened.
	snap.Probes = append(snap.Probes,
		snap.NFTables.Probe,
		snap.TrafficControl.Probe,
		snap.DNS.Probe,
	)

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

	ifaces, err := ParseLinks([]byte(out.Stdout))
	if err != nil {
		return nil, []Diagnostic{{
			Subject:  "interfaces",
			Severity: "error",
			Message:  fmt.Sprintf("could not parse ip link output: %v", err),
		}}
	}
	return ifaces, nil
}

// ParseLinks turns `ip -j -d link show` output into interfaces.
//
// Split from ipLinks so it can be tested without an `ip` binary and a Linux
// host. That split is the whole reason this function is separate: the parser
// decides whether THN understands the host, and while it was welded to the
// exec call it could only ever be exercised on the device it was written for —
// which is a device nobody can reach during development. A parser that has
// never run is not a parser that works; it is a parser that has not been found
// to be broken yet.
//
// The input is real `ip -j` output, byte for byte, because the whole risk is
// that the shape was imagined rather than observed. Fixtures are checked in
// rather than generated, so a change in what the parser expects is a visible
// edit rather than a test that quietly agrees with itself.
func ParseLinks(raw []byte) ([]Interface, error) {
	var parsed []ipLinkJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	ifaces := make([]Interface, 0, len(parsed))
	for _, r := range parsed {
		kind, physical, wlanMode := classify(r)
		ifaces = append(ifaces, Interface{
			Name:         r.IfName,
			Index:        r.IfIndex,
			MAC:          r.Address,
			MTU:          r.MTU,
			SpeedMbps:    r.Speed,
			State:        linkState(r.Operstate, r.Flags, kind),
			Kind:         kind,
			LinkType:     r.LinkType,
			Physical:     physical,
			AdminUp:      hasFlag(r.Flags, "UP"),
			Carrier:      hasFlag(r.Flags, "LOWER_UP"),
			Master:       r.Master,
			WirelessMode: wlanMode,
			Flags:        r.Flags,
			Role:         RoleUnassigned,
		})
	}
	sort.Slice(ifaces, func(a, b int) bool { return ifaces[a].Name < ifaces[b].Name })
	return ifaces, nil
}

// # Classifying an interface without its name
//
// The kernel names interfaces for humans, and humans are not a stable
// interface. An onboard NIC is `enp0s31f6` on one machine and `eth0` on
// another; a USB adapter is `enx00e099001812`; a Docker bridge is `docker0`;
// Tailscale is `tailscale0`. Every one of those names is a convention layered
// on top of the hardware, and every one of them can change.
//
// So nothing here looks at the name. Classification uses only what the kernel
// states about the link:
//
//   - a `wireless` object exists        → wireless, and it is physical
//   - the LOOPBACK flag, or loopback    → loopback
//   - linkinfo.info_kind names a kind  → that kind, and it is virtual
//   - link_type is "ether" otherwise   → a real NIC
//
// The last rule is the important one and it is an absence test: an interface
// with no virtual kind and an Ethernet link type is hardware. Docker
// interfaces, tunnels, bridges and VLANs all declare a kind, so none of them
// can reach it.
//
// A NIC enslaved into a bond or bridge still has no virtual kind of its own.
// It reports a `master`, and it is correctly classified physical — which is
// what it is. The bond is the virtual thing, and the bond says so.

// tunnelKinds are the link kinds that are always virtual.
//
// They are listed rather than pattern-matched because a tunnel that THN
// misclassifies as a NIC would be offered to an operator as an uplink.
var tunnelKinds = map[string]bool{
	"tun": true, "tap": true, "wireguard": true,
	"gre": true, "ipgre": true, "ip6gre": true, "gretap": true, "erspan": true,
	"sit": true, "ip6tnl": true, "vxlan": true, "geneve": true, "ip6vti": true,
}

// virtualKinds are non-tunnel virtual link kinds.
//
// "ether" is listed because that is what the kernel reports for a physical
// NIC's info_kind, and the absence of a virtual kind is the physical signal.
var virtualKinds = map[string]bool{
	"vlan": true, "bridge": true, "veth": true,
	"bond": true, "team": true, "dummy": true,
	"macvlan": true, "ipvlan": true,
}

// classify decides what an observed link IS.
//
// It returns the kernel's link kind, whether the link is physical hardware,
// and — for wireless — the operating mode.
//
// It deliberately returns no name and no opinion about which interface is an
// uplink. Deciding that is a separate act performed by an operator.
func classify(r ipLinkJSON) (kind string, physical bool, wirelessMode string) {
	infoKind := strings.ToLower(strings.TrimSpace(r.LinkInfo.InfoKind))
	linkType := strings.ToLower(strings.TrimSpace(r.LinkType))

	// Wireless first. The kernel emits a `wireless` object for exactly the
	// wireless links and for no others, which makes it a fact rather than a
	// guess — and it is what distinguishes a Wi-Fi NIC from a wired one when
	// both report link_type "ether".
	if hasWireless(r.Wireless) {
		return "wlan", true, wirelessModeOf(r.Wireless)
	}

	// Loopback is reported three different ways depending on the kernel and
	// the iproute2 version, so all three are accepted.
	if hasFlag(r.Flags, "LOOPBACK") || infoKind == "loopback" || linkType == "loopback" {
		return "loopback", false, ""
	}

	if virtualKinds[infoKind] || tunnelKinds[infoKind] {
		return infoKind, false, ""
	}

	// No virtual kind, and the link carries Ethernet. That is hardware.
	if linkType == "ether" || infoKind == "ether" {
		return "ether", true, ""
	}

	// Anything else — ppp, "none", a kind this build has never seen — is
	// treated as virtual. The default is the cautious one: offering an
	// unknown link type to an operator as a gateway port is the failure that
	// matters; declining to is a limitation they can work around.
	if infoKind == "" {
		return "unknown", false, ""
	}
	return infoKind, false, ""
}

// hasWireless reports whether the `wireless` object was present.
//
// `null` counts as absent: some iproute2 versions emit the key with a null
// value rather than omitting it.
func hasWireless(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}

// wirelessModeOf extracts the operating mode from the `wireless` object.
//
// A decode failure costs this one field and nothing else, because the object
// was decoded as RawMessage precisely so that this could not take the rest of
// the host down with it.
//
// The result is NORMALISED into THN's vocabulary, so that both wireless
// sources — this one and nl80211 — hand the model the same words. It did not
// used to, which meant the two sources disagreed: this path said "managed"
// while nl80211 said "client", and a rule written against one silently
// stopped matching the other.
func wirelessModeOf(raw json.RawMessage) string {
	var w ipWirelessJSON
	if err := json.Unmarshal(raw, &w); err != nil {
		return ""
	}
	if w.Iftype != "" {
		return NormaliseWirelessMode(w.Iftype)
	}
	if w.Mode != "" {
		return NormaliseWirelessMode(w.Mode)
	}
	return ""
}

// linkState maps a kernel operstate onto THN's link state.
//
// # The loopback case
//
// The kernel reports `lo` as operstate UNKNOWN even when it is fully up. That
// is not a quirk of any distribution: an interface with no carrier has no
// operational state to report, and a loopback device has no carrier, so the
// kernel declines to guess. `ip -j` nevertheless reports the IFF_UP *flag* on
// it, because the interface is administratively up.
//
// Reading operstate alone therefore reports the loopback as unknown on every
// Linux host ever shipped. That matters more than it sounds: the resolver
// binds to the loopback, and a gateway whose loopback reads as unknown cannot
// verify that its own name resolution is working — so a resolver check reports
// "undetermined" forever, on every gateway, for a reason that has nothing to
// do with the resolver.
//
// So an unknown operstate with the UP flag set is treated as up, which is what
// it means. An unknown operstate without the flag stays unknown, because that
// genuinely is not something anybody can say.
func linkState(operstate string, flags []string, kind string) LinkState {
	state := linkStateFromOperstate(operstate)

	if state == LinkUnknown && kind == "loopback" && hasFlag(flags, "UP") {
		return LinkUp
	}
	if state == LinkUnknown && hasFlag(flags, "UP") && hasFlag(flags, "LOWER_UP") {
		return LinkUp
	}
	return state
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, want) {
			return true
		}
	}
	return false
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

	addrs, err := ParseAddresses([]byte(out.Stdout))
	if err != nil {
		return nil, []Diagnostic{{
			Subject:  "addresses",
			Severity: "error",
			Message:  fmt.Sprintf("could not parse ip addr output: %v", err),
		}}
	}
	return addrs, nil
}

// parseAddresses turns `ip -j addr show` output into addresses.
func ParseAddresses(raw []byte) ([]Address, error) {
	var parsed []ipAddrJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	var addrs []Address
	for _, r := range parsed {
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

	routes, err := ParseRoutes([]byte(out.Stdout))
	if err != nil {
		return nil, []Diagnostic{{
			Subject:  "routes",
			Severity: "error",
			Message:  fmt.Sprintf("could not parse ip route output: %v", err),
		}}
	}
	return routes, nil
}

// parseAddresses turns `ip -j route show` output into routes.
//
// The destination needs normalising because `ip -j` reports the default route
// as `"dst": "default"` on some versions and as an absent field on others.
// Both mean the same route, and a gateway that treats them as two different
// routes has a default route it did not know it had.
func ParseRoutes(raw []byte) ([]Route, error) {
	var parsed []ipRouteJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	var routes []Route
	for _, r := range parsed {
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

	n, err := ParseNeighbours([]byte(out.Stdout))
	if err != nil {
		// A missing or unparseable neighbour table is not interesting on its
		// own. The ARP table is a cache, and a gateway that refused to report
		// because the cache was in an odd state would be worse than one that
		// reports what it could read.
		return nil, nil
	}
	return n, nil
}

// parseNeighbours turns `ip -j neigh show` output into neighbours.
func ParseNeighbours(raw []byte) ([]Neighbour, error) {
	var parsed []ipNeighJSON
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	var n []Neighbour
	for _, r := range parsed {
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
