// Package lab declares the THN M6.2 disposable gateway topology.
//
// # What this is
//
// M6.0 made transactions safe and M6.1 made them executable against a real
// Linux kernel. M6.2 has to answer a different question: does THN actually
// behave like a router? A transaction that completes is not evidence of that.
// The evidence is a packet leaving a client, crossing a LAN, being forwarded,
// filtered, translated, and arriving at a WAN-side endpoint — and the same
// endpoint's attempt to reach back into the LAN failing.
//
// This package is the address plan for that experiment. It is deliberately
// data, not behaviour: the topology can be checked, printed and asserted
// against on any platform, including a laptop that will never carry a packet.
//
// The behaviour that builds it lives in e2e_linux_test.go, behind
// //go:build linux, because building it needs root and a kernel.
//
// # The four points
//
//	      disposable WAN  10.77.250.0/24
//	           |
//	┌──────────▼──────────┐
//	│  WAN-side target    │  the only endpoint the client may reach
//	│  10.77.250.2        │
//	└──────────┬──────────┘
//	           |
//	┌──────────▼──────────┐
//	│     THN Gateway     │
//	│  WAN  10.77.250.1   │
//	│  LAN  10.77.0.1/24  │
//	└──────────┬──────────┘
//	           |
//	┌──────────▼──────────┐
//	│     Test client     │
//	│     10.77.0.100     │
//	└─────────────────────┘
//
// The WAN-side target is a process the harness starts, on a fixed port, that
// reports the source address it observed. That is what makes the NAT assertion
// real: "the LAN client reached the target" is a weaker claim than "the target
// saw 10.77.250.1 rather than 10.77.0.100".
//
// # Why the interface names are not eth0 and eth1
//
// The lab's interfaces are named thnwan0 and thnlan0. If they were called
// eth0 and eth1, every test would still pass if THN had grown a hardcoded
// special case for those two names. Naming them anything else means the tests
// pass only if logical-role resolution actually worked.
//
// # Why nothing here can reach a real network
//
// Every address is inside RFC 1918 space chosen for this lab, and the live
// harness builds the whole topology from network namespaces. The host's own
// interfaces are never referenced, never routed to, and never read.
package lab

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Canonical addressing for the disposable lab.
//
// The LAN block is fixed by the rest of the project — docs, fixtures and the
// planner all already assume 10.77.0.1/24 — so it is declared once here and
// asserted by TestCanonicalTopologyAddressing.
const (
	// LANPrefix is the downstream segment THN serves.
	LANPrefix = "10.77.0.0/24"

	// GatewayAddress is THN's LAN-side address. This is the value an operator
	// sees and the value the client's default route points at.
	GatewayAddress = "10.77.0.1/24"

	// GatewayIP is GatewayAddress without its prefix length.
	GatewayIP = "10.77.0.1"

	// ClientAddress is the test client's LAN-side address.
	ClientAddress = "10.77.0.100/24"

	// ClientIP is ClientAddress without its prefix length.
	ClientIP = "10.77.0.100"

	// WANPrefix is the disposable upstream segment. It is deliberately not the
	// LAN block: the two are separate segments so that "the packet left the
	// LAN" is visible in the addresses rather than inferred from a router.
	WANPrefix = "10.77.250.0/24"

	// GatewayWANAddress is THN's uplink address inside the lab VM.
	GatewayWANAddress = "10.77.250.1/24"

	// TargetAddress is the WAN-side test target. It is also the lab's default
	// gateway, so it plays the part an upstream router would.
	TargetAddress = "10.77.250.2/24"

	// TargetIP is TargetAddress without its prefix length.
	TargetIP = "10.77.250.2"
)

// Namespace names. They are prefixed so a leaked namespace is obvious in
// `ip netns list` rather than looking like something the operator created.
const (
	GatewayNamespace = "thn-m62-gateway"
	ClientNamespace  = "thn-m62-client"
	TargetNamespace  = "thn-m62-wan"
)

// Interface names inside the namespaces.
//
// Deliberately not eth0/eth1 — see the package comment.
const (
	GatewayWANInterface = "thnwan0"
	GatewayLANInterface = "thnlan0"

	ClientLANInterface = "thnlan0"
	TargetWANInterface = "thnwan0"
)

// TargetPort is the TCP port the WAN-side test target listens on.
//
// A fixed port rather than an ephemeral one because the gateway has to be told
// where to send traffic before the transaction that permits the traffic has
// run. An ephemeral port cannot be part of a health check that is written
// before the firewall exists.
const TargetPort = 18080

// Interface is one named endpoint in the topology.
type Interface struct {
	// Namespace is the network namespace it lives in.
	Namespace string
	// Name is its kernel name inside that namespace.
	Name string
	// Address is its CIDR, empty for a link with no address yet.
	Address string
	// Role is the logical role THN assigns to it: "wan", "lan" or "" for
	// endpoints THN never manages.
	Role string
}

// Route is a route present in the topology before THN runs.
//
// The gateway already has a correct default route. That is deliberate: THN is
// a gateway, not an autoconfiguring host, and a test that let it invent its own
// next hop would be testing something THN does not do.
type Route struct {
	// Namespace is the network namespace the route lives in.
	Namespace string
	// Destination is the prefix, or "default".
	Destination string
	// Via is the next hop.
	Via string
	// Device is the outgoing interface.
	Device string
}

// Topology is the complete disposable lab the M6.2 tests build.
type Topology struct {
	// Interfaces are every endpoint, gateway interfaces first.
	Interfaces []Interface
	// Routes are the routes that exist before THN runs.
	Routes []Route
}

// Canonical returns the M6.2 disposable topology.
func Canonical() Topology {
	return Topology{
		Interfaces: []Interface{
			{Namespace: GatewayNamespace, Name: GatewayWANInterface, Address: GatewayWANAddress, Role: "wan"},
			{Namespace: GatewayNamespace, Name: GatewayLANInterface, Address: GatewayAddress, Role: "lan"},
			{Namespace: TargetNamespace, Name: TargetWANInterface, Address: TargetAddress},
			{Namespace: ClientNamespace, Name: ClientLANInterface, Address: ClientAddress},
		},
		Routes: []Route{
			{Namespace: GatewayNamespace, Destination: "default", Via: TargetIP, Device: GatewayWANInterface},
			{Namespace: ClientNamespace, Destination: "default", Via: GatewayIP, Device: ClientLANInterface},
		},
	}
}

// Validate checks that the topology is internally coherent.
//
// It runs on every platform and exists so that a mistake in the address plan
// is caught on the workstation that typed it, rather than in a lab VM.
func (t Topology) Validate() error {
	if len(t.Interfaces) == 0 {
		return fmt.Errorf("topology declares no interfaces")
	}

	seen := map[string]string{}
	claimed := map[netip.Addr]string{}

	for _, iface := range t.Interfaces {
		if iface.Namespace == "" {
			return fmt.Errorf("interface %s has no namespace", iface.Name)
		}
		if iface.Name == "" {
			return fmt.Errorf("interface in namespace %s has no name", iface.Namespace)
		}

		key := iface.Namespace + "/" + iface.Name
		if prev, dup := seen[key]; dup {
			return fmt.Errorf("interface %s is declared twice (namespace %s and %s)", iface.Name, prev, iface.Namespace)
		}
		seen[key] = iface.Namespace

		if iface.Address == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(iface.Address)
		if err != nil {
			return fmt.Errorf("interface %s has unparseable address %q: %w", iface.Name, iface.Address, err)
		}
		if prefix.Bits() == 0 {
			return fmt.Errorf("interface %s address %q covers a whole network; it must be a host address",
				iface.Name, iface.Address)
		}

		// A duplicate host address on two links produces the most confusing
		// possible symptom: ARP answered by whichever link the route happened
		// to prefer, and behaviour that changes with traffic.
		if prev, dup := claimed[prefix.Addr()]; dup {
			return fmt.Errorf("interfaces %s and %s both claim address %s", prev, iface.Name, prefix.Addr())
		}
		claimed[prefix.Addr()] = iface.Name
	}

	// The LAN and the WAN are separate segments. That is not cosmetic: it is
	// what makes "the packet left the LAN" visible in the addresses rather
	// than something a reader has to take on trust.
	if LANNetwork().Overlaps(WANNetwork()) {
		return fmt.Errorf("the LAN block %s and the WAN block %s overlap", LANNetwork(), WANNetwork())
	}

	for _, r := range t.Routes {
		if _, err := netip.ParseAddr(r.Via); err != nil {
			return fmt.Errorf("route %s in %s has unparseable next hop %q: %w", r.Destination, r.Namespace, r.Via, err)
		}
	}

	return nil
}

// LANNetwork returns the LAN block the topology serves.
func LANNetwork() netip.Prefix {
	p, _ := netip.ParsePrefix(LANPrefix)
	return p
}

// WANNetwork returns the disposable upstream block.
func WANNetwork() netip.Prefix {
	p, _ := netip.ParsePrefix(WANPrefix)
	return p
}

// GatewayLAN returns THN's LAN-side interface as declared.
func (t Topology) GatewayLAN() (Interface, bool) { return t.byRole("lan") }

// GatewayWAN returns THN's uplink interface as declared.
func (t Topology) GatewayWAN() (Interface, bool) { return t.byRole("wan") }

func (t Topology) byRole(role string) (Interface, bool) {
	for _, i := range t.Interfaces {
		if i.Role == role {
			return i, true
		}
	}
	return Interface{}, false
}

// Namespaces lists every namespace the topology uses, sorted.
//
// Sorted so teardown order is deterministic, which matters when a test fails
// partway: an unstable teardown leaves a different set of leftovers on each
// run and the failure becomes unreproducible.
func (t Topology) Namespaces() []string {
	seen := map[string]bool{}
	var out []string
	for _, i := range t.Interfaces {
		if !seen[i.Namespace] {
			seen[i.Namespace] = true
			out = append(out, i.Namespace)
		}
	}
	for _, r := range t.Routes {
		if !seen[r.Namespace] {
			seen[r.Namespace] = true
			out = append(out, r.Namespace)
		}
	}
	sort.Strings(out)
	return out
}

// TargetEndpoint is the address of the WAN-side test target.
func TargetEndpoint() string {
	return fmt.Sprintf("%s:%d", TargetIP, TargetPort)
}

// Describe renders the topology for a test log, one line per fact.
func (t Topology) Describe() string {
	var b strings.Builder
	for _, i := range t.Interfaces {
		fmt.Fprintf(&b, "  %-16s %-10s %-16s %s\n", i.Namespace, i.Name, orDash(i.Address), orDash(i.Role))
	}
	for _, r := range t.Routes {
		fmt.Fprintf(&b, "  %-16s route %-8s via %-12s dev %s\n", r.Namespace, r.Destination, r.Via, r.Device)
	}
	return strings.TrimRight(b.String(), "\n")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
