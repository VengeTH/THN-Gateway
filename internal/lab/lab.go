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

	// GatewayWANIP is GatewayWANAddress without its prefix length.
	GatewayWANIP = "10.77.250.1"

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

// The gateway-side veth ports.
//
// THN never sees these: they are enslaved to the bridges, and THN resolves its
// roles to the bridges. They are named here rather than inline in the harness
// so that Validate can account for every name that will exist in the gateway
// namespace, including the ones THN does not manage.
const (
	GatewayWANPort = "vwan0"
	GatewayLANPort = "vlan0"

	// UnmanagedInterface is the interface THN must never touch. A dummy,
	// which is also not assignable, so it cannot be picked up by a role.
	UnmanagedInterface = "thnmgmt0"

	// UnmanagedAddress is that interface's address, asserted after apply and
	// after rollback to prove THN left it alone.
	UnmanagedAddress = "10.77.99.1/24"
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

// Port is one end of a veth pair that carries the lab's wiring.
//
// # Why this is declared rather than written inline
//
// A veth peer has to be *named* at creation, before it can be moved into the
// namespace that will keep it. That name is a real interface for the moment the
// pair exists, in whichever namespace created it. If it is the same as a name
// that namespace already holds, the kernel refuses the pair outright:
//
//	RTNETLINK answers: File exists
//
// which is why each Port is created in the namespace that KEEPS its End and
// moves only Port out. Declaring both ends here, together with the bridges and
// endpoints, lets Validate assert the invariant that prevents it: no namespace
// ever holds the same interface name twice.
type Port struct {
	// Namespace is where the pair is created. It is also where End stays.
	Namespace string

	// End is the name End keeps in Namespace.
	End string

	// Port is the name of the far end, which is moved into PortNamespace.
	//
	// It must be free in PortNamespace when it arrives.
	Port string

	// PortNamespace is where the far end is moved to.
	PortNamespace string

	// Master is the interface in Namespace that End is enslaved to.
	Master string
}

// Topology is the complete disposable lab the M6.2 tests build.
type Topology struct {
	// Interfaces are every endpoint, gateway interfaces first.
	Interfaces []Interface
	// Routes are the routes that exist before THN runs.
	Routes []Route
	// Ports are the veth pairs that wire the gateway to the two endpoints.
	Ports []Port
}

// Canonical returns the M6.2 disposable topology.
func Canonical() Topology {
	return Topology{
		Interfaces: []Interface{
			{Namespace: GatewayNamespace, Name: GatewayWANInterface, Address: GatewayWANAddress, Role: "wan"},
			{Namespace: GatewayNamespace, Name: GatewayLANInterface, Address: GatewayAddress, Role: "lan"},
			{Namespace: GatewayNamespace, Name: UnmanagedInterface, Address: UnmanagedAddress},
			{Namespace: TargetNamespace, Name: TargetWANInterface, Address: TargetAddress},
			{Namespace: ClientNamespace, Name: ClientLANInterface, Address: ClientAddress},
		},
		Ports: []Port{
			{
				Namespace:     TargetNamespace,
				End:           TargetWANInterface,
				Port:          GatewayWANPort,
				PortNamespace: GatewayNamespace,
				Master:        GatewayWANInterface,
			},
			{
				Namespace:     ClientNamespace,
				End:           ClientLANInterface,
				Port:          GatewayLANPort,
				PortNamespace: GatewayNamespace,
				Master:        GatewayLANInterface,
			},
		},
		Routes: []Route{
			{Namespace: GatewayNamespace, Destination: "default", Via: TargetIP, Device: GatewayWANInterface},
			{Namespace: ClientNamespace, Destination: "default", Via: GatewayIP, Device: ClientLANInterface},

			// The WAN side's return path for the LAN segment.
			//
			// Without it the target can answer a connection the gateway opened
			// — NAT rewrites the source, so those replies are directly
			// connected — but has no route at all to 10.77.0.0/24, so a reply
			// to an untranslated LAN address is undeliverable.
			//
			// That matters for the isolation test, which has to measure the
			// firewall refusing WAN→LAN rather than a missing route making the
			// same connection impossible. Without this route the "reachable
			// before the firewall" half of that test fails for a reason that has
			// nothing to do with the firewall, and the assertion it is guarding
			// never gets made.
			//
			// A specific prefix rather than a default: the upstream is not
			// THN's next hop for anywhere else, and pretending otherwise would
			// hide a missing route elsewhere in the topology.
			{Namespace: TargetNamespace, Destination: LANPrefix, Via: GatewayWANIP, Device: TargetWANInterface},
		},
	}
}

// Validate checks that the topology is internally coherent.
//
// It runs on every platform and exists so that a mistake in the address plan
// is caught on the workstation that typed it, rather than in a lab VM.
//
// The name-uniqueness check is the one that matters most, and it exists because
// its absence was found the hard way. Interface names are unique per namespace
// and nothing else: two links claiming one name is refused by the kernel with
// "RTNETLINK answers: File exists", which says nothing about which link
// collided with which. Asserting it here turns an opaque runtime failure into a
// plain statement about the topology.
func (t Topology) Validate() error {
	if len(t.Interfaces) == 0 {
		return fmt.Errorf("topology declares no interfaces")
	}

	seen := map[string]string{}
	claimed := map[netip.Addr]string{}

	// occupy reserves a kernel interface name in a namespace.
	occupy := func(namespace, name, what string) error {
		key := namespace + "/" + name
		if prev, dup := seen[key]; dup {
			return fmt.Errorf("%s claims interface %s in namespace %s, which %s already holds", what, name, namespace, prev)
		}
		seen[key] = what
		return nil
	}

	for _, iface := range t.Interfaces {
		if iface.Namespace == "" {
			return fmt.Errorf("interface %s has no namespace", iface.Name)
		}
		if iface.Name == "" {
			return fmt.Errorf("interface in namespace %s has no name", iface.Namespace)
		}
		if err := occupy(iface.Namespace, iface.Name, "interface "+iface.Name); err != nil {
			return err
		}

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

	for _, p := range t.Ports {
		// The far end arrives in the gateway under its own name, so that name
		// must be free there.
		if err := occupy(p.PortNamespace, p.Port, "veth port "+p.Port); err != nil {
			return err
		}

		// The end that stays behind is not a separate interface: it IS the
		// endpoint the topology already declared, carrying its address. It has
		// to be declared, or the pair would be wired to something THN cannot
		// address.
		if _, ok := seen[p.Namespace+"/"+p.End]; !ok {
			return fmt.Errorf("veth end %s is not a declared interface in namespace %s", p.End, p.Namespace)
		}
		if _, ok := seen[p.PortNamespace+"/"+p.Master]; !ok {
			return fmt.Errorf("veth port %s is enslaved to %s, which namespace %s does not declare",
				p.Port, p.Master, p.PortNamespace)
		}
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
		if r.Destination != "default" {
			if _, err := netip.ParsePrefix(r.Destination); err != nil {
				return fmt.Errorf("route %s in %s is neither `default` nor a prefix: %w", r.Destination, r.Namespace, err)
			}
		}
	}

	return nil
}

// LinkNames returns every interface name the topology expects in a namespace.
//
// It is the expectation the live harness asserts the kernel against after
// building, which is how an interface the topology did not ask for becomes
// visible instead of merely tolerated.
func (t Topology) LinkNames(namespace string) []string {
	seen := map[string]bool{}
	var out []string

	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}

	for _, iface := range t.Interfaces {
		if iface.Namespace == namespace {
			add(iface.Name)
		}
	}
	for _, p := range t.Ports {
		// The end that stays is already listed above as an endpoint; only the
		// end that arrives needs adding here.
		if p.PortNamespace == namespace {
			add(p.Port)
		}
	}

	sort.Strings(out)
	return out
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
	for _, p := range t.Ports {
		for _, ns := range []string{p.Namespace, p.PortNamespace} {
			if !seen[ns] {
				seen[ns] = true
				out = append(out, ns)
			}
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
