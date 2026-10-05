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

	// Kind is the link type to create, "bridge" or "dummy".
	//
	// Empty for an endpoint that is not created from scratch — the veth ends
	// below, which arrive with their pair rather than being created here.
	// Declaring it is what lets the harness create links from data instead of
	// branching on a name, which is how two code paths ended up owning the same
	// interface.
	Kind string `json:"kind,omitempty"`

	// Up is the administrative state the interface is left in before THN runs.
	//
	// False for the gateway's LAN on purpose: that link starting down and
	// unaddressed is the work THN is about to do, and a lab that arrived
	// already configured would prove nothing about whether the transaction
	// configured it.
	Up bool `json:"up"`

	// Baseline reports whether the harness installs Address before THN runs.
	//
	// It is separate from Up, because a declared address and an applied one
	// are different claims. The gateway's LAN declares the address THN is
	// expected to give it — that is the *desired* state the plan converges on —
	// but the harness must not put it there, or there is no drift for the
	// transaction to detect.
	//
	// Conflating the two is how a generalised "address every declared
	// interface" loop ends up pre-configuring the one link the test depends on
	// THN configuring.
	Baseline bool `json:"baseline"`
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

	// Sysctls are the kernel tunables the lab establishes on the gateway
	// before THN runs.
	//
	// # Why they have to be stated
	//
	// A network namespace does not begin neutral. Linux copies `conf.all` and
	// `conf.default` from the initial namespace when a new one is created, and
	// `net.ipv4.ip_forward` is an alias for `conf.all.forwarding`. On a host
	// that routes between subnets — which any machine running this lab does —
	// a fresh namespace arrives with forwarding already enabled.
	//
	// Inheriting that is not a lab; it is a copy of whatever the host happened
	// to be doing. Worse, it makes the tests' meaning shift with the host: the
	// lab asserted forwarding was 0 at baseline, and when it was not, THN
	// correctly produced no forwarding drift, so no forwarding operation was
	// ever applied and none could be rolled back. Two tests then failed an
	// assertion about a step that had never been in the plan.
	//
	// Stating the baseline restores the distinction that matters: this is what
	// the lab is before THN runs; the desired state is what THN is asked to
	// converge it onto.
	Sysctls map[string]string
}

// IPForwardKey is the tunable THN manages to make the gateway route at all.
const IPForwardKey = "net.ipv4.ip_forward"

// Canonical returns the M6.2 disposable topology.
func Canonical() Topology {
	return Topology{
		Sysctls: map[string]string{
			// Forwarding off at baseline. This is not an assertion about the
			// host — it is a declaration about the lab, applied inside the
			// gateway namespace only, and it is what gives `ip-forwarding` its
			// drift. With forwarding already on, THN has nothing to change and
			// the rollback tests have nothing to undo.
			IPForwardKey: "0",
		},
		Interfaces: []Interface{
			{Namespace: GatewayNamespace, Name: GatewayWANInterface, Address: GatewayWANAddress, Role: "wan", Kind: "bridge", Up: true, Baseline: true},
			{Namespace: GatewayNamespace, Name: GatewayLANInterface, Address: GatewayAddress, Role: "lan", Kind: "bridge", Up: false, Baseline: false},
			{Namespace: GatewayNamespace, Name: UnmanagedInterface, Address: UnmanagedAddress, Kind: "dummy", Up: true, Baseline: true},
			{Namespace: TargetNamespace, Name: TargetWANInterface, Address: TargetAddress, Up: true, Baseline: true},
			{Namespace: ClientNamespace, Name: ClientLANInterface, Address: ClientAddress, Up: true, Baseline: true},
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
		switch iface.Kind {
		case "", "bridge", "dummy":
		default:
			return fmt.Errorf("interface %s declares link kind %q; only \"bridge\" and \"dummy\" are created by this lab",
				iface.Name, iface.Kind)
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
		//
		// It is also what the kernel calls `ipv4: Address already assigned`,
		// which names neither link. The live lab hit exactly that, because one
		// address had two owners in the setup path rather than one. This check
		// makes the second owner impossible to declare in the first place.
		if prev, dup := claimed[prefix.Addr()]; dup {
			return fmt.Errorf("interfaces %s and %s both claim address %s; each address has exactly one owner",
				prev, iface.Name, prefix.Addr())
		}
		claimed[prefix.Addr()] = iface.Name
	}

	for _, iface := range t.Interfaces {
		if iface.Kind != "" && iface.Baseline && iface.Address == "" {
			return fmt.Errorf("interface %s is created and installed at baseline but carries no address", iface.Name)
		}
	}

	// Every endpoint the live probes originate from or terminate on has to be
	// reachable at baseline, or a probe cannot distinguish "the firewall
	// blocked it" from "there was never anything there". That distinction is
	// what the isolation test rests on.
	for _, ns := range []string{ClientNamespace, TargetNamespace} {
		found := false
		for _, iface := range t.Interfaces {
			if iface.Namespace != ns {
				continue
			}
			found = true
			if !iface.Baseline || iface.Address == "" {
				return fmt.Errorf("endpoint %s in namespace %s is not addressed at baseline; "+
					"a probe there would fail before THN did anything", iface.Name, ns)
			}
		}
		if !found {
			return fmt.Errorf("namespace %s declares no endpoint", ns)
		}
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

	for key, value := range t.Sysctls {
		if value != "0" && value != "1" {
			return fmt.Errorf("baseline sysctl %s declares value %q; only 0 or 1 are meaningful here", key, value)
		}
	}
	if _, ok := t.Sysctls[IPForwardKey]; !ok {
		return fmt.Errorf("no baseline declared for %s; a namespace inherits the host's value, "+
			"so the lab must state the forwarding baseline it means to reconcile from", IPForwardKey)
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
