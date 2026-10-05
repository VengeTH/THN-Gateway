package lab

// These assertions run on every platform, including the Windows workstation
// where the lab is typed. The live packet tests are behind //go:build linux;
// the address plan they depend on is checked here so a mistake in it is caught
// where it was made rather than three in the morning in a lab VM.

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestCanonicalTopologyAddressing(t *testing.T) {
	top := Canonical()
	if err := top.Validate(); err != nil {
		t.Fatalf("canonical topology is invalid: %v", err)
	}

	lan, ok := top.GatewayLAN()
	if !ok {
		t.Fatal("canonical topology declares no LAN interface")
	}
	if lan.Address != GatewayAddress {
		t.Errorf("THN LAN address is %q, want %q", lan.Address, GatewayAddress)
	}
	if lan.Namespace != GatewayNamespace {
		t.Errorf("THN LAN lives in %q, want %q", lan.Namespace, GatewayNamespace)
	}

	wan, ok := top.GatewayWAN()
	if !ok {
		t.Fatal("canonical topology declares no WAN interface")
	}
	if wan.Namespace != GatewayNamespace {
		t.Errorf("THN WAN lives in %q, want %q", wan.Namespace, GatewayNamespace)
	}

	client := interfaceIn(t, top, ClientNamespace)
	if client.Address != ClientAddress {
		t.Errorf("client address is %q, want %q", client.Address, ClientAddress)
	}
	if client.Role != "" {
		t.Errorf("the client carries role %q; the client is not a THN-managed interface", client.Role)
	}

	target := interfaceIn(t, top, TargetNamespace)
	if target.Address != TargetAddress {
		t.Errorf("WAN-side target address is %q, want %q", target.Address, TargetAddress)
	}

	// The client's only way off its segment is THN. A topology with any other
	// path would let a forwarding test pass without forwarding.
	clientRoute := routeIn(t, top, ClientNamespace)
	if clientRoute.Destination != "default" || clientRoute.Via != GatewayIP {
		t.Errorf("client route is %+v, want a default route via %s", clientRoute, GatewayIP)
	}

	gatewayRoute := routeIn(t, top, GatewayNamespace)
	if gatewayRoute.Destination != "default" || gatewayRoute.Via != TargetIP {
		t.Errorf("gateway route is %+v, want a default route via %s", gatewayRoute, TargetIP)
	}
	if gatewayRoute.Device != wan.Name {
		t.Errorf("gateway default route leaves via %q, want the WAN interface %q",
			gatewayRoute.Device, wan.Name)
	}
}

// TestNoNamespaceHoldsOneInterfaceNameTwice is the regression test for the
// first real M6.3 live failure.
//
// The lab used to create each veth pair inside the gateway and move the peer
// out, so the peer name was a live interface in the gateway for the microseconds
// between creation and the move. That name was the same one the gateway's
// bridge already held, and the kernel refused the pair with:
//
//	RTNETLINK answers: File exists
//
// — an error naming neither of the two interfaces involved. This asserts the
// property that makes it impossible: within one namespace, one kernel
// interface name, one owner.
func TestNoNamespaceHoldsOneInterfaceNameTwice(t *testing.T) {
	// The declared topology must satisfy it.
	if err := Canonical().Validate(); err != nil {
		t.Fatalf("canonical topology violates name uniqueness: %v", err)
	}

	// And the check must actually reject a violation, rather than passing
	// everything it is handed.
	cases := []struct {
		name    string
		mutate  func(*Topology)
		wantSub string
	}{
		{
			name: "a veth port takes a bridge's name in the gateway",
			mutate: func(tp *Topology) {
				tp.Ports[0].Port = GatewayWANInterface
			},
			wantSub: "which interface thnwan0 already holds",
		},
		{
			name: "two interfaces share a name in one namespace",
			mutate: func(tp *Topology) {
				tp.Interfaces[0].Name = GatewayLANInterface
			},
			wantSub: "already holds",
		},
		{
			name: "a veth end is not a declared interface",
			mutate: func(tp *Topology) {
				tp.Ports[0].End = "thn-nosuch0"
			},
			wantSub: "not a declared interface",
		},
		{
			name: "a port is enslaved to something undeclared",
			mutate: func(tp *Topology) {
				tp.Ports[0].Master = "thn-nosuch0"
			},
			wantSub: "does not declare",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			top := Canonical()
			c.mutate(&top)

			err := top.Validate()
			if err == nil {
				t.Fatalf("Validate accepted an invalid topology: %+v", top.Interfaces)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("error = %q, want it to mention %q", err, c.wantSub)
			}
		})
	}
}

// TestVethPairsAreCreatedWhereTheirNameBelongs pins the ordering that fixes the
// collision, in terms the builder relies on.
//
// A peer name is a real interface from the moment the pair exists until it is
// moved away. So the pair must be created in the namespace that KEEPS one of
// its ends under its final name, and only the far end must be moved. Asserted
// here because the live suite discovered this by failing, and because the
// alternative formulation looks equally reasonable until it does not.
func TestVethPairsAreCreatedWhereTheirNameBelongs(t *testing.T) {
	top := Canonical()

	namespaces := map[string]map[string]string{} // namespace -> name -> owner
	for _, iface := range top.Interfaces {
		if namespaces[iface.Namespace] == nil {
			namespaces[iface.Namespace] = map[string]string{}
		}
		namespaces[iface.Namespace][iface.Name] = "interface"
	}

	for _, p := range top.Ports {
		// The end that stays must already be a declared interface here, so
		// creating the pair in this namespace cannot clobber it.
		if _, ok := namespaces[p.Namespace][p.End]; !ok {
			t.Errorf("port %s is created in %s, where %s is not declared; "+
				"it would be a new name in a namespace that may already have one",
				p.Port, p.Namespace, p.End)
		}

		// And the end that departs must be arriving at a name that is not
		// already taken there.
		if owner, taken := namespaces[p.PortNamespace][p.Port]; taken {
			t.Errorf("port %s arrives in %s where %s is already held by a %s; "+
				"RTNETLINK would answer File exists", p.Port, p.PortNamespace, p.Port, owner)
		}
		if p.PortNamespace == p.Namespace {
			t.Errorf("port %s is created and arrives in the same namespace %s, "+
				"so the transient name cannot be avoided by this layout", p.Port, p.Namespace)
		}
		if namespaces[p.PortNamespace] == nil {
			namespaces[p.PortNamespace] = map[string]string{}
		}
		namespaces[p.PortNamespace][p.Port] = "veth port"
	}
}

// TestLinkNamesIsExactlyWhatTheKernelMustHold checks the expectation the live
// harness asserts after building.
//
// A builder that only verifies the interfaces it addressed cannot see an
// interface it did not ask for — which is what a name collision produces — so
// the expected set is derived here and compared as a whole.
func TestLinkNamesIsExactlyWhatTheKernelMustHold(t *testing.T) {
	top := Canonical()

	cases := map[string][]string{
		// Loopback is the kernel's, not the topology's; the harness adds it
		// to the expectation itself.
		GatewayNamespace: {GatewayLANInterface, GatewayWANInterface,
			GatewayLANPort, GatewayWANPort, UnmanagedInterface},
		ClientNamespace: {ClientLANInterface},
		TargetNamespace: {TargetWANInterface},
	}

	for ns, want := range cases {
		sort.Strings(want)
		if got := top.LinkNames(ns); !slices.Equal(got, want) {
			t.Errorf("LinkNames(%s) = %v, want %v", ns, got, want)
		}
	}
}

// TestWANSideHasAReturnPathForTheLAN pins the route the isolation test depends
// on.
//
// The WAN-side target answers NATed traffic on its own connected segment, so it
// never needed a route to the LAN — until the isolation test asks it to open a
// connection into the LAN, which it must be able to complete when THN's firewall
// is NOT installed. Without a return path that connection is impossible for
// reasons that have nothing to do with the firewall, and the test's "reachable
// before, blocked after" assertion silently degrades into "unreachable both
// times, for the wrong reason".
func TestWANSideHasAReturnPathForTheLAN(t *testing.T) {
	top := Canonical()

	var found bool
	for _, r := range top.Routes {
		if r.Namespace != TargetNamespace {
			continue
		}
		found = true
		if r.Destination != LANPrefix {
			t.Errorf("WAN-side route is %+v, want a route for %s", r, LANPrefix)
		}
		if r.Via != GatewayWANIP {
			t.Errorf("WAN-side route next hop is %q, want the gateway's WAN address %s", r.Via, GatewayWANIP)
		}
	}
	if !found {
		t.Errorf("the WAN side has no route at all; it cannot reply to an untranslated LAN address")
	}
}

// TestGatewayAndClientShareTheLANBlock is the property the client's gateway
// address depends on: THN's LAN address and the client's address must be on
// the same segment, or the client cannot reach its own gateway.
func TestGatewayAndClientShareTheLANBlock(t *testing.T) {
	top := Canonical()

	lan, _ := top.GatewayLAN()
	client := interfaceIn(t, top, ClientNamespace)

	lanAddr := mustAddr(t, lan.Address)
	clientAddr := mustAddr(t, client.Address)

	if !LANNetwork().Contains(clientAddr) {
		t.Errorf("client address %s is outside the declared LAN block %s", clientAddr, LANNetwork())
	}
	if !LANNetwork().Contains(lanAddr) {
		t.Errorf("gateway address %s is outside the declared LAN block %s", lanAddr, LANNetwork())
	}
	if lanAddr == clientAddr {
		t.Fatalf("gateway and client share address %s", lanAddr)
	}

	// And neither is on the WAN side, so "the packet left the LAN" is visible
	// in the addresses rather than inferred from a router.
	for _, addr := range []netip.Addr{lanAddr, clientAddr} {
		if WANNetwork().Contains(addr) {
			t.Errorf("%s is inside the WAN block %s", addr, WANNetwork())
		}
	}
}

// TestLabUsesNonPhysicalInterfaceNames guards against the tests accidentally
// agreeing with a hardcoded eth0/eth1 special case.
//
// If the lab were built on eth0 and eth1, every test here would still pass if
// THN had grown code that treated those two names as the gateway.
func TestLabUsesNonPhysicalInterfaceNames(t *testing.T) {
	forbidden := map[string]bool{"eth0": true, "eth1": true, "eth2": true}

	top := Canonical()
	for _, iface := range top.Interfaces {
		if forbidden[iface.Name] {
			t.Errorf("lab interface %s uses a conventional physical name; "+
				"tests would pass even if THN special-cased it", iface.Name)
		}
	}
}

// TestCanonicalTopologyNamespacesAreDistinct keeps cleanup deterministic: two
// endpoints sharing a namespace would make teardown order ambiguous.
func TestCanonicalTopologyNamespacesAreDistinct(t *testing.T) {
	names := Canonical().Namespaces()
	if len(names) != 3 {
		t.Fatalf("topology uses %d namespaces (%v), want 3", len(names), names)
	}

	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("Namespaces() is not sorted and deduplicated: %v", names)
		}
	}
}

// TestTargetEndpointIsOnTheWANSide stops a copy-and-paste error turning the
// target into something the client can reach without THN.
func TestTargetEndpointIsOnTheWANSide(t *testing.T) {
	endpoint := TargetEndpoint()
	if !strings.HasPrefix(endpoint, TargetIP+":") {
		t.Errorf("target endpoint is %q, want it to be %s on some port", endpoint, TargetIP)
	}
	if LANNetwork().Contains(netip.MustParseAddr(TargetIP)) {
		t.Errorf("the WAN-side target %s is inside the LAN block %s", TargetIP, LANNetwork())
	}
}

func interfaceIn(t *testing.T, top Topology, namespace string) Interface {
	t.Helper()

	for _, i := range top.Interfaces {
		if i.Namespace == namespace {
			return i
		}
	}
	t.Fatalf("topology declares no interface in namespace %s", namespace)
	return Interface{}
}

func routeIn(t *testing.T, top Topology, namespace string) Route {
	t.Helper()

	for _, r := range top.Routes {
		if r.Namespace == namespace {
			return r
		}
	}
	t.Fatalf("topology declares no route in namespace %s", namespace)
	return Route{}
}

func mustAddr(t *testing.T, cidr string) netip.Addr {
	t.Helper()

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("parsing %q: %v", cidr, err)
	}
	return prefix.Addr()
}
