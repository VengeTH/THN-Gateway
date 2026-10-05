package lab

// These assertions run on every platform, including the Windows workstation
// where the lab is typed. The live packet tests are behind //go:build linux;
// the address plan they depend on is checked here so a mistake in it is caught
// where it was made rather than three in the morning in a lab VM.

import (
	"net/netip"
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
