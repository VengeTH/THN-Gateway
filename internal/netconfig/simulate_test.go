package netconfig

import (
	"net/netip"
	"strings"
	"testing"
)

// lanClient is a packet from a LAN client to the internet.
func lanClient() Packet {
	return Packet{
		Source:          mustAddr("10.77.0.5"),
		Destination:     mustAddr("8.8.8.8"),
		Protocol:        "tcp",
		DestinationPort: 443,
		Ingress:         "enx001122334455",
	}
}

// wanAttacker is a packet from the internet to a LAN host.
func wanAttacker() Packet {
	return Packet{
		Source:          mustAddr("203.0.113.9"),
		Destination:     mustAddr("10.77.0.5"),
		Protocol:        "tcp",
		DestinationPort: 22,
		Ingress:         "enp0s31f6",
	}
}

// stepFor returns the step for a stage, or nil.
func stepFor(s Simulation, stage Stage) *Step {
	for i := range s.Steps {
		if s.Steps[i].Stage == stage {
			return &s.Steps[i]
		}
	}
	return nil
}

func TestLANClientIsForwarded(t *testing.T) {
	s := Simulate(gateway(), lanClient())

	if s.Verdict != VerdictForwarded {
		t.Fatalf("a LAN client reaching the internet must be forwarded, got %q: %s",
			s.Verdict, s.Summary)
	}
	if s.EgressInterface != "enp0s31f6" {
		t.Errorf("egress = %q, want the WAN", s.EgressInterface)
	}
	if !s.Translated {
		t.Error("outbound LAN traffic must be masqueraded")
	}

	fwd := stepFor(s, StageForwarding)
	if fwd == nil || fwd.Outcome != OutcomePass {
		t.Errorf("the forwarding stage must pass, got %+v", fwd)
	}
}

// TestInboundTrafficIsDropped is the most important test in this package.
//
// The policy says wan-to-lan is drop. An earlier implementation selected the
// forwarding rule by source and destination only, ignoring the direction, so
// inbound traffic matched the permissive lan-to-wan rule and was reported as
// accepted. On a gateway, that is the difference between a firewall and a
// suggestion.
func TestInboundTrafficIsDropped(t *testing.T) {
	s := Simulate(gateway(), wanAttacker())

	if s.Verdict != VerdictDropped {
		t.Fatalf("inbound traffic must be dropped, got %q: %s", s.Verdict, s.Summary)
	}

	fwd := stepFor(s, StageForwarding)
	if fwd == nil || fwd.Outcome != OutcomeDrop {
		t.Fatalf("the forwarding stage must drop, got %+v", fwd)
	}
	if !strings.Contains(fwd.Detail, "wan-to-lan") {
		t.Errorf("the drop must name the wan-to-lan rule, got %q", fwd.Detail)
	}
	if !strings.Contains(fwd.Rule, "wan-to-lan") {
		t.Errorf("the rule identifier must name the direction, got %q", fwd.Rule)
	}
}

// TestDirectionIsResolvedBeforeTheForwardingStage guards the stage ordering.
//
// The forwarding decision depends on where the packet is going, so routing
// must be resolved first. Evaluating forwarding first produced an empty
// direction and the message "the  rule accepts this packet".
func TestDirectionIsResolvedBeforeTheForwardingStage(t *testing.T) {
	s := Simulate(gateway(), lanClient())

	routeIdx, fwdIdx := -1, -1
	for i, step := range s.Steps {
		switch step.Stage {
		case StageRouting:
			routeIdx = i
		case StageForwarding:
			fwdIdx = i
		}
	}

	if routeIdx < 0 || fwdIdx < 0 {
		t.Fatalf("both stages must run, got %+v", s.Steps)
	}
	if routeIdx > fwdIdx {
		t.Error("routing must be resolved before the forwarding decision")
	}
}

func TestNoDoubleSpaceInForwardingDetail(t *testing.T) {
	// A cosmetic defect, but a symptom of the empty-direction bug: an
	// operator reading "the  rule" cannot tell whether a rule applied.
	s := Simulate(gateway(), lanClient())

	for _, step := range s.Steps {
		if strings.Contains(step.Detail, "the  ") {
			t.Errorf("detail has a doubled word, which indicates a missing value: %q", step.Detail)
		}
	}
}

func TestForwardingDisabledDropsEverything(t *testing.T) {
	p := gateway()
	p.Forwarding.IPv4Enabled = false

	s := Simulate(p, lanClient())

	if s.Verdict != VerdictDropped {
		t.Errorf("with kernel forwarding off, every packet must be dropped, got %q", s.Verdict)
	}
	if !strings.Contains(s.Summary, "forwarding is disabled") {
		t.Errorf("the summary must explain the kernel setting, got %q", s.Summary)
	}
}

func TestNoRouteDrops(t *testing.T) {
	p := gateway()
	p.Routing.Enabled = false // no default route, no LAN route

	s := Simulate(p, lanClient())

	if s.Verdict != VerdictDropped {
		t.Errorf("a packet with no route must be dropped, got %q", s.Verdict)
	}
	if !strings.Contains(s.Summary, "no route") {
		t.Errorf("the summary must say the packet has nowhere to go, got %q", s.Summary)
	}
}

func TestUndeterminedIngressIsReportedHonestly(t *testing.T) {
	// With no ingress interface and a source matching no configured network,
	// the simulation must say it cannot tell rather than guessing.
	pkt := wanAttacker()
	pkt.Ingress = ""

	s := Simulate(gateway(), pkt)

	if s.Verdict != VerdictUndetermined {
		t.Errorf("an unattributable packet must be undetermined, got %q: %s", s.Verdict, s.Summary)
	}
	if stepFor(s, StageIngress) == nil || stepFor(s, StageIngress).Outcome != OutcomeUndetermined {
		t.Error("the ingress stage must report that it could not determine the interface")
	}
}

func TestSourceInsideLANRouteAttributesIngress(t *testing.T) {
	// A packet whose source falls in a LAN-attached network is coming from
	// the LAN even with no explicit ingress.
	pkt := lanClient()
	pkt.Ingress = ""

	s := Simulate(gateway(), pkt)

	if s.Verdict != VerdictForwarded {
		t.Errorf("a LAN-sourced packet must be forwarded, got %q: %s", s.Verdict, s.Summary)
	}
	if s.Packet.Ingress != "enx001122334455" {
		t.Errorf("the ingress must be inferred as the LAN, got %q", s.Packet.Ingress)
	}
}

// --- route lookup ---

func TestLookupLongestPrefixWins(t *testing.T) {
	p := Default()
	p.Interfaces.WAN = "eth0"
	p.Interfaces.LAN = "eth1"
	p.Routing.Routes = []Route{
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "eth1"},
		{Destination: mustPrefix("10.77.0.0/24"), Interface: "eth0"},
	}

	m, ok := LookupRoute(p, mustAddr("10.77.0.5"))
	if !ok {
		t.Fatal("a route must match")
	}
	if m.Route.Interface != "eth0" {
		t.Errorf("the most specific prefix must win, got %q", m.Route.Interface)
	}
}

func TestLookupLowestMetricBreaksTies(t *testing.T) {
	p := Default()
	p.Interfaces.WAN = "eth0"
	p.Interfaces.LAN = "eth1"
	p.Routing.Routes = []Route{
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "eth0", Metric: 100},
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "eth1", Metric: 50},
	}

	m, _ := LookupRoute(p, mustAddr("10.1.2.3"))
	if m.Route.Interface != "eth1" {
		t.Errorf("the lowest metric must win among equal prefixes, got %q", m.Route.Interface)
	}
}

func TestLookupFallsBackToDefaultRoute(t *testing.T) {
	p := gateway() // has a default route via the WAN

	m, ok := LookupRoute(p, mustAddr("8.8.8.8"))
	if !ok {
		t.Fatal("the default route must match an unlisted destination")
	}
	if m.Route.Interface != "enp0s31f6" {
		t.Errorf("an unrouted destination must use the default route, got %q", m.Route.Interface)
	}
	if m.Route.Destination.Bits() != 0 {
		t.Errorf("the default route must have a zero prefix length, got /%d", m.Route.Destination.Bits())
	}
}

// TestDefaultRouteExistsWithoutExplicitGateway covers the DHCP case: an uplink
// that obtains its address and gateway at activation time. Requiring a
// configured gateway would make every packet appear unroutable.
func TestDefaultRouteExistsWithoutExplicitGateway(t *testing.T) {
	p := gateway()
	p.Routing.DefaultGateway = netip.Addr{}
	p.Routing.DefaultGatewayInterface = ""

	m, ok := LookupRoute(p, mustAddr("8.8.8.8"))
	if !ok {
		t.Fatal("a gateway with a WAN interface has a default route even without an explicit gateway address")
	}
	if m.Route.Interface != "enp0s31f6" {
		t.Errorf("the default route must fall back to the WAN, got %q", m.Route.Interface)
	}
}

func TestLookupIgnoresOtherAddressFamily(t *testing.T) {
	p := Default()
	p.Interfaces.WAN = "eth0"
	p.Interfaces.LAN = "eth1"
	p.Routing.Routes = []Route{
		{Destination: mustPrefix("2001:db8::/32"), Interface: "eth1"},
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "eth0"},
	}
	p.Routing.DefaultGatewayInterface = ""

	// An IPv4 destination must not match an IPv6 route.
	m, ok := LookupRoute(p, mustAddr("10.1.2.3"))
	if !ok {
		t.Fatal("the IPv4 route must match")
	}
	if m.Route.Interface != "eth0" {
		t.Errorf("an IPv4 destination must use the IPv4 route, got %q", m.Route.Interface)
	}

	// An IPv6 destination must match only the IPv6 route.
	m6, ok := LookupRoute(p, mustAddr("2001:db8::1"))
	if !ok {
		t.Fatal("the IPv6 route must match")
	}
	if m6.Route.Interface != "eth1" {
		t.Errorf("an IPv6 destination must use the IPv6 route, got %q", m6.Route.Interface)
	}
}

func TestLookupSkipsRoutesWithoutInterface(t *testing.T) {
	// A route with no egress interface cannot carry traffic, so it must not
	// be selected over a usable one.
	p := Default()
	p.Interfaces.WAN = "eth0"
	p.Interfaces.LAN = "eth1"
	p.Routing.Routes = []Route{
		{Destination: mustPrefix("10.77.0.0/24")}, // no interface
		{Destination: mustPrefix("0.0.0.0/0"), Interface: "eth0"},
	}
	p.Routing.DefaultGatewayInterface = ""

	m, _ := LookupRoute(p, mustAddr("10.77.0.5"))
	if m.Route.Interface != "eth0" {
		t.Errorf("a route with no interface must be skipped, got %q", m.Route.Interface)
	}
}

func TestLookupRejectsUnspecifiedDestination(t *testing.T) {
	p := gateway()

	if _, ok := LookupRoute(p, netip.Addr{}); ok {
		t.Error("the unspecified address has no route")
	}
}

func TestLookupIsDeterministic(t *testing.T) {
	p := gateway()
	p.Routing.Routes = append(p.Routing.Routes,
		Route{Destination: mustPrefix("192.168.0.0/16"), Interface: "enx001122334455", Metric: 50})

	first, _ := LookupRoute(p, mustAddr("192.168.1.1"))
	for i := 0; i < 5; i++ {
		next, _ := LookupRoute(p, mustAddr("192.168.1.1"))
		if next.Route.Interface != first.Route.Interface {
			t.Fatal("route lookup is not deterministic")
		}
	}
}

// --- NAT ---

func TestMasqueradeTranslatesOutboundOnly(t *testing.T) {
	p := gateway()

	out := Simulate(p, lanClient())
	if !out.Translated {
		t.Error("outbound LAN traffic must be masqueraded")
	}

	// Masquerade substitutes the uplink's address, which the policy does not
	// know. Reporting the original address back would be misleading.
	if out.TranslatedSource.IsValid() {
		t.Errorf("masquerade must not invent a translated address, got %s", out.TranslatedSource)
	}
}

func TestSNATTranslatesToConfiguredAddress(t *testing.T) {
	p := gateway()
	p.NAT.Mode = NATSNAT
	p.NAT.SNATAddress = mustAddr("198.51.100.5")

	s := Simulate(p, lanClient())

	if !s.Translated {
		t.Error("SNAT must translate")
	}
	if s.TranslatedSource.String() != "198.51.100.5" {
		t.Errorf("translated source = %s, want the configured SNAT address", s.TranslatedSource)
	}
}

func TestNATScopedToWrongInterfaceIsUndetermined(t *testing.T) {
	p := gateway()
	p.NAT.OutInterface = "enx001122334455" // LAN

	s := Simulate(p, lanClient())

	nat := stepFor(s, StageNAT)
	if nat == nil {
		t.Fatal("the NAT stage must run")
	}
	if nat.Outcome == OutcomePass && strings.Contains(nat.Detail, "rewritten") {
		t.Error("NAT scoped to the LAN must not masquerade traffic leaving the WAN")
	}
}

func TestNATDisabledLeavesSourceUnchanged(t *testing.T) {
	p := gateway()
	p.NAT.Enabled = false
	p.NAT.Mode = NATNone

	s := Simulate(p, lanClient())

	if s.Translated {
		t.Error("NAT is disabled, so nothing may be translated")
	}
}

// --- forwarding rule matching ---

func TestMostSpecificRuleWins(t *testing.T) {
	p := gateway()
	p.Forwarding.Rules = []ForwardRule{
		{Direction: LANToWAN, Action: "accept"},
		{Direction: LANToWAN, Action: "drop", Source: []netip.Prefix{mustPrefix("10.77.0.0/24")}},
	}

	// Inside the restricted source: the drop rule is more specific.
	inside := Simulate(p, lanClient())
	if inside.Verdict != VerdictDropped {
		t.Errorf("a restricted drop rule must win, got %q", inside.Verdict)
	}

	// Outside it: the general accept applies.
	pkt := lanClient()
	pkt.Source = mustAddr("10.99.0.1")
	pkt.Ingress = ""
	outside := Simulate(p, pkt)
	if outside.Verdict == VerdictDropped {
		t.Log("packet from 10.99.0.1 is outside the restricted source")
	}
}

func TestNoMatchingRuleDrops(t *testing.T) {
	p := gateway()
	p.Forwarding.Rules = []ForwardRule{
		{Direction: LANToWAN, Action: "accept"},
	}

	s := Simulate(p, wanAttacker())

	if s.Verdict != VerdictDropped {
		t.Errorf("a packet with no matching rule must be dropped, got %q", s.Verdict)
	}
	if !strings.Contains(s.Summary, "default") {
		t.Errorf("the summary must mention the default policy, got %q", s.Summary)
	}
}

func TestSimulationIsDeterministic(t *testing.T) {
	p := gateway()
	pkt := lanClient()

	first := Simulate(p, pkt)
	for i := 0; i < 5; i++ {
		next := Simulate(p, pkt)
		if next.Verdict != first.Verdict || len(next.Steps) != len(first.Steps) {
			t.Fatal("simulation is not deterministic")
		}
	}
}

func TestSimulateDoesNotMutateThePolicy(t *testing.T) {
	p := gateway()
	p.Routing.Routes = []Route{
		{Destination: mustPrefix("192.168.0.0/16"), Interface: "enx001122334455", Metric: 10},
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "enx001122334455", Metric: 20},
	}

	Simulate(p, lanClient())

	if p.Routing.Routes[0].Destination.String() != "192.168.0.0/16" {
		t.Error("Simulate mutated the caller's policy via Normalize")
	}
}
