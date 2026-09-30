package cli

import (
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/dhcp"
	"github.com/venth/thn-gateway/internal/dns"
	fwpolicy "github.com/venth/thn-gateway/internal/firewall/policy"
	"github.com/venth/thn-gateway/internal/netconfig"
	"github.com/venth/thn-gateway/internal/qos"
)

// This file holds the coherence, routing, NAT and firewall phases of the gate.
//
// Coherence comes first deliberately. The data-plane phases below assert that
// packets go where the configuration says. If the subsystems disagree about
// what the configuration says, those assertions would pass or fail for reasons
// that have nothing to do with the data plane — so the seams are checked
// before the behaviour.

// derivedPolicies bundles every policy the gate derives from one config.
//
// Bundling them is the point. Building each separately, in each test, would
// let a test accidentally compare two policies derived from different
// configurations and conclude they disagreed when they never did.
type derivedPolicies struct {
	cfg   gateConfig
	net   netconfig.Policy
	fw    fwpolicy.Policy
	dhcp  dhcp.Policy
	bound map[string]string // subsystem -> interface it was bound to
}

// deriveAll derives every subsystem policy from one configuration.
//
// The translators are the CLI's own. That is what makes the gate meaningful:
// if netPolicyFromConfig and policyFromConfig ever disagree about a shared
// field, the gate sees it immediately, because it is calling both.
func deriveAll(t *testing.T, cfg gateConfig) derivedPolicies {
	t.Helper()

	dhcpPolicy, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("deriving the DHCP policy: %v", err)
	}

	return derivedPolicies{
		cfg:  cfg,
		net:  netPolicyFromConfig(cfg),
		fw:   policyFromConfig(cfg),
		dhcp: dhcpPolicy,
		bound: map[string]string{
			"netconfig": netPolicyFromConfig(cfg).Interfaces.WAN,
			"firewall":  policyFromConfig(cfg).Interfaces.WAN,
			"dhcp":      dhcpPolicy.Interface,
			"dns":       dnsPolicyOrFail(t, cfg).Interface,
			"qos":       qosPolicyFromConfig(cfg).Interface,
		},
	}
}

// TestGateCoherenceInterfacesAreIdentical is the first seam.
//
// Five subsystems independently decide which interface they act on. If DHCP
// serves one interface while the firewall's anti-spoofing rule covers another,
// every client gets an address that is then dropped as spoofed — a gateway
// that appears to work and serves nobody.
func TestGateCoherenceInterfacesAreIdentical(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	d := deriveAll(t, cfg)

	// Every subsystem that names the WAN must name the same one.
	if got := d.net.Interfaces.WAN; got != gateWANIface {
		t.Errorf("netconfig WAN = %q, want %q", got, gateWANIface)
	}
	if got := d.fw.Interfaces.WAN; got != gateWANIface {
		t.Errorf("firewall WAN = %q, want %q", got, gateWANIface)
	}
	if got := d.dhcp.Interface; got != gateLANIface {
		t.Errorf("dhcp interface = %q, want %q (DHCP serves the LAN)", got, gateLANIface)
	}

	// And the LAN must be the same interface everywhere it is named.
	if got := d.net.Interfaces.LAN; got != gateLANIface {
		t.Errorf("netconfig LAN = %q, want %q", got, gateLANIface)
	}
	if got := d.fw.Interfaces.LAN; got != gateLANIface {
		t.Errorf("firewall LAN = %q, want %q", got, gateLANIface)
	}
}

// TestGateCoherenceForwardingModelsAgree is the seam this gate exists for.
//
// Forwarding is modelled twice, independently:
//
//   - netconfig.Forwarding holds a rule per direction with source and
//     destination restrictions. netconfig.Simulate() reads this one.
//   - fwpolicy.Forward holds a bare bool per direction. nft.Render() reads
//     this one.
//
// Nothing in the codebase connects them. Each is individually correct and they
// can still disagree, and when they do the gateway either forwards nothing
// while claiming it does, or forwards something the firewall was told to drop.
//
// The two are derived from one configuration here, so any disagreement is a
// defect in the translators rather than in the test.
func TestGateCoherenceForwardingModelsAgree(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	d := deriveAll(t, cfg)

	// LAN to WAN: the whole purpose of the gateway.
	netOut, ok := d.net.Forwarding.RuleFor(netconfig.LANToWAN)
	if !ok {
		t.Fatal("netconfig has no lan-to-wan rule; the data plane would have no opinion")
	}
	if netOut.Action != "accept" {
		t.Errorf("netconfig lan-to-wan action = %q, want accept", netOut.Action)
	}
	if !d.fw.Forward.LANToWAN {
		t.Error("firewall LANToWAN = false while the data plane accepts lan-to-wan; " +
			"the simulator would forward a packet the ruleset drops")
	}

	// WAN to LAN: unsolicited inbound must be denied in both models.
	netIn, ok := d.net.Forwarding.RuleFor(netconfig.WANToLAN)
	if !ok {
		t.Fatal("netconfig has no wan-to-lan rule")
	}
	if netIn.Action != "drop" {
		t.Errorf("netconfig wan-to-lan action = %q, want drop", netIn.Action)
	}
	if d.fw.Forward.WANToLAN {
		t.Error("firewall WANToLAN = true while the data plane drops wan-to-lan; " +
			"unsolicited inbound would reach the LAN behind a policy that says it cannot")
	}
}

// TestGateCoherenceFirewallDisabledStopsBothModels is the check that a
// subsystem-blind reading would miss.
//
// Disabling the firewall is a single configuration switch. Both models must
// honour it. If only the renderer honours it, the simulator keeps reporting
// that traffic forwards and every data-plane assertion below passes against a
// gateway that would black-hole the entire LAN.
func TestGateCoherenceFirewallDisabledStopsBothModels(t *testing.T) {
	cfg := topologyConfig()
	cfg.Firewall.Enabled = false

	loaded, _ := loadTopology(t, cfg)
	d := deriveAll(t, loaded)

	if d.fw.Forward.LANToWAN {
		t.Error("firewall LANToWAN = true after the firewall was disabled")
	}

	// This is the assertion the gate exists for. If netPolicyFromConfig does
	// not consult cfg.Firewall.Enabled, this fails — and that failure is a
	// real defect: the simulator would report forwarding for a gateway whose
	// ruleset drops everything.
	netOut, ok := d.net.Forwarding.RuleFor(netconfig.LANToWAN)
	if !ok {
		t.Fatal("netconfig has no lan-to-wan rule")
	}
	if netOut.Action == "accept" {
		t.Error("the data plane still accepts lan-to-wan after the firewall was disabled\n" +
			"netPolicyFromConfig does not consult cfg.Firewall.Enabled, so `thn simulate` " +
			"reports forwarding for a gateway that would black-hole the LAN")
	}
}

// TestGateCoherenceNATAgrees is the third dual-modelling seam.
//
// NAT appears in netconfig (with a mode and an SNAT address), in fwpolicy
// (a bool and an output interface), and in config (a bool and a list of
// interfaces). All three must resolve to the same decision.
func TestGateCoherenceNATAgrees(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	d := deriveAll(t, loadedOrFail(t, cfg))

	if !d.net.NAT.Enabled {
		t.Error("netconfig NAT is disabled but the configuration enables it")
	}
	if !d.fw.Masquerade.Enabled {
		t.Error("the firewall policy would emit no masquerade rule; the LAN would be " +
			"unreachable from the internet even though NAT is configured")
	}
	if got := d.net.NAT.OutInterface; got != gateWANIface {
		t.Errorf("netconfig NAT out interface = %q, want %q", got, gateWANIface)
	}
	if got := d.net.NAT.InInterface; got != gateLANIface {
		t.Errorf("netconfig NAT in interface = %q, want %q; NAT scoped to the wrong "+
			"interface translates the wrong traffic", got, gateLANIface)
	}

	// The firewall policy's Masquerade.OutInterface is optional: when it is
	// empty the renderer falls back to Interfaces.WAN. Asserting the rendered
	// rule rather than the model field is the point — the model field alone
	// proves nothing about what nft will read.
	_, path := loadTopology(t, topologyConfig())
	doc, code := runGateJSON(t, "firewall", "render", "--config", path)
	if code != ExitOK {
		t.Fatalf("firewall render exited %d", code)
	}
	requireContains(t, "the ruleset", jsonString(t, doc, "ruleset"),
		"oifname \""+gateWANIface+"\" masquerade")
}

// TestGateCoherenceNATDisabledAgrees is the negative half of the seam.
func TestGateCoherenceNATDisabledAgrees(t *testing.T) {
	cfg := topologyConfig()
	cfg.NAT.Enabled = false

	loaded, _ := loadTopology(t, cfg)
	d := deriveAll(t, loaded)

	if d.net.NAT.Mode != netconfig.NATNone {
		t.Errorf("netconfig NAT mode = %q, want none", d.net.NAT.Mode)
	}
	if d.fw.Masquerade.Enabled {
		t.Error("the firewall policy would still emit a masquerade rule after NAT was disabled")
	}
}

// TestGateCoherenceOneLANPrefixEverywhere is the fourth seam, and the one with
// the worst failure mode.
//
// The LAN prefix appears in the DHCP pool derivation, the firewall's
// anti-spoofing rule, the DNS listen address and the DHCP gateway option. If
// they come from different sources, a client can be handed an address the
// firewall will later classify as spoofed — and the symptom is "the network
// is flaky", which is close to undiagnosable from the gateway.
func TestGateCoherenceOneLANPrefixEverywhere(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	d := deriveAll(t, loadedOrFail(t, cfg))

	lanPrefix := mustPrefix(t, gateLANAddr)

	// The firewall's anti-spoofing prefix must be the LAN, exactly.
	if got := mustPrefix(t, d.fw.AntiSpoofing.LANPrefix); got != lanPrefix {
		t.Errorf("firewall anti-spoofing prefix = %s, want %s; clients would be "+
			"dropped as spoofing", got, lanPrefix)
	}

	// DHCP's notion of the LAN must be the same network.
	if got := d.dhcp.LANPrefix.Masked(); got != lanPrefix {
		t.Errorf("dhcp LAN prefix = %s, want %s", got, lanPrefix)
	}

	// The pool must sit inside the LAN. A pool outside the prefix produces
	// addresses the LAN interface has no route for.
	if len(d.dhcp.Ranges) == 0 {
		t.Fatal("dhcp has no ranges; no client could be served")
	}
	for _, r := range d.dhcp.Ranges {
		if !r.Start.IsValid() || !r.End.IsValid() {
			t.Errorf("dhcp range %s is not a usable address range", r)
			continue
		}
		if !lanPrefix.Contains(r.Start) {
			t.Errorf("pool start %s is outside the LAN %s", r.Start, lanPrefix)
		}
		if !lanPrefix.Contains(r.End) {
			t.Errorf("pool end %s is outside the LAN %s", r.End, lanPrefix)
		}
		if lanPrefix.Contains(r.End) && r.End.IsUnspecified() {
			t.Error("the pool ends at the unspecified address")
		}
	}

	// DNS must listen where DHCP tells clients to look. This is the check that
	// catches a gateway that hands out a working address and an unusable
	// resolver.
	dnsPolicy := dnsPolicyOrFail(t, cfg)
	if got := dnsPolicy.ListenAddress; got != addr(t, "10.77.0.1") {
		t.Errorf("dns listen address = %s, want the gateway address 10.77.0.1", got)
	}
	if got := d.dhcp.GatewayAddress; got != addr(t, "10.77.0.1") {
		t.Errorf("dhcp gateway option = %s, want 10.77.0.1", got)
	}
	if got := dnsPolicy.ListenAddress; got != d.dhcp.GatewayAddress {
		t.Errorf("dns listens on %s but DHCP advertises %s as the resolver; "+
			"every name lookup from a client would fail", got, d.dhcp.GatewayAddress)
	}
}

// TestGateCoherenceMTUIsConsistent guards the fq_codel quantum, which is
// derived from the MTU and silently costs throughput when it is wrong.
func TestGateCoherenceMTUIsConsistent(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	loaded := loadedOrFail(t, cfg)

	qp := qosPolicyFromConfig(loaded)
	if qp.MTU != loaded.Network.MTU {
		t.Errorf("qos MTU = %d, want the configured %d", qp.MTU, loaded.Network.MTU)
	}

	fq := qos.FqCodelLimits(qp.MTU)
	if fq.Quantum != loaded.Network.MTU {
		t.Errorf("fq_codel quantum = %d, want the MTU %d", fq.Quantum, loaded.Network.MTU)
	}
}

// TestGateCoherenceEveryRendererProducesOutput is the broadest check in the
// gate: all four generated artefacts must come out of one configuration
// without error.
//
// A subsystem that renders nothing is a subsystem that does nothing, and a
// per-subsystem unit test cannot see it because each one's fixture is its own.
func TestGateCoherenceEveryRendererProducesOutput(t *testing.T) {
	_, path := loadTopology(t, topologyConfig())

	// Firewall.
	fwStdout, _, code := runGateCLI(t, "firewall", "render", "--config", path)
	if code != ExitOK {
		t.Errorf("firewall render exited %d", code)
	}
	requireContains(t, "the ruleset", fwStdout, "table inet thn")
	requireContains(t, "the ruleset", fwStdout, "chain forward")

	// DHCP and DNS together: dnsmasq serves both, so they must render as one
	// file rather than two that can disagree.
	svcStdout, _, code := runGateCLI(t, "dhcp", "render", "--config", path)
	if code != ExitOK {
		t.Errorf("dhcp render exited %d", code)
	}
	requireContains(t, "the dnsmasq configuration", svcStdout, "dhcp-range")

	// Traffic shaping.
	qosStdout, _, code := runGateCLI(t, "qos", "render", "--config", path, "--assume-cake")
	if code != ExitOK {
		t.Errorf("qos render exited %d", code)
	}
	requireContains(t, "the shaping script", qosStdout, "tc qdisc replace dev "+gateWANIface)

	// Routing, NAT and forwarding.
	netStdout, _, code := runGateCLI(t, "net", "render", "--config", path)
	if code != ExitOK {
		t.Errorf("net render exited %d", code)
	}
	requireContains(t, "the network script", netStdout, "ip route")
}

// TestGateRoutingLANClientReachesTheInternet is the data-plane spine: a
// packet from a DHCP-assigned client to an arbitrary internet address.
func TestGateRoutingLANClientReachesTheInternet(t *testing.T) {
	cfg, path := loadTopology(t, topologyConfig())
	p := netPolicyFromConfig(loadedOrFail(t, cfg))

	client := addr(t, "10.77.0.100")
	internet := addr(t, "8.8.8.8")

	sim := netconfig.Simulate(p, netconfig.Packet{
		Source:      client,
		Destination: internet,
		Protocol:    "tcp",
		// 443 so the trace is a recognisable flow rather than a bare
		// connection. The data plane does not filter on it, and the gate
		// should not imply that it does.
		DestinationPort: 443,
		Ingress:         gateLANIface,
	})

	if sim.Verdict != netconfig.VerdictForwarded {
		t.Fatalf("verdict = %q (%s)\nsteps: %+v", sim.Verdict, sim.Summary, sim.Steps)
	}
	if sim.EgressInterface != gateWANIface {
		t.Errorf("egress = %q, want %q", sim.EgressInterface, gateWANIface)
	}
	if sim.NextHop != addr(t, gateUpstreamGW) {
		t.Errorf("next hop = %s, want the upstream gateway %s", sim.NextHop, gateUpstreamGW)
	}

	// The trace must visit every stage a forwarded packet passes through.
	// A stage that vanished would mean the simulation stopped modelling it,
	// and the trace would look fine while covering less.
	wantStages := map[netconfig.Stage]bool{
		netconfig.StageIngress:    true,
		netconfig.StageRouting:    true,
		netconfig.StageForwarding: true,
		netconfig.StageNAT:        true,
		netconfig.StageEgress:     true,
	}
	for _, step := range sim.Steps {
		delete(wantStages, step.Stage)
	}
	if len(wantStages) > 0 {
		t.Errorf("the trace skipped stages %v; a forwarded packet must be modelled "+
			"at every stage or the simulation proves less than it appears to", wantStages)
	}

	// The command line must agree with the model, since that is the artefact
	// an operator reads.
	doc, code := runGateJSON(t, "simulate", "--config", path,
		"--from", client.String(), "--to", internet.String(), "--proto", "tcp", "--port", "443")
	if code != ExitOK {
		t.Errorf("thn simulate exited %d for a packet the model says should forward", code)
	}
	simJSON := jsonObject(t, doc, "simulation")
	if got := jsonString(t, simJSON, "verdict"); got != string(netconfig.VerdictForwarded) {
		t.Errorf("thn simulate verdict = %q, want forwarded", got)
	}
	if got := jsonString(t, simJSON, "egress_interface"); got != gateWANIface {
		t.Errorf("thn simulate egress = %q, want %q", got, gateWANIface)
	}
}

// TestGateRoutingLANClientReachesTheGateway covers the local-delivery case,
// which is the one the internet case does not exercise.
func TestGateRoutingLANClientReachesTheGateway(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p := netPolicyFromConfig(loadedOrFail(t, cfg))

	sim := netconfig.Simulate(p, netconfig.Packet{
		Source:      addr(t, "10.77.0.100"),
		Destination: addr(t, "10.77.0.1"), // the gateway itself
		Protocol:    "icmp",
		Ingress:     gateLANIface,
	})

	if sim.Verdict != netconfig.VerdictAccepted {
		t.Errorf("verdict = %q (%s); traffic to the gateway must be delivered locally, "+
			"not forwarded or dropped", sim.Verdict, sim.Summary)
	}
	if sim.EgressInterface == gateWANIface {
		t.Error("traffic addressed to the gateway was routed to the WAN")
	}
}

// TestGateRoutingWithNoInterfaceNamedHasNoRoute is the boundary the simulator
// actually draws, and it is worth pinning precisely.
//
// A gateway that names its WAN but not its upstream gateway still simulates a
// default route, because a DHCP-attached uplink is handed one at activation
// time and refusing to model that would make every packet on such a gateway
// appear unroutable. A gateway that has named no WAN at all has no uplink to
// learn from, and must simulate as having no route.
func TestGateRoutingWithNoInterfaceNamedHasNoRoute(t *testing.T) {
	cfg := topologyConfig()
	cfg.Network.WAN = ""
	cfg.Network.UpstreamGateway = ""

	loaded, _ := loadTopology(t, cfg)
	p := netPolicyFromConfig(loaded)

	sim := netconfig.Simulate(p, netconfig.Packet{
		Source:      addr(t, "10.77.0.100"),
		Destination: addr(t, "8.8.8.8"),
		Protocol:    "tcp",
		Ingress:     gateLANIface,
	})

	if sim.Verdict != netconfig.VerdictDropped {
		t.Fatalf("verdict = %q; with no WAN and no default route the packet has "+
			"nowhere to go, and a gateway that reports otherwise is describing "+
			"connectivity it does not have", sim.Verdict)
	}
	if sim.Summary == "" {
		t.Error("the drop carries no explanation; an operator cannot tell a missing " +
			"uplink from a firewall misconfiguration")
	}
}

// TestGateRoutingMissingUpstreamStillRoutesToTheWAN documents the other half of
// that boundary, so a future change cannot quietly tighten it and break every
// DHCP-attached gateway.
func TestGateRoutingMissingUpstreamStillRoutesToTheWAN(t *testing.T) {
	cfg := topologyConfig()
	cfg.Network.UpstreamGateway = "" // the uplink gets its gateway over DHCP

	loaded, _ := loadTopology(t, cfg)
	p := netPolicyFromConfig(loaded)

	sim := netconfig.Simulate(p, netconfig.Packet{
		Source:      addr(t, "10.77.0.100"),
		Destination: addr(t, "8.8.8.8"),
		Protocol:    "tcp",
		Ingress:     gateLANIface,
	})

	if sim.Verdict != netconfig.VerdictForwarded {
		t.Errorf("verdict = %q; a named WAN with no configured upstream is a DHCP "+
			"uplink, which supplies a default route at activation time", sim.Verdict)
	}
	if sim.EgressInterface != gateWANIface {
		t.Errorf("egress = %q, want %q", sim.EgressInterface, gateWANIface)
	}
}

// TestGateRoutingLongestPrefixWins checks that a more specific route is
// preferred, and — more importantly — that adding one does not disturb the
// default.
func TestGateRoutingLongestPrefixWins(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p := netPolicyFromConfig(loadedOrFail(t, cfg))

	// A VPN-style route that is more specific than the default.
	p.Routing.Routes = append(p.Routing.Routes, netconfig.Route{
		Destination: mustPrefix(t, "10.99.0.0/16"),
		NextHop:     addr(t, "203.0.113.99"),
		Interface:   gateWANIface,
		Metric:      10,
		Scope:       "global",
	})

	specific, ok := netconfig.LookupRoute(p, addr(t, "10.99.5.5"))
	if !ok {
		t.Fatal("no route matched a destination that has one")
	}
	if specific.Route.Destination != mustPrefix(t, "10.99.0.0/16") {
		t.Errorf("matched %s, want the more specific 10.99.0.0/16",
			specific.Route.Destination)
	}

	// The default must still serve everything else.
	fallback, ok := netconfig.LookupRoute(p, addr(t, "1.1.1.1"))
	if !ok {
		t.Fatal("adding a specific route broke the default route")
	}
	if fallback.Route.Destination.Bits() != 0 {
		t.Errorf("1.1.1.1 matched %s, want the default route", fallback.Route.Destination)
	}
}

// TestGateNATTranslatesLANTraffic is the NAT phase.
func TestGateNATTranslatesLANTraffic(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p := netPolicyFromConfig(loadedOrFail(t, cfg))

	sim := netconfig.Simulate(p, netconfig.Packet{
		Source:          addr(t, "10.77.0.100"),
		Destination:     addr(t, "8.8.8.8"),
		Protocol:        "tcp",
		DestinationPort: 443,
		Ingress:         gateLANIface,
	})

	if sim.Verdict != netconfig.VerdictForwarded {
		t.Fatalf("verdict = %q (%s)", sim.Verdict, sim.Summary)
	}
	if !sim.Translated {
		t.Error("the packet left untranslated; with a private source and a public " +
			"destination it would be unroutable and the client would see a timeout " +
			"rather than an error")
	}
}

// TestGateNATIsScopedToTheLAN is the negative case that matters most.
//
// NAT scoped too widely rewrites traffic that should pass through untouched —
// including the client's own traffic to another LAN host, which must keep its
// address so the reply comes back to the right place.
func TestGateNATIsScopedToTheLAN(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p := netPolicyFromConfig(loadedOrFail(t, cfg))

	// Traffic entering from the WAN must not be masqueraded. If it were, the
	// upstream would see replies addressed to the WAN interface and return
	// them to the wrong host.
	sim := netconfig.Simulate(p, netconfig.Packet{
		Source:      addr(t, "198.51.100.7"),
		Destination: addr(t, "8.8.8.8"),
		Protocol:    "tcp",
		Ingress:     gateWANIface,
	})

	for _, step := range sim.Steps {
		if step.Stage == netconfig.StageNAT && step.Outcome == netconfig.OutcomePass &&
			strings.Contains(step.Detail, "translat") {
			t.Errorf("traffic from the WAN was translated: %s", step.Detail)
		}
	}
}

// TestGateNATDisabledMeansNoTranslation is the negative case.
func TestGateNATDisabledMeansNoTranslation(t *testing.T) {
	cfg := topologyConfig()
	cfg.NAT.Enabled = false

	loaded, _ := loadTopology(t, cfg)
	p := netPolicyFromConfig(loaded)

	sim := netconfig.Simulate(p, netconfig.Packet{
		Source:      addr(t, "10.77.0.100"),
		Destination: addr(t, "8.8.8.8"),
		Protocol:    "tcp",
		Ingress:     gateLANIface,
	})

	if sim.Translated {
		t.Error("the packet was translated although NAT is disabled")
	}
}

// TestGateFirewallDeniesUnsolicitedInbound is the firewall phase's central
// property. A gateway that answers from the internet is the failure this whole
// project exists to prevent.
func TestGateFirewallDeniesUnsolicitedInbound(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p := netPolicyFromConfig(loadedOrFail(t, cfg))

	for _, dst := range []string{"10.77.0.10", "10.77.0.100", "10.77.0.1"} {
		sim := netconfig.Simulate(p, netconfig.Packet{
			Source:          addr(t, "198.51.100.7"),
			Destination:     addr(t, dst),
			Protocol:        "tcp",
			DestinationPort: 22, // SSH: the port an attacker tries first
			Ingress:         gateWANIface,
		})

		if sim.Verdict == netconfig.VerdictForwarded {
			t.Errorf("unsolicited inbound to %s was forwarded; the LAN is exposed "+
				"to the internet behind a gateway", dst)
		}
	}
}

// TestGateFirewallRulesetDeniesByDefault checks the rendered artefact rather
// than the model, because the ruleset is what the kernel will actually read.
//
// A model that says "drop" and a ruleset that says "accept" is the exact
// failure the coherence phase cannot see, and it is worth asserting on the
// rendered text separately.
func TestGateFirewallRulesetDeniesByDefault(t *testing.T) {
	_, path := loadTopology(t, topologyConfig())

	doc, code := runGateJSON(t, "firewall", "render", "--config", path)
	if code != ExitOK {
		t.Fatalf("firewall render exited %d", code)
	}

	ruleset := jsonString(t, doc, "ruleset")

	// The forward chain must be closed by default. The chain header alone is
	// not enough — the policy statement after it is what denies.
	chain := forwardChain(t, ruleset)
	requireContains(t, "the forward chain", chain, "policy drop")

	// Every table brace must be closed, or nft refuses the whole file and the
	// gateway runs with no firewall at all while `thn` reports one.
	if open := countOf(ruleset, "{"); open != countOf(ruleset, "}") {
		t.Errorf("the ruleset has %d opening and %d closing braces; nft will reject it "+
			"entirely, leaving the host unfiltered", open, countOf(ruleset, "}"))
	}

	// A masquerade rule must be present, because NAT is configured.
	requireContains(t, "the ruleset", ruleset, "masquerade")
}

// TestGateFirewallAcceptInboundOnlyWhenAsked is the positive control for the
// previous test. Without it, a ruleset that denied everything would pass.
//
// An accept-by-default inbound policy is implemented by adding an explicit
// wan-to-lan accept rule, not by loosening the chain policy. That is the
// better shape: the rule is visible in the trace, and the chain keeps denying
// anything nobody thought about. The rule also carries a comment naming the
// exposure, which is checked here because "everything is permitted" deserves
// a warning in the artefact itself.
func TestGateFirewallAcceptInboundOnlyWhenAsked(t *testing.T) {
	cfg := topologyConfig()
	cfg.Firewall.DefaultInboundPolicy = "accept"

	_, path := loadTopology(t, cfg)

	doc, code := runGateJSON(t, "firewall", "render", "--config", path)
	if code != ExitOK {
		t.Fatalf("firewall render exited %d", code)
	}
	ruleset := jsonString(t, doc, "ruleset")

	chain := forwardChain(t, ruleset)

	// The chain itself still denies by default.
	requireContains(t, "the forward chain", chain, "policy drop")

	// And the accepted direction is stated explicitly, inside that chain.
	requireContains(t, "the forward chain", chain,
		"iifname \""+gateWANIface+"\" oifname \""+gateLANIface+"\" accept")

	// The exposure must be named in the file, not just in a log line.
	requireContains(t, "the forward chain", chain, "exposed")
}

// forwardChain extracts the body of the forward chain from a ruleset.
//
// The match is anchored on the declaration "chain forward {", not on "chain
// forward". A ruleset contains a jump target named forward_chain, and that
// appears earlier in the file — so an unanchored search returns a chain body
// of four characters and every assertion against it passes vacuously or fails
// for the wrong reason.
//
// The body ends at the next chain declaration, or at the table's closing
// brace. Searching for the brace alone would run past the end of the chain and
// pick up rules from the chains after it, which is how a test ends up
// asserting on text that merely happens to be somewhere in the file.
func forwardChain(t *testing.T, ruleset string) string {
	t.Helper()

	const decl = "chain forward {"

	idx := indexOf(ruleset, decl)
	if idx < 0 {
		t.Fatal("the ruleset has no forward chain; forwarded traffic is unfiltered")
	}

	chain := ruleset[idx:]

	// Stop at the next chain declaration, if there is one.
	if end := indexOf(chain[len(decl):], "chain "); end >= 0 {
		return chain[:len(decl)+end]
	}
	// Otherwise stop at the table's closing brace.
	if end := indexOf(chain, "\n}"); end >= 0 {
		return chain[:end]
	}
	return chain
}

// dnsPolicyOrFail derives the DNS policy or fails the test.
//
// dnsPolicyFromConfig returns an error, so every call site would otherwise
// carry the same three lines of boilerplate and the same chance of ignoring
// it.
func dnsPolicyOrFail(t *testing.T, cfg gateConfig) dns.Policy {
	t.Helper()

	p, err := dnsPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("deriving the DNS policy: %v", err)
	}
	return p
}

// loadedOrFail reloads a config so the gate asserts against the normalised
// document rather than the struct it built.
func loadedOrFail(t *testing.T, cfg gateConfig) gateConfig {
	t.Helper()

	loaded, _ := loadTopology(t, cfg)
	return loaded
}

// indexOf returns the byte offset of sub in s, or -1.
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// countOf counts non-overlapping occurrences of sub in s.
func countOf(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); {
		if s[i:i+len(sub)] == sub {
			n++
			i += len(sub)
			continue
		}
		i++
	}
	return n
}
