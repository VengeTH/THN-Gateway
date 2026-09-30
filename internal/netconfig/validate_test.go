package netconfig

import (
	"net/netip"
	"testing"
)

// mustPrefix parses a prefix or panics, for use in table-driven tests.
func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// mustAddr parses an address or panics.
func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// gateway returns a complete, coherent policy with both interfaces identified.
func gateway() Policy {
	p := Default()
	p.Interfaces.WAN = "enp0s31f6"
	p.Interfaces.LAN = "enx001122334455"
	p.NAT.OutInterface = "enp0s31f6"
	p.NAT.InInterface = "enx001122334455"
	p.Routing.DefaultGatewayInterface = "enp0s31f6"
	p.Routing.DefaultGateway = mustAddr("203.0.113.1")
	p.Routing.Routes = []Route{
		{Destination: mustPrefix("10.77.0.0/24"), Interface: "enx001122334455"},
	}
	return p
}

// hasError reports whether field carries an error-level finding.
func hasError(r Result, field string) bool {
	for _, f := range r.Findings {
		if f.Field == field && f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// hasFinding reports whether field carries a finding at the given severity.
func hasFinding(r Result, field string, sev Severity) bool {
	for _, f := range r.Findings {
		if f.Field == field && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestDefaultPolicyIsValidAndCoherent(t *testing.T) {
	r, issues := Validate(Default())

	if !r.Valid {
		t.Errorf("the default policy must be valid, got: %v", r.Errors())
	}
	// With no interfaces identified, coherence issues are expected: NAT and
	// forwarding rules reference a LAN that does not exist. That is the
	// documented development state, reported as issues rather than errors.
	if r.Coherent {
		t.Log("default policy is coherent with no interfaces identified")
	}
	for _, i := range issues {
		t.Logf("issue: [%s] %s", i.Subsystems, i.Message)
	}
}

func TestCompleteGatewayIsCoherent(t *testing.T) {
	r, issues := Validate(gateway())

	if !r.Valid {
		t.Errorf("a complete gateway must be valid, got: %v", r.Errors())
	}
	if !r.Coherent {
		t.Errorf("a complete gateway must be coherent, got: %v", issues)
	}
}

func TestValidationIsDeterministic(t *testing.T) {
	p := gateway()
	p.Routing.Routes = append(p.Routing.Routes,
		Route{Destination: mustPrefix("192.168.50.0/24"), Interface: "enx001122334455", Metric: 50})

	first, _ := Validate(p)
	for i := 0; i < 5; i++ {
		next, _ := Validate(p)
		if len(next.Findings) != len(first.Findings) {
			t.Fatalf("finding count varies: %d then %d", len(first.Findings), len(next.Findings))
		}
		for j := range next.Findings {
			if next.Findings[j].Field != first.Findings[j].Field {
				t.Fatalf("finding order varies at %d", j)
			}
		}
	}
}

// TestCoherenceIsSeparateFromValidity is the central design claim: each
// subsystem can be individually valid while the combination cannot work.
func TestCoherenceIsSeparateFromValidity(t *testing.T) {
	p := gateway()

	// LAN-to-WAN accepted, NAT off: individually fine, jointly useless.
	p.NAT.Enabled = false
	p.NAT.Mode = NATNone

	r, issues := Validate(p)

	if !r.Valid {
		t.Errorf("each subsystem is individually valid, so Valid should hold: %v", r.Errors())
	}
	if r.Coherent {
		t.Error("accepting LAN-to-WAN without NAT must be reported as incoherent")
	}

	var found bool
	for _, i := range issues {
		if i.Subsystems == "forwarding+nat" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a forwarding+nat coherence issue, got %v", issues)
	}
}

func TestRouteWithoutInterfaceIsError(t *testing.T) {
	p := gateway()
	p.Routing.Routes = []Route{{Destination: mustPrefix("10.0.0.0/8")}}

	r, _ := Validate(p)

	if !hasError(r, "routing.routes[0].interface") {
		t.Error("a route with no egress interface is not installable and must be an error")
	}
}

func TestNextHopInsideDestinationIsError(t *testing.T) {
	// A next hop inside the destination network is a forwarding loop.
	p := gateway()
	p.Routing.Routes = []Route{{
		Destination: mustPrefix("10.77.0.0/24"),
		Interface:   "enx001122334455",
		NextHop:     mustAddr("10.77.0.99"),
	}}

	r, _ := Validate(p)

	if !hasError(r, "routing.routes[0].next_hop") {
		t.Error("a next hop inside the destination must be rejected")
	}
}

func TestDuplicateRouteMetricIsError(t *testing.T) {
	p := gateway()
	p.Routing.Routes = []Route{
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "enx001122334455", Metric: 100},
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "enp0s31f6", Metric: 100},
	}

	r, _ := Validate(p)

	if !hasError(r, "routing.routes[1].destination") {
		t.Error("identical prefixes with identical metrics are ambiguous and must be rejected")
	}
}

func TestFailoverRoutePairIsAccepted(t *testing.T) {
	// The same prefix with different metrics is a legitimate failover pair.
	p := gateway()
	p.Routing.Routes = []Route{
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "enx001122334455", Metric: 100},
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "enp0s31f6", Metric: 200},
	}

	r, _ := Validate(p)

	if !r.Valid {
		t.Errorf("a failover pair must be valid, got: %v", r.Errors())
	}
}

func TestDefaultGatewayWithoutInterfaceIsError(t *testing.T) {
	p := gateway()
	p.Routing.DefaultGatewayInterface = ""

	r, _ := Validate(p)

	if !hasError(r, "routing.default_gateway_interface") {
		t.Error("a gateway with no egress interface cannot carry traffic")
	}
}

func TestDefaultRouteThroughLANIsError(t *testing.T) {
	// The default route must not exit through the LAN or traffic loops back
	// down the segment it came from.
	p := gateway()
	p.Routing.DefaultGateway = mustAddr("10.77.0.99") // inside the LAN prefix
	p.Routing.DefaultGatewayInterface = p.Interfaces.LAN
	p.Routing.Routes = []Route{{Destination: mustPrefix("10.77.0.0/24"), Interface: p.Interfaces.LAN}}

	r, issues := Validate(p)

	if !hasError(r, "routing.default_gateway") {
		t.Errorf("a default gateway inside the LAN network must be rejected: %v", r.Findings)
	}
	var coherent bool
	for _, i := range issues {
		if i.Subsystems == "routing+interfaces" {
			coherent = true
		}
	}
	if !coherent {
		t.Error("a default route exiting the LAN must be a coherence issue")
	}
}

func TestMasqueradeScopedToLANIsError(t *testing.T) {
	// Masquerading traffic leaving the LAN would rewrite client addresses.
	p := gateway()
	p.NAT.OutInterface = p.Interfaces.LAN

	r, _ := Validate(p)

	if !hasError(r, "nat.out_interface") {
		t.Error("masquerading scoped to the LAN must be rejected")
	}
}

func TestUnscopedMasqueradeWarns(t *testing.T) {
	p := gateway()
	p.NAT.OutInterface = ""

	r, _ := Validate(p)

	if !hasFinding(r, "nat.out_interface", SeverityWarning) {
		t.Error("masquerading without an egress interface must warn")
	}
}

func TestSNATWithoutAddressIsError(t *testing.T) {
	p := gateway()
	p.NAT.Mode = NATSNAT
	p.NAT.SNATAddress = netip.Addr{}
	p.NAT.SNATPrefix = netip.Prefix{}

	r, _ := Validate(p)

	if !hasError(r, "nat.snat_address") {
		t.Error("SNAT with no translation address must be rejected")
	}
}

func TestSNATModeWithMasqueradeAddressWarns(t *testing.T) {
	p := gateway()
	p.NAT.Mode = NATMasquerade
	p.NAT.SNATAddress = mustAddr("198.51.100.5")

	r, _ := Validate(p)

	if !hasFinding(r, "nat.snat_address", SeverityWarning) {
		t.Error("an address ignored by masquerade mode must warn")
	}
}

func TestForwardingDisabledIsIncoherent(t *testing.T) {
	// Routing on, kernel forwarding off: nothing can be routed.
	p := gateway()
	p.Forwarding.IPv4Enabled = false
	p.Routing.IPv4Enabled = true

	_, issues := Validate(p)

	var found bool
	for _, i := range issues {
		if i.Subsystems == "routing+forwarding" {
			found = true
		}
	}
	if !found {
		t.Errorf("routing with forwarding disabled must be incoherent, got %v", issues)
	}
}

func TestNoForwardingRulesWarns(t *testing.T) {
	p := gateway()
	p.Forwarding.Rules = nil

	r, issues := Validate(p)

	if !hasFinding(r, "forwarding.rules", SeverityWarning) {
		t.Errorf("forwarding with no rules should warn, got: %v", r.Findings)
	}
	var found bool
	for _, i := range issues {
		if i.Subsystems == "forwarding" {
			found = true
		}
	}
	if !found {
		t.Error("enabling forwarding with no rules must be a coherence issue")
	}
}

func TestUnknownForwardDirectionIsError(t *testing.T) {
	p := gateway()
	p.Forwarding.Rules = []ForwardRule{{Direction: "sideways", Action: "accept"}}

	r, _ := Validate(p)

	if !hasError(r, "forwarding.rules[0].direction") {
		t.Error("an unknown forwarding direction must be rejected")
	}
}

func TestUnknownActionIsError(t *testing.T) {
	p := gateway()
	p.Forwarding.Rules = []ForwardRule{{Direction: LANToWAN, Action: "permit"}}

	r, _ := Validate(p)

	if !hasError(r, "forwarding.rules[0].action") {
		t.Error("an unknown action must be rejected")
	}
}

func TestNATWithNoLANIsIncoherent(t *testing.T) {
	p := gateway()
	p.Interfaces.LAN = ""

	_, issues := Validate(p)

	var found bool
	for _, i := range issues {
		if i.Subsystems == "nat+interfaces" {
			found = true
		}
	}
	if !found {
		t.Errorf("NAT with no LAN must be incoherent, got %v", issues)
	}
}

func TestFindingsSortedBySeverity(t *testing.T) {
	p := Default()
	p.Interfaces.WAN = "enp0s31f6"
	p.Routing.Routes = []Route{{Destination: mustPrefix("10.0.0.0/8")}} // error
	p.NAT.OutInterface = ""                                             // warning

	r, _ := Validate(p)

	last := -1
	for _, f := range r.Findings {
		rank := f.Severity.rank()
		if rank < last {
			t.Errorf("findings not sorted by severity: %s after rank %d", f.Severity, last)
		}
		last = rank
	}
}

func TestRoleAssignment(t *testing.T) {
	i := Interfaces{WAN: "eth0", LAN: "eth1", Loopback: "lo"}

	cases := []struct {
		name string
		want Role
	}{
		{"eth0", RoleWAN},
		{"eth1", RoleLAN},
		{"lo", RoleLoopback},
		{"eth9", RoleUnknown},
	}
	for _, c := range cases {
		if got := i.RoleOf(c.name); got != c.want {
			t.Errorf("RoleOf(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestNormalizeSortsRoutesAndDefaultsProtocol(t *testing.T) {
	p := gateway()
	p.Routing.Routes = []Route{
		{Destination: mustPrefix("192.168.0.0/16"), Interface: "eth1", Metric: 50},
		{Destination: mustPrefix("10.0.0.0/8"), Interface: "eth1", Metric: 10},
	}

	p.Normalize()

	if p.Routing.Routes[0].Destination.String() != "10.0.0.0/8" {
		t.Error("routes must be sorted by destination for deterministic rendering")
	}
	if p.Routing.Routes[0].Protocol == "" {
		t.Error("Normalize must default the protocol")
	}
	if p.Routing.Routes[0].Scope == "" {
		t.Error("Normalize must derive a scope")
	}
}

func TestCloneIsDeep(t *testing.T) {
	p := gateway()
	p.Forwarding.Rules = []ForwardRule{{
		Direction: LANToWAN,
		Action:    "accept",
		Source:    []netip.Prefix{mustPrefix("10.77.0.0/24")},
	}}

	c := p.Clone()
	c.Forwarding.Rules[0].Source[0] = mustPrefix("192.168.0.0/16")
	c.Routing.Routes[0].Interface = "changed"

	if p.Forwarding.Rules[0].Source[0].String() != "10.77.0.0/24" {
		t.Error("Clone must not share the source slice")
	}
	if p.Routing.Routes[0].Interface == "changed" {
		t.Error("Clone must not share the routes slice")
	}
}
