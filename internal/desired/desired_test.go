package desired

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
)

// base returns a configuration with the WAN identified and no LAN, which is
// the expected state during remote development.
func base() config.Config {
	cfg := config.Defaults()
	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = ""
	if err := cfg.Normalize(); err != nil {
		panic(err)
	}
	return cfg
}

func TestWANIsPresentWhenConfigured(t *testing.T) {
	s := FromConfig(base())

	if !s.WAN.Present {
		t.Error("a configured WAN must be marked present")
	}
	if s.WAN.Role != RoleWAN {
		t.Errorf("role = %q, want %q", s.WAN.Role, RoleWAN)
	}
}

func TestMissingWANYieldsUnidentifiedReason(t *testing.T) {
	cfg := base()
	cfg.Network.WAN = ""
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	s := FromConfig(cfg)

	if s.WAN.Present {
		t.Error("an unconfigured WAN must not be marked present")
	}
	if s.WAN.Reason == "" {
		t.Error("an absent interface must explain why")
	}
}

// TestUnidentifiedLANIsNotTheSameAsNoAddresses is the distinction this
// package exists to preserve.
func TestUnidentifiedLANIsNotTheSameAsNoAddresses(t *testing.T) {
	s := FromConfig(base())

	if s.LAN.Present {
		t.Error("an unconfigured LAN must not be marked present")
	}
	if len(s.LAN.Addresses) != 0 {
		t.Errorf("an absent LAN has no addresses, got %v", s.LAN.Addresses)
	}
	if s.LAN.Reason == "" {
		t.Error("the LAN must carry a reason explaining it is not identified")
	}
}

func TestIdentifiedLANCarriesItsAddress(t *testing.T) {
	cfg := base()
	cfg.Network.LAN = "enx0011"
	cfg.Network.LANPrefix = "10.77.0.1/24"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	s := FromConfig(cfg)

	if !s.LAN.Present {
		t.Error("an identified LAN must be marked present")
	}
	if len(s.LAN.Addresses) != 1 || s.LAN.Addresses[0] != "10.77.0.1/24" {
		t.Errorf("addresses = %v, want [10.77.0.1/24]", s.LAN.Addresses)
	}
	if s.LAN.Role != RoleLAN {
		t.Errorf("role = %q, want %q", s.LAN.Role, RoleLAN)
	}
}

func TestIdentifiedLANWithoutPrefixIsPresentButPending(t *testing.T) {
	// The interface is plugged in but has no address configured. That is a
	// different state from "not plugged in", and the diff must be able to
	// tell them apart.
	cfg := base()
	cfg.Network.LAN = "enx0011"
	cfg.Network.LANPrefix = ""

	s := FromConfig(cfg)

	if !s.LAN.Present {
		t.Error("the interface is identified, so it must be marked present")
	}
	if len(s.LAN.Addresses) != 0 {
		t.Errorf("addresses = %v, want none", s.LAN.Addresses)
	}
	if s.LAN.Reason == "" {
		t.Error("a LAN with no address must say so")
	}
}

func TestNATResolvesFromLANWhenInterfacesEmpty(t *testing.T) {
	cfg := base()
	cfg.Network.LAN = "enx0011"
	cfg.NAT.Enabled = true
	cfg.NAT.Interfaces = nil
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	s := FromConfig(cfg)

	if !s.NAT.Resolved {
		t.Error("NAT should resolve from the identified LAN")
	}
	if len(s.NAT.Interfaces) != 1 || s.NAT.Interfaces[0] != "enx0011" {
		t.Errorf("interfaces = %v, want [enx0011]", s.NAT.Interfaces)
	}
}

func TestNATUnresolvedWithoutLAN(t *testing.T) {
	s := FromConfig(base())

	if !s.NAT.Enabled {
		t.Fatal("NAT should be enabled by default")
	}
	if s.NAT.Resolved {
		t.Error("NAT cannot resolve without a masquerade interface")
	}
}

func TestNATDisabledIsResolved(t *testing.T) {
	// "NAT off" is a complete answer, not a pending one.
	cfg := base()
	cfg.NAT.Enabled = false

	s := FromConfig(cfg)

	if s.NAT.Resolved {
		t.Error("disabled NAT should not claim to be resolved; it should simply be off")
	}
	if s.NAT.Enabled {
		t.Error("NAT must be reported as disabled")
	}
}

func TestQoSDisabledIsResolved(t *testing.T) {
	s := FromConfig(base())

	if !s.QoS.Resolved {
		t.Error("QoS being off is a settled state")
	}
	if s.QoS.Enabled {
		t.Error("QoS must be reported as disabled")
	}
}

func TestQoSEnabledIncompleteIsUnresolved(t *testing.T) {
	cfg := base()
	cfg.QoS.Enabled = true
	cfg.QoS.Interface = "enp0s31f6"
	cfg.QoS.DownloadKbps = 0 // missing
	cfg.QoS.UploadKbps = 1000

	s := FromConfig(cfg)

	if s.QoS.Resolved {
		t.Error("QoS with a zero rate must not be resolved")
	}
}

func TestFirewallDefaultsToDrop(t *testing.T) {
	s := FromConfig(base())

	if !s.Firewall.Enabled {
		t.Error("the firewall is enabled by default")
	}
	if s.Firewall.DefaultInboundPolicy != "drop" {
		t.Errorf("policy = %q, want drop", s.Firewall.DefaultInboundPolicy)
	}
	if !s.Firewall.AllowEstablished || !s.Firewall.AllowLoopback {
		t.Error("the base rules must allow established and loopback traffic")
	}
}

func TestPendingListsUndeterminedSubsystems(t *testing.T) {
	s := FromConfig(base())

	p := s.Pending()
	if _, ok := p["lan"]; !ok {
		t.Errorf("an unidentified LAN must be pending, got %v", p)
	}
	if _, ok := p["nat"]; !ok {
		t.Errorf("unresolved NAT must be pending, got %v", p)
	}
	if s.Ready() {
		t.Error("a state with pending subsystems is not ready")
	}
}

func TestReadyWhenFullyDetermined(t *testing.T) {
	cfg := base()
	cfg.Network.LAN = "enx0011"
	cfg.Network.LANPrefix = "10.77.0.1/24"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	s := FromConfig(cfg)

	if p := s.Pending(); len(p) != 0 {
		t.Errorf("expected no pending subsystems, got %v", p)
	}
	if !s.Ready() {
		t.Error("a fully determined state must be ready")
	}
}

func TestInterfaceLookupByRole(t *testing.T) {
	cfg := base()
	cfg.Network.LAN = "enx0011"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	s := FromConfig(cfg)

	if got := s.Interface(RoleLAN); got.Name != "enx0011" {
		t.Errorf("LAN lookup returned %q", got.Name)
	}
	if got := s.Interface(RoleWAN); got.Name != "enp0s31f6" {
		t.Errorf("WAN lookup returned %q", got.Name)
	}
}

func TestSummaryMentionsEverySubsystem(t *testing.T) {
	s := FromConfig(base())
	sum := s.Summary()

	for _, want := range []string{"gateway:", "WAN:", "LAN:", "forward:", "NAT:", "firewall:", "QoS:", "DNS:"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary missing %q:\n%s", want, sum)
		}
	}
}

func TestSummaryShowsPendingNAT(t *testing.T) {
	// An operator reading the summary must be able to tell that NAT is
	// wanted but not yet actionable.
	s := FromConfig(base())

	if !strings.Contains(s.Summary(), "pending") {
		t.Errorf("summary must flag pending NAT:\n%s", s.Summary())
	}
}

func TestPrefixesParse(t *testing.T) {
	cfg := base()
	cfg.Network.LAN = "enx0011"
	cfg.Network.LANPrefix = "10.77.0.1/24"
	s := FromConfig(cfg)

	p, err := s.Prefixes()
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if len(p) != 1 || p[0].String() != "10.77.0.1/24" {
		t.Errorf("prefixes = %v, want [10.77.0.1/24]", p)
	}
}

func TestPrefixesRejectInvalidInput(t *testing.T) {
	cfg := base()
	cfg.Network.LAN = "enx0011"
	cfg.Network.LANPrefix = "not-a-prefix"
	s := FromConfig(cfg)

	if _, err := s.Prefixes(); err == nil {
		t.Error("an invalid prefix must be reported, not silently ignored")
	}
}

func TestGenerationAndNameAreCarried(t *testing.T) {
	cfg := base()
	cfg.Gateway.Name = "edge-01"
	cfg.Gateway.Generation = 42

	s := FromConfig(cfg)

	if s.Name != "edge-01" || s.Generation != 42 {
		t.Errorf("identity not carried: name=%q generation=%d", s.Name, s.Generation)
	}
}

func TestAddressingIsPopulated(t *testing.T) {
	cfg := base()
	cfg.Network.UpstreamGateway = "192.168.1.1"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	s := FromConfig(cfg)

	if !s.Addressing.UpstreamPresent {
		t.Error("a configured gateway must mark the upstream present")
	}
	if s.Addressing.DefaultGateway != "192.168.1.1" {
		t.Errorf("gateway = %q", s.Addressing.DefaultGateway)
	}
	if !s.Addressing.IPv4Forwarding {
		t.Error("a gateway must request IPv4 forwarding")
	}
}

func TestFromConfigWithResolution(t *testing.T) {
	cfg := config.Defaults()
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.NAT.Enabled = true

	res := host.Resolution{
		Assigned: map[host.Role]host.Interface{
			host.RoleWAN: {SystemName: "enp0s31f6", ID: "hw:7c6170fd7f34317a", Role: host.RoleWAN},
			host.RoleLAN: {SystemName: "enx00e099001812", ID: "hw:2c886f45ad0cb12f", Role: host.RoleLAN},
		},
	}

	s := FromConfigWithResolution(cfg, res)

	if !s.WAN.Present || s.WAN.Name != "enp0s31f6" {
		t.Errorf("WAN = %+v, want present enp0s31f6", s.WAN)
	}
	if !s.LAN.Present || s.LAN.Name != "enx00e099001812" {
		t.Errorf("LAN = %+v, want present enx00e099001812", s.LAN)
	}
	if !s.NAT.Resolved || len(s.NAT.Interfaces) != 1 || s.NAT.Interfaces[0] != "enx00e099001812" {
		t.Errorf("NAT = %+v, want resolved with enx00e099001812", s.NAT)
	}
}

func TestKnownRolesAreDefined(t *testing.T) {
	roles := []Role{RoleWAN, RoleLAN, RoleMGMT, RoleGuest, RoleDMZ, RoleUnassigned}
	for _, r := range roles {
		if r.String() == "" {
			t.Errorf("role %v has empty string representation", r)
		}
	}
}
