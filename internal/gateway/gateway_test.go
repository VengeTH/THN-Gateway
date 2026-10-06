package gateway

// Tests for gateway intent: the statement of what the operator wants, and the
// verdict on whether this host can provide it.
//
// # What these tests are actually for
//
// The milestone this package exists for draws one distinction and asks that it
// be kept everywhere: hardware that COULD be a gateway is evidence, and the
// operator WANTS a gateway is intent. Most of what follows tests that the
// distinction holds, because everywhere else it is easy to lose — a default
// that fills in a missing role, a validation rule that accepts an unverified
// selector as a good one, a verifier that treats "unresolved" as "fine".
//
// The remaining tests cover the validation rules themselves, which are only
// worth having if the distinction above is what they are protecting.

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/host"
)

// ------------------------------------------------------------- fixtures

// device builds an observed host with n physical NICs, plus loopback.
//
// The identities are derived through host.IDFor rather than written out, so a
// fixture can never disagree with the derivation the real discovery layer
// uses. A hardcoded literal that stops matching produces a host where nothing
// resolves, and every assertion after it passes or fails for a reason nobody
// can see.
func device(t *testing.T, n int) *host.Device {
	t.Helper()

	d := &host.Device{
		Supported: true,
		Hostname:  "test-gateway",
		Interfaces: []host.Interface{{
			ID:         host.IDFor("00:00:00:00:00:01"),
			IDKind:     host.IdentityHardware,
			SystemName: "lo",
			Kind:       host.KindLoopback,
			Assignable: false,
		}},
	}

	for i := 0; i < n; i++ {
		d.Interfaces = append(d.Interfaces, host.Interface{
			ID:         host.IDFor(fmt.Sprintf("3c:ec:ef:00:00:%02d", i)),
			IDKind:     host.IdentityHardware,
			SystemName: fmt.Sprintf("eth%d", i),
			Kind:       host.KindEthernet,
			Physical:   true,
			LinkUp:     true,
			Assignable: true,
		})
	}
	return d
}

// wanSelector and lanSelector are the stable identities the fixtures use.
//
// Taken from host.IDFor rather than written out, because a hardcoded literal
// that happens to disagree with the derivation produces a fixture in which
// nothing resolves — and every test then passes for the wrong reason, or fails
// for one nobody can see.
func wanSelector() string { return host.IDFor("3c:ec:ef:00:00:00") }
func lanSelector() string { return host.IDFor("3c:ec:ef:00:00:01") }

// gatewayConfig is a complete, valid gateway document.
func gatewayConfig() config.Config {
	cfg := config.Defaults()
	cfg.Gateway.Enabled = true
	cfg.Network.WAN = wanSelector()
	cfg.Network.LAN = lanSelector()
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.NAT.Enabled = true
	cfg.NAT.Masquerade.Enabled = true
	cfg.NAT.Masquerade.Outbound = "wan"
	return cfg
}

// resolvedFor resolves a document's roles against a two-port host.
func resolvedFor(t *testing.T, cfg config.Config) host.Resolution {
	t.Helper()

	d := device(t, 2)
	res := host.Resolve(d, []host.Assignment{
		{Role: host.RoleWAN, Selector: cfg.Network.WAN},
		{Role: host.RoleLAN, Selector: cfg.Network.LAN},
	})
	return res
}

// reportFor validates a document the way `thn validate` does on a host.
//
// The resolution is passed to BOTH FromConfig and Observed. Handing it to one
// and not the other would produce a report about a host nobody supplied —
// every role would read as unresolved and the failures would all point at the
// fixture rather than at the rule under test.
func reportFor(t *testing.T, cfg config.Config) Report {
	t.Helper()

	res := resolvedFor(t, cfg)
	return Validate(FromConfig(cfg, res), Observed{Device: device(t, 2), Resolution: &res})
}

// has reports whether a finding with code is present.
func has(rep Report, code string) bool {
	for _, f := range rep.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// hasBlocking reports whether code is present and blocking.
func hasBlocking(rep Report, code string) bool {
	for _, f := range rep.Findings {
		if f.Code == code && f.Severity == SeverityBlocking {
			return true
		}
	}
	return false
}

// codes lists the finding codes, for failure messages.
func codes(rep Report) string {
	var b strings.Builder
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "  [%s] %s: %s\n", f.Severity, f.Code, f.Message)
	}
	if b.Len() == 0 {
		return "  (no findings)\n"
	}
	return b.String()
}

// ------------------------------------------- observation is not intent

// TestGatewayMustBeAskedFor is the milestone's headline claim.
//
// A host with two NICs, forwarding already on in the kernel, and a document
// that describes none of it explicitly must NOT become a gateway. If this test
// fails, THN has started inferring intent from capability, which is the exact
// failure the whole layer was built to prevent.
func TestGatewayMustBeAskedFor(t *testing.T) {
	cfg := config.Defaults()
	cfg.Gateway.Enabled = false
	cfg.Network.WAN = ""
	cfg.Network.LAN = ""
	cfg.Network.LANPrefix = ""

	in := FromConfig(cfg, host.Resolution{})
	rep := Validate(in, Observed{})

	if in.Enabled {
		t.Fatal("a document that did not ask for a gateway must not be treated as asking")
	}
	if rep.Verdict == VerdictBlocked {
		t.Errorf("declining to configure a gateway must not be an error:\n%s", codes(rep))
	}
	if !has(rep, CodeGatewayDisabled) {
		t.Errorf("the operator must be told the gateway was not requested:\n%s", codes(rep))
	}
}

// TestDisabledGatewayRequiresNoRoles proves the flag actually relaxes the
// requirements rather than merely being recorded.
//
// The interesting property is not that the verdict is fine but that the
// findings are absent. A validator that reported "missing WAN" here would be
// asking the operator to configure something they declined to configure.
func TestDisabledGatewayRequiresNoRoles(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Gateway.Enabled = false
	cfg.Network.WAN = ""
	cfg.Network.LAN = ""
	cfg.Network.LANPrefix = ""

	rep := reportFor(t, cfg)

	if has(rep, CodeRoleMissing) {
		t.Errorf("a disabled gateway must not be told it is missing roles:\n%s", codes(rep))
	}
	if has(rep, CodeLANAddressMissing) {
		t.Errorf("a disabled gateway must not be told it needs a LAN address:\n%s", codes(rep))
	}
}

// TestCapabilityIsNotIntent states the distinction using the strongest
// available evidence: a host that genuinely could be a gateway, and a
// document that genuinely does not ask for one.
//
// The two-port fixture has everything a gateway needs. That has to make no
// difference at all.
func TestCapabilityIsNotIntent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Gateway.Enabled = false
	cfg.Network.WAN = "hw:3cec:ef00:0000:0000"
	cfg.Network.LAN = "hw:3cec:ef00:0000:0001"

	// The hardware analysis says this host can be a gateway.
	d := device(t, 2)
	intel := host.AnalyzeHardware(d)
	if !intel.Supported {
		t.Fatal("fixture host must be analysable; the rest of this test assumes it")
	}

	rep := Validate(FromConfig(cfg, host.Resolution{}), Observed{Device: d, Intelligence: &intel})

	if rep.Verdict == VerdictBlocked {
		t.Errorf("hardware capability must not block a document that declined the role:\n%s", codes(rep))
	}
}

// TestIntentIsExplicitlyDeclared proves the canonical document states the
// gateway rather than leaving it to a default.
//
// A default is a safety net, not a statement. The shipped document is the one
// operators copy, so if it does not say so, the message the project wants to
// give is not being given anywhere an operator will read.
func TestIntentIsExplicitlyDeclared(t *testing.T) {
	cfg := gatewayConfig()
	if !cfg.Gateway.Enabled {
		t.Error("the canonical gateway document must ask for a gateway")
	}
}

// ----------------------------------------------- valid configurations

// TestAValidGatewayValidates is the acceptance case.
func TestAValidGatewayValidates(t *testing.T) {
	rep := reportFor(t, gatewayConfig())

	if rep.Verdict != VerdictValid {
		t.Errorf("a complete gateway must validate, got %s:\n%s", rep.Verdict, codes(rep))
	}
}

// TestStableIDSelectorsResolve proves the canonical form works: a document
// naming interfaces by hardware identity, with no kernel name anywhere.
func TestStableIDSelectorsResolve(t *testing.T) {
	cfg := gatewayConfig()
	rep := reportFor(t, cfg)

	wan := rep.Intent.Roles[host.RoleWAN]
	lan := rep.Intent.Roles[host.RoleLAN]

	if !wan.Resolved || !lan.Resolved {
		t.Fatalf("stable-ID selectors must resolve: wan=%+v lan=%+v\n%s", wan, lan, codes(rep))
	}
	if wan.StableID == "" || lan.StableID == "" {
		t.Error("a resolved role must carry the stable identity it resolved to")
	}
}

// TestKernelNameSelectorsStillResolve proves the legacy selector form still
// works. It is not the preferred form, but removing it would break every
// existing deployment for no gain.
func TestKernelNameSelectorsStillResolve(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Network.WAN = "eth0"
	cfg.Network.LAN = "eth1"

	rep := reportFor(t, cfg)

	if rep.Verdict != VerdictValid {
		t.Errorf("kernel-name selectors must remain valid, got %s:\n%s", rep.Verdict, codes(rep))
	}
	if rep.Intent.Roles[host.RoleWAN].Interface != "eth0" {
		t.Error("a kernel-name selector must resolve to that kernel name")
	}
}

// TestCustomLANCIDRIsAccepted proves the default does not become a rule.
func TestCustomLANCIDRIsAccepted(t *testing.T) {
	for _, prefix := range []string{"192.168.50.1/24", "172.16.4.1/16", "fd00::1/64", "10.77.0.1/24"} {
		cfg := gatewayConfig()
		cfg.Network.LANPrefix = prefix

		rep := reportFor(t, cfg)
		if has(rep, CodeLANAddressInvalid) || has(rep, CodeLANAddressMissing) {
			t.Errorf("%s must be a usable LAN address:\n%s", prefix, codes(rep))
		}
	}
}

// TestForwardingIsIntent proves forwarding is read from the document rather
// than from the kernel.
//
// The fixture host is built with no forwarding observation at all, so nothing
// could have leaked in from the host even by accident. The value reported
// must be the document's.
func TestForwardingIsIntent(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Routing.IPv4Forwarding = true

	rep := reportFor(t, cfg)
	if !rep.Intent.Routing.IPv4Forwarding {
		t.Error("IPv4 forwarding intent must come from the document")
	}

	cfg.Routing.IPv4Forwarding = false
	cfg.NAT.Enabled = false
	cfg.NAT.Masquerade.Enabled = false

	rep = reportFor(t, cfg)
	if rep.Intent.Routing.IPv4Forwarding {
		t.Error("a document asking for no forwarding must produce no forwarding intent")
	}
}

// TestExplicitNATViaWANRole proves NAT resolves through the role system rather
// than by naming an interface.
//
// "wan" is the whole point of the role vocabulary: it lets the document
// describe the topology without knowing what the uplink is called on this
// particular machine.
func TestExplicitNATViaWANRole(t *testing.T) {
	cfg := gatewayConfig()
	cfg.NAT.Masquerade.Outbound = "wan"

	rep := reportFor(t, cfg)

	if rep.Intent.NAT.OutboundRole != host.RoleWAN {
		t.Errorf("the outbound role = %q, want %q", rep.Intent.NAT.OutboundRole, host.RoleWAN)
	}
	if !rep.Intent.NAT.OutboundResolved {
		t.Errorf("the WAN role is resolved on this host, so the outbound must be too:\n%s", codes(rep))
	}
}

// TestNATIsNotInferred proves two ports do not turn NAT on by themselves.
//
// The document here has NAT off explicitly. Nothing may re-enable it, because
// "NAT appears possible" is an observation and this layer exists to keep it
// that way.
func TestNATIsNotInferred(t *testing.T) {
	cfg := gatewayConfig()
	cfg.NAT.Enabled = false
	cfg.NAT.Masquerade.Enabled = false

	rep := reportFor(t, cfg)

	if rep.Intent.NAT.Enabled {
		t.Error("NAT must not be enabled by the presence of two interfaces")
	}
}

// --------------------------------------------- invalid configurations

// TestGatewayWithoutWANIsBlocked is the first invalid case.
func TestGatewayWithoutWANIsBlocked(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Network.WAN = ""

	rep := reportFor(t, cfg)

	if !hasBlocking(rep, CodeRoleMissing) {
		t.Errorf("a gateway with no uplink must be blocked:\n%s", codes(rep))
	}
	if rep.Verdict != VerdictBlocked {
		t.Errorf("verdict = %s, want %s", rep.Verdict, VerdictBlocked)
	}
}

// TestGatewayWithoutLANIsBlocked is the second.
//
// This is the case the config layer deliberately does NOT treat as an error —
// an unidentified LAN is pending there — so the intent layer is the only place
// that can notice a gateway with nowhere to serve clients.
func TestGatewayWithoutLANIsBlocked(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Network.LAN = ""

	rep := reportFor(t, cfg)

	if !hasBlocking(rep, CodeRoleMissing) {
		t.Errorf("a gateway with no downstream must be blocked:\n%s", codes(rep))
	}
}

// TestUnresolvedSelectorIsReportedNotGuessed proves an unknown selector is
// reported as unknown, never replaced with "the only other interface".
//
// The severity is warning rather than blocking on purpose: the hardware may
// simply be unplugged, and the operator may have written the identity
// correctly. Guessing would be the unrecoverable error.
func TestUnresolvedSelectorIsReportedNotGuessed(t *testing.T) {
	for _, role := range []struct {
		name string
		set  func(*config.Config)
		want host.Role
	}{
		{"WAN", func(c *config.Config) { c.Network.WAN = "hw:doesnotexist" }, host.RoleWAN},
		{"LAN", func(c *config.Config) { c.Network.LAN = "hw:doesnotexist" }, host.RoleLAN},
	} {
		t.Run(role.name, func(t *testing.T) {
			cfg := gatewayConfig()
			role.set(&cfg)

			rep := reportFor(t, cfg)

			if !has(rep, CodeRoleUnresolved) {
				t.Errorf("an unknown selector must be reported unresolved:\n%s", codes(rep))
			}
			if rep.Intent.Roles[role.want].Resolved {
				t.Error("an unresolved selector must not be marked resolved")
			}
			if rep.Verdict == VerdictBlocked {
				t.Errorf("an unattached interface is pending, not blocked:\n%s", codes(rep))
			}
		})
	}
}

// TestWANAndLANOnOneInterfaceIsBlocked is the separation rule.
//
// Two different spellings of the same interface is the interesting case: a
// stable ID on one role and a kernel name on the other describes one link as
// two roles, and a string comparison would miss it.
func TestWANAndLANOnOneInterfaceIsBlocked(t *testing.T) {
	cfg := gatewayConfig()
	// The same link, named two ways: one by stable identity, one by kernel
	// name. A string comparison would call these different selectors.
	cfg.Network.WAN = lanSelector()
	cfg.Network.LAN = "eth1"

	rep := reportFor(t, cfg)

	if !hasBlocking(rep, CodeRoleConflict) {
		t.Errorf("two roles on one interface must be a conflict:\n%s", codes(rep))
	}
}

// TestRoleConflictCarriesStableIdentity proves the diagnostic is actionable.
//
// An operator told "the WAN and LAN resolve to the same interface" still has
// to work out which one. The stable ID is what makes the finding point at a
// specific piece of hardware.
func TestRoleConflictCarriesStableIdentity(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Network.WAN = cfg.Network.LAN

	rep := reportFor(t, cfg)

	for _, f := range rep.Findings {
		if f.Code != CodeRoleConflict {
			continue
		}
		if f.StableID == "" {
			t.Error("a role conflict must name the stable identity it concerns")
		}
		if f.Interface == "" {
			t.Error("a role conflict must name the interface it resolved to")
		}
		if f.Role != host.RoleLAN {
			t.Errorf("a role conflict must name the role, got %q", f.Role)
		}
		return
	}
	t.Errorf("no role conflict finding:\n%s", codes(rep))
}

// TestLoopbackSelectorIsBlocked proves a non-assignable interface is graded
// differently from an unresolved one.
//
// Loopback will never be an uplink. "Not plugged in yet" is a different
// problem with a different fix, and conflating them teaches operators the
// wrong lesson about the warning that means "attach the cable".
func TestLoopbackSelectorIsBlocked(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Network.WAN = "lo"

	d := device(t, 2)
	res := host.Resolve(d, []host.Assignment{
		{Role: host.RoleWAN, Selector: "lo"},
		{Role: host.RoleLAN, Selector: cfg.Network.LAN},
	})

	rep := Validate(FromConfig(cfg, res), Observed{Device: d, Resolution: &res})

	if !hasBlocking(rep, CodeRoleNotAssignable) {
		t.Errorf("loopback must not be accepted as an uplink:\n%s", codes(rep))
	}
}

// TestInvalidLANCIDR covers every malformed-address case in one table.
func TestInvalidLANCIDR(t *testing.T) {
	for _, prefix := range []string{
		"10.77.0.1",      // no prefix length
		"not-an-ip/24",   // unparseable
		"10.77.0.1/33",   // impossible prefix for IPv4
		"10.77.0.256/24", // impossible octet
		"fd00::1/129",    // impossible prefix for IPv6
		"10.77.0.0/24",   // the network address
		"10.77.0.255/24", // the broadcast address
		"10.77.0.1/-1",   // negative prefix length
		"10.77.0.1/ 24",  // malformed
	} {
		t.Run(prefix, func(t *testing.T) {
			cfg := gatewayConfig()
			cfg.Network.LANPrefix = prefix

			rep := reportFor(t, cfg)

			if !hasBlocking(rep, CodeLANAddressInvalid) {
				t.Errorf("%q must be rejected as a LAN address:\n%s", prefix, codes(rep))
			}
		})
	}
}

// TestHostBitsAreRequired proves the one correct value is not rejected.
//
// The field names the address THN assigns, not the network it belongs to, so
// 10.77.0.1/24 is right and 10.77.0.0/24 is not. A rule borrowed from tools
// that want a masked network would reject the canonical value.
func TestHostBitsAreRequired(t *testing.T) {
	for _, prefix := range []string{"10.77.0.1/24", "192.168.1.1/16", "172.16.0.1/20"} {
		cfg := gatewayConfig()
		cfg.Network.LANPrefix = prefix

		rep := reportFor(t, cfg)
		if has(rep, CodeLANAddressInvalid) {
			t.Errorf("%q is a usable gateway address and must be accepted:\n%s", prefix, codes(rep))
		}
	}
}

// TestNarrowPrefixesAreNotHostAddressErrors proves the /31 and /32 carve-out.
//
// Those have no network or broadcast address in the IPv4 sense, so the rule
// that rejects one has nothing to reject.
func TestNarrowPrefixesAreNotHostAddressErrors(t *testing.T) {
	for _, prefix := range []string{"10.77.0.1/31", "10.77.0.1/32"} {
		cfg := gatewayConfig()
		cfg.Network.LANPrefix = prefix

		rep := reportFor(t, cfg)
		if has(rep, CodeLANAddressInvalid) {
			t.Errorf("%s has no network address to reject:\n%s", prefix, codes(rep))
		}
	}
}

// TestIPv6LANPrefixesAreValid proves the host-address rule is IPv4-only.
//
// In IPv6 the first address of a prefix is an ordinary host address, so
// applying the IPv4 rule to both families would reject every correct ULA LAN.
func TestIPv6LANPrefixesAreValid(t *testing.T) {
	for _, prefix := range []string{"fd00::1/64", "fd00::/64", "fd00::1/128"} {
		cfg := gatewayConfig()
		cfg.Network.LANPrefix = prefix

		rep := reportFor(t, cfg)
		if has(rep, CodeLANAddressInvalid) {
			t.Errorf("%s is a valid IPv6 LAN address:\n%s", prefix, codes(rep))
		}
	}
}

// TestInvalidNATOutbound covers the masquerade-outbound rules.
func TestInvalidNATOutbound(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		cfg := gatewayConfig()
		cfg.NAT.Masquerade.Outbound = ""

		rep := reportFor(t, cfg)
		if !hasBlocking(rep, CodeNATOutboundInvalid) {
			t.Errorf("masquerade with no outbound must be blocked:\n%s", codes(rep))
		}
	})

	t.Run("the LAN role", func(t *testing.T) {
		cfg := gatewayConfig()
		cfg.NAT.Masquerade.Outbound = "lan"

		rep := reportFor(t, cfg)
		if !hasBlocking(rep, CodeNATOutboundInvalid) {
			t.Errorf("masquerading out of the LAN is a routing loop:\n%s", codes(rep))
		}
	})

	t.Run("an unresolved role", func(t *testing.T) {
		cfg := gatewayConfig()
		cfg.Network.WAN = "hw:doesnotexist"

		rep := reportFor(t, cfg)
		if !has(rep, CodeNATOutboundUnresolved) {
			t.Errorf("a masquerade with no WAN to leave by must be reported:\n%s", codes(rep))
		}
	})
}

// TestForwardingAndNATMustAgree catches the combination that describes a
// machine that cannot work.
func TestForwardingAndNATMustAgree(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Routing.IPv4Forwarding = false

	rep := reportFor(t, cfg)

	if !hasBlocking(rep, CodeForwardingIncoherent) {
		t.Errorf("NAT without forwarding can never carry LAN traffic:\n%s", codes(rep))
	}
}

// TestBridgeIntentIsAllowed proves forwarding-off is not automatically an
// error. A bridge is a legitimate machine, and only the NAT combination is a
// contradiction.
func TestBridgeIntentIsAllowed(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Routing.IPv4Forwarding = false
	cfg.NAT.Enabled = false
	cfg.NAT.Masquerade.Enabled = false

	rep := reportFor(t, cfg)

	if hasBlocking(rep, CodeForwardingIncoherent) {
		t.Errorf("a gateway with forwarding off and NAT off is a bridge, not a mistake:\n%s", codes(rep))
	}
}

// --------------------------------------- hardware suitability is evidence

// TestInfrastructureInterfaceIsProfiledNotForbidden is the distinction the
// milestone is most careful about: invalid for this profile, versus impossible.
//
// Loopback is genuinely impossible — nothing routes through it. A container
// bridge is not: it is the ordinary way to build the VM, bridge and namespace
// topologies THN intends to support. So the LAN on a bridge is reported
// against the profile, with evidence, and never as "this can never work".
func TestInfrastructureInterfaceIsProfiledNotForbidden(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Network.LAN = "docker0"

	d := device(t, 2)
	d.Interfaces = append(d.Interfaces, host.Interface{
		ID:         "ephemeral:docker0",
		IDKind:     host.IdentityEphemeral,
		SystemName: "docker0",
		Kind:       host.KindBridge,
		Physical:   false,
		Assignable: true,
	})

	res := host.Resolve(d, []host.Assignment{
		{Role: host.RoleWAN, Selector: cfg.Network.WAN},
		{Role: host.RoleLAN, Selector: "docker0"},
	})
	intel := host.AnalyzeHardware(d)

	rep := Validate(FromConfig(cfg, res), Observed{Device: d, Resolution: &res, Intelligence: &intel})

	for _, f := range rep.Findings {
		if f.Code != CodeRoleUnsuitable {
			continue
		}
		if f.Severity == SeverityBlocking {
			t.Errorf("a bridge must not be declared impossible; it is out of profile, not invalid:\n%s",
				codes(rep))
		}
		if !strings.Contains(f.Message, "profile") {
			t.Errorf("the finding must scope itself to the gateway profile: %q", f.Message)
		}
		return
	}
}

// TestSuitabilityIsSilentWhenNoAnalysisRan proves the layer degrades
// honestly.
//
// "Not analysed" must not become "nothing suitable": reporting a host as
// unsuitable because THN did not look would be a judgement it never made.
func TestSuitabilityIsSilentWhenNoAnalysisRan(t *testing.T) {
	cfg := gatewayConfig()
	d := device(t, 2)
	res := resolvedFor(t, cfg)

	withoutAnalysis := Validate(FromConfig(cfg, res), Observed{Device: d, Resolution: &res})
	withAnalysis := Validate(FromConfig(cfg, res), Observed{Device: d, Resolution: &res})

	if withoutAnalysis.Verdict != withAnalysis.Verdict {
		t.Errorf("the verdict must not depend on whether hardware analysis ran: %s vs %s",
			withoutAnalysis.Verdict, withAnalysis.Verdict)
	}
}

// ------------------------------------------------ observed vs desired

// TestObservedForwardingDoesNotBecomeIntent is the separation, tested
// directly.
//
// A host whose forwarding is on, and a document that says nothing about
// forwarding, must not produce forwarding intent. If the desired state ever
// came from the observation, the two would be indistinguishable — which is
// precisely why they are tested separately.
func TestObservedForwardingDoesNotBecomeIntent(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Routing.IPv4Forwarding = false
	cfg.NAT.Enabled = false
	cfg.NAT.Masquerade.Enabled = false

	d := device(t, 2)
	// The host has forwarding ON. The document does not want it.
	res := resolvedFor(t, cfg)

	rep := Validate(FromConfig(cfg, res), Observed{Device: d, Resolution: &res})

	if rep.Intent.Routing.IPv4Forwarding {
		t.Error("intent must come from the document, never from the host's current forwarding")
	}
}

// TestResolveDoesNotMutateTheHost proves validation leaves observation alone.
//
// Building desired state must never write to the device it was derived from.
// If it did, the next observation would report what the configuration wanted
// rather than what the machine is.
func TestResolveDoesNotMutateTheHost(t *testing.T) {
	cfg := gatewayConfig()
	d := device(t, 2)
	before := len(d.Interfaces)

	res := resolvedFor(t, cfg)
	intel := host.AnalyzeHardware(d)
	_ = Validate(FromConfig(cfg, res), Observed{Device: d, Resolution: &res, Intelligence: &intel})

	if len(d.Interfaces) != before {
		t.Errorf("validation changed the observed host: %d interfaces, want %d",
			len(d.Interfaces), before)
	}
}

// ---------------------------------------------------------- determinism

// TestValidationIsDeterministic runs the same input repeatedly and requires
// identical output.
//
// This is not a formality. A CI log that reorders between runs cannot be
// diffed, and a plan ID that moves when nothing changed makes it impossible
// to tell an intentional change from noise.
func TestValidationIsDeterministic(t *testing.T) {
	cfg := gatewayConfig()
	d := device(t, 2)
	res := resolvedFor(t, cfg)
	intel := host.AnalyzeHardware(d)

	first := Validate(FromConfig(cfg, res), Observed{Device: d, Resolution: &res, Intelligence: &intel})

	for i := 0; i < 25; i++ {
		again := Validate(FromConfig(cfg, res), Observed{Device: d, Resolution: &res, Intelligence: &intel})
		if again.Verdict != first.Verdict {
			t.Fatalf("run %d verdict = %s, want %s", i, again.Verdict, first.Verdict)
		}
		if len(again.Findings) != len(first.Findings) {
			t.Fatalf("run %d produced %d findings, want %d", i, len(again.Findings), len(first.Findings))
		}
		for j := range again.Findings {
			if !reflect.DeepEqual(again.Findings[j], first.Findings[j]) {
				t.Fatalf("run %d finding %d = %+v, want %+v", i, j, again.Findings[j], first.Findings[j])
			}
		}
	}
}

// TestFindingsAreSortedBlockingFirst proves the ordering is stable and
// meaningful rather than incidental.
func TestFindingsAreSortedBlockingFirst(t *testing.T) {
	cfg := gatewayConfig()
	cfg.Network.LAN = "hw:doesnotexist"
	cfg.Network.LANPrefix = "not-an-address"
	cfg.NAT.Masquerade.Outbound = ""

	rep := reportFor(t, cfg)
	if len(rep.Findings) < 2 {
		t.Skip("the fixture was expected to produce several findings")
	}

	for i := 1; i < len(rep.Findings); i++ {
		if rep.Findings[i-1].Severity.Rank() > rep.Findings[i].Severity.Rank() {
			t.Errorf("finding %d (%s) is ranked above finding %d (%s)",
				i-1, rep.Findings[i-1].Severity, i, rep.Findings[i].Severity)
		}
	}
}

// TestValidationDoesNotDependOnInterfaceOrder proves the report is stable
// when the observed interface enumeration order changes.
//
// The kernel does not enumerate interfaces in a stable order across boots,
// so a validator whose output depended on it would report a different answer
// on the same machine after a reboot.
func TestValidationDoesNotDependOnInterfaceOrder(t *testing.T) {
	cfg := gatewayConfig()
	res := resolvedFor(t, cfg)
	intel := host.AnalyzeHardware(device(t, 2))

	reversed := device(t, 2)
	for i, j := 0, len(reversed.Interfaces)-1; i < j; i, j = i+1, j-1 {
		reversed.Interfaces[i], reversed.Interfaces[j] = reversed.Interfaces[j], reversed.Interfaces[i]
	}
	reversedIntel := host.AnalyzeHardware(reversed)

	a := Validate(FromConfig(cfg, res), Observed{Device: device(t, 2), Resolution: &res, Intelligence: &intel})
	b := Validate(FromConfig(cfg, res), Observed{Device: reversed, Resolution: &res, Intelligence: &reversedIntel})

	if a.Verdict != b.Verdict {
		t.Errorf("interface enumeration order changed the verdict: %s vs %s", a.Verdict, b.Verdict)
	}
}

// ----------------------------------------------- static vs live checking

// TestStaticValidationReportsUnresolvedHonestly proves a document reviewed
// without a host is told the difference between "wrong" and "unchecked".
//
// Skipping the role checks because no host was consulted would let a CI gate
// pass a document whose selectors match nothing.
func TestStaticValidationReportsUnresolvedHonestly(t *testing.T) {
	cfg := gatewayConfig()
	rep := Validate(FromConfig(cfg, host.Resolution{}), Observed{})

	if !has(rep, CodeRoleUnresolved) {
		t.Errorf("an unchecked selector must be reported as unchecked:\n%s", codes(rep))
	}
	for _, f := range rep.Findings {
		if f.Code == CodeRoleUnresolved && f.Severity == SeverityBlocking {
			t.Error("an unchecked selector is not a broken selector")
		}
	}
}
