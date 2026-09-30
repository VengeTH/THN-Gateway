package policy

import (
	"strings"
	"testing"
)

// complete returns a policy that passes every check, with both interfaces
// identified.
func complete() Policy {
	p := Default()
	p.Interfaces.WAN = "enp0s31f6"
	p.Interfaces.LAN = "enx001122334455"
	p.Admin.Source = []string{"203.0.113.0/24"}
	p.AntiSpoofing.LANPrefix = "10.77.0.1/24"
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

func TestDefaultPolicyIsValid(t *testing.T) {
	p := Default()
	p.Interfaces.WAN = "enp0s31f6"
	p.Interfaces.LAN = "enx0011"
	p.Admin.Source = []string{"203.0.113.0/24"}

	r := Validate(p)
	if !r.Valid {
		t.Errorf("the default policy must be valid, got:")
		for _, f := range r.Errors() {
			t.Errorf("  %s: %s", f.Field, f.Message)
		}
	}
	if !r.Reachable {
		t.Error("the default policy must leave the admin path reachable")
	}
}

// TestReachabilityIsTheCentralCheck covers the failure that matters most: a
// structurally perfect policy that still locks the operator out.
func TestReachabilityIsTheCentralCheck(t *testing.T) {
	p := complete()
	p.Admin.Enabled = false

	r := Validate(p)

	if r.Valid {
		t.Error("a policy with no admin path must not validate")
	}
	if !hasError(r, "admin") {
		t.Error("expected an error on admin")
	}
	if r.Reachable {
		t.Error("Reachable must be false when admin access is disabled")
	}
	if len(r.Trace) == 0 {
		t.Error("an unreachable policy must explain how it concluded that")
	}
}

func TestAdminWithNoPortsIsUnreachable(t *testing.T) {
	// An admin service with no ports emits no accept rule, so the default
	// drop policy applies to the operator's own traffic.
	p := complete()
	p.Admin.Service.Ports = nil

	r := Validate(p)

	if r.Reachable {
		t.Error("an admin service with no ports cannot be reachable")
	}
	if !hasError(r, "admin") {
		t.Error("expected an error on admin")
	}
}

func TestAdminWithInvalidPortIsUnreachable(t *testing.T) {
	// A port range that cannot be rendered must not be counted as rescuing
	// reachability: validation would refuse it anyway.
	p := complete()
	p.Admin.Service.Ports = []PortRange{{Low: 70000, High: 80000}}

	r := Validate(p)

	if r.Reachable {
		t.Error("an unrenderable admin port range cannot make the device reachable")
	}
}

func TestNoWANDoesNotImplyLockout(t *testing.T) {
	// Without a WAN interface nothing can reach the device from the WAN, so
	// this is not a lockout — it is simply not deployed yet.
	p := Default()
	p.Interfaces.WAN = ""
	p.Interfaces.LAN = "enx0011"
	p.Admin.Source = []string{"203.0.113.0/24"}

	r := Validate(p)

	if !r.Reachable {
		t.Error("an unidentified WAN is not a lockout")
	}
	if !r.Valid {
		t.Errorf("the policy should still be valid, got: %v", r.Errors())
	}
}

func TestOpenAdminSourceWarns(t *testing.T) {
	p := complete()
	p.Admin.Source = nil

	r := Validate(p)

	if !r.Valid {
		t.Error("an open admin source is a risk, not an error")
	}
	if !hasFinding(r, "admin.source", SeverityWarning) {
		t.Error("administration from any source must warn")
	}
}

func TestWideAdminSourceWarns(t *testing.T) {
	p := complete()
	p.Admin.Source = []string{"0.0.0.0/0"}

	r := Validate(p)

	if !hasFinding(r, "admin.source", SeverityWarning) {
		t.Error("administration from 0.0.0.0/0 must warn")
	}
}

func TestNarrowAdminSourceDoesNotWarn(t *testing.T) {
	p := complete()
	p.Admin.Source = []string{"203.0.113.0/24"}

	r := Validate(p)

	if hasFinding(r, "admin.source", SeverityWarning) {
		t.Error("a narrow admin source should not warn")
	}
}

// TestICMPBlockedEverywhereIsAnError covers the PMTU black hole: the failure
// presents as an intermittent hang and is very hard to diagnose.
func TestICMPBlockedEverywhereIsAnError(t *testing.T) {
	p := complete()
	p.ICMP.AllowWAN = false
	p.ICMP.AllowLAN = false

	r := Validate(p)

	if r.Valid {
		t.Error("blocking ICMP everywhere must be an error")
	}
	if !hasError(r, "icmp") {
		t.Error("expected an error on icmp")
	}
}

func TestNoForwardingIsAnError(t *testing.T) {
	p := complete()
	p.Forward.LANToWAN = false

	r := Validate(p)

	if r.Valid {
		t.Error("a gateway that forwards nothing must be an error")
	}
	if !hasError(r, "forward.lan_to_wan") {
		t.Error("expected an error on forward.lan_to_wan")
	}
}

func TestWANToLANWarns(t *testing.T) {
	p := complete()
	p.Forward.WANToLAN = true

	r := Validate(p)

	if !r.Valid {
		t.Error("permitting WAN-to-LAN is a risk, not an error")
	}
	if !hasFinding(r, "forward.wan_to_lan", SeverityWarning) {
		t.Error("exposing the LAN must warn")
	}
}

func TestSameInterfaceForBothRolesIsError(t *testing.T) {
	p := complete()
	p.Interfaces.LAN = p.Interfaces.WAN

	r := Validate(p)

	if !hasError(r, "interfaces.lan") {
		t.Error("the WAN and LAN must be different interfaces")
	}
}

func TestPortRangeValidation(t *testing.T) {
	cases := []struct {
		name    string
		ports   []PortRange
		wantErr bool
	}{
		{"valid single", []PortRange{Single(22)}, false},
		{"valid range", []PortRange{{Low: 100, High: 200}}, false},
		{"port zero", []PortRange{Single(0)}, true},
		{"port too high", []PortRange{Single(70000)}, true},
		{"inverted", []PortRange{{Low: 200, High: 100}}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := complete()
			p.Admin.Service.Ports = c.ports

			r := Validate(p)
			if c.wantErr && r.Valid {
				t.Errorf("%v must be rejected", c.ports)
			}
			if !c.wantErr && !r.Valid {
				t.Errorf("%v must be accepted: %v", c.ports, r.Errors())
			}
		})
	}
}

func TestInvertedPortRangeFails(t *testing.T) {
	p := complete()
	p.Admin.Service.Ports = []PortRange{{Low: 443, High: 80}}

	r := Validate(p)

	if !hasError(r, "admin.service") {
		t.Errorf("an inverted range must be rejected, got %v", r.Findings)
	}
}

func TestNoPortsIsError(t *testing.T) {
	p := complete()
	p.Services = []Service{{Name: "dns", Protocol: ProtoUDP}}

	r := Validate(p)

	if !hasError(r, "services[0]") {
		t.Error("a service with no ports must be rejected")
	}
}

func TestDuplicateServiceNameIsError(t *testing.T) {
	p := complete()
	p.Services = []Service{{Name: "ssh", Protocol: ProtoTCP, Ports: []PortRange{Single(2222)}}}

	r := Validate(p)

	if !hasError(r, "services[0]") {
		t.Error("a service duplicating the admin name must be rejected")
	}
}

func TestPortShadowingAdminWarns(t *testing.T) {
	// A service on the admin port could shadow the admin rule, which is a
	// lockout risk rather than a cosmetic problem.
	p := complete()
	p.Services = []Service{{Name: "alternate-ssh", Protocol: ProtoTCP, Ports: []PortRange{Single(22)}}}

	r := Validate(p)

	if !hasFinding(r, "services[0]", SeverityWarning) {
		t.Error("a service sharing the admin port must warn")
	}
}

func TestICMPServiceWithPortsWarns(t *testing.T) {
	p := complete()
	p.Services = []Service{{
		Name: "ping", Protocol: ProtoICMP, Ports: []PortRange{Single(0)},
	}}

	r := Validate(p)

	if !hasFinding(r, "services[0]", SeverityWarning) {
		t.Error("declaring ports on an ICMP service must warn")
	}
}

func TestInvalidSourceIsError(t *testing.T) {
	p := complete()
	p.Admin.Source = []string{"not-a-prefix"}

	r := Validate(p)

	if !hasError(r, "source") {
		t.Error("an invalid source prefix must be rejected")
	}
}

func TestUnknownVersionIsError(t *testing.T) {
	p := complete()
	p.Version = "99"

	if !hasError(Validate(p), "version") {
		t.Error("an unknown policy version must be rejected")
	}
}

func TestUnknownFamilyIsError(t *testing.T) {
	p := complete()
	p.Family = "ipv4"

	if !hasError(Validate(p), "family") {
		t.Error("an unsupported address family must be rejected")
	}
}

func TestWhitespaceTableNameIsError(t *testing.T) {
	p := complete()
	p.Table = "my table"

	if !hasError(Validate(p), "table") {
		t.Error("a table name with whitespace must be rejected")
	}
}

func TestUnscopedMasqueradeWarns(t *testing.T) {
	p := complete()
	p.Masquerade.OutInterface = ""

	r := Validate(p)

	if !hasFinding(r, "masquerade.out_interface", SeverityWarning) {
		t.Error("masquerading without an outbound interface must warn")
	}
}

func TestAntiSpoofingWithoutPrefixWarns(t *testing.T) {
	p := complete()
	p.AntiSpoofing.LANPrefix = ""

	r := Validate(p)

	if !hasFinding(r, "anti_spoofing.lan_prefix", SeverityWarning) {
		t.Error("anti-spoofing without a prefix must warn")
	}
}

func TestUnlimitedLoggingWarns(t *testing.T) {
	p := complete()
	p.Logging.Enabled = true
	p.Logging.RateLimit = 0

	r := Validate(p)

	if !hasFinding(r, "logging.rate_limit", SeverityWarning) {
		t.Error("unlimited logging must warn")
	}
}

func TestNegativeRateLimitIsError(t *testing.T) {
	p := complete()
	p.Logging.Enabled = true
	p.Logging.RateLimit = -1

	if !hasError(Validate(p), "logging.rate_limit") {
		t.Error("a negative rate limit must be rejected")
	}
}

func TestMissingInterfacesAreInformational(t *testing.T) {
	// Not having a LAN identified is the expected development state.
	p := Default()
	p.Interfaces.WAN = "enp0s31f6"

	r := Validate(p)

	if !hasFinding(r, "interfaces.lan", SeverityInfo) {
		t.Error("an unidentified LAN must be reported as informational")
	}
	if !r.Valid {
		t.Errorf("an unidentified LAN must not fail validation: %v", r.Errors())
	}
}

func TestFindingsAreSortedBySeverity(t *testing.T) {
	p := Default()
	p.Interfaces.WAN = "enp0s31f6"
	p.Forward.LANToWAN = false // error
	p.Forward.WANToLAN = true  // warning
	p.ICMP.AllowWAN = false    // error

	r := Validate(p)

	last := -1
	for _, f := range r.Findings {
		rank := f.Severity.rank()
		if rank < last {
			t.Errorf("findings not sorted by severity: %s after rank %d", f.Severity, last)
		}
		last = rank
	}
}

func TestValidationIsDeterministic(t *testing.T) {
	// Two renders of the same policy must produce the same findings, or a
	// ruleset that has not changed would appear to change.
	p := Default()
	p.Interfaces.WAN = "enp0s31f6"
	p.Interfaces.LAN = "enx0011"

	first := Validate(p)
	for i := 0; i < 5; i++ {
		next := Validate(p)
		if len(next.Findings) != len(first.Findings) {
			t.Fatalf("finding count varies: %d then %d", len(first.Findings), len(next.Findings))
		}
		for j := range next.Findings {
			if next.Findings[j].Field != first.Findings[j].Field {
				t.Fatalf("finding order varies at %d: %q then %q",
					j, first.Findings[j].Field, next.Findings[j].Field)
			}
		}
	}
}

func TestCloneIsDeep(t *testing.T) {
	p := complete()
	p.Services = []Service{{Name: "dns", Ports: []PortRange{Single(53)}}}

	c := p.Clone()
	c.Services[0].Ports[0] = Single(9999)
	c.Admin.Source[0] = "10.0.0.0/8"

	if p.Services[0].Ports[0] != Single(53) {
		t.Error("Clone must not share the port slice")
	}
	if p.Admin.Source[0] != "203.0.113.0/24" {
		t.Error("Clone must not share the source slice")
	}
}

func TestNormalizeSortsServicesButNotComments(t *testing.T) {
	p := complete()
	p.Services = []Service{
		{Name: "zebra", Ports: []PortRange{Single(90), Single(80)}},
		{Name: "alpha", Ports: []PortRange{Single(10)}},
	}
	p.Comments = []string{"zebra first", "alpha second"}

	p.Normalize()

	if p.Services[0].Name != "alpha" {
		t.Errorf("services must be sorted for deterministic rendering, got %q first", p.Services[0].Name)
	}
	if p.Comments[0] != "zebra first" {
		t.Errorf("comments are ordered prose and must not be sorted, got %q first", p.Comments[0])
	}
}

func TestAllInboundServicesPutsAdminFirst(t *testing.T) {
	p := complete()
	p.Services = []Service{
		{Name: "https", Protocol: ProtoTCP, Ports: []PortRange{Single(443)}},
	}

	got := p.AllInboundServices()

	if len(got) == 0 || got[0].Name != "ssh" {
		t.Errorf("the admin service must come first, got %v", got)
	}
}

func TestPortRangeString(t *testing.T) {
	if got := Single(22).String(); got != "22" {
		t.Errorf("single port renders as %q, want 22", got)
	}
	if got := (PortRange{Low: 100, High: 200}).String(); got != "100-200" {
		t.Errorf("range renders as %q, want 100-200", got)
	}
	if !(PortRange{Low: 5, High: 5}).IsSingle() {
		t.Error("5-5 is a single port")
	}
}

func TestFindingStringIncludesHint(t *testing.T) {
	f := Finding{
		Field:    "icmp",
		Severity: SeverityError,
		Message:  "ICMP is blocked everywhere",
		Hint:     "permit PMTU discovery",
	}

	s := f.String()
	for _, want := range []string{"error", "icmp", "ICMP is blocked everywhere", "permit PMTU discovery"} {
		if !strings.Contains(s, want) {
			t.Errorf("finding string missing %q: %s", want, s)
		}
	}
}
