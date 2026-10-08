package validation

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/diff"
)

// valid returns a configuration that passes every check.
func valid() config.Config {
	cfg := config.Defaults()
	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "enx001122334455"
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.QoS.Enabled = true
	cfg.QoS.Algorithm = "cake"
	cfg.QoS.Interface = "enp0s31f6"
	cfg.QoS.DownloadKbps = 100000
	cfg.QoS.UploadKbps = 20000
	if err := cfg.Normalize(); err != nil {
		panic(err)
	}
	return cfg
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

// hasMessage reports whether any finding contains the given substring.
func hasMessage(r Result, substr string) bool {
	for _, f := range r.Findings {
		if strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func TestValidConfigurationPasses(t *testing.T) {
	r := Static(valid())

	if !r.Valid {
		t.Errorf("a valid configuration must pass, got:")
		for _, f := range r.Errors() {
			t.Errorf("  %s: %s", f.Field, f.Message)
		}
	}
}

func TestStaticRunsOnlyStaticLayer(t *testing.T) {
	r := Static(valid())

	if len(r.Layers) != 1 || r.Layers[0] != LayerStatic {
		t.Errorf("layers = %v, want [static]", r.Layers)
	}
}

// TestStaticIsDeterministic is what makes this usable as a CI gate: the same
// document must always produce the same findings, on any machine.
func TestStaticIsDeterministic(t *testing.T) {
	cfg := valid()
	cfg.Network.LANPrefix = "10.77.0.1/31" // narrow, triggers a warning
	cfg.Firewall.DefaultInboundPolicy = "accept"

	first := Static(cfg)
	for i := 0; i < 10; i++ {
		next := Static(cfg)
		if next.ErrorCount != first.ErrorCount || next.WarningCount != first.WarningCount {
			t.Fatalf("finding counts vary: %d/%d then %d/%d",
				first.ErrorCount, first.WarningCount, next.ErrorCount, next.WarningCount)
		}
		for j := range next.Findings {
			if next.Findings[j].Field != first.Findings[j].Field {
				t.Fatalf("finding order varies at %d: %q then %q",
					j, first.Findings[j].Field, next.Findings[j].Field)
			}
		}
	}
}

func TestFindingsAreSortedBySeverity(t *testing.T) {
	cfg := valid()
	cfg.Network.LANPrefix = "203.0.113.1/24" // public, warns
	cfg.QoS.UploadKbps = 200000              // exceeds download, warns
	cfg.Network.MTU = 100                    // errors

	r := Static(cfg)

	var lastRank = -1
	for _, f := range r.Findings {
		rank := f.Severity.rank()
		if rank < lastRank {
			t.Errorf("findings are not sorted by severity: %v after rank %d", f.Severity, lastRank)
		}
		lastRank = rank
	}
}

func TestInvalidLANPrefixIsError(t *testing.T) {
	cfg := valid()
	cfg.Network.LANPrefix = "not-a-prefix"

	r := Static(cfg)

	if r.Valid {
		t.Fatal("an invalid prefix must fail validation")
	}
	if !hasError(r, "network.lan_prefix") {
		t.Errorf("expected an error on network.lan_prefix, got %v", r.Errors())
	}
}

func TestLoopbackLANPrefixIsError(t *testing.T) {
	cfg := valid()
	cfg.Network.LANPrefix = "127.0.0.1/8"

	if !hasError(Static(cfg), "network.lan_prefix") {
		t.Error("a loopback LAN prefix must be an error")
	}
}

func TestPublicLANPrefixIsWarning(t *testing.T) {
	// A public LAN is legal but almost certainly a mistake, so it warns
	// rather than blocking.
	cfg := valid()
	cfg.Network.LANPrefix = "203.0.113.1/24"

	r := Static(cfg)

	if !hasFinding(r, "network.lan_prefix", SeverityWarning) {
		t.Error("a public LAN prefix should warn")
	}
}

func TestNarrowLANPrefixWarns(t *testing.T) {
	cfg := valid()
	cfg.Network.LANPrefix = "10.77.0.1/31"

	if !hasFinding(Static(cfg), "network.lan_prefix", SeverityWarning) {
		t.Error("a /31 LAN should warn about usable addresses")
	}
}

// An IPv6 LAN prefix panicked this layer.
//
// The narrow-prefix rule read prefix.Bits() and passed it to a helper that
// computed 1 << (32 - bits). Every IPv6 LAN prefix has Bits() above 32, so the
// shift count went negative and the process died — `thn validate` on a
// perfectly valid fd00::/64 configuration took the CLI down with it.
//
// The rule was written for IPv4 and applied to both families; /64 is the
// ordinary IPv6 LAN size and is not remotely too narrow.
func TestIPv6LANPrefixDoesNotPanicAndIsNotCalledNarrow(t *testing.T) {
	// fd00::/8 is unique-local, so a LAN prefix in it is unremarkable in
	// every respect. 2001:db8::/32 is the documentation range: it warns about
	// being public, which is correct and unrelated to size, so it is asserted
	// separately below.
	for _, prefix := range []string{"fd00::1/64", "fd00::1/48", "fd00::1/127"} {
		cfg := valid()
		cfg.Network.LANPrefix = prefix

		r := Static(cfg)

		if !r.Valid {
			t.Errorf("prefix %q should be valid, got %v", prefix, r.Errors())
		}
		for _, f := range r.Warnings() {
			if f.Field == "network.lan_prefix" {
				t.Errorf("prefix %q must not be reported as too narrow: %s", prefix, f.Message)
			}
		}
	}
}

// A public IPv6 prefix warns, and it must warn for the right reason.
func TestPublicIPv6LANPrefixWarnsAboutBeingPublic(t *testing.T) {
	cfg := valid()
	cfg.Network.LANPrefix = "2001:db8::1/64"

	r := Static(cfg)

	if !r.Valid {
		t.Errorf("a documentation-range prefix is legal, got %v", r.Errors())
	}

	var warned bool
	for _, f := range r.Warnings() {
		if f.Field == "network.lan_prefix" && strings.Contains(f.Message, "public") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("a public IPv6 prefix should warn about being public, got %v", r.Warnings())
	}
}

func TestGatewayInsideLANIsError(t *testing.T) {
	// A default route pointing back into the LAN is a routing loop.
	cfg := valid()
	cfg.Network.UpstreamGateway = "10.77.0.99"

	r := Static(cfg)

	if r.Valid {
		t.Fatal("a gateway inside the LAN must fail validation")
	}
	if !hasError(r, "network.upstream_gateway") {
		t.Errorf("expected an error on network.upstream_gateway, got %v", r.Errors())
	}
}

func TestMTUBounds(t *testing.T) {
	for _, mtu := range []int{100, 500, 9500} {
		cfg := valid()
		cfg.Network.MTU = mtu
		if !hasError(Static(cfg), "network.mtu") {
			t.Errorf("MTU %d must be rejected", mtu)
		}
	}

	for _, mtu := range []int{576, 1500, 9000} {
		cfg := valid()
		cfg.Network.MTU = mtu
		if hasError(Static(cfg), "network.mtu") {
			t.Errorf("MTU %d must be accepted", mtu)
		}
	}
}

func TestInvalidResolverIsError(t *testing.T) {
	cfg := valid()
	cfg.Network.DNS = []string{"1.1.1.1", "not-an-ip"}

	if !hasError(Static(cfg), "network.dns[1]") {
		t.Error("an invalid resolver must be an error")
	}
}

func TestUnspecifiedResolverIsError(t *testing.T) {
	cfg := valid()
	cfg.Network.DNS = []string{"0.0.0.0"}

	if !hasError(Static(cfg), "network.dns[0]") {
		t.Error("the unspecified address must not be accepted as a resolver")
	}
}

func TestUnsupportedFirewallBackendIsError(t *testing.T) {
	cfg := valid()
	cfg.Firewall.Backend = "iptables"

	r := Static(cfg)

	if !hasError(r, "firewall.backend") {
		t.Error("only nftables is supported")
	}
}

func TestUnsupportedQoSAlgorithmIsError(t *testing.T) {
	cfg := valid()
	cfg.QoS.Algorithm = "htb"

	if !hasError(Static(cfg), "qos.algorithm") {
		t.Error("only cake is supported")
	}
}

func TestNonPositiveQoSRatesAreErrors(t *testing.T) {
	cfg := valid()
	cfg.QoS.DownloadKbps = 0

	r := Static(cfg)

	if !hasError(r, "qos.download_kbps") {
		t.Error("a zero download rate must be rejected when QoS is enabled")
	}
}

func TestMasqueradeFromWANIsError(t *testing.T) {
	cfg := valid()
	cfg.NAT.Interfaces = []string{cfg.Network.WAN}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	if !hasError(Static(cfg), "nat.interfaces[0]") {
		t.Error("masquerading from the WAN must be rejected")
	}
}

func TestQoSOnLANInterfaceWarns(t *testing.T) {
	// Shaping the LAN is meaningless: shaping applies to the egress device,
	// and the constrained link is the uplink.
	cfg := valid()
	cfg.QoS.Interface = cfg.Network.LAN

	if !hasFinding(Static(cfg), "qos.interface", SeverityWarning) {
		t.Error("shaping the LAN should warn")
	}
}

func TestDropFirewallWithoutNATWarns(t *testing.T) {
	// The LAN would be able to reach nothing: outbound is unfiltered but
	// return traffic is dropped.
	cfg := valid()
	cfg.NAT.Enabled = false
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	r := Static(cfg)

	if !hasFinding(r, "firewall.default_inbound_policy", SeverityWarning) {
		t.Error("drop-by-default without NAT should warn")
	}
}

// TestPhysicalPresenceMustStayTrue is the safety test for the most important
// gate in the system.
func TestPhysicalPresenceMustStayTrue(t *testing.T) {
	cfg := valid()
	cfg.Activation.RequirePhysicalPresence = false

	r := Static(cfg)

	if r.Valid {
		t.Fatal("disabling the physical-presence gate must fail validation")
	}
	if !hasError(r, "activation.require_physical_presence") {
		t.Errorf("expected an error on activation.require_physical_presence, got %v", r.Errors())
	}
	if !hasMessage(r, "unattended") {
		t.Error("the finding should explain why the gate exists")
	}
}

func TestUnsupportedSchemaVersionIsError(t *testing.T) {
	cfg := valid()
	cfg.SchemaVersion = config.SchemaVersion + 10

	r := Static(cfg)

	if r.Valid {
		t.Fatal("an unknown schema version must fail validation")
	}
	if !hasError(r, "schema_version") {
		t.Errorf("expected an error on schema_version, got %v", r.Errors())
	}
}

func TestUnsatisfiedSubscriptionIsNotAnError(t *testing.T) {
	// Not having a LAN identified is the expected development state, so it
	// must be informational rather than blocking.
	cfg := valid()
	cfg.Network.LAN = ""
	cfg.NAT.Interfaces = nil
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	r := Static(cfg)

	if !r.Valid {
		t.Errorf("an unidentified LAN must not fail validation, got: %v", r.Errors())
	}
	if !hasFinding(r, "nat.interfaces", SeverityInfo) {
		t.Errorf("expected an informational finding about the unidentified LAN, got %v", r.Findings)
	}
}

func TestErrorsAndWarningsAccessors(t *testing.T) {
	cfg := valid()
	cfg.Network.MTU = 100                    // error
	cfg.Network.LANPrefix = "203.0.113.1/24" // warning

	r := Static(cfg)

	if len(r.Errors()) == 0 {
		t.Error("Errors() must return the error findings")
	}
	if len(r.Warnings()) == 0 {
		t.Error("Warnings() must return the warning findings")
	}
	for _, f := range r.Errors() {
		if f.Severity != SeverityError {
			t.Errorf("Errors() returned a %s finding", f.Severity)
		}
	}
}

func TestLiveLayerOnSupportedHost(t *testing.T) {
	cfg := valid()
	obs := diff.Observed{
		Supported:           true,
		WANPresent:          true,
		WANName:             cfg.Network.WAN,
		WANUp:               true,
		LANPresent:          true,
		LANName:             cfg.Network.LAN,
		IPv4ForwardingKnown: true,
	}
	d := diff.Compare(obs, diff.Desired{})

	r := Combined(cfg, &obs, d)

	if len(r.Layers) != 2 {
		t.Errorf("layers = %v, want [static live]", r.Layers)
	}
	if hasError(r, "network.wan") {
		t.Error("a present, correctly named WAN must not fail live validation")
	}
}

func TestLiveLayerFlagsMissingWAN(t *testing.T) {
	cfg := valid()
	obs := diff.Observed{
		Supported:           true,
		WANPresent:          true,
		WANName:             "eth9", // not the configured name
		IPv4ForwardingKnown: true,
	}
	d := diff.Compare(obs, diff.Desired{})

	r := Combined(cfg, &obs, d)

	if !hasError(r, "network.wan") {
		t.Error("a WAN name that does not exist on the host must fail")
	}
}

func TestLiveLayerOnUnsupportedPlatform(t *testing.T) {
	// Without an observation, live validation cannot run; it must say so
	// rather than pretending to have checked.
	cfg := valid()
	obs := diff.Observed{Supported: false}

	r := Combined(cfg, &obs, diff.Result{})

	if !hasFinding(r, "", SeverityWarning) {
		t.Errorf("expected a warning that host inspection was unavailable, got %v", r.Findings)
	}
}

func TestCombinedWithoutObservationIsStaticOnly(t *testing.T) {
	r := Combined(valid(), nil, diff.Result{})

	if len(r.Layers) != 1 || r.Layers[0] != LayerStatic {
		t.Errorf("layers = %v, want [static] when no observation is supplied", r.Layers)
	}
}

// TestCombinedReportsStaticErrorsFirst asserts the merge order, because the
// CI gate must report document errors before host mismatches: a typo in the
// document is worth knowing about even when the host is not the right machine.
//
// Findings sort by severity first and layer second, so this asserts that no
// live finding ever precedes a static one at the same severity.
func TestCombinedReportsStaticErrorsFirst(t *testing.T) {
	cfg := valid()
	cfg.Network.MTU = 100                                                    // static error
	obs := diff.Observed{Supported: true, WANPresent: true, WANName: "eth9"} // live error
	d := diff.Compare(obs, diff.Desired{})

	r := Combined(cfg, &obs, d)

	if len(r.Findings) < 2 {
		t.Fatalf("expected both static and live findings, got %d", len(r.Findings))
	}

	var sawStaticError bool
	for _, f := range r.Findings {
		if f.Severity != SeverityError {
			continue
		}
		if f.Layer == LayerStatic {
			sawStaticError = true
			continue
		}
		if sawStaticError {
			t.Errorf("a live error (%s) appears after a static error", f.Field)
		}
	}
}

func TestFindingStringIncludesHint(t *testing.T) {
	f := Finding{
		Layer:    LayerStatic,
		Field:    "network.wan",
		Severity: SeverityError,
		Message:  "the WAN is missing",
		Hint:     "set it to enp0s31f6",
	}

	s := f.String()
	for _, want := range []string{"error", "static", "network.wan", "the WAN is missing", "set it to enp0s31f6"} {
		if !strings.Contains(s, want) {
			t.Errorf("finding string missing %q: %s", want, s)
		}
	}
}

func TestCountsMatchFindings(t *testing.T) {
	cfg := valid()
	cfg.Network.MTU = 100
	cfg.Network.LANPrefix = "203.0.113.1/24"

	r := Static(cfg)

	if r.ErrorCount+r.WarningCount+r.InfoCount != len(r.Findings) {
		t.Errorf("counts %d+%d+%d do not match %d findings",
			r.ErrorCount, r.WarningCount, r.InfoCount, len(r.Findings))
	}
	if r.Valid != (r.ErrorCount == 0) {
		t.Errorf("Valid = %v but ErrorCount = %d", r.Valid, r.ErrorCount)
	}
}
