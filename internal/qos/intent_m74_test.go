package qos

import (
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

// validIntent returns an Intent with all prerequisites satisfied and CAKE observed.
func validIntent() Intent {
	p := Policy{
		Enabled:   true,
		Interface: "enp0s31f6",
		Algorithm: AlgorithmCake,
		Bandwidth: Bandwidth{
			DownloadKbps: 100_000,
			UploadKbps:   20_000,
		},
		Limits: Limits{
			TargetMS:   5,
			IntervalMS: 100,
		},
	}
	role := LANRole{
		Selector:  "wan",
		Declared:  true,
		Resolved:  true,
		Interface: "enp0s31f6",
		StableID:  "hw:7c6170fd7f34317a",
	}
	cap := Evidence{
		State:  CapabilityAvailable,
		Source: "observed",
		Reason: "observed: a CAKE queue discipline is attached on this host",
	}
	return FromPolicy(p, role, cap, []string{"cake"})
}

func hasCode(rep Report, code string) bool {
	for _, f := range rep.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func codes(rep Report) []string {
	out := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		out = append(out, f.Code)
	}
	return out
}

// -----------------------------------------------------------------------------
// Intent Tests (Section 35: 1-14)
// -----------------------------------------------------------------------------

// 1. QoS disabled
func TestIntentQoSDisabled(t *testing.T) {
	in := validIntent()
	in.Enabled = false
	in.Policy.Enabled = false

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID for disabled QoS", rep.Verdict)
	}
	if !hasCode(rep, CodeQoSDisabled) {
		t.Errorf("expected code %s, got: %v", CodeQoSDisabled, codes(rep))
	}
	if len(rep.Blocking()) != 0 {
		t.Errorf("expected 0 blocking findings, got %d", len(rep.Blocking()))
	}
}

// 2. QoS enabled with valid configuration
func TestIntentQoSEnabledValid(t *testing.T) {
	in := validIntent()

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID; findings: %v", rep.Verdict, codes(rep))
	}
	if len(rep.Blocking()) != 0 {
		t.Errorf("expected 0 blocking findings, got: %v", rep.Blocking())
	}
}

// 3. Valid CAKE configuration
func TestIntentValidCakeConfiguration(t *testing.T) {
	in := validIntent()
	in.Algorithm = AlgorithmCake
	in.Policy.Algorithm = AlgorithmCake

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID; findings: %v", rep.Verdict, codes(rep))
	}
	if in.Algorithm != AlgorithmCake {
		t.Errorf("algorithm = %s, want cake", in.Algorithm)
	}
}

// 4. Missing WAN
func TestIntentMissingWAN(t *testing.T) {
	in := validIntent()
	in.RoleDeclared = false

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED when WAN is missing", rep.Verdict)
	}
	if !hasCode(rep, CodeWANMissing) {
		t.Errorf("expected code %s, got: %v", CodeWANMissing, codes(rep))
	}
}

// 5. Unresolved WAN (pending, does not claim CAKE unavailable)
func TestIntentUnresolvedWAN(t *testing.T) {
	in := validIntent()
	in.RoleDeclared = true
	in.RoleResolved = false
	in.RoleInterface = ""
	in.Policy.Interface = ""

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictPending {
		t.Fatalf("verdict = %s, want PENDING when WAN is unresolved", rep.Verdict)
	}
	if !hasCode(rep, CodeWANUnresolved) {
		t.Errorf("expected code %s, got: %v", CodeWANUnresolved, codes(rep))
	}
	// Must NOT report CAKE unavailable or unknown when link is unresolved.
	if hasCode(rep, CodeAlgorithmUnavailable) || hasCode(rep, CodeCakeUnavailable) {
		t.Errorf("unresolved WAN must not blame CAKE availability: %v", codes(rep))
	}
}

// 6. WAN/LAN role conflict
func TestIntentRoleConflict(t *testing.T) {
	in := validIntent()
	in.RoleConflict = true

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED for role conflict", rep.Verdict)
	}
	if !hasCode(rep, CodeWANConflict) {
		t.Errorf("expected code %s, got: %v", CodeWANConflict, codes(rep))
	}
}

// 7. Missing algorithm
func TestIntentMissingAlgorithm(t *testing.T) {
	in := validIntent()
	in.Algorithm = ""
	in.Policy.Algorithm = ""

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED when algorithm is missing", rep.Verdict)
	}
	if !hasCode(rep, CodeAlgorithmMissing) {
		t.Errorf("expected code %s, got: %v", CodeAlgorithmMissing, codes(rep))
	}
}

// 8. Unsupported algorithm
func TestIntentUnsupportedAlgorithm(t *testing.T) {
	in := validIntent()
	in.Algorithm = Algorithm("htb")
	in.Policy.Algorithm = Algorithm("htb")

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED when algorithm is unsupported", rep.Verdict)
	}
	if !hasCode(rep, CodeAlgorithmUnknown) {
		t.Errorf("expected code %s, got: %v", CodeAlgorithmUnknown, codes(rep))
	}
}

// 9. Missing download rate
func TestIntentMissingDownloadRate(t *testing.T) {
	in := validIntent()
	in.Bandwidth.DownloadKbps = 0
	in.Bandwidth.UploadKbps = 20_000
	in.Policy.Bandwidth = in.Bandwidth

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictPending {
		t.Fatalf("verdict = %s, want PENDING when download rate is missing", rep.Verdict)
	}
	if !hasCode(rep, CodeBandwidthZero) {
		t.Errorf("expected code %s, got: %v", CodeBandwidthZero, codes(rep))
	}
}

// 10. Missing upload rate
func TestIntentMissingUploadRate(t *testing.T) {
	in := validIntent()
	in.Bandwidth.DownloadKbps = 100_000
	in.Bandwidth.UploadKbps = 0
	in.Policy.Bandwidth = in.Bandwidth

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictPending {
		t.Fatalf("verdict = %s, want PENDING when upload rate is missing", rep.Verdict)
	}
	if !hasCode(rep, CodeBandwidthZero) {
		t.Errorf("expected code %s, got: %v", CodeBandwidthZero, codes(rep))
	}
}

// 11. Zero rate
func TestIntentZeroRate(t *testing.T) {
	in := validIntent()
	in.Bandwidth.DownloadKbps = 0
	in.Bandwidth.UploadKbps = 0
	in.Policy.Bandwidth = in.Bandwidth

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED when both rates are zero", rep.Verdict)
	}
	if !hasCode(rep, CodeBandwidthMissing) {
		t.Errorf("expected code %s, got: %v", CodeBandwidthMissing, codes(rep))
	}
}

// 12. Negative rate
func TestIntentNegativeRate(t *testing.T) {
	in := validIntent()
	in.Bandwidth.DownloadKbps = -100_000
	in.Policy.Bandwidth = in.Bandwidth

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED when rate is negative", rep.Verdict)
	}
	if !hasCode(rep, CodeBandwidthInvalid) {
		t.Errorf("expected code %s, got: %v", CodeBandwidthInvalid, codes(rep))
	}
}

// 13. Invalid rate representation (overflow / implausibly large)
func TestIntentInvalidRateRepresentation(t *testing.T) {
	in := validIntent()
	in.Bandwidth.DownloadKbps = 500_000_000 // 500 Gbps > 400 Gbps
	in.Policy.Bandwidth = in.Bandwidth

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED when rate is implausibly large", rep.Verdict)
	}
	if !hasCode(rep, CodeBandwidthInvalid) {
		t.Errorf("expected code %s, got: %v", CodeBandwidthInvalid, codes(rep))
	}
}

// 14. Stable WAN identity
func TestIntentPreservesStableWANIdentity(t *testing.T) {
	in := validIntent()
	if in.RoleStableID != "hw:7c6170fd7f34317a" {
		t.Errorf("stable ID = %q, want hw:7c6170fd7f34317a", in.RoleStableID)
	}
	if in.RoleInterface != "enp0s31f6" {
		t.Errorf("interface = %q, want enp0s31f6", in.RoleInterface)
	}
}

// -----------------------------------------------------------------------------
// Rate Validation Tests (Section 35: 1-5)
// -----------------------------------------------------------------------------

// 1. Small valid rate
func TestRateValidationSmall(t *testing.T) {
	in := validIntent()
	in.Bandwidth = Bandwidth{DownloadKbps: 512, UploadKbps: 128}
	in.Policy.Bandwidth = in.Bandwidth

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID for small rate (512/128 Kbps)", rep.Verdict)
	}
}

// 2. Typical broadband rate
func TestRateValidationTypicalBroadband(t *testing.T) {
	in := validIntent()
	in.Bandwidth = Bandwidth{DownloadKbps: 200_000, UploadKbps: 20_000}
	in.Policy.Bandwidth = in.Bandwidth

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID for broadband rate (200/20 Mbps)", rep.Verdict)
	}
}

// 3. High-speed rate (> 1 Gbps, e.g. 2.5 Gbps, 10 Gbps)
func TestRateValidationHighSpeed(t *testing.T) {
	in := validIntent()
	in.Bandwidth = Bandwidth{DownloadKbps: 2_500_000, UploadKbps: 2_500_000} // 2.5 Gbps
	in.Policy.Bandwidth = in.Bandwidth

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID for 2.5 Gbps rate", rep.Verdict)
	}

	in10g := validIntent()
	in10g.Bandwidth = Bandwidth{DownloadKbps: 10_000_000, UploadKbps: 10_000_000} // 10 Gbps
	in10g.Policy.Bandwidth = in10g.Bandwidth
	rep10g := ValidateIntent(in10g)
	if rep10g.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID for 10 Gbps rate", rep10g.Verdict)
	}
}

// 4. Boundary/overflow behavior
func TestRateValidationBoundaryBehavior(t *testing.T) {
	in := validIntent()
	in.Bandwidth = Bandwidth{DownloadKbps: -1, UploadKbps: 10_000}
	in.Policy.Bandwidth = in.Bandwidth

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED for negative rate", rep.Verdict)
	}
}

// 5. Deterministic canonical rate representation
func TestRateValidationBandwidthMbps(t *testing.T) {
	in := validIntent()
	in.Bandwidth = Bandwidth{DownloadKbps: 200_000, UploadKbps: 120_000}

	down, up := in.BandwidthMbps()
	if down != 200.0 || up != 120.0 {
		t.Errorf("BandwidthMbps = (%v, %v), want (200.0, 120.0)", down, up)
	}
}

// -----------------------------------------------------------------------------
// Capability Tests (Section 35: 1-9)
// -----------------------------------------------------------------------------

// 1. CAKE observed → valid/actionable
func TestCapabilityCakeObserved(t *testing.T) {
	in := validIntent()
	in.Capability = Evidence{
		State:  CapabilityAvailable,
		Source: "observed",
		Reason: "observed: a CAKE queue discipline is attached on this host",
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID when CAKE is observed; findings: %v", rep.Verdict, codes(rep))
	}
}

// 2. CAKE unknown → pending, but NOT unavailable
func TestCapabilityCakeUnknown(t *testing.T) {
	in := validIntent()
	in.Capability = Evidence{
		State:  CapabilityUnknown,
		Source: "probe",
		Reason: "tc is installed and answered a qdisc query, but CAKE was not attached",
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictPending {
		t.Fatalf("verdict = %s, want PENDING when CAKE is unknown", rep.Verdict)
	}
	if !hasCode(rep, CodeCakeUnknown) {
		t.Errorf("expected code %s, got: %v", CodeCakeUnknown, codes(rep))
	}
	if hasCode(rep, CodeCakeUnavailable) || hasCode(rep, CodeAlgorithmUnavailable) {
		t.Errorf("unknown CAKE must not be reported as unavailable: %v", codes(rep))
	}
}

// 3. CAKE confirmed unavailable → blocked
func TestCapabilityCakeUnavailable(t *testing.T) {
	in := validIntent()
	in.Capability = Evidence{
		State:  CapabilityUnavailable,
		Source: "observed",
		Reason: "observed: tc tool is not installed on this host",
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED when CAKE is confirmed unavailable", rep.Verdict)
	}
	if !hasCode(rep, CodeCakeUnavailable) {
		t.Errorf("expected code %s, got: %v", CodeCakeUnavailable, codes(rep))
	}
}

// 4. tc available + CAKE unknown → CAKE remains unknown
func TestCapabilityTCAvailableCakeUnknown(t *testing.T) {
	dev := &host.Device{
		Capabilities: map[host.Capability]host.CapabilityState{
			host.CapTC:   {Available: true, Confidence: host.ConfidenceObserved, Reason: "tc installed"},
			host.CapCake: {Available: false, Confidence: host.ConfidenceUnknown, Reason: "tc present, CAKE not attached"},
		},
	}

	ev := CakeCapability(dev)
	if ev.State != CapabilityUnknown {
		t.Errorf("CakeCapability state = %s, want %s", ev.State, CapabilityUnknown)
	}
}

// 5. Existing fq_codel → not misclassified as CAKE
func TestCapabilityFqCodelNotMisclassifiedAsCake(t *testing.T) {
	dev := &host.Device{
		TrafficControl: network.TCState{
			Checked:      true,
			Available:    true,
			CakeObserved: false,
			Qdiscs: []network.Qdisc{
				{Kind: "fq_codel", Device: "enp0s31f6"},
			},
		},
		Capabilities: map[host.Capability]host.CapabilityState{
			host.CapCake: {Available: false, Confidence: host.ConfidenceUnknown, Reason: "fq_codel attached, CAKE not attached"},
		},
	}

	ev := CakeCapability(dev)
	if ev.State != CapabilityUnknown {
		t.Errorf("CakeCapability state = %s, want unknown; fq_codel must not be classified as CAKE", ev.State)
	}
}

// 6. Existing CAKE → correctly observed
func TestCapabilityExistingCakeCorrectlyObserved(t *testing.T) {
	dev := &host.Device{
		TrafficControl: network.TCState{
			Checked:      true,
			Available:    true,
			CakeObserved: true,
			Qdiscs: []network.Qdisc{
				{Kind: "cake", Device: "enp0s31f6"},
			},
		},
		Capabilities: map[host.Capability]host.CapabilityState{
			host.CapCake: {Available: true, Confidence: host.ConfidenceObserved, Reason: "observed CAKE"},
		},
	}

	ev := CakeCapability(dev)
	if ev.State != CapabilityAvailable {
		t.Errorf("CakeCapability state = %s, want available", ev.State)
	}
}

// 7. Missing CAKE qdisc → does not prove CAKE unavailable
func TestCapabilityMissingCakeQdiscDoesNotProveUnavailable(t *testing.T) {
	dev := &host.Device{
		TrafficControl: network.TCState{
			Checked:      true,
			Available:    true,
			CakeObserved: false,
		},
		Capabilities: map[host.Capability]host.CapabilityState{
			host.CapCake: {Available: false, Confidence: host.ConfidenceUnknown, Reason: "CAKE not observed"},
		},
	}

	ev := CakeCapability(dev)
	if ev.State == CapabilityUnavailable {
		t.Error("missing CAKE qdisc must NOT prove CAKE unavailable")
	}
	if ev.State != CapabilityUnknown {
		t.Errorf("CakeCapability state = %s, want unknown", ev.State)
	}
}

// 8. Failed probe → does not become confirmed absence
func TestCapabilityFailedProbeDoesNotBecomeAbsence(t *testing.T) {
	dev := &host.Device{
		TrafficControl: network.TCState{
			Checked:   false,
			Available: false,
		},
		Capabilities: map[host.Capability]host.CapabilityState{
			host.CapCake: {Available: false, Confidence: host.ConfidenceUnknown, Reason: "probe failed"},
		},
	}

	ev := CakeCapability(dev)
	if ev.State == CapabilityUnavailable {
		t.Error("failed probe must not become confirmed absence")
	}
	if ev.State != CapabilityUnknown {
		t.Errorf("state = %s, want unknown", ev.State)
	}
}

// 9. Evidence remains connected to capability verdict
func TestCapabilityEvidenceFields(t *testing.T) {
	dev := &host.Device{
		Capabilities: map[host.Capability]host.CapabilityState{
			host.CapCake: {Available: true, Confidence: host.ConfidenceObserved, Reason: "verified"},
		},
	}

	ev := CakeCapability(dev)
	if ev.State != CapabilityAvailable {
		t.Errorf("state = %s, want available", ev.State)
	}
	if ev.Source == "" {
		t.Error("evidence source must not be empty")
	}
	if ev.Reason == "" {
		t.Error("evidence reason must not be empty")
	}
}

// TestCapabilityInferredNeverTreatedAsObserved asserts that ConfidenceInferred
// lands on unknown rather than available.
func TestCapabilityInferredNeverTreatedAsObserved(t *testing.T) {
	ev := CapabilityFrom(true, host.ConfidenceInferred, "inferred capability")
	if ev.State == CapabilityAvailable {
		t.Error("ConfidenceInferred must never be treated as CapabilityAvailable")
	}
	if ev.State != CapabilityUnknown {
		t.Errorf("state = %s, want unknown", ev.State)
	}
}

// TestUnmanagedQdiscReportedWithCode asserts that existing qdiscs generate
// the CodeExistingQdiscUnmanaged info finding.
func TestUnmanagedQdiscReportedWithCode(t *testing.T) {
	in := validIntent()
	in.ObservedQdiscs = []string{"fq_codel"}

	rep := ValidateIntent(in)
	if !hasCode(rep, CodeExistingQdiscUnmanaged) {
		t.Errorf("expected code %s for unmanaged qdisc, got: %v", CodeExistingQdiscUnmanaged, codes(rep))
	}
}
