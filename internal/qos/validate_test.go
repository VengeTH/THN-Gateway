package qos

import (
	"strings"
	"testing"
	"time"
)

// validPolicy returns a policy that passes validation with no findings, so a
// test can change one thing and attribute any finding to that change.
func validPolicy() Policy {
	p := Default()
	p.Enabled = true
	p.Interface = "eth0"
	p.Algorithm = AlgorithmCake
	p.MTU = 1500
	return p.WithBandwidth(100_000, 20_000)
}

// cakeAvailable is the ordinary case for validation.
func cakeAvailable() Availability {
	return Availability{Algorithms: setOf(AlgorithmCake, AlgorithmFqCodel), CheckedAt: time.Now()}
}

// hasFinding reports whether a finding exists for a field at a severity.
func hasFinding(r Result, field string, sev Severity) bool {
	for _, f := range r.Findings {
		if f.Field == field && f.Severity == sev {
			return true
		}
	}
	return false
}

// findingFields lists the fields with findings at a severity.
func findingFields(r Result, sev Severity) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Severity == sev {
			out = append(out, f.Field)
		}
	}
	return out
}

// TestValidateAcceptsAWellFormedPolicy is the baseline every other test is
// measured against: if this fails, the failures below prove nothing.
func TestValidateAcceptsAWellFormedPolicy(t *testing.T) {
	r := Validate(validPolicy(), cakeAvailable())

	if !r.Valid {
		t.Errorf("policy rejected: %v", findingFields(r, SeverityError))
	}
	if r.ErrorCount != 0 {
		t.Errorf("error count = %d, want 0: %v", r.ErrorCount, findingFields(r, SeverityError))
	}
	if r.Selection.Algorithm != AlgorithmCake {
		t.Errorf("selected %q, want cake", r.Selection.Algorithm)
	}
	if r.Selection.Degraded {
		t.Error("degraded = true, want false when cake is available")
	}
}

// TestValidateRejectsMissingBandwidth: a shaper with no rate has nothing to
// shape toward, and rendering a command anyway would produce a config that
// looks complete and does nothing.
func TestValidateRejectsMissingBandwidth(t *testing.T) {
	p := validPolicy()
	p.Bandwidth = Bandwidth{OverheadPercent: 10}

	r := Validate(p, cakeAvailable())

	if r.Valid {
		t.Error("a policy with no bandwidth must not be valid")
	}
	if !hasFinding(r, "bandwidth", SeverityError) {
		t.Errorf("no bandwidth error; findings: %v", findingFields(r, SeverityError))
	}
}

// TestValidateRejectsMissingInterface: shaping needs somewhere to be applied.
func TestValidateRejectsMissingInterface(t *testing.T) {
	p := validPolicy()
	p.Interface = ""

	r := Validate(p, cakeAvailable())

	if r.Valid {
		t.Error("a policy with no interface must not be valid")
	}
	if !hasFinding(r, "interface", SeverityError) {
		t.Errorf("no interface error; findings: %v", findingFields(r, SeverityError))
	}
}

// TestValidateRejectsUnknownAlgorithm catches a typo that would otherwise
// render a comment and no command.
func TestValidateRejectsUnknownAlgorithm(t *testing.T) {
	p := validPolicy()
	p.Algorithm = "htb"

	r := Validate(p, cakeAvailable())

	if r.Valid {
		t.Error("an unknown algorithm must not be valid")
	}
	if !hasFinding(r, "algorithm", SeverityError) {
		t.Errorf("no algorithm error; findings: %v", findingFields(r, SeverityError))
	}
}

// TestValidateRejectsImplausibleRate: a rate far beyond any gateway link is
// almost always a unit mistake — kbit/s entered where Mbit/s was meant.
func TestValidateRejectsImplausibleRate(t *testing.T) {
	p := validPolicy().WithBandwidth(500_000_000, 20_000)

	r := Validate(p, cakeAvailable())

	if r.Valid {
		t.Error("a 500,000,000 kbit/s link must not be valid")
	}
	if !hasFinding(r, "bandwidth", SeverityError) {
		t.Errorf("no bandwidth error; findings: %v", findingFields(r, SeverityError))
	}
}

// TestValidateWarnsWhenRateExceedsLinkSpeed: shaping above the physical link
// does nothing about bufferbloat, because the bottleneck is the link itself.
func TestValidateWarnsWhenRateExceedsLinkSpeed(t *testing.T) {
	p := validPolicy().WithBandwidth(2_000_000, 20_000)
	p.LinkSpeedMbps = 1000 // 1,000,000 kbit/s

	r := Validate(p, cakeAvailable())

	if !r.Valid {
		t.Error("exceeding link speed is a warning, not an error")
	}
	if !hasFinding(r, "bandwidth.download_kbps", SeverityWarning) {
		t.Errorf("no link-speed warning; findings: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateToleratesRateNearLinkSpeed: an ISP may quote a rate slightly
// above the negotiated figure, and that must not be reported as a problem.
func TestValidateToleratesRateNearLinkSpeed(t *testing.T) {
	p := validPolicy().WithBandwidth(1_050_000, 20_000)
	p.LinkSpeedMbps = 1000

	r := Validate(p, cakeAvailable())

	if !r.Valid {
		t.Errorf("a rate 5%% above link speed must be accepted: %v", findingFields(r, SeverityError))
	}
}

// TestValidateWarnsWhenRateIsAFractionOfLinkSpeed: under 1% of the link is
// almost always a unit error in the other direction, and it throttles the
// connection to a crawl.
func TestValidateWarnsWhenRateIsAFractionOfLinkSpeed(t *testing.T) {
	p := validPolicy().WithBandwidth(100, 20)
	p.LinkSpeedMbps = 1000

	r := Validate(p, cakeAvailable())

	if !r.Valid {
		t.Error("a tiny rate is a warning, not an error")
	}
	if !hasFinding(r, "bandwidth.download_kbps", SeverityWarning) {
		t.Errorf("no small-rate warning; findings: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateWarnsWhenUploadExceedsDownload: few links are provisioned faster
// upstream, so this is nearly always transposed digits.
func TestValidateWarnsWhenUploadExceedsDownload(t *testing.T) {
	p := validPolicy().WithBandwidth(20_000, 100_000)

	r := Validate(p, cakeAvailable())

	if !hasFinding(r, "bandwidth", SeverityWarning) {
		t.Errorf("no transposed-rate warning; findings: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateAcceptsSymmetricRates: a link provisioned equally both ways is
// unusual but perfectly valid, and must not be flagged.
func TestValidateAcceptsSymmetricRates(t *testing.T) {
	p := validPolicy().WithBandwidth(50_000, 50_000)

	r := Validate(p, cakeAvailable())

	if !r.Valid || r.WarningCount != 0 {
		t.Errorf("a symmetric link must be accepted cleanly: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateWarnsOnEachUnsetDirection: shaping only one direction is
// legitimate, but the other direction being silently unshaped is worth saying.
func TestValidateWarnsOnEachUnsetDirection(t *testing.T) {
	p := validPolicy().WithBandwidth(100_000, 0)

	r := Validate(p, cakeAvailable())

	if !hasFinding(r, "bandwidth.upload_kbps", SeverityWarning) {
		t.Errorf("no missing-upload warning; findings: %v", findingFields(r, SeverityWarning))
	}
	if hasFinding(r, "bandwidth.download_kbps", SeverityWarning) {
		t.Error("the configured direction must not be reported as unset")
	}
}

// TestValidateWarnsOnHighOverhead: above 30% the compensation itself is
// distorting the rate.
func TestValidateWarnsOnHighOverhead(t *testing.T) {
	p := validPolicy()
	p.Bandwidth.OverheadPercent = 50

	r := Validate(p, cakeAvailable())

	if !hasFinding(r, "bandwidth.overhead_percent", SeverityWarning) {
		t.Errorf("no overhead warning; findings: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateRejectsNegativeOverhead.
func TestValidateRejectsNegativeOverhead(t *testing.T) {
	p := validPolicy()
	p.Bandwidth.OverheadPercent = -10

	r := Validate(p, cakeAvailable())

	if r.Valid {
		t.Error("negative overhead must be an error")
	}
	if !hasFinding(r, "bandwidth.overhead_percent", SeverityError) {
		t.Errorf("no overhead error; findings: %v", findingFields(r, SeverityError))
	}
}

// TestValidateWarnsOnShortInterval: the measurement window must span the
// target, or the delay estimate is noise and the shaper oscillates.
func TestValidateWarnsOnShortInterval(t *testing.T) {
	p := validPolicy()
	p.Limits.TargetMS = 5
	p.Limits.IntervalMS = 5 // equal to, not twice, the target

	r := Validate(p, cakeAvailable())

	if !hasFinding(r, "limits.interval_ms", SeverityWarning) {
		t.Errorf("no short-interval warning; findings: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateAcceptsDefaultLimits: CAKE's own defaults must pass unchanged.
func TestValidateAcceptsDefaultLimits(t *testing.T) {
	p := validPolicy() // 5ms / 100ms

	r := Validate(p, cakeAvailable())

	if r.WarningCount != 0 {
		t.Errorf("CAKE's default limits must validate cleanly: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateRejectsZeroTarget: a zero standing queue is not a usable one.
func TestValidateRejectsZeroTarget(t *testing.T) {
	p := validPolicy()
	p.Limits.TargetMS = 0

	r := Validate(p, cakeAvailable())

	if r.Valid {
		t.Error("a zero target delay must not be valid")
	}
	if !hasFinding(r, "limits.target_ms", SeverityError) {
		t.Errorf("no target error; findings: %v", findingFields(r, SeverityError))
	}
}

// TestValidateWarnsOnHugeTarget: a large standing queue is itself a latency
// source, so aiming at one contradicts the point of shaping.
func TestValidateWarnsOnHugeTarget(t *testing.T) {
	p := validPolicy()
	p.Limits.TargetMS = 5000
	p.Limits.IntervalMS = 10_000

	r := Validate(p, cakeAvailable())

	if !hasFinding(r, "limits.target_ms", SeverityWarning) {
		t.Errorf("no large-target warning; findings: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateWarnsWhenFqCodelQuantumIsNotTheMTU: fq_codel's quantum below the
// MTU costs throughput measurably.
func TestValidateWarnsWhenFqCodelQuantumIsNotTheMTU(t *testing.T) {
	p := validPolicy()
	p.Algorithm = AlgorithmFqCodel
	p.Limits = FqCodelLimits(9000)
	p.Limits.Quantum = 1514 // CAKE's default, left in place by mistake
	p.MTU = 9000

	r := Validate(p, cakeAvailable())

	if !hasFinding(r, "limits.quantum", SeverityWarning) {
		t.Errorf("no quantum warning; findings: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateAcceptsMatchingFqCodelQuantum.
func TestValidateAcceptsMatchingFqCodelQuantum(t *testing.T) {
	p := validPolicy()
	p.Algorithm = AlgorithmFqCodel
	p.Limits = FqCodelLimits(1500)
	p.MTU = 1500

	r := Validate(p, cakeAvailable())

	if r.WarningCount != 0 {
		t.Errorf("a matching quantum must validate cleanly: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateDoesNotApplyQuantumRuleToCake: CAKE's 1514 is its own default
// and has nothing to do with the interface MTU.
func TestValidateDoesNotApplyQuantumRuleToCake(t *testing.T) {
	p := validPolicy()
	p.MTU = 9000 // differs from CAKE's default quantum
	p.Limits = DefaultLimits()

	r := Validate(p, cakeAvailable())

	if hasFinding(r, "limits.quantum", SeverityWarning) {
		t.Error("the fq_codel MTU rule must not be applied to cake")
	}
}

// TestValidateReportsFallbackAsWarningNotError: a degraded render is still
// worth producing, so it cannot be an error.
func TestValidateReportsFallbackAsWarningNotError(t *testing.T) {
	p := validPolicy()

	r := Validate(p, Availability{Algorithms: setOf(AlgorithmFqCodel), CheckedAt: time.Now()})

	if !r.Valid {
		t.Errorf("a fallback must not invalidate the policy: %v", findingFields(r, SeverityError))
	}
	if !hasFinding(r, "algorithm", SeverityWarning) {
		t.Errorf("no fallback warning; findings: %v", findingFields(r, SeverityWarning))
	}
	if r.Selection.Algorithm != AlgorithmFqCodel || !r.Selection.Degraded {
		t.Errorf("selection = %+v, want a degraded fq_codel fallback", r.Selection)
	}
}

// TestValidateErrorsWhenNothingIsAvailable: with no shaping possible the
// operator must be told, not handed a script that silently does nothing.
func TestValidateErrorsWhenNothingIsAvailable(t *testing.T) {
	p := validPolicy()

	r := Validate(p, Availability{Algorithms: map[Algorithm]bool{}, CheckedAt: time.Now()})

	if r.Valid {
		t.Error("no usable algorithm must not validate")
	}
	if !hasFinding(r, "algorithm", SeverityError) {
		t.Errorf("no algorithm error; findings: %v", findingFields(r, SeverityError))
	}
}

// TestValidateDisabledPolicyIsClean: shaping turned off is a legitimate state
// and must produce no complaints.
func TestValidateDisabledPolicyIsClean(t *testing.T) {
	r := Validate(Default(), cakeAvailable())

	if !r.Valid {
		t.Errorf("a disabled policy must be valid: %v", findingFields(r, SeverityError))
	}
	if len(r.Findings) != 0 {
		t.Errorf("a disabled policy produced findings: %v", r.Findings)
	}
	if r.Selection.Algorithm != AlgorithmNone {
		t.Errorf("selected %q, want none", r.Selection.Algorithm)
	}
}

// TestValidateWarnsWhenEnabledWithNoAlgorithm: the configuration says shape
// but names nothing to shape with, which is a contradiction worth reporting.
func TestValidateWarnsWhenEnabledWithNoAlgorithm(t *testing.T) {
	p := validPolicy()
	p.Algorithm = AlgorithmNone

	r := Validate(p, cakeAvailable())

	if !hasFinding(r, "algorithm", SeverityWarning) {
		t.Errorf("no contradictory-algorithm warning; findings: %v", findingFields(r, SeverityWarning))
	}
}

// TestValidateRejectsOverlongInterfaceName: Linux caps interface names at 15
// characters, and a longer one is a typo that would fail at apply time.
func TestValidateRejectsOverlongInterfaceName(t *testing.T) {
	p := validPolicy()
	p.Interface = "this-name-is-far-too-long"

	r := Validate(p, cakeAvailable())

	if r.Valid {
		t.Error("an overlong interface name must not be valid")
	}
	if !hasFinding(r, "interface", SeverityError) {
		t.Errorf("no interface error; findings: %v", findingFields(r, SeverityError))
	}
}

// TestFindingsAreSortedBySeverity: the reason a render was refused has to be
// the first thing printed, or the operator reads past it.
func TestFindingsAreSortedBySeverity(t *testing.T) {
	p := validPolicy()
	p.Interface = ""
	p.Bandwidth = Bandwidth{}
	p.Algorithm = "htb"

	r := Validate(p, cakeAvailable())

	if len(r.Findings) < 3 {
		t.Fatalf("expected several findings, got %d", len(r.Findings))
	}
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i-1].Severity.rank() > r.Findings[i].Severity.rank() {
			t.Fatalf("findings out of order at %d: %s before %s",
				i, r.Findings[i-1].Severity, r.Findings[i].Severity)
		}
	}
	if r.Findings[0].Severity != SeverityError {
		t.Errorf("first finding is %s, want error", r.Findings[0].Severity)
	}
}

// TestCountsMatchFindings: the summary line is what CI reads, so the counts
// and the list must agree.
func TestCountsMatchFindings(t *testing.T) {
	p := validPolicy().WithBandwidth(2_000_000, 200_000)
	p.LinkSpeedMbps = 100
	p.Limits.TargetMS = 5000
	p.Limits.IntervalMS = 20_000

	r := Validate(p, cakeAvailable())

	var e, w, i int
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityError:
			e++
		case SeverityWarning:
			w++
		default:
			i++
		}
	}
	if r.ErrorCount != e || r.WarningCount != w || r.InfoCount != i {
		t.Errorf("counts (%d,%d,%d) do not match findings (%d,%d,%d)",
			r.ErrorCount, r.WarningCount, r.InfoCount, e, w, i)
	}
	if r.Valid != (e == 0) {
		t.Errorf("valid = %v with %d errors", r.Valid, e)
	}
}

// TestFindingStringIncludesHint: the hint is the actionable half of a
// finding, and it must be visible in the default rendering.
func TestFindingStringIncludesHint(t *testing.T) {
	f := Finding{Field: "bandwidth", Severity: SeverityError, Message: "no rate set", Hint: "set download and upload"}

	s := f.String()

	for _, want := range []string{"bandwidth", "no rate set", "set download and upload"} {
		if !strings.Contains(s, want) {
			t.Errorf("finding string %q is missing %q", s, want)
		}
	}
}
