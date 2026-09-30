package qos

import (
	"strings"
	"testing"
)

// setOf builds an availability set from the given algorithms.
func setOf(algs ...Algorithm) map[Algorithm]bool {
	m := map[Algorithm]bool{}
	for _, a := range algs {
		m[a] = true
	}
	return m
}

// TestSelectUsesRequestedAlgorithmWhenAvailable is the ordinary case: the
// kernel can do what was asked, so nothing about the selection should suggest
// otherwise.
func TestSelectUsesRequestedAlgorithmWhenAvailable(t *testing.T) {
	p := Default()
	p.Enabled = true
	p.Algorithm = AlgorithmCake

	got := Select(p, setOf(AlgorithmCake, AlgorithmFqCodel))

	if got.Algorithm != AlgorithmCake {
		t.Errorf("algorithm = %q, want cake", got.Algorithm)
	}
	if !got.Available {
		t.Error("available = false, want true; the request was met")
	}
	if got.Degraded {
		t.Error("degraded = true, want false; nothing was lost")
	}
	if got.Reason != "" {
		t.Errorf("reason = %q, want empty; a met request needs no explanation", got.Reason)
	}
}

// TestSelectFallsBackAndReportsDegradation is the case the whole fallback
// design exists for. A silent fallback would leave an operator believing
// bufferbloat was solved when it was not.
func TestSelectFallsBackAndReportsDegradation(t *testing.T) {
	p := Default()
	p.Enabled = true
	p.Algorithm = AlgorithmCake

	got := Select(p, setOf(AlgorithmFqCodel))

	if got.Algorithm != AlgorithmFqCodel {
		t.Errorf("algorithm = %q, want fq_codel", got.Algorithm)
	}
	if got.Available {
		t.Error("available = true, want false; cake was not present")
	}
	if !got.Degraded {
		t.Error("degraded = false, want true; falling back from a rate-aware to a " +
			"rate-unaware algorithm is a real loss and must be reported")
	}
	if got.Reason == "" {
		t.Error("reason is empty; a fallback must explain itself")
	}
	// The reason has to name both algorithms, or an operator reading only the
	// message cannot tell what happened.
	if !strings.Contains(got.Reason, "cake") || !strings.Contains(got.Reason, "fq_codel") {
		t.Errorf("reason = %q; it must name both the requested and the actual algorithm", got.Reason)
	}
}

// TestSelectRefusesFallbackWhenDisabled: an operator who turned fallback off
// wants to be told their kernel cannot do the job, not silently given something
// weaker.
func TestSelectRefusesFallbackWhenDisabled(t *testing.T) {
	p := Default()
	p.Enabled = true
	p.Algorithm = AlgorithmCake
	p.FallbackToFqCodel = false

	got := Select(p, setOf(AlgorithmFqCodel))

	if got.Algorithm != AlgorithmCake {
		t.Errorf("algorithm = %q, want cake; with fallback off nothing else may be substituted",
			got.Algorithm)
	}
	if got.Available {
		t.Error("available = true, want false")
	}
	if got.Degraded {
		t.Error("degraded = true, want false; the request simply failed")
	}
	if got.Reason == "" {
		t.Error("reason is empty; a refusal must explain itself")
	}
}

// TestSelectWithNothingAvailable covers the kernel that has neither.
func TestSelectWithNothingAvailable(t *testing.T) {
	p := Default()
	p.Enabled = true
	p.Algorithm = AlgorithmCake

	got := Select(p, map[Algorithm]bool{})

	if got.Algorithm != AlgorithmCake {
		t.Errorf("algorithm = %q, want cake", got.Algorithm)
	}
	if got.Available {
		t.Error("available = true, want false")
	}
	if got.Degraded {
		t.Error("degraded = true, want false; nothing was substituted, so nothing was lost")
	}
	if !strings.Contains(got.Reason, "neither") {
		t.Errorf("reason = %q; it must say that neither algorithm was available", got.Reason)
	}
}

// TestSelectTreatsAnEmptySetAsNothingDetected guards a subtle failure: a nil
// or empty map read as "everything is fine" would mean a failed probe
// silently produced a no-fallback verdict.
func TestSelectTreatsAnEmptySetAsNothingDetected(t *testing.T) {
	p := Default()
	p.Enabled = true
	p.Algorithm = AlgorithmCake

	if got := Select(p, nil); got.Available {
		t.Error("a nil availability map must not be read as 'cake is present'")
	}
}

// TestFqCodelIsNotDegradedWhenItIsTheRequest: asking for fq_codel and getting
// fq_codel is not a loss, and reporting it as one would train operators to
// ignore the warning.
func TestFqCodelIsNotDegradedWhenItIsTheRequest(t *testing.T) {
	p := Default()
	p.Enabled = true
	p.Algorithm = AlgorithmFqCodel

	got := Select(p, setOf(AlgorithmFqCodel))

	if !got.Available {
		t.Error("available = false, want true")
	}
	if got.Degraded {
		t.Error("degraded = true, want false")
	}
}

// TestEffectiveAppliesOverhead: CAKE's bandwidth is the wire rate, so the
// configured payload rate must be raised by the overhead allowance.
func TestEffectiveAppliesOverhead(t *testing.T) {
	b := Bandwidth{DownloadKbps: 100_000, UploadKbps: 20_000, OverheadPercent: 10}

	if got := b.Effective(Download); got != 110_000 {
		t.Errorf("download effective = %d, want 110000", got)
	}
	if got := b.Effective(Upload); got != 22_000 {
		t.Errorf("upload effective = %d, want 22000", got)
	}
}

// TestEffectiveDefaultsOverheadWhenUnset: a zero must mean "not configured",
// not "no overhead". Treating it as zero would under-shape the link by a tenth
// of its capacity, permanently.
func TestEffectiveDefaultsOverheadWhenUnset(t *testing.T) {
	b := Bandwidth{DownloadKbps: 100_000, UploadKbps: 20_000}

	if got := b.Effective(Download); got != 110_000 {
		t.Errorf("download effective = %d, want 110000 (the default overhead must apply)", got)
	}
}

// TestEffectiveZeroBandwidth: an unset rate must stay zero rather than becoming
// a small nonzero value through the overhead multiply.
func TestEffectiveZeroBandwidth(t *testing.T) {
	b := Bandwidth{OverheadPercent: 10}

	if got := b.Effective(Download); got != 0 {
		t.Errorf("download effective = %d, want 0", got)
	}
	if got := b.Effective(Upload); got != 0 {
		t.Errorf("upload effective = %d, want 0", got)
	}
}

// TestEffectiveClampsNegativeOverhead: a negative value would reduce the rate,
// which is the opposite of what the field means.
func TestEffectiveClampsNegativeOverhead(t *testing.T) {
	b := Bandwidth{DownloadKbps: 1000, UploadKbps: 1000, OverheadPercent: -50}

	if got := b.Effective(Download); got != 1000 {
		t.Errorf("download effective = %d, want 1000; negative overhead must clamp to zero", got)
	}
}

// TestAlgorithmRateAware: the property that makes a fallback a degradation.
func TestAlgorithmRateAware(t *testing.T) {
	if !AlgorithmCake.RateAware() {
		t.Error("cake must be rate-aware")
	}
	if AlgorithmFqCodel.RateAware() {
		t.Error("fq_codel must not be reported as rate-aware; that claim is the reason " +
			"a fallback to it is a degradation")
	}
	if AlgorithmNone.RateAware() {
		t.Error("none must not be rate-aware")
	}
}

// TestDefaultSetsNoRate: guessing a rate would silently cap a real link, and
// that failure presents as "the internet got slower".
func TestDefaultSetsNoRate(t *testing.T) {
	p := Default()

	if !p.Bandwidth.IsZero() {
		t.Errorf("default bandwidth = %+v, want zero", p.Bandwidth)
	}
	if p.Enabled {
		t.Error("default policy must be disabled")
	}
	if !p.FallbackToFqCodel {
		t.Error("fallback must default on; fq_codel beats no shaping at all")
	}
	if p.Algorithm != AlgorithmCake {
		t.Errorf("default algorithm = %q, want cake", p.Algorithm)
	}
}

// TestDefaultOverheadIsTenPercent pins the value that every other test's
// arithmetic depends on.
func TestDefaultOverheadIsTenPercent(t *testing.T) {
	if DefaultOverheadPercent != 10 {
		t.Errorf("DefaultOverheadPercent = %d, want 10", DefaultOverheadPercent)
	}
}

// TestPolicyStringReportsTheRealNumbers: the summary is what an operator reads
// to confirm the shaper is set to what they meant.
func TestPolicyStringReportsTheRealNumbers(t *testing.T) {
	p := Default().WithInterface("eth0").WithBandwidth(100_000, 20_000)
	p.Enabled = true

	s := p.String()

	for _, want := range []string{"cake", "eth0", "100000", "20000", "110000", "22000", "10%"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q is missing %q", s, want)
		}
	}
}

// TestPolicyStringWhenDisabled is the state a gateway in qos-disabled config
// reports, and it must not claim any rate.
func TestPolicyStringWhenDisabled(t *testing.T) {
	if got := Default().String(); got != "qos: disabled" {
		t.Errorf("summary = %q, want %q", got, "qos: disabled")
	}
}

// TestAvailabilitySummaryIsDeterministic: two reads of the same host must
// produce identical output, or diffing two reports is useless.
func TestAvailabilitySummaryIsDeterministic(t *testing.T) {
	a := Availability{Algorithms: map[Algorithm]bool{AlgorithmFqCodel: true, AlgorithmCake: true}}

	first := a.Summary()
	for i := 0; i < 50; i++ {
		if got := a.Summary(); got != first {
			t.Fatalf("summary changed between calls: %q then %q", first, got)
		}
	}
	if !strings.HasPrefix(first, "cake") {
		t.Errorf("summary = %q; the rate-aware algorithm should lead", first)
	}
}

// TestAvailabilitySummaryWhenEmpty.
func TestAvailabilitySummaryWhenEmpty(t *testing.T) {
	a := Availability{Algorithms: map[Algorithm]bool{}}

	if got := a.Summary(); got != "none detected" {
		t.Errorf("summary = %q, want %q", got, "none detected")
	}
}

// TestAvailabilitySummaryReportsUnknown: a failed probe must not be presented
// as an answer.
func TestAvailabilitySummaryReportsUnknown(t *testing.T) {
	a := Availability{Error: "not root"}

	if got := a.Summary(); !strings.Contains(got, "unknown") || !strings.Contains(got, "not root") {
		t.Errorf("summary = %q, want it to say unknown and give the reason", got)
	}
}

// TestFqCodelLimitsUsesMTU: fq_codel's quantum is the interface MTU, and
// leaving CAKE's 1514 in place on a 9000-byte MTU would cost throughput.
func TestFqCodelLimitsUsesMTU(t *testing.T) {
	got := FqCodelLimits(9000)

	if got.Quantum != 9000 {
		t.Errorf("quantum = %d, want 9000", got.Quantum)
	}
	if got.TargetMS != 5 {
		t.Errorf("target = %d, want 5", got.TargetMS)
	}
}

// TestFqCodelLimitsFallsBackToDefaultMTU.
func TestFqCodelLimitsFallsBackToDefaultMTU(t *testing.T) {
	if got := FqCodelLimits(0); got.Quantum != 1500 {
		t.Errorf("quantum = %d, want 1500", got.Quantum)
	}
}

// TestWithInterfaceAndWithBandwidthDoNotMutate: these are value receivers, so
// a mutation would corrupt the default policy for every other caller.
func TestWithInterfaceAndWithBandwidthDoNotMutate(t *testing.T) {
	base := Default()

	a := base.WithInterface("eth0")
	b := base.WithBandwidth(100, 200)

	if base.Interface != "" {
		t.Errorf("base interface = %q, want empty; WithInterface mutated the receiver", base.Interface)
	}
	if !base.Bandwidth.IsZero() {
		t.Errorf("base bandwidth = %+v, want zero; WithBandwidth mutated the receiver", base.Bandwidth)
	}
	if a.Interface != "eth0" || b.Bandwidth.DownloadKbps != 100 {
		t.Error("the returned copies do not carry the requested values")
	}
}
