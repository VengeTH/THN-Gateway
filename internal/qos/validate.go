package qos

import (
	"fmt"
)

// Severity classifies a validation finding.
type Severity string

const (
	// SeverityError means the policy must not be rendered.
	SeverityError Severity = "error"
	// SeverityWarning means it is renderable but probably wrong.
	SeverityWarning Severity = "warning"
	// SeverityInfo is informational.
	SeverityInfo Severity = "info"
)

// rank orders severities for sorting.
func (s Severity) rank() int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

// Finding is a single validation result.
type Finding struct {
	// Field is the dotted path of the offending setting.
	Field string `json:"field"`
	// Severity classifies the finding.
	Severity Severity `json:"severity"`
	// Message describes the problem.
	Message string `json:"message"`
	// Hint suggests a correction.
	Hint string `json:"hint,omitempty"`
}

// String renders a finding for terminal output.
func (f Finding) String() string {
	s := fmt.Sprintf("[%s] %s: %s", f.Severity, f.Field, f.Message)
	if f.Hint != "" {
		s += " (" + f.Hint + ")"
	}
	return s
}

// Result aggregates the findings of a validation pass.
type Result struct {
	// Findings are all results, sorted by severity.
	Findings []Finding `json:"findings"`
	// Valid reports that no error-level finding was raised.
	Valid bool `json:"valid"`
	// ErrorCount, WarningCount and InfoCount summarise the findings.
	ErrorCount   int `json:"error_count"`
	WarningCount int `json:"warning_count"`
	InfoCount    int `json:"info_count"`
	// Selection is the algorithm that would actually be used.
	Selection Selection `json:"selection"`
}

// add appends a finding.
func (r *Result) add(field string, sev Severity, msg, hint string) {
	r.Findings = append(r.Findings, Finding{Field: field, Severity: sev, Message: msg, Hint: hint})
}

// errorf appends an error finding.
func (r *Result) errorf(field, msg, hint string) { r.add(field, SeverityError, msg, hint) }

// warnf appends a warning finding.
func (r *Result) warnf(field, msg, hint string) { r.add(field, SeverityWarning, msg, hint) }

// infof appends an informational finding.
func (r *Result) infof(field, msg, hint string) { r.add(field, SeverityInfo, msg, hint) }

// Errors returns the error-level findings.
func (r Result) Errors() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			out = append(out, f)
		}
	}
	return out
}

// finalise counts, sorts and sets Valid.
func (r *Result) finalise() {
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityError:
			r.ErrorCount++
		case SeverityWarning:
			r.WarningCount++
		default:
			r.InfoCount++
		}
	}
	r.Valid = r.ErrorCount == 0

	// Insertion sort keeps this dependency-free and the list is short. The
	// ordering matters: the reason a render is refused appears first.
	for i := 1; i < len(r.Findings); i++ {
		for j := i; j > 0 && r.Findings[j].Severity.rank() < r.Findings[j-1].Severity.rank(); j-- {
			r.Findings[j], r.Findings[j-1] = r.Findings[j-1], r.Findings[j]
		}
	}
}

// Validate checks a shaping policy against what the host can do.
//
// The checks concentrate on mistakes that make shaping actively harmful rather
// than merely ineffective. A too-low rate throttles a link below its real
// capacity, which presents to the user as "the internet got slower" and is
// indistinguishable from a genuine network problem.
func Validate(p Policy, avail Availability) Result {
	var r Result

	alg := p.Algorithm
	if alg == "" {
		alg = AlgorithmCake
	}

	if !p.Enabled || alg == AlgorithmNone {
		r.Selection = Selection{Algorithm: AlgorithmNone, Requested: alg, Available: true}
		if p.Enabled && alg == AlgorithmNone {
			r.warnf("algorithm",
				"shaping is enabled but the algorithm is \"none\", so nothing will be shaped",
				"set the algorithm to cake")
		}
		r.finalise()
		return r
	}

	validateAlgorithm(&r, p, alg)
	validateBandwidth(&r, p)
	validateLimits(&r, p, alg)
	validateSelection(&r, p, alg, avail)

	r.finalise()
	return r
}

// validateAlgorithm checks the requested algorithm.
func validateAlgorithm(r *Result, p Policy, alg Algorithm) {
	if !alg.Valid() {
		r.errorf("algorithm",
			fmt.Sprintf("unknown algorithm %q", alg),
			"supported algorithms are cake, fq_codel and none")
		return
	}

	if p.Interface == "" {
		// Shaping must be on the interface facing the bottleneck. Without a
		// named interface, shaping would be applied to the wrong link or to
		// all of them.
		r.errorf("interface",
			"no interface is configured, so there is nowhere to apply shaping",
			"set the interface to the uplink; shaping belongs on the bottleneck link")
		return
	}

	if len(p.Interface) > 15 {
		r.errorf("interface",
			fmt.Sprintf("interface name %q exceeds the 15 characters Linux permits", p.Interface), "")
	}
}

// validateBandwidth checks the configured rate.
func validateBandwidth(r *Result, p Policy) {
	b := p.Bandwidth

	if b.IsZero() {
		// Guessing a rate is worse than having none. A wrong rate throttles a
		// real link and nothing reports an error.
		r.errorf("bandwidth",
			"no bandwidth is configured, so the shaper has nothing to shape toward",
			"set download and upload rates to what the link is actually provisioned for")
		return
	}

	if b.DownloadKbps < 0 || b.UploadKbps < 0 {
		r.errorf("bandwidth", "a bandwidth must not be negative", "")
		return
	}

	if b.DownloadKbps == 0 {
		r.warnf("bandwidth.download_kbps",
			"no download bandwidth is configured; downstream traffic would be unshaped",
			"set the provisioned downstream rate")
	}

	if b.UploadKbps == 0 {
		r.warnf("bandwidth.upload_kbps",
			"no upload bandwidth is configured; upstream traffic would be unshaped",
			"set the provisioned upload rate")
	}

	// An upload rate above the download rate is legal and common, so it is
	// not itself a problem. The reverse is almost always a typo, because few
	// links are provisioned faster upstream than downstream.
	if b.UploadKbps > 0 && b.DownloadKbps > 0 && b.UploadKbps > b.DownloadKbps {
		r.warnf("bandwidth",
			fmt.Sprintf("the upload rate (%dkbit/s) exceeds the download rate (%dkbit/s), which is unusual",
				b.UploadKbps, b.DownloadKbps),
			"if the numbers are swapped, shaping will throttle the wrong direction")
	}

	// Absurd rates are almost always a unit mistake: kbit/s entered where
	// Mbit/s was meant, or vice versa.
	const maxPlausibleKbps = 400_000_000 // 400 Gbit/s
	if b.DownloadKbps > maxPlausibleKbps || b.UploadKbps > maxPlausibleKbps {
		r.errorf("bandwidth",
			fmt.Sprintf("a rate of %dkbit/s is not plausible for a gateway link", max(bandwidthValue(b))),
			"check whether the unit is wrong: THN expects kilobits per second")
	}

	if b.OverheadPercent < 0 {
		r.errorf("bandwidth.overhead_percent",
			"the overhead compensation must not be negative", "")
	} else if b.OverheadPercent > 30 {
		r.warnf("bandwidth.overhead_percent",
			fmt.Sprintf("%d%% overhead compensation is unusually high; typical values are 8 to 12",
				b.OverheadPercent),
			"a high value under-shapes the link")
	}

	// The cross-check that catches the most common real mistake.
	if p.LinkSpeedMbps > 0 {
		validateAgainstLinkSpeed(r, p)
	}
}

// bandwidthValue returns the larger of the two configured rates.
func bandwidthValue(b Bandwidth) int {
	if b.UploadKbps > b.DownloadKbps {
		return b.UploadKbps
	}
	return b.DownloadKbps
}

// validateAgainstLinkSpeed cross-checks the rate against the negotiated link
// speed.
//
// This catches the case where the configured rate is an order of magnitude out,
// which is nearly always a unit error. It cannot catch a cable provisioned
// below its physical speed, because the interface reports the physical speed
// and not the provisioned one.
func validateAgainstLinkSpeed(r *Result, p Policy) {
	linkKbps := p.LinkSpeedMbps * 1000

	// A little over the link speed is legitimate: the link may negotiate at
	// a nominal figure the ISP rates slightly above.
	const tolerance = 1.10

	if linkKbps <= 0 {
		return
	}

	if p.Bandwidth.DownloadKbps > int(float64(linkKbps)*tolerance) {
		r.warnf("bandwidth.download_kbps",
			fmt.Sprintf("the configured download rate (%dkbit/s) exceeds the interface's link speed (%dkbit/s)",
				p.Bandwidth.DownloadKbps, linkKbps),
			"shaping above the real link speed has no effect on bufferbloat; the bottleneck is the link itself")
	}

	if p.Bandwidth.UploadKbps > int(float64(linkKbps)*tolerance) {
		r.warnf("bandwidth.upload_kbps",
			fmt.Sprintf("the configured upload rate (%dkbit/s) exceeds the interface's link speed (%dkbit/s)",
				p.Bandwidth.UploadKbps, linkKbps),
			"shaping above the real link speed has no effect on bufferbloat")
	}

	// A rate far below the link is not necessarily wrong — a provisioned
	// speed on a gigabit link is common — but a very small fraction of it is
	// almost always a unit error in the other direction.
	const tinyFraction = 0.01 // under 1% of link speed
	if p.Bandwidth.DownloadKbps > 0 && float64(p.Bandwidth.DownloadKbps) < float64(linkKbps)*tinyFraction {
		r.warnf("bandwidth.download_kbps",
			fmt.Sprintf("the configured download rate (%dkbit/s) is under 1%% of the link speed (%dkbit/s)",
				p.Bandwidth.DownloadKbps, linkKbps),
			"this will throttle the link far below its capacity; check the unit")
	}
}

// validateLimits checks the queue depths.
func validateLimits(r *Result, p Policy, alg Algorithm) {
	l := p.Limits

	if l.TargetMS < 0 {
		r.errorf("limits.target_ms", "the target delay must not be negative", "")
	} else if l.TargetMS == 0 {
		r.errorf("limits.target_ms",
			"the target delay is zero, which is not a usable standing queue",
			"5ms is CAKE's default")
	} else if l.TargetMS > 1000 {
		r.warnf("limits.target_ms",
			fmt.Sprintf("a %dms standing queue is far above the ~5ms target and would itself cause latency",
				l.TargetMS),
			"a larger target is appropriate only on a link with a very long buffer")
	}

	if l.IntervalMS <= 0 {
		r.errorf("limits.interval_ms",
			"the measurement interval must be positive",
			"100ms is CAKE's default")
	} else if l.TargetMS > 0 && l.IntervalMS < l.TargetMS*2 {
		// The window has to be long enough to measure the target delay, or
		// the estimate is noise and the shaper oscillates.
		r.warnf("limits.interval_ms",
			fmt.Sprintf("the interval (%dms) is short relative to the target delay (%dms)",
				l.IntervalMS, l.TargetMS),
			"the window must span the target, otherwise the estimate is unstable")
	}

	if l.Quantum < 0 {
		r.errorf("limits.quantum", "the quantum must not be negative", "")
	}

	// fq_codel's quantum is the interface MTU, and a wrong one degrades
	// throughput measurably.
	if alg == AlgorithmFqCodel {
		if l.Quantum > 0 && p.MTU > 0 && l.Quantum != p.MTU {
			r.warnf("limits.quantum",
				fmt.Sprintf("the fq_codel quantum (%d) does not match the interface MTU (%d)",
					l.Quantum, p.MTU),
				"a quantum smaller than the MTU costs throughput")
		}
	}
}

// validateSelection reports what will actually be applied.
//
// The fallback case is reported here rather than at render time, because an
// operator reviewing a validation result should learn that their kernel cannot
// do what they asked before the generated file is written, not after.
func validateSelection(r *Result, p Policy, alg Algorithm, avail Availability) {
	s := Select(p, avail.Algorithms)
	r.Selection = s

	if s.Available {
		return
	}

	if s.Degraded {
		r.warnf("algorithm",
			s.Reason,
			"latency will not improve as configured; this is a capability limit, not a configuration error")
		return
	}

	if s.Reason != "" {
		r.errorf("algorithm", s.Reason,
			"install the kernel module for "+alg.String()+" or accept the fallback")
	}
}
