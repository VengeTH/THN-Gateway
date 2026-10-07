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

// Finding codes.
//
// These are the stable, machine-readable reasons a shaping policy is not
// renderable. They are a vocabulary, not sentences: a UI groups on them, a CI
// log greps them, and a future automated remediation dispatches on them. The
// human text beside them is free to be reworded; these are not.
const (
	// CodeQoSDisabled means the document does not ask for traffic shaping.
	//
	// Declining to shape is a decision, and unlike DHCP it is one with a
	// real consequence in both directions: an unwanted shaper caps a link,
	// and no shaper leaves bufferbloat unaddressed. Neither is an error.
	CodeQoSDisabled = "qos-disabled"

	// CodeWANMissing means shaping was requested with no uplink to attach to.
	CodeWANMissing = "qos-wan-missing"

	// CodeWANUnresolved means the uplink role is written down but matches no
	// observed interface.
	//
	// Unresolved is pending, not broken: the cable may not be plugged in yet,
	// and the operator may already have written the right identity.
	CodeWANUnresolved = "qos-wan-unresolved"

	// CodeWANConflict means the uplink role is in conflict with another role
	// or pointed at the LAN interface.
	CodeWANConflict = "qos-wan-conflict"

	// CodeAlgorithmUnavailable means THN has evidence the requested algorithm
	// cannot be used on this host.
	//
	// Distinct from CodeCakeUnknown on purpose. "THN checked and it is not
	// there" and "THN did not check, because checking would mutate the host"
	// are different facts about different machines, and collapsing them would
	// report a host as incapable on the strength of THN's own restraint.
	CodeAlgorithmUnavailable = "qos-algorithm-unavailable"

	// CodeCakeUnavailable means THN has confirmed that CAKE cannot be used on
	// this host.
	CodeCakeUnavailable = "qos-cake-unavailable"

	// CodeCakeUnknown means the requested algorithm's availability is not
	// established, and was deliberately not established by mutation.
	//
	// Named for CAKE because that is where the distinction bites hardest:
	// sch_cake is a kernel module whose presence cannot be confirmed without
	// attaching a discipline, which is mutation.
	CodeCakeUnknown = "qos-cake-unknown"

	// CodeExistingQdiscUnmanaged records an observed queue discipline that is
	// unmanaged by THN.
	CodeExistingQdiscUnmanaged = "qos-existing-qdisc-unmanaged"

	// CodeAlgorithmMissing means no algorithm was named.
	CodeAlgorithmMissing = "qos-algorithm-missing"

	// CodeAlgorithmUnknown means the named algorithm is not one THN knows.
	CodeAlgorithmUnknown = "qos-algorithm-unsupported"

	// CodeAlgorithmNone means shaping is on but the algorithm disables it.
	CodeAlgorithmNone = "qos-algorithm-none"

	// CodeInterfaceMissing means there is nowhere to apply shaping.
	//
	// It covers both "no interface named" and "the name is not one Linux
	// would accept", because both leave the shaper with nowhere to attach and
	// an operator fixes both by naming a usable device.
	CodeInterfaceMissing = "qos-interface-missing"

	// CodeBandwidthMissing means no rate is configured at all.
	CodeBandwidthMissing = "qos-rate-missing"

	// CodeBandwidthInvalid means a rate is negative or implausible.
	CodeBandwidthInvalid = "qos-rate-invalid"

	// CodeBandwidthZero means one direction is unshaped.
	//
	// Distinct from missing: a half-configured shaper is a different problem
	// from an unconfigured one, and the remedy is different.
	CodeBandwidthZero = "qos-rate-zero"

	// CodeBandwidthInverted means the upstream rate exceeds the downstream.
	CodeBandwidthInverted = "qos-rate-inverted"

	// CodeOverheadInvalid means the overhead compensation is out of range.
	CodeOverheadInvalid = "qos-overhead-invalid"

	// CodeRateAboveLinkSpeed means the configured rate exceeds what the link
	// can carry.
	CodeRateAboveLinkSpeed = "qos-rate-above-link-speed"

	// CodeRateBelowLinkSpeed means the configured rate is implausibly small.
	CodeRateBelowLinkSpeed = "qos-rate-below-link-speed"

	// CodeLimitsInvalid means the queue depths are out of range.
	CodeLimitsInvalid = "qos-limits-invalid"

	// CodeAlgorithmDegraded means the requested algorithm was substituted
	// with a weaker one.
	CodeAlgorithmDegraded = "qos-algorithm-degraded"

	// CodeAlgorithmUnusable means neither the requested algorithm nor its
	// fallback is available on this host.
	CodeAlgorithmUnusable = "qos-algorithm-unusable"
)

// Finding is a single validation result.
type Finding struct {
	// Field is the dotted path of the offending setting.
	Field string `json:"field"`

	// Code is the stable, machine-readable reason.
	//
	// Field alone cannot separate these findings: "bandwidth" is produced by a
	// missing rate, a negative rate and an implausibly large one, and a UI
	// that wants to react to one of those specifically cannot. The code is the
	// vocabulary a consumer dispatches on; Message is free to be reworded.
	//
	// Empty where this package has not yet classified the finding.
	Code string `json:"code,omitempty"`

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

// addC appends a finding carrying a stable classification code.
func (r *Result) addC(code, field string, sev Severity, msg, hint string) {
	r.Findings = append(r.Findings, Finding{Field: field, Code: code, Severity: sev, Message: msg, Hint: hint})
}

// errorf appends an error finding.
func (r *Result) errorf(field, msg, hint string) { r.add(field, SeverityError, msg, hint) }

// errorc appends an error finding carrying a stable classification code.
func (r *Result) errorc(code, field, msg, hint string) {
	r.addC(code, field, SeverityError, msg, hint)
}

// warnf appends a warning finding.
func (r *Result) warnf(field, msg, hint string) { r.add(field, SeverityWarning, msg, hint) }

// warnc appends a warning finding carrying a stable classification code.
func (r *Result) warnc(code, field, msg, hint string) {
	r.addC(code, field, SeverityWarning, msg, hint)
}

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
			r.warnc(CodeAlgorithmNone, "algorithm",
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
		r.errorc(CodeAlgorithmUnknown, "algorithm",
			fmt.Sprintf("unknown algorithm %q", alg),
			"supported algorithms are cake, fq_codel and none")
		return
	}

	if p.Interface == "" {
		// Shaping must be on the interface facing the bottleneck. Without a
		// named interface, shaping would be applied to the wrong link or to
		// all of them.
		r.errorc(CodeInterfaceMissing, "interface",
			"no interface is configured, so there is nowhere to apply shaping",
			"set the interface to the uplink; shaping belongs on the bottleneck link")
		return
	}

	if len(p.Interface) > 15 {
		r.errorc(CodeInterfaceMissing, "interface",
			fmt.Sprintf("interface name %q exceeds the 15 characters Linux permits", p.Interface), "")
	}
}

// validateBandwidth checks the configured rate.
func validateBandwidth(r *Result, p Policy) {
	b := p.Bandwidth

	if b.IsZero() {
		// Guessing a rate is worse than having none. A wrong rate throttles a
		// real link and nothing reports an error.
		r.errorc(CodeBandwidthMissing, "bandwidth",
			"no bandwidth is configured, so the shaper has nothing to shape toward",
			"set download and upload rates to what the link is actually provisioned for")
		return
	}

	if b.DownloadKbps < 0 || b.UploadKbps < 0 {
		r.errorc(CodeBandwidthInvalid, "bandwidth", "a bandwidth must not be negative", "")
		return
	}

	if b.DownloadKbps == 0 {
		r.warnc(CodeBandwidthZero, "bandwidth.download_kbps",
			"no download bandwidth is configured; downstream traffic would be unshaped",
			"set the provisioned downstream rate")
	}

	if b.UploadKbps == 0 {
		r.warnc(CodeBandwidthZero, "bandwidth.upload_kbps",
			"no upload bandwidth is configured; upstream traffic would be unshaped",
			"set the provisioned upload rate")
	}

	// An upload rate above the download rate is legal and common, so it is
	// not itself a problem. The reverse is almost always a typo, because few
	// links are provisioned faster upstream than downstream.
	if b.UploadKbps > 0 && b.DownloadKbps > 0 && b.UploadKbps > b.DownloadKbps {
		r.warnc(CodeBandwidthInverted, "bandwidth",
			fmt.Sprintf("the upload rate (%dkbit/s) exceeds the download rate (%dkbit/s), which is unusual",
				b.UploadKbps, b.DownloadKbps),
			"if the numbers are swapped, shaping will throttle the wrong direction")
	}

	// Absurd rates are almost always a unit mistake: kbit/s entered where
	// Mbit/s was meant, or vice versa.
	//
	// The ceiling is a plausibility bound, not a capability limit. It exists
	// to catch a unit error, and it is deliberately far above any real
	// broadband rate so that a genuinely fast link is never rejected as
	// impossible.
	const maxPlausibleKbps = 400_000_000 // 400 Gbit/s
	if b.DownloadKbps > maxPlausibleKbps || b.UploadKbps > maxPlausibleKbps {
		r.errorc(CodeBandwidthInvalid, "bandwidth",
			fmt.Sprintf("a rate of %dkbit/s is not plausible for a gateway link", max(bandwidthValue(b))),
			"check whether the unit is wrong: THN expects kilobits per second")
	}

	if b.OverheadPercent < 0 {
		r.errorc(CodeOverheadInvalid, "bandwidth.overhead_percent",
			"the overhead compensation must not be negative", "")
	} else if b.OverheadPercent > 30 {
		r.warnc(CodeOverheadInvalid, "bandwidth.overhead_percent",
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
		r.warnc(CodeRateAboveLinkSpeed, "bandwidth.download_kbps",
			fmt.Sprintf("the configured download rate (%dkbit/s) exceeds the interface's link speed (%dkbit/s)",
				p.Bandwidth.DownloadKbps, linkKbps),
			"shaping above the real link speed has no effect on bufferbloat; the bottleneck is the link itself")
	}

	if p.Bandwidth.UploadKbps > int(float64(linkKbps)*tolerance) {
		r.warnc(CodeRateAboveLinkSpeed, "bandwidth.upload_kbps",
			fmt.Sprintf("the configured upload rate (%dkbit/s) exceeds the interface's link speed (%dkbit/s)",
				p.Bandwidth.UploadKbps, linkKbps),
			"shaping above the real link speed has no effect on bufferbloat")
	}

	// A rate far below the link is not necessarily wrong — a provisioned
	// speed on a gigabit link is common — but a very small fraction of it is
	// almost always a unit error in the other direction.
	const tinyFraction = 0.01 // under 1% of link speed
	if p.Bandwidth.DownloadKbps > 0 && float64(p.Bandwidth.DownloadKbps) < float64(linkKbps)*tinyFraction {
		r.warnc(CodeRateBelowLinkSpeed, "bandwidth.download_kbps",
			fmt.Sprintf("the configured download rate (%dkbit/s) is under 1%% of the link speed (%dkbit/s)",
				p.Bandwidth.DownloadKbps, linkKbps),
			"this will throttle the link far below its capacity; check the unit")
	}
}

// validateLimits checks the queue depths.
func validateLimits(r *Result, p Policy, alg Algorithm) {
	l := p.Limits

	if l.TargetMS < 0 {
		r.errorc(CodeLimitsInvalid, "limits.target_ms", "the target delay must not be negative", "")
	} else if l.TargetMS == 0 {
		r.errorc(CodeLimitsInvalid, "limits.target_ms",
			"the target delay is zero, which is not a usable standing queue",
			"5ms is CAKE's default")
	} else if l.TargetMS > 1000 {
		r.warnc(CodeLimitsInvalid, "limits.target_ms",
			fmt.Sprintf("a %dms standing queue is far above the ~5ms target and would itself cause latency",
				l.TargetMS),
			"a larger target is appropriate only on a link with a very long buffer")
	}

	if l.IntervalMS <= 0 {
		r.errorc(CodeLimitsInvalid, "limits.interval_ms",
			"the measurement interval must be positive",
			"100ms is CAKE's default")
	} else if l.TargetMS > 0 && l.IntervalMS < l.TargetMS*2 {
		// The window has to be long enough to measure the target delay, or
		// the estimate is noise and the shaper oscillates.
		r.warnc(CodeLimitsInvalid, "limits.interval_ms",
			fmt.Sprintf("the interval (%dms) is short relative to the target delay (%dms)",
				l.IntervalMS, l.TargetMS),
			"the window must span the target, otherwise the estimate is unstable")
	}

	if l.Quantum < 0 {
		r.errorc(CodeLimitsInvalid, "limits.quantum", "the quantum must not be negative", "")
	}

	// fq_codel's quantum is the interface MTU, and a wrong one degrades
	// throughput measurably.
	if alg == AlgorithmFqCodel {
		if l.Quantum > 0 && p.MTU > 0 && l.Quantum != p.MTU {
			r.warnc(CodeLimitsInvalid, "limits.quantum",
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
	// The confidence travels with the set so that "nothing detected" and
	// "nobody looked" cannot collapse into one another here. Without it, an
	// unestablished host reads as a host that has nothing, and every enabled
	// QoS configuration fails on a machine THN never inspected.
	s := SelectWithConfidence(p, avail.Algorithms, avail.Confidence)
	r.Selection = s

	if s.Available {
		return
	}

	// Uncertain is a warning, not an error.
	//
	// This is the single most important branch in the package. An operator
	// who asked for CAKE on a host THN could not establish CAKE support for
	// has a perfectly valid document; what is missing is THN's knowledge, not
	// their configuration. Erroring here would report that knowledge gap as
	// their mistake.
	if s.Uncertain {
		r.warnc(CodeCakeUnknown, "algorithm", s.Reason,
			"attach a CAKE discipline to observe it, or run on a host where the capability is already established")
		return
	}

	if s.Degraded {
		r.warnc(CodeAlgorithmDegraded, "algorithm",
			s.Reason,
			"latency will not improve as configured; this is a capability limit, not a configuration error")
		return
	}

	if s.Reason != "" {
		r.errorc(CodeAlgorithmUnusable, "algorithm", s.Reason,
			"install the kernel module for "+alg.String()+" or accept the fallback")
	}
}
