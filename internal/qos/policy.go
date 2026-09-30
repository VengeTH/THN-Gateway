// Package qos declares THN's traffic-shaping intent: which algorithm, at what
// bandwidth, on which interface, with what fallback behaviour.
//
// # CAKE, and why fq_codel is only a fallback
//
// CAKE (Common Applications Kept Enhanced) and fq_codel solve different
// problems, and treating them as interchangeable is a mistake worth naming.
//
// CAKE is rate-aware and application-aware. Given a correct bandwidth it
// diffuses traffic into a managed queue per flow and keeps the device's own
// queue short, which is what actually reduces bufferbloat. It needs the rate,
// because without one it has nothing to shape toward.
//
// fq_codel is a queue discipline with no rate awareness. On an idle link it
// does very little. On a saturated link it shortens the device queue but has no
// upstream signal, so the bottleneck queue still fills and latency still
// climbs. It is a genuine improvement over a default pfifo_fast queue, and it
// is not the same thing as CAKE.
//
// So the fallback is real but lossy, and this package reports that loss rather
// than presenting fq_codel as an equivalent substitute. A policy that wanted
// CAKE and got fq_codel is degraded, and saying so is the difference between an
// operator who knows why latency did not improve and one who does not.
//
// # Rates are the operator's responsibility
//
// CAKE shapes toward a configured bandwidth. If that number is wrong, shaping
// is actively harmful: too low and the link is throttled below its real
// capacity, which looks like a slow network. THN cross-checks the configured
// rate against the interface's negotiated link speed where it can, but a
// cable or DSL link that is provisioned below its physical speed cannot be
// distinguished from a misconfiguration by reading the interface.
//
// # Read-only in this build
//
// This package models intent and observes. It does not run tc. The generated
// commands are text for review, consistent with every other part of THN.
package qos

import (
	"fmt"
	"time"
)

// Algorithm is a traffic-shaping algorithm.
type Algorithm string

const (
	// AlgorithmCake is the CAKE qdisc. Rate-aware and application-aware, and
	// the default because it is what actually reduces bufferbloat.
	AlgorithmCake Algorithm = "cake"

	// AlgorithmFqCodel is the fq_codel qdisc. A fallback only: it smooths
	// bursts and shortens the local queue, but without a rate it cannot
	// shape, so bufferbloat on the bottleneck link remains.
	AlgorithmFqCodel Algorithm = "fq_codel"

	// AlgorithmNone disables shaping.
	AlgorithmNone Algorithm = "none"
)

// RateAware reports whether an algorithm can enforce a configured bandwidth.
//
// This is the property that separates CAKE from fq_codel, and it is why a
// fallback is reported as a degradation rather than a substitution.
func (a Algorithm) RateAware() bool { return a == AlgorithmCake }

// Valid reports whether an algorithm is one THN can render.
func (a Algorithm) Valid() bool {
	switch a {
	case AlgorithmCake, AlgorithmFqCodel, AlgorithmNone:
		return true
	}
	return false
}

// String renders an algorithm for display.
func (a Algorithm) String() string { return string(a) }

// Bandwidth is a configured shaping rate.
type Bandwidth struct {
	// DownloadKbps is the downstream rate in kilobits per second.
	DownloadKbps int `json:"download_kbps" yaml:"download_kbps"`

	// UploadKbps is the upstream rate in kilobits per second.
	UploadKbps int `json:"upload_kbps" yaml:"upload_kbps"`

	// OverheadPercent compensates for protocol and Ethernet framing
	// overhead, which is typically 8 to 12 percent on a wired link.
	//
	// This matters more than it looks: shaping at exactly the provisioned
	// rate without accounting for overhead means the payload rate is
	// slightly under the real capacity, so shaping never fills the link and
	// under-utilises it.
	OverheadPercent int `json:"overhead_percent,omitempty" yaml:"overhead_percent,omitempty"`
}

// Effective returns the rate after overhead compensation.
//
// CAKE's bandwidth is the rate at the wire, not the rate of useful payload.
func (b Bandwidth) Effective(direction Direction) int {
	kbps := b.DownloadKbps
	if direction == Upload {
		kbps = b.UploadKbps
	}
	if kbps <= 0 {
		return 0
	}

	overhead := b.OverheadPercent
	if overhead == 0 {
		// A zero here means "not configured", not "no overhead". Silently
		// treating it as zero would under-shape by about a tenth.
		overhead = DefaultOverheadPercent
	}
	if overhead < 0 {
		overhead = 0
	}

	return kbps * (100 + overhead) / 100
}

// IsZero reports whether no rate is configured.
func (b Bandwidth) IsZero() bool { return b.DownloadKbps == 0 && b.UploadKbps == 0 }

// Direction is a traffic direction.
type Direction string

const (
	// Download is traffic leaving the gateway toward the internet, as seen
	// from a LAN client. This is what CAKE's egress bandwidth shapes.
	Download Direction = "download"

	// Upload is traffic arriving at the gateway from the internet.
	Upload Direction = "upload"
)

// DefaultOverheadPercent is the framing overhead assumed when none is set.
const DefaultOverheadPercent = 10

// Limits are CAKE's default queue depths, exposed so they can be tuned.
type Limits struct {
	// TargetMS is the target standing queue delay in milliseconds.
	TargetMS int `json:"target_ms" yaml:"target_ms"`

	// IntervalMS is the moving window over which the delay is measured.
	IntervalMS int `json:"interval_ms" yaml:"interval_ms"`

	// Quantum is the byte quantum used when the delay estimate is unknown.
	Quantum int `json:"quantum" yaml:"quantum"`
}

// DefaultLimits returns CAKE's default queue depths.
//
// These are tuned upstream and are the right values for a home gateway.
// They are exposed so an operator on a long-buffer link can raise them, not so
// THN can silently change them.
func DefaultLimits() Limits {
	return Limits{
		TargetMS:   5,
		IntervalMS: 100,
		Quantum:    1514,
	}
}

// FqCodelLimits returns the parameters fq_codel's tc interface expects.
//
// fq_codel derives target and interval from the measured rate, so these are
// expressed differently from CAKE's. The quantum is the notable one: it should
// match the interface MTU, which THN takes from the configuration rather than
// assuming 1500.
func FqCodelLimits(mtu int) Limits {
	if mtu <= 0 {
		mtu = 1500
	}
	return Limits{
		TargetMS:   5,
		IntervalMS: 100,
		Quantum:    mtu,
	}
}

// Policy is the desired traffic-shaping configuration.
type Policy struct {
	// Enabled reports whether shaping is applied to the interface at all.
	Enabled bool `json:"enabled"`

	// Algorithm is the shaping algorithm. AlgorithmNone is equivalent to
	// Enabled=false.
	Algorithm Algorithm `json:"algorithm"`

	// FallbackToFqCodel permits a rate-unaware algorithm when the kernel
	// cannot provide the requested one.
	//
	// It is on by default because an old kernel with no CAKE support is
	// better served by fq_codel than by no shaping at all — but the loss is
	// always reported, because fq_codel cannot do what CAKE does.
	FallbackToFqCodel bool `json:"fallback_to_fq_codel"`

	// Interface is the egress device. Shaping must be applied on the
	// interface facing the bottleneck link, which for a gateway is the WAN.
	Interface string `json:"interface,omitempty"`

	// Bandwidth is the configured rate.
	Bandwidth Bandwidth `json:"bandwidth"`

	// Limits are the queue depths.
	Limits Limits `json:"limits"`

	// MTU is used to size the fq_codel quantum.
	MTU int `json:"mtu,omitempty"`

	// LinkSpeedMbps is the interface's negotiated speed, when observed. It is
	// used to cross-check the configured rate and is never rendered: tc does
	// not need it, and a stale value must not reach the command line.
	LinkSpeedMbps int `json:"link_speed_mbps,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty"`
}

// PolicyVersion is the policy shape this build produces.
const PolicyVersion = 1

// Default returns a policy with no interface identified and no rate set.
//
// No rate is set deliberately. Guessing a rate would silently cap a real link
// at whatever the guess was, and that failure is invisible: traffic is slower
// and nothing reports an error. The operator has to say what their link
// actually provides.
func Default() Policy {
	return Policy{
		Enabled:           false,
		Algorithm:         AlgorithmCake,
		FallbackToFqCodel: true,
		Interface:         "",
		Bandwidth:         Bandwidth{OverheadPercent: DefaultOverheadPercent},
		Limits:            DefaultLimits(),
		MTU:               1500,
	}
}

// WithInterface returns a copy of the policy bound to an interface.
func (p Policy) WithInterface(iface string) Policy {
	p.Interface = iface
	return p
}

// WithBandwidth returns a copy of the policy with a rate set.
func (p Policy) WithBandwidth(down, up int) Policy {
	p.Bandwidth.DownloadKbps = down
	p.Bandwidth.UploadKbps = up
	return p
}

// String renders a one-line summary.
func (p Policy) String() string {
	if !p.Enabled || p.Algorithm == AlgorithmNone {
		return "qos: disabled"
	}
	return fmt.Sprintf("qos %s on %s: down %dkbit/s up %dkbit/s (wire %dkbit/s down / %dkbit/s up), overhead %d%%",
		p.Algorithm, orNone(p.Interface),
		p.Bandwidth.DownloadKbps, p.Bandwidth.UploadKbps,
		p.Bandwidth.Effective(Download), p.Bandwidth.Effective(Upload),
		p.Bandwidth.OverheadPercent)
}

// orNone renders an empty string as a placeholder.
func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// Selection is the outcome of choosing an algorithm for a host.
type Selection struct {
	// Algorithm is what will be rendered.
	Algorithm Algorithm `json:"algorithm"`

	// Requested is what the policy asked for.
	Requested Algorithm `json:"requested"`

	// Available reports whether the requested algorithm was usable.
	Available bool `json:"requested_available"`

	// Reason explains a fallback, or "" when the request was met.
	Reason string `json:"fallback_reason,omitempty"`

	// Degraded reports whether shaping is materially weaker than requested.
	//
	// This is the field that matters: a fallback that renders successfully
	// but silently does nothing about bufferbloat is worse than one that
	// fails, because the operator believes the problem is solved.
	Degraded bool `json:"degraded"`
}

// Select chooses an algorithm given what the host can provide.
//
// available is the set of algorithms the kernel supports. An empty set means
// nothing was detected, which is treated as "no shaping available" rather than
// "everything available".
func Select(p Policy, available map[Algorithm]bool) Selection {
	requested := p.Algorithm
	if requested == "" {
		requested = AlgorithmCake
	}

	s := Selection{Requested: requested}

	// The requested algorithm is usable.
	if available[requested] {
		s.Algorithm = requested
		s.Available = true
		return s
	}

	// The requested algorithm is unavailable. Whether a fallback applies
	// depends on whether the requested one was the one that needed rate
	// awareness.
	if !p.FallbackToFqCodel {
		s.Algorithm = requested
		s.Reason = fmt.Sprintf("%s is not available on this kernel and fallback is disabled", requested)
		return s
	}

	if available[AlgorithmFqCodel] {
		s.Algorithm = AlgorithmFqCodel
		s.Reason = fmt.Sprintf("%s is not available on this kernel; fell back to %s, which smooths bursts "+
			"but cannot enforce a rate, so bufferbloat on the bottleneck link will remain",
			requested, AlgorithmFqCodel)
		// A fallback from a rate-aware algorithm to a rate-unaware one is a
		// genuine degradation, not an equivalent substitution.
		s.Degraded = requested.RateAware() && !AlgorithmFqCodel.RateAware()
		return s
	}

	s.Algorithm = requested
	s.Reason = fmt.Sprintf("neither %s nor %s is available on this kernel; no shaping can be applied",
		requested, AlgorithmFqCodel)
	return s
}

// Availability describes what a host kernel supports.
type Availability struct {
	// Algorithms is the set of usable algorithms.
	Algorithms map[Algorithm]bool `json:"algorithms"`

	// Source records how this was determined: "probe", "cache" or "unknown".
	Source string `json:"source"`

	// CheckedAt is when the probe ran.
	CheckedAt time.Time `json:"checked_at"`

	// Error records why detection failed, if it did.
	Error string `json:"error,omitempty"`
}

// Supports reports whether an algorithm is available.
func (a Availability) Supports(alg Algorithm) bool { return a.Algorithms[alg] }

// Summary renders availability for display.
//
// The order is fixed rather than map order. Go randomises map iteration, so a
// map-derived summary would print a different string on every call and two
// reports of the same host could not be diffed.
func (a Availability) Summary() string {
	if a.Error != "" {
		return "unknown (" + a.Error + ")"
	}

	if len(a.Algorithms) == 0 {
		return "none detected"
	}

	// The rate-aware algorithm leads, because it is the one an operator is
	// deciding about and the one whose absence changes behaviour.
	order := []Algorithm{AlgorithmCake, AlgorithmFqCodel}

	names := make([]string, 0, len(order))
	for _, alg := range order {
		if a.Algorithms[alg] {
			names = append(names, alg.String())
		}
	}
	if len(names) == 0 {
		return "none detected"
	}
	return joinComma(names)
}

// joinComma joins a list for display.
func joinComma(in []string) string {
	switch len(in) {
	case 0:
		return ""
	case 1:
		return in[0]
	}
	out := in[0]
	for _, s := range in[1:] {
		out += ", " + s
	}
	return out
}
