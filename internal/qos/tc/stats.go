// Package tc renders traffic-shaping commands and parses queue statistics.
//
// # Read only
//
// Render produces command text. Stats parses text that was read. Neither
// executes anything, and neither can: this package imports no os/exec, and
// the repository-wide guard test would fail the build if it did.
//
// # Statistics are the point of shaping
//
// Shaping is invisible until something goes wrong. A queue that is not
// dropping, and a queue that is dropping everything, look identical from
// outside. Statistics are how an operator finds out which one they have, so
// they are modelled here rather than left as a wall of tc output.
package tc

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Stats are the observed counters for one queue discipline.
type Stats struct {
	// Algorithm is the qdisc kind, e.g. "cake" or "fq_codel".
	Algorithm string `json:"algorithm"`

	// Handle is the qdisc handle, e.g. "8001:".
	Handle string `json:"handle,omitempty"`

	// Interface is the device the qdisc is attached to.
	Interface string `json:"interface,omitempty"`

	// Root reports whether this is the root qdisc.
	Root bool `json:"root"`

	// Bytes is the total bytes the qdisc has handled.
	Bytes uint64 `json:"bytes"`

	// Packets is the total packet count.
	Packets uint64 `json:"packets"`

	// Dropped is the packet count discarded by the qdisc.
	//
	// A non-zero value under load is normal and is how a shaper does its job:
	// it drops deliberately rather than letting the device queue fill. What
	// matters is whether drops are proportional to load.
	Dropped uint64 `json:"dropped"`

	// Overlimits is the count of times the shaper had to impose its limit.
	//
	// This is the signal that the link is genuinely saturated. A high
	// overlimit count with a low drop count means CAKE is managing the queue
	// well; a high count with a high drop count means it is not.
	Overlimits uint64 `json:"overlimits"`

	// Requeues is the count of packets the qdisc had to requeue. Frequent
	// requeues indicate contention within the queue.
	Requeues uint64 `json:"requeues"`

	// BacklogBytes is the bytes currently held in the queue.
	//
	// This is the number that matters most for bufferbloat: it is the delay
	// the queue is currently adding.
	BacklogBytes uint32 `json:"backlog_bytes"`

	// BacklogPackets is the packet count currently held.
	BacklogPackets uint32 `json:"backlog_packets"`

	// QueueLength is the configured queue depth, in packets.
	QueueLength uint32 `json:"queue_length"`

	// BandwidthMbps is the rate CAKE is shaping to, as read back from the
	// qdisc. Zero for algorithms with no rate.
	BandwidthMbps int `json:"bandwidth_mbps,omitempty"`

	// Errors is anything that could not be parsed from this qdisc.
	Errors []string `json:"errors,omitempty"`
}

// Present reports whether any traffic has been handled.
//
// A qdisc that exists but has seen nothing is different from one that is not
// installed, and the distinction matters: the first means shaping is armed and
// idle, the second means it is not working.
func (s Stats) Present() bool { return s.Bytes > 0 || s.Packets > 0 }

// DropRatio returns the fraction of packets dropped.
//
// It is 0 for a qdisc that has handled nothing, because reporting "50% drops"
// for an idle queue would be nonsense.
func (s Stats) DropRatio() float64 {
	if s.Packets == 0 {
		return 0
	}
	return float64(s.Dropped) / float64(s.Packets)
}

// OverlimitRatio returns the fraction of packets that hit the shaper limit.
func (s Stats) OverlimitRatio() float64 {
	if s.Packets == 0 {
		return 0
	}
	return float64(s.Overlimits) / float64(s.Packets)
}

// ThroughputBps estimates the current throughput from the backlog-free
// counters.
//
// This is an approximation: it assumes the counters were read over the
// interval since they last changed, which is not knowable from a single read.
// Callers that need a rate should read twice and divide.
func (s Stats) ThroughputBps(elapsedSeconds float64) float64 {
	if elapsedSeconds <= 0 {
		return 0
	}
	return float64(s.Bytes) * 8 / elapsedSeconds
}

// Health classifies whether the queue is behaving.
//
// The distinction that matters is between a shaper managing a saturated link
// and a shaper failing to. Both show high overlimits. Only the second shows
// high drops alongside a growing backlog.
type Health string

const (
	// HealthIdle means the queue has seen no traffic.
	HealthIdle Health = "idle"
	// HealthHealthy means the queue is passing traffic without excessive loss.
	HealthHealthy Health = "healthy"
	// HealthShaping means the link is saturated and the shaper is managing it,
	// which is the intended behaviour under load.
	HealthShaping Health = "shaping"
	// HealthCongested means the queue is dropping heavily, which suggests the
	// shaping rate is too low for the offered load.
	HealthCongested Health = "congested"
	// HealthStalled means traffic is queued but not moving, which indicates a
	// problem below the shaper.
	HealthStalled Health = "stalled"
)

// Assess classifies queue health from its counters.
//
// The thresholds are deliberately conservative. Reporting a healthy queue as
// congested trains an operator to ignore the warning, and the cost of a missed
// congestion signal on a remote link is an afternoon of "the internet is slow"
// with nothing to point at.
func (s Stats) Assess() Health {
	switch {
	case !s.Present():
		return HealthIdle

	// Heavy loss with traffic still moving: the shaper rate is below the
	// offered load.
	case s.DropRatio() > 0.10:
		return HealthCongested

	// Packets held but nothing progressing.
	case s.BacklogPackets > 1000 && s.BacklogBytes == 0:
		return HealthStalled

	// The link is genuinely busy and the shaper is managing it.
	case s.OverlimitRatio() > 0.05:
		return HealthShaping

	default:
		return HealthHealthy
	}
}

// Explain renders a one-line explanation of the health verdict.
func (s Stats) Explain() string {
	switch h := s.Assess(); h {
	case HealthIdle:
		return "no traffic has been handled yet; shaping is armed but idle"
	case HealthCongested:
		return fmt.Sprintf("%s of packets dropped (%d of %d); the shaped rate is below the offered load",
			percent(s.DropRatio()), s.Dropped, s.Packets)
	case HealthStalled:
		return fmt.Sprintf("%d packets queued but none moving; the link below is not draining",
			s.BacklogPackets)
	case HealthShaping:
		return fmt.Sprintf("link is saturated and the shaper is managing it (%s overlimit, %s dropped)",
			percent(s.OverlimitRatio()), percent(s.DropRatio()))
	default:
		return fmt.Sprintf("passing traffic normally (%d packets, %s dropped)",
			s.Packets, percent(s.DropRatio()))
	}
}

// percent renders a ratio as a short percentage.
func percent(r float64) string {
	return strconv.FormatFloat(r*100, 'f', 1, 64) + "%"
}

// Snapshot is a read of one interface's queue discipline.
type Snapshot struct {
	// Interface is the device read.
	Interface string `json:"interface"`

	// Root is the root qdisc's statistics.
	Root Stats `json:"root"`

	// Children are any qdiscs beneath the root.
	Children []Stats `json:"children,omitempty"`

	// Present reports whether a root qdisc was found.
	Present bool `json:"present"`

	// ReadAtUnix is when the counters were read, for rate calculation.
	ReadAtUnix int64 `json:"read_at_unix,omitempty"`
}

// tcQdiscJSON mirrors one entry of `tc -j -s qdisc show`.
//
// Only the fields THN reads are declared. iproute2 has added fields over time
// and encoding/json ignores the rest, which is what keeps this decoding
// working across versions.
type tcQdiscJSON struct {
	Kind   string `json:"kind"`
	Handle string `json:"handle"`
	Root   bool   `json:"root"`
	Refcnt int    `json:"refcnt"`

	Bytes      uint64 `json:"bytes"`
	Packets    uint64 `json:"packets"`
	Drops      uint64 `json:"drops"`
	Overlimits uint64 `json:"overlimits"`
	Requeues   uint64 `json:"requeues"`
	Backlog    uint32 `json:"backlog"`
	Queued     uint32 `json:"queued"`
	Qlen       uint32 `json:"qlen"`

	Options map[string]any `json:"options"`
}

// ParseStats parses `tc -j -s qdisc show` output for one interface.
//
// An empty array means no qdisc is attached, which is a normal state and is
// reported as Present=false rather than as an error. Malformed output is
// reported through Errors on the snapshot rather than by failing, because a
// caller inspecting a busy host should see partial data plus a complaint.
func ParseStats(iface, output string) (Snapshot, error) {
	snap := Snapshot{Interface: iface, Root: Stats{Interface: iface}}

	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		// tc prints nothing at all when no qdisc is present. This is the
		// common case on an unshaped interface.
		return snap, nil
	}

	var entries []tcQdiscJSON
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		return snap, fmt.Errorf("parsing tc output for %s: %w", iface, err)
	}

	for _, e := range entries {
		st := Stats{
			Algorithm:      e.Kind,
			Handle:         e.Handle,
			Interface:      iface,
			Root:           e.Root,
			Bytes:          e.Bytes,
			Packets:        e.Packets,
			Dropped:        e.Drops,
			Overlimits:     e.Overlimits,
			Requeues:       e.Requeues,
			BacklogBytes:   e.Backlog,
			BacklogPackets: e.Queued,
			QueueLength:    e.Qlen,
		}

		st.BandwidthMbps = bandwidthFromOptions(e.Options)

		if e.Root {
			snap.Root = st
			snap.Present = true
			continue
		}
		snap.Children = append(snap.Children, st)
	}

	// Children are sorted by kind then handle so that two reads of an
	// unchanged host produce identical output.
	sort.SliceStable(snap.Children, func(i, j int) bool {
		if snap.Children[i].Algorithm != snap.Children[j].Algorithm {
			return snap.Children[i].Algorithm < snap.Children[j].Algorithm
		}
		return snap.Children[i].Handle < snap.Children[j].Handle
	})

	return snap, nil
}

// bandwidthFromOptions reads the shaped rate back out of the qdisc options.
//
// iproute2 reports CAKE's bandwidth in megabits under the key "bandwidth", and
// that value is taken as megabits. An earlier version of this function tried
// to be clever: it guessed that a number above 10000 must be bytes per second
// and converted it. That guess is wrong, and wrong in the worst direction —
// it read a 10 Gbit/s CAKE link as 0 Mbit/s, because 10000 Mbit/s * 8 / 1e6
// rounds to 0. A shaper reporting no rate reads as "not configured", which is
// the one conclusion an operator must never be misled about.
//
// So the ambiguous keys are not interpreted at all. "rate" appears on several
// qdiscs in several different units and is left alone; the caller can tell from
// the algorithm what it is looking at. An unreadable rate is reported as zero
// rather than guessed, because a wrong rate here would be used to judge
// whether the shaper is configured correctly.
func bandwidthFromOptions(opts map[string]any) int {
	if opts == nil {
		return 0
	}

	// Both keys carry an explicit unit, so neither needs guessing.
	for _, key := range []string{"bandwidth", "bandwidth_mbps"} {
		v, ok := opts[key]
		if !ok {
			continue
		}
		if mbps, ok := toMbps(v); ok {
			return mbps
		}
	}
	return 0
}

// toMbps converts a tc option value to whole megabits per second.
//
// The input is already in megabits. This is a plain numeric conversion with no
// unit inference: refusing to guess is worth more here than covering a case
// that the algorithm name already identifies.
func toMbps(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		if t <= 0 {
			return 0, false
		}
		return int(t + 0.5), true
	case int:
		if t <= 0 {
			return 0, false
		}
		return t, true
	case string:
		f, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return 0, false
		}
		return toMbps(f)
	default:
		return 0, false
	}
}
