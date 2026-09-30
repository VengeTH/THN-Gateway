package tc

import (
	"strings"
	"testing"
)

// cakeOutput is the shape `tc -j -s qdisc show dev eth0` produces when CAKE is
// attached. Field names and the integer-as-megabits convention are taken from
// iproute2's JSON writer.
const cakeOutput = `[
	{
		"kind": "cake",
		"handle": "8001:",
		"root": true,
		"refcnt": 2,
		"bytes": 8473620944,
		"packets": 5914221,
		"drops": 1284,
		"overlimits": 481203,
		"requeues": 0,
		"backlog": 0,
		"queued": 0,
		"qlen": 1000,
		"options": {
			"bandwidth": 110,
			"uplink": 22,
			"target": 5000000,
			"interval": 100000000,
			"quantum": 1514,
			"besteffort": true,
			"diffserv4": true
		}
	},
	{
		"kind": "fq_codel",
		"handle": "0:",
		"parent": "8001:",
		"refcnt": 2
	}
]`

// fqCodelOutput is the shape when only fq_codel is attached.
const fqCodelOutput = `[
	{
		"kind": "fq_codel",
		"handle": "0:",
		"root": true,
		"refcnt": 2,
		"bytes": 1048576,
		"packets": 1024,
		"drops": 12,
		"overlimits": 0,
		"backlog": 4096,
		"queued": 3,
		"qlen": 10240,
		"options": {
			"limit": 10240,
			"flows": 1024,
			"quantum": 1500
		}
	}
]`

// defaultQueueOutput is what a machine with no shaping looks like.
const defaultQueueOutput = `[
	{
		"kind": "pfifo_fast",
		"handle": "0:",
		"root": true,
		"refcnt": 2,
		"bytes": 2048,
		"packets": 16,
		"drops": 0,
		"overlimits": 0,
		"backlog": 0,
		"queued": 0,
		"qlen": 1000
	}
]`

// TestParseStatsReadsCake: the counters an operator actually acts on must come
// back from real tc output.
func TestParseStatsReadsCake(t *testing.T) {
	snap, err := ParseStats("eth0", cakeOutput)
	if err != nil {
		t.Fatalf("ParseStats: %v", err)
	}

	if !snap.Present {
		t.Fatal("present = false, want true")
	}
	if snap.Interface != "eth0" {
		t.Errorf("interface = %q, want eth0", snap.Interface)
	}

	r := snap.Root
	if r.Algorithm != "cake" {
		t.Errorf("algorithm = %q, want cake", r.Algorithm)
	}
	if r.Handle != "8001:" {
		t.Errorf("handle = %q, want 8001:", r.Handle)
	}
	if !r.Root {
		t.Error("root = false, want true")
	}
	if r.Bytes != 8473620944 {
		t.Errorf("bytes = %d, want 8473620944", r.Bytes)
	}
	if r.Packets != 5914221 {
		t.Errorf("packets = %d, want 5914221", r.Packets)
	}
	if r.Dropped != 1284 {
		t.Errorf("dropped = %d, want 1284", r.Dropped)
	}
	if r.Overlimits != 481203 {
		t.Errorf("overlimits = %d, want 481203", r.Overlimits)
	}
	if r.QueueLength != 1000 {
		t.Errorf("qlen = %d, want 1000", r.QueueLength)
	}
	if r.BandwidthMbps != 110 {
		t.Errorf("bandwidth = %d, want 110", r.BandwidthMbps)
	}
}

// TestParseStatsReadsFqCodel: an algorithm with no rate must report a rate of
// zero, not a guess.
func TestParseStatsReadsFqCodel(t *testing.T) {
	snap, err := ParseStats("eth0", fqCodelOutput)
	if err != nil {
		t.Fatalf("ParseStats: %v", err)
	}

	if !snap.Present {
		t.Fatal("present = false, want true")
	}
	if snap.Root.Algorithm != "fq_codel" {
		t.Errorf("algorithm = %q, want fq_codel", snap.Root.Algorithm)
	}
	if snap.Root.BandwidthMbps != 0 {
		t.Errorf("bandwidth = %d, want 0; fq_codel has no rate to report", snap.Root.BandwidthMbps)
	}
	if snap.Root.Dropped != 12 {
		t.Errorf("dropped = %d, want 12", snap.Root.Dropped)
	}
}

// TestParseStatsReportsTheDefaultQueue is the important negative case: pfifo_fast
// is present and is not shaping, which an operator needs to be able to see.
func TestParseStatsReportsTheDefaultQueue(t *testing.T) {
	snap, err := ParseStats("eth0", defaultQueueOutput)
	if err != nil {
		t.Fatalf("ParseStats: %v", err)
	}

	if !snap.Present {
		t.Fatal("present = false; a pfifo_fast qdisc is present even though it does not shape")
	}
	if snap.Root.Algorithm != "pfifo_fast" {
		t.Errorf("algorithm = %q, want pfifo_fast", snap.Root.Algorithm)
	}
}

// TestParseStatsOnEmptyArray is the common unshaped case: tc prints an empty
// JSON array, which must not be an error.
func TestParseStatsOnEmptyArray(t *testing.T) {
	snap, err := ParseStats("eth0", "[]")
	if err != nil {
		t.Fatalf("an empty array must not be an error: %v", err)
	}
	if snap.Present {
		t.Error("present = true, want false for an empty array")
	}
	if snap.Root.Algorithm != "" {
		t.Errorf("algorithm = %q, want empty", snap.Root.Algorithm)
	}
}

// TestParseStatsOnEmptyOutput covers tc printing nothing at all.
func TestParseStatsOnEmptyOutput(t *testing.T) {
	for _, in := range []string{"", "   ", "\n\n"} {
		snap, err := ParseStats("eth0", in)
		if err != nil {
			t.Errorf("input %q must not be an error: %v", in, err)
		}
		if snap.Present {
			t.Errorf("input %q: present = true, want false", in)
		}
	}
}

// TestParseStatsOnMalformedOutput: a parse failure is reported, not swallowed
// and not presented as "no qdisc", which would read as good news.
func TestParseStatsOnMalformedOutput(t *testing.T) {
	for _, in := range []string{"qdisc cake 8001:", "{not json", "[{\"kind\":"} {
		if _, err := ParseStats("eth0", in); err == nil {
			t.Errorf("input %q: expected an error, got nil", in)
		}
	}
}

// TestParseStatsCollectsChildren: a root with a child must report both, and
// the child must not be mistaken for the root.
func TestParseStatsCollectsChildren(t *testing.T) {
	snap, err := ParseStats("eth0", cakeOutput)
	if err != nil {
		t.Fatalf("ParseStats: %v", err)
	}

	if len(snap.Children) != 1 {
		t.Fatalf("children = %d, want 1", len(snap.Children))
	}
	if snap.Children[0].Algorithm != "fq_codel" {
		t.Errorf("child algorithm = %q, want fq_codel", snap.Children[0].Algorithm)
	}
	if snap.Root.Algorithm == snap.Children[0].Algorithm {
		t.Error("the child overwrote the root")
	}
}

// TestParseStatsChildrenAreDeterministic: two reads of an unchanged host must
// produce identical output, or two reports of the same host cannot be diffed.
func TestParseStatsChildrenAreDeterministic(t *testing.T) {
	multi := `[
		{"kind":"cake","handle":"8001:","root":true},
		{"kind":"fq_codel","handle":"0:","parent":"8001:"},
		{"kind":"netem","handle":"0:","parent":"8001:","refcnt":2}
	]`

	first, err := ParseStats("eth0", multi)
	if err != nil {
		t.Fatalf("ParseStats: %v", err)
	}
	for i := 0; i < 30; i++ {
		got, err := ParseStats("eth0", multi)
		if err != nil {
			t.Fatalf("ParseStats: %v", err)
		}
		if len(got.Children) != len(first.Children) {
			t.Fatalf("child count varies: %d then %d", len(first.Children), len(got.Children))
		}
		for j := range got.Children {
			if got.Children[j].Algorithm != first.Children[j].Algorithm {
				t.Fatalf("child order varies: %v then %v", first.Children, got.Children)
			}
		}
	}
}

// TestParseStatsIgnoresUnknownFields: iproute2 adds fields over time, and a
// new one must not break decoding.
func TestParseStatsIgnoresUnknownFields(t *testing.T) {
	out := `[{"kind":"cake","handle":"8001:","root":true,"future_field":42,"nested":{"a":[1,2]}}]`

	snap, err := ParseStats("eth0", out)
	if err != nil {
		t.Fatalf("unknown fields must be ignored: %v", err)
	}
	if snap.Root.Algorithm != "cake" {
		t.Errorf("algorithm = %q, want cake", snap.Root.Algorithm)
	}
}

// TestDropRatioAndOverlimitRatio are the numbers the health verdict rests on.
func TestDropRatioAndOverlimitRatio(t *testing.T) {
	s := Stats{Packets: 1000, Dropped: 100, Overlimits: 500}

	if got := s.DropRatio(); got != 0.1 {
		t.Errorf("drop ratio = %v, want 0.1", got)
	}
	if got := s.OverlimitRatio(); got != 0.5 {
		t.Errorf("overlimit ratio = %v, want 0.5", got)
	}
}

// TestRatiosAreZeroForAnIdleQueue: reporting "50% drops" for a queue that has
// seen nothing is nonsense, and an operator acting on it would be misled.
func TestRatiosAreZeroForAnIdleQueue(t *testing.T) {
	s := Stats{}

	if got := s.DropRatio(); got != 0 {
		t.Errorf("drop ratio = %v, want 0", got)
	}
	if got := s.OverlimitRatio(); got != 0 {
		t.Errorf("overlimit ratio = %v, want 0", got)
	}
	if s.Present() {
		t.Error("present = true for a qdisc that has handled nothing")
	}
}

// TestAssessIdle covers a correctly-configured but unused shaper.
func TestAssessIdle(t *testing.T) {
	s := Stats{Algorithm: "cake"}

	if got := s.Assess(); got != HealthIdle {
		t.Errorf("health = %q, want idle", got)
	}
	if !strings.Contains(s.Explain(), "idle") {
		t.Errorf("explanation %q should mention that it is idle", s.Explain())
	}
}

// TestAssessHealthy is the ordinary good state.
func TestAssessHealthy(t *testing.T) {
	s := Stats{Algorithm: "cake", Bytes: 1 << 30, Packets: 1_000_000, Dropped: 100, Overlimits: 1000}

	if got := s.Assess(); got != HealthHealthy {
		t.Errorf("health = %q, want healthy (overlimits %v, drops %v)",
			got, s.OverlimitRatio(), s.DropRatio())
	}
}

// TestAssessShaping is the state a working shaper is in under load: high
// overlimits, low drops. It is the intended behaviour, not a fault.
func TestAssessShaping(t *testing.T) {
	s := Stats{Algorithm: "cake", Bytes: 1 << 30, Packets: 1_000_000, Dropped: 10_000, Overlimits: 500_000}

	if got := s.Assess(); got != HealthShaping {
		t.Errorf("health = %q, want shaping (overlimits %v, drops %v)",
			got, s.OverlimitRatio(), s.DropRatio())
	}
}

// TestAssessCongested: a shaper rate below the offered load shows heavy loss
// alongside traffic still moving.
func TestAssessCongested(t *testing.T) {
	s := Stats{Algorithm: "cake", Bytes: 1 << 30, Packets: 1_000_000, Dropped: 200_000, Overlimits: 900_000}

	if got := s.Assess(); got != HealthCongested {
		t.Errorf("health = %q, want congested (drops %v)", got, s.DropRatio())
	}
	if !strings.Contains(s.Explain(), "below the offered load") {
		t.Errorf("explanation %q should name the cause", s.Explain())
	}
}

// TestAssessStalled: packets held with nothing progressing points at
// something below the shaper.
func TestAssessStalled(t *testing.T) {
	s := Stats{Algorithm: "cake", Packets: 5000, BacklogPackets: 2000, BacklogBytes: 0}

	if got := s.Assess(); got != HealthStalled {
		t.Errorf("health = %q, want stalled", got)
	}
	if !strings.Contains(s.Explain(), "not draining") {
		t.Errorf("explanation %q should say the link is not draining", s.Explain())
	}
}

// TestCongestedOutranksStalled: heavy loss with traffic moving is the more
// specific diagnosis, and reporting a generic stall instead would send an
// operator to the wrong component.
func TestCongestedOutranksStalled(t *testing.T) {
	s := Stats{Algorithm: "cake", Packets: 1000, Dropped: 500, BacklogPackets: 2000, BacklogBytes: 0}

	if got := s.Assess(); got != HealthCongested {
		t.Errorf("health = %q, want congested", got)
	}
}

// TestAssessIsDeterministic across repeated calls.
func TestAssessIsDeterministic(t *testing.T) {
	s := Stats{Algorithm: "cake", Bytes: 1 << 20, Packets: 1000, Dropped: 5, Overlimits: 800}

	first := s.Assess()
	for i := 0; i < 100; i++ {
		if got := s.Assess(); got != first {
			t.Fatalf("health changed between calls: %q then %q", first, got)
		}
	}
}

// TestEveryHealthHasAnExplanation: an operator reading the verdict needs the
// sentence with it, and a missing one reads as a bug in the tool.
func TestEveryHealthHasAnExplanation(t *testing.T) {
	cases := []Stats{
		{Algorithm: "cake"},
		{Algorithm: "cake", Bytes: 1 << 20, Packets: 1000, Dropped: 1},
		{Algorithm: "cake", Bytes: 1 << 20, Packets: 1000, Dropped: 1, Overlimits: 900},
		{Algorithm: "cake", Bytes: 1 << 20, Packets: 1000, Dropped: 500},
		{Algorithm: "cake", Packets: 2000, BacklogPackets: 2000},
	}

	seen := map[Health]bool{}
	for _, s := range cases {
		h := s.Assess()
		seen[h] = true
		if s.Explain() == "" {
			t.Errorf("health %q has no explanation", h)
		}
	}

	for _, want := range []Health{HealthIdle, HealthHealthy, HealthShaping, HealthCongested, HealthStalled} {
		if !seen[want] {
			t.Errorf("the fixture set never produces %q; the test is not covering it", want)
		}
	}
}

// TestThroughputBps covers the rate helper, including the divide-by-zero case
// that a zero interval would otherwise turn into a NaN.
func TestThroughputBps(t *testing.T) {
	s := Stats{Bytes: 1_000_000} // 8,000,000 bits

	if got := s.ThroughputBps(2); got != 4_000_000 {
		t.Errorf("throughput = %v, want 4000000", got)
	}
	if got := s.ThroughputBps(0); got != 0 {
		t.Errorf("throughput with a zero interval = %v, want 0", got)
	}
	if got := s.ThroughputBps(-1); got != 0 {
		t.Errorf("throughput with a negative interval = %v, want 0", got)
	}
}

// TestBandwidthFromOptions covers the key variants iproute2 has used.
//
// Only keys carrying an explicit unit are read. The ambiguous "rate" key is
// deliberately not interpreted; see the comment on bandwidthFromOptions.
func TestBandwidthFromOptions(t *testing.T) {
	cases := []struct {
		name string
		opts map[string]any
		want int
	}{
		{"megabits", map[string]any{"bandwidth": float64(110)}, 110},
		{"explicit mbps key", map[string]any{"bandwidth_mbps": float64(50)}, 50},
		{"string", map[string]any{"bandwidth": "40"}, 40},
		{"integer", map[string]any{"bandwidth": 100}, 100},
		{"fractional", map[string]any{"bandwidth": 2.5}, 3},
		{"absent", map[string]any{"other": 1}, 0},
		{"nil", nil, 0},
		{"unparseable string", map[string]any{"bandwidth": "fast"}, 0},
		{"zero", map[string]any{"bandwidth": float64(0)}, 0},
		{"negative", map[string]any{"bandwidth": float64(-1)}, 0},
		{"wrong type", map[string]any{"bandwidth": []int{1}}, 0},
		{"ambiguous rate key is not read", map[string]any{"rate": float64(25)}, 0},
		{"a byte rate is not converted", map[string]any{"bandwidth": float64(12_500_000)}, 12_500_000},
	}

	for _, c := range cases {
		if got := bandwidthFromOptions(c.opts); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// TestBandwidthIsNotUnitGuessed is a regression test for a real bug.
//
// The parser used to treat any value above 10000 as bytes per second and
// convert it. That made a 10 Gbit/s CAKE link report 0 Mbit/s, because
// 10000 * 8 / 1e6 rounds to 0. A shaper that reports no rate looks exactly
// like one that was never configured, which is the single most misleading
// thing this reader could produce.
func TestBandwidthIsNotUnitGuessed(t *testing.T) {
	for _, c := range []struct {
		raw  float64
		want int
	}{
		{110, 110},
		{1000, 1000},
		{10000, 10000},
		{100000, 100000},
		{400000, 400000}, // 400 Gbit/s, the ceiling the validator allows
	} {
		got := bandwidthFromOptions(map[string]any{"bandwidth": c.raw})
		if got != c.want {
			t.Errorf("bandwidth %v: got %d, want %d", c.raw, got, c.want)
		}
		if got == 0 {
			t.Errorf("bandwidth %v reported as 0; a configured shaper must never look unset", c.raw)
		}
	}
}

// TestParseStatsReadsAFastLinkEndToEnd: the regression above, exercised
// through the public entry point rather than the helper.
func TestParseStatsReadsAFastLinkEndToEnd(t *testing.T) {
	out := `[{"kind":"cake","handle":"8001:","root":true,"options":{"bandwidth":40000}}]`

	snap, err := ParseStats("eth0", out)
	if err != nil {
		t.Fatalf("ParseStats: %v", err)
	}
	if snap.Root.BandwidthMbps != 40000 {
		t.Errorf("bandwidth = %d, want 40000", snap.Root.BandwidthMbps)
	}
}

// TestStatsErrorsFieldIsAvailable: a caller must be able to attach a problem
// to a specific qdisc rather than failing the whole read.
func TestStatsErrorsFieldIsAvailable(t *testing.T) {
	s := Stats{Algorithm: "cake"}
	s.Errors = append(s.Errors, "bandwidth could not be read")

	if len(s.Errors) != 1 {
		t.Fatalf("errors = %v, want one entry", s.Errors)
	}
}
