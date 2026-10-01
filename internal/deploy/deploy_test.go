package deploy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/deploy"
	"github.com/venth/thn-gateway/internal/health"
)

var at = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func healthy(gw string) health.Report {
	return health.Report{Gateway: gw, Verdict: health.VerdictHealthy}
}

func withVerdict(gw string, v health.Verdict) health.Report {
	return health.Report{Gateway: gw, Verdict: v}
}

func rollout(t *testing.T, fleet int) *deploy.Rollout {
	t.Helper()
	r := deploy.New("gen-41", fleet, deploy.DefaultThresholds())
	r.Now = func() time.Time { return at }
	return r
}

// ----------------------------------------------------------------- stages

// The stages exist to bound the cost of finding out the change is wrong.
func TestStagesAdvanceInOrder(t *testing.T) {
	s, ok := deploy.Next(deploy.StageCanary)
	if !ok || s != deploy.StageSmall {
		t.Errorf("canary -> %s, want small", s)
	}
	s, ok = deploy.Next(deploy.StageHalf)
	if !ok || s != deploy.StageFull {
		t.Errorf("half -> %s, want full", s)
	}
	if _, ok := deploy.Next(deploy.StageFull); ok {
		t.Error("full reported a next stage")
	}
}

func TestCapsWiden(t *testing.T) {
	fleet := 1000
	prev := 0
	for _, s := range []deploy.Stage{
		deploy.StageCanary, deploy.StageSmall, deploy.StageQuarter,
		deploy.StageHalf, deploy.StageFull,
	} {
		n := deploy.CapFor(s, fleet)
		if n <= prev {
			t.Errorf("stage %s caps at %d, not more than the previous %d", s, n, prev)
		}
		prev = n
	}
	if deploy.CapFor(deploy.StageFull, fleet) != fleet {
		t.Error("full does not cover the fleet")
	}
}

// A canary is one gateway, not one per cent. A percentage of a small fleet is
// zero, and a rollout that advances by nothing looks like one that has stalled.
func TestCanaryIsOneGatewayEvenOnATinyFleet(t *testing.T) {
	for _, fleet := range []int{1, 3, 9} {
		if n := deploy.CapFor(deploy.StageCanary, fleet); n != 1 {
			t.Errorf("canary on a fleet of %d is %d, want 1", fleet, n)
		}
		if n := deploy.CapFor(deploy.StageSmall, fleet); n < 1 {
			t.Errorf("small stage on a fleet of %d is %d", fleet, n)
		}
	}
}

// ------------------------------------------------------------------ halting

// The property the package exists for. A rollout that has to be watched and
// stopped by a person will, once, run to completion with nobody watching.
func TestOneUnhealthyGatewayHaltsTheRollout(t *testing.T) {
	r := rollout(t, 100)

	// Send the change, then the reports come back, then judge. This order is
	// the lifecycle: MarkApplied clears the stage's reports because they
	// belong to the previous stage.
	r.MarkApplied(1)
	r.Record(healthy("site-001"))

	d := r.Advance()
	if d.Action != deploy.ActionAdvance {
		t.Fatalf("a healthy canary did not advance: %s", d.Action)
	}

	r.MarkApplied(10)
	r.Record(withVerdict("site-002", health.VerdictUnhealthy))
	d = r.Advance()
	if d.Action != deploy.ActionHalt {
		t.Fatalf("an unhealthy gateway did not halt the rollout: %s (%s)", d.Action, d.Reason)
	}
	if len(d.Triggered) == 0 {
		t.Error("the halt does not name the gateway that caused it")
	}
	if !strings.Contains(d.Reason, "site-002") {
		t.Errorf("the reason does not name the gateway: %s", d.Reason)
	}
}

// Zero unhealthy is tolerated. One is not: that is the whole point of a canary.
func TestASingleUnhealthyGatewayIsEnoughToHalt(t *testing.T) {
	r := rollout(t, 100)
	r.MarkApplied(1)
	r.Record(withVerdict("site-001", health.VerdictUnhealthy))

	if d := r.Advance(); d.Action != deploy.ActionHalt {
		t.Fatalf("one unhealthy gateway out of one did not halt: %s", d.Action)
	}
}

// A gateway that cannot be read after a change is not a gateway that passed.
func TestUnreadableGatewayHaltsTheRollout(t *testing.T) {
	r := rollout(t, 100)
	r.MarkApplied(1)
	r.Record(withVerdict("site-001", health.VerdictUnknowable))

	d := r.Advance()
	if d.Action != deploy.ActionHalt {
		t.Fatalf("an unreadable gateway did not halt: %s", d.Action)
	}
	if !strings.Contains(d.Reason, "not a gateway that passed") {
		t.Errorf("the reason does not explain why an unread is not a pass: %s", d.Reason)
	}
}

func TestTooManyDegradedHaltsTheRollout(t *testing.T) {
	th := deploy.DefaultThresholds()
	th.MaxDegradedFraction = 0.25

	r := deploy.New("gen-41", 10, th)
	r.Now = func() time.Time { return at }
	r.MarkApplied(4)

	for i := 0; i < 4; i++ {
		r.Record(withVerdict(string(rune('a'+i))+"site", health.VerdictDegraded))
	}

	d := r.Advance()
	if d.Action != deploy.ActionHalt {
		t.Fatalf("4 of 4 degraded did not halt: %s (%s)", d.Action, d.Reason)
	}
}

func TestManyUnhealthyRecommendsRollback(t *testing.T) {
	th := deploy.DefaultThresholds()
	th.MaxUnhealthy = 1

	r := deploy.New("gen-41", 10, th)
	r.Now = func() time.Time { return at }
	r.MarkApplied(4)

	for _, gw := range []string{"a", "b", "c", "d"} {
		r.Record(withVerdict(gw, health.VerdictUnhealthy))
	}

	d := r.Advance()
	if d.Action != deploy.ActionRollback {
		t.Fatalf("4 unhealthy gateways did not recommend rollback: %s", d.Action)
	}
}

// ---------------------------------------------------------------- sticky

// A halt is sticky. A rollout that resumes because the newest report looks
// better has no halt in it at all.
func TestHaltDoesNotResumeOnAHealthyReport(t *testing.T) {
	r := rollout(t, 100)
	r.MarkApplied(1)
	r.Record(withVerdict("site-001", health.VerdictUnhealthy))
	r.Advance()

	if !r.Halted {
		t.Fatal("the rollout did not halt")
	}

	r.Record(healthy("site-002"), healthy("site-003"))

	d := r.Advance()
	if d.Action != deploy.ActionHalt {
		t.Fatalf("a halted rollout resumed: %s", d.Action)
	}
	if !strings.Contains(d.Reason, "new decision") {
		t.Errorf("the reason does not say resuming is a decision: %s", d.Reason)
	}
}

// Resuming produces a new rollout rather than clearing this one, so the halt
// and the resumption stay distinguishable in a record.
func TestResumeProducesANewRollout(t *testing.T) {
	r := rollout(t, 100)
	r.MarkApplied(1)
	r.Record(withVerdict("site-001", health.VerdictUnhealthy))
	r.Advance()

	if !r.Halted {
		t.Fatal("setup: the rollout did not halt")
	}

	next := r.Resume("gen-42", 100)
	if next == r {
		t.Error("Resume returned the same rollout")
	}
	if next.Halted {
		t.Error("the new rollout started halted")
	}
	if r.Halted != true {
		t.Error("the original rollout lost its halted flag")
	}
}

// ------------------------------------------------------------- evidence

// Advancing before the canary has reported is how a rollout reaches the fleet
// before anyone has heard back from the canary.
func TestDoesNotWidenOnIncompleteEvidence(t *testing.T) {
	th := deploy.DefaultThresholds()
	th.MinReports = 2

	r := deploy.New("gen-41", 100, th)
	r.Now = func() time.Time { return at }
	r.MarkApplied(10)

	d := r.Advance()
	if d.Action != deploy.ActionRepeat {
		t.Fatalf("widened with one report out of two required: %s", d.Action)
	}
	if !strings.Contains(d.Reason, "incomplete evidence") {
		t.Errorf("the reason does not say why: %s", d.Reason)
	}
}

// A stage's reports must not be carried into the next stage, or a good gateway
// averages with a bad one and hides what the stages exist to separate.
func TestMarkAppliedClearsTheStageReports(t *testing.T) {
	r := rollout(t, 100)
	r.Record(healthy("site-001"), healthy("site-002"))

	if len(r.Reports) != 2 {
		t.Fatal("setup: reports were not recorded")
	}
	r.MarkApplied(2)

	if len(r.Reports) != 0 {
		t.Errorf("MarkApplied left %d reports behind", len(r.Reports))
	}
}

// ------------------------------------------------------------- completion

func TestRolloutCompletesAtFullStage(t *testing.T) {
	r := rollout(t, 10)
	r.Stage = deploy.StageFull
	r.Applied = 10
	r.Record(healthy("site-001"))

	d := r.Advance()
	if d.Action != deploy.ActionComplete {
		t.Errorf("Action = %s, want complete", d.Action)
	}
}

// The report buffer must stay bounded: a process meant to run unattended
// should not accumulate one entry per gateway per interval forever.
func TestReportBufferIsBounded(t *testing.T) {
	r := rollout(t, 10_000)
	for i := 0; i < 5000; i++ {
		r.Record(healthy("site-" + strings.Repeat("x", i%20) + itoa(i)))
	}
	if n := len(r.Reports); n > 256 {
		t.Errorf("the report buffer grew to %d entries", n)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
