package health_test

import (
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/health"
)

var at = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// up is a gateway that is working: inspected, uplink and LAN both up.
func up() diff.Observed {
	return diff.Observed{
		Supported: true,
		WANName:   "enp0s31f6", WANPresent: true, WANUp: true,
		LANName: "enx0011", LANPresent: true, LANUp: true,
	}
}

func noChange() diff.Result {
	return diff.Result{Converged: true}
}

// ------------------------------------------------- unknowable is not healthy

// The property this package exists for. Immediately after an apply, "I could
// not read it" and "it is fine" look identical on a dashboard, and the
// dashboard is what the person deciding whether to continue the rollout sees.
func TestUninspectableGatewayIsNotHealthy(t *testing.T) {
	blind := up()
	blind.Supported = false

	r := health.Assess("site-001", 42, noChange(), blind, at)

	if r.Verdict != health.VerdictUnknowable {
		t.Fatalf("Verdict = %s, want unknowable", r.Verdict)
	}
	if r.Verdict == health.VerdictHealthy {
		t.Fatal("an uninspectable gateway reported healthy")
	}
	if r.Failed() != true {
		t.Error("Failed() should be true for unknowable; it must stop a rollout")
	}
}

func TestUnknowableIsWorseThanHealthy(t *testing.T) {
	if health.Worst(health.VerdictHealthy, health.VerdictUnknowable) != health.VerdictUnknowable {
		t.Error("combining healthy and unknowable lost the unknowable")
	}
	if health.Worst(health.VerdictDegraded, health.VerdictUnknowable) != health.VerdictDegraded {
		t.Error("degraded should outrank unknowable")
	}
	if health.Worst(health.VerdictUnhealthy, health.VerdictDegraded) != health.VerdictUnhealthy {
		t.Error("unhealthy should outrank degraded")
	}
}

// A gateway that reads fine and is fine is healthy. The point of separating
// the verdicts is not to make everything doubtful.
func TestWorkingGatewayIsHealthy(t *testing.T) {
	r := health.Assess("site-001", 42, noChange(), up(), at)
	if r.Verdict != health.VerdictHealthy {
		t.Errorf("Verdict = %s, want healthy", r.Verdict)
	}
	if r.Failed() {
		t.Error("a healthy gateway reported Failed()")
	}
}

// ------------------------------------------------------------ reachability

// A gateway that is up downstream but has no uplink is still serving the LAN,
// and saying "unhealthy" would be wrong. But it is not healthy either.
func TestUplinkDownIsDegradedNotUnhealthy(t *testing.T) {
	obs := up()
	obs.WANUp = false

	r := health.Assess("site-001", 42, noChange(), obs, at)
	if r.Verdict != health.VerdictDegraded {
		t.Errorf("Verdict = %s, want degraded", r.Verdict)
	}
	if !strings.Contains(render(r), "no path to anything beyond it") {
		t.Error("the report does not say what is still working")
	}
}

func TestNoInterfacesAtAllIsUnhealthy(t *testing.T) {
	obs := up()
	obs.WANPresent, obs.WANUp = false, false
	obs.LANPresent, obs.LANUp = false, false

	r := health.Assess("site-001", 42, noChange(), obs, at)
	if r.Verdict != health.VerdictUnhealthy {
		t.Errorf("Verdict = %s, want unhealthy", r.Verdict)
	}
	if !strings.Contains(render(r), "cannot be managed") {
		t.Error("the report does not say the gateway cannot be managed")
	}
}

// ------------------------------------------------------ resolved changes

// The uplink not coming up after an apply is not an apply failure. The apply
// succeeded; the carrier is the problem. Reporting it as unhealthy and
// indistinguishable from "the change broke something" is misleading.
func TestUplinkStillDownAfterChangeIsDegraded(t *testing.T) {
	obs := up()
	obs.WANUp = false

	d := diff.Result{DriftCount: 1, Changes: []diff.Change{{
		ID: "wan-link-state", Kind: diff.KindDrift, Risk: diff.RiskHigh,
		Field: "wan.up", Current: "down", Desired: "up",
		Reason: "the uplink is down",
	}}}

	r := health.Assess("site-001", 42, d, obs, at)

	if r.Verdict != health.VerdictDegraded {
		t.Errorf("Verdict = %s, want degraded", r.Verdict)
	}
	if !strings.Contains(render(r), "what remains is physical") {
		t.Error("the report does not distinguish a physical fault from an apply failure")
	}
}

func TestUplinkAbsentAfterChangeIsUnhealthy(t *testing.T) {
	obs := up()
	obs.WANPresent, obs.WANUp = false, false

	d := diff.Result{Changes: []diff.Change{{
		ID: "wan-link-state", Kind: diff.KindDrift,
		Field: "wan.up", Desired: "up",
	}}}

	r := health.Assess("site-001", 42, d, obs, at)
	if r.Verdict != health.VerdictUnhealthy {
		t.Errorf("Verdict = %s, want unhealthy", r.Verdict)
	}
}

// A blocked change was never applied, so the gateway is running something other
// than what was asked for. That is degraded, and must be visible.
func TestBlockedChangeIsReported(t *testing.T) {
	d := diff.Result{BlockedCount: 1, Changes: []diff.Change{{
		ID: "firewall-empty", Kind: diff.KindBlocked,
		Field: "firewall.rules", Reason: "the policy is invalid",
	}}}

	r := health.Assess("site-001", 42, d, up(), at)

	if r.Verdict != health.VerdictDegraded {
		t.Errorf("Verdict = %s, want degraded", r.Verdict)
	}
	if !strings.Contains(render(r), "was not applied") {
		t.Error("the report does not say the change was not applied")
	}
}

// A check that could not run has to be named. A report that simply omits it
// looks like a report where everything passed.
func TestPendingItemsAreReportedAsSkipped(t *testing.T) {
	d := diff.Result{PendingCount: 2, Changes: []diff.Change{
		{ID: "wan-unobservable", Kind: diff.KindPending, Field: "wan.interface"},
		{ID: "firewall-unobservable", Kind: diff.KindPending, Field: "firewall.enabled"},
	}}

	r := health.Assess("site-001", 42, d, up(), at)

	if len(r.Skipped) != 2 {
		t.Errorf("Skipped = %v, want both pending fields", r.Skipped)
	}
	if !strings.Contains(render(r), "Not checked") {
		t.Error("the rendering does not distinguish not-checked from passed")
	}
}

// Every check reports a detail, including the passing ones. A report that only
// names failures cannot tell a pass from a check that never ran.
func TestEveryCheckExplainsItself(t *testing.T) {
	blind := up()
	blind.Supported = false
	for _, r := range []health.Report{
		health.Assess("a", 1, noChange(), up(), at),
		health.Assess("b", 1, noChange(), blind, at),
	} {
		for _, c := range r.Checks {
			if strings.TrimSpace(c.Detail) == "" {
				t.Errorf("check %q has no detail", c.Name)
			}
		}
	}
}

func render(r health.Report) string { return health.Render(r) }
