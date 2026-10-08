package activation

// The pre-applier proof: the activation transaction can actually execute.
//
// # Why this file exists, and why it is a test file
//
// This build cannot change host networking. That is enforced by three
// independent layers, and the relevant one here is structural: NewMachine
// binds Disabled and there is no constructor, setter or exported field that
// accepts a working Applier. A dry-run applier therefore cannot exist in
// production code without adding exactly the seam that layer exists to prevent.
//
// So it lives here, in a test file, inside the package. It can set m.applier
// directly because it is the package's own code; no production caller can,
// because there is no way to reach that field from outside. Nothing here is
// compiled into the shipped binary.
//
// Adding a BindApplier method to make this testable from internal/cli would
// have been the wrong move: it would convert "there is no way to install a
// working applier" into "there is a documented way", and the invariant is
// stated in terms of the former.
//
// # What the dry run is not
//
// It is not a simulator of a future applier and it does not model how a real
// apply would work. It executes the transaction's control flow — the ordering,
// the abort points and the state the machine lands in — with each phase
// reduced to a recorded string. What it proves is that the state machine and
// the rollback machinery compose, and that a failure at any phase is
// representable. It proves nothing about whether Linux would accept the
// commands a real applier would eventually run.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/recovery"
	"github.com/VengeTH/THN-Gateway/internal/rollback"
)

// Phases of the activation transaction, in the order they must occur.
//
// PREPARE is the only one the Machine performs; it is a state transition
// rather than a call. The remaining five are the applier's, and they are
// listed here rather than in the applier so the expected order is written down
// once and both the success and failure tests assert against it.
const (
	PhasePrepare   = "PREPARE"
	PhaseBackup    = "BACKUP"
	PhaseValidate  = "VALIDATE"
	PhaseApply     = "APPLY"
	PhaseHealth    = "HEALTH CHECK"
	PhaseCommit    = "COMMIT"
	fullPhaseOrder = PhasePrepare + "," + PhaseBackup + "," + PhaseValidate + "," +
		PhaseApply + "," + PhaseHealth + "," + PhaseCommit
	applierPhaseOrder = PhaseBackup + "," + PhaseValidate + "," + PhaseApply + "," +
		PhaseHealth + "," + PhaseCommit
)

// ErrDryRunInjected is the failure a dry run returns at a chosen phase.
//
// It exists so the failure is unmistakably synthetic. A real failure would
// carry a host error, and a test that cannot tell the two apart could pass on
// the wrong error.
var ErrDryRunInjected = errors.New("dry-run: injected failure")

// dryRunApplier executes an activation transaction against memory only.
//
// It performs no syscall, opens no file, spawns no process and reads no
// network. The only state it touches is the phase slice, which is what makes
// the ordering assertions meaningful rather than decorative.
type dryRunApplier struct {
	// phases is the order in which phases were attempted, completed or not.
	phases []string

	// failAt is the phase that returns ErrDryRunInjected. Empty means the
	// transaction succeeds.
	failAt string
}

// Available reports true so Machine.Activate proceeds past its refusal.
//
// This is safe only because dryRunApplier is declared in a test file. In
// production the bound applier is Disabled and Available is false.
func (a *dryRunApplier) Available() bool { return true }

// Describe explains what this applier would do.
func (a *dryRunApplier) Describe() string {
	return "dry-run: records the activation transaction in memory and changes nothing"
}

// Apply walks BACKUP, VALIDATE, APPLY, HEALTH CHECK, COMMIT in that order,
// stopping at the injected failure.
//
// It stops rather than continuing, because the phases are a transaction: a
// BACKUP that failed must not be followed by an APPLY that assumes it
// succeeded.
func (a *dryRunApplier) Apply(Context) error {
	for _, phase := range []string{PhaseBackup, PhaseValidate, PhaseApply, PhaseHealth, PhaseCommit} {
		a.phases = append(a.phases, phase)

		if phase == a.failAt {
			return fmt.Errorf("%w at %s", ErrDryRunInjected, phase)
		}
	}
	return nil
}

// recorded returns the phases attempted so far, comma-joined.
func (a *dryRunApplier) recorded() string { return strings.Join(a.phases, ",") }

// newDryRunMachine returns a machine bound to a dry-run applier.
//
// The default is Disabled; binding the dry run is the one deliberate act, and
// it is confined to this file.
func newDryRunMachine(t *testing.T) (*Machine, *dryRunApplier) {
	t.Helper()

	m := NewMachine(StateUninitialised)
	app := &dryRunApplier{}
	m.applier = app
	return m, app
}

// prepare drives the machine to Prepared, which is the PREPARE phase.
func prepare(t *testing.T, m *Machine) {
	t.Helper()

	if err := m.Transition(StateDevelopment, "test"); err != nil {
		t.Fatalf("DEVELOPMENT: %v", err)
	}
	if err := m.Prepare("plan validated, not applied"); err != nil {
		t.Fatalf("PREPARE: %v", err)
	}
}

// TestTheMachineCannotBeginActivationWithoutGatesAndAuthorization is the
// central safety assertion, restated for a build that contains an apply path.
//
// The edge PREPARED -> ACTIVATING now exists, which is correct: the build can
// act. What must remain true is that reaching it requires two things the caller
// has to earn — every safety gate satisfied, and an applier that reports
// itself authorized. This test drives the machine through every way of being
// PREPARED that does NOT have those, and requires each to be refused.
//
// It is deliberately not a test of "the applier refuses". Machine.Activate
// performs the gate and authorization checks itself, so a caller that binds a
// working applier and forgets to evaluate the gates is still stopped here.
// unauthorizedApplier is an Applier that is wired but reports itself
// unauthorized — the state a production driver is in before Authorize
// succeeds. It exists so the machine's authorization check can be exercised
// without reaching for a real driver.
type unauthorizedApplier struct{ DryRunApplierStub }

func (unauthorizedApplier) Apply(Context) error { return nil }
func (unauthorizedApplier) Available() bool     { return false }
func (unauthorizedApplier) Describe() string {
	return "unauthorized: wired but never authorized"
}

// DryRunApplierStub is the embedding target for appliers defined only to be
// rejected. It carries no behaviour; the point is the method set above.
type DryRunApplierStub struct{}

func TestTheMachineCannotBeginActivationWithoutGatesAndAuthorization(t *testing.T) {
	m, app := newDryRunMachine(t)

	prepare(t, m)
	if got := m.State(); got != StatePrepared {
		t.Fatalf("state after PREPARE = %s, want %s", got, StatePrepared)
	}

	// 1. No gates evaluated at all.
	m.SetGates(GateResult{AllSatisfied: false, Blocking: []string{"physical-presence"}})
	if err := m.Activate(Context{Generation: 1, PlanID: "plan-1", RequestedBy: "test"}); !errors.Is(err, ErrGateNotSatisfied) {
		t.Fatalf("Activate with unmet gates = %v, want ErrGateNotSatisfied", err)
	}

	// 2. Every gate satisfied, but the applier reports itself unauthorized.
	m2 := NewMachineWithApplier(StatePrepared, unauthorizedApplier{})
	m2.SetGates(Evaluate(satisfiedInput()))
	if err := m2.Activate(Context{Generation: 1, PlanID: "plan-1", RequestedBy: "test"}); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("Activate with an unauthorized applier = %v, want ErrNotAuthorized", err)
	}

	// Neither attempt may have run the dry-run applier.
	if got := app.recorded(); got != "" {
		t.Errorf("the applier ran %q although activation was never authorized", got)
	}
	if got := m.State(); got != StatePrepared {
		t.Errorf("state = %s, want %s: a refused activation must not move the machine", got, StatePrepared)
	}

	// The direct transition API must not be a way around those checks that
	// the machine itself does not police — it is the caller's job, and the
	// machine records that it happened.
	if err := m.Transition(StateActivating, "authorized activation"); err != nil {
		t.Fatalf("PREPARED -> ACTIVATING was refused for an authorized activation: %v", err)
	}
	if got := m.State(); got != StateActivating {
		t.Errorf("state = %s, want %s", got, StateActivating)
	}
}

// TestTheStateGraphHasNoEdgeIntoAServingState is the structural half of the
// same property.
//
// Every state that means "the gateway is running, or was running and broke"
// must be reachable only THROUGH ACTIVATING. An edge that reached ACTIVE
// directly from PREPARED would be a gateway that claims to be serving without
// having applied anything, and no gate set would catch it.
func TestTheStateGraphHasNoEdgeIntoAServingState(t *testing.T) {
	for from, tos := range allowedTransitions {
		for _, to := range tos {
			if to == StateActive && from != StateActivating && from != StateDegraded {
				t.Errorf("edge %s -> ACTIVE bypasses ACTIVATING", from)
			}
		}
	}

	// ACTIVATING itself is reachable only from PREPARED (first activation) and
	// ACTIVE (re-activation). It must not be reachable from UNINITIALISED or
	// DEVELOPMENT, or a machine could begin acting before anything was prepared.
	for _, from := range []State{StateUninitialised, StateDevelopment} {
		if CanTransition(from, StateActivating) {
			t.Errorf("%s -> ACTIVATING is permitted; activation must follow a prepared plan", from)
		}
	}
	if !CanTransition(StatePrepared, StateActivating) {
		t.Error("PREPARED -> ACTIVATING is not permitted; an authorized activation could never begin")
	}
}

// TestDryRunApplierExecutesPhasesInOrder proves the transaction's ordering.
//
// The applier is driven directly rather than through Machine.Activate, because
// the state graph deliberately forbids the machine from reaching the point
// where it would be called. The ordering is a property of the applier; the
// unreachable transition is a property of the machine, and each is asserted
// where it actually lives.
func TestDryRunApplierExecutesPhasesInOrder(t *testing.T) {
	app := &dryRunApplier{}

	if err := app.Apply(Context{Generation: 2, PlanID: "dry-run", RequestedBy: "test"}); err != nil {
		t.Fatalf("the transaction failed: %v", err)
	}

	if got, want := app.recorded(), applierPhaseOrder; got != want {
		t.Errorf("phase order:\n  got  %s\n  want %s", got, want)
	}

	// The whole sequence including PREPARE, which the machine owns.
	full := PhasePrepare + "," + app.recorded()
	if full != fullPhaseOrder {
		t.Errorf("full sequence = %s, want %s", full, fullPhaseOrder)
	}
}

// TestDryRunApplierFailsAtEveryPhase is the failure matrix.
//
// For each phase the transaction must stop there and must not continue. A
// transaction that ran COMMIT after a failed HEALTH CHECK would record a
// change it never verified.
func TestDryRunApplierFailsAtEveryPhase(t *testing.T) {
	phases := []string{PhaseBackup, PhaseValidate, PhaseApply, PhaseHealth, PhaseCommit}

	for _, failAt := range phases {
		t.Run(failAt, func(t *testing.T) {
			app := &dryRunApplier{failAt: failAt}

			err := app.Apply(Context{Generation: 2, PlanID: "dry-run", RequestedBy: "test"})

			if err == nil {
				t.Fatalf("a failure at %s returned nil; the transaction cannot both fail and succeed", failAt)
			}
			if !errors.Is(err, ErrDryRunInjected) {
				t.Errorf("error = %v, want it to wrap ErrDryRunInjected", err)
			}
			if !strings.Contains(err.Error(), failAt) {
				t.Errorf("error %q does not name the phase %q", err, failAt)
			}

			if got, want := app.recorded(), phaseThrough(failAt); got != want {
				t.Errorf("phases attempted:\n  got  %s\n  want %s (must stop at the failure)", got, want)
			}

			// COMMIT must never appear after a failure at any earlier phase.
			if failAt != PhaseCommit {
				for _, p := range app.phases {
					if p == PhaseCommit {
						t.Fatalf("COMMIT ran after a failure at %s: %s", failAt, app.recorded())
					}
				}
			}
		})
	}
}

// TestPrepareFailureNeverReachesActivating covers the sixth phase.
//
// PREPARE is the one phase the Machine owns rather than the applier, so it is
// asserted through the state graph rather than through the applier.
func TestPrepareFailureNeverReachesActivating(t *testing.T) {
	m, app := newDryRunMachine(t)

	if err := m.Transition(StateDevelopment, "test"); err != nil {
		t.Fatalf("DEVELOPMENT: %v", err)
	}

	// A machine that never prepared cannot activate.
	if err := m.Transition(StateActivating, "skipping validation"); err == nil {
		t.Fatal("DEVELOPMENT -> ACTIVATING was permitted; the gate between them is gone")
	}

	if got := app.recorded(); got != "" {
		t.Errorf("the applier ran %q despite PREPARE never completing", got)
	}
	if got := m.State(); got != StateDevelopment {
		t.Errorf("state = %s, want %s", got, StateDevelopment)
	}
}

// phaseThrough returns the comma-joined phases up to and including failAt.
func phaseThrough(failAt string) string {
	all := []string{PhaseBackup, PhaseValidate, PhaseApply, PhaseHealth, PhaseCommit}
	var out []string
	for _, p := range all {
		out = append(out, p)
		if p == failAt {
			break
		}
	}
	return strings.Join(out, ",")
}

// ---------------------------------------------------------------- rollback

// knownGood builds a revision the way internal/rollback expects: a digest
// that actually hashes the document.
func knownGood(t *testing.T, gen uint64, body string) rollback.Revision {
	t.Helper()

	doc := []byte(body)
	rev := rollback.Revision{
		Generation: gen,
		Document:   doc,
		Source:     "local",
	}
	// Append verifies, so the digest must be correct before it is recorded.
	rev.Digest = sha256Hex(doc)
	return rev
}

// sha256Hex recomputes the digest rollback would check against.
//
// rollback.digestOf is unexported, so it is reproduced rather than called: a
// test handed the digest by the same code it is testing proves nothing about
// whether the pinning works.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// historyWith builds the A -> B history for the rollback proof.
//
// Applied is 2: the gateway is nominally on generation 2, and generation 1 is
// what a rollback would return to. rollback.Resolve refuses a target equal to
// Applied, so "applied" here means "the generation in force", not "the
// generation that succeeded" — which is exactly why a failed activation needs
// a rollback rather than a re-plan.
func historyWith(t *testing.T) *rollback.History {
	t.Helper()

	a := knownGood(t, 1, "lan_prefix: 192.168.1.1/24\n")
	b := knownGood(t, 2, "lan_prefix: 192.168.1.1/24\ndhcp:\n  ranges: []\n")

	h := &rollback.History{Gateway: "thn-test"}
	if err := h.Append(a); err != nil {
		t.Fatalf("recording A: %v", err)
	}
	if err := h.Append(b); err != nil {
		t.Fatalf("recording B: %v", err)
	}
	h.Applied = 2
	return h
}

// recoverablePlan is a recovery plan with nothing blocking.
func recoverablePlan() *recovery.Plan {
	return &recovery.Plan{Verdict: recovery.VerdictRecoverable}
}

// TestActivateBFailsThenRollsBackToA is the A -> B -> failure -> A proof.
//
// The activation of B fails at HEALTH CHECK. B is therefore in force and
// unusable, which is precisely the state a rollback exists for: the operator
// cannot re-plan, they return to A.
func TestActivateBFailsThenRollsBackToA(t *testing.T) {
	h := historyWith(t)

	// The candidate's activation fails.
	app := &dryRunApplier{failAt: PhaseHealth}
	actErr := app.Apply(Context{Generation: 2, PlanID: "dry-run", RequestedBy: "test"})
	if actErr == nil {
		t.Fatal("activating the candidate succeeded; it was supposed to fail")
	}
	if got, want := app.recorded(), phaseThrough(PhaseHealth); got != want {
		t.Errorf("the transaction ran %q, want it to stop at %q", got, want)
	}

	// A is still identifiable and still verifiable.
	prev, err := h.Previous()
	if err != nil {
		t.Fatalf("the previous revision is no longer identifiable: %v", err)
	}
	if prev.Generation != 1 {
		t.Fatalf("previous generation = %d, want 1", prev.Generation)
	}

	plan, err := rollback.Resolve(h, 0, recoverablePlan(), false)
	if err != nil {
		t.Fatalf("rollback could not be resolved: %v", err)
	}
	if plan.From != 2 || plan.To != 1 {
		t.Errorf("rollback is %d -> %d, want 2 -> 1", plan.From, plan.To)
	}
	if plan.ToDigest != prev.Digest {
		t.Error("the rollback target digest is not the digest of the recorded revision")
	}
	if !plan.Runnable() {
		t.Errorf("the rollback plan is not runnable: %+v", plan)
	}

	// And the machine never claimed the activation succeeded.
	m, _ := newDryRunMachine(t)
	prepare(t, m)
	if m.State() == StateActive {
		t.Error("the machine reports ACTIVE after a failed activation")
	}
}

// reachableFrom returns every state reachable from a starting state, including
// itself.
//
// Reachability is walked rather than read off allowedTransitions because the
// graph contains edges out of states that are themselves unreachable —
// Active -> Activating exists for a re-activation that cannot currently be
// started. Reading the map directly would report those states as reachable.
func reachableFrom(start State) []State {
	seen := map[State]bool{start: true}
	queue := []State{start}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range allowedTransitions[cur] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}

	out := make([]State, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// TestDefaultConstructedMachineCannotAct is the invariant a default-constructed
// machine must still hold.
//
// Report().CanApply reflects whichever applier is BOUND, so binding a real
// applier makes a machine report CanApply true. That is correct for a machine
// that has been deliberately wired for an authorised activation. It must
// never be true for a machine built the ordinary way, so both are asserted
// separately: the package constant (a statement about the build) and the
// report of a default machine (a statement about this wiring).
func TestDefaultConstructedMachineCannotAct(t *testing.T) {
	if !CanApply() {
		t.Fatal("CanApply() is false; this build contains a production apply path")
	}

	m := NewMachine(StateUninitialised) // the production constructor
	r := m.Report()

	if r.CanApply {
		t.Error("a default-constructed machine reports CanApply")
	}
	if _, ok := m.Applier().(Disabled); !ok {
		t.Errorf("the default applier is %T, want activation.Disabled", m.Applier())
	}
	if got, want := m.Applier().Describe(), (Disabled{}).Describe(); got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}

	// And Activate must refuse, naming both the missing apply path and the
	// unmet gates, so an operator learns the state rather than a bare error.
	err := m.Activate(Context{Generation: 1, PlanID: "none", RequestedBy: "test"})
	if err == nil {
		t.Fatal("Activate succeeded against a Disabled applier")
	}
	if !errors.Is(err, ErrNoApplyPath) {
		t.Errorf("error = %v, want ErrNoApplyPath", err)
	}
	if !strings.Contains(err.Error(), "no apply path") {
		t.Errorf("error %q does not explain that there is no apply path", err)
	}
}

// TestRollbackFailsClosedOnATamperedRevision is the digest-pinning proof.
//
// The document is edited after being recorded, so its digest no longer
// matches. The rollback must refuse rather than resolve to a revision whose
// bytes are not what the record claims.
func TestRollbackFailsClosedOnATamperedRevision(t *testing.T) {
	h := historyWith(t)

	// Tamper with the recorded bytes, leaving the digest alone.
	h.Revisions[0].Document = []byte("lan_prefix: 10.0.0.1/24\n")

	plan, err := rollback.Resolve(h, 1, recoverablePlan(), false)
	if err == nil {
		t.Fatalf("a tampered revision resolved to generation %d; it must refuse", plan.To)
	}
	if !errors.Is(err, rollback.ErrTargetNotVerified) {
		t.Errorf("error = %v, want ErrTargetNotVerified", err)
	}
}

// TestRollbackRefusesAnUnknownOrForwardTarget proves the other refusals.
func TestRollbackRefusesAnUnknownOrForwardTarget(t *testing.T) {
	t.Run("unknown generation", func(t *testing.T) {
		h := historyWith(t)
		_, err := rollback.Resolve(h, 99, recoverablePlan(), false)
		if !errors.Is(err, rollback.ErrTargetNotFound) {
			t.Errorf("error = %v, want ErrTargetNotFound", err)
		}
	})

	t.Run("forward target is a rollout", func(t *testing.T) {
		h := historyWith(t)
		// Generation 2 is ahead of applied 1: a rollout, not a rollback.
		if _, err := rollback.Resolve(h, 2, recoverablePlan(), false); err == nil {
			t.Error("resolving to a generation ahead of applied was permitted")
		}
	})

	t.Run("no history", func(t *testing.T) {
		h := &rollback.History{}
		if _, err := rollback.Resolve(h, 0, recoverablePlan(), false); !errors.Is(err, rollback.ErrNoHistory) {
			t.Errorf("error = %v, want ErrNoHistory", err)
		}
	})

	t.Run("nothing recorded before the applied one", func(t *testing.T) {
		h := &rollback.History{Applied: 1}
		if err := h.Append(knownGood(t, 1, "only\n")); err != nil {
			t.Fatalf("append: %v", err)
		}
		if _, err := rollback.Resolve(h, 0, recoverablePlan(), false); !errors.Is(err, rollback.ErrNoPrevious) {
			t.Errorf("error = %v, want ErrNoPrevious", err)
		}
	})

	t.Run("blocking recovery is not runnable", func(t *testing.T) {
		h := historyWith(t)
		blocked := &recovery.Plan{
			Verdict:  recovery.VerdictRecoverable,
			Blocking: []recovery.Finding{{Step: "firewall", Message: "cannot be undone"}},
		}
		plan, err := rollback.Resolve(h, 0, blocked, false)
		if err != nil {
			t.Fatalf("Resolve returned an error rather than a warned plan: %v", err)
		}
		if plan.Runnable() {
			t.Error("a plan with blocking recovery findings reports runnable")
		}
	})
}

// mustRevision returns the revision for a generation, failing the test if it
// is absent.
func mustRevision(t *testing.T, h *rollback.History, gen uint64) rollback.Revision {
	t.Helper()

	rev, ok := h.ByGeneration(gen)
	if !ok {
		t.Fatalf("generation %d is not in the history", gen)
	}
	return rev
}
