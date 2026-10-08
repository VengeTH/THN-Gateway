package execution

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/planner"
)

// ExecutionOptions provides runtime context and state inputs to the Executor.
type ExecutionOptions struct {
	Observed                 diff.Observed
	Desired                  desired.State
	Assignments              []host.Assignment
	Journal                  JournalStore
	DryRun                   bool
	ExpectedPlanID           string
	ExpectedObservedDigest   string
	ExpectedDesiredDigest    string
	ExpectedAssignmentDigest string
	ManagementSafe           bool
	ManagementProblem        string
	Capabilities             []activation.CapabilityGate
}

// Executor orchestrates the six-phase execution transaction:
// PREPARE → BACKUP → VALIDATE → APPLY → HEALTH_CHECK → COMMIT
// and coordinates scoped rollbacks on failure.
type Executor struct{}

func NewExecutor() *Executor {
	return &Executor{}
}

// ExecutePlan executes a plan using the provided driver.
func (e *Executor) ExecutePlan(ctx context.Context, plan *planner.Plan, driver ExecutorDriver, opts ExecutionOptions) (*ExecutionResult, error) {
	now := time.Now().UTC()
	res := &ExecutionResult{
		PlanID:     plan.ID,
		Generation: plan.Generation,
		Timestamp:  now,
		Phases:     make([]string, 0, 6),
	}

	// 0. Crash recovery check: verify no uncompleted transaction was left in-flight
	if opts.Journal != nil {
		if rec, interrupted := DetectInterrupted(opts.Journal); interrupted {
			res.FinalState = StateRecoveryRequired
			res.Error = fmt.Sprintf("%v: plan %s was interrupted in state %s", ErrRecoveryRequired, rec.PlanID, rec.State)
			return res, ErrRecoveryRequired
		}
	}

	// 1. PREPARE PHASE
	res.Phases = append(res.Phases, string(StatePrepare))

	// Ensure driver can apply
	if !driver.CanApply() {
		res.FinalState = StateBlocked
		res.Error = ErrCannotApply.Error()
		return res, ErrCannotApply
	}

	// Check plan preconditions and digest freshness
	currObsDigest := planner.ComputeObservedDigest(opts.Observed)
	currDesDigest := planner.ComputeDesiredDigest(opts.Desired)
	currAssignDigest := planner.ComputeAssignmentDigest(opts.Assignments)

	if currObsDigest != plan.Inputs.ObservedDigest {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: observed digest %s != plan input %s", ErrStalePlan, currObsDigest, plan.Inputs.ObservedDigest)
		return res, ErrStalePlan
	}

	if currDesDigest != plan.Inputs.DesiredDigest {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: desired digest %s != plan input %s", ErrStalePlan, currDesDigest, plan.Inputs.DesiredDigest)
		return res, ErrStalePlan
	}

	if plan.Inputs.AssignmentDigest != "" && currAssignDigest != plan.Inputs.AssignmentDigest {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: assignment digest %s != plan input %s", ErrStalePlan, currAssignDigest, plan.Inputs.AssignmentDigest)
		return res, ErrStalePlan
	}

	// Verify plan-bound constraints when caller specifies expected binding
	if opts.ExpectedPlanID != "" && plan.ID != opts.ExpectedPlanID {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: plan ID %s != expected %s", ErrStalePlan, plan.ID, opts.ExpectedPlanID)
		return res, ErrStalePlan
	}
	if opts.ExpectedObservedDigest != "" && currObsDigest != opts.ExpectedObservedDigest {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: observed digest %s != expected %s", ErrStalePlan, currObsDigest, opts.ExpectedObservedDigest)
		return res, ErrStalePlan
	}
	if opts.ExpectedDesiredDigest != "" && currDesDigest != opts.ExpectedDesiredDigest {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: desired digest %s != expected %s", ErrStalePlan, currDesDigest, opts.ExpectedDesiredDigest)
		return res, ErrStalePlan
	}
	if opts.ExpectedAssignmentDigest != "" && currAssignDigest != opts.ExpectedAssignmentDigest {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: assignment digest %s != expected %s", ErrStalePlan, currAssignDigest, opts.ExpectedAssignmentDigest)
		return res, ErrStalePlan
	}

	// Verify management safety
	if opts.ManagementProblem != "" || (!opts.ManagementSafe && opts.ExpectedPlanID != "") {
		prob := opts.ManagementProblem
		if prob == "" {
			prob = "remote management path cannot be proven safe"
		}
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: %s", ErrCannotApply, prob)
		return res, fmt.Errorf("%w: %s", ErrCannotApply, prob)
	}

	ok, preconditions := plan.ValidatePreconditions(opts.Observed, opts.Desired)
	if !ok {
		var reasons []string
		for _, p := range preconditions {
			if !p.Satisfied {
				reasons = append(reasons, fmt.Sprintf("%s: %s", p.ID, p.Reason))
			}
		}
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: unsatisfied preconditions: %s", ErrStalePlan, strings.Join(reasons, "; "))
		return res, ErrStalePlan
	}

	// Translate plan steps to structured operations
	ops, err := PlanToOperations(plan, opts.Observed)
	if err != nil {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("failed translating plan steps to operations: %v", err)
		return res, err
	}

	// Multi-WAN safety check: non-single mode requires explicit policy routing operations
	if opts.Desired.MultiWAN.Enabled && opts.Desired.MultiWAN.Mode != "single" && opts.Desired.MultiWAN.Mode != "" {
		hasPolicyRouting := false
		for _, op := range ops {
			if op.Subsystem() == "route" && strings.Contains(op.RenderCommand(), "table") {
				hasPolicyRouting = true
				break
			}
		}
		if !hasPolicyRouting {
			res.FinalState = StateBlocked
			res.Error = fmt.Sprintf("%v: Multi-WAN mode %q cannot be activated without verified policy routing", ErrCannotApply, opts.Desired.MultiWAN.Mode)
			return res, fmt.Errorf("%w: Multi-WAN mode %q cannot be activated without verified policy routing", ErrCannotApply, opts.Desired.MultiWAN.Mode)
		}
	}

	// Check required capabilities
	caps, err := driver.DetectCapabilities(ctx)
	if err != nil {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("probing driver capabilities: %v", err)
		return res, err
	}

	var requiredCaps []string
	for _, op := range ops {
		for _, rc := range op.RequiredCapabilities() {
			if !slices.Contains(requiredCaps, rc) {
				requiredCaps = append(requiredCaps, rc)
			}
		}
	}

	if sat, missing := caps.Satisfies(requiredCaps); !sat {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("%v: %s", ErrCapabilityMissing, missing)
		return res, fmt.Errorf("%w: %s", ErrCapabilityMissing, missing)
	}

	// Section 5: never use inferred capabilities as activation permission
	if len(opts.Capabilities) > 0 {
		for _, rc := range requiredCaps {
			found := false
			for _, cg := range opts.Capabilities {
				if cg.Name == rc {
					found = true
					if !cg.Satisfied() {
						res.FinalState = StateBlocked
						res.Error = fmt.Sprintf("%v: capability %s is %s (must be observed)", ErrCapabilityMissing, rc, cg.Confidence)
						return res, fmt.Errorf("%w: capability %s is %s; activation requires observed capability", ErrCapabilityMissing, rc, cg.Confidence)
					}
					break
				}
			}
			if !found {
				res.FinalState = StateBlocked
				res.Error = fmt.Sprintf("%v: capability %s is unknown", ErrCapabilityMissing, rc)
				return res, fmt.Errorf("%w: capability %s is unknown", ErrCapabilityMissing, rc)
			}
		}
	}

	// 2. BACKUP PHASE
	res.Phases = append(res.Phases, string(StateBackup))
	scope := BackupScopeFor(ops, opts.Observed)
	baselineSnapshot, err := driver.CaptureState(ctx, scope)
	if err != nil {
		res.FinalState = StateBlocked
		res.Error = fmt.Sprintf("capturing pre-execution baseline backup: %v", err)
		return res, err
	}

	if opts.Journal != nil {
		_ = opts.Journal.RecordState(TransactionRecord{
			PlanID:          plan.ID,
			Generation:      plan.Generation,
			State:           StateBackup,
			StartedAt:       now,
			UpdatedAt:       time.Now().UTC(),
			PhasesAttempted: res.Phases,
		})
	}

	// 3. VALIDATE PHASE
	res.Phases = append(res.Phases, string(StateValidate))
	for _, op := range ops {
		if err := op.Validate(); err != nil {
			res.FinalState = StateBlocked
			res.Error = fmt.Sprintf("validating operation %s: %v", op.Kind(), err)
			return res, err
		}
	}

	// 4. APPLY PHASE
	res.Phases = append(res.Phases, string(StateApply))
	if opts.Journal != nil {
		_ = opts.Journal.RecordState(TransactionRecord{
			PlanID:          plan.ID,
			Generation:      plan.Generation,
			State:           StateApply,
			StartedAt:       now,
			UpdatedAt:       time.Now().UTC(),
			PhasesAttempted: res.Phases,
		})
	}

	var appliedOps []Operation
	var appliedOpNames []string

	for i, op := range ops {
		if err := driver.Execute(ctx, op); err != nil {
			res.Error = fmt.Sprintf("operation %d (%s %s) failed: %v", i+1, op.Kind(), op.Target(), err)
			return e.rollback(ctx, plan, driver, appliedOps, baselineSnapshot, scope, opts.Journal, res, err)
		}
		appliedOps = append(appliedOps, op)
		appliedOpNames = append(appliedOpNames, op.RenderCommand())

		if opts.Journal != nil {
			_ = opts.Journal.RecordState(TransactionRecord{
				PlanID:          plan.ID,
				Generation:      plan.Generation,
				State:           StateApply,
				StartedAt:       now,
				UpdatedAt:       time.Now().UTC(),
				PhasesAttempted: res.Phases,
				AppliedOps:      appliedOpNames,
			})
		}
	}
	res.AppliedOps = appliedOpNames

	// 5. HEALTH CHECK PHASE
	res.Phases = append(res.Phases, string(StateHealthCheck))
	if opts.Journal != nil {
		_ = opts.Journal.RecordState(TransactionRecord{
			PlanID:          plan.ID,
			Generation:      plan.Generation,
			State:           StateHealthCheck,
			StartedAt:       now,
			UpdatedAt:       time.Now().UTC(),
			PhasesAttempted: res.Phases,
			AppliedOps:      appliedOpNames,
		})
	}

	healthChecks := make([]HealthCheck, 0, len(plan.Verification.Checks))
	for _, c := range plan.Verification.Checks {
		healthChecks = append(healthChecks, HealthCheck{
			Target:      c.Target,
			Check:       c.Check,
			Expectation: c.Expectation,
		})
	}

	hr, err := driver.VerifyHealth(ctx, healthChecks)
	res.Health = hr
	if err != nil || !hr.Healthy {
		reason := hr.FailureReason
		if reason == "" && err != nil {
			reason = err.Error()
		}
		res.Error = fmt.Sprintf("post-apply health verification failed: %s", reason)
		return e.rollback(ctx, plan, driver, appliedOps, baselineSnapshot, scope, opts.Journal, res, ErrHealthCheckFailed)
	}

	// 6. COMMIT PHASE
	res.Phases = append(res.Phases, string(StateCommit))
	res.FinalState = StateCommitted

	if opts.Journal != nil {
		_ = opts.Journal.RecordState(TransactionRecord{
			PlanID:          plan.ID,
			Generation:      plan.Generation,
			State:           StateCommitted,
			StartedAt:       now,
			UpdatedAt:       time.Now().UTC(),
			PhasesAttempted: res.Phases,
			AppliedOps:      appliedOpNames,
			Completed:       true,
		})
	}

	return res, nil
}

// rollback executes compensating operations in reverse order of apply, followed by baseline verification.
func (e *Executor) rollback(
	ctx context.Context,
	plan *planner.Plan,
	driver ExecutorDriver,
	appliedOps []Operation,
	baseline *StateSnapshot,
	scope BackupScope,
	journal JournalStore,
	res *ExecutionResult,
	cause error,
) (*ExecutionResult, error) {
	res.Phases = append(res.Phases, string(StateRollingBack))

	if journal != nil {
		_ = journal.RecordState(TransactionRecord{
			PlanID:          plan.ID,
			Generation:      plan.Generation,
			State:           StateRollingBack,
			StartedAt:       res.Timestamp,
			UpdatedAt:       time.Now().UTC(),
			PhasesAttempted: res.Phases,
			AppliedOps:      res.AppliedOps,
			Error:           res.Error,
		})
	}

	var rolledBackOpNames []string
	rollbackOpFailed := false
	var rollbackErr error

	// Execute rollback in reverse order
	for i := len(appliedOps) - 1; i >= 0; i-- {
		op := appliedOps[i]
		rb := op.RollbackOp()
		if rb == nil {
			continue
		}

		if err := driver.Execute(ctx, rb); err != nil {
			rollbackOpFailed = true
			rollbackErr = err
			break
		}
		rolledBackOpNames = append(rolledBackOpNames, rb.RenderCommand())

		if journal != nil {
			_ = journal.RecordState(TransactionRecord{
				PlanID:          plan.ID,
				Generation:      plan.Generation,
				State:           StateRollingBack,
				StartedAt:       res.Timestamp,
				UpdatedAt:       time.Now().UTC(),
				PhasesAttempted: res.Phases,
				AppliedOps:      res.AppliedOps,
				RolledBackOps:   rolledBackOpNames,
			})
		}
	}
	res.RolledBackOps = rolledBackOpNames

	if rollbackOpFailed {
		res.FinalState = StateDegraded
		res.Error = fmt.Sprintf("rollback failed mid-flight: %v (initial trigger: %v)", rollbackErr, cause)
		if journal != nil {
			_ = journal.RecordState(TransactionRecord{
				PlanID:          plan.ID,
				Generation:      plan.Generation,
				State:           StateDegraded,
				StartedAt:       res.Timestamp,
				UpdatedAt:       time.Now().UTC(),
				PhasesAttempted: res.Phases,
				AppliedOps:      res.AppliedOps,
				RolledBackOps:   rolledBackOpNames,
				Completed:       false,
				Error:           res.Error,
			})
		}
		return res, ErrRollbackFailed
	}

	// ROLLBACK VERIFICATION
	res.Phases = append(res.Phases, string(StateRollbackVerification))
	if journal != nil {
		_ = journal.RecordState(TransactionRecord{
			PlanID:          plan.ID,
			Generation:      plan.Generation,
			State:           StateRollbackVerification,
			StartedAt:       res.Timestamp,
			UpdatedAt:       time.Now().UTC(),
			PhasesAttempted: res.Phases,
			AppliedOps:      res.AppliedOps,
			RolledBackOps:   rolledBackOpNames,
		})
	}

	postRollbackState, err := driver.CaptureState(ctx, scope)
	if err != nil {
		res.FinalState = StateDegraded
		res.Error = fmt.Sprintf("failed capturing post-rollback verification snapshot: %v", err)
		return res, err
	}

	matched, diffs := baseline.MatchesBaseline(postRollbackState)
	if !matched {
		res.FinalState = StateDegraded
		res.Error = fmt.Sprintf("rollback verification failed to reinstate baseline: %s", strings.Join(diffs, "; "))
		if journal != nil {
			_ = journal.RecordState(TransactionRecord{
				PlanID:          plan.ID,
				Generation:      plan.Generation,
				State:           StateDegraded,
				StartedAt:       res.Timestamp,
				UpdatedAt:       time.Now().UTC(),
				PhasesAttempted: res.Phases,
				AppliedOps:      res.AppliedOps,
				RolledBackOps:   rolledBackOpNames,
				Completed:       false,
				Error:           res.Error,
			})
		}
		return res, fmt.Errorf("%w: rollback verification failed: %s", ErrRollbackFailed, strings.Join(diffs, "; "))
	}

	// Verification succeeded: cleanly rolled back
	res.FinalState = StateRolledBack
	if journal != nil {
		_ = journal.RecordState(TransactionRecord{
			PlanID:          plan.ID,
			Generation:      plan.Generation,
			State:           StateRolledBack,
			StartedAt:       res.Timestamp,
			UpdatedAt:       time.Now().UTC(),
			PhasesAttempted: res.Phases,
			AppliedOps:      res.AppliedOps,
			RolledBackOps:   rolledBackOpNames,
			Completed:       true,
		})
	}

	return res, cause
}

// BackupScopeFor derives the set of state that must be captured before ops are
// applied.
//
// # Why it is exported
//
// The activation gate that asks "is this transaction recoverable?" has to ask
// it about the SAME scope the executor will use. Deriving the scope twice —
// once here for the gate and once in the executor for the backup — would
// produce two answers, and a gate that certified a narrower scope than the
// executor captures would certify a rollback that restores nothing.
func BackupScopeFor(ops []Operation, obs diff.Observed) BackupScope {
	scope := BackupScope{
		Sysctls: []string{"net.ipv4.ip_forward"},
		Routes:  true,
	}

	seenIfaces := make(map[string]bool)
	for _, op := range ops {
		switch o := op.(type) {
		case OpLinkSetUp:
			seenIfaces[o.Interface] = true
		case OpLinkSetDown:
			seenIfaces[o.Interface] = true
		case OpAddressAdd:
			seenIfaces[o.Interface] = true
		case OpAddressDelete:
			seenIfaces[o.Interface] = true
		case OpNFTApplyTHNTable, OpNFTDeleteTHNTable:
			scope.NFTables = true
		case OpQDiscApply, OpQDiscDelete:
			seenIfaces[o.Target()] = true
			scope.QDiscs = true
		case OpDNSApply:
			scope.DNS = true
		}
	}

	if obs.WANName != "" {
		seenIfaces[obs.WANName] = true
	}
	if obs.LANName != "" {
		seenIfaces[obs.LANName] = true
	}

	for iface := range seenIfaces {
		scope.Interfaces = append(scope.Interfaces, iface)
	}
	return scope
}
