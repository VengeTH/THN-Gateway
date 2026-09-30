package activation

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// State is a lifecycle state of the gateway.
type State string

const (
	// StateUninitialised is the state before any configuration is loaded.
	StateUninitialised State = "UNINITIALISED"

	// StateDevelopment is the state during remote development: the host may
	// be observed, nothing may be applied.
	StateDevelopment State = "DEVELOPMENT"

	// StatePrepared means a plan has been generated and validated but has
	// deliberately not been applied. It is the terminal state of this build.
	StatePrepared State = "PREPARED"

	// StateActivating means an apply is in progress. Unreachable in this build.
	StateActivating State = "ACTIVATING"

	// StateActive means the gateway is serving traffic as planned.
	// Unreachable in this build.
	StateActive State = "ACTIVE"

	// StateDegraded means the gateway is active but unhealthy.
	// Unreachable in this build.
	StateDegraded State = "DEGRADED"

	// StateFailed means activation failed and recovery is required.
	// Unreachable in this build.
	StateFailed State = "FAILED"
)

// String renders the state for display.
func (s State) String() string { return string(s) }

// Errors returned by the state machine. They are distinct so that the CLI
// can report precisely why an activation was refused rather than a generic
// failure.
var (
	// ErrNoApplyPath is returned because this build has no apply path. It is
	// the expected outcome, not a malfunction.
	ErrNoApplyPath = errors.New("activation: this build has no apply path; host networking cannot be changed")

	// ErrInvalidTransition is returned when a state change is not permitted.
	ErrInvalidTransition = errors.New("activation: invalid state transition")

	// ErrGateNotSatisfied is returned when a safety gate is not satisfied.
	ErrGateNotSatisfied = errors.New("activation: safety gate not satisfied")

	// ErrPresenceNotConfirmed is returned when physical presence has not been
	// confirmed and the configuration requires it.
	ErrPresenceNotConfirmed = errors.New("activation: physical presence has not been confirmed")
)

// Stage names the capabilities the current build implements.
type Stage string

const (
	// StageObserve is implemented: the host can be read.
	StageObserve Stage = "observe"
	// StageModel is implemented: a desired state can be represented.
	StageModel Stage = "model"
	// StagePlan is implemented: a plan can be generated.
	StagePlan Stage = "plan"
	// StageValidate is implemented: a plan can be checked.
	StageValidate Stage = "validate"
	// StageSimulate is implemented: a plan's effect can be described.
	StageSimulate Stage = "simulate"
	// StageApply is NOT implemented in this build.
	StageApply Stage = "apply"
	// StageHealthCheck is NOT implemented in this build.
	StageHealthCheck Stage = "health-check"
	// StageCommit is NOT implemented in this build.
	StageCommit Stage = "commit"
	// StageRollback is NOT implemented in this build.
	StageRollback Stage = "rollback"
)

// ImplementedStages returns the stages this build can perform.
func ImplementedStages() []Stage {
	return []Stage{StageObserve, StageModel, StagePlan, StageValidate, StageSimulate}
}

// UnsupportedStages returns the stages this build cannot perform.
func UnsupportedStages() []Stage {
	return []Stage{StageApply, StageHealthCheck, StageCommit, StageRollback}
}

// CanApply reports whether this build can change host networking. It is a
// constant false in this build, and exists so that callers can express the
// question instead of hard-coding an assumption.
func CanApply() bool { return false }

// Applier performs activation.
//
// The interface exists so the state machine can be written against the real
// thing, and so that a future implementation slots in without reshaping the
// machine. There is exactly one implementation in this repository: Disabled.
type Applier interface {
	// Apply would activate the gateway. It is never called in this build.
	Apply(ctx Context) error

	// Available reports whether this applier can act. Disabled returns false.
	Available() bool

	// Describe explains what this applier would do, for `thn diagnostics`.
	Describe() string
}

// Context carries what an applier would need to act.
type Context struct {
	// Generation is the configuration generation being activated.
	Generation uint64
	// PlanID identifies the plan being activated.
	PlanID string
	// RequestedBy records who asked, for the audit trail.
	RequestedBy string
}

// Disabled is the only Applier in this build. It refuses every request.
type Disabled struct{}

// Apply always returns ErrNoApplyPath.
func (Disabled) Apply(Context) error { return ErrNoApplyPath }

// Available always returns false.
func (Disabled) Available() bool { return false }

// Describe explains the refusal.
func (Disabled) Describe() string {
	return "activation is disabled in this build: THN can observe, plan, validate and simulate, but cannot modify host networking"
}

// Gate is a safety condition that must hold before activation is permitted.
//
// Gates exist so that the conditions are explicit and individually testable,
// rather than being scattered through the apply path as conditionals.
type Gate struct {
	// Name identifies the gate.
	Name string
	// Description explains why the gate exists.
	Description string
	// Satisfied reports whether the gate currently holds.
	Satisfied bool
	// Reason explains why it is not satisfied, when it is not.
	Reason string
}

// GateResult reports the outcome of evaluating all gates.
type GateResult struct {
	// Gates are the individual gate outcomes.
	Gates []Gate `json:"gates"`
	// AllSatisfied reports whether every gate holds.
	AllSatisfied bool `json:"all_satisfied"`
	// Blocking names the gates that failed.
	Blocking []string `json:"blocking,omitempty"`
}

// Evaluate runs the standard gate set for an activation request.
//
// Even though this build cannot activate, the gates are evaluated for real so
// that `thn status` can show an operator exactly how far they are from a
// deployable gateway. That visibility is the point: the operator should learn
// on a laptop, over SSH, that the LAN interface is unattached.
func Evaluate(in GateInput) GateResult {
	var gates []Gate

	gates = append(gates, Gate{
		Name:        "apply-path-available",
		Description: "the running build must contain an apply path",
		Satisfied:   CanApply(),
		Reason:      "this build implements observe, model, plan, validate and simulate only",
	})

	gates = append(gates, Gate{
		Name:        "plan-validated",
		Description: "a plan must have been generated and validated",
		Satisfied:   in.PlanValidated,
		Reason:      reasonUnless(in.PlanValidated, "no validated plan exists; run `thn plan` first"),
	})

	gates = append(gates, Gate{
		Name:        "config-valid",
		Description: "the configuration must validate without errors",
		Satisfied:   in.ConfigValid,
		Reason:      reasonUnless(in.ConfigValid, in.ConfigProblem),
	})

	gates = append(gates, Gate{
		Name:        "wan-present",
		Description: "the configured WAN interface must be present on the host",
		Satisfied:   in.WANPresent,
		Reason:      reasonUnless(in.WANPresent, in.WANProblem),
	})

	gates = append(gates, Gate{
		Name:        "lan-identified",
		Description: "the LAN interface must be identified and attached",
		Satisfied:   in.LANPresent,
		Reason:      reasonUnless(in.LANPresent, in.LANProblem),
	})

	gates = append(gates, Gate{
		Name:        "recoverable",
		Description: "a recovery plan must exist and must not be blocked",
		Satisfied:   in.RecoveryOK,
		Reason:      reasonUnless(in.RecoveryOK, in.RecoveryProblem),
	})

	gates = append(gates, Gate{
		Name:        "physical-presence",
		Description: "an operator must confirm physical presence at the device",
		Satisfied:   in.PresenceConfirmed,
		Reason: reasonUnless(in.PresenceConfirmed,
			"nobody has confirmed being at the device; being logged in as root is not sufficient"),
	})

	res := GateResult{Gates: gates, AllSatisfied: true}
	for _, g := range gates {
		if !g.Satisfied {
			res.AllSatisfied = false
			res.Blocking = append(res.Blocking, g.Name)
		}
	}
	return res
}

// GateInput carries the observed facts the gates evaluate.
type GateInput struct {
	// PlanValidated reports whether a validated plan exists.
	PlanValidated bool
	// ConfigValid reports whether the configuration validates.
	ConfigValid bool
	// ConfigProblem explains an invalid configuration.
	ConfigProblem string
	// WANPresent reports whether the WAN interface was observed.
	WANPresent bool
	// WANProblem explains a missing WAN interface.
	WANProblem string
	// LANPresent reports whether the LAN interface was observed.
	LANPresent bool
	// LANProblem explains a missing LAN interface.
	LANProblem string
	// RecoveryOK reports whether recovery is possible.
	RecoveryOK bool
	// RecoveryProblem explains an unrecoverable situation.
	RecoveryProblem string
	// PresenceConfirmed reports whether an operator confirmed being present.
	PresenceConfirmed bool
}

// reasonUnless returns "" when cond holds, otherwise reason.
func reasonUnless(cond bool, reason string) string {
	if cond {
		return ""
	}
	if reason == "" {
		return "condition not satisfied"
	}
	return reason
}

// Machine tracks the gateway's lifecycle state.
type Machine struct {
	mu         sync.RWMutex
	state      State
	since      time.Time
	history    []Transition
	applier    Applier
	presence   bool
	gates      GateResult
	maxHistory int
}

// Transition records one state change.
type Transition struct {
	From State     `json:"from"`
	To   State     `json:"to"`
	TS   time.Time `json:"ts"`
	Why  string    `json:"why"`
}

// NewMachine returns a machine in the given initial state.
//
// The applier defaults to Disabled. There is no constructor that accepts a
// working applier, which is what makes "this build cannot activate" a
// property of the package rather than a runtime configuration.
func NewMachine(initial State) *Machine {
	if initial == "" {
		initial = StateUninitialised
	}
	return &Machine{
		state:      initial,
		since:      time.Now().UTC(),
		applier:    Disabled{},
		gates:      GateResult{AllSatisfied: false},
		maxHistory: 64,
	}
}

// State returns the current state.
func (m *Machine) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// Since returns when the machine entered its current state.
func (m *Machine) Since() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.since
}

// History returns the recorded transitions.
func (m *Machine) History() []Transition {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Transition, len(m.history))
	copy(out, m.history)
	return out
}

// SetGates records the latest gate evaluation.
func (m *Machine) SetGates(g GateResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gates = g
}

// Gates returns the latest gate evaluation.
func (m *Machine) Gates() GateResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gates
}

// ConfirmPresence records that an operator confirmed physical presence.
//
// In this build the confirmation is recorded and surfaced, but it cannot by
// itself enable activation: the apply-path gate remains unsatisfied.
func (m *Machine) ConfirmPresence() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.presence = true
}

// PresenceConfirmed reports whether presence has been confirmed.
func (m *Machine) PresenceConfirmed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.presence
}

// Applier returns the applier bound to this machine.
func (m *Machine) Applier() Applier {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.applier
}

// allowedTransitions defines the state graph.
//
// The graph is written out in full rather than computed, because the whole
// point is that a reader can verify at a glance that no edge leaves Prepared
// toward Activating in this build. A generated or default-allow graph would
// hide exactly the property this package exists to guarantee.
var allowedTransitions = map[State][]State{
	StateUninitialised: {StateDevelopment},
	StateDevelopment:   {StatePrepared, StateDevelopment},
	StatePrepared:      {StatePrepared, StateDevelopment},
	// The remaining states are unreachable in this build: there is no
	// Applier that can reach them. They are declared so that a future
	// implementation has an obvious place to extend the graph.
	StateActivating: {StateActive, StateDegraded, StateFailed},
	StateActive:     {StateDegraded, StateActivating},
	StateDegraded:   {StateActive, StateFailed},
	StateFailed:     {StateDevelopment, StatePrepared},
}

// CanTransition reports whether from -> to is a legal transition.
func CanTransition(from, to State) bool {
	for _, s := range allowedTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Transition moves the machine to a new state, recording why.
func (m *Machine) Transition(to State, why string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == to {
		return fmt.Errorf("%w: already in %s", ErrInvalidTransition, to)
	}
	if !CanTransition(m.state, to) {
		return fmt.Errorf("%w: %s -> %s is not permitted", ErrInvalidTransition, m.state, to)
	}

	m.history = append(m.history, Transition{
		From: m.state, To: to, TS: time.Now().UTC(), Why: why,
	})
	if len(m.history) > m.maxHistory {
		m.history = m.history[len(m.history)-m.maxHistory:]
	}
	m.state = to
	m.since = time.Now().UTC()
	return nil
}

// Prepare moves the machine to Prepared, recording that a plan is validated
// and deliberately not applied.
func (m *Machine) Prepare(why string) error {
	return m.Transition(StatePrepared, why)
}

// Activate attempts activation.
//
// It always fails in this build, and it fails in the most informative way
// possible: the reason names the unmet gates and the missing apply path, so an
// operator running `thn activate` out of curiosity learns exactly what state
// the gateway is in instead of getting a bare "not implemented".
func (m *Machine) Activate(ctx Context) error {
	app := m.Applier()

	if !app.Available() {
		var missing []string
		for _, name := range m.Gates().Blocking {
			missing = append(missing, name)
		}
		detail := "no apply path is compiled into this build"
		if len(missing) > 0 {
			detail += fmt.Sprintf("; additionally unmet: %v", missing)
		}
		return fmt.Errorf("%w (%s)", ErrNoApplyPath, detail)
	}

	// Unreachable in this build: Disabled is the only Applier and it reports
	// Available() == false. The call exists so that adding a real applier does
	// not require restructuring the machine.
	return app.Apply(ctx)
}

// Report renders the machine's current position for `thn status`.
type Report struct {
	// State is the current lifecycle state.
	State State `json:"state"`
	// Since is when the state was entered.
	Since time.Time `json:"since"`
	// CanApply reports whether this build can change the host.
	CanApply bool `json:"can_apply"`
	// Applier describes the bound applier.
	Applier string `json:"applier"`
	// ImplementedStages lists what this build can do.
	ImplementedStages []Stage `json:"implemented_stages"`
	// UnsupportedStages lists what this build cannot do.
	UnsupportedStages []Stage `json:"unsupported_stages"`
	// Gates is the latest gate evaluation.
	Gates GateResult `json:"gates"`
	// PresenceConfirmed reports operator presence confirmation.
	PresenceConfirmed bool `json:"presence_confirmed"`
}

// Report returns a snapshot of the machine for display.
func (m *Machine) Report() Report {
	// The applier is read directly rather than through Applier(), which
	// takes its own read lock; taking both here would deadlock, because
	// sync.RWMutex is not reentrant.
	m.mu.RLock()
	app := m.applier
	report := Report{
		State:             m.state,
		Since:             m.since,
		Applier:           app.Describe(),
		ImplementedStages: ImplementedStages(),
		UnsupportedStages: UnsupportedStages(),
		Gates:             m.gates,
		PresenceConfirmed: m.presence,
	}
	m.mu.RUnlock()

	report.CanApply = app.Available()
	return report
}
