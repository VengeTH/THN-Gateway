package activation

import (
	"errors"
	"fmt"
	"strings"
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

	// StatePrepared means a plan has been generated and validated but has not
	// been applied. It is the resting state before an authorised activation.
	StatePrepared State = "PREPARED"

	// StateActivating means an apply is in progress.
	StateActivating State = "ACTIVATING"

	// StateActive means the gateway is serving traffic as planned.
	StateActive State = "ACTIVE"

	// StateDegraded means activation failed and the host could not be returned
	// to its baseline. It is a terminal state requiring operator action.
	StateDegraded State = "DEGRADED"

	// StateFailed means activation was rolled back and verified.
	StateFailed State = "FAILED"
)

// String renders the state for display.
func (s State) String() string { return string(s) }

// Errors returned by the state machine. They are distinct so that the CLI
// can report precisely why an activation was refused rather than a generic
// failure.
var (
	// ErrNoApplyPath is returned when no applier is bound to the machine.
	// The build contains an apply path; a machine reached without one has
	// been wired incorrectly.
	ErrNoApplyPath = errors.New("activation: no apply path is bound to this machine")

	// ErrInvalidTransition is returned when a state change is not permitted.
	ErrInvalidTransition = errors.New("activation: invalid state transition")

	// ErrGateNotSatisfied is returned when a safety gate is not satisfied.
	ErrGateNotSatisfied = errors.New("activation: safety gate not satisfied")

	// ErrPresenceNotConfirmed is returned when physical presence has not been
	// confirmed and the configuration requires it.
	ErrPresenceNotConfirmed = errors.New("activation: physical presence has not been confirmed")

	// ErrNotAuthorized is returned when the bound applier is not authorized.
	ErrNotAuthorized = errors.New("activation: applier is not authorized to act")
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
	// StageApply is implemented behind the production authorization path.
	StageApply Stage = "apply"
	// StageHealthCheck is implemented: post-apply verification runs.
	StageHealthCheck Stage = "health-check"
	// StageCommit is implemented: a verified apply is committed.
	StageCommit Stage = "commit"
	// StageRollback is implemented: a failed apply is compensated and verified.
	StageRollback Stage = "rollback"
)

// ImplementedStages returns the stages this build can perform.
func ImplementedStages() []Stage {
	return []Stage{
		StageObserve, StageModel, StagePlan, StageValidate,
		StageSimulate, StageApply, StageHealthCheck, StageCommit, StageRollback,
	}
}

// UnsupportedStages returns the stages this build cannot perform.
//
// It is empty. It is retained because callers render it, and a caller that
// silently stopped rendering the list would hide a regression rather than
// report one.
func UnsupportedStages() []Stage { return []Stage{} }

// CanApply reports whether this build contains an apply path.
//
// # What this does and does not mean
//
// This is a statement about the BUILD, not about any one activation request.
// It is true because internal/execution contains a complete, scoped
// production transaction: baseline capture, structured operations, post-apply
// health verification, compensating rollback and rollback verification.
//
// It is deliberately not, and must never be read as, a statement that an
// activation will be permitted. That question is answered by the gates in
// EvaluateProduction, by the Applier bound to a Machine reporting
// Available(), and again independently by Executor.ExecutePlan re-deriving
// every digest at the moment of execution. Three separate checks, because a
// single check is one mistake away from being the only thing standing between
// a plan and a host.
//
// Flipping this constant to true without the machinery behind it would make
// the apply-path gate decorative. The machinery is what makes it honest.
func CanApply() bool { return true }

// Applier performs activation.
//
// The interface exists so the state machine is written against the real thing
// rather than against a hard-coded refusal. There is exactly one production
// implementation — execution's production transaction — and Disabled, which
// refuses.
type Applier interface {
	// Apply activates the gateway.
	Apply(ctx Context) error

	// Available reports whether this applier is currently authorized to act.
	// Disabled returns false; the production applier returns false until
	// Authorize has succeeded.
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
// Evaluate runs the standard 7-gate set for an activation readiness check.
func Evaluate(in GateInput) GateResult {
	var gates []Gate

	gates = append(gates, Gate{
		Name:        "apply-path-available",
		Description: "the running build must contain an apply path",
		Satisfied:   CanApply(),
		Reason:      "this build contains no apply path; it can observe, model, plan, validate and simulate only",
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
		Description: "an interface satisfying the desired WAN role must exist on this host",
		Satisfied:   in.WAN.Satisfied,
		Reason:      reasonUnless(in.WAN.Satisfied, in.WAN.Reason),
	})

	gates = append(gates, Gate{
		Name:        "lan-identified",
		Description: "an interface satisfying the desired LAN role must be identified and attached",
		Satisfied:   in.LAN.Satisfied,
		Reason:      reasonUnless(in.LAN.Satisfied, in.LAN.Reason),
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

// EvaluateProduction runs the complete set of M7.6 production activation gates.
// All gates must pass before a production applier is authorized to mutate host networking.
func EvaluateProduction(in GateInput) GateResult {
	var gates []Gate

	gates = append(gates, Gate{
		Name:        "apply-path-available",
		Description: "the running build must contain an apply path",
		Satisfied:   CanApply(),
		Reason:      "this build contains no apply path; it can observe, model, plan, validate and simulate only",
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
		Description: "an interface satisfying the desired WAN role must exist on this host",
		Satisfied:   in.WAN.Satisfied,
		Reason:      reasonUnless(in.WAN.Satisfied, in.WAN.Reason),
	})

	gates = append(gates, Gate{
		Name:        "lan-identified",
		Description: "an interface satisfying the desired LAN role must be identified and attached",
		Satisfied:   in.LAN.Satisfied,
		Reason:      reasonUnless(in.LAN.Satisfied, in.LAN.Reason),
	})

	gates = append(gates, Gate{
		Name:        "no-role-conflicts",
		Description: "LAN and WAN roles must not collide or reference the same physical interface",
		Satisfied:   in.NoRoleConflicts,
		Reason:      reasonUnless(in.NoRoleConflicts, fallback(in.RoleConflictProblem, "logical roles are unassigned or conflict with each other")),
	})

	gates = append(gates, Gate{
		Name:        "host-readiness",
		Description: "host readiness criteria and required interfaces must be satisfied",
		Satisfied:   in.HostReadinessOK,
		Reason:      reasonUnless(in.HostReadinessOK, fallback(in.HostReadinessProblem, "host hardware or operating environment is not ready")),
	})

	gates = append(gates, Gate{
		Name:        "capabilities-observed",
		Description: "required networking capabilities must be explicitly observed rather than inferred",
		Satisfied:   in.CapabilitiesObserved,
		Reason:      reasonUnless(in.CapabilitiesObserved, fallback(in.CapabilitiesProblem, "required capabilities are not explicitly observed")),
	})

	gates = append(gates, Gate{
		Name:        "digests-fresh",
		Description: "plan digests must match live host observation and desired state",
		Satisfied:   in.DigestsFresh,
		Reason:      reasonUnless(in.DigestsFresh, fallback(in.DigestsProblem, "plan digests are stale or uncalculated")),
	})

	gates = append(gates, Gate{
		Name:        "management-safety",
		Description: "remote management connectivity (SSH, Tailscale) must be verified safe",
		Satisfied:   in.ManagementSafe,
		Reason:      reasonUnless(in.ManagementSafe, fallback(in.ManagementProblem, "remote management path safety cannot be proven")),
	})

	gates = append(gates, Gate{
		Name:        "recoverable",
		Description: "a recovery plan must exist and must not be blocked",
		Satisfied:   in.RecoveryOK,
		Reason:      reasonUnless(in.RecoveryOK, in.RecoveryProblem),
	})

	gates = append(gates, Gate{
		Name: "subsystems-executable",
		Description: "every subsystem the configuration requires must be one THN can " +
			"actually apply at runtime, not merely represent in desired state",
		Satisfied: in.SubsystemsExecutable,
		Reason: reasonUnless(in.SubsystemsExecutable, fallback(in.SubsystemsProblem,
			"a required subsystem has no runtime implementation")),
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

// RoleGate records how one logical role was satisfied on this host.
//
// # Why this replaced a boolean
//
// The gate used to read a bare `WANPresent bool`, which the CLI computed as
// "does an interface exist whose kernel name equals the string in
// network.wan". That is not the question the gate asks. The question is
// whether a suitable uplink exists. Expressing it as name equality meant:
//
//   - the gate could only ever be satisfied by a document that already named a
//     kernel interface, so the product could not be configured the way an
//     operator thinks about it;
//   - it said nothing about WHICH interface satisfied it, or why, so a
//     readiness report could not be acted on;
//   - and it had no way to express "the right interface exists but this host
//     cannot route", which is a different problem with a different fix.
//
// RoleGate can express all three. It is a value, not a flag, because a gate an
// operator cannot read the detail of is a gate they cannot act on.
type RoleGate struct {
	// Role is the logical role this gate is about: "wan", "lan".
	Role string `json:"role"`

	// Satisfied reports whether a suitable interface fills the role.
	Satisfied bool `json:"satisfied"`

	// Interface is the kernel name that satisfied it, when one did.
	//
	// It is recorded, never required. An operator may legitimately change
	// the NIC and the gate must still pass; the name is here to explain the
	// verdict, not to define it.
	Interface string `json:"interface,omitempty"`

	// Selector is what the configuration asked for: a stable identity, a
	// kernel name, or empty when the role was filled by assignment.
	Selector string `json:"selector,omitempty"`

	// Capability is the host capability this role depends on, if any.
	Capability string `json:"capability,omitempty"`

	// Reason explains the verdict. It is required when unsatisfied, and
	// optional but valuable when satisfied.
	Reason string `json:"reason,omitempty"`
}

// GateInput carries the observed facts the gates evaluate.
type GateInput struct {
	// PlanValidated reports whether a validated plan exists.
	PlanValidated bool
	// ConfigValid reports whether the configuration validates.
	ConfigValid bool
	// ConfigProblem explains an invalid configuration.
	ConfigProblem string

	// WAN is how the desired WAN role was satisfied on the observed host.
	WAN RoleGate

	// LAN is how the desired LAN role was satisfied on the observed host.
	LAN RoleGate

	// Capabilities is what the host was observed to be able to do.
	//
	// The gates do not currently require any particular capability, and
	// that is deliberate: a capability derived from the platform rather than
	// from a probe must not be able to enable anything. The set is carried
	// so that a future gate CAN require one, and so that the readiness
	// report can show the operator the full picture rather than two booleans.
	Capabilities []CapabilityGate

	// NoRoleConflicts reports whether logical roles are free of conflicts.
	NoRoleConflicts bool
	// RoleConflictProblem explains a role collision or conflict.
	RoleConflictProblem string

	// HostReadinessOK reports whether the host satisfies readiness criteria.
	HostReadinessOK bool
	// HostReadinessProblem explains host readiness failure.
	HostReadinessProblem string

	// CapabilitiesObserved reports whether required capabilities were explicitly observed.
	CapabilitiesObserved bool
	// CapabilitiesProblem explains missing or unobserved capabilities.
	CapabilitiesProblem string

	// DigestsFresh reports whether plan input digests match live host state.
	DigestsFresh bool
	// DigestsProblem explains stale plan or digest divergence.
	DigestsProblem string

	// ManagementSafe reports whether remote management paths are preserved.
	ManagementSafe bool
	// ManagementProblem explains management risk.
	ManagementProblem string

	// RecoveryOK reports whether recovery is possible.
	RecoveryOK bool
	// RecoveryProblem explains an unrecoverable situation.
	RecoveryProblem string

	// SubsystemsExecutable reports whether every subsystem the configuration
	// asks for is one the execution layer can actually bring up.
	//
	// This is separate from ConfigValid. A configuration asking for a DHCP
	// server is perfectly coherent — it is what a home gateway normally wants
	// — and it validates cleanly. It is also, in this build, not something
	// that can be applied. Collapsing the two would produce a gateway that
	// reports a committed activation while handing out no addresses.
	SubsystemsExecutable bool
	// SubsystemsProblem names the required-but-unimplementable subsystems.
	SubsystemsProblem string

	// PresenceConfirmed reports whether an operator confirmed being present.
	PresenceConfirmed bool
}

// CapabilityGate is one observed host capability, as the gates see it.
//
// It is a separate type from the host package's own so that internal/activation
// — the package that owns the safety boundary — depends on nothing but itself.
// A safety package that imports the discovery package inherits its bugs; this
// one imports nothing.
type CapabilityGate struct {
	// Name is the capability: "routing", "nat", "dhcp", and so on.
	Name string `json:"name"`
	// Available reports whether the host can perform it.
	Available bool `json:"available"`
	// Confidence is "observed", "inferred" or "unknown".
	Confidence string `json:"confidence,omitempty"`
	// Reason explains the verdict.
	Reason string `json:"reason,omitempty"`
}

// Satisfied reports whether a capability is available AND was actually
// observed, not inferred.
//
// This is the distinction the design turns on. A capability concluded from the
// platform — "Linux can NAT" — is not evidence that this machine can, and a
// gate must never be satisfied by an inference. Until a probe exists, nothing
// reaches AVAILABLE through this method, and that is the correct answer
// rather than a gap to be papered over.
func (c CapabilityGate) Satisfied() bool {
	return c.Available && c.Confidence == "observed"
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

func fallback(val, def string) string {
	if val != "" {
		return val
	}
	return def
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
// The applier defaults to Disabled, which refuses everything. Callers that
// intend to act must bind the production applier with NewMachineWithApplier;
// there is no path by which a machine acquires one implicitly, so "this machine
// cannot act" is always a deliberate construction rather than an accident.
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

// NewMachineWithApplier returns a machine bound to app.
//
// It exists so that a machine which can act is constructed by naming the thing
// that will act, in one place, on purpose. The alternative — a default applier
// parameter that silently means Disabled in one caller and the production
// applier in another — is how a machine ends up live that nobody meant to
// enable.
func NewMachineWithApplier(initial State, app Applier) *Machine {
	m := NewMachine(initial)
	if app != nil {
		m.applier = app
	}
	return m
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
// point is that a reader can verify at a glance that no edge bypasses the
// ACTIVATING state. A gateway goes PREPARED -> ACTIVATING -> {ACTIVE,
// DEGRADED, FAILED} and reaches ACTIVE only through ACTIVATING, so there is no
// edge anywhere that reaches a serving state without having applied something
// first.
var allowedTransitions = map[State][]State{
	StateUninitialised: {StateDevelopment},
	StateDevelopment:   {StatePrepared, StateDevelopment},
	StatePrepared:      {StatePrepared, StateActivating, StateDevelopment},
	StateActivating:    {StateActive, StateDegraded, StateFailed},
	StateActive:        {StateDegraded, StateActivating},
	StateDegraded:      {StateActive, StateFailed},
	StateFailed:        {StateDevelopment, StatePrepared},
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
// # What it refuses, and why the refusals are in this order
//
// Four things must hold before the bound applier is called, and they are
// checked in a fixed order so the message an operator sees names the first
// thing that is actually wrong rather than whichever check happened to run
// first in the source:
//
//  1. an applier is bound at all (Disabled, or a miswired caller);
//  2. every safety gate in the latest evaluation holds;
//  3. the applier reports itself authorized;
//  4. the transition into ACTIVATING is legal from the current state.
//
// Gates are checked before authorization on purpose. An authorized driver is
// evidence that someone passed --confirm, not evidence that the host was
// surveyed. A caller who satisfies authorization while a gate is unmet —
// because they constructed ProductionAuth from a stale or partial
// GateInput — must still be refused here, or the ordering would let
// confirmation stand in for evidence.
func (m *Machine) Activate(ctx Context) error {
	app := m.Applier()

	if _, ok := app.(Disabled); ok {
		var missing []string
		missing = append(missing, m.Gates().Blocking...)
		detail := "no apply path is bound to this machine"
		if len(missing) > 0 {
			detail += fmt.Sprintf("; additionally unmet: %v", missing)
		}
		return fmt.Errorf("%w (%s)", ErrNoApplyPath, detail)
	}

	if g := m.Gates(); !g.AllSatisfied {
		return fmt.Errorf("%w: %s", ErrGateNotSatisfied,
			strings.Join(nonEmpty(g.Blocking), ", "))
	}

	if !app.Available() {
		return fmt.Errorf("%w: %s reports it is not authorized; "+
			"explicit production confirmation is required", ErrNotAuthorized, app.Describe())
	}

	if !CanTransition(m.State(), StateActivating) {
		return fmt.Errorf("%w: %s -> %s is not permitted", ErrInvalidTransition, m.State(), StateActivating)
	}

	return app.Apply(ctx)
}

// nonEmpty filters an empty slice down, so a refusal message never renders a
// stray comma for a gate that contributed no name.
func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
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

	_, isDisabled := app.(Disabled)
	report.CanApply = CanApply() && app != nil && !isDisabled
	return report
}
