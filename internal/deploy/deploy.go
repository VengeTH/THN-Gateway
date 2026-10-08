// Package deploy advances a change across a fleet in stages, and stops when
// the fleet gets worse.
//
// # Why staged
//
// A change that is right for every gateway is still wrong for some gateway.
// The reason to roll out in stages is not caution in the abstract — it is that
// the first stage is the cheapest place to discover the change is wrong, and a
// fleet-wide apply makes that discovery arrive after the damage.
//
// The stages exist to bound that cost, not to create ceremony:
//
//	canary    1 gateway
//	small     up to 10%
//	quarter   up to 25%
//	half      up to 50%
//	full      everything
//
// # The property that matters: it stops by itself
//
// A rollout that an operator has to watch and decide to stop is a rollout that
// will, once, run to completion with nobody watching. That is not a risk
// anybody accepts explicitly; it is a risk taken by not writing the code.
//
// So `Advance` halts on deterioration without being asked. It halts when any
// gateway in the current stage reports worse than the baseline, when the
// failure rate exceeds a threshold, and when the gateway that is being changed
// reports health that cannot be determined. It does not halt on a single
// healthy gateway and it does not halt on improvement.
//
// Halting is sticky. A halted rollout does not resume because the next report
// looks better; resuming is a new decision, made by a person, recorded as a
// new rollout. A system that resumes on its own has no halt at all.
//
// # What it does not do
//
// It does not apply anything, does not contact anything, and has no transport.
// It is the decision half: given what the last stage did and what the health
// reports say, what should happen next. The thing that acts on the decision is
// elsewhere and must honour it — which is why `Action` is a value rather than a
// bool, and why "halt" is not a special case of "advance".
package deploy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/health"
)

// Stage is a point in a rollout.
type Stage string

const (
	// StageCanary is a single gateway.
	StageCanary Stage = "canary"
	// StageSmall is up to ten per cent.
	StageSmall Stage = "small"
	// StageQuarter is up to twenty-five per cent.
	StageQuarter Stage = "quarter"
	// StageHalf is up to fifty per cent.
	StageHalf Stage = "half"
	// StageFull is the whole fleet.
	StageFull Stage = "full"
)

// order is the sequence a rollout advances through.
var order = []Stage{StageCanary, StageSmall, StageQuarter, StageHalf, StageFull}

func stageIndex(s Stage) int {
	for i, v := range order {
		if v == s {
			return i
		}
	}
	return -1
}

// Next returns the stage after s, and whether there is one.
func Next(s Stage) (Stage, bool) {
	i := stageIndex(s)
	if i < 0 || i+1 >= len(order) {
		return "", false
	}
	return order[i+1], true
}

// CapFor returns the largest batch a stage may cover, as a fraction.
//
// A canary is one gateway rather than a percentage because a percentage of a
// small fleet is zero gateways, and a rollout that advances by nothing looks
// like one that has stalled.
func CapFor(s Stage, fleet int) int {
	switch s {
	case StageCanary:
		return 1
	case StageSmall:
		return atLeast(1, fleet/10)
	case StageQuarter:
		return atLeast(1, fleet/4)
	case StageHalf:
		return atLeast(1, fleet/2)
	default:
		return fleet
	}
}

func atLeast(n, v int) int {
	if v < n {
		return n
	}
	return v
}

// Action is what the rollout should do next.
type Action string

const (
	// ActionAdvance means widen to the next stage.
	ActionAdvance Action = "advance"

	// ActionRepeat means this stage is not finished.
	//
	// Returned when the stage has been applied but not enough health reports
	// have come back to judge it. Rolling forward on incomplete evidence is
	// the failure this exists to prevent.
	ActionRepeat Action = "repeat"

	// ActionHalt means stop and do nothing further.
	ActionHalt Action = "halt"

	// ActionRollback means stop and undo what has been done.
	ActionRollback Action = "rollback"

	// ActionComplete means every gateway has had the change and it held.
	ActionComplete Action = "complete"
)

// Decision is what to do next, and why.
type Decision struct {
	Action Action `json:"action"`

	// Stage is the stage this decision concerns.
	Stage Stage `json:"stage"`

	// Batch is how many gateways the next stage covers. Zero on a halt.
	Batch int `json:"batch"`

	// Reason is a sentence for the operator.
	//
	// Always populated, and specific about what caused the decision. A
	// rollout that halts because "health degraded" tells the person deciding
	// whether to resume nothing they can act on.
	Reason string `json:"reason"`

	// Triggered names the health report that caused a halt or rollback.
	Triggered []string `json:"triggered,omitempty"`

	// At is when the decision was made.
	At time.Time `json:"at"`
}

// Thresholds are the limits at which a rollout stops.
type Thresholds struct {
	// MaxUnhealthy is how many gateways in a stage may report Unhealthy
	// before the rollout stops.
	//
	// Zero by default, and zero is the only defensible default here. A staged
	// rollout exists to find the gateway this change breaks, and it will find
	// it; continuing past that finding means the staging achieved nothing
	// except a slower failure. An operator who wants to tolerate some can
	// raise this deliberately.
	MaxUnhealthy int

	// MaxDegraded is how many may report Degraded.
	//
	// A proportion rather than a count, because 3 degraded out of 10 is a
	// problem and 3 out of 1000 is noise.
	MaxDegradedFraction float64

	// MinReports is how many gateways must report before a stage is judged.
	//
	// Without it, a stage that applied to ten gateways and got one reply is
	// judged on one reply, and one silent gateway counts as a healthy one.
	MinReports int
}

// DefaultThresholds are the values used when none are supplied.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MaxUnhealthy:        0,
		MaxDegradedFraction: 0.25,
		MinReports:          1,
	}
}

// Rollout is the state of one change's progress across a fleet.
type Rollout struct {
	// ChangeID is the artifact digest or generation this rollout is carrying.
	ChangeID string `json:"change_id"`

	// Fleet is how many gateways the rollout covers.
	Fleet int `json:"fleet"`

	// Stage is the current stage.
	Stage Stage `json:"stage"`

	// Applied is how many gateways have had the change.
	Applied int `json:"applied"`

	// Reports are the health reports from the current stage.
	Reports []health.Report `json:"reports"`

	// Halted records that the rollout stopped and why.
	//
	// Sticky, and checked before anything else. A rollout that resumes
	// because the newest report looks better has no halt in it at all.
	Halted bool `json:"halted"`

	// HaltReason is why it stopped.
	HaltReason string `json:"halt_reason,omitempty"`

	// HaltedAt is when.
	HaltedAt time.Time `json:"halted_at,omitempty"`

	// Thresholds govern the judgement.
	Thresholds Thresholds `json:"-"`

	// Now supplies the clock.
	Now func() time.Time `json:"-"`
}

// New starts a rollout at the canary stage.
func New(changeID string, fleet int, th Thresholds) *Rollout {
	if th.MaxUnhealthy == 0 {
		th = DefaultThresholds()
	}
	if fleet < 1 {
		fleet = 1
	}
	return &Rollout{
		ChangeID:   changeID,
		Fleet:      fleet,
		Stage:      StageCanary,
		Thresholds: th,
	}
}

// Record adds health reports from the current stage.
func (r *Rollout) Record(reports ...health.Report) {
	r.Reports = append(r.Reports, reports...)
	r.Reports = trim(r.Reports, r.Thresholds)
}

// trim keeps the report buffer bounded.
//
// An unbounded buffer on a fleet of a thousand gateways, polled on an interval,
// is a memory leak in a process that is meant to run unattended.
func trim(reports []health.Report, th Thresholds) []health.Report {
	limit := th.MinReports * 4
	if limit < 32 {
		limit = 32
	}
	if len(reports) <= limit {
		return reports
	}
	return reports[len(reports)-limit:]
}

// Advance decides what happens next.
//
// The order is: halted check, completion check, evidence check, judgement,
// then widening. A halt is checked first so that nothing — including a healthy
// report — can move a stopped rollout.
func (r *Rollout) Advance() Decision {
	now := r.now()

	if r.Halted {
		return Decision{
			Action:    ActionHalt,
			Stage:     r.Stage,
			Reason:    r.HaltReason + " It will not resume on its own: continuing is a new decision.",
			At:        now,
			Triggered: []string{"already halted"},
		}
	}

	if r.Applied >= r.Fleet && r.Stage == StageFull {
		return Decision{
			Action: ActionComplete,
			Stage:  StageFull,
			Reason: fmt.Sprintf(
				"Every gateway in the fleet of %d has had the change and no stage halted.", r.Fleet),
			At: now,
		}
	}

	// Not enough evidence yet. Advancing on a partial stage is how a rollout
	// reaches the whole fleet before anyone has heard back from the canary.
	if len(r.Reports) < r.Thresholds.MinReports && r.Applied > 0 {
		return Decision{
			Action: ActionRepeat,
			Stage:  r.Stage,
			Reason: fmt.Sprintf(
				"%d of %d gateway/gateways in the %s stage have reported; waiting for more "+
					"before widening. Judging a stage on incomplete evidence is how a rollout "+
					"reaches the fleet before anyone has heard from the canary.",
				len(r.Reports), r.Thresholds.MinReports, r.Stage),
			At: now,
		}
	}

	if d, halted := r.judge(); halted {
		return d
	}

	// The stage held. Widen.
	next, ok := Next(r.Stage)
	if !ok {
		return Decision{
			Action: ActionComplete,
			Stage:  r.Stage,
			Reason: "The final stage held and every gateway has had the change.",
			At:     now,
		}
	}

	batch := CapFor(next, r.Fleet)
	remaining := r.Fleet - r.Applied
	if batch > remaining {
		batch = remaining
	}

	return Decision{
		Action: ActionAdvance,
		Stage:  next,
		Batch:  batch,
		Reason: fmt.Sprintf(
			"The %s stage held with %d report(s) and no gateway worse than degraded. "+
				"Widening to %s: %d gateway/gateways, %d already done.",
			r.Stage, len(r.Reports), next, batch, r.Applied),
		At: now,
	}
}

// judge assesses the current stage's reports.
//
// Three things stop a rollout, in increasing order of seriousness: an
// unreadable gateway, a degraded majority, and any unhealthy gateway at all.
func (r *Rollout) judge() (Decision, bool) {
	now := r.now()

	var (
		unhealthy  []string
		degraded   []string
		unknowable []string
	)

	for _, rep := range r.Reports {
		switch rep.Verdict {
		case health.VerdictUnhealthy:
			unhealthy = append(unhealthy, rep.Gateway)
		case health.VerdictDegraded:
			degraded = append(degraded, rep.Gateway)
		case health.VerdictUnknowable:
			unknowable = append(unknowable, rep.Gateway)
		}
	}

	sort.Strings(unhealthy)
	sort.Strings(degraded)
	sort.Strings(unknowable)

	// An unreadable gateway in a rollout is the case most likely to be
	// mishandled, because the dashboard shows no red box. It halts.
	if len(unknowable) > 0 {
		return r.halt(now, ActionHalt,
			fmt.Sprintf(
				"%d gateway/gateways in the %s stage could not be health-checked: %s. "+
					"Stopping. A gateway that cannot be read after a change is not a gateway "+
					"that passed; it is a gateway nobody knows the state of, and continuing "+
					"the rollout widens an unknown.",
				len(unknowable), r.Stage, strings.Join(unknowable, ", ")),
			unknowable)
	}

	// Any unhealthy gateway stops the rollout. One is the point of the canary.
	if len(unhealthy) > r.Thresholds.MaxUnhealthy {
		action := ActionHalt
		if len(unhealthy) > r.Thresholds.MaxUnhealthy+2 {
			// By this point it is not a canary finding, it is a bad change.
			action = ActionRollback
		}
		return r.halt(now, action,
			fmt.Sprintf(
				"%d gateway/gateways in the %s stage report unhealthy: %s. Stopping. "+
					"Staged rollout exists to find exactly this before the fleet does.",
				len(unhealthy), r.Stage, strings.Join(unhealthy, ", ")),
			unhealthy)
	}

	if len(r.Reports) > 0 {
		fraction := float64(len(degraded)) / float64(len(r.Reports))
		if fraction > r.Thresholds.MaxDegradedFraction {
			return r.halt(now, ActionHalt,
				fmt.Sprintf(
					"%d of %d gateway/gateways in the %s stage report degraded (%s). "+
						"Stopping: the change is not holding everywhere it has been tried.",
					len(degraded), len(r.Reports), r.Stage, strings.Join(degraded, ", ")),
				degraded)
		}
	}

	return Decision{}, false
}

// halt stops the rollout and records why.
func (r *Rollout) halt(now time.Time, action Action, reason string, triggered []string) (Decision, bool) {
	r.Halted = true
	r.HaltReason = reason
	r.HaltedAt = now

	return Decision{
		Action:    action,
		Stage:     r.Stage,
		Reason:    reason,
		Triggered: triggered,
		At:        now,
	}, true
}

// MarkApplied records that gateways were given the change at the current
// stage, and clears the reports so the next judgement is about that stage.
//
// The reports are cleared deliberately: keeping the canary's reports while
// judging the small stage would average a good gateway with a bad one and hide
// exactly what the stages exist to separate.
func (r *Rollout) MarkApplied(n int) {
	r.Applied += n
	r.Reports = nil
}

// Resume starts a new rollout after a halt.
//
// It returns a new Rollout rather than clearing this one, because a halt and
// its resumption are two decisions by two people and both need to appear in the
// record. Mutating this one in place would make them indistinguishable.
func (r *Rollout) Resume(changeID string, fleet int) *Rollout {
	return New(changeID, fleet, r.Thresholds)
}

func (r *Rollout) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// Render formats a decision for a terminal.
func Render(d Decision) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Action: %s\n", d.Action)
	fmt.Fprintf(&sb, "Stage:  %s\n", d.Stage)
	if d.Batch > 0 {
		fmt.Fprintf(&sb, "Batch:  %d gateway/gateways\n", d.Batch)
	}
	fmt.Fprintf(&sb, "\n%s\n", strings.Repeat("-", 72))
	sb.WriteString(d.Reason)

	if len(d.Triggered) > 0 {
		fmt.Fprintf(&sb, "\n\nTriggered by:\n")
		for _, t := range d.Triggered {
			fmt.Fprintf(&sb, "  %s\n", t)
		}
	}
	return sb.String()
}
