// Package rules declares the conditions THN evaluates against signals, and
// evaluates them over time.
//
// # A rule is a condition that must hold
//
// A rule does not fire because a signal matched. It fires because a condition
// held continuously for a stated duration. That distinction is the difference
// between an alerting system and a noise generator.
//
// A carrier link that flaps for 200 milliseconds several times a minute is
// healthy in every sense that matters, and a system without a duration
// threshold opens an incident for each flap. With one, the flapping never
// reaches the threshold and the operator is not paged about a link that is
// working.
//
// The cost of the duration is a real one: a genuine failure takes that much
// longer to report. That trade is worth making deliberately, per rule, rather
// than globally. A link down for a minute and a pool that is 95% full need
// very different thresholds, and a single global one would be wrong for both.
//
// # Unknown does not fire
//
// A condition returns one of three results, not two. When the signal it needs
// was not read, the result is TruthUnknown and the rule does not fire, does
// not resolve, and does not change state at all.
//
// This is stricter than it sounds. A rule that was firing and whose signal
// becomes unreadable stays firing, because "we can no longer tell" is not
// evidence of recovery. Reporting a resolution on lost visibility would let a
// gateway that has stopped answering appear to have fixed itself.
//
// # Rules describe themselves
//
// Every condition can render itself as a sentence. `thn rules list` shows
// those sentences, and an incident quotes the condition that produced it.
// A rule nobody can explain is a rule nobody can trust, and on a device that
// cannot be reached from the console, the explanation is the only thing there
// is.
package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/signals"
)

// Truth is the result of evaluating a condition.
type Truth int

const (
	// TruthFalse means the condition did not hold.
	TruthFalse Truth = iota

	// TruthTrue means the condition held.
	TruthTrue

	// TruthUnknown means the condition could not be determined, because a
	// signal it depends on was not read.
	//
	// This is not a synonym for false and is never treated as one. A rule
	// that cannot see its input has learned nothing, and reporting that it
	// learned the condition was false would be a fabrication.
	TruthUnknown
)

// String renders the truth for display.
func (t Truth) String() string {
	switch t {
	case TruthTrue:
		return "true"
	case TruthFalse:
		return "false"
	default:
		return "unknown"
	}
}

// MarshalJSON emits the truth as its name rather than as its ordinal.
//
// Left to the default marshaller this becomes 0, 1 or 2, which is worse than
// merely terse: a consumer reading `last_truth: 2` has to know the encoding to
// learn that the condition could not be determined, and the two states that
// most need telling apart — false and unknown — are adjacent integers. A
// consumer that guessed, or that defaulted an unrecognised value to "not
// firing", would report an unread signal as a healthy one. That is precisely
// the conflation this type exists to prevent, so it does not happen in the
// serialised form either.
func (t Truth) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// Condition is a test over a set of signals.
type Condition interface {
	// Test evaluates the condition.
	Test(set *signals.Set) Truth

	// Describe renders the condition as a sentence, in terms of the signal
	// names it reads.
	Describe() string

	// Signals returns the names this condition depends on, so a rule can be
	// checked against a set that does not contain what it needs.
	Signals() []string

	// Conditions explains why the condition could not be determined.
	//
	// It returns nil when the condition was determinable, including when it
	// was determinably false. The distinction matters: "the link is up" and
	// "the link could not be read" are different answers, and only the second
	// is one the operator has to act on.
	Conditions(set *signals.Set) []string
}

// Severity is how serious a rule firing is.
type Severity string

const (
	// SeverityCritical means the gateway is not doing its job.
	//
	// It is reserved for conditions where traffic is actually affected. A
	// critical label that appears for conditions nobody would act on
	// immediately trains an operator to triage, and triage is what makes
	// critical mean anything.
	SeverityCritical Severity = "critical"

	// SeverityWarning means something is wrong but traffic still flows.
	SeverityWarning Severity = "warning"

	// SeverityInfo is worth recording and not worth interrupting anyone for.
	SeverityInfo Severity = "info"
)

// rank orders severities, highest first.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// AtLeast reports whether s is at least as severe as other.
func (s Severity) AtLeast(other Severity) bool { return s.rank() >= other.rank() }

// WeakerThan reports whether s is strictly less severe than other.
//
// It exists because the common comparison is "is this new severity lower than
// the one recorded", and AtLeast cannot express it: asking "is the new
// severity below the old" is not the same as "the new severity does not meet
// the old", because equal satisfies the latter.
func (s Severity) WeakerThan(other Severity) bool { return s.rank() < other.rank() }

// Max returns the more severe of two severities.
//
// An incident's severity is the worst of its contributors. Reporting a group
// of five warnings as a warning when one of them is critical would bury the
// one that matters.
func Max(a, b Severity) Severity {
	if a.rank() >= b.rank() {
		return a
	}
	return b
}

// Valid reports whether the severity is one of the three defined values.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityWarning, SeverityInfo:
		return true
	}
	return false
}

// String renders the severity.
func (s Severity) String() string { return string(s) }

// Rule is a named condition with a duration threshold.
type Rule struct {
	// Name identifies the rule. It appears in incidents, so it is part of the
	// package's contract.
	Name string `json:"name"`

	// Title is a one-line statement of what is wrong when this fires, phrased
	// as the operator would say it.
	Title string `json:"title"`

	// Severity is how serious a firing is.
	Severity Severity `json:"severity"`

	// For is how long the condition must hold continuously before the rule
	// fires.
	//
	// Zero is allowed and means "fire immediately". It is a poor default for
	// anything derived from link state, and a good one for something derived
	// from configuration, which does not flap.
	For time.Duration `json:"for"`

	// Condition is what must hold.
	Condition Condition `json:"-"`

	// Labels are attached to every instance this rule produces, and are what
	// correlation groups on.
	Labels map[string]string `json:"labels,omitempty"`

	// Remedy says what to do about it.
	//
	// A rule that can say nothing actionable is usually better expressed as
	// an info-level observation than as a warning nobody can act on.
	Remedy string `json:"remedy,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty"`
}

// String renders the rule for display.
func (r Rule) String() string {
	var b strings.Builder

	b.WriteString(r.Name)
	b.WriteString(": ")
	b.WriteString(r.Condition.Describe())
	if r.For > 0 {
		fmt.Fprintf(&b, " for at least %s", r.For)
	}
	return b.String()
}

// Validate checks a rule for the mistakes that make it useless.
func (r Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("a rule must have a name; it appears in incidents")
	}
	if r.Condition == nil {
		return fmt.Errorf("rule %q has no condition", r.Name)
	}
	if !r.Severity.Valid() {
		return fmt.Errorf("rule %q has severity %q, which is not one of critical, warning or info",
			r.Name, r.Severity)
	}
	if r.Title == "" {
		return fmt.Errorf("rule %q has no title; a firing would have nothing to say", r.Name)
	}
	if r.For < 0 {
		return fmt.Errorf("rule %q has a negative duration threshold", r.Name)
	}
	return nil
}

// State is where a rule is in its lifecycle for one group of labels.
type State string

const (
	// StateInactive means the condition does not hold.
	StateInactive State = "inactive"

	// StatePending means the condition holds but has not held long enough.
	StatePending State = "pending"

	// StateFiring means the condition has held long enough to report.
	StateFiring State = "firing"
)

// String renders the state.
func (s State) String() string { return string(s) }

// Instance is one rule's lifecycle for one set of labels.
//
// A rule with labels produces one instance per distinct label set, because a
// pool 95% full on the LAN and one 95% full on a future guest segment are
// different problems with different fixes.
type Instance struct {
	// Rule is the name of the rule this is an instance of.
	Rule string `json:"rule"`

	// Group is the label fingerprint that distinguishes this instance.
	Group string `json:"group,omitempty"`

	// State is the current lifecycle position.
	State State `json:"state"`

	// Since is when the current state was entered.
	Since time.Time `json:"since"`

	// Severity is the rule's severity, copied onto the instance.
	//
	// It is carried rather than looked up because downstream stages correlate
	// and group instances, and making them hold a rule table to answer a
	// question the instance already knows is a chance for the two to disagree.
	Severity Severity `json:"severity"`

	// Title is the rule's statement of what is wrong, and Condition is the
	// sentence describing what held.
	//
	// Both are carried rather than looked up for the same reason as Severity.
	// They matter more than the severity does: an incident that names a rule
	// without saying what that rule means leaves the operator to go and read
	// the source, from a device they cannot reach.
	Title     string `json:"title,omitempty"`
	Condition string `json:"condition,omitempty"`

	// Evidence is the signal that made the rule fire, kept so the incident
	// can quote what was actually observed rather than re-deriving it.
	Evidence *signals.Signal `json:"evidence,omitempty"`

	// LastTruth is the most recent evaluation result.
	//
	// An instance whose last truth was unknown keeps its previous state, and
	// this is how an operator can tell that the rule is being evaluated but
	// cannot see its input.
	LastTruth Truth `json:"last_truth"`

	// Conditions records why the condition could not be determined, when it
	// could not be.
	Conditions []string `json:"conditions,omitempty"`
}

// Firing reports whether the instance is firing.
func (i Instance) Firing() bool { return i.State == StateFiring }

// Transition is a change of state, for the event log and the timeline.
type Transition struct {
	// Rule is the rule that changed.
	Rule string `json:"rule"`

	// Group is the label fingerprint.
	Group string `json:"group,omitempty"`

	// From and To are the states before and after.
	From State `json:"from"`
	To   State `json:"to"`

	// At is when the change happened.
	At time.Time `json:"at"`

	// Firing is the signal that triggered the change, when there was one.
	Firing *signals.Signal `json:"firing,omitempty"`

	// HeldFor is how long the condition had held when the transition
	// happened, which is what shows a duration threshold did its job.
	HeldFor time.Duration `json:"held_for,omitempty"`
}

// It is the component that makes duration thresholds possible: evaluating a
// rule repeatedly against the same signals yields the same answer, and only an
// evaluator that remembers the previous one can tell a condition that has held
// for a minute from one that has held for an instant.
type Evaluator struct {
	instances map[string]*Instance

	// pending holds the transitions produced by the current Evaluate, keyed
	// by instance. A rule that fans out over several label sets produces one
	// transition per set, and a single return value would keep only the last.
	pending map[string]Transition

	now func() time.Time
}

// NewEvaluator returns an evaluator that reads the clock through now.
//
// The clock is injectable so that a test can advance time deliberately. A
// test that slept instead would be slow, and one that used the real clock
// would be flaky — and an alerting engine is exactly the kind of code where a
// flaky test trains people to ignore it.
func NewEvaluator(now func() time.Time) *Evaluator {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Evaluator{
		instances: map[string]*Instance{},
		pending:   map[string]Transition{},
		now:       now,
	}
}

// Evaluate advances every rule by one observation.
//
// It returns the instances that are firing and the transitions that occurred.
// The two are separate because a caller that only wants the current picture
// should not have to reconstruct it from a transition log, and a caller that
// wants the log should not have to diff two snapshots to build one.
func (e *Evaluator) Evaluate(rules []Rule, set *signals.Set) ([]Instance, []Transition) {
	// The evaluator's clock governs, and the observation's own timestamp is
	// deliberately ignored.
	//
	// An earlier version let the set's timestamp win, on the reasoning that a
	// caller replaying recorded observations should get their history rather
	// than the history of now. That is a real need, and solving it this way
	// was wrong: the observation's timestamp is data, and a data value is not
	// a clock. A set that is stamped identically on every evaluation — which
	// is what a collector that reuses a construction time produces — freezes
	// every duration threshold, so a rule with a one-minute grace can never
	// fire at all. A set stamped in the future fast-forwards them instead.
	//
	// Replay is driven through NewEvaluator, which is where a clock belongs.
	// A caller replaying a recording constructs an evaluator whose clock
	// returns the recorded time, and the state machine behaves identically.
	now := e.now()

	var firing []Instance
	var transitions []Transition

	// Rules are evaluated in name order so that a caller reading the
	// transitions sees them the same way twice.
	sorted := append([]Rule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	for _, rule := range sorted {
		for _, inst := range e.advance(rule, set, now) {
			if inst.State == StateFiring {
				firing = append(firing, inst)
			}
		}
	}

	for _, key := range e.instanceKeys() {
		if tr, ok := e.pending[key]; ok {
			transitions = append(transitions, tr)
			delete(e.pending, key)
		}
	}

	sort.SliceStable(firing, func(i, j int) bool {
		if firing[i].Rule != firing[j].Rule {
			return firing[i].Rule < firing[j].Rule
		}
		return firing[i].Group < firing[j].Group
	})
	sort.SliceStable(transitions, func(i, j int) bool {
		if transitions[i].Rule != transitions[j].Rule {
			return transitions[i].Rule < transitions[j].Rule
		}
		return transitions[i].Group < transitions[j].Group
	})

	return firing, transitions
}

// advance evaluates one rule for one instance, returning it if it is firing.
func (e *Evaluator) advance(rule Rule, set *signals.Set, now time.Time) []Instance {
	if rule.Condition == nil {
		return nil
	}

	// Rules with labels fan out over the label sets actually present in the
	// observation, so an interface that has gone away stops producing
	// instances rather than lingering with a stale label set.
	groups := e.groupsFor(rule, set)

	var out []Instance
	for _, group := range groups {
		inst := e.step(rule, group, set, now)
		if inst.State == StateFiring {
			out = append(out, *inst)
		}
	}
	return out
}

// step evaluates one rule for one group.
func (e *Evaluator) step(rule Rule, group string, set *signals.Set, now time.Time) *Instance {
	key := rule.Name + "\x00" + group

	inst, ok := e.instances[key]
	if !ok {
		inst = &Instance{
			Rule:      rule.Name,
			Group:     group,
			State:     StateInactive,
			Since:     now,
			Severity:  rule.Severity,
			Title:     rule.Title,
			Condition: rule.Condition.Describe(),
		}
		e.instances[key] = inst
	}
	// Refreshed on every evaluation so that changing a rule's severity, title
	// or condition takes effect without having to reset the evaluator.
	inst.Severity = rule.Severity
	inst.Title = rule.Title
	inst.Condition = rule.Condition.Describe()

	truth := rule.Condition.Test(set)
	inst.LastTruth = truth
	inst.Conditions = rule.Condition.Conditions(set)

	transition := func(to State, sig *signals.Signal) {
		heldFor := now.Sub(inst.Since)
		from := inst.State

		inst.State = to
		inst.Since = now
		inst.Evidence = sig

		if e.pending == nil {
			e.pending = map[string]Transition{}
		}
		e.pending[key] = Transition{
			Rule:    rule.Name,
			Group:   group,
			From:    from,
			To:      to,
			At:      now,
			Firing:  sig,
			HeldFor: heldFor,
		}
	}

	switch truth {
	case TruthUnknown:
		// Deliberately does nothing. A rule that was firing stays firing and
		// a rule that was pending stays pending, because losing sight of the
		// input is not evidence about the condition.

		return inst

	case TruthFalse:
		if inst.State != StateInactive {
			transition(StateInactive, nil)
		}

	case TruthTrue:
		sig := e.evidence(rule, set, group)

		switch inst.State {
		case StateInactive:
			if rule.For > 0 {
				transition(StatePending, sig)
			} else {
				transition(StateFiring, sig)
			}

		case StatePending:
			// The threshold is measured from when THN first observed the
			// condition holding, not from when the condition actually began.
			//
			// A gateway that was already broken when THN started observing is
			// therefore not reported instantly — it is reported after one
			// threshold, during which THN confirms the condition is real rather
			// than a single bad read. That is the conservative direction: a
			// fault that is already true is reported a minute late, which costs
			// a minute, and a fault that was not true is never reported, which
			// costs an operator an afternoon.
			if now.Sub(inst.Since) >= rule.For {
				transition(StateFiring, sig)
			}

		case StateFiring:
			// Already firing. The evidence is refreshed so an incident always
			// quotes the most recent observation, not the one that opened it.
			inst.Evidence = sig
		}
	}

	return inst
}

// evidence finds the signal to quote for a firing or pending instance.
//
// It prefers the signal the condition actually depends on, because quoting an
// unrelated signal would be technically accurate and practically useless.
func (e *Evaluator) evidence(rule Rule, set *signals.Set, group string) *signals.Signal {
	for _, name := range rule.Condition.Signals() {
		sig, ok := set.Get(name)
		if !ok {
			continue
		}
		// An instance only ever quotes a signal matching its own labels,
		// otherwise a per-interface rule would quote whichever interface
		// happened to be read first.
		if group != "" && sig.LabelFingerprint() != group {
			continue
		}
		out := sig
		return &out
	}
	return nil
}

// groupsFor returns the label sets an instance should exist for.
func (e *Evaluator) groupsFor(rule Rule, set *signals.Set) []string {
	labelKey, ok := rule.Labels[GroupLabel]
	if !ok || labelKey == "" {
		return []string{""}
	}

	// Fan out over the values the labelled signal actually has, so an
	// interface that disappears stops being evaluated.
	var groups []string
	seen := map[string]bool{}

	for _, sig := range set.All() {
		if len(rule.Condition.Signals()) > 0 && !contains(rule.Condition.Signals(), sig.Name) {
			continue
		}
		v := sig.Label(labelKey)
		if v == "" {
			continue
		}
		g := labelKey + "=" + escapeGroup(v)
		if seen[g] {
			continue
		}
		seen[g] = true
		groups = append(groups, g)
	}

	sort.Strings(groups)
	return groups
}

// instanceKeys returns every live instance key, sorted.
func (e *Evaluator) instanceKeys() []string {
	out := make([]string, 0, len(e.instances))
	for k := range e.instances {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// All returns every live instance, sorted by rule then group.
//
// It exists so an operator can see a pending rule, not just a firing one. A
// condition that has held for four of its five minutes is the single most
// useful early warning an alerting system can give, and an API that only
// returned firings would hide it.
func (e *Evaluator) All() []Instance {
	keys := e.instanceKeys()
	out := make([]Instance, 0, len(keys))
	for _, k := range keys {
		out = append(out, *e.instances[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Group < out[j].Group
	})
	return out
}

// Instances returns the live instances of one rule.
func (e *Evaluator) Instances(rule string) []Instance {
	var out []Instance
	for _, inst := range e.All() {
		if inst.Rule == rule {
			out = append(out, inst)
		}
	}
	return out
}

// Firing returns the instances that are currently firing.
func (e *Evaluator) Firing() []Instance {
	var out []Instance
	for _, inst := range e.All() {
		if inst.Firing() {
			out = append(out, inst)
		}
	}
	return out
}

// Pending returns the instances whose condition holds but has not yet held
// long enough.
func (e *Evaluator) Pending() []Instance {
	var out []Instance
	for _, inst := range e.All() {
		if inst.State == StatePending {
			out = append(out, inst)
		}
	}
	return out
}

// Undecidable returns the instances whose last evaluation could not be
// determined.
//
// This is the "I cannot tell" list, and it is the one an operator most needs
// on a gateway that has stopped answering. A system that reports only its
// firings presents silence as health.
func (e *Evaluator) Undecidable() []Instance {
	var out []Instance
	for _, inst := range e.All() {
		if inst.LastTruth == TruthUnknown {
			out = append(out, inst)
		}
	}
	return out
}

// Reset forgets every instance.
//
// Used when a rule set changes: an instance keyed by a rule that no longer
// exists would otherwise linger, holding state for a condition that is no
// longer evaluated.
func (e *Evaluator) Reset() {
	e.instances = map[string]*Instance{}
	e.pending = map[string]Transition{}
}

// contains reports whether a slice holds a value.
func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// escapeGroup makes a label value safe to use in a group key.
func escapeGroup(v string) string {
	return strings.NewReplacer(`\`, `\\`, `,`, `\,`, `=`, `\=`).Replace(v)
}
