// Package incidents turns correlated groups into a record of what was wrong,
// for how long, and what it was a consequence of.
//
// # An incident is a record, not a notification
//
// The output of this package is a history. A gateway that was unreachable for
// four minutes last Tuesday is a fact about the device that an operator three
// time zones away will need next week, when a user reports it and THN has
// already forgotten.
//
// That is why resolved incidents are kept rather than dropped, why they carry
// a timeline rather than a single timestamp, and why the flapping count is
// part of the record. "The uplink flapped forty times" and "the uplink was
// down once" are different problems with different fixes, and a system that
// collapses them to the same incident has thrown away the diagnosis.
//
// # Identity comes from the fingerprint
//
// An incident is identified by the fingerprint of its group, which is derived
// from the grouping key alone. Five conditions firing, then four, then three,
// then one, are one incident evolving — not four incidents.
//
// The alternative, fingerprinting on the member set, is the obvious
// implementation and it is wrong in a way that only shows up in production: a
// degrading gateway would open a new incident every time a condition cleared,
// and the operator would see a stream of near-identical incidents instead of
// one that got steadily worse.
//
// # Severity is the worst contributor, and escalation is recorded
//
// An incident containing one critical and four warnings is critical. Reporting
// it as a warning would bury the one that matters.
//
// When severity rises, that is recorded as its own timeline entry. An incident
// that quietly became critical is a different event from the one that opened
// as a warning, and an operator reading the history needs to see where it
// turned.
package incidents

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/correlation"
	"github.com/VengeTH/THN-Gateway/internal/rules"
)

// Status is where an incident is in its lifecycle.
type Status string

const (
	// StatusActive means the conditions are still true.
	StatusActive Status = "active"

	// StatusResolved means they are no longer true.
	//
	// A resolved incident is retained. It is the record of what happened, and
	// deleting it would make the device forget its own history.
	StatusResolved Status = "resolved"
)

// String renders the status.
func (s Status) String() string { return string(s) }

// Action is what happened to an incident at a point in its timeline.
type Action string

const (
	// ActionOpened is the first occurrence.
	ActionOpened Action = "opened"

	// ActionUpdated is a change in the contributing conditions.
	ActionUpdated Action = "updated"

	// ActionEscalated is a rise in severity.
	ActionEscalated Action = "escalated"

	// ActionResolved is when the conditions stopped holding.
	ActionResolved Action = "resolved"

	// ActionReopened is when a resolved incident started again.
	//
	// It is a separate action rather than another open, because the two mean
	// different things: an open is a first sighting, and a reopen means a
	// problem THN already thought was over has come back.
	ActionReopened Action = "reopened"
)

// Contribution is one rule that is part of an incident.
type Contribution struct {
	// Rule is the rule's name.
	Rule string `json:"rule"`

	// Title is the rule's statement of what is wrong.
	Title string `json:"title,omitempty"`

	// Condition is the sentence describing what held.
	Condition string `json:"condition,omitempty"`

	// Evidence is what was observed.
	Evidence string `json:"evidence,omitempty"`

	// Severity is the rule's severity.
	Severity rules.Severity `json:"severity"`

	// Suppressed reports whether this is a consequence rather than a cause.
	//
	// It is kept on the incident rather than dropped, so the operator can see
	// what else was true and so that resolving the cause does not lose the
	// information.
	Suppressed bool `json:"suppressed,omitempty"`

	// SuppressedBy names the cause responsible.
	SuppressedBy string `json:"suppressed_by,omitempty"`

	// SuppressedReason explains the suppression.
	SuppressedReason string `json:"suppressed_reason,omitempty"`
}

// Entry is one point in an incident's timeline.
type Entry struct {
	// At is when it happened.
	At time.Time `json:"at"`

	// Action is what happened.
	Action Action `json:"action"`

	// Detail explains it in a sentence.
	Detail string `json:"detail"`

	// Severity is the incident's severity at this point, so the history
	// carries the escalation without needing to be reconstructed.
	Severity rules.Severity `json:"severity"`

	// Conditions is the number of contributing conditions at this point.
	Conditions int `json:"conditions"`
}

// Incident is one problem, tracked over time.
type Incident struct {
	// ID is the stable identifier, derived from the fingerprint.
	ID string `json:"id"`

	// Fingerprint is the grouping key's hash. It is retained alongside the ID
	// so the two can be compared, and so a caller that has a fingerprint from
	// a correlation group can find the incident without going through the key.
	Fingerprint string `json:"fingerprint"`

	// Key is the grouping key, rendered for display.
	Key string `json:"key"`

	// Title is the one-line statement of what is wrong.
	Title string `json:"title"`

	// Severity is the highest severity among the causes.
	Severity rules.Severity `json:"severity"`

	// Status is whether it is still happening.
	Status Status `json:"status"`

	// Labels are the grouping labels.
	Labels map[string]string `json:"labels,omitempty"`

	// OpenedAt is when it was first seen.
	OpenedAt time.Time `json:"opened_at"`

	// UpdatedAt is when it last changed.
	UpdatedAt time.Time `json:"updated_at"`

	// ResolvedAt is when the conditions stopped holding, if they have.
	ResolvedAt time.Time `json:"resolved_at,omitempty"`

	// Duration is how long it has been open, or how long it was open.
	Duration time.Duration `json:"duration"`

	// Flaps counts how many times it has reopened after resolving.
	//
	// A flapping incident is a different problem from a persistent one, and
	// the count is what tells them apart. Without it, forty brief outages and
	// one long one look identical.
	Flaps int `json:"flaps"`

	// Causes are the conditions that are actually responsible.
	Causes []Contribution `json:"causes"`

	// Consequences are the conditions suppressed as results of a cause.
	Consequences []Contribution `json:"consequences,omitempty"`

	// Timeline is the history.
	Timeline []Entry `json:"timeline"`
}

// Active reports whether the incident is still happening.
func (i Incident) Active() bool { return i.Status == StatusActive }

// String renders the incident for display.
func (i Incident) String() string {
	state := string(i.Status)
	if i.Flaps > 0 {
		state = fmt.Sprintf("%s (flapped %d times)", state, i.Flaps)
	}
	return fmt.Sprintf("[%s] %s — %s", i.Severity, i.Title, state)
}

// Manager tracks incidents over time.
//
// It is safe for concurrent use. Observation runs on a timer while an operator
// reads the current list, and a manager that could tear is worse than one that
// takes a lock.
type Manager struct {
	mu sync.Mutex

	// byFingerprint indexes the live incidents.
	byFingerprint map[string]*Incident

	// order preserves first-seen order, so the list reads oldest first. A
	// sorted-by-severity list would put a new critical above a four-hour-old
	// one, and age is what an operator triages by.
	order []string

	// now is the clock, injectable so a test can advance time deliberately.
	now func() time.Time

	// Retain is how many resolved incidents are kept. Zero keeps all of them.
	//
	// A cap exists because this is an in-memory record on a device with a
	// small disk, and an unbounded history is an outage of its own. Keeping
	// the resolved ones is the point; keeping all of them forever is not.
	Retain int
}

// NewManager returns a manager reading the clock through now.
func NewManager(now func() time.Time) *Manager {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Manager{
		byFingerprint: map[string]*Incident{},
		now:           now,
	}
}

// Apply folds a set of correlated groups into the incident record.
//
// The groups are the complete current picture, not a delta. Anything not
// present is treated as having stopped, so a caller must pass everything that
// is firing each time rather than only what changed. This is deliberate: the
// alternative — a delta — cannot distinguish "this stopped" from "this was
// never reported", and a caller that sends deltas will eventually resolve an
// incident that is still happening.
//
// It returns the incidents that changed, which is what a caller renders or
// records. Returning only the changes keeps a caller from re-notifying on
// every observation, which is how an alerting system floods.
func (m *Manager) Apply(groups []correlation.Group) []Incident {
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := map[string]bool{}
	var changed []Incident

	for _, g := range groups {
		if g.Empty() {
			// A group of only suppressed members is a consequence whose cause
			// has already resolved. It is not a problem, and opening an
			// incident for it would be reporting the absence of a cause.
			continue
		}

		fp := g.Fingerprint
		seen[fp] = true

		inc, ok := m.byFingerprint[fp]
		if !ok {
			inc = m.open(g)
			m.byFingerprint[fp] = inc
			m.order = append(m.order, fp)
			changed = append(changed, *inc)
			continue
		}

		if updated := m.update(inc, g); updated {
			changed = append(changed, *inc)
		}
	}

	// Anything previously open that is no longer present has resolved.
	for _, fp := range append([]string(nil), m.order...) {
		if seen[fp] {
			continue
		}
		inc, ok := m.byFingerprint[fp]
		if !ok || inc.Status == StatusResolved {
			continue
		}
		m.resolve(inc)
		changed = append(changed, *inc)
	}

	m.prune()

	return changed
}

// open creates a new incident for a group.
func (m *Manager) open(g correlation.Group) *Incident {
	at := g.At
	if at.IsZero() {
		at = m.now()
	}

	inc := &Incident{
		ID:           IDFor(g.Fingerprint),
		Fingerprint:  g.Fingerprint,
		Key:          g.Key,
		Title:        g.Title(),
		Severity:     g.Severity,
		Status:       StatusActive,
		Labels:       g.Labels,
		OpenedAt:     at,
		UpdatedAt:    at,
		Causes:       causesOf(g),
		Consequences: consequencesOf(g),
	}

	inc.Timeline = []Entry{{
		At:         at,
		Action:     ActionOpened,
		Detail:     incidentDetail(g),
		Severity:   inc.Severity,
		Conditions: len(inc.Causes),
	}}

	return inc
}

// update folds new group content into an existing incident.
//
// It reports whether anything changed. A group whose members are identical to
// last time is not an update, and treating it as one would fill the timeline
// with identical entries and make the real transitions impossible to find.
func (m *Manager) update(inc *Incident, g correlation.Group) bool {
	at := g.At
	if at.IsZero() {
		at = m.now()
	}

	causes := causesOf(g)
	consequences := consequencesOf(g)
	severity := g.Severity

	changed := false

	// A resolved incident that is firing again is a reopen, not an update.
	if inc.Status == StatusResolved {
		inc.Status = StatusActive
		inc.ResolvedAt = time.Time{}
		inc.Flaps++
		inc.Timeline = append(inc.Timeline, Entry{
			At:         at,
			Action:     ActionReopened,
			Detail:     fmt.Sprintf("the problem returned after %s resolved; this is flap %d", roundDur(inc.Duration), inc.Flaps),
			Severity:   severity,
			Conditions: len(causes),
		})
		changed = true
	}

	// The title follows the causes. A group that lost its primary cause and
	// is now only a warning should say so, rather than keeping the title of a
	// problem that is no longer what is happening.
	if title := g.Title(); title != inc.Title {
		inc.Title = title
		changed = true
	}

	if severity.AtLeast(inc.Severity) && severity != inc.Severity {
		inc.Timeline = append(inc.Timeline, Entry{
			At:         at,
			Action:     ActionEscalated,
			Detail:     fmt.Sprintf("the severity rose from %s to %s", inc.Severity, severity),
			Severity:   severity,
			Conditions: len(causes),
		})
		inc.Severity = severity
		changed = true
	} else if severity.WeakerThan(inc.Severity) {
		// Severity dropping is recorded but does not lower the incident's
		// severity. An incident opened as critical stays critical in the
		// record: that is what happened, and rewriting it would hide the fact
		// that the gateway was ever in a state that bad.
		inc.Timeline = append(inc.Timeline, Entry{
			At:         at,
			Action:     ActionUpdated,
			Detail:     fmt.Sprintf("the contributing conditions are now %s, below the %s this incident opened at", severity, inc.Severity),
			Severity:   inc.Severity,
			Conditions: len(causes),
		})
		changed = true
	}

	if !sameContributions(inc.Causes, causes) {
		inc.Timeline = append(inc.Timeline, Entry{
			At:         at,
			Action:     ActionUpdated,
			Detail:     contributionDetail(inc.Causes, causes),
			Severity:   inc.Severity,
			Conditions: len(causes),
		})
		changed = true
	}

	if !sameContributions(inc.Consequences, consequences) {
		inc.Consequences = consequences
		changed = true
	}

	if changed {
		inc.Causes = causes
		inc.UpdatedAt = at
	}
	return changed
}

// resolve marks an incident as no longer happening.
func (m *Manager) resolve(inc *Incident) {
	at := m.now()

	inc.Status = StatusResolved
	inc.ResolvedAt = at
	inc.UpdatedAt = at
	inc.Duration = at.Sub(inc.OpenedAt)

	inc.Timeline = append(inc.Timeline, Entry{
		At:         at,
		Action:     ActionResolved,
		Detail:     fmt.Sprintf("all %d contributing conditions stopped holding after %s", len(inc.Causes), roundDur(inc.Duration)),
		Severity:   inc.Severity,
		Conditions: 0,
	})
}

// prune drops the oldest resolved incidents beyond the retention limit.
//
// Only resolved ones. An active incident is never pruned regardless of age,
// because forgetting a problem that is still happening is the worst thing this
// package could do.
func (m *Manager) prune() {
	if m.Retain <= 0 {
		return
	}

	var resolved []string
	for _, fp := range m.order {
		if inc, ok := m.byFingerprint[fp]; ok && inc.Status == StatusResolved {
			resolved = append(resolved, fp)
		}
	}

	if len(resolved) <= m.Retain {
		return
	}

	// resolved is already in first-seen order, so the oldest go first.
	for _, fp := range resolved[:len(resolved)-m.Retain] {
		delete(m.byFingerprint, fp)
		m.order = removeString(m.order, fp)
	}
}

// All returns every incident, oldest first.
func (m *Manager) All() []Incident {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]Incident, 0, len(m.order))
	for _, fp := range m.order {
		if inc, ok := m.byFingerprint[fp]; ok {
			out = append(out, *inc)
		}
	}
	return out
}

// Active returns the incidents still happening, oldest first.
func (m *Manager) Active() []Incident {
	var out []Incident
	for _, inc := range m.All() {
		if inc.Active() {
			out = append(out, inc)
		}
	}
	return out
}

// Resolved returns the incidents that have ended, newest first.
//
// Newest first because this is the list someone reads when a user reports a
// problem that has already been fixed; the question is what happened most
// recently.
func (m *Manager) Resolved() []Incident {
	var out []Incident
	for _, inc := range m.All() {
		if !inc.Active() {
			out = append(out, inc)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ResolvedAt.After(out[j].ResolvedAt) })
	return out
}

// Get returns an incident by ID.
func (m *Manager) Get(id string) (Incident, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, fp := range m.order {
		if inc, ok := m.byFingerprint[fp]; ok && inc.ID == id {
			return *inc, true
		}
	}
	return Incident{}, false
}

// Len returns the number of tracked incidents.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byFingerprint)
}

// Counts summarises the incident record.
type Counts struct {
	Active   int `json:"active"`
	Resolved int `json:"resolved"`
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Flapping int `json:"flapping"`
}

// Summarise counts the incidents by state and severity.
func (m *Manager) Summarise() Counts {
	m.mu.Lock()
	defer m.mu.Unlock()

	var c Counts
	for _, inc := range m.byFingerprint {
		if inc.Active() {
			c.Active++
		} else {
			c.Resolved++
		}
		if inc.Severity == rules.SeverityCritical {
			c.Critical++
		}
		if inc.Severity == rules.SeverityWarning {
			c.Warning++
		}
		if inc.Flaps > 0 {
			c.Flapping++
		}
	}
	return c
}

// IDFor derives a stable incident identifier from a fingerprint.
//
// It is the same shape as identity.IDFor, for the same reason: an identifier
// derived from a hash is stable across restarts and across processes, which an
// incrementing number is not.
func IDFor(fingerprint string) string {
	sum := sha256.Sum256([]byte("thn-incident:" + fingerprint))
	return "inc_" + hex.EncodeToString(sum[:8])
}

// causesOf projects a group's reportable members.
func causesOf(g correlation.Group) []Contribution {
	var out []Contribution
	for _, m := range g.Reportable() {
		out = append(out, Contribution{
			Rule:      m.Rule,
			Title:     m.Title,
			Condition: m.Condition,
			Evidence:  m.Evidence,
			Severity:  m.Severity,
		})
	}
	sortContributions(out)
	return out
}

// consequencesOf projects a group's suppressed members.
func consequencesOf(g correlation.Group) []Contribution {
	var out []Contribution
	for _, m := range g.Suppressed() {
		out = append(out, Contribution{
			Rule:             m.Rule,
			Title:            m.Title,
			Condition:        m.Condition,
			Evidence:         m.Evidence,
			Severity:         m.Severity,
			Suppressed:       true,
			SuppressedBy:     m.SuppressedBy,
			SuppressedReason: m.SuppressedReason,
		})
	}
	sortContributions(out)
	return out
}

func sortContributions(in []Contribution) {
	sort.SliceStable(in, func(i, j int) bool { return in[i].Rule < in[j].Rule })
}

// sameContributions reports whether two contribution sets are equivalent.
//
// Compared by rule name rather than by the whole struct, because the evidence
// text is expected to change between observations — the same condition
// observed twice quotes different words — and treating that as a change would
// fill the timeline with updates that say nothing.
func sameContributions(a, b []Contribution) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Rule != b[i].Rule {
			return false
		}
	}
	return true
}

// incidentDetail renders the opening sentence for a group.
func incidentDetail(g correlation.Group) string {
	causes := g.Reportable()
	consequences := g.Suppressed()

	var b strings.Builder
	fmt.Fprintf(&b, "%d condition%s held: %s",
		len(causes), plural(len(causes)), strings.Join(ruleNames(causes), ", "))

	if len(consequences) > 0 {
		fmt.Fprintf(&b, "; %d suppressed as consequences: %s",
			len(consequences), strings.Join(ruleNames(consequences), ", "))
	}
	return b.String()
}

// contributionDetail renders what changed between two contribution sets.
func contributionDetail(before, after []Contribution) string {
	beforeNames := ruleNameSet(before)
	afterNames := ruleNameSet(after)

	var added, removed []string
	for _, c := range after {
		if !beforeNames[c.Rule] {
			added = append(added, c.Rule)
		}
	}
	for _, c := range before {
		if !afterNames[c.Rule] {
			removed = append(removed, c.Rule)
		}
	}

	var parts []string
	if len(added) > 0 {
		parts = append(parts, "began: "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "stopped: "+strings.Join(removed, ", "))
	}
	if len(parts) == 0 {
		return "the contributing conditions changed"
	}
	return strings.Join(parts, "; ")
}

func ruleNames(members []correlation.Member) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.Rule)
	}
	sort.Strings(out)
	return out
}

func ruleNameSet(cs []Contribution) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		out[c.Rule] = true
	}
	return out
}

func removeString(in []string, want string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != want {
			out = append(out, s)
		}
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// roundDur renders a duration at a resolution a person can read.
func roundDur(d time.Duration) time.Duration {
	switch {
	case d >= time.Hour:
		return d.Round(time.Minute)
	case d >= time.Minute:
		return d.Round(time.Second)
	case d >= time.Second:
		return d.Round(100 * time.Millisecond)
	default:
		return d.Round(time.Millisecond)
	}
}
