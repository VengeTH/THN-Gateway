package incidents_test

import (
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/correlation"
	"github.com/venth/thn-gateway/internal/incidents"
	"github.com/venth/thn-gateway/internal/rules"
)

var base = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

// clock is a manually advanced clock.
type clock struct{ now time.Time }

func newClock() *clock { return &clock{now: base} }

func (c *clock) advance(d time.Duration) time.Time {
	c.now = c.now.Add(d)
	return c.now
}

func (c *clock) Now() time.Time { return c.now }

// member builds a reportable group member.
func member(rule string, sev rules.Severity) correlation.Member {
	return correlation.Member{Rule: rule, Severity: sev, Title: rule + " happened"}
}

// suppressedMember builds a suppressed group member.
func suppressedMember(rule, by string) correlation.Member {
	return correlation.Member{
		Rule: rule, Severity: rules.SeverityCritical, Title: rule + " happened",
		Suppressed: true, SuppressedBy: by, SuppressedReason: "a consequence of " + by,
	}
}

// group builds a group with a stable fingerprint.
//
// The name is part of the grouping key, so two groups built with different
// names are two incidents. An earlier version ignored it and produced the same
// fingerprint for every group, which made one test fail for the right reason
// and three pass for the wrong one.
func group(name string, members ...correlation.Member) correlation.Group {
	key := "source=" + name
	return correlation.Group{
		Key:         key,
		Fingerprint: "inc_test_" + key,
		Labels:      map[string]string{"source": name},
		Members:     members,
		Severity:    worstSeverity(members),
		At:          base,
		FirstSeen:   base,
	}
}

// worstSeverity returns the highest severity among reportable members.
func worstSeverity(members []correlation.Member) rules.Severity {
	var out rules.Severity
	for _, m := range members {
		if !m.Reportable() {
			continue
		}
		out = rules.Max(out, m.Severity)
	}
	return out
}

// letter returns a distinct name for the nth test fixture.
func letter(n int) string { return string(rune('a' + n)) }

// TestAGroupOpensAnIncident is the basic path.
func TestAGroupOpensAnIncident(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	changed := m.Apply([]correlation.Group{group("a", member("wan-down", rules.SeverityCritical))})

	if len(changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(changed))
	}
	inc := changed[0]
	if inc.Status != incidents.StatusActive {
		t.Errorf("status = %q, want active", inc.Status)
	}
	if inc.Severity != rules.SeverityCritical {
		t.Errorf("severity = %q, want critical", inc.Severity)
	}
	if len(inc.Causes) != 1 {
		t.Errorf("causes = %d, want 1", len(inc.Causes))
	}
	if len(inc.Timeline) != 1 || inc.Timeline[0].Action != incidents.ActionOpened {
		t.Errorf("timeline = %+v; an incident opens with exactly one entry", inc.Timeline)
	}
	if m.Len() != 1 {
		t.Errorf("tracked = %d, want 1", m.Len())
	}
}

// TestAnUnchangedGroupIsNotAChange: a caller that re-receives the same
// conditions must not be handed a change every observation, or it will
// re-notify and the alerting system will flood.
func TestAnUnchangedGroupIsNotAChange(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	g := group("a", member("wan-down", rules.SeverityCritical))
	m.Apply([]correlation.Group{g})

	for i := 0; i < 20; i++ {
		c.advance(time.Minute)
		g.At = c.now
		if changed := m.Apply([]correlation.Group{g}); len(changed) != 0 {
			t.Fatalf("observation %d reported a change for an unchanged group: %+v", i, changed)
		}
	}
}

// TestAMemberAppearingIsRecorded: a group that grows is a change, and the
// timeline has to say what arrived.
func TestAMemberAppearingIsRecorded(t *testing.T) {
	c := newClock()
	mgr := incidents.NewManager(c.Now)

	mgr.Apply([]correlation.Group{group("a", member("a", rules.SeverityWarning))})

	c.advance(time.Minute)
	g := group("a", member("a", rules.SeverityWarning), member("b", rules.SeverityWarning))
	g.At = c.now

	changed := mgr.Apply([]correlation.Group{g})
	if len(changed) != 1 {
		t.Fatalf("changed = %d, want 1; a growing group is a change", len(changed))
	}

	var found bool
	for _, e := range changed[0].Timeline {
		if e.Action == incidents.ActionUpdated {
			found = true
			if !contains(e.Detail, "b") {
				t.Errorf("the update does not name what arrived: %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("no update entry was recorded for the new member")
	}
}

// TestAMemberLeavingIsRecorded: a group that shrinks is also a change, and it
// is the one that precedes recovery.
func TestAMemberLeavingIsRecorded(t *testing.T) {
	c := newClock()
	mgr := incidents.NewManager(c.Now)

	mgr.Apply([]correlation.Group{group("a",
		member("a", rules.SeverityWarning), member("b", rules.SeverityWarning))})

	c.advance(time.Minute)
	g := group("a", member("a", rules.SeverityWarning))
	g.At = c.now

	changed := mgr.Apply([]correlation.Group{g})
	if len(changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(changed))
	}

	var found bool
	for _, e := range changed[0].Timeline {
		if e.Action == incidents.ActionUpdated && contains(e.Detail, "stopped") {
			found = true
		}
	}
	if !found {
		t.Errorf("no update recorded the departure: %+v", changed[0].Timeline)
	}
}

// TestAnIncidentResolvesWhenItsGroupStops is the property that makes the
// record trustworthy. An incident that never ends is an incident nobody
// believes.
func TestAnIncidentResolvesWhenItsGroupStops(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	m.Apply([]correlation.Group{group("a", member("wan-down", rules.SeverityCritical))})

	c.advance(5 * time.Minute)
	changed := m.Apply(nil)

	if len(changed) != 1 {
		t.Fatalf("changed = %d, want 1; the incident should have resolved", len(changed))
	}
	inc := changed[0]
	if inc.Status != incidents.StatusResolved {
		t.Errorf("status = %q, want resolved", inc.Status)
	}
	if inc.ResolvedAt.IsZero() {
		t.Error("a resolved incident has no resolution time")
	}
	if inc.Duration != 5*time.Minute {
		t.Errorf("duration = %s, want 5m", inc.Duration)
	}
	if len(m.Active()) != 0 {
		t.Error("a resolved incident is still listed as active")
	}
}

// TestAReopenIsCountedNotForgotten is the flap property.
//
// "The uplink flapped forty times" and "the uplink was down once" are
// different problems with different fixes, and a record that treats them the
// same has thrown away the diagnosis.
func TestAReopenIsCountedNotForgotten(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	g := group("a", member("wan-down", rules.SeverityCritical))

	m.Apply([]correlation.Group{g}) // opens
	openedAt := m.All()[0].OpenedAt

	for i := 0; i < 5; i++ {
		c.advance(time.Minute)
		m.Apply(nil) // resolves

		c.advance(time.Minute)
		g.At = c.now
		m.Apply([]correlation.Group{g}) // reopens
	}

	all := m.All()
	if len(all) != 1 {
		t.Fatalf("incidents = %d, want 1; a flapping problem is one incident", len(all))
	}
	inc := all[0]

	if inc.Flaps != 5 {
		t.Errorf("flaps = %d, want 5", inc.Flaps)
	}
	if !inc.OpenedAt.Equal(openedAt) {
		t.Errorf("opened at %s, want the original %s; a reopen must not reset "+
			"the record of when this started", inc.OpenedAt, openedAt)
	}
	if !inc.Active() {
		t.Error("the incident is not active after its last reopen")
	}

	var reopens int
	for _, e := range inc.Timeline {
		if e.Action == incidents.ActionReopened {
			reopens++
		}
	}
	if reopens != 5 {
		t.Errorf("reopen entries = %d, want 5", reopens)
	}
}

// TestSeverityRisesAndIsRecorded: an incident that quietly became critical is
// a different event from the one that opened as a warning.
func TestSeverityRisesAndIsRecorded(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	m.Apply([]correlation.Group{group("a", member("a", rules.SeverityWarning))})

	c.advance(time.Minute)
	g := group("a", member("a", rules.SeverityWarning), member("b", rules.SeverityCritical))
	g.At = c.now

	changed := m.Apply([]correlation.Group{g})
	if len(changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(changed))
	}

	inc := changed[0]
	if inc.Severity != rules.SeverityCritical {
		t.Errorf("severity = %q, want critical; the worst contributor wins", inc.Severity)
	}

	var escalations int
	for _, e := range inc.Timeline {
		if e.Action == incidents.ActionEscalated {
			escalations++
		}
	}
	if escalations != 1 {
		t.Errorf("escalation entries = %d, want 1: %+v", escalations, inc.Timeline)
	}
}

// TestSeverityDoesNotFallBack is deliberate and worth defending.
//
// An incident that opened critical stays critical in the record. Lowering it
// when the worst contributor clears would hide the fact that the gateway was
// ever in a state that bad, and a history that has been quietly edited is not
// a history.
func TestSeverityDoesNotFallBack(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	m.Apply([]correlation.Group{group("a",
		member("a", rules.SeverityCritical), member("b", rules.SeverityCritical))})

	c.advance(time.Minute)
	g := group("a", member("a", rules.SeverityWarning))
	g.At = c.now

	changed := m.Apply([]correlation.Group{g})
	inc := changed[0]

	if inc.Severity != rules.SeverityCritical {
		t.Errorf("severity = %q, want critical; the record of what happened must "+
			"not be rewritten when the worst contributor clears", inc.Severity)
	}
	if len(inc.Causes) != 1 {
		t.Errorf("causes = %d, want 1; the contributing set did change", len(inc.Causes))
	}
}

// TestSuppressedMembersAreKeptAsConsequences: the information is still true,
// and dropping it would mean resolving the cause loses what else was true.
func TestSuppressedMembersAreKeptAsConsequences(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	g := group("a",
		member("wan-down", rules.SeverityCritical),
		suppressedMember("no-default-route", "wan-down"),
	)
	g.At = c.now

	changed := m.Apply([]correlation.Group{g})
	inc := changed[0]

	if len(inc.Causes) != 1 {
		t.Errorf("causes = %d, want 1", len(inc.Causes))
	}
	if len(inc.Consequences) != 1 {
		t.Fatalf("consequences = %d, want 1; a suppressed member must be kept "+
			"and marked rather than discarded", len(inc.Consequences))
	}
	if !inc.Consequences[0].Suppressed {
		t.Error("the consequence is not marked as suppressed")
	}
	if inc.Consequences[0].SuppressedBy != "wan-down" {
		t.Errorf("suppressed by %q, want wan-down", inc.Consequences[0].SuppressedBy)
	}
	if !contains(inc.Timeline[0].Detail, "suppressed") {
		t.Errorf("the opening entry does not mention the suppression: %q", inc.Timeline[0].Detail)
	}
}

// TestAGroupOfOnlyConsequencesIsNotAnIncident: reporting the absence of a
// cause as a cause.
func TestAGroupOfOnlyConsequencesIsNotAnIncident(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	g := group("a", suppressedMember("b", "a"))

	if changed := m.Apply([]correlation.Group{g}); len(changed) != 0 {
		t.Errorf("a group with nothing reportable opened an incident: %+v", changed)
	}
	if m.Len() != 0 {
		t.Errorf("tracked = %d, want 0", m.Len())
	}
}

// TestRetentionKeepsResolvedAndDropsOldest: this is an in-memory record on a
// device with a small disk, so it has to be bounded — but resolved incidents
// are the record, and the oldest go first.
func TestRetentionKeepsResolvedAndDropsOldest(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)
	m.Retain = 2

	for i := 0; i < 3; i++ {
		c.advance(time.Minute)
		g := group(letter(i), member("rule-"+letter(i), rules.SeverityWarning))
		g.At = c.now
		m.Apply([]correlation.Group{g})

		c.advance(time.Minute)
		m.Apply(nil)
	}

	all := m.All()
	if len(all) != 2 {
		t.Fatalf("retained = %d, want 2", len(all))
	}
	for _, inc := range all {
		if inc.Causes[0].Rule == "rule-a" {
			t.Error("the oldest resolved incident was retained; retention drops " +
				"oldest first")
		}
	}
}

// TestRetentionNeverDropsAnActiveIncident: forgetting a problem that is still
// happening is the worst thing this package could do.
func TestRetentionNeverDropsAnActiveIncident(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)
	m.Retain = 1

	// Three active incidents in one call. Apply takes the complete picture, so
	// passing them one at a time would mean each call says the other two have
	// stopped — which is exactly the behaviour, and exactly what a caller must
	// not do.
	var groups []correlation.Group
	for i := 0; i < 3; i++ {
		g := group(letter(i), member("r"+letter(i), rules.SeverityWarning))
		g.At = c.now
		groups = append(groups, g)
	}
	m.Apply(groups)

	if len(m.Active()) != 3 {
		t.Errorf("active = %d, want 3; retention must not prune what is still "+
			"happening, however many there are", len(m.Active()))
	}

	// Even after a later call that still contains all three.
	c.advance(time.Minute)
	for i := range groups {
		groups[i].At = c.now
	}
	m.Apply(groups)

	if len(m.Active()) != 3 {
		t.Errorf("active = %d after a second observation, want 3", len(m.Active()))
	}
}

// TestIncidentsAreLookedUpByID: an operator following up on an incident
// reported yesterday needs to find it by the identifier they were given.
func TestIncidentsAreLookedUpByID(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	changed := m.Apply([]correlation.Group{group("a", member("a", rules.SeverityWarning))})
	id := changed[0].ID

	got, ok := m.Get(id)
	if !ok {
		t.Fatalf("incident %s not found", id)
	}
	if got.ID != id {
		t.Errorf("got %s, want %s", got.ID, id)
	}

	if _, ok := m.Get("inc_nonexistent"); ok {
		t.Error("a nonexistent ID was found")
	}
}

// TestSummaryCountsEverything: the headline numbers an operator reads first.
func TestSummaryCountsEverything(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	m.Apply([]correlation.Group{
		group("a", member("a", rules.SeverityCritical)),
		group("b", member("b", rules.SeverityWarning)),
	})

	// Resolve the warning one; the critical one stays open.
	c.advance(time.Minute)
	m.Apply([]correlation.Group{group("a", member("a", rules.SeverityCritical))})

	counts := m.Summarise()
	if counts.Active != 1 {
		t.Errorf("active = %d, want 1", counts.Active)
	}
	if counts.Resolved != 1 {
		t.Errorf("resolved = %d, want 1", counts.Resolved)
	}
	if counts.Critical != 1 {
		t.Errorf("critical = %d, want 1", counts.Critical)
	}
	if counts.Warning != 1 {
		t.Errorf("warning = %d, want 1", counts.Warning)
	}
}

// TestIDForIsStable: an identifier derived from a hash survives a restart,
// which an incrementing number would not.
func TestIDForIsStable(t *testing.T) {
	first := incidents.IDFor("inc_abc123")

	if first != incidents.IDFor("inc_abc123") {
		t.Error("IDFor is not stable for the same fingerprint")
	}
	if first == incidents.IDFor("inc_abc124") {
		t.Error("two different fingerprints produced the same ID")
	}
	if !hasPrefix(first, "inc_") {
		t.Errorf("ID = %q, want an inc_ prefix so it is recognisable in a log", first)
	}
}

// TestResolvedAreNewestFirst: this is the list someone reads when a user
// reports a problem that has already been fixed, so the most recent is the
// most useful.
func TestResolvedAreNewestFirst(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	for i := 0; i < 3; i++ {
		c.advance(time.Minute)
		g := group(letter(i), member("r"+letter(i), rules.SeverityWarning))
		g.At = c.now
		m.Apply([]correlation.Group{g})
		c.advance(time.Minute)
		m.Apply(nil)
	}

	resolved := m.Resolved()
	if len(resolved) != 3 {
		t.Fatalf("resolved = %d, want 3", len(resolved))
	}
	for i := 1; i < len(resolved); i++ {
		if resolved[i].ResolvedAt.After(resolved[i-1].ResolvedAt) {
			t.Errorf("resolved incidents are not newest first: %s then %s",
				resolved[i-1].ResolvedAt, resolved[i].ResolvedAt)
		}
	}
}

// TestManagerIsSafeForConcurrentUse: observation runs on a timer while an
// operator reads the list.
func TestManagerIsSafeForConcurrentUse(t *testing.T) {
	c := newClock()
	m := incidents.NewManager(c.Now)

	g := group("a", member("a", rules.SeverityWarning))
	g.At = base
	m.Apply([]correlation.Group{g})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			m.All()
			m.Active()
			m.Summarise()
			m.Len()
		}
	}()

	for i := 0; i < 200; i++ {
		c.advance(time.Minute)
		g.At = c.now
		m.Apply([]correlation.Group{g})
	}

	<-done
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}
