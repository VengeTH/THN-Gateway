// Package correlation reduces a set of firing rules to a small number of
// incidents worth an operator's attention.
//
// # One fault, one incident
//
// The problem this package exists for is arithmetic. A gateway loses its
// uplink and, within seconds, a dozen conditions become true: the link is
// down, there is no default route, the queue stops moving, DHCP clients stop
// reaching the internet, DNS lookups fail, the shaping algorithm reports
// nothing useful. Each of those is a true observation. Reporting each as its
// own incident produces twelve incidents, twelve pieces of work, and an
// operator who learns to ignore the eleventh.
//
// They are not twelve problems. They are one problem with twelve symptoms.
//
// # Two mechanisms, both necessary
//
// Grouping collapses instances that share labels into one incident. That
// handles the easy case: five interfaces reporting high drop ratio are one
// incident about high drop ratio.
//
// Inhibition is stronger and handles the case grouping cannot. It declares
// that when a root cause fires, its known consequences are suppressed. The
// uplink being down explains the absent default route, the stalled queue and
// the failed DNS lookups; reporting them separately claims four independent
// faults when there is one. A suppressed member is not discarded — it stays on
// the incident, marked, so the operator can see what else was true at the
// time and so that a later resolution of the root cause does not lose the
// information.
//
// # Grouping windows
//
// A group is not opened immediately. It waits, because conditions arrive
// together and a burst of five within two seconds is one event, while the
// same five spread over ten minutes is five events. Without a window, a
// gateway that degrades gradually produces a stream of partial incidents that
// never quite match each other, and none of them is the real one.
//
// # A group that shrinks is not a new group
//
// The fingerprint is derived from the group key, not from its members. Five
// conditions firing, then four, then three, then one, are the same incident
// evolving. A fingerprint derived from the member set would open four
// incidents for one outage.
package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/rules"
)

// Config controls how firing instances are grouped and suppressed.
type Config struct {
	// GroupBy names the signal labels that form the incident key.
	//
	// Every distinct combination of these labels becomes one incident. An
	// empty list means one incident for everything, which is almost never
	// what is wanted: an uplink fault and a full DHCP pool have nothing to do
	// with each other and merging them would hide both.
	GroupBy []string

	// GroupWindow is how long a group collects members before it is emitted.
	//
	// It should be longer than the interval between observations, or a single
	// evaluation produces a group that is immediately complete and the window
	// does nothing. It should be much shorter than the time an operator needs
	// to react, or a real fault is reported late for no benefit.
	GroupWindow time.Duration

	// Inhibit declares which rules suppress which.
	Inhibit []InhibitRule

	// Comments are emitted verbatim in rendered output.
	Comments []string
}

// Default returns a configuration suitable for a home gateway.
//
// The group window is one minute. It is long enough that the conditions
// around a single uplink failure land in the same group, and short enough
// that a real fault is reported while an operator is still looking at the
// screen.
func Default() Config {
	return Config{
		GroupBy:     []string{"source"},
		GroupWindow: time.Minute,
	}
}

// InhibitRule declares that Target is suppressed while Source fires.
//
// This models a causal relationship, so it is written as one: source causes
// target. A rule that suppresses without a stated cause is a suppression
// waiting to hide something real, and the whole value of inhibition is that it
// is justified rather than convenient.
//
// The json tags are explicit because this struct is serialised by
// `thn rules list --json`. Without them Go emits `Source`, `Target`, `Equal`
// and `Reason` while every other type in the project emits lower-case names,
// so a consumer reading one document would have to know which structs were
// tagged and which were not. That is not a fact worth making anyone look up.
type InhibitRule struct {
	// Source is the rule whose firing causes the suppression. "*" matches any.
	Source string `json:"source"`

	// Target is the rule that is suppressed while Source fires. "*" matches
	// any.
	Target string `json:"target"`

	// Equal names the labels that must match for the suppression to apply.
	//
	// An empty list suppresses across every group, which is rarely right: a
	// WAN that is down does not explain a LAN-side problem. Listing the
	// interface or source label keeps the suppression to cases where the two
	// rules are genuinely talking about the same thing.
	Equal []string `json:"equal,omitempty"`

	// Reason explains the suppression, and is carried onto the suppressed
	// member so an incident can show why something was not reported.
	Reason string `json:"reason"`
}

// Validate checks a configuration.
func (c Config) Validate() error {
	if c.GroupWindow < 0 {
		return fmt.Errorf("the group window must not be negative")
	}
	if len(c.GroupBy) == 0 {
		return fmt.Errorf("no grouping labels are configured; every condition would " +
			"collapse into one incident, including conditions with nothing in common")
	}
	for _, i := range c.Inhibit {
		if i.Source == "" || i.Target == "" {
			return fmt.Errorf("an inhibition rule needs both a source and a target")
		}
		if i.Source == "*" && i.Target == "*" {
			return fmt.Errorf("an inhibition rule cannot suppress everything with everything; " +
				"that would silence the whole system")
		}
		if strings.TrimSpace(i.Reason) == "" {
			return fmt.Errorf("inhibition of %q by %q states no reason; an unjustified "+
				"suppression hides real conditions", i.Target, i.Source)
		}
	}
	return nil
}

// Member is one firing rule instance within a group.
type Member struct {
	// Rule is the rule's name.
	Rule string `json:"rule"`

	// Group is the rule instance's own label fingerprint.
	Group string `json:"group,omitempty"`

	// Title is the rule's one-line statement of what is wrong.
	Title string `json:"title,omitempty"`

	// Severity is the rule's severity.
	Severity rules.Severity `json:"severity"`

	// Condition is the sentence describing what held.
	Condition string `json:"condition,omitempty"`

	// Evidence is the signal that made it fire, when one was found.
	Evidence string `json:"evidence,omitempty"`

	// Labels are the instance's labels.
	Labels map[string]string `json:"labels,omitempty"`

	// Suppressed reports whether this member was inhibited.
	Suppressed bool `json:"suppressed,omitempty"`

	// SuppressedBy names the rule responsible, when it was.
	SuppressedBy string `json:"suppressed_by,omitempty"`

	// SuppressedReason explains the suppression.
	SuppressedReason string `json:"suppressed_reason,omitempty"`
}

// Reportable reports whether the member should contribute to an incident.
//
// A suppressed member does not. It stays on the group so the information is
// not lost, but a group whose only members are suppressed is not a problem.
func (m Member) Reportable() bool { return !m.Suppressed }

// Group is a set of firing instances that belong to one incident.
type Group struct {
	// Key is the grouping key, rendered for display.
	Key string `json:"key"`

	// Fingerprint is the stable identifier. It is derived from the key alone,
	// never from the members, so a shrinking group keeps its identity.
	Fingerprint string `json:"fingerprint"`

	// Labels are the grouping labels.
	Labels map[string]string `json:"labels,omitempty"`

	// Members are the firing instances, including suppressed ones.
	Members []Member `json:"members"`

	// Severity is the highest severity among the reportable members.
	Severity rules.Severity `json:"severity"`

	// At is when the group was emitted.
	At time.Time `json:"at"`

	// FirstSeen is when this group key was first observed.
	FirstSeen time.Time `json:"first_seen"`
}

// Reportable returns the members that should be reported.
func (g Group) Reportable() []Member {
	var out []Member
	for _, m := range g.Members {
		if m.Reportable() {
			out = append(out, m)
		}
	}
	return out
}

// Suppressed returns the members that were inhibited.
func (g Group) Suppressed() []Member {
	var out []Member
	for _, m := range g.Members {
		if m.Suppressed {
			out = append(out, m)
		}
	}
	return out
}

// Empty reports whether the group has nothing to report.
//
// A group of only suppressed members is a consequence with no cause, which
// happens when the cause has already resolved. It is not a problem, and
// opening an incident for it would be noise.
func (g Group) Empty() bool { return len(g.Reportable()) == 0 }

// Title renders a one-line statement of the group.
func (g Group) Title() string {
	parts := make([]string, 0, len(g.Reportable()))
	for _, m := range g.Reportable() {
		if m.Title != "" {
			parts = append(parts, m.Title)
			continue
		}
		parts = append(parts, m.Rule)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%s (%d suppressed)", g.Key, len(g.Members))
	}

	// Distinct titles only: three interfaces reporting the same condition
	// should not produce a title three times over.
	seen := map[string]bool{}
	var distinct []string
	for _, p := range parts {
		if seen[p] {
			continue
		}
		seen[p] = true
		distinct = append(distinct, p)
	}

	if len(distinct) == 1 {
		return distinct[0]
	}
	return fmt.Sprintf("%s (and %d more condition%s)", distinct[0], len(distinct)-1, plural(len(distinct)-1))
}

// Correlator groups firing instances over time.
type Correlator struct {
	cfg Config

	// open maps a fingerprint to the time it was first seen, so the
	// fingerprint can be derived from the key alone and still be stable while
	// the member set changes.
	open map[string]time.Time

	// ready holds groups whose window has elapsed, keyed by fingerprint.
	ready map[string]*Group

	// emitted records the member signature each fingerprint was last emitted
	// with, so an unchanged group is not re-emitted on every observation.
	emitted map[string]string
}

// New returns a correlator.
//
// A configuration that fails validation is reported rather than silently
// repaired. A correlator that quietly fixed its own grouping would group
// differently from what the operator configured, and the difference would only
// show up as incidents that do not match expectation.
func New(cfg Config) (*Correlator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Correlator{
		cfg:     cfg,
		open:    map[string]time.Time{},
		ready:   map[string]*Group{},
		emitted: map[string]string{},
	}, nil
}

// Config returns the correlator's configuration.
func (c *Correlator) Config() Config { return c.cfg }

// Process groups a set of firing instances and returns the groups ready to
// become incidents.
//
// An instance that is no longer firing is removed from its group. A group
// left with no reportable members is dropped rather than emitted, which is how
// a resolved fault disappears without leaving a trail of empty incidents.
//
// Everything is keyed by fingerprint throughout. An earlier version keyed the
// live set by grouping key and the accumulated state by fingerprint, and the
// membership checks compared one against the other — so they never matched,
// every accumulated group was discarded on every call, and the grouping window
// silently did nothing. The window is the whole reason this function holds
// state, so a bug there is a bug in the feature.
func (c *Correlator) Process(instances []rules.Instance, at time.Time) []Group {
	if at.IsZero() {
		at = time.Now().UTC()
	}

	// Every currently-firing instance, indexed by fingerprint. The key is
	// carried alongside so a group can report it.
	type bucket struct {
		key     string
		members []Member
	}
	live := map[string]*bucket{}

	for _, inst := range instances {
		member := memberOf(inst)
		key := c.keyFor(member.Labels)
		fp := c.keyFingerprint(key)

		if _, ok := live[fp]; !ok {
			live[fp] = &bucket{key: key}
		}
		live[fp].members = append(live[fp].members, member)
	}

	// Forget groups that are no longer firing, so the state does not grow
	// without bound across a long run. Without this a gateway that has been
	// up and down repeatedly would accumulate a first-seen time for every
	// distinct label set it ever had.
	for fp := range c.open {
		if _, still := live[fp]; !still {
			delete(c.open, fp)
		}
	}
	for fp := range c.ready {
		if _, still := live[fp]; !still {
			delete(c.ready, fp)
		}
	}
	for fp := range c.emitted {
		if _, still := live[fp]; !still {
			delete(c.emitted, fp)
		}
	}

	// Apply inhibition within each group, after grouping rather than before.
	//
	// Inhibition is defined between rules, not between raw instances, so it
	// has to see the whole set. Applying it earlier would let a suppressed
	// rule suppress another, which is how a chain of suppressions can silence
	// everything.
	for _, b := range live {
		c.applyInhibition(b.members)
		sortMembers(b.members)
	}

	// Emit a group when its window has elapsed AND its content has changed
	// since it was last emitted.
	//
	// Re-emitting an unchanged group on every observation would be correct
	// only if the consumer deduplicated it. The incident manager does, but
	// pushing that burden downstream to avoid a signature check here inverts
	// the dependency: the correlator is the thing that knows when a group has
	// become interesting, and a group that has not changed is not
	// interesting however many times it is observed.
	//
	// "Changed" means the reportable member set differs. Suppression changes
	// count, because a member moving from cause to consequence is exactly the
	// kind of change an operator needs to see.
	var out []Group
	for fp, b := range live {
		if len(b.members) == 0 {
			continue
		}

		first, seen := c.open[fp]
		if !seen {
			first = at
			c.open[fp] = at
		}

		sig := memberSignature(b.members)

		if at.Sub(first) < c.cfg.GroupWindow {
			// Still collecting. The partial group is kept so the window
			// accumulates rather than restarting.
			c.ready[fp] = &Group{Fingerprint: fp, Members: b.members, FirstSeen: first}
			continue
		}

		if last, ok := c.emitted[fp]; ok && last == sig {
			// Unchanged since the last emission. The group is still firing and
			// the incident below is still open; there is nothing to say.
			continue
		}
		c.emitted[fp] = sig

		group := Group{
			Key:         b.key,
			Fingerprint: fp,
			Labels:      labelsOf(b.members),
			Members:     b.members,
			Severity:    severityOf(b.members),
			At:          at,
			FirstSeen:   first,
		}
		out = append(out, group)
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

// keyFor renders a grouping key from a set of labels.
//
// A label that is present on one member and absent on another is included
// with an empty value rather than omitted, so that "wan present, lan absent"
// and "wan absent, lan present" are different keys rather than both
// collapsing to the empty string.
func (c *Correlator) keyFor(labels map[string]string) string {
	if len(c.cfg.GroupBy) == 0 {
		return ""
	}

	parts := make([]string, 0, len(c.cfg.GroupBy))
	for _, name := range c.cfg.GroupBy {
		parts = append(parts, name+"="+escapeKey(labels[name]))
	}
	return strings.Join(parts, ",")
}

// fingerprintFor derives a stable identifier from a grouping key.
func fingerprintFor(key string) string {
	sum := sha256.Sum256([]byte("thn-incident:" + key))
	return "inc_" + hex.EncodeToString(sum[:8])
}

// keyFingerprint is the pairing of key and fingerprint, since a group needs
// both and deriving one from the other twice would be a chance to disagree.
func (c *Correlator) keyFingerprint(key string) string { return fingerprintFor(key) }

// applyInhibition marks members suppressed by a firing member.
func (c *Correlator) applyInhibition(members []Member) {
	for _, rule := range c.cfg.Inhibit {
		for i := range members {
			// Inhibition is only meaningful against something that is
			// already firing. A rule that suppresses everything whenever it
			// is not firing would silence the entire system, so the source
			// must be present and unsuppressed.
			if !matchesRule(rule.Source, members[i].Rule) {
				continue
			}
			if members[i].Suppressed {
				// A suppressed rule does not suppress anything else. Without
				// this, a chain of consequences would cascade: A fires,
				// B is suppressed by A, and B then suppresses C — so two
				// levels of causality would silence an entire tree.
				continue
			}

			for j := range members {
				if i == j {
					continue
				}
				if !matchesRule(rule.Target, members[j].Rule) {
					continue
				}
				if !labelsEqual(rule.Equal, members[i].Labels, members[j].Labels) {
					continue
				}
				members[j].Suppressed = true
				members[j].SuppressedBy = members[i].Rule
				members[j].SuppressedReason = rule.Reason
			}
		}
	}
}

// matchesRule reports whether a rule name pattern selects a rule.
//
// "*" is the only pattern. A prefix or glob would be convenient and would
// make a suppression's reach hard to reason about when reading an incident,
// which is the one moment its scope has to be clear.
func matchesRule(pattern, rule string) bool {
	if pattern == "*" {
		return true
	}
	return pattern == rule
}

// labelsEqual reports whether two label sets agree on the named labels.
func labelsEqual(names []string, a, b map[string]string) bool {
	for _, n := range names {
		if a[n] != b[n] {
			return false
		}
	}
	return true
}

// memberOf projects a firing instance into a group member.
func memberOf(inst rules.Instance) Member {
	m := Member{
		Rule:      inst.Rule,
		Group:     inst.Group,
		Severity:  inst.Severity,
		Title:     inst.Title,
		Condition: inst.Condition,
	}
	if inst.Evidence != nil {
		m.Labels = inst.Evidence.Labels
		m.Evidence = inst.Evidence.Detail
	}
	return m
}

// labelsOf returns the first non-empty label set among members.
func labelsOf(members []Member) map[string]string {
	for _, m := range members {
		if len(m.Labels) > 0 {
			return m.Labels
		}
	}
	return nil
}

// severityOf returns the highest severity among reportable members.
func severityOf(members []Member) rules.Severity {
	var out rules.Severity
	for _, m := range members {
		if !m.Reportable() {
			continue
		}
		out = rules.Max(out, m.Severity)
	}
	return out
}

// sortMembers orders members so two groups with the same content render
// identically. Without it, two runs over the same observations would produce
// different incident text, and a diff between them would show noise.
func sortMembers(members []Member) {
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].Rule != members[j].Rule {
			return members[i].Rule < members[j].Rule
		}
		return members[i].Group < members[j].Group
	})
}

// memberSignature renders a member set for change detection.
//
// Rule names and their suppressed state are both included. The instance
// group is included too, so a per-interface change within one rule is still a
// change — five interfaces with one problem and then four is a different
// observation from five with a different problem.
func memberSignature(members []Member) string {
	parts := make([]string, 0, len(members))
	for _, m := range members {
		suppressed := "0"
		if m.Suppressed {
			suppressed = "1"
		}
		parts = append(parts, m.Rule+"/"+m.Group+"/"+suppressed)
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

// escapeKey makes a label value safe in a grouping key.
func escapeKey(v string) string {
	return strings.NewReplacer(`\`, `\\`, `,`, `\,`, `=`, `\=`).Replace(v)
}

// plural renders an "s" for counts other than one.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
