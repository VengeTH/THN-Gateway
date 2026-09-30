package assistant

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/venth/thn-gateway/internal/correlation"
	"github.com/venth/thn-gateway/internal/incidents"
	"github.com/venth/thn-gateway/internal/rules"
	"github.com/venth/thn-gateway/internal/signals"
)

// Coherence is a finding that the configuration contradicts itself.
//
// It is declared here rather than imported from the validation package so that
// this package's dependency list stays short and its inputs stay obvious. The
// caller adapts; the shape is four strings and nothing else.
type Coherence struct {
	// ID is the finding's identifier, used for citation.
	ID string
	// Rule is the bracket label, e.g. "nat+interfaces".
	Rule string
	// Severity is error, warning or info.
	Severity string
	// Message states the contradiction.
	Message string
	// Hint says what would resolve it.
	Hint string
}

// Input is everything the assistant is allowed to know.
//
// It is a struct rather than a set of arguments because the alternative is
// passing the whole evaluation environment and trusting every future caller to
// remember that only some of it may be read. Here the surface is the
// permission: if it is not in Input, no sentence can be built from it.
type Input struct {
	// At is the moment the observations were taken.
	At time.Time

	// Instances are every rule instance the evaluator produced, in any state.
	Instances []rules.Instance

	// Definitions are the rules themselves, for title, threshold and remedy.
	Definitions map[string]rules.Rule

	// Observations are the signals that were read, and their known/unknown
	// state. An absent observation is not the same as a false one, and the
	// difference is what most of the limitation facts are about.
	Observations []signals.Signal

	// Groups are the correlated groups, which is where one incident and many
	// symptoms are distinguished from many incidents.
	Groups []correlation.Group

	// Incidents are the recorded ones. Empty in a build with no daemon, which
	// is itself worth saying out loud rather than leaving as an empty list.
	Incidents []incidents.Incident

	// Coherence are the configuration's self-contradictions.
	Coherence []Coherence

	// Degradable describes the parts of the system that were not inspectable,
	// so a limitation can be stated rather than inferred from an absence.
	Degradable []string
}

// Build turns the pipeline's output into a bundle of facts.
//
// This is the only place facts are created. Every sentence that can ever reach
// an operator or a model is constructed here, from values the deterministic
// system produced, and nowhere else.
func Build(in Input) Bundle {
	var facts []Fact

	// The evaluator returns firing, pending and undecidable as three lists, and
	// an instance can appear in more than one of them - a rule that is pending
	// and whose last evaluation was unknown appears in both. Concatenating the
	// lists without deduplicating produced "firewall-empty, firewall-empty" in
	// a sentence listing the rules that could not be read, which reads as two
	// rules rather than one.
	instances := dedupeInstances(in.Instances)

	facts = append(facts, ruleFacts(in, instances)...)
	facts = append(facts, undecidableFacts(in, instances)...)
	facts = append(facts, evidenceFacts(in)...)
	facts = append(facts, incidentFacts(in)...)
	facts = append(facts, suppressionFacts(in)...)
	facts = append(facts, coherenceFacts(in)...)
	facts = append(facts, limitationFacts(in)...)

	return NewBundle(in.At, facts)
}

// dedupeInstances keeps the first instance for each rule and state.
//
// Keyed on rule and state rather than on the whole instance, because two
// records of the same rule in the same state are the same observation reported
// twice, while the same rule in two different states is genuinely two things.
func dedupeInstances(in []rules.Instance) []rules.Instance {
	seen := make(map[string]bool, len(in))
	out := make([]rules.Instance, 0, len(in))
	for _, inst := range in {
		key := inst.Rule + "\x00" + string(inst.State)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, inst)
	}
	return out
}

// definition looks a rule up. A missing definition means the rule set changed
// under a recorded observation, and the sentence should still be true without
// it, so callers fall back to the instance rather than failing.
func definition(in Input, name string) rules.Rule {
	return in.Definitions[name]
}

// instanceData is the structured detail attached to a rule fact.
//
// `at` is passed in rather than read from the clock. A bundle that embedded
// time.Now() would have a different digest on every run over identical
// observations, and a digest that changes when nothing has changed is worse
// than no digest: it looks like a working integrity check and is not one.
func instanceData(inst rules.Instance, def rules.Rule, at time.Time, known bool) map[string]string {
	held := at.Sub(inst.Since).Round(time.Second)
	if held < 0 {
		held = 0
	}
	d := map[string]string{
		"rule":  inst.Rule,
		"state": string(inst.State),
		"since": inst.Since.UTC().Format(time.RFC3339),
		"truth": inst.LastTruth.String(),
		"held":  held.String(),
		"known": fmt.Sprintf("%t", known),
	}
	if def.Title != "" {
		d["title"] = trustedValue(def.Title)
	}
	if def.For > 0 {
		d["threshold"] = def.For.String()
	}
	return d
}

// ruleFacts covers firing and pending instances.
func ruleFacts(in Input, instances []rules.Instance) []Fact {
	var out []Fact

	// Sorted so statement order does not depend on evaluation order.
	insts := append([]rules.Instance(nil), instances...)
	sort.SliceStable(insts, func(i, j int) bool {
		if insts[i].State != insts[j].State {
			return instStateRank(insts[i].State) < instStateRank(insts[j].State)
		}
		if insts[i].Severity != insts[j].Severity {
			return severityRank(severityFrom(insts[i].Severity)) <
				severityRank(severityFrom(insts[j].Severity))
		}
		return insts[i].Rule < insts[j].Rule
	})

	for _, inst := range insts {
		if inst.State == rules.StateInactive {
			// An inactive rule is the absence of news. Listing every rule that
			// did not fire would bury the ones that did, and the reader can get
			// the full catalogue from `thn rules list`.
			continue
		}

		def := definition(in, inst.Rule)
		known := inst.LastTruth.String() != "unknown"

		kind := FactPending
		var statement string
		switch inst.State {
		case rules.StateFiring:
			kind = FactFiring
			statement = firingStatement(inst, def, in.At)
		default:
			statement = pendingStatement(inst, def, in.At)
		}

		f := Fact{
			Kind:      kind,
			Severity:  severityFrom(inst.Severity),
			Subject:   inst.Rule,
			Statement: statement,
			Data:      instanceData(inst, def, in.At, known),
		}
		if def.Remedy != "" {
			f.Remedy = trustedValue(def.Remedy)
		}
		out = append(out, f)
	}
	return out
}

// instStateRank orders instance states for sorting, most urgent first.
func instStateRank(s rules.State) int {
	switch s {
	case rules.StateFiring:
		return 0
	case rules.StatePending:
		return 1
	default:
		return 2
	}
}

// firingStatement says what is wrong and how long it has been true.
func firingStatement(inst rules.Instance, def rules.Rule, now time.Time) string {
	title := ruleTitle(inst, def)
	held := now.Sub(inst.Since).Round(time.Second)
	if held <= 0 {
		return fmt.Sprintf("%s: %s.", title, sentence(def.Title, inst.Condition))
	}
	return fmt.Sprintf("%s: %s, true for %s.", title, sentence(def.Title, inst.Condition), held)
}

// pendingStatement says the condition holds but the clock has not run out.
//
// The distinction from firing is the whole reason this package exists: an
// operator seeing "pending" who is not told how much longer must wait will
// either act too early or assume the problem is not real.
func pendingStatement(inst rules.Instance, def rules.Rule, now time.Time) string {
	title := ruleTitle(inst, def)
	held := now.Sub(inst.Since).Round(time.Second)
	if held < 0 {
		held = 0
	}

	if def.For <= 0 {
		return fmt.Sprintf("%s: the condition holds and has no time threshold.", title)
	}

	remaining := (def.For - held).Round(time.Second)
	if remaining < 0 {
		remaining = 0
	}

	return fmt.Sprintf(
		"%s: the condition has held for %s of the %s it needs, so it will be reported in %s unless it clears first.",
		title, held, def.For, remaining)
}

// ruleTitle prefers the rule set's own sentence and falls back to the rule
// name, which is a label rather than a statement but is better than nothing.
func ruleTitle(inst rules.Instance, def rules.Rule) string {
	if def.Title != "" {
		return trustedValue(def.Title)
	}
	return inst.Rule
}

// undecidableFacts covers instances whose input could not be read.
//
// These are separated from the rule facts and given their own kind because they
// answer a different question. "Nothing is wrong" and "THN could not tell" are
// not the same claim, and an assistant that merges them is worse than one that
// says nothing.
//
// Undecidability is not a fourth State - the engine has three - so it is
// detected where it is actually recorded: in the instance's last truth. An
// instance whose most recent evaluation was unknown is an instance the engine
// declined to conclude about, whichever state it was left in.
func undecidableFacts(in Input, instances []rules.Instance) []Fact {
	var out []Fact

	// Grouped by the signal that could not be read, because that is the
	// actionable unit: one unread interface explains every rule that depends on
	// it, and telling an operator about fifteen rules separately is fifteen
	// times the work and none of the insight.
	missing := make(map[string][]rules.Instance)
	const unnamed = "an input these rules depend on"

	// An instance can name several unread signals, and more than one of them
	// can fail to yield a name - in which case every one of them lands on the
	// same fallback key and the rule is appended once per condition. That is
	// how "firewall-empty, firewall-empty" got into a sentence about how many
	// rules could not be read.
	added := make(map[string]bool)

	add := func(key string, inst rules.Instance) {
		k := key + "\x00" + inst.Rule
		if added[k] {
			return
		}
		added[k] = true
		missing[key] = append(missing[key], inst)
	}

	for _, inst := range instances {
		if inst.LastTruth != rules.TruthUnknown {
			continue
		}
		if len(inst.Conditions) == 0 {
			add(unnamed, inst)
			continue
		}
		for _, reason := range inst.Conditions {
			key := unreadSignal(reason)
			if key == "" {
				key = unnamed
			}
			add(key, inst)
		}
	}

	keys := make([]string, 0, len(missing))
	for k := range missing {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, signal := range keys {
		insts := missing[signal]
		sort.SliceStable(insts, func(i, j int) bool { return insts[i].Rule < insts[j].Rule })

		names := make([]string, 0, len(insts))
		severity := SeverityInfo
		for _, inst := range insts {
			names = append(names, inst.Rule)
			if s := severityFrom(inst.Severity); severityRank(s) < severityRank(severity) {
				severity = s
			}
		}

		// Listing every affected rule is not the point. The point is that one
		// unread signal explains all of them, so the list is capped and the
		// remainder counted.
		listedNames := names
		extra := 0
		const maxNames = 8
		if len(names) > maxNames {
			listedNames = names[:maxNames]
			extra = len(names) - maxNames
		}

		enumeration := strings.Join(listedNames, ", ")
		if extra > 0 {
			enumeration += fmt.Sprintf(" and %d more", extra)
		}

		out = append(out, Fact{
			Kind:     FactUndecidable,
			Severity: severity,
			Subject:  signal,
			Statement: fmt.Sprintf(
				"%d rule(s) could not be evaluated because %s could not be read: %s. They have neither fired nor cleared.",
				len(insts), signal, enumeration),
			Data: map[string]string{
				"signal": signal,
				"rules":  strings.Join(names, ","),
				"count":  fmt.Sprintf("%d", len(insts)),
			},
		})
	}
	return out
}

// unreadSignal pulls a signal name out of an undecidability reason.
//
// The reasons are written by the rule engine, for humans, in prose. Rather
// than restructure that prose into a machine format - which would mean changing
// every condition's Describe for the benefit of an assistant - the name is
// recovered from the quoted form the engine already uses, and the result is
// treated as a hint rather than a certainty: if it cannot be found the fact is
// still emitted, just without a named signal.
func unreadSignal(reason string) string {
	const quote = `"`
	i := strings.Index(reason, quote)
	if i < 0 {
		return ""
	}
	rest := reason[i+1:]
	j := strings.Index(rest, quote)
	if j <= 0 {
		return ""
	}
	candidate := rest[:j]
	clean, _ := UntrustedValue(candidate)
	if clean == "" {
		return ""
	}
	// A signal name has no spaces. Anything else is prose that happened to
	// contain a quotation mark, and guessing at it would be worse than
	// reporting nothing.
	if strings.ContainsAny(clean, " \t") {
		return ""
	}
	return clean
}

// evidenceFacts record the signals that could not be read.
func evidenceFacts(in Input) []Fact {
	var out []Fact

	obs := append([]signals.Signal(nil), in.Observations...)
	sort.SliceStable(obs, func(i, j int) bool { return obs[i].Name < obs[j].Name })

	for _, s := range obs {
		if s.Value.Known {
			// A known value is not news. It is an input, and every conclusion
			// drawn from it is already reported against the rule that drew it.
			continue
		}
		out = append(out, Fact{
			Kind:     FactEvidence,
			Severity: SeverityNone,
			Subject:  trustedValue(s.Name),
			Statement: fmt.Sprintf(
				"%s could not be read (source: %s). Any conclusion that depends on it is undetermined rather than negative.",
				trustedValue(s.Name), trustedValue(s.Source)),
			Data: map[string]string{
				"signal": trustedValue(s.Name),
				"source": trustedValue(s.Source),
				"known":  "false",
				"kind":   string(s.Value.Kind),
				"at":     s.At.UTC().Format(time.RFC3339),
			},
		})
	}
	return out
}

// incidentFacts summarise correlated groups.
func incidentFacts(in Input) []Fact {
	var out []Fact

	groups := append([]correlation.Group(nil), in.Groups...)
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].Fingerprint < groups[j].Fingerprint
	})

	for _, g := range groups {
		if g.Empty() {
			continue
		}
		members := g.Reportable()
		names := make([]string, 0, len(members))
		for _, m := range members {
			names = append(names, m.Rule)
		}
		sort.Strings(names)

		out = append(out, Fact{
			Kind:     FactIncident,
			Severity: severityFrom(g.Severity),
			Subject:  g.Fingerprint,
			Statement: fmt.Sprintf(
				"%d condition(s) share the grouping key %s and are reported as one incident rather than %d: %s.",
				len(members), quoteValue(g.Key), len(members), strings.Join(names, ", ")),
			Data: map[string]string{
				"fingerprint": g.Fingerprint,
				"key":         trustedValue(g.Key),
				"members":     strings.Join(names, ","),
				"first_seen":  g.FirstSeen.UTC().Format(time.RFC3339),
			},
		})
	}
	return out
}

// suppressionFacts record what was inhibited and why.
//
// Suppression is invisible by design - that is what makes it useful - so it is
// made explicit here. An operator asking "why did I not hear about the uplink"
// needs to be able to find out that something was suppressed, and the reason is
// carried on the member precisely so this sentence can be built.
func suppressionFacts(in Input) []Fact {
	var out []Fact

	for _, g := range in.Groups {
		for _, m := range g.Suppressed() {
			reason := m.SuppressedReason
			if reason == "" {
				reason = "no reason was recorded"
			}
			by := m.SuppressedBy
			if by == "" {
				by = "another rule"
			}
			out = append(out, Fact{
				Kind:     FactSuppressed,
				Severity: SeverityNone,
				Subject:  trustedValue(m.Rule),
				Statement: fmt.Sprintf(
					"%s was firing but is not reported, because %s is firing and the two are treated as the same failure.",
					trustedValue(m.Rule), trustedValue(by)),
				Remedy: trustedValue(reason),
				Data: map[string]string{
					"rule":     trustedValue(m.Rule),
					"by":       trustedValue(by),
					"reason":   trustedValue(reason),
					"severity": string(m.Severity),
				},
			})
		}
	}
	return out
}

// coherenceFacts record configuration self-contradictions.
func coherenceFacts(in Input) []Fact {
	var out []Fact

	for _, c := range in.Coherence {
		sev := SeverityWarning
		switch strings.ToLower(c.Severity) {
		case "error":
			sev = SeverityCritical
		case "info":
			sev = SeverityInfo
		}
		f := Fact{
			Kind:     FactCoherence,
			Severity: sev,
			Subject:  trustedValue(c.ID),
			Statement: fmt.Sprintf(
				"The configuration contradicts itself (%s): %s",
				trustedValue(c.Rule), trustedValue(c.Message)),
			Data: map[string]string{
				"id":       trustedValue(c.ID),
				"rule":     trustedValue(c.Rule),
				"severity": strings.ToLower(c.Severity),
			},
		}
		if c.Hint != "" {
			f.Remedy = trustedValue(c.Hint)
		}
		out = append(out, f)
	}
	return out
}

// limitationFacts record what could not be determined at all.
//
// This is the fact kind that most easily goes missing and most easily matters.
// A tool that reports only what it found will, on a partially readable host,
// produce a shorter report that reads like a healthier one. These sentences
// exist so that the report cannot get shorter when visibility gets worse.
//
// Each component is a noun phrase, because the sentence template supplies the
// verb. Passing a clause here produced "the gateway itself, because the
// observations were supplied was not inspected", which is grammatically broken
// and reads as a bug in the tool rather than as a limitation.
func limitationFacts(in Input) []Fact {
	var out []Fact

	for _, d := range in.Degradable {
		clean := trustedValue(d)
		if clean == "" {
			continue
		}
		out = append(out, Fact{
			Kind:      FactLimitation,
			Severity:  SeverityNone,
			Subject:   clean,
			Statement: fmt.Sprintf("%s was not inspected, so nothing in this report describes it.", clean),
			Data:      map[string]string{"component": clean},
		})
	}

	// A build with no daemon has no incident history, and an empty incident
	// list is indistinguishable from a quiet day. Say so.
	if len(in.Incidents) == 0 {
		out = append(out, Fact{
			Kind:      FactLimitation,
			Severity:  SeverityNone,
			Subject:   "incident history",
			Statement: "There is no incident history: nothing records what has happened in the past, so this report describes only this instant.",
			Data:      map[string]string{"component": "incidents", "count": "0"},
		})
	}

	return out
}

// sentence picks the best available prose for a conclusion.
//
// The condition string is a fallback and reads as a fragment - "network.wan.up
// is false" - so it is only used when the rule set supplied no title. A
// fragment is better than nothing and worse than a sentence, in that order.
func sentence(title string, fallback string) string {
	if title != "" {
		return lowerFirst(trustedValue(title))
	}
	if fallback != "" {
		return trustedValue(fallback)
	}
	return "the condition holds"
}

// quoteValue renders a grouping key for a sentence.
//
// The key is built from label values, some of which come from the network, so
// it is quoted. A hostname reading `wan-down is not firing` is then visibly a
// name rather than a clause, which is the difference between a confusing
// report and an obviously wrong one.
func quoteValue(s string) string {
	clean := trustedValue(s)
	if clean == "" {
		return "(unlabelled)"
	}
	return strconv.Quote(clean)
}

// lowerFirst lower-cases the first rune, unless the word looks like an
// acronym. Lower-casing "DHCP" reads as a typo, and a report full of typos is
// a report nobody trusts.
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if len(r) > 1 && unicode.IsUpper(r[1]) {
		return s
	}
	return string(unicode.ToLower(r[0])) + string(r[1:])
}
