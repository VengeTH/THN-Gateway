package assistant

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/correlation"
	"github.com/VengeTH/THN-Gateway/internal/rules"
)

// Correlation assistance: proposing groupings and suppressions a human has not
// written down yet.
//
// # Suggestions, never changes
//
// Nothing in this file is applied, and nothing in this package can apply it.
// A Suggestion is a YAML fragment printed for a person to read, edit and paste
// if they agree. That is the entire workflow, and the reason it is safe: a
// wrong suggestion costs a few seconds of someone's attention, and a wrong
// automatic inhibition would silently hide a real failure.
//
// This matters more than it might seem. Inhibition is how a tool avoids
// crying wolf, and a wrongly-configured inhibition is how a tool stops
// reporting a problem at all while continuing to look healthy. The asymmetry
// between those two costs is the reason nothing here is automatic.
//
// # What makes a suggestion worth reading
//
// A candidate pair is only worth printing if the two rules co-occur more often
// than chance would suggest, over enough observations to mean anything. A pair
// seen once is noise. So every Suggestion carries the evidence that produced
// it - the count, the window, the groups - and a suggestion below the
// evidence threshold is not produced at all rather than produced weakly.

// Suggestion is a proposed correlation rule, for a human to accept or reject.
type Suggestion struct {
	// Kind is what is being proposed.
	Kind SuggestionKind `json:"kind"`

	// Source is the rule whose firing would cause the grouping or suppression.
	Source string `json:"source"`

	// Target is the rule affected.
	Target string `json:"target"`

	// Equal proposes label keys the two must agree on.
	Equal []string `json:"equal,omitempty"`

	// CoOccurrences is how many times the two were seen in one group.
	CoOccurrences int `json:"co_occurrences"`

	// Groups is how many distinct groups they shared, which is the number
	// that distinguishes a pattern from one incident.
	Groups int `json:"groups"`

	// Window is the period the observations span.
	Window string `json:"window"`

	// Confidence is a coarse label, not a probability.
	//
	// It is deliberately coarse. A percentage would imply a calibration this
	// does not have and cannot easily acquire, and a number that looks
	// measured is trusted more than a word, which would be the wrong way round.
	Confidence Confidence `json:"confidence"`

	// Rationale explains the suggestion in one sentence, for the human deciding.
	Rationale string `json:"rationale"`

	// YAML is the fragment to paste into the configuration.
	YAML string `json:"yaml"`
}

// SuggestionKind is what a suggestion proposes.
type SuggestionKind string

const (
	// SuggestGroup proposes grouping two rules into one incident.
	//
	// Grouping is the safe direction: it changes how many incidents are
	// reported, not whether something is reported.
	SuggestGroup SuggestionKind = "group"

	// SuggestInhibit proposes suppressing one rule while another fires.
	//
	// This is the dangerous direction and is only ever proposed with the
	// strongest available evidence, and always with a stated reason. A
	// suggestion here is a request for a human to take responsibility for a
	// suppression, which is exactly what should require one.
	SuggestInhibit SuggestionKind = "inhibit"
)

// Confidence is how much weight a suggestion deserves.
type Confidence string

const (
	// ConfidenceWeak means seen, but not enough to act on.
	ConfidenceWeak Confidence = "weak"
	// ConfidenceModerate means recurring across several distinct groups.
	ConfidenceModerate Confidence = "moderate"
	// ConfidenceStrong means recurring across many distinct groups.
	ConfidenceStrong Confidence = "strong"
)

// MinimumCoOccurrences is how often two rules must be seen together before a
// suppression is suggested at all.
//
// Three is the smallest number where "these keep happening together" is
// distinguishable from "this happened once, at a moment when several things
// were wrong". It is not a statistical threshold and is not claimed to be; it
// is the point below which a suggestion would be noise dressed as insight.
const MinimumCoOccurrences = 3

// MinimumGroupsForStrong is how many distinct groups a pair must span to be
// called strong.
//
// The distinction that matters is between one bad afternoon and a pattern. A
// pair seen together in a single group tells you they coincided once. A pair
// seen together across many groups, days apart, tells you they are related -
// which is what a grouping or inhibition rule asserts.
const MinimumGroupsForStrong = 3

// SuggestCorrelations proposes groupings and inhibitions from observed groups.
//
// It reads only from groups the correlator actually produced. It does not
// consult a rule catalogue, does not guess at rules that never fired, and does
// not use the model. A suggestion about a rule set THN has never observed is
// a guess, and a guess printed in the same format as an observation is
// indistinguishable from one.
func SuggestCorrelations(groups []correlation.Group, ruleset map[string]rules.Rule, existing []correlation.InhibitRule, at time.Time) []Suggestion {
	pairs := coOccurrences(groups)

	// Suppress a candidate if the operator has already said how these relate.
	// Re-suggesting a rule that exists is the kind of thing that makes a tool
	// feel like it is not paying attention.
	already := make(map[string]bool, len(existing)*2)
	for _, e := range existing {
		already[pairKey(e.Source, e.Target)] = true
		already[pairKey(e.Target, e.Source)] = true
	}

	var window string
	if len(groups) > 0 {
		first, last := groups[0].FirstSeen, groups[0].At
		for _, g := range groups {
			if g.FirstSeen.Before(first) {
				first = g.FirstSeen
			}
			if g.At.After(last) {
				last = g.At
			}
		}
		window = last.Sub(first).Round(time.Second).String()
	}

	var out []Suggestion
	for _, p := range pairs {
		key := pairKey(p.a, p.b)
		if already[key] {
			continue
		}
		if p.count < MinimumCoOccurrences {
			continue
		}

		confidence := ConfidenceWeak
		switch {
		case p.groups >= MinimumGroupsForStrong*3:
			confidence = ConfidenceStrong
		case p.groups >= MinimumGroupsForStrong:
			confidence = ConfidenceModerate
		}

		out = append(out, Suggestion{
			Kind:          SuggestGroup,
			Source:        p.a,
			Target:        p.b,
			Equal:         p.equal,
			CoOccurrences: p.count,
			Groups:        p.groups,
			Window:        window,
			Confidence:    confidence,
			Rationale: fmt.Sprintf(
				"%s and %s were firing together in %d observation(s) across %d distinct group(s). Grouping them would report one incident instead of %d.",
				p.a, p.b, p.count, p.groups, p.groups),
			YAML: groupYAML(p),
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return confidenceRank(out[i].Confidence) < confidenceRank(out[j].Confidence)
		}
		return out[i].CoOccurrences > out[j].CoOccurrences
	})
	return out
}

// pairCount is one observed co-occurrence tally.
type pairCount struct {
	a, b  string
	count int
	// groups counts distinct group fingerprints, deduplicated so that repeated
	// emissions of the same group do not inflate the evidence.
	groups int
	seen   map[string]bool
	// equal records the label keys both members agreed on, which is what an
	// inhibition rule needs and what a grouping rule usually wants.
	equal []string
}

// coOccurrences tallies which rules keep appearing together.
func coOccurrences(groups []correlation.Group) []pairCount {
	tally := make(map[string]*pairCount)

	for _, g := range groups {
		names := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			names = append(names, m.Rule)
		}
		sort.Strings(names)

		for i := 0; i < len(names); i++ {
			for j := i + 1; j < len(names); j++ {
				key := pairKey(names[i], names[j])
				p, ok := tally[key]
				if !ok {
					p = &pairCount{a: names[i], b: names[j], seen: make(map[string]bool)}
					tally[key] = p
				}
				p.count++
				if !p.seen[g.Fingerprint] {
					p.seen[g.Fingerprint] = true
					p.groups++
				}
				if p.equal == nil {
					p.equal = sharedLabels(g, names[i], names[j])
				}
			}
		}
	}

	out := make([]pairCount, 0, len(tally))
	for _, p := range tally {
		out = append(out, *p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].a < out[j].a
	})
	return out
}

// sharedLabels finds label keys both rules carry, which is what makes a
// suppression narrow rather than global.
func sharedLabels(g correlation.Group, a, b string) []string {
	var la, lb map[string]string
	for _, m := range g.Members {
		switch m.Rule {
		case a:
			la = m.Labels
		case b:
			lb = m.Labels
		}
	}
	var out []string
	for k := range la {
		if _, ok := lb[k]; ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func pairKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "\x00" + b
}

func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceStrong:
		return 0
	case ConfidenceModerate:
		return 1
	default:
		return 2
	}
}

// groupYAML renders a suggestion as a configuration fragment.
//
// The output is a fragment rather than a whole document because pasting a whole
// document over a working configuration is how a helpful suggestion becomes a
// destructive one.
func groupYAML(p pairCount) string {
	var sb strings.Builder
	sb.WriteString("correlation:\n")
	sb.WriteString("  group_by:\n")
	for _, k := range p.equal {
		fmt.Fprintf(&sb, "    - %s\n", k)
	}
	if len(p.equal) == 0 {
		sb.WriteString("    # add label keys here to keep the grouping narrow\n")
	}
	return sb.String()
}

// RenderSuggestions formats suggestions for a terminal or the console.
//
// It prints the evidence before the proposal, every time. A suggestion whose
// rationale is not immediately above it is a suggestion that gets pasted
// without being read, which is the outcome this whole file exists to avoid.
func RenderSuggestions(s []Suggestion) string {
	if len(s) == 0 {
		return "No correlation suggestions: no pair of rules was observed firing together often enough to suggest a relationship.\n"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d suggestion(s). None of these is applied; they are for you to read and decide on.\n\n", len(s))

	for i, sug := range s {
		fmt.Fprintf(&sb, "%d. %s / %s  [%s, %d observation(s) across %d group(s), window %s]\n",
			i+1, sug.Source, sug.Target, sug.Confidence, sug.CoOccurrences, sug.Groups, sug.Window)
		fmt.Fprintf(&sb, "   %s\n", sug.Rationale)
		if len(sug.Equal) > 0 {
			fmt.Fprintf(&sb, "   agree on labels: %s\n", strings.Join(sug.Equal, ", "))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Grouping changes how many incidents are reported.\n")
	sb.WriteString("Inhibition hides one rule while another fires, and a wrong inhibition\n")
	sb.WriteString("is a real failure that never gets reported. Read those harder.\n")
	return sb.String()
}
