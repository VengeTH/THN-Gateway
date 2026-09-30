package assistant

import (
	"fmt"
	"sort"
	"strings"
)

// Claim is one sentence in an answer, with the facts it rests on.
//
// A claim without a fact is not a claim, it is an assertion. Keeping the two
// distinct in the type is what lets Verify drop the second without having to
// judge whether the first is *true* - which is the engine's job, not this
// package's.
type Claim struct {
	// Text is the sentence, without its citation.
	Text string `json:"text"`

	// FactIDs are the facts this sentence is derived from. Never empty on a
	// kept claim.
	FactIDs []string `json:"fact_ids,omitempty"`

	// Remedy accompanies the sentence when the fact prescribed an action.
	Remedy string `json:"remedy,omitempty"`
}

// Answer is the result of a question.
//
// It carries the claims rather than only the rendered text so that a reader -
// or a test - can check the prose against the facts after the fact, rather than
// taking it on trust.
type Answer struct {
	// Question is the operator's original words, if there were any. Never
	// logged; see audit.go.
	Question string `json:"question,omitempty"`

	// Query is the validated query that was answered.
	Query Query `json:"query"`

	// Claims are the sentences, in order.
	Claims []Claim `json:"claims"`

	// Dropped are sentences that were removed, with the reason. A non-empty
	// Dropped is not a failure of the answer; it is the answer having been
	// filtered, and hiding that would be the one thing worse than showing it.
	Dropped []DroppedClaim `json:"dropped,omitempty"`

	// Model names the model that wrote the prose, or is empty when the
	// deterministic path produced it.
	Model string `json:"model,omitempty"`

	// Facts is how many facts were available to answer from.
	Facts int `json:"facts"`

	// Digest ties the answer to the exact state it describes.
	Digest string `json:"digest"`
}

// DroppedClaim is a sentence that did not survive verification.
type DroppedClaim struct {
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

// Text renders the answer as prose, one sentence per line.
func (a Answer) Text() string {
	var sb strings.Builder
	for i, c := range a.Claims {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(c.Text)
		if len(c.FactIDs) > 0 {
			sb.WriteString(" ")
			sb.WriteString(strings.Join(c.FactIDs, " "))
		}
		if c.Remedy != "" {
			sb.WriteString("\n  → ")
			sb.WriteString(c.Remedy)
		}
	}
	return sb.String()
}

// Explain is the deterministic entry point: it answers a query from the bundle
// without a model, and is the fallback whenever a model is unavailable or
// produces something that fails verification.
//
// This function is the reason the package is worth having even with no model
// configured. Everything a language model would be asked to do here - ordering,
// phrasing, summarising, recommending - is done from facts, and a capable
// model asked to do the same job would be adding fluency rather than accuracy.
// On a gateway where a wrong sentence costs an hour of somebody's time, that
// is not a trade worth making by default.
func Explain(b Bundle, q Query, question string) (Answer, error) {
	if err := q.Validate(); err != nil {
		return Answer{}, err
	}
	q = q.Normalised()

	facts := selectFacts(b, q)

	a := Answer{
		Question: question,
		Query:    q,
		Facts:    len(facts),
		Digest:   b.Digest,
	}

	a.Claims = buildClaims(facts, q, b)
	return a, nil
}

// buildClaims turns facts into the narrative structure of an answer.
//
// The order is the argument: what is wrong, what is about to be, what could
// not be determined, what was deliberately not reported, what to do, and what
// this cannot tell you. Each of those answers a question an operator asks in
// roughly that order, and a report that puts the remedies before the
// undecidable facts is telling someone what to do about a problem it has not
// established exists.
func buildClaims(facts []Fact, q Query, b Bundle) []Claim {
	var claims []Claim

	byKind := make(map[Kind][]Fact)
	for _, f := range facts {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}

	// Remedies already printed against the fact they belong to. Repeating them
	// in the summary at the end makes an answer say the same thing twice about
	// the one action it is recommending, which reads as more urgent than it is.
	shownRemedies := make(map[string]bool)
	for _, f := range facts {
		if f.Remedy != "" && f.Kind != FactSuppressed {
			shownRemedies[f.Remedy] = true
		}
	}

	if q.Kind == QueryStatus {
		if lead := statusLead(byKind, b); lead != nil {
			claims = append(claims, *lead)
		}
	}

	for _, kind := range []Kind{FactFiring, FactIncident, FactPending, FactCoherence} {
		for _, f := range byKind[kind] {
			claims = append(claims, claimFor(f))
		}
	}

	// Undecidable and limitations come before remedies for the reason given
	// above: an action taken against a problem that was never established is
	// worse than no action.
	for _, kind := range []Kind{FactUndecidable, FactEvidence, FactLimitation} {
		for _, f := range byKind[kind] {
			claims = append(claims, claimFor(f))
		}
	}

	for _, f := range byKind[FactSuppressed] {
		claims = append(claims, claimFor(f))
	}

	if q.Kind == QueryRecommendations || q.IncludeRemedies || q.Kind == QueryStatus {
		claims = append(claims, remedyClaims(facts, shownRemedies)...)
	}

	return claims
}

// claimFor converts one fact into a cited sentence.
func claimFor(f Fact) Claim {
	return Claim{
		Text:    f.Statement,
		FactIDs: []string{f.ID},
		Remedy:  f.Remedy,
	}
}

// statusLead writes the one sentence a reader should take away.
//
// Its job is to prevent the single most expensive misreading this tool permits:
// taking a short report as a healthy one. When nothing is firing but something
// could not be determined, the lead says that, rather than opening with the
// absence of problems.
func statusLead(byKind map[Kind][]Fact, b Bundle) *Claim {
	firing := byKind[FactFiring]
	pending := byKind[FactPending]
	undecidable := byKind[FactUndecidable]
	limitations := byKind[FactLimitation]

	switch {
	case len(firing) > 0:
		worst := firing[0]
		return &Claim{
			Text: fmt.Sprintf(
				"%d condition(s) are firing now, the most serious being: %s",
				len(firing), worst.Statement),
			FactIDs: []string{worst.ID},
		}

	case len(undecidable) > 0:
		first := undecidable[0]
		return &Claim{
			Text: fmt.Sprintf(
				"Nothing is firing, but %d rule(s) could not be evaluated, so this is not a report of a healthy gateway: %s could not be read.",
				len(undecidable), first.Subject),
			FactIDs: []string{first.ID},
		}

	case len(pending) > 0:
		first := pending[0]
		return &Claim{
			Text: fmt.Sprintf(
				"Nothing is firing. %d rule(s) have a condition that holds and are waiting for their time threshold, the first being %q.",
				len(pending), first.Subject),
			FactIDs: []string{first.ID},
		}

	case len(limitations) > 0:
		return &Claim{
			Text: fmt.Sprintf(
				"Nothing is firing, none is pending, and none was left undetermined, but %s.",
				strings.ToLower(strings.TrimSuffix(limitations[0].Statement, "."))),
			FactIDs: []string{limitations[0].ID},
		}

	default:
		// Nothing is firing, pending, undecidable or limited. That is a
		// genuine all-clear on what was checked, and it is worth saying so
		// explicitly rather than leaving the reader to infer it from the
		// absence of bad news - an empty report is not the same artefact as a
		// report saying there is nothing to report.
		return &Claim{
			Text: fmt.Sprintf(
				"No rule is firing, none is pending, and none was left undetermined. %d condition(s) were evaluated and all of them were clear.",
				len(b.Facts)),
		}
	}
}

// remedyClaims collects the actions the rule set prescribes that have not
// already been shown against the fact they belong to.
//
// The remedies come from Rule.Remedy verbatim. This function does not write
// advice, and it does not rank advice it wrote. What it does is deduplicate -
// several rules firing on one uplink carry the same remedy, and printing it
// three times reads as emphasis the evidence does not support - and then skip
// the ones already printed inline, so that an answer does not say the same
// thing about a remedy twice.
//
// The result is ordered most severe first, because a critical remedy printed
// after a warning one is a remedy that gets read second.
func remedyClaims(facts []Fact, shown map[string]bool) []Claim {
	type entry struct {
		remedy string
		sev    Severity
		ids    []string
		order  int
	}

	var entries []entry
	seen := make(map[string]bool)

	for _, f := range facts {
		if f.Remedy == "" || shown[f.Remedy] {
			continue
		}
		if seen[f.Remedy] {
			for i := range entries {
				if entries[i].remedy == f.Remedy {
					entries[i].ids = append(entries[i].ids, f.ID)
				}
			}
			continue
		}
		seen[f.Remedy] = true
		entries = append(entries, entry{
			remedy: f.Remedy, sev: f.Severity, ids: []string{f.ID}, order: len(entries),
		})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].sev != entries[j].sev {
			return severityRank(entries[i].sev) < severityRank(entries[j].sev)
		}
		return entries[i].order < entries[j].order
	})

	claims := make([]Claim, 0, len(entries))
	for _, e := range entries {
		claims = append(claims, Claim{
			Text:    "What the rule set prescribes: " + e.remedy,
			FactIDs: e.ids,
			Remedy:  e.remedy,
		})
	}
	return claims
}
