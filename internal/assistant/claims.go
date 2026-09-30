package assistant

import (
	"fmt"
	"strings"
)

// Verification: what happens to prose that was not built from facts.
//
// # The rule
//
// A sentence reaches the reader if, and only if, it cites at least one fact
// that exists in the bundle. A sentence citing a fact that does not exist is
// dropped, and the drop is reported. A sentence citing nothing is dropped.
//
// That is the whole mechanism, and it is deliberately blunt.
//
// # Why not ask the model nicely
//
// The alternative is a system prompt instructing the model to cite its sources,
// plus a reviewer trusting that it mostly does. Both parts of that are a bet
// on compliance. A model that is wrong once is wrong in a way no prompt
// anticipates, and the failure mode is not an error message - it is a confident,
// plausible paragraph saying the uplink is fine on a gateway whose uplink is
// down.
//
// So compliance is not relied on. The model is asked to cite, and then the
// citations are checked here, in code that has no model in it and cannot be
// talked into anything. A model that ignores the instruction produces prose
// with no citations, and the answer becomes empty rather than wrong.
//
// # What this does and does not prove
//
// It proves every sentence is derived from something the deterministic system
// said. It does not prove the sentence is a faithful *reading* of that fact: a
// model can cite a correct fact and misdescribe it.
//
// That is a real limit and worth stating rather than hiding. It is bounded in
// two ways. The bundle contains only what was observed, so there is nothing to
// be right about beyond it; and the deterministic path is the default and the
// fallback, so a deployment that never configures a model is not exposed to
// this at all. What the check does buy is that the blast radius of a bad model
// is "you get less prose", not "you get a confident lie".
//
// The remaining gap is closed by the audit log, which records which path
// produced each answer.

// Verify checks prose against a bundle and returns only the sentences whose
// citations resolve.
//
// The returned claims are in input order and the dropped sentences are
// returned alongside them, because an answer that silently lost two of its
// five sentences is a different artefact from one that had three sentences to
// begin with, and the reader is entitled to know which they are looking at.
func Verify(b Bundle, prose string) (kept []Claim, dropped []DroppedClaim) {
	for _, sentence := range SplitSentences(prose) {
		ids := Citations(sentence)

		switch {
		case len(ids) == 0:
			dropped = append(dropped, DroppedClaim{
				Text:   sentence,
				Reason: "cites no fact; every sentence in an answer must be traceable to an observation",
			})

		default:
			var resolved []string
			var missing []string
			for _, id := range ids {
				if _, ok := b.ByID(id); ok {
					resolved = append(resolved, id)
				} else {
					missing = append(missing, id)
				}
			}
			if len(resolved) == 0 {
				dropped = append(dropped, DroppedClaim{
					Text: sentence,
					Reason: fmt.Sprintf(
						"cites %s, which is not in this bundle; a conclusion about a fact that was not observed is a fabrication",
						strings.Join(missing, ", ")),
				})
				continue
			}
			kept = append(kept, Claim{
				Text:    StripCitations(sentence),
				FactIDs: resolved,
			})
		}
	}
	return kept, dropped
}

// VerifyAnswer applies Verify to an answer that already carries claims.
//
// It exists so the model path and the deterministic path converge on the same
// check. An answer that arrived with claims already attached is still verified,
// because a claim attached without going through this function is exactly the
// thing this function exists to catch.
func VerifyAnswer(b Bundle, a Answer) Answer {
	if len(a.Claims) == 0 {
		return a
	}

	var (
		kept    []Claim
		dropped []DroppedClaim
	)

	for _, c := range a.Claims {
		if len(c.FactIDs) == 0 {
			dropped = append(dropped, DroppedClaim{
				Text:   c.Text,
				Reason: "cites no fact",
			})
			continue
		}
		var resolved []string
		for _, id := range c.FactIDs {
			if _, ok := b.ByID(id); ok {
				resolved = append(resolved, id)
			}
		}
		if len(resolved) == 0 {
			dropped = append(dropped, DroppedClaim{
				Text:   c.Text,
				Reason: "cites no fact in this bundle",
			})
			continue
		}
		c.FactIDs = resolved
		kept = append(kept, c)
	}

	a.Claims = kept
	a.Dropped = append(a.Dropped, dropped...)
	return a
}

// SplitSentences breaks prose into sentences.
//
// The splitting is deliberately conservative about the two cases that would
// otherwise mangle meaning: a full stop between digits is a decimal, not a
// sentence boundary, and a citation marker is not one either. Getting this
// wrong does not produce a false answer - Verify drops anything it cannot find
// a citation in - but it does drop sentences that were fine, and a check that
// discards good output gets ignored.
func SplitSentences(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	var (
		out     []string
		current strings.Builder
	)
	runes := []rune(text)
	depth := 0 // bracket nesting, so a citation marker is never split

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		current.WriteRune(r)

		switch r {
		case '[':
			depth++
			continue
		case ']':
			if depth > 0 {
				depth--
			}
			continue
		}

		if depth > 0 || (r != '.' && r != '!' && r != '?') {
			continue
		}
		if r == '.' && i+1 < len(runes) && isDigit(runes[i+1]) {
			continue // a decimal point, or a version number
		}
		// Consume following terminators so "Really?!" is one sentence.
		for i+1 < len(runes) && (runes[i+1] == '.' || runes[i+1] == '!' || runes[i+1] == '?') {
			i++
			current.WriteRune(runes[i])
		}
		// A boundary needs whitespace or end of text after it.
		if i+1 < len(runes) && !isSpace(runes[i+1]) {
			continue
		}
		if s := strings.TrimSpace(current.String()); s != "" {
			out = append(out, s)
		}
		current.Reset()
	}

	if s := strings.TrimSpace(current.String()); s != "" {
		out = append(out, s)
	}
	return out
}

// Citations extracts the fact identifiers a sentence cites.
//
// Identifiers are the bracketed tokens beginning with the fact prefix. Only
// that shape counts: a sentence that mentions a rule name in prose has not
// cited anything, and treating the name as a citation would let an unsourced
// sentence through on the strength of a word it happens to contain.
func Citations(sentence string) []string {
	var out []string
	runes := []rune(sentence)

	for i := 0; i < len(runes); i++ {
		if runes[i] != '[' {
			continue
		}
		end := -1
		for j := i + 1; j < len(runes) && j <= i+32; j++ {
			if runes[j] == ']' {
				end = j
				break
			}
		}
		if end < 0 {
			continue
		}
		token := string(runes[i+1 : end])
		if isFactID(token) {
			out = append(out, token)
			i = end
		}
	}
	return out
}

// isFactID reports whether a token is a fact identifier.
func isFactID(s string) bool {
	if len(s) < 2 || s[0] != 'f' {
		return false
	}
	for _, r := range s[1:] {
		if !isDigit(r) && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// StripCitations removes the citation markers from a sentence, leaving prose.
//
// The whitespace a marker leaves behind is removed with it, and the result is
// re-flowed. Without that, "Something happened [f1a2b3c4]." comes back as
// "Something happened ." and every cited sentence in the output has a
// typographic tell that the verification pass ran.
func StripCitations(sentence string) string {
	var (
		sb    strings.Builder
		runes = []rune(sentence)
	)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '[' {
			end := -1
			for j := i + 1; j < len(runes) && j <= i+32; j++ {
				if runes[j] == ']' {
					end = j
					break
				}
			}
			if end > i && isFactID(string(runes[i+1:end])) {
				i = end
				// Swallow the space that separated the citation from the
				// sentence, so removing it does not leave a gap before the
				// full stop.
				for sb.Len() > 0 {
					last := lastRune(sb.String())
					if !isSpace(last) {
						break
					}
					trimmed := trimLastRune(sb.String())
					sb.Reset()
					sb.WriteString(trimmed)
				}
				continue
			}
		}
		sb.WriteRune(runes[i])
	}
	return strings.TrimSpace(strings.Join(strings.Fields(sb.String()), " "))
}

func lastRune(s string) rune {
	r := []rune(s)
	if len(r) == 0 {
		return 0
	}
	return r[len(r)-1]
}

func trimLastRune(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return string(r[:len(r)-1])
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }
