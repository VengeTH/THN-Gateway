package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Natural language: turning what somebody typed into a Query.
//
// # Two paths, and why the deterministic one is first
//
// Parse is a keyword-and-pattern translator that runs with no model at all. It
// handles the questions an operator actually asks about a gateway - "why is
// the uplink down", "what can't you see", "what should I do" - because those
// are a small, recurring set, and recognising them costs nothing.
//
// When it cannot recognise a question, and a model is configured, the model is
// asked to translate. Its output is parsed as JSON into a Query and then run
// through the same Validate as everything else. If it produces something that
// does not validate, the request is refused. It is not repaired, not guessed
// at, and not passed through loosely.
//
// # The model translates; it does not answer
//
// This is the sharpest edge in the whole design and the easiest to get wrong.
// The natural temptation is to ask the model "answer this question about the
// gateway" and return what it says. That makes the model the thing being
// queried, and everything downstream - selection, remedies, the audit log -
// becomes advisory.
//
// Here the model is only ever asked for a Query. The facts it will be answered
// from are chosen before it is called, by selectFacts, and a model that asks
// for a different set of facts gets a different question, not different facts.

// Parse translates an operator's question into a Query.
//
// It returns an error when the question is not recognised. An error means the
// caller should say so plainly rather than guess, because a wrong guess here
// produces a confident answer about the wrong thing.
func Parse(question string) (Query, error) {
	q := strings.ToLower(strings.TrimSpace(question))
	if q == "" {
		return Query{}, fmt.Errorf("%w: the question is empty", ErrInvalidQuery)
	}

	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(q, w) {
				return true
			}
		}
		return false
	}

	// A named rule or signal overrides the intent keywords, because asking
	// "what about wan-down" is a question about a specific thing regardless of
	// which words surround it.
	if subject := namedSubject(q); subject != "" {
		switch {
		case has("what should i do", "how do i fix", "remedy", "fix"):
			return Query{Kind: QueryRecommendations, Subject: subject}, nil
		case has("why", "explain", "what happened", "how long"):
			return Query{Kind: QueryRule, Subject: subject}, nil
		default:
			return Query{Kind: QueryRule, Subject: subject}, nil
		}
	}

	switch {
	case has("what should i do", "how do i fix", "what do i do", "remedy",
		"recommend", "fix", "action"):
		return Query{Kind: QueryRecommendations}, nil

	case has("what can't", "what cannot", "what can't you", "blind spot",
		"unreadable", "limitation", "limitations", "what don't you know",
		"don't know", "do not know", "not sure", "what can't you see"):
		return Query{Kind: QueryLimitations}, nil

	case has("evidence", "observed", "observe", "observation", "what did you see",
		"what did thn see", "signals"):
		return Query{Kind: QueryEvidence}, nil

	case has("incident", "grouped", "correlated", "one problem", "same problem"):
		return Query{Kind: QuerySubject}, nil

	case has("why", "explain", "what happened", "what is wrong", "how long",
		"tell me", "what's up", "whats up", "status", "how is"):
		return Query{Kind: QueryStatus}, nil
	}

	return Query{}, fmt.Errorf(
		"%w: could not tell what %q is about. This build understands: %s",
		ErrInvalidQuery, truncate(question, 60), kindList())
}

// namedSubject extracts a rule or signal name from a question.
//
// It matches against the dotted signal vocabulary the rule set uses, because
// those names are the only identifiers an operator can be expected to know -
// they appear in every incident, every finding and every rendered artefact. A
// bare word is not treated as a subject: guessing that "wifi" names a rule
// would produce a confident answer about the wrong rule, which is worse than
// asking.
func namedSubject(q string) string {
	runes := []rune(q)
	start := -1

	for i := 0; i < len(runes); i++ {
		c := runes[i]
		isWord := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'
		if !isWord {
			start = -1
			continue
		}
		if start < 0 {
			start = i
		}
		end := i + 1
		for end < len(runes) {
			n := runes[end]
			if !((n >= 'a' && n <= 'z') || (n >= '0' && n <= '9') || n == '.' || n == '-' || n == '_') {
				break
			}
			end++
		}
		word := string(runes[start:end])
		if looksLikeSignalName(word) {
			return word
		}
		i = end - 1
		start = -1
	}
	return ""
}

// looksLikeSignalName reports whether a word has the shape of a signal name.
//
// A dot is required. Rule names are hyphenated and would need their own
// catalogue to distinguish from ordinary English; signal names are dotted and
// unambiguous, and the vocabulary is discoverable from the output itself.
func looksLikeSignalName(w string) bool {
	if !strings.Contains(w, ".") {
		return false
	}
	if strings.HasPrefix(w, ".") || strings.HasSuffix(w, ".") || strings.Contains(w, "..") {
		return false
	}
	for _, r := range w {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '-' || r == '_'
		if !ok {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Translator converts free text into a Query using a model.
//
// It exists so the model path is a narrow, testable seam: everything a model is
// allowed to influence is the translation, and everything after it is the same
// code the deterministic path uses.
type Translator interface {
	// Translate returns a JSON object matching the Query schema.
	//
	// Implementations are told the permitted kinds and nothing else. Returning
	// anything unparseable is expected and is handled, not treated as a bug.
	Translate(ctx context.Context, question string) (string, error)
}

// Ask is the top-level entry point for a question in any form.
//
// The order is deliberate and is the whole safety argument in one function:
//
//  1. translate - deterministically if possible, otherwise via a model;
//  2. validate the result, with no repair;
//  3. select the facts, in code with no model in it;
//  4. answer - deterministic always, plus model prose if one is configured and
//     what it wrote survives verification.
func Ask(ctx context.Context, b Bundle, question string, m Model, t Translator) (Answer, error) {
	q, err := resolveQuery(ctx, question, t)
	if err != nil {
		return Answer{}, err
	}
	return Narrate(ctx, m, b, q, question), nil
}

// resolveQuery produces a validated Query from free text.
func resolveQuery(ctx context.Context, question string, t Translator) (Query, error) {
	q, err := Parse(question)
	if err == nil {
		return q.Normalised(), nil
	}

	if t == nil {
		return Query{}, err
	}

	raw, terr := t.Translate(ctx, question)
	if terr != nil {
		// The deterministic parser's complaint is more useful than the
		// translator's failure, so it is the one returned.
		return Query{}, err
	}

	parsed, perr := decodeQuery(raw)
	if perr != nil {
		return Query{}, fmt.Errorf("%w: the translator did not produce a valid query: %v", ErrInvalidQuery, perr)
	}
	if verr := parsed.Validate(); verr != nil {
		return Query{}, verr
	}
	return parsed.Normalised(), nil
}

// decodeQuery parses a translator's output.
//
// Decoding is strict. Unknown fields are rejected rather than ignored, because
// a model that invents a field is telling you it did not understand the
// schema, and quietly dropping the field it invented would leave you with a
// query that validates and does not mean what it was asked to mean.
func decodeQuery(raw string) (Query, error) {
	var q Query
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return Query{}, err
	}
	// A second value in the stream means the model emitted more than a query.
	if dec.More() {
		return Query{}, fmt.Errorf("trailing content after the query object")
	}
	return q, nil
}
