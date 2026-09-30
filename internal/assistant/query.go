package assistant

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Query is a question the assistant can answer, in the only form the system
// accepts.
//
// # Why a closed schema rather than free text
//
// Everything downstream - which facts are selected, what the audit log
// records, what a model is permitted to see - keys off this struct. A schema
// with a fixed set of kinds and a fixed set of fields each makes those three
// things decidable by inspection.
//
// The alternative, letting a question stay as text and matching against it
// downstream, has no such property: a new question shape arrives as
// unrecognised text, and the behaviour for unrecognised text is whatever the
// matching code happens to do. That is how a read-only reporting tool grows a
// code path nobody reviewed.
//
// So the schema is closed. An unknown kind is an error, an unknown field is an
// error, and a query that does not validate produces no answer at all rather
// than a best-effort one.
type Query struct {
	// Kind selects what is being asked about.
	Kind QueryKind `json:"kind"`

	// Subject narrows the question to one rule, signal or fingerprint.
	Subject string `json:"subject,omitempty"`

	// Severity floors the answer: only facts at or above this are included.
	Severity Severity `json:"severity,omitempty"`

	// Limit caps how many facts of each kind are reported. Zero means the
	// default. A limit exists because the undecidable set can be large on a
	// host where nothing could be read, and an operator does not need all
	// fifteen rule names to learn that the interface is unreadable.
	Limit int `json:"limit,omitempty"`

	// IncludeRemedies asks for the actions the rule set prescribes.
	IncludeRemedies bool `json:"include_remedies,omitempty"`
}

// QueryKind is what a query is about.
type QueryKind string

const (
	// QueryStatus asks for the overall picture: what is firing, what is
	// pending, what could not be determined. The default, and the right
	// answer to "how is the gateway".
	QueryStatus QueryKind = "status"

	// QueryRule asks about one rule, named in Subject.
	QueryRule QueryKind = "rule"

	// QuerySubject asks about one grouping key or fingerprint.
	QuerySubject QueryKind = "subject"

	// QueryEvidence asks what was observed, including what was unreadable.
	QueryEvidence QueryKind = "evidence"

	// QueryRecommendations asks what to do, using the rule set's own remedies.
	QueryRecommendations QueryKind = "recommendations"

	// QueryLimitations asks what could not be determined. Separate from
	// QueryStatus because it is the question an operator asks when the tool
	// has just told them everything is fine and they do not believe it.
	QueryLimitations QueryKind = "limitations"
)

// AllQueryKinds is every kind, for documentation and tests.
func AllQueryKinds() []QueryKind {
	return []QueryKind{
		QueryStatus, QueryRule, QuerySubject,
		QueryEvidence, QueryRecommendations, QueryLimitations,
	}
}

// ErrInvalidQuery is returned when a query does not satisfy the schema.
var ErrInvalidQuery = errors.New("assistant: invalid query")

// DefaultLimit is how many facts of one kind are reported when the query does
// not say.
//
// Twelve is chosen so that a gateway with several distinct problems shows all
// of them, while a host where one unread interface made everything
// undecidable shows the interface rather than the fifteen rules that depend on
// it.
const DefaultLimit = 12

// Validate checks a query against the closed schema.
//
// It returns an error rather than a repaired query. A caller that asked for
// something this system cannot answer should be told so, and a caller that
// produced a malformed query - which is what a language model does often
// enough to matter - should have it rejected, not have its output quietly
// interpreted. Silently repairing a model's malformed output is how a wrong
// answer acquires the appearance of a right one.
func (q Query) Validate() error {
	if q.Kind == "" {
		return fmt.Errorf("%w: kind is required; one of %s", ErrInvalidQuery, kindList())
	}

	known := false
	for _, k := range AllQueryKinds() {
		if q.Kind == k {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("%w: unknown kind %q; one of %s", ErrInvalidQuery, q.Kind, kindList())
	}

	switch q.Kind {
	case QueryRule, QuerySubject:
		if strings.TrimSpace(q.Subject) == "" {
			return fmt.Errorf("%w: kind %q requires a subject", ErrInvalidQuery, q.Kind)
		}
	default:
		if strings.TrimSpace(q.Subject) != "" {
			return fmt.Errorf("%w: kind %q does not take a subject", ErrInvalidQuery, q.Kind)
		}
	}

	if q.Severity != "" {
		switch q.Severity {
		case SeverityCritical, SeverityWarning, SeverityInfo, SeverityNone:
		default:
			return fmt.Errorf("%w: unknown severity %q", ErrInvalidQuery, q.Severity)
		}
	}

	if q.Limit < 0 {
		return fmt.Errorf("%w: limit cannot be negative, got %d", ErrInvalidQuery, q.Limit)
	}
	if q.Limit > 100 {
		// An upper bound rather than a warning. A model that produced a large
		// limit probably misunderstood the field, and an unbounded answer is
		// exactly the thing that crowds out the part the operator needed.
		return fmt.Errorf("%w: limit %d is above the maximum of 100", ErrInvalidQuery, q.Limit)
	}

	return nil
}

func kindList() string {
	parts := make([]string, 0, len(AllQueryKinds()))
	for _, k := range AllQueryKinds() {
		parts = append(parts, string(k))
	}
	return strings.Join(parts, ", ")
}

// Normalised returns a copy with defaults applied.
func (q Query) Normalised() Query {
	if q.Limit == 0 {
		q.Limit = DefaultLimit
	}
	q.Subject = strings.TrimSpace(q.Subject)
	return q
}

// String renders the query for a log line.
//
// It renders the parsed query rather than the operator's original words,
// because the original may contain a hostname, a MAC or an incident reference
// that has no business in a log. See audit.go.
func (q Query) String() string {
	parts := []string{string(q.Kind)}
	if q.Subject != "" {
		parts = append(parts, "subject="+q.Subject)
	}
	if q.Severity != "" {
		parts = append(parts, "severity="+string(q.Severity))
	}
	if q.Limit != 0 {
		parts = append(parts, fmt.Sprintf("limit=%d", q.Limit))
	}
	if q.IncludeRemedies {
		parts = append(parts, "remedies")
	}
	return strings.Join(parts, " ")
}

// selectFacts applies a query to a bundle and returns the matching facts.
//
// This is the whole of "what the question is about". Everything after this
// point is presentation, and everything before it is the deterministic
// pipeline. Keeping the selection here, in one pure function, is what makes
// the same query answerable by the deterministic path and by the model path
// without either being able to change what is selected.
func selectFacts(b Bundle, q Query) []Fact {
	q = q.Normalised()

	var wanted []Kind
	switch q.Kind {
	case QueryStatus:
		// Undecidable and limitation facts belong here, and leaving them out
		// was a real bug: the opening sentence is chosen from these very kinds,
		// so a status query that did not select them reported "nothing is
		// wrong" on a gateway where nothing could be read. The most important
		// sentence in the answer was being decided by the selection step two
		// functions earlier.
		wanted = []Kind{
			FactFiring, FactPending, FactIncident, FactCoherence,
			FactUndecidable, FactLimitation, FactSuppressed,
		}
	case QueryRule:
		wanted = []Kind{FactFiring, FactPending, FactUndecidable, FactRecommendation}
	case QuerySubject:
		wanted = []Kind{FactIncident, FactSuppressed, FactFiring, FactPending}
	case QueryEvidence:
		wanted = []Kind{FactEvidence, FactUndecidable, FactLimitation}
	case QueryRecommendations:
		wanted = []Kind{FactFiring, FactPending, FactCoherence}
	case QueryLimitations:
		wanted = []Kind{FactLimitation, FactEvidence, FactUndecidable}
	}

	out := make([]Fact, 0, len(b.Facts))
	for _, f := range b.Facts {
		if !containsKind(wanted, f.Kind) {
			continue
		}
		if q.Subject != "" && !matchesSubject(f, q.Subject) {
			continue
		}
		if q.Severity != "" && severityRank(f.Severity) > severityRank(q.Severity) {
			continue
		}
		out = append(out, f)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})

	return capPerKind(out, q.Limit)
}

func containsKind(kinds []Kind, k Kind) bool {
	for _, want := range kinds {
		if want == k {
			return true
		}
	}
	return false
}

// matchesSubject reports whether a fact is about the named subject.
//
// The subject is compared against every identifier the fact carries rather
// than one chosen field, because an operator naming a rule does not know
// whether THN filed it under the rule name, the instance group fingerprint or
// the grouping key - and requiring them to know would make the feature
// unusable for exactly the person who needs it.
func matchesSubject(f Fact, subject string) bool {
	want := strings.ToLower(strings.TrimSpace(subject))
	if want == "" {
		return true
	}
	if strings.EqualFold(f.Subject, subject) {
		return true
	}
	for _, v := range f.Data {
		if v != "" && strings.EqualFold(v, subject) {
			return true
		}
		for _, part := range strings.Split(v, ",") {
			if part != "" && strings.EqualFold(strings.TrimSpace(part), subject) {
				return true
			}
		}
	}
	return false
}

// capPerKind limits each kind independently.
//
// Limiting globally would let a long list of pending rules push the single
// firing one out of the answer, which inverts the priority the report is
// built around. Limiting per kind keeps the shape of the problem intact: a few
// of each, so the reader learns that there are more without losing the ones
// that matter.
func capPerKind(facts []Fact, limit int) []Fact {
	if limit <= 0 {
		return facts
	}
	counts := make(map[Kind]int)
	out := make([]Fact, 0, len(facts))
	var dropped int
	for _, f := range facts {
		if counts[f.Kind] >= limit {
			dropped++
			continue
		}
		counts[f.Kind]++
		out = append(out, f)
	}
	_ = dropped
	return out
}
