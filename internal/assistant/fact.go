// Package assistant turns what the deterministic pipeline already concluded
// into prose an operator can act on.
//
// # What this package is for
//
// A gateway that is unattended, remote, and read-only produces a great deal of
// precise output — rule instances, evidence signals, correlations, remedies —
// and almost none of it is readable at three in the morning without the
// manual open. "wan-down: pending, 42s of 60s" is correct and useless. "The
// uplink has been down for 42 seconds and needs another 18 before it is
// reported; it is expected to clear on its own, and if it does not, the
// carrier is the first thing to check" is the same fact arranged for a human.
//
// This package does that arranging. It is deliberately not a second source of
// truth: every sentence it can emit is assembled from a Fact, and every Fact
// came out of the rule engine, the correlator or the incident manager.
//
// # The arrangement is an assistant, not an authority
//
// The division of labour is the whole design:
//
//   - The deterministic system decides what is true. Rules fire or do not,
//     signals are known or unknown, correlations group or do not. That
//     judgement is made in code that has tests and no model in it.
//   - This package decides how to say it. Ordering, grouping, emphasis,
//     pruning of noise. All of it reversible, none of it load-bearing.
//
// A language model, where one is configured, sits strictly on the second side.
// It is given facts and asked for prose. It is never asked what is true, and
// its prose is checked against the facts before anyone sees it (see claims.go).
// This is not a prompt instruction that a capable model would probably obey —
// prompts are not a control boundary, and a system that depends on one has no
// control boundary at all. The check is in this package and runs regardless of
// what the model was told.
//
// # Nothing here writes
//
// The package imports nothing that mutates state, spawns a process, or opens a
// network connection. It is a function from observed state to text. The
// repository-wide test that forbids unguarded process spawning therefore passes
// over it without needing an exemption, and there is no path from an assistant
// answer to a changed gateway — not because one was closed, but because none
// was ever opened.
package assistant

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/rules"
)

// Kind classifies a fact, and exists so that a reader — human or model — can
// tell what kind of claim they are looking at without parsing the sentence.
//
// The distinction that matters most is FactObserved against FactUndecidable. An
// undecidable fact is a statement about what could not be read, and it must
// never be laundered into a statement about the state of the gateway.
type Kind string

const (
	// FactFiring is a rule whose condition holds and whose threshold is met.
	FactFiring Kind = "firing"

	// FactPending is a rule whose condition holds but whose duration threshold
	// has not yet elapsed.
	FactPending Kind = "pending"

	// FactUndecidable is a rule that could not be evaluated because a signal it
	// depends on was not read.
	//
	// This kind is not a softer version of FactFiring. It is the absence of a
	// conclusion, and an assistant that renders it as "fine" has invented a
	// result the engine deliberately refused to produce.
	FactUndecidable Kind = "undecidable"

	// FactClear is a rule whose condition does not hold.
	FactClear Kind = "clear"

	// FactSuppressed is a rule that is firing but was inhibited by another.
	FactSuppressed Kind = "suppressed"

	// FactIncident is a correlated group of firing rules.
	FactIncident Kind = "incident"

	// FactEvidence is the observed signal behind a conclusion.
	FactEvidence Kind = "evidence"

	// FactCoherence is a finding that the configuration contradicts itself.
	FactCoherence Kind = "coherence"

	// FactRecommendation is a remedy carried by a rule.
	FactRecommendation Kind = "recommendation"

	// FactLimitation is something THN could not determine at all. These are
	// first-class: a system that can only report what it knows needs to say
	// what it does not.
	FactLimitation Kind = "limitation"
)

// Severity ranks a fact for ordering. It mirrors rules.Severity rather than
// reusing it, because a fact can also be a limitation, which has no severity,
// and overloading one type with two meanings makes both harder to read.
type Severity string

const (
	// SeverityCritical needs attention now.
	SeverityCritical Severity = "critical"
	// SeverityWarning needs attention soon.
	SeverityWarning Severity = "warning"
	// SeverityInfo is worth knowing.
	SeverityInfo Severity = "info"
	// SeverityNone is neither. Limitations and observations.
	SeverityNone Severity = "none"
)

// severityFrom maps a rule severity onto a fact severity.
func severityFrom(s rules.Severity) Severity {
	switch s {
	case rules.SeverityCritical:
		return SeverityCritical
	case rules.SeverityWarning:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// Fact is one statement the assistant is permitted to make.
//
// A Fact is self-contained: it carries a sentence that is true on its own, and
// the structured values it was derived from. That redundancy is the point. The
// sentence exists so nothing has to be re-derived to check it, and the data
// exists so a reader who does not trust the sentence can look at what it came
// from.
type Fact struct {
	// ID is a short content hash. Deriving it from the content rather than
	// from a position means a citation stays meaningful if the bundle is
	// rebuilt, and means two facts cannot silently swap identities between
	// runs because a sort order changed.
	ID string `json:"id"`

	// Kind is what sort of claim this is.
	Kind Kind `json:"kind"`

	// Severity ranks it for ordering.
	Severity Severity `json:"severity"`

	// Subject is what the fact is about: a rule name, a group key, a signal
	// name. It is a name from the deterministic system, never free text.
	Subject string `json:"subject,omitempty"`

	// Statement is the sentence. It must be true as written, with no
	// antecedent, because it may be quoted out of context.
	Statement string `json:"statement"`

	// Remedy is the action the rule set prescribes, when it prescribes one.
	// It comes from Rule.Remedy verbatim. The assistant does not write
	// remedies; it selects them. A generated remedy would be advice with
	// nobody's name on it, and the whole reason to trust this package is that
	// every instruction in it was written by a person and reviewed.
	Remedy string `json:"remedy,omitempty"`

	// Data holds the structured values the statement was built from, so the
	// statement can be checked rather than believed.
	Data map[string]string `json:"data,omitempty"`

	// Untrusted marks a fact whose text originated outside THN — a DHCP
	// hostname, a DNS label, a MAC from a lease file.
	//
	// These are the only strings in the system an attacker can choose, and
	// they are treated accordingly throughout: see Sanitise.
	Untrusted bool `json:"untrusted,omitempty"`
}

// Bundle is every fact available to answer one question, with a digest tying
// any answer back to the exact state that produced it.
//
// The digest is not decoration. An answer is only useful if it can be shown to
// have come from the observations it claims to describe, and "the gateway was
// fine at 09:14" stops being checkable the moment the gateway's state moves on.
// Carrying the digest lets a reader — or a test — confirm that an answer and a
// bundle describe the same moment.
type Bundle struct {
	// Facts are the statements available, in a deterministic order.
	Facts []Fact `json:"facts"`

	// At is when the bundle was built.
	At time.Time `json:"at"`

	// Digest is a hash over the facts. Two bundles with the same digest
	// describe the same gateway state and will produce the same answer.
	Digest string `json:"digest"`
}

// NewBundle assembles a bundle, assigning identifiers and computing the digest.
//
// Facts are sorted before hashing so that the digest depends on the content
// and not on the order the callers happened to discover them in. Two runs over
// the same state produce byte-identical bundles, which is what makes the
// digest worth having.
func NewBundle(at time.Time, facts []Fact) Bundle {
	sorted := make([]Fact, len(facts))
	copy(sorted, facts)

	for i := range sorted {
		if sorted[i].ID == "" {
			sorted[i].ID = factID(sorted[i])
		}
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Severity != b.Severity {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.ID < b.ID
	})

	sorted = dedupe(sorted)

	return Bundle{
		Facts:  sorted,
		At:     at.UTC(),
		Digest: digestOf(sorted),
	}
}

// factID derives a short, stable identifier from a fact's content.
func factID(f Fact) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		string(f.Kind), string(f.Severity), f.Subject, f.Statement, f.Remedy,
	}, "\x00")))
	return "f" + hex.EncodeToString(h[:])[:8]
}

// digestOf hashes the canonical form of the facts.
func digestOf(facts []Fact) string {
	// json.Marshal sorts map keys, so Data contributes deterministically.
	b, err := json.Marshal(facts)
	if err != nil {
		// Facts contain only strings and a map of strings, so this cannot
		// happen. Falling back to the statement keeps the digest total rather
		// than panicking a read-only reporting path.
		b = []byte(strings.Join(statements(facts), "\x00"))
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:16]
}

// severityRank orders severities for sorting, most severe first.
func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityWarning:
		return 1
	case SeverityInfo:
		return 2
	default:
		return 3
	}
}

// dedupe removes facts with identical content.
//
// Two rules can legitimately produce the same sentence — "the uplink is down"
// from wan-down and from no-default-route, once the latter is unreported. That
// is not an error, but repeating it in prose reads as emphasis the evidence
// does not support, so it is collapsed here rather than left to the renderer.
func dedupe(facts []Fact) []Fact {
	seen := make(map[string]bool, len(facts))
	out := facts[:0]
	for _, f := range facts {
		key := string(f.Kind) + "\x00" + f.Subject + "\x00" + f.Statement
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func statements(facts []Fact) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		out = append(out, f.Statement)
	}
	return out
}

// ByID returns the fact with the given identifier.
func (b Bundle) ByID(id string) (Fact, bool) {
	for _, f := range b.Facts {
		if f.ID == id {
			return f, true
		}
	}
	return Fact{}, false
}

// OfKind returns every fact of a kind, preserving order.
func (b Bundle) OfKind(kinds ...Kind) []Fact {
	want := make(map[Kind]bool, len(kinds))
	for _, k := range kinds {
		want[k] = true
	}
	var out []Fact
	for _, f := range b.Facts {
		if want[f.Kind] {
			out = append(out, f)
		}
	}
	return out
}

// Statements renders the bundle as plain text, one fact per line, for handing
// to something that reads language.
//
// This is the only representation a model ever sees. It carries no formatting,
// no severity colours and no structure a model could mistake for authority —
// and, critically, it is the *same* text a human sees, so there is no separate
// "prompt version" that could drift from what was verified.
func (b Bundle) Statements() string {
	var sb strings.Builder
	for _, f := range b.Facts {
		sb.WriteString(f.ID)
		sb.WriteString(" [")
		sb.WriteString(string(f.Kind))
		if f.Severity != SeverityNone {
			sb.WriteString("/")
			sb.WriteString(string(f.Severity))
		}
		sb.WriteString("] ")
		if f.Untrusted {
			sb.WriteString("(untrusted) ")
		}
		sb.WriteString(f.Statement)
		if f.Remedy != "" {
			sb.WriteString(" Remedy: ")
			sb.WriteString(f.Remedy)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// Describe renders a one-line human summary of the bundle's composition, used
// by the CLI so an operator can see what the assistant was given before reading
// what it said.
func (b Bundle) Describe() string {
	counts := make(map[Kind]int)
	for _, f := range b.Facts {
		counts[f.Kind]++
	}
	parts := make([]string, 0, len(counts))
	for k, n := range counts {
		parts = append(parts, fmt.Sprintf("%d %s", n, k))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%d facts (%s), digest %s", len(b.Facts), strings.Join(parts, ", "), b.Digest)
}
