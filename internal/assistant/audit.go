package assistant

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// The audit trail.
//
// # What is recorded, and what is deliberately not
//
// Recorded: when the call happened, which query was answered, which model was
// involved, how many facts it drew on, how many sentences were kept and how
// many were dropped, and the digest tying the answer to a bundle.
//
// Not recorded: the operator's question.
//
// The question is the one part of a request that can carry anything at all. It
// may name a customer, quote a hostname, contain a MAC, or be a pasted ticket
// with a password in it. A log is the wrong place for that, and a log is also
// the thing most likely to be shipped somewhere else. So the question is
// hashed: the same question produces the same digest, which is enough to detect
// repetition and correlate calls, and the content stays where it was typed.
//
// The query that was *derived* from it is logged in full, because that is a
// closed vocabulary of rule names and signal names. It carries no operator
// input beyond the subject they named, and that is what an audit trail is for.
//
// # Append-only
//
// Records are written as JSON Lines and never rewritten. A log that can be
// edited is not evidence, and an assistant audit trail whose value is "this
// system does not quietly make things up" collapses the moment someone can
// remove the entries where it did.

// AuditEntry is one recorded interaction.
type AuditEntry struct {
	// At is when the call was made.
	At time.Time `json:"at"`

	// Event names what happened: asked, answered, refused.
	Event string `json:"event"`

	// Query is the validated query, rendered. See Query.String.
	Query string `json:"query,omitempty"`

	// QueryError is why a question could not be turned into a query.
	QueryError string `json:"query_error,omitempty"`

	// QuestionDigest is a hash of the operator's words, never the words.
	QuestionDigest string `json:"question_digest,omitempty"`

	// QuestionLength is how long the question was, in runes.
	QuestionLength int `json:"question_length,omitempty"`

	// Model is the model that was consulted, or "none".
	Model string `json:"model,omitempty"`

	// FactsAvailable is how many facts the bundle held.
	FactsAvailable int `json:"facts_available,omitempty"`

	// FactsSelected is how many the query matched.
	FactsSelected int `json:"facts_selected,omitempty"`

	// ClaimsKept and ClaimsDropped are the verification result.
	ClaimsKept    int `json:"claims_kept"`
	ClaimsDropped int `json:"claims_dropped"`

	// BundleDigest ties the answer to a bundle.
	BundleDigest string `json:"bundle_digest,omitempty"`
}

// Audit events.
const (
	// EventAsked records a question being answered.
	EventAsked = "asked"

	// EventRefused records a question that could not be answered.
	EventRefused = "refused"

	// EventSuggested records correlation suggestions being produced.
	EventSuggested = "suggested"
)

// AuditLog is an append-only sink for audit entries.
//
// The interface is deliberately tiny so that the real implementation - a file,
// a syslog forwarder, a test buffer - is a few lines rather than a decision.
// Callers that do not need a log pass nil and skip it; a nil interface value
// cannot be called, so the guard belongs at the call site rather than here.
type AuditLog interface {
	Append(entry AuditEntry) error
}

// DiscardAudit is an AuditLog that writes nowhere.
var DiscardAudit AuditLog = discardAudit{}

type discardAudit struct{}

func (discardAudit) Append(AuditEntry) error { return nil }

// Audit builds an entry describing one answered question.
//
// The kept and dropped counts are taken from the answer rather than counted
// again, so the log cannot disagree with what the reader was shown.
func Audit(at time.Time, event string, question string, a Answer, qErr error) AuditEntry {
	e := AuditEntry{
		At:         at.UTC(),
		Event:      event,
		Model:      "none (deterministic answers only)",
		ClaimsKept: len(a.Claims),
	}

	if question != "" {
		e.QuestionDigest = digestOfString(question)
		e.QuestionLength = len([]rune(question))
	}
	if a.Model != "" {
		e.Model = a.Model
	}
	if qErr != nil {
		e.QueryError = qErr.Error()
	}
	if a.Query.Kind != "" {
		e.Query = a.Query.String()
	}
	e.FactsSelected = a.Facts
	e.ClaimsDropped = len(a.Dropped)
	e.BundleDigest = a.Digest

	return e
}

// AuditSuggestion records that suggestions were produced.
func AuditSuggestion(at time.Time, count int) AuditEntry {
	return AuditEntry{
		At:         at.UTC(),
		Event:      EventSuggested,
		Model:      "none (deterministic answers only)",
		ClaimsKept: count,
	}
}

// digestOfString hashes a string for the log.
func digestOfString(s string) string {
	h := sha256.Sum256([]byte(s))
	return "q" + hex.EncodeToString(h[:])[:12]
}

// JSONL writes entries as JSON Lines.
//
// JSON Lines rather than a JSON array because an append-only log written as an
// array is either rewritten on every append or left truncated by a crash. One
// object per line is append-safe: a crash loses the last line and corrupts
// nothing.
type JSONL struct {
	// W is where entries are written.
	W io.Writer

	// Now supplies the timestamp, so a test can produce a deterministic log.
	Now func() time.Time
}

// Append writes one entry.
func (j *JSONL) Append(entry AuditEntry) error {
	if j == nil || j.W == nil {
		return nil
	}
	if entry.At.IsZero() && j.Now != nil {
		entry.At = j.Now().UTC()
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("assistant: encoding audit entry: %w", err)
	}
	if _, err := j.W.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("assistant: writing audit entry: %w", err)
	}
	return nil
}

// String renders an entry for a terminal.
//
// The question hash is deliberately omitted from the human-readable form as
// well: an operator looking at a log wants to know what was asked, and a hash
// tells them only that two questions were the same.
func (e AuditEntry) String() string {
	var parts []string
	parts = append(parts, e.At.Format(time.RFC3339))
	parts = append(parts, e.Event)
	if e.Query != "" {
		parts = append(parts, "query="+e.Query)
	}
	if e.QueryError != "" {
		parts = append(parts, "error="+e.QueryError)
	}
	if e.QuestionLength > 0 {
		parts = append(parts, fmt.Sprintf("question=%d chars", e.QuestionLength))
	}
	parts = append(parts, "model="+e.Model)
	parts = append(parts, fmt.Sprintf("claims=%d kept %d dropped", e.ClaimsKept, e.ClaimsDropped))
	if e.BundleDigest != "" {
		parts = append(parts, "bundle="+e.BundleDigest)
	}
	return strings.Join(parts, " ")
}
