package assistant

import (
	"context"
	"errors"
	"strings"
)

// ErrNoModel is returned when a model was required and none is configured.
var ErrNoModel = errors.New("assistant: no model configured")

// ErrModelRefused is returned when a model declines or fails.
//
// It is a distinct error from a model returning nothing useful, because the
// two call for different responses: a refusal is a configuration fact, and an
// empty answer is a fact about the model's output. Both end the same way -
// the deterministic answer is used - but the audit log records which happened,
// because "the model was never configured" and "the model was configured and
// produced nothing" are very different states for a system to be in.
var ErrModelRefused = errors.New("assistant: model refused")

// Model turns a bundle of facts into prose.
//
// # What a model is for here
//
// Reordering, phrasing and summarising. Nothing else. A model is never asked
// what is true, whether something is a problem, or what should be done about
// it - those are questions with answers already in the bundle, and a model
// answering them is a second source of truth with none of the guarantees of
// the first.
//
// # What a model cannot do
//
// It cannot reach the bundle's facts by any route other than the text it is
// given. It cannot cause a process to run, a file to be written, or a
// configuration to change: this package has no path to any of those, and the
// repository-wide test that forbids unguarded process spawning passes over it.
//
// It cannot add a fact. Output that cites nothing, or cites a fact that is not
// in the bundle, is dropped by Verify before anyone reads it.
//
// # The default is no model
//
// NoModel is the default and it refuses. THN runs on an unattended gateway
// that is not expected to reach the internet, and a build that quietly began
// sending device names and incident details to a third party would be a change
// of posture that nobody voted for. An operator who wants a model configures
// one deliberately, and can see from the audit log that it did.
type Model interface {
	// Name identifies the model in answers and in the audit log.
	Name() string

	// Narrate returns prose describing the facts in the request.
	//
	// The returned text is not trusted. It is passed to Verify, which keeps
	// only sentences citing a fact that exists. A model returning text that
	// fails verification is not an error - it is an empty answer, and the
	// caller falls back to the deterministic path.
	//
	// Implementations must not include the request's facts in a way that lets
	// text outside the bundle be treated as sourced. In practice that means:
	// return prose, and let Verify decide what survives.
	Narrate(ctx context.Context, req Request) (string, error)
}

// Request is what a model is given.
//
// It carries the question and the facts, and nothing else. There is no field
// for host configuration, for a command, or for a filesystem path, because a
// struct with those fields is a struct whose contents will eventually be read
// by something that acts on them.
type Request struct {
	// Question is the operator's words. It is untrusted: it is typed by
	// somebody who may be relaying it from elsewhere, and it is passed as data
	// rather than as instructions.
	Question string `json:"question"`

	// Query is the validated, structured form of the question.
	Query Query `json:"query"`

	// Facts is the rendered fact list. See Bundle.Statements.
	Facts string `json:"facts"`

	// Digest identifies the bundle, so a model can be asked to echo it and a
	// caller can confirm which facts it was given.
	Digest string `json:"digest"`
}

// NoModel is the default. It refuses every request.
type NoModel struct{}

// Name identifies it in the audit log, so that "no model" is visible as a
// deliberate configuration rather than an absence of one.
func (NoModel) Name() string { return "none" }

// Narrate always refuses.
func (NoModel) Narrate(context.Context, Request) (string, error) {
	return "", ErrNoModel
}

// Narrate asks a model for prose and verifies the result, falling back to the
// deterministic answer whenever the model cannot help.
//
// The fallback is the important part. Every failure mode - not configured,
// refused, returned nothing, returned only uncited sentences - produces the
// same useful result: the deterministic answer. There is no path through this
// function that returns less than the deterministic path would have returned
// on its own, which is what makes it safe to leave a model configured on a
// device nobody is watching.
func Narrate(ctx context.Context, m Model, b Bundle, q Query, question string) Answer {
	deterministic, err := Explain(b, q, question)
	if err != nil {
		return Answer{}
	}

	if m == nil {
		return deterministic
	}

	prose, err := m.Narrate(ctx, Request{
		Question: question,
		Query:    deterministic.Query,
		Facts:    b.Statements(),
		Digest:   b.Digest,
	})
	if err != nil {
		// The deterministic answer is already correct and complete. Recording
		// the model's failure is the caller's business, via the audit log; the
		// reader gets an answer either way.
		return deterministic
	}

	kept, dropped := Verify(b, prose)
	if len(kept) == 0 {
		// Nothing survived. The model produced either nothing or something
		// unsourced, and shipping the deterministic answer is both correct and
		// quieter than shipping an apology.
		deterministic.Model = m.Name()
		deterministic.Dropped = append(deterministic.Dropped, dropped...)
		return deterministic
	}

	// The model's prose leads, because asking a question in prose and getting
	// prose back is the whole point of asking. The deterministic claims follow
	// as the complete, unedited version of the same answer, so nothing is lost
	// by preferring the model's phrasing.
	answer := Answer{
		Question: question,
		Query:    deterministic.Query,
		Model:    m.Name(),
		Facts:    deterministic.Facts,
		Digest:   b.Digest,
		Claims:   append(kept, deterministic.Claims...),
		Dropped:  append(dropped, deterministic.Dropped...),
	}
	return VerifyAnswer(b, answer)
}

// ModelName renders a model name for display, so that "none" never appears as
// an empty string implying something was configured and produced nothing.
func ModelName(m Model) string {
	if m == nil {
		return "none (deterministic answers only)"
	}
	name := strings.TrimSpace(m.Name())
	if name == "" {
		return "unnamed model"
	}
	return name
}
