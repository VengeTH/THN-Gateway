package rollback

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/artifact"
	"github.com/VengeTH/THN-Gateway/internal/recovery"
)

// Target is a named point a gateway could be returned to.
//
// # Why a target is identified by digest and not by generation
//
// A generation number says "the third thing anybody wrote". A digest says
// "these exact bytes". Only the second survives the case that matters: a
// configuration is edited, the edit is reverted, the generation counter goes
// up, and now generation 42 holds the content generation 41 used to hold.
//
// When that happens a rollback to "generation 41" goes somewhere the operator
// did not mean, and the fact that it did is discoverable only afterwards. A
// digest makes the two distinguishable at the moment of the request.
//
// The generation is carried alongside the digest so that a rollback can also
// assert "this is the state I was in before generation 43", which is a
// statement about ordering as well as content.
//
// # What this does not do
//
// It selects a target and describes the recovery. It performs nothing.
// `internal/recovery` already computes the recovery steps, and
// `activation.CanApply()` is still false, so there is no path from a decision
// here to a changed host.

// Errors returned when a target cannot be resolved.
var (
	// ErrNoHistory means no target was recorded for this gateway.
	ErrNoHistory = errors.New("rollback: no configuration history for this gateway")

	// ErrTargetNotFound means the named target is not in the history.
	ErrTargetNotFound = errors.New("rollback: no such configuration in this gateway's history")

	// ErrTargetNotVerified means the stored document does not hash to the
	// digest recorded for it.
	//
	// This is the check that makes a history usable. A history that has been
	// corrupted, truncated or written by something else cannot be rolled back
	// to, and discovering that at the moment of recovery is the worst time.
	ErrTargetNotVerified = errors.New("rollback: stored configuration does not match its digest")

	// ErrNoPrevious means the target is the oldest recorded state, so there is
	// nothing to roll back to.
	ErrNoPrevious = errors.New("rollback: no configuration before this one")

	// ErrUnverifiableArtifact means the target's artifact could not be
	// verified against a trusted key.
	//
	// Rolling back to a state whose provenance cannot be established replaces a
	// known-good configuration with an unaccounted-for one. A rollback that
	// cannot be signed is not a rollback.
	ErrUnverifiableArtifact = errors.New("rollback: target artifact is not verifiably signed")
)

// Revision is one recorded configuration state for a gateway.
type Revision struct {
	// Generation is the configuration generation.
	Generation uint64 `json:"generation"`

	// Digest is the SHA-256 of the document.
	Digest string `json:"digest"`

	// Document is the configuration bytes.
	Document []byte `json:"-"`

	// RecordedAt is when it was recorded.
	RecordedAt time.Time `json:"recorded_at"`

	// Source describes where it came from: "local", "artifact", "rollback".
	Source string `json:"source"`

	// KeyID is the signing key, when it came from a signed artifact.
	KeyID string `json:"key_id,omitempty"`
}

// History is a gateway's recorded configurations, oldest first.
type History struct {
	// Gateway is whose history this is.
	Gateway string `json:"gateway"`

	// Revisions are the recorded states.
	Revisions []Revision `json:"revisions"`

	// Applied is the generation currently on the host.
	Applied uint64 `json:"applied"`
}

// Append records a revision.
//
// Rejects a document whose digest does not match the one supplied, rather than
// recording the mismatch and hoping it is noticed. A history that silently
// accepts corrupt entries is a history whose every rollback has to be verified
// anyway.
func (h *History) Append(r Revision) error {
	if got := digestOf(r.Document); got != r.Digest {
		return fmt.Errorf("%w: recorded %s, document hashes to %s",
			ErrTargetNotVerified, r.Digest, got)
	}
	if r.Generation == 0 {
		return fmt.Errorf("%w: generation must be greater than zero", ErrTargetNotVerified)
	}
	if len(h.Revisions) > 0 {
		last := h.Revisions[len(h.Revisions)-1]
		if r.Generation <= last.Generation {
			return fmt.Errorf("rollback: generation %d is not ahead of the recorded %d",
				r.Generation, last.Generation)
		}
	}
	h.Revisions = append(h.Revisions, r)
	return nil
}

// RecordArtifact records a verified artifact as a revision.
//
// It takes an *artifact.Artifact, which is the only way to obtain one, so
// anything recorded here has been through signature verification. That is why
// this exists rather than a method taking a digest and bytes.
func (h *History) RecordArtifact(a *artifact.Artifact) error {
	if a == nil {
		return ErrUnverifiableArtifact
	}
	return h.Append(Revision{
		Generation: a.Meta.Generation,
		Digest:     a.Digest,
		Document:   a.Document,
		RecordedAt: a.Meta.IssuedAt,
		Source:     "artifact",
		KeyID:      a.KeyID,
	})
}

// ByGeneration finds a revision.
func (h *History) ByGeneration(gen uint64) (Revision, bool) {
	for _, r := range h.Revisions {
		if r.Generation == gen {
			return r, true
		}
	}
	return Revision{}, false
}

// Latest returns the most recent revision.
func (h *History) Latest() (Revision, bool) {
	if len(h.Revisions) == 0 {
		return Revision{}, false
	}
	return h.Revisions[len(h.Revisions)-1], true
}

// Previous returns the revision before the applied one.
func (h *History) Previous() (Revision, error) {
	var prior []Revision
	for _, r := range h.Revisions {
		if r.Generation < h.Applied {
			prior = append(prior, r)
		}
	}
	if len(prior) == 0 {
		return Revision{}, fmt.Errorf("%w: nothing is recorded before generation %d",
			ErrNoPrevious, h.Applied)
	}
	sort.Slice(prior, func(i, j int) bool { return prior[i].Generation < prior[j].Generation })
	return prior[len(prior)-1], nil
}

// Plan is a resolved rollback: where to, from where, and how.
type Plan struct {
	// From is the generation currently on the host.
	From uint64 `json:"from"`

	// To is the target generation.
	To uint64 `json:"to"`

	// ToDigest pins the exact bytes being returned to.
	ToDigest string `json:"to_digest"`

	// Artifact is the signed artifact for the target, when one is available.
	//
	// A rollback that carries a verified artifact is one a gateway can accept
	// through the same path as any other change, which means it is authorised
	// by the same floor and refused by the same refusals.
	Artifact *artifact.Artifact `json:"-"`

	// Recovery is what reverting would involve.
	Recovery *recovery.Plan `json:"recovery"`

	// Warnings are things an operator should know before proceeding.
	Warnings []string `json:"warnings,omitempty"`
}

// Runnable reports whether the plan can proceed.
//
// False when the recovery planner found anything blocking, or when the target
// cannot be verified. Both mean the same thing operationally: proceeding would
// put the gateway in a state nobody can describe.
func (p Plan) Runnable() bool {
	if p.Recovery == nil {
		return false
	}
	if len(p.Recovery.Blocking) > 0 {
		return false
	}
	return p.Recovery.Verdict != recovery.VerdictNotRecoverable
}

// Resolve works out what a rollback would do.
//
// target is the generation to return to, or zero for "the one before the
// applied generation". It is resolved and verified before anything is
// described, so that a plan is never produced for a target that turns out to
// be unusable.
func Resolve(h *History, target uint64, recoveryPlan *recovery.Plan, requireSignature bool) (Plan, error) {
	if len(h.Revisions) == 0 {
		return Plan{}, ErrNoHistory
	}

	// target == 0 means "the state before the applied one", which is what an
	// operator means when they say roll back without naming a generation.
	var rev Revision

	switch {
	case target == 0:
		prior, err := h.Previous()
		if err != nil {
			return Plan{}, err
		}
		rev = prior

	default:
		found, ok := h.ByGeneration(target)
		if !ok {
			return Plan{}, fmt.Errorf("%w: generation %d", ErrTargetNotFound, target)
		}
		rev = found
	}

	if rev.Generation == h.Applied {
		return Plan{}, fmt.Errorf("rollback: generation %d is already applied", rev.Generation)
	}
	if rev.Generation > h.Applied {
		return Plan{}, fmt.Errorf(
			"rollback: generation %d is ahead of the applied generation %d; "+
				"that is a rollout, not a rollback",
			rev.Generation, h.Applied)
	}

	// The digest is re-checked here rather than trusted from the record. This
	// is the last moment before a recovery, and it is cheap.
	if got := digestOf(rev.Document); got != rev.Digest {
		return Plan{}, fmt.Errorf("%w: generation %d recorded %s but hashes to %s",
			ErrTargetNotVerified, rev.Generation, rev.Digest, got)
	}

	p := Plan{
		From:     h.Applied,
		To:       rev.Generation,
		ToDigest: rev.Digest,
		Recovery: recoveryPlan,
	}

	if requireSignature && rev.KeyID == "" {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"Generation %d was not produced by a signed artifact (source: %s). "+
				"Rolling back to it puts an unsigned configuration on the host, which "+
				"the gateway's own artifact path will then refuse.",
			rev.Generation, orUnattributed(rev.Source)))
	}

	if recoveryPlan != nil {
		for _, f := range recoveryPlan.Blocking {
			p.Warnings = append(p.Warnings,
				fmt.Sprintf("recovery blocker on %s: %s", f.Step, f.Message))
		}
		if recoveryPlan.Verdict == recovery.VerdictPartiallyRecoverable {
			p.Warnings = append(p.Warnings,
				"some of the changes cannot be undone; see the recovery plan")
		}
		if recoveryPlan.Verdict == recovery.VerdictNotRecoverable {
			p.Warnings = append(p.Warnings,
				"recovery would not restore the prior state at all")
		}
	}

	return p, nil
}

func orUnattributed(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Render formats a plan for a terminal.
func Render(p Plan, err error) string {
	var sb strings.Builder

	if err != nil {
		fmt.Fprintf(&sb, "Rollback not possible\n")
		fmt.Fprintf(&sb, "%s\n\n", strings.Repeat("-", 72))
		fmt.Fprintf(&sb, "%v\n", err)
		return sb.String()
	}

	fmt.Fprintf(&sb, "Rollback: generation %d -> %d\n", p.From, p.To)
	fmt.Fprintf(&sb, "Target digest: %s\n", p.ToDigest)
	fmt.Fprintf(&sb, "Runnable:    %t\n", p.Runnable())
	sb.WriteString(strings.Repeat("-", 72) + "\n")

	if len(p.Warnings) > 0 {
		sb.WriteString("Before proceeding\n\n")
		for _, w := range p.Warnings {
			fmt.Fprintf(&sb, "  - %s\n", w)
		}
		sb.WriteString("\n")
	}

	if p.Recovery != nil {
		fmt.Fprintf(&sb, "Recovery: %s\n", p.Recovery.Verdict)
		for _, s := range p.Recovery.Steps {
			fmt.Fprintf(&sb, "  %-14s %s\n", s.Reversibility, s.Description)
		}
	}

	return sb.String()
}
