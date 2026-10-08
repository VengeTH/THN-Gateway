package rollback_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/artifact"
	"github.com/VengeTH/THN-Gateway/internal/recovery"
	"github.com/VengeTH/THN-Gateway/internal/rollback"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// historyWith builds a history of generations 40..applied, all unsigned.
func historyWith(applied uint64) *rollback.History {
	h := &rollback.History{Gateway: "site-001", Applied: applied}
	for g := uint64(40); g <= applied; g++ {
		doc := "gen " + string(rune('0'+g%10))
		if err := h.Append(rollback.Revision{
			Generation: g,
			Digest:     digest(doc),
			Document:   []byte(doc),
			RecordedAt: now,
			Source:     "local",
		}); err != nil {
			panic(err)
		}
	}
	return h
}

func recoverable() *recovery.Plan {
	return &recovery.Plan{
		ID:          "rec-1",
		Verdict:     recovery.VerdictRecoverable,
		GeneratedAt: now,
		Steps: []recovery.Step{{
			ID: "s1", Description: "restore the uplink", Target: "link",
			Reversibility: recovery.Reversible, RestoreFrom: "down",
		}},
	}
}

// --------------------------------------------------- digest over generation

// A generation number says "the third thing anybody wrote". It cannot tell two
// states apart when a config is edited and reverted, because the counter goes up
// while the content goes back. A digest can.
func TestTargetIsPinnedByDigestNotJustGeneration(t *testing.T) {
	h := historyWith(42)
	p, err := rollback.Resolve(h, 41, recoverable(), false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	target, _ := h.ByGeneration(41)
	if p.ToDigest != target.Digest {
		t.Errorf("ToDigest = %s, want the target's digest %s", p.ToDigest, target.Digest)
	}
	if p.To != 41 {
		t.Errorf("To = %d, want 41", p.To)
	}
}

// ------------------------------------------------------------- refusals

func TestNoHistoryIsRefused(t *testing.T) {
	h := &rollback.History{Gateway: "site-001"}
	if _, err := rollback.Resolve(h, 0, nil, false); !errors.Is(err, rollback.ErrNoHistory) {
		t.Errorf("got %v, want ErrNoHistory", err)
	}
}

func TestUnknownTargetIsRefused(t *testing.T) {
	h := historyWith(42)
	if _, err := rollback.Resolve(h, 99, recoverable(), false); !errors.Is(err, rollback.ErrTargetNotFound) {
		t.Errorf("got %v, want ErrTargetNotFound", err)
	}
}

// Rolling forward is a rollout, not a rollback, and saying so is more useful
// than computing a plan that goes nowhere.
func TestForwardTargetIsRefused(t *testing.T) {
	h := historyWith(42)
	_, err := rollback.Resolve(h, 0, recoverable(), false)

	h.Applied = 40
	if _, err := rollback.Resolve(h, 42, recoverable(), false); err == nil {
		t.Fatal("a forward target was accepted as a rollback")
	} else if !strings.Contains(err.Error(), "rollout, not a rollback") {
		t.Errorf("the refusal does not say what it actually is: %v", err)
	}
	_ = err
}

func TestNoPreviousGenerationIsRefused(t *testing.T) {
	h := &rollback.History{Gateway: "site-001", Applied: 1}
	if err := h.Append(rollback.Revision{
		Generation: 1, Digest: digest("only"), Document: []byte("only"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rollback.Resolve(h, 0, nil, false); !errors.Is(err, rollback.ErrNoPrevious) {
		t.Errorf("got %v, want ErrNoPrevious", err)
	}
}

// ------------------------------------------------- corruption is detected

// Discovering that the history is corrupt at the moment of recovery is the
// worst possible time. It is therefore checked before a plan is produced.
func TestCorruptedHistoryIsRefusedBeforeAPlanIsProduced(t *testing.T) {
	h := historyWith(42)
	h.Revisions[1].Document = []byte("tampered")

	if _, err := rollback.Resolve(h, 41, recoverable(), false); !errors.Is(err, rollback.ErrTargetNotVerified) {
		t.Errorf("got %v, want ErrTargetNotVerified", err)
	}
}

// A history that quietly accepts a corrupt entry is a history whose every
// rollback has to be verified anyway.
func TestAppendRejectsAMismatchedDigest(t *testing.T) {
	h := &rollback.History{}
	err := h.Append(rollback.Revision{
		Generation: 1, Digest: digest("what I meant"), Document: []byte("what I wrote"),
	})
	if !errors.Is(err, rollback.ErrTargetNotVerified) {
		t.Errorf("got %v, want ErrTargetNotVerified", err)
	}
}

func TestAppendRejectsNonMonotonicGenerations(t *testing.T) {
	h := historyWith(42)
	err := h.Append(rollback.Revision{
		Generation: 41, Digest: digest("old"), Document: []byte("old"),
	})
	if err == nil {
		t.Fatal("a generation behind the recorded one was accepted")
	}
}

// ------------------------------------------------------------- signature

// Rolling back to a state whose provenance cannot be established replaces a
// known-good configuration with an unaccounted-for one.
func TestUnsignedTargetIsWarnedAboutWhenSignatureIsRequired(t *testing.T) {
	h := historyWith(42)
	p, err := rollback.Resolve(h, 41, recoverable(), true)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	joined := strings.Join(p.Warnings, " ")
	if !strings.Contains(joined, "not produced by a signed artifact") {
		t.Errorf("no warning about the unsigned target: %v", p.Warnings)
	}
	if !strings.Contains(joined, "will then refuse") {
		t.Errorf("the warning does not say the gateway will refuse it: %v", p.Warnings)
	}
}

// A target that came from a verified artifact carries its provenance through.
func TestArtifactBackedTargetCarriesProvenance(t *testing.T) {
	signer, err := artifact.GenerateSigner("key-1")
	if err != nil {
		t.Fatal(err)
	}

	meta := artifact.Metadata{
		Version: artifact.FormatVersion, Org: "acme", Gateway: "site-001",
		Generation: 41, IssuedAt: now,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
	}
	env, err := signer.Sign(meta, []byte("wan: enp0s31f6"), now)
	if err != nil {
		t.Fatal(err)
	}

	v := &artifact.Verifier{
		Trust: artifact.Trust{Keys: map[string]artifact.PublicKey{
			signer.Public().KeyID: signer.Public(),
		}},
		Org: "acme", Now: func() time.Time { return now },
	}
	v.BindGateway("site-001")

	verified, err := v.Verify(env)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	h := &rollback.History{Gateway: "site-001", Applied: 42}
	if err := h.RecordArtifact(verified); err != nil {
		t.Fatalf("RecordArtifact: %v", err)
	}

	// 41 is the artifact, so the recorded target is signed.
	p, err := rollback.Resolve(h, 41, recoverable(), true)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "not produced by a signed artifact") {
			t.Errorf("a signed target was warned about as unsigned: %v", p.Warnings)
		}
	}
}

// Nothing but Verify produces an *artifact.Artifact, so anything recorded via
// RecordArtifact has been through verification.
func TestRecordArtifactRejectsNil(t *testing.T) {
	h := &rollback.History{}
	if err := h.RecordArtifact(nil); !errors.Is(err, rollback.ErrUnverifiableArtifact) {
		t.Errorf("got %v, want ErrUnverifiableArtifact", err)
	}
}

// -------------------------------------------------------------- runnable

// A plan the gateway cannot execute is a plan nobody should run.
func TestPlanIsNotRunnableWithBlockingFindings(t *testing.T) {
	rec := recoverable()
	rec.Blocking = []recovery.Finding{{
		Step: "s2", Severity: "error", Message: "the prior qdisc cannot be reinstated",
	}}

	h := historyWith(42)
	p, err := rollback.Resolve(h, 41, rec, false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Runnable() {
		t.Error("a plan with blocking findings reported itself runnable")
	}
	if len(p.Warnings) == 0 {
		t.Error("the blocking finding was not surfaced as a warning")
	}
}

func TestPlanIsNotRunnableWithNoRecoveryPlan(t *testing.T) {
	h := historyWith(42)
	p, err := rollback.Resolve(h, 41, nil, false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Runnable() {
		t.Error("a plan with no recovery plan reported itself runnable")
	}
}

func TestRecoverablePlanIsRunnable(t *testing.T) {
	h := historyWith(42)
	p, err := rollback.Resolve(h, 41, recoverable(), false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !p.Runnable() {
		t.Errorf("a recoverable plan reported itself un-runnable: %s", rollback.Render(p, nil))
	}
}
