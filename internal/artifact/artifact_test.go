package artifact_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/artifact"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func meta(gen uint64) artifact.Metadata {
	return artifact.Metadata{
		Version:    artifact.FormatVersion,
		Org:        "acme",
		Gateway:    "site-001",
		Generation: gen,
		IssuedAt:   now,
		NotBefore:  now.Add(-time.Minute),
		NotAfter:   now.Add(time.Hour),
	}
}

func signer(t *testing.T) *artifact.Signer {
	t.Helper()
	return signerNamed(t, "key-1")
}

func signerNamed(t *testing.T, id string) *artifact.Signer {
	t.Helper()
	s, err := artifact.GenerateSigner(id)
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	return s
}

func trusted(s *artifact.Signer) artifact.Trust {
	return artifact.Trust{
		Keys:    map[string]artifact.PublicKey{s.Public().KeyID: s.Public()},
		Revoked: map[string]string{},
	}
}

func verifierFor(s *artifact.Signer, org string) *artifact.Verifier {
	v := &artifact.Verifier{
		Trust: trusted(s),
		Org:   org,
		Now:   func() time.Time { return now },
	}
	v.BindGateway("site-001")
	return v
}

func signed(t *testing.T, s *artifact.Signer, m artifact.Metadata, doc string) *artifact.Envelope {
	t.Helper()
	e, err := s.Sign(m, []byte(doc), now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return e
}

// ------------------------------------------------------------- round trip

func TestSignAndVerifyRoundTrip(t *testing.T) {
	s := signer(t)
	e := signed(t, s, meta(41), "wan: enp0s31f6")

	a, err := verifierFor(s, "acme").Verify(e)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(a.Document) != "wan: enp0s31f6" {
		t.Errorf("document = %q", a.Document)
	}
	if a.Meta.Generation != 41 {
		t.Errorf("generation = %d", a.Meta.Generation)
	}
	if a.KeyID != "key-1" {
		t.Errorf("key = %q", a.KeyID)
	}
}

// An envelope has to survive the wire, or signing is only useful in-process.
func TestEnvelopeSurvivesJSON(t *testing.T) {
	s := signer(t)
	e := signed(t, s, meta(41), "wan: enp0s31f6")

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back artifact.Envelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	a, err := verifierFor(s, "acme").Verify(&back)
	if err != nil {
		t.Fatalf("a deserialised envelope failed verification: %v", err)
	}
	if string(a.Document) != "wan: enp0s31f6" {
		t.Errorf("document survived the wire as %q", a.Document)
	}
}

// ---------------------------------------------------------------- refusals

// A tampered document must not verify.
func TestTamperedDocumentIsRefused(t *testing.T) {
	s := signer(t)
	e := signed(t, s, meta(41), "wan: enp0s31f6")

	// Re-serialise with a different document, keeping the original signature.
	b, _ := json.Marshal(e)
	var w map[string]any
	_ = json.Unmarshal(b, &w)
	w["document"] = "ff" + w["document"].(string)[2:] // same length, one byte changed
	tampered, _ := json.Marshal(w)

	var back artifact.Envelope
	if err := json.Unmarshal(tampered, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if _, err := verifierFor(s, "acme").Verify(&back); !errors.Is(err, artifact.ErrBadSignature) {
		t.Errorf("a tampered document verified: %v", err)
	}
}

// A tampered generation must not verify. This is why generation is signed:
// otherwise a valid artifact can be presented as a newer one.
func TestTamperedGenerationIsRefused(t *testing.T) {
	s := signer(t)
	e := signed(t, s, meta(41), "wan: enp0s31f6")

	b, _ := json.Marshal(e)
	var w map[string]any
	_ = json.Unmarshal(b, &w)
	m := w["meta"].(map[string]any)
	m["generation"] = 999
	tampered, _ := json.Marshal(w)

	var back artifact.Envelope
	_ = json.Unmarshal(tampered, &back)

	if _, err := verifierFor(s, "acme").Verify(&back); err == nil {
		t.Fatal("a tampered generation verified")
	}
}

// A tampered expiry must not verify. An artifact that could be given a new
// expiry after signing is a permanent capability.
func TestTamperedWindowIsRefused(t *testing.T) {
	s := signer(t)
	e := signed(t, s, meta(41), "doc")

	b, _ := json.Marshal(e)
	var w map[string]any
	_ = json.Unmarshal(b, &w)
	m := w["meta"].(map[string]any)
	m["not_after"] = now.Add(10000 * time.Hour).Format(time.RFC3339Nano)
	tampered, _ := json.Marshal(w)

	var back artifact.Envelope
	_ = json.Unmarshal(tampered, &back)

	if _, err := verifierFor(s, "acme").Verify(&back); err == nil {
		t.Fatal("an extended validity window verified")
	}
}

// A tampered gateway must not verify. Otherwise a valid artifact for one
// gateway can be presented to another.
func TestTamperedGatewayIsRefused(t *testing.T) {
	s := signer(t)
	e := signed(t, s, meta(41), "doc")

	b, _ := json.Marshal(e)
	var w map[string]any
	_ = json.Unmarshal(b, &w)
	m := w["meta"].(map[string]any)
	m["gateway"] = "site-999"
	tampered, _ := json.Marshal(w)

	var back artifact.Envelope
	_ = json.Unmarshal(tampered, &back)

	if _, err := verifierFor(s, "acme").Verify(&back); err == nil {
		t.Fatal("a re-addressed artifact verified")
	}
}

func TestUnknownKeyIsRefusedAndDistinctFromBadSignature(t *testing.T) {
	s := signerNamed(t, "key-1")
	other := signerNamed(t, "key-2")
	e := signed(t, other, meta(41), "doc")

	_, err := verifierFor(s, "acme").Verify(e)
	if !errors.Is(err, artifact.ErrUnknownKey) {
		t.Fatalf("got %v, want ErrUnknownKey", err)
	}
	if errors.Is(err, artifact.ErrBadSignature) {
		t.Error("an unknown key was reported as a bad signature; those are different problems")
	}
}

func TestRevokedKeyIsRefused(t *testing.T) {
	s := signer(t)
	e := signed(t, s, meta(41), "doc")

	v := verifierFor(s, "acme")
	v.Trust.Revoked["key-1"] = "rotated out on 2026-09-01"

	if _, err := v.Verify(e); !errors.Is(err, artifact.ErrRevokedKey) {
		t.Fatalf("got %v, want ErrRevokedKey", err)
	}
}

// A key trusted for one organisation must not sign for another.
func TestWrongScopeIsRefused(t *testing.T) {
	s := signer(t)
	e := signed(t, s, meta(41), "doc")

	if _, err := verifierFor(s, "other-co").Verify(e); !errors.Is(err, artifact.ErrWrongScope) {
		t.Fatalf("got %v, want ErrWrongScope", err)
	}
}

func TestUnsignedEnvelopeIsRefused(t *testing.T) {
	var e artifact.Envelope
	if _, err := verifierFor(signer(t), "acme").Verify(&e); !errors.Is(err, artifact.ErrNoSignature) {
		t.Fatalf("got %v, want ErrNoSignature", err)
	}
	if _, err := verifierFor(signer(t), "acme").Verify(nil); !errors.Is(err, artifact.ErrNoSignature) {
		t.Fatalf("a nil envelope gave %v", err)
	}
}

// The window is checked at both ends. Signing refuses to attest to something
// already unusable, and verification refuses one that has since gone stale —
// so the two checks are genuinely independent.
func TestExpiredAndNotYetValid(t *testing.T) {
	s := signer(t)
	v := verifierFor(s, "acme")

	// Signed while valid, then verified after it has expired.
	m := meta(41)
	m.NotBefore = now.Add(-2 * time.Hour)
	m.NotAfter = now.Add(-time.Hour)
	if _, err := s.Sign(m, []byte("doc"), m.NotBefore); err != nil {
		t.Fatalf("signing an in-window artifact failed: %v", err)
	}
	env, err := s.Sign(m, []byte("doc"), m.NotBefore)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := v.Verify(env); !errors.Is(err, artifact.ErrExpired) {
		t.Errorf("got %v, want ErrExpired", err)
	}

	// Signing something already expired is refused outright: a signature that
	// attests to an unusable artifact is a signature that should not exist.
	if _, err := s.Sign(m, []byte("doc"), now); !errors.Is(err, artifact.ErrExpired) {
		t.Errorf("signing an expired artifact gave %v, want ErrExpired", err)
	}

	// Not yet valid. Modelled as clock skew: the control plane signs at 13:00
	// for a window opening at 13:00, and the gateway's clock reads 12:00. This
	// is the real shape of the failure — signing before its own window opens
	// is refused, so the gateway is the one whose clock is behind.
	future := meta(42)
	future.NotBefore = now.Add(time.Hour)
	future.NotAfter = now.Add(2 * time.Hour)

	fe, err := s.Sign(future, []byte("doc"), future.NotBefore)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	behind := verifierFor(s, "acme")
	behind.Now = func() time.Time { return now } // an hour early

	if _, err := behind.Verify(fe); !errors.Is(err, artifact.ErrNotYetValid) {
		t.Errorf("got %v, want ErrNotYetValid", err)
	}
}

// An artifact with no expiry is a permanent capability to change a firewall.
func TestArtifactWithoutAnExpiryIsRefused(t *testing.T) {
	s := signer(t)
	m := meta(41)
	m.NotAfter = time.Time{}

	if _, err := s.Sign(m, []byte("doc"), now); err == nil {
		t.Fatal("an artifact with no expiry was signed")
	}
}

// ---------------------------------------------------------------- replay

// Signing does not prevent replay on its own; generation does. Without a floor
// a correctly signed old artifact stays correctly signed forever.
func TestOlderGenerationIsRefusedAfterANewerOne(t *testing.T) {
	s := signer(t)
	v := verifierFor(s, "acme")

	newer := signed(t, s, meta(41), "doc")
	if _, err := v.Verify(newer); err != nil {
		t.Fatalf("generation 41: %v", err)
	}

	older := signed(t, s, meta(40), "older doc")
	if _, err := v.Verify(older); !errors.Is(err, artifact.ErrReplay) {
		t.Errorf("got %v, want ErrReplay", err)
	}

	if v.HighestGeneration() != 41 {
		t.Errorf("HighestGeneration = %d, want 41", v.HighestGeneration())
	}
}

// The floor must also come from durable state, not only from this process's
// memory: a gateway that restarts must not forget what it already applied.
func TestMinGenerationIsHonoured(t *testing.T) {
	s := signer(t)
	v := verifierFor(s, "acme")
	v.MinGeneration = 50

	e := signed(t, s, meta(41), "doc")
	if _, err := v.Verify(e); !errors.Is(err, artifact.ErrReplay) {
		t.Errorf("got %v, want ErrReplay against a persisted floor of 50", err)
	}

	fresh := signed(t, s, meta(51), "doc")
	if _, err := v.Verify(fresh); err != nil {
		t.Errorf("a generation above the floor was refused: %v", err)
	}
}

// An artifact addressed to another gateway must not apply here.
func TestWrongGatewayIsRefused(t *testing.T) {
	s := signer(t)
	m := meta(41)
	m.Gateway = "site-002"
	e := signed(t, s, m, "doc")

	if _, err := verifierFor(s, "acme").Verify(e); !errors.Is(err, artifact.ErrWrongGateway) {
		t.Fatalf("got %v, want ErrWrongGateway", err)
	}
}

// ----------------------------------------------------------- determinism

// Label order comes from a map, and an unsorted map would make signing
// non-deterministic — the signature would verify against bytes that no longer
// exist the next time round.
func TestSigningIsDeterministicAcrossLabelOrder(t *testing.T) {
	s := signer(t)

	a := meta(41)
	a.Labels = map[string]string{"b": "2", "a": "1", "c": "3"}

	b := meta(41)
	b.Labels = map[string]string{"c": "3", "a": "1", "b": "2"}

	ea, err := s.Sign(a, []byte("doc"), now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	eb, err := s.Sign(b, []byte("doc"), now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ja, _ := json.Marshal(ea)
	jb, _ := json.Marshal(eb)
	if string(ja) != string(jb) {
		t.Errorf("the same content signed to different bytes:\n%s\n%s", ja, jb)
	}
}

// Every refusal must be an error from the closed set, and each must say what
// it is. A refusal whose reason is empty is a refusal nobody can act on.
func TestEveryRefusalExplainsItself(t *testing.T) {
	s := signer(t)
	v := verifierFor(s, "acme")

	cases := []struct {
		name string
		env  *artifact.Envelope
		want error
	}{
		{"unsigned", &artifact.Envelope{}, artifact.ErrNoSignature},
		{"unknown key", signed(t, signerNamed(t, "key-2"), meta(41), "doc"),
			artifact.ErrUnknownKey},
		{"wrong gateway", signed(t, s, metaWithGateway(t, 41, "elsewhere"), "doc"),
			artifact.ErrWrongGateway},
	}

	for _, c := range cases {
		_, err := v.Verify(c.env)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
			continue
		}
		if !strings.Contains(err.Error(), "") || err.Error() == "" {
			t.Errorf("%s: the refusal carries no detail", c.name)
		}
	}
}

func metaWithGateway(t *testing.T, gen uint64, gw string) artifact.Metadata {
	t.Helper()
	m := meta(gen)
	m.Gateway = gw
	return m
}
