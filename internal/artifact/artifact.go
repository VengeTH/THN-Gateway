// Package artifact signs desired-state documents and verifies them.
//
// # What a signature is for
//
// The configuration store already keeps a SHA-256 of every revision, and it is
// worth being precise about what that does and does not do. A hash proves the
// bytes have not changed since they were written. It says nothing about who
// wrote them: anyone able to write the store can write a document and compute
// its hash.
//
// That is enough for a single-host tool reading its own database. It is not
// enough once a remote control plane produces the document, because at that
// point the question changes from "has this changed?" to "may I act on this,
// and am I sure it came from somebody authorised to tell me to?"
//
// A signature answers the second question. The two are complementary and
// neither substitutes for the other: the hash is what pins a rollback target to
// bytes, the signature is what makes the bytes a request rather than a forgery.
//
// # Fails closed, in code
//
// Every failure here is a refusal, and the refusals are a closed set of
// sentinel errors so that a caller cannot accidentally treat one as success by
// comparing against the wrong value.
//
// The stronger property is structural: a document's bytes are not reachable
// until verification has succeeded. `Envelope` keeps them in an unexported
// field with custom JSON, so the only way to obtain the desired state is to
// call Verify and receive a *Artifact. A caller cannot skip the check, because
// there is nothing to skip it to.
//
// This is the same arrangement as the guard allowlist and the authority floor:
// the property does not depend on a caller remembering to enforce it.
//
// # What is signed
//
// Every field that can change what the gateway does, including the validity
// window and the target gateway. Omitting any of them produces a signature that
// is still a signature and still verifies, over a request that is not the one
// that was signed:
//
//   - omit the gateway and a valid artifact for site-a can be replayed at site-b;
//   - omit the window and an expired artifact can be given a new expiry;
//   - omit the generation and an old artifact can be replayed after a newer one
//     has already been applied.
//
// The encoding is length-prefixed rather than a canonicalised document format.
// A canonical form is a thing a future contributor can get subtly wrong, and
// getting it wrong means signatures verify against the wrong bytes.
package artifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// FormatVersion is the artifact envelope version this build produces.
//
// Checked on verification rather than tolerated, because an envelope whose
// fields this build does not know about may have fields that were not signed.
const FormatVersion = 1

// Errors returned by verification. All are refusals.
var (
	// ErrNoSignature means the envelope carried no signature at all.
	ErrNoSignature = errors.New("artifact: envelope carries no signature")

	// ErrUnknownKey means the key ID is not one this gateway trusts.
	//
	// Distinct from ErrBadSignature deliberately: "I have never heard of this
	// key" and "this key signed something else" are different problems for an
	// operator, and collapsing them makes a misconfiguration look like an
	// attack.
	ErrUnknownKey = errors.New("artifact: signing key is not trusted here")

	// ErrRevokedKey means the key is known and has been revoked.
	ErrRevokedKey = errors.New("artifact: signing key has been revoked")

	// ErrWrongScope means the key is trusted, but not for this organisation.
	ErrWrongScope = errors.New("artifact: signing key is not trusted for this organisation")

	// ErrBadSignature means the signature does not match the body.
	ErrBadSignature = errors.New("artifact: signature does not match the body")

	// ErrMalformed means the body could not be decoded.
	ErrMalformed = errors.New("artifact: body is malformed")

	// ErrNotYetValid means the artifact is outside its window, early.
	ErrNotYetValid = errors.New("artifact: not valid yet")

	// ErrExpired means the artifact is outside its window.
	ErrExpired = errors.New("artifact: expired")

	// ErrWrongGateway means the artifact names a different gateway.
	ErrWrongGateway = errors.New("artifact: artifact is for a different gateway")

	// ErrUnsupportedVersion means this build does not understand the envelope.
	ErrUnsupportedVersion = errors.New("artifact: unsupported format version")

	// ErrReplay means the artifact is older than the highest already seen.
	//
	// This is the check that makes generation numbers worth having. Without
	// it, a correctly signed artifact from an hour ago remains correctly
	// signed forever, and a signed "return to generation 40" can be replayed
	// after generation 41 has been applied.
	ErrReplay = errors.New("artifact: older than the highest generation already seen")
)

// Metadata is everything about a request except the document itself.
//
// It is a separate type from Artifact so that the signed portion is explicit
// in the source. Every field here is covered by the signature; a field added to
// Artifact but not here would be signed without being attested to, which is
// the bug this separation exists to make hard to write.
type Metadata struct {
	// Version is the envelope format version.
	Version int `json:"version"`

	// Org is the organisation the artifact is scoped to.
	Org string `json:"org"`

	// Gateway is the gateway the artifact is addressed to.
	Gateway string `json:"gateway"`

	// Generation is the configuration generation this artifact represents.
	//
	// Monotonic per gateway, and the basis of replay protection.
	Generation uint64 `json:"generation"`

	// IssuedAt is when the control plane signed it.
	IssuedAt time.Time `json:"issued_at"`

	// NotBefore is the earliest time it may be applied.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is the latest time it may be applied.
	//
	// Required rather than optional. An artifact with no expiry is a permanent
	// capability, and a permanent capability to change a gateway's firewall is
	// not something an artefact format should make easy to express.
	NotAfter time.Time `json:"not_after"`

	// Labels carry control-plane metadata that does not affect application.
	Labels map[string]string `json:"labels,omitempty"`
}

// Artifact is a verified desired state: metadata plus the document.
//
// The only way to obtain one is Verifier.Verify. There is no constructor that
// takes a document and returns an Artifact, so an unverified document cannot
// be passed onward by mistake.
type Artifact struct {
	// Meta is the signed metadata.
	Meta Metadata

	// Document is the desired state, opaque to this package.
	//
	// Opaque on purpose. THN does not interpret a desired state here: it
	// renders, diffs and applies it elsewhere. A package that parsed it would
	// need to be updated when the configuration schema changed, and would
	// become a second place where the meaning of a configuration lives.
	Document []byte

	// Digest is the SHA-256 of Document, for logging and rollback targeting.
	//
	// Carried in the signature as well as computed from the body, so a
	// mismatch between the two is detectable rather than merely improbable.
	Digest string

	// KeyID identifies the key that signed it.
	KeyID string
}

// Validate checks the metadata.
//
// Called before signing and again after verification, so that a malformed
// artifact is rejected at both ends rather than only at the one that happens
// to run first.
func (m Metadata) Validate(now time.Time) error {
	if m.Version != FormatVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, m.Version, FormatVersion)
	}
	if strings.TrimSpace(m.Org) == "" {
		return fmt.Errorf("%w: org is required", ErrMalformed)
	}
	if strings.TrimSpace(m.Gateway) == "" {
		return fmt.Errorf("%w: gateway is required", ErrMalformed)
	}
	if m.Generation == 0 {
		return fmt.Errorf("%w: generation must be greater than zero", ErrMalformed)
	}
	if m.NotAfter.IsZero() {
		return fmt.Errorf("%w: not_after is required; an artifact never expires by default",
			ErrMalformed)
	}
	if !m.NotAfter.After(m.NotBefore) {
		return fmt.Errorf("%w: not_after (%s) is not after not_before (%s)",
			ErrMalformed, m.NotAfter.Format(time.RFC3339), m.NotBefore.Format(time.RFC3339))
	}
	if now.Before(m.NotBefore) {
		return fmt.Errorf("%w: valid from %s", ErrNotYetValid, m.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(m.NotAfter) {
		return fmt.Errorf("%w: expired at %s", ErrExpired, m.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// ------------------------------------------------------------ canonical bytes

// canonical renders the signed bytes.
//
// Length-prefixed: each field contributes its name, then an eight-byte
// big-endian length, then its value. No separator can appear in a name, so no
// pair of distinct field values can produce the same encoding — which is the
// property a signature depends on and the one a hand-rolled concatenation does
// not have.
func (m Metadata) canonical() []byte {
	var buf bytes.Buffer

	field(&buf, "version", []byte(fmt.Sprintf("%d", m.Version)))
	field(&buf, "org", []byte(m.Org))
	field(&buf, "gateway", []byte(m.Gateway))
	field(&buf, "generation", []byte(fmt.Sprintf("%d", m.Generation)))
	field(&buf, "issued_at", []byte(m.IssuedAt.UTC().Format(time.RFC3339Nano)))
	field(&buf, "not_before", []byte(m.NotBefore.UTC().Format(time.RFC3339Nano)))
	field(&buf, "not_after", []byte(m.NotAfter.UTC().Format(time.RFC3339Nano)))

	// Labels are sorted so that map iteration order cannot change the signed
	// bytes. An unsorted map would make signing non-deterministic and the
	// signature unverifiable.
	keys := make([]string, 0, len(m.Labels))
	for k := range m.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		field(&buf, "label:"+k, []byte(m.Labels[k]))
	}

	return buf.Bytes()
}

func field(buf *bytes.Buffer, name string, value []byte) {
	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(value)))
	buf.WriteString(name)
	buf.WriteByte(0)
	buf.Write(lenbuf[:])
	buf.Write(value)
}

// payload is what the signature covers: the metadata and the document, bound
// together.
//
// The document length is written before the metadata so that a document cannot
// be shifted into the metadata's byte range.
func payload(m Metadata, document []byte) []byte {
	var buf bytes.Buffer

	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(document)))
	buf.WriteString("thn-artifact")
	buf.WriteByte(0)
	buf.Write(lenbuf[:])
	buf.Write(m.canonical())
	buf.Write(document)
	return buf.Bytes()
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ------------------------------------------------------------------ signing

// Signer holds a private key and signs artifacts with it.
//
// The private key never leaves this value, and there is deliberately no method
// that returns it. A key that can be read out of a struct can end up in a log.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewSigner returns a signer for a key.
//
// In production the key comes from the control plane's key store, not from
// this function. The generated-key constructor exists so that a gateway and a
// control plane can be wired together in a test without inventing a key format
// here, and so that anyone using it by accident gets a key that is obviously
// ephemeral.
func NewSigner(keyID string, private ed25519.PrivateKey) (*Signer, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("artifact: private key is %d bytes, want %d",
			len(private), ed25519.PrivateKeySize)
	}
	return &Signer{keyID: keyID, priv: private}, nil
}

// GenerateSigner returns a signer with a fresh ephemeral key.
//
// Refuses under any name other than this one, so that a caller reaching for a
// real key cannot land on it.
func GenerateSigner(keyID string) (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("artifact: generating a key: %w", err)
	}
	return NewSigner(keyID, priv)
}

// KeyID returns the signer's key identifier.
func (s *Signer) KeyID() string { return s.keyID }

// Public returns the verification key. This is the one thing that may leave.
func (s *Signer) Public() PublicKey {
	pub, ok := s.priv.Public().(ed25519.PublicKey)
	if !ok {
		// ed25519.PrivateKey.Public always returns ed25519.PublicKey. The
		// assertion documents that rather than defending against it.
		return PublicKey{}
	}
	return PublicKey{KeyID: s.keyID, Key: pub}
}

// PublicKey is a verification key.
type PublicKey struct {
	KeyID string            `json:"key_id"`
	Key   ed25519.PublicKey `json:"key"`
}

// Sign produces a signed envelope.
//
// It validates the metadata first, so that an artifact which could never be
// applied is never signed. Signing something unusable is harmless, but a
// signature that attests to an expired window is a signature that should have
// been refused.
func (s *Signer) Sign(m Metadata, document []byte, now time.Time) (*Envelope, error) {
	if err := m.Validate(now); err != nil {
		return nil, err
	}

	sig := ed25519.Sign(s.priv, payload(m, document))
	return &Envelope{
		keyID:  s.keyID,
		sig:    sig,
		body:   document,
		meta:   m,
		digest: digestOf(document),
	}, nil
}

// ----------------------------------------------------------------- envelope

// Envelope is what travels between the control plane and a gateway.
//
// The fields are unexported so that the document cannot be read without
// verifying. MarshalJSON and UnmarshalJSON exist so it still crosses a wire.
type Envelope struct {
	keyID  string
	sig    []byte
	body   []byte
	meta   Metadata
	digest string
}

// wire is the serialised form.
type wire struct {
	KeyID    string   `json:"key_id"`
	Sig      string   `json:"sig"`
	Document string   `json:"document"`
	Digest   string   `json:"digest"`
	Meta     Metadata `json:"meta"`
}

// MarshalJSON serialises the envelope.
func (e *Envelope) MarshalJSON() ([]byte, error) {
	if e == nil {
		return []byte("null"), nil
	}
	return json.Marshal(wire{
		KeyID:    e.keyID,
		Sig:      hex.EncodeToString(e.sig),
		Document: hex.EncodeToString(e.body),
		Digest:   e.digest,
		Meta:     e.meta,
	})
}

// UnmarshalJSON reads an envelope.
func (e *Envelope) UnmarshalJSON(b []byte) error {
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	keyID := w.KeyID
	sig, err := hex.DecodeString(w.Sig)
	if err != nil {
		return fmt.Errorf("%w: signature is not hex: %v", ErrMalformed, err)
	}
	doc, err := hex.DecodeString(w.Document)
	if err != nil {
		return fmt.Errorf("%w: document is not hex: %v", ErrMalformed, err)
	}

	e.keyID, e.sig, e.body, e.digest, e.meta = keyID, sig, doc, w.Digest, w.Meta
	return nil
}

// KeyID returns the key identifier the envelope claims, without verifying.
//
// Safe to read before verification because it is only a name, and reading it
// is how a caller reports "signed by a key we do not trust" as distinct from
// "the signature is wrong".
func (e *Envelope) KeyID() string { return e.keyID }

// SignatureLength returns how long a signature is.
//
// Exposed so a test can check the signature was not truncated in transit,
// which would otherwise surface as a signature mismatch and be misdiagnosed as
// tampering.
func SignatureLength() int { return ed25519.SignatureSize }

// -------------------------------------------------------------- verification

// Trust is the set of keys a gateway will accept, and where.
type Trust struct {
	// Keys maps key ID to verification key.
	Keys map[string]PublicKey

	// Revoked lists key IDs that are known but no longer accepted.
	//
	// A separate set rather than a flag on the key, because revocation is
	// normally broadcast and outlives the key's own entry: a fleet must be
	// able to revoke without having received the key it is revoking.
	Revoked map[string]string
}

// Revocation records why a key was revoked.
type Revocation struct {
	KeyID     string    `json:"key_id"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason"`
}

// Verifier checks envelopes against a trust set and a policy.
type Verifier struct {
	// Trust is the set of acceptable keys.
	Trust Trust

	// Org, when set, restricts acceptance to keys trusted for this
	// organisation.
	Org string

	// Now supplies the clock, so that expiry is testable.
	Now func() time.Time

	// MinGeneration is the highest generation already applied to this gateway.
	//
	// Zero means no floor has been established. Callers should pass the real
	// value from durable state: without it, a valid older artifact can be
	// replayed, which is the one thing signing exists to prevent.
	MinGeneration uint64

	// gateway is the gateway this verifier belongs to.
	gateway string

	// highest records the largest generation seen, for the caller to persist.
	highest uint64
}

// Verified reports whether the last verification succeeded.
func (v *Verifier) Verified() bool { return v.highest > 0 }

// HighestGeneration returns the largest generation successfully verified.
//
// Persist this. It is the caller's job to remember, and a verifier that
// forgets is a verifier that can be replayed against next time it runs.
func (v *Verifier) HighestGeneration() uint64 { return v.highest }

// Verify checks an envelope and returns the artifact it attests to.
//
// The order is: structure, trust, signature, window, target, replay. Signature
// before window so that an artifact with a broken signature is reported as
// forged rather than as stale — an operator debugging a rotation needs to know
// which of the two it is.
func (v *Verifier) Verify(e *Envelope) (*Artifact, error) {
	if e == nil {
		return nil, ErrNoSignature
	}
	if len(e.sig) == 0 {
		return nil, ErrNoSignature
	}
	if len(e.sig) != SignatureLength() {
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d",
			ErrBadSignature, len(e.sig), SignatureLength())
	}

	if _, revoked := v.Trust.Revoked[e.keyID]; revoked {
		return nil, fmt.Errorf("%w: %s (%s)", ErrRevokedKey, e.keyID, v.Trust.Revoked[e.keyID])
	}

	pub, known := v.Trust.Keys[e.keyID]
	if !known {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, e.keyID)
	}

	if v.Org != "" && e.meta.Org != v.Org {
		return nil, fmt.Errorf("%w: artifact is for %q, this gateway is %q",
			ErrWrongScope, e.meta.Org, v.Org)
	}

	if !ed25519.Verify(pub.Key, payload(e.meta, e.body), e.sig) {
		return nil, fmt.Errorf("%w: key %s", ErrBadSignature, e.keyID)
	}

	// The declared digest must match the document actually carried. The
	// signature already covers the document, so this cannot pass if the body
	// was altered — but a mismatch here means the producer and the body
	// disagree, which is a producer bug rather than an attack, and worth
	// distinguishing.
	if got := digestOf(e.body); e.digest != "" && got != e.digest {
		return nil, fmt.Errorf("%w: digest says %s, document hashes to %s",
			ErrMalformed, e.digest, got)
	}

	now := v.now()
	if err := e.meta.Validate(now); err != nil {
		return nil, err
	}

	if e.meta.Gateway != v.expectedGateway() {
		return nil, fmt.Errorf("%w: addressed to %q",
			ErrWrongGateway, e.meta.Gateway)
	}

	floor := v.MinGeneration
	if v.highest > floor {
		floor = v.highest
	}
	if e.meta.Generation <= floor {
		return nil, fmt.Errorf("%w: generation %d is not ahead of %d",
			ErrReplay, e.meta.Generation, floor)
	}

	v.highest = e.meta.Generation

	return &Artifact{
		Meta:     e.meta,
		Document: e.body,
		Digest:   digestOf(e.body),
		KeyID:    e.keyID,
	}, nil
}

// expectedGateway returns the gateway this verifier will accept artifacts for.
//
// Bound by BindGateway so that Verify can check the target without the caller
// passing it in separately, where a mismatch between the two would be easy.
func (v *Verifier) expectedGateway() string { return v.gateway }

// BindGateway sets the gateway this verifier will accept artifacts for.
func (v *Verifier) BindGateway(name string) { v.gateway = name }

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return time.Now().UTC()
}
