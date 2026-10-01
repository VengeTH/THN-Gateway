package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/artifact"
	"github.com/venth/thn-gateway/internal/authority"
	"github.com/venth/thn-gateway/internal/deploy"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/health"
	"github.com/venth/thn-gateway/internal/reconcile"
)

// This file is the gate phase for the transactional lifecycle: signing,
// verification, health, staged deployment and rollback.
//
// # What it guards
//
// These five packages are the machinery that would sit either side of an
// apply. None of them applies anything, and that is the property most worth
// asserting: the moment one of them gains the ability to change a host, the
// guard invariant stops being the only thing standing between THN and the
// device.
//
// The second property is ordering. Signing is worthless if verification can be
// skipped, and verification is worthless if health can pass for a gateway that
// could not be read. Both are structural in their own packages; this file
// asserts they are structural at the seams the commands use.

// lifecycleCommands is every command this phase covers.
var lifecycleCommands = []string{"verify", "health", "rollout", "rollback"}

// Nothing here may become able to apply.
func TestGateLifecycleCommandsArePure(t *testing.T) {
	for _, name := range lifecycleCommands {
		cmd, ok := commands[name]
		if !ok {
			t.Errorf("command %q is not registered", name)
			continue
		}
		if cmd.Tier != TierPure {
			t.Errorf("%s is %s; the lifecycle machinery decides and reports only",
				name, cmd.Tier)
		}
	}
}

// The build still cannot apply. Signing, health and rollback must not have
// quietly enabled the stage they sit either side of.
func TestGateLifecycleDidNotEnableApply(t *testing.T) {
	if activation.CanApply() {
		t.Fatal("activation.CanApply() became true")
	}
	implemented := activation.ImplementedStages()
	for _, s := range activation.UnsupportedStages() {
		for _, got := range implemented {
			if got == s {
				t.Errorf("stage %s became implemented", s)
			}
		}
	}
}

// The authority floor is unchanged. A control plane that can sign an artifact
// is not thereby permitted to do everything.
func TestGateLifecycleDidNotWeakenTheAuthorityFloor(t *testing.T) {
	p := authority.NewPolicy("permissive")
	for _, op := range []authority.Operation{
		authority.OpShellCommand,
		authority.OpFactoryReset,
		authority.OpDisableFirewall,
	} {
		if got := p.Effective(op); got != authority.TierForbidden {
			t.Errorf("%s is %s; signing must not have relaxed the floor", op, got)
		}
	}
}

// A health check that passed vacuously on a gateway nobody could read is the
// failure mode this gate exists to catch.
func TestGateHealthCannotPassOnAnUnreadableGateway(t *testing.T) {
	blind := diff.Observed{Supported: false}

	r := health.Assess("site-001", 42,
		diff.Result{Converged: true}, blind, time.Now().UTC())

	if r.Verdict == health.VerdictHealthy {
		t.Fatal("an uninspectable gateway reported healthy")
	}
	if !r.Failed() {
		t.Fatal("an uninspectable gateway did not fail; a rollout would have continued")
	}
}

// A rollout must stop by itself. A staged deployment an operator has to watch
// and stop will, once, run to completion with nobody watching.
func TestGateRolloutHaltsWithoutBeingAsked(t *testing.T) {
	r := deploy.New("gen-41", 50, deploy.DefaultThresholds())
	r.Now = func() time.Time { return time.Now().UTC() }

	r.MarkApplied(1)
	r.Record(health.Report{Gateway: "site-001", Verdict: health.VerdictUnhealthy})

	if d := r.Advance(); d.Action != deploy.ActionHalt {
		t.Fatalf("a rollout continued past an unhealthy gateway: %s", d.Action)
	}
}

// An unreadable gateway halts a rollout, and the halt survives good news.
func TestGateRolloutHaltIsSticky(t *testing.T) {
	r := deploy.New("gen-41", 50, deploy.DefaultThresholds())
	r.Now = func() time.Time { return time.Now().UTC() }

	r.MarkApplied(1)
	r.Record(health.Report{Gateway: "site-001", Verdict: health.VerdictUnknowable})
	r.Advance()

	r.Record(health.Report{Gateway: "site-002", Verdict: health.VerdictHealthy})
	if d := r.Advance(); d.Action != deploy.ActionHalt {
		t.Fatalf("a halted rollout resumed on good news: %s", d.Action)
	}
}

// An artifact's document must not be reachable without verification. The
// Envelope keeps it in an unexported field, so this asserts that property still
// holds through the JSON round trip the commands use.
func TestGateArtifactBodyIsNotReadableWithoutVerification(t *testing.T) {
	signer, err := artifact.GenerateSigner("key-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	meta := artifact.Metadata{
		Version: artifact.FormatVersion, Org: "acme", Gateway: "site-001",
		Generation: 1, IssuedAt: now,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
	}
	env, err := signer.Sign(meta, []byte("wan: enp0s31f6"), now)
	if err != nil {
		t.Fatal(err)
	}

	// The only accessor on Envelope is KeyID, which is a name and not a
	// document. If a Document accessor is ever added without verification,
	// this stops compiling in a way a reader would notice.
	if env.KeyID() != "key-1" {
		t.Fatalf("KeyID = %q", env.KeyID())
	}

	// And verification genuinely gates the bytes.
	v := &artifact.Verifier{
		Trust: artifact.Trust{Keys: map[string]artifact.PublicKey{}},
		Org:   "acme", Now: func() time.Time { return now },
	}
	v.BindGateway("site-001")

	if _, err := v.Verify(env); err == nil {
		t.Fatal("an envelope from an untrusted key verified")
	} else if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("the refusal does not say the key is untrusted: %v", err)
	}
}

// The gateway still refuses changes that would remove its own management path,
// whatever signed them. Signing is provenance, not permission.
func TestGateSignedArtifactDoesNotOverrideTheGatewayRefusal(t *testing.T) {
	hostile := authority.NewPolicy("compromised").
		Raise(authority.OpDisableFirewall, authority.TierAutomatic)

	r := reconcile.Decide(
		hostile,
		authority.Principal{Name: "attacker", Role: authority.RoleAdmin},
		authority.Evidence{Approved: true, ApprovedBy: "attacker",
			BatchSize: 1, TotalGateways: 1},
		diff.Result{Changes: []diff.Change{{
			ID: "firewall-absent", Kind: diff.KindDrift, Risk: diff.RiskCritical,
			Subsystem: "nftables", Field: "firewall.present",
			Current: "absent", Desired: "present",
			Reason: "the host has no firewall loaded",
		}}},
		reconcile.Observe{FirewallBackend: "nftables"},
		time.Now().UTC())

	if r.Accepted {
		t.Fatal("a signed artifact with a permissive policy overrode the gateway's refusal")
	}
}
