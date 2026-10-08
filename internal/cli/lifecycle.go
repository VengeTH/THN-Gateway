package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/artifact"
	"github.com/VengeTH/THN-Gateway/internal/deploy"
	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/health"
	"github.com/VengeTH/THN-Gateway/internal/rollback"
)

// This file implements `thn verify`, `thn health`, `thn rollout` and
// `thn rollback`.
//
// # All four decide; none of them acts
//
// `thn verify` checks a signed artifact and refuses it if anything is wrong.
// `thn health` assesses the host against a change set. `thn rollout` says what
// should happen next across a fleet. `thn rollback` says what returning to a
// previous configuration would involve.
//
// None of them can change anything, and `activation.CanApply()` is false
// regardless of what any of them reports. A tool that can describe an apply but
// not perform it is what makes the description reviewable before the action,
// which is the only stage at which reviewing it is free.

// runVerify implements `thn verify`.
func runVerify(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.String("file", "")
	fs.String("key", "")
	fs.String("org", "")
	fs.String("gateway", "")
	fs.String("generation", "")
	fs.String("min-generation", "")

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn verify: %v\n", err)
	}

	path := fsValue(fs, "file")
	if path == "" {
		env.errorf("thn verify: --file is required.\n")
		env.errorf("\n")
		env.errorf("The file is an artifact envelope as produced by the control plane,\n")
		env.errorf("or a JSON object with the same shape.\n")
		return ExitUsage
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return env.fatalf("thn verify: %v\n", err)
	}

	// The trust set and the gateway identity are supplied by the caller in
	// this build. A gateway that shipped with a baked-in key list would have
	// to be rebuilt to rotate one, which is the wrong trade: rotation should
	// not require shipping new firmware to a fleet.
	trust, err := loadTrust(fsValue(fs, "key"))
	if err != nil {
		return env.fatalf("thn verify: %v\n", err)
	}

	v := &artifact.Verifier{
		Trust: trust,
		Org:   fsValue(fs, "org"),
		Now:   func() time.Time { return time.Now().UTC() },
	}
	v.BindGateway(fsValue(fs, "gateway"))
	if g := fsValue(fs, "min-generation"); g != "" {
		n, perr := parseUnsigned(g)
		if perr != nil {
			return env.fatalf("thn verify: --min-generation %q is not a number\n", g)
		}
		v.MinGeneration = n
	}

	var env1 artifact.Envelope
	if err := json.Unmarshal(raw, &env1); err != nil {
		return env.fatalf("thn verify: %v: %v\n", artifact.ErrMalformed, err)
	}

	verified, verr := v.Verify(&env1)

	if env.IsJSON {
		out := map[string]any{
			"file":     path,
			"key_id":   env1.KeyID(),
			"accepted": verr == nil,
			"min_gen":  v.MinGeneration,
			"high_gen": v.HighestGeneration(),
			"verifier": "verify does not apply; acceptance here is a statement about the signature",
		}
		if verr != nil {
			out["refused"] = verr.Error()
		} else {
			out["generation"] = verified.Meta.Generation
			out["digest"] = verified.Digest
			out["document_bytes"] = len(verified.Document)
		}
		if err := env.printJSON(out); err != nil {
			env.errorf("thn verify: %v\n", err)
			return ExitProblems
		}
		if verr != nil {
			return ExitProblems
		}
		return ExitOK
	}

	if verr != nil {
		env.printf("REFUSED\n")
		env.printf("%s\n\n", strings.Repeat("─", 72))
		env.printf("%v\n\n", verr)
		env.printf("The envelope was not accepted. Nothing was read out of it, and no\n")
		env.printf("change would be made even if it had been.\n")
		return ExitProblems
	}

	env.printf("ACCEPTED\n")
	env.printf("%s\n\n", strings.Repeat("─", 72))
	env.printf("Gateway      %s\n", verified.Meta.Gateway)
	env.printf("Organisation %s\n", verified.Meta.Org)
	env.printf("Generation   %d\n", verified.Meta.Generation)
	env.printf("Digest       %s\n", verified.Digest)
	env.printf("Signed by    %s\n", verified.KeyID)
	env.printf("Valid        %s .. %s\n",
		verified.Meta.NotBefore.Format(time.RFC3339),
		verified.Meta.NotAfter.Format(time.RFC3339))
	env.printf("Document     %d bytes\n", len(verified.Document))
	env.printf("\nPersist this generation before acting on it. A verifier that\n")
	env.printf("forgets the highest generation it has seen can be replayed\n")
	env.printf("against next time it runs.\n")
	return ExitOK
}

// loadTrust reads a trust set from a JSON file.
//
// The file is a flat map of key ID to base64 public key, so that an operator
// can produce one with openssl or jq without a THN-specific tool.
func loadTrust(path string) (artifact.Trust, error) {
	trust := artifact.Trust{
		Keys:    map[string]artifact.PublicKey{},
		Revoked: map[string]string{},
	}
	if path == "" {
		return trust, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return trust, err
	}

	var doc struct {
		Keys    map[string]string `json:"keys"`
		Revoked map[string]string `json:"revoked"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return trust, err
	}

	for id, b64 := range doc.Keys {
		key, derr := decodeKey(b64)
		if derr != nil {
			return trust, derr
		}
		trust.Keys[id] = artifact.PublicKey{KeyID: id, Key: key}
	}
	for id, reason := range doc.Revoked {
		trust.Revoked[id] = reason
	}
	return trust, nil
}

// runHealth implements `thn health`.
func runHealth(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("local", false)
	fs.String("at", "")
	fs.String("generation", "0")
	_ = fs.String("observe", "")

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn health: %v\n", err)
	}

	when, wcode := resolveWhen(env, fs, "thn health")
	if wcode != ExitOK {
		return wcode
	}

	path := env.resolveConfigPath("")
	cfg, cerr := loadConfig(env, path)
	if cerr != nil {
		return ExitProblems
	}

	gen, gerr := parseUnsigned(fsValue(fs, "generation"))
	if gerr != nil {
		return env.fatalf("thn health: --generation %q is not a number\n",
			fsValue(fs, "generation"))
	}

	obs, _, _, _ := observeHost(cfg)
	d := diff.Compare(obs, desiredFor(desired.FromConfig(cfg)))
	report := health.Assess(cfg.Gateway.Name, gen, d, obs, when)

	if env.IsJSON {
		if err := env.printJSON(report); err != nil {
			env.errorf("thn health: %v\n", err)
			return ExitProblems
		}
		if report.Failed() {
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("%s", health.Render(report))
	env.printf("\n%s\n", strings.Repeat("─", 72))
	env.printf("A verdict of unknowable means the gateway could not be read, not\n")
	env.printf("that it is fine. A rollout must stop on it.\n")

	if report.Failed() {
		return ExitProblems
	}
	return ExitOK
}

// runRollout implements `thn rollout`.
//
// It reports what a staged deployment would do next given the health reports
// it is given. It does not contact a fleet: there is no fleet to contact in
// this build, and a rollout command that cannot reach anything is honest about
// itself rather than pretending.
func runRollout(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.String("change", "gen-0")
	fs.String("fleet", "1")
	fs.String("stage", string(deploy.StageCanary))
	fs.String("reports", "")
	fs.String("max-unhealthy", "")
	fs.String("max-degraded", "")
	fs.String("min-reports", "")

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn rollout: %v\n", err)
	}

	fleet, ferr := parsePositiveInt(fsValue(fs, "fleet"))
	if ferr != nil || fleet < 1 {
		return env.fatalf("thn rollout: --fleet %q is not a positive number\n",
			fsValue(fs, "fleet"))
	}

	th := deploy.DefaultThresholds()
	if v := fsValue(fs, "max-unhealthy"); v != "" {
		n, err := parsePositiveInt(v)
		if err != nil {
			return env.fatalf("thn rollout: --max-unhealthy %q is not a number\n", v)
		}
		th.MaxUnhealthy = n
	}
	if v := fsValue(fs, "min-reports"); v != "" {
		n, err := parsePositiveInt(v)
		if err != nil {
			return env.fatalf("thn rollout: --min-reports %q is not a number\n", v)
		}
		th.MinReports = n
	}

	r := deploy.New(fsValue(fs, "change"), fleet, th)
	r.Stage = deploy.Stage(fsValue(fs, "stage"))
	r.Now = func() time.Time { return time.Now().UTC() }

	// Reports are read from a JSON file so that a decision can be reproduced
	// from what was actually observed rather than from what someone retyped.
	if path := fsValue(fs, "reports"); path != "" {
		reports, err := readReports(path)
		if err != nil {
			return env.fatalf("thn rollout: %v\n", err)
		}
		r.Record(reports...)
	}

	// Assume the current stage has been applied: otherwise there is nothing
	// to have health reports about.
	if len(r.Reports) > 0 {
		r.Applied = deploy.CapFor(r.Stage, fleet)
	}

	decision := r.Advance()

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"change":   r.ChangeID,
			"fleet":    r.Fleet,
			"stage":    r.Stage,
			"applied":  r.Applied,
			"reports":  len(r.Reports),
			"halted":   r.Halted,
			"decision": decision,
		}); err != nil {
			env.errorf("thn rollout: %v\n", err)
			return ExitProblems
		}
		if decision.Action == deploy.ActionHalt || decision.Action == deploy.ActionRollback {
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Rollout of %s across %d gateway(s)\n", r.ChangeID, r.Fleet)
	env.printf("Stage %s, %d applied, %d report(s)\n", r.Stage, r.Applied, len(r.Reports))
	env.printf("%s\n\n", strings.Repeat("─", 72))
	env.printf("%s", deploy.Render(decision))
	env.printf("\n%s\n", strings.Repeat("─", 72))
	env.printf("No gateway was contacted. This reports what a staged deployment\n")
	env.printf("should do next given these health reports.\n")

	if decision.Action == deploy.ActionHalt || decision.Action == deploy.ActionRollback {
		return ExitProblems
	}
	return ExitOK
}

func readReports(path string) ([]health.Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var reports []health.Report
	if err := json.Unmarshal(raw, &reports); err != nil {
		return nil, err
	}
	return reports, nil
}

// runRollback implements `thn rollback`.
func runRollback(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.String("history", "")
	fs.String("generation", "")
	fs.String("at", "")
	fs.Bool("require-signature", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn rollback: %v\n", err)
	}

	path := fsValue(fs, "history")
	if path == "" {
		env.errorf("thn rollback: --history is required.\n")
		env.errorf("\n")
		env.errorf("It is the gateway's recorded configuration history, as written by\n")
		env.errorf("`thn config record` or by the control plane's report.\n")
		return ExitUsage
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return env.fatalf("thn rollback: %v\n", err)
	}

	var hist rollback.History
	if err := json.Unmarshal(raw, &hist); err != nil {
		return env.fatalf("thn rollback: history is malformed: %v\n", err)
	}

	target := uint64(0)
	if g := fsValue(fs, "generation"); g != "" {
		n, perr := parseUnsigned(g)
		if perr != nil {
			return env.fatalf("thn rollback: --generation %q is not a number\n", g)
		}
		target = n
	}

	plan, rerr := rollback.Resolve(&hist, target, nil, *fs.bools["require-signature"])

	if env.IsJSON {
		out := map[string]any{
			"gateway": hist.Gateway,
			"applied": hist.Applied,
			"plan":    plan,
			"ran":     false,
		}
		if rerr != nil {
			out["error"] = rerr.Error()
		}
		if err := env.printJSON(out); err != nil {
			env.errorf("thn rollback: %v\n", err)
			return ExitProblems
		}
		if rerr != nil {
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("%s", rollback.Render(plan, rerr))
	env.printf("\n%s\n", strings.Repeat("─", 72))
	env.printf("Nothing was reverted. This describes what reverting would involve.\n")

	if rerr != nil {
		return ExitProblems
	}
	if !plan.Runnable() {
		return ExitProblems
	}
	return ExitOK
}

// parseUnsigned parses a non-negative integer.
//
// Separate from parsePositiveInt because a generation of zero means "unspecified"
// and a threshold of zero means "tolerate none", and conflating them would make
// one of those untypeable.
func parseUnsigned(s string) (uint64, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// decodeKey reads a base64-encoded ed25519 public key.
func decodeKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("public key is not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
