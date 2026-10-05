package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCLIActivationStatusOutput(t *testing.T) {
	env, out, _ := newTestEnv()
	code := runActivation(env, []string{"status"})

	if code != ExitOK {
		t.Fatalf("thn activation status failed with exit %d", code)
	}

	output := out.String()
	for _, want := range []string{
		"Activation Status",
		"State:",
		"Can Apply:",
		"false",
		"Bound Applier:",
		"Implemented Stages:",
		"Unsupported Stages:",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("thn activation status output missing %q:\n%s", want, output)
		}
	}
}

func TestCLIActivationStatusJSON(t *testing.T) {
	env, out, _ := newTestEnv()
	env.IsJSON = true
	code := runActivation(env, []string{"status"})

	if code != ExitOK {
		t.Fatalf("thn activation status --json failed with exit %d", code)
	}

	var data struct {
		State    string `json:"state"`
		CanApply bool   `json:"can_apply"`
		Applier  string `json:"applier"`
		Gates    struct {
			AllSatisfied bool `json:"all_satisfied"`
		} `json:"gates"`
	}

	if err := json.Unmarshal([]byte(out.String()), &data); err != nil {
		t.Fatalf("failed decoding JSON from thn activation status: %v\noutput: %s", err, out.String())
	}

	if data.CanApply {
		t.Error("can_apply must be false in activation status")
	}
	if data.State == "" {
		t.Error("state must not be empty in activation status")
	}
}

func TestCLIActivationVerifyOutput(t *testing.T) {
	env, out, _ := newTestEnv()
	code := runActivation(env, []string{"verify"})

	// code is ExitProblems because apply-path-available is unsatisfied
	if code == ExitOK {
		t.Fatalf("thn activation verify unexpectedly exited OK")
	}

	output := out.String()
	for _, want := range []string{
		"Activation Gate Verification",
		"apply-path-available",
		"plan-validated",
		"Activation is BLOCKED",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("thn activation verify output missing %q:\n%s", want, output)
		}
	}
}

func TestCLIActivationVerifyJSON(t *testing.T) {
	env, out, _ := newTestEnv()
	env.IsJSON = true
	code := runActivation(env, []string{"verify"})

	if code == ExitOK {
		t.Fatalf("thn activation verify --json unexpectedly exited OK")
	}

	var data struct {
		AllSatisfied bool     `json:"all_satisfied"`
		Blocking     []string `json:"blocking"`
		Gates        []struct {
			Name      string `json:"name"`
			Satisfied bool   `json:"satisfied"`
		} `json:"gates"`
	}

	if err := json.Unmarshal([]byte(out.String()), &data); err != nil {
		t.Fatalf("failed decoding JSON from thn activation verify: %v\noutput: %s", err, out.String())
	}

	if data.AllSatisfied {
		t.Error("all_satisfied must be false because apply-path is unavailable")
	}
	foundApplyPathGate := false
	for _, g := range data.Gates {
		if g.Name == "apply-path-available" {
			foundApplyPathGate = true
			if g.Satisfied {
				t.Error("apply-path-available must not be satisfied")
			}
		}
	}
	if !foundApplyPathGate {
		t.Error("apply-path-available gate not found in verify output")
	}
}

func TestCLIActivationUnknownSubcommand(t *testing.T) {
	env, _, errOut := newTestEnv()
	code := runActivation(env, []string{"nonexistent"})
	if code != ExitUsage {
		t.Fatalf("expected ExitUsage for unknown subcommand, got %d", code)
	}
	if !strings.Contains(errOut.String(), "unknown subcommand") {
		t.Errorf("expected unknown subcommand in stderr, got: %s", errOut.String())
	}
}
