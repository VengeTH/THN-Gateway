package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCLIPlanDeterministicOutput(t *testing.T) {
	path := canonicalConfigPath(t)

	out1, err1, code1 := runGateCLI(t, "plan", path)
	if code1 != ExitOK {
		t.Fatalf("thn plan failed with exit %d: %s\nstderr: %s", code1, out1, err1)
	}

	out2, err2, code2 := runGateCLI(t, "plan", path)
	if code2 != ExitOK {
		t.Fatalf("thn plan run 2 failed with exit %d: %s\nstderr: %s", code2, out2, err2)
	}

	if out1 != out2 {
		t.Errorf("thn plan output is not deterministic across runs:\nRun 1:\n%s\nRun 2:\n%s", out1, out2)
	}
}

func TestCLIPlanStructuredJSONOutput(t *testing.T) {
	path := canonicalConfigPath(t)

	stdout, stderr, code := runGateCLI(t, "plan", "--json", path)
	if code != ExitOK {
		t.Fatalf("thn plan --json failed with exit %d: %s\nstderr: %s", code, stdout, stderr)
	}

	var data struct {
		Config string `json:"config"`
		Plan   struct {
			ID                 string   `json:"id"`
			Generation         uint64   `json:"generation"`
			ManagedResources   []string `json:"managed_resources"`
			UnmanagedResources []string `json:"unmanaged_resources"`
			Inputs             struct {
				ObservedDigest   string `json:"observed_digest"`
				DesiredDigest    string `json:"desired_digest"`
				AssignmentDigest string `json:"assignment_digest"`
			} `json:"inputs"`
			Preconditions []struct {
				ID          string `json:"id"`
				Description string `json:"description"`
				Satisfied   bool   `json:"satisfied"`
			} `json:"preconditions"`
			Steps []struct {
				ID       string   `json:"id"`
				Action   string   `json:"action"`
				Phase    int      `json:"phase"`
				Commands []string `json:"commands"`
				Rollback *struct {
					Target          string   `json:"target"`
					RestoreCommands []string `json:"restore_commands"`
					Reversibility   string   `json:"reversibility"`
				} `json:"rollback"`
			} `json:"steps"`
			Transaction struct {
				DryRun bool `json:"dry_run"`
				Phases []struct {
					Phase   string `json:"phase"`
					Purpose string `json:"purpose"`
				} `json:"phases"`
			} `json:"transaction"`
			Verification struct {
				Checks []struct {
					Target string `json:"target"`
					Check  string `json:"check"`
				} `json:"checks"`
			} `json:"verification"`
			Simulation struct {
				Headline string `json:"headline"`
			} `json:"simulation"`
			Ready   bool   `json:"ready"`
			Summary string `json:"summary"`
		} `json:"plan"`
	}

	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		t.Fatalf("failed to decode JSON from thn plan --json: %v\noutput: %s", err, stdout)
	}

	if data.Plan.ID == "" {
		t.Error("plan ID must not be empty in JSON output")
	}
	if !data.Plan.Transaction.DryRun {
		t.Error("transaction must be dry-run in JSON output")
	}
	if len(data.Plan.Transaction.Phases) == 0 {
		t.Error("transaction phases must be populated in JSON output")
	}
	if data.Plan.Inputs.DesiredDigest == "" {
		t.Error("desired digest must not be empty in plan inputs")
	}
}

func TestCLIPlanExplainModeDisplaysActionsAndRollback(t *testing.T) {
	path := canonicalConfigPath(t)

	stdout, stderr, code := runGateCLI(t, "plan", "--explain", path)
	if code != ExitOK {
		t.Fatalf("thn plan --explain failed with exit %d: %s\nstderr: %s", code, stdout, stderr)
	}

	for _, want := range []string{
		"Simulation (nothing has been changed)",
		"Plan",
		"Source:",
		"Diff",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("thn plan --explain missing expected section %q:\n%s", want, stdout)
		}
	}
}

func TestCLIPlanConfigPlanAgreement(t *testing.T) {
	path := canonicalConfigPath(t)

	pOut, _, pCode := runGateCLI(t, "plan", path)
	cpOut, _, cpCode := runGateCLI(t, "config", "plan", path)

	if pCode != ExitOK || cpCode != ExitOK {
		t.Fatalf("both plan commands must succeed, got %d and %d", pCode, cpCode)
	}
	if pOut != cpOut {
		t.Errorf("thn plan output != thn config plan output:\nplan:\n%s\nconfig plan:\n%s", pOut, cpOut)
	}
}

func TestCLIPlanPreservesSafetyGuarantees(t *testing.T) {
	// Planning describes. It must never become a route to acting.
	assertActivationRemainsGated(t, "adding `thn plan`")
}
