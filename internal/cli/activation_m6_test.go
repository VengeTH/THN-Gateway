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
		t.Error("all_satisfied must be false because physical presence cannot be " +
			"confirmed by a command that is not run at the device")
	}

	// Every gate the report carries must have a reason when it blocks, and the
	// apply-path gate must report the truth about the binary rather than a
	// stale claim about it.
	foundApplyPathGate := false
	for _, g := range data.Gates {
		if g.Name == "apply-path-available" {
			foundApplyPathGate = true
			if !g.Satisfied {
				t.Error("apply-path-available is unsatisfied; this build has an apply path " +
					"and the gate must report it truthfully")
			}
		}
	}
	if !foundApplyPathGate {
		t.Error("apply-path-available gate not found in verify output")
	}

	foundPresence := false
	for _, g := range data.Gates {
		if g.Name == "physical-presence" {
			foundPresence = true
			if g.Satisfied {
				t.Error("physical-presence reports satisfied without --confirm-present")
			}
		}
	}
	if !foundPresence {
		t.Error("physical-presence gate not found in verify output")
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

func TestCLIActivationInspectOutput(t *testing.T) {
	env, out, _ := newTestEnv()
	code := runActivation(env, []string{"inspect"})
	if code != ExitOK {
		t.Fatalf("thn activation inspect failed with exit %d", code)
	}

	output := out.String()
	for _, want := range []string{
		"Activation Plan Inspection",
		"WHAT WILL CHANGE",
		"WHAT WILL NOT CHANGE",
		"WHICH INTERFACES",
		"WHICH ROUTES",
		"WHICH FIREWALL RESOURCES",
		"WHICH QOS RESOURCES",
		"WHICH DNS/DHCP RESOURCES",
		"ROLLBACK AVAILABLE",
		"MANAGEMENT PATH SAFE",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("thn activation inspect output missing %q:\n%s", want, output)
		}
	}
}

func TestCLIActivationInspectJSON(t *testing.T) {
	env, out, _ := newTestEnv()
	env.IsJSON = true
	code := runActivation(env, []string{"inspect"})
	if code != ExitOK {
		t.Fatalf("thn activation inspect --json failed with exit %d", code)
	}

	var data struct {
		WhatWillChange      []string `json:"what_will_change"`
		WhatWillNotChange   []string `json:"what_will_not_change"`
		ManagedInterfaces   []string `json:"managed_interfaces"`
		UnmanagedInterfaces []string `json:"unmanaged_interfaces"`
		ManagedRoutes       []string `json:"managed_routes"`
		UnmanagedRoutes     []string `json:"unmanaged_routes"`
		FirewallResources   []string `json:"firewall_resources"`
		QoSResources        []string `json:"qos_resources"`
		DNSDHCPResources    []string `json:"dns_dhcp_resources"`
		RollbackAvailable   bool     `json:"rollback_available"`
		ManagementPathSafe  bool     `json:"management_path_safe"`
	}

	if err := json.Unmarshal([]byte(out.String()), &data); err != nil {
		t.Fatalf("failed decoding JSON from thn activation inspect: %v\noutput: %s", err, out.String())
	}

	if !data.RollbackAvailable {
		t.Error("expected rollback_available to be true")
	}
	if len(data.FirewallResources) == 0 {
		t.Error("expected firewall_resources to be populated")
	}
}

func TestCLIActivateConfirmRefusesSafely(t *testing.T) {
	env, _, errOut := newTestEnv("activate", "--confirm")
	code := Run(env)
	if code != ExitProblems {
		t.Fatalf("expected ExitProblems on an unapproved host, got %d", code)
	}
	errStr := errOut.String()
	if !strings.Contains(errStr, "Current network remains untouched") {
		t.Errorf("expected 'Current network remains untouched' in error output:\n%s", errStr)
	}

	// --confirm authorizes a change. It is not a statement that anyone is at
	// the device, and the refusal must say which of the two is missing.
	if !strings.Contains(errStr, "--confirm-present") {
		t.Errorf("expected the refusal to name the missing confirmation:\n%s", errStr)
	}
}
