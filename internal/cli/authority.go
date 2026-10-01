package cli

import (
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/authority"
	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/reconcile"
)

// This file implements `thn authority` and `thn reconcile`.
//
// # Why the gateway needs both
//
// `thn authority` answers "what may be changed, and by whom". `thn reconcile`
// answers "will this gateway accept this change". They are separate questions
// with different answers, and collapsing them would be the exact mistake the
// design is meant to prevent: a system in which approval and safety are the
// same check has a control plane that can overrule the device.
//
// # Both are pure
//
// Neither reads the host unless --local is given, neither contacts anything,
// and neither can change anything. `thn reconcile` in particular produces a
// decision and not an action: it says whether a change would be accepted, and
// `activation.CanApply()` remains false regardless of what it says.

// runAuthority implements `thn authority`.
func runAuthority(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn authority: expected a subcommand\n\n")
	}

	switch args[0] {
	case "policy":
		return runAuthorityPolicy(env, args[1:])
	case "check":
		return runAuthorityCheck(env, args[1:])
	default:
		return env.fatalf("thn authority: unknown subcommand %q; expected policy or check\n", args[0])
	}
}

// runAuthorityPolicy prints the floors and the policy's overrides.
func runAuthorityPolicy(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.String("name", "default")
	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn authority policy: %v\n", err)
	}

	policy := authority.NewPolicy(fsValue(fs, "name"))

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"policy":    policy.Name(),
			"floors":    floorTable(),
			"overrides": policy.Overrides(),
			"lowerings": policy.LoweringAttempts(),
			"note":      "a policy may raise a requirement; it cannot lower one",
		}); err != nil {
			env.errorf("thn authority policy: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("%s", authority.RenderPolicy(policy))
	return ExitOK
}

// floorTable renders the floor for every operation, for JSON output.
func floorTable() map[string]string {
	out := make(map[string]string)
	for _, op := range authority.AllOperations() {
		out[string(op)] = authority.FloorFor(op).String()
	}
	return out
}

// runAuthorityCheck authorises one operation and reports the decision.
//
// It exists so the decision is inspectable without a fleet, and so that the
// "allowed but not satisfied" state has a visible form somewhere. An operator
// debugging an approval workflow needs to see which of the two they are in.
func runAuthorityCheck(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.String("operation", "")
	fs.String("role", string(authority.RoleAdmin))
	fs.String("policy", "default")
	fs.Bool("approved", false)
	fs.String("batch", "0")
	fs.String("fleet", "0")
	fs.Bool("rollout-halted", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn authority check: %v\n", err)
	}

	raw := fsValue(fs, "operation")
	if raw == "" {
		env.errorf("thn authority check: --operation is required.\n")
		env.errorf("\n")
		env.errorf("One of:\n")
		for _, op := range authority.AllOperations() {
			env.errorf("  %s\n", op)
		}
		return ExitUsage
	}

	batch, berr := parsePositiveInt(fsValue(fs, "batch"))
	if berr != nil {
		return env.fatalf("thn authority check: --batch %q is not a number\n", fsValue(fs, "batch"))
	}
	fleet, ferr := parsePositiveInt(fsValue(fs, "fleet"))
	if ferr != nil {
		return env.fatalf("thn authority check: --fleet %q is not a number\n", fsValue(fs, "fleet"))
	}

	decision := authority.Decide(
		authority.NewPolicy(fsValue(fs, "policy")),
		authority.Principal{Name: "operator", Role: authority.Role(fsValue(fs, "role"))},
		authority.Operation(raw),
		authority.Evidence{
			Approved:      *fs.bools["approved"],
			BatchSize:     batch,
			TotalGateways: fleet,
			RolloutHalted: *fs.bools["rollout-halted"],
		})

	if env.IsJSON {
		if err := env.printJSON(decision); err != nil {
			env.errorf("thn authority check: %v\n", err)
			return ExitProblems
		}
		if !decision.Satisfied {
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Operation   %s\n", decision.Operation)
	env.printf("Policy      %s\n", decision.Policy)
	env.printf("Role        %s\n", decision.Role)
	env.printf("Requires    %s\n", decision.Required)
	env.printf("Permitted   %t\n", decision.Allowed)
	env.printf("Satisfied   %t\n", decision.Satisfied)
	env.printf("\n%s\n", decision.Reason)

	if !decision.Satisfied {
		return ExitProblems
	}
	return ExitOK
}

// runReconcile implements `thn reconcile`.
//
// It runs the same diff the planner uses, then asks the gateway's own refusal
// logic whether the result would be accepted. It does not apply anything, and
// there is no flag that would make it.
func runReconcile(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("local", false)
	fs.String("at", "")
	fs.String("role", string(authority.RoleAdmin))
	fs.String("policy", "default")
	fs.Bool("approved", false)
	fs.Bool("rollout-halted", false)
	fs.String("batch", "1")
	fs.String("fleet", "1")
	_ = fs.String("observe", "")

	raw, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn reconcile: %v\n", err)
	}
	_ = raw

	when, wcode := resolveWhen(env, fs, "thn reconcile")
	if wcode != ExitOK {
		return wcode
	}

	path := env.resolveConfigPath("")
	cfg, cerr := loadConfig(env, path)
	if cerr != nil {
		return ExitProblems
	}

	obs, _, fw := observeHost(cfg)
	d := diff.Compare(obs, desiredFor(desired.FromConfig(cfg)))

	// The capability facts come from the host, which is why --local matters.
	// An empty algorithm list means "could not enumerate", not "none available",
	// and the refusal logic distinguishes the two rather than blaming the kernel.
	capabilities := reconcile.Observe{
		FirewallBackend: string(fw.Status),
		Current:         obs,
	}

	batch, ferr := parsePositiveInt(fsValue(fs, "batch"))
	if ferr != nil {
		return env.fatalf("thn reconcile: --batch %q is not a number\n", fsValue(fs, "batch"))
	}
	fleet, ferr := parsePositiveInt(fsValue(fs, "fleet"))
	if ferr != nil {
		return env.fatalf("thn reconcile: --fleet %q is not a number\n", fsValue(fs, "fleet"))
	}

	result := reconcile.Decide(
		authority.NewPolicy(fsValue(fs, "policy")),
		authority.Principal{Name: "operator", Role: authority.Role(fsValue(fs, "role"))},
		authority.Evidence{
			Approved:      *fs.bools["approved"],
			BatchSize:     batch,
			TotalGateways: fleet,
			RolloutHalted: *fs.bools["rollout-halted"],
		},
		d, capabilities, when)

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"at":      when,
			"result":  result,
			"diff":    d,
			"applied": false,
			"note":    "this command decides whether a change would be accepted; it does not make it",
		}); err != nil {
			env.errorf("thn reconcile: %v\n", err)
			return ExitProblems
		}
		if !result.Accepted {
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Gateway decision at %s\n", when.Format(time.RFC3339))
	env.printf("%s\n\n", strings.Repeat("─", 72))
	env.printf("%s", reconcile.RenderRefusals(result))

	env.printf("%s\n", strings.Repeat("─", 72))
	env.printf("No change was made. This command reports whether the gateway would\n")
	env.printf("accept the requested state; it does not make it.\n")

	if !result.Accepted {
		return ExitProblems
	}
	return ExitOK
}
