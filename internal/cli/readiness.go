package cli

// `thn readiness` — how far this gateway is from being deployable.
//
// # Why this command exists
//
// The readiness gates already existed and were already evaluated, but only
// inside a test. `thn activate` refused without printing them, so an operator
// had no way to ask the one question that matters before a cutover: what,
// specifically, is still missing?
//
// That question has a surprising answer today. Everything about the
// configuration can be correct and the verdict is still BLOCKED, because this
// build contains no apply path at all. Printing the gates is what separates
// "nearly ready" from "not ready in a way more configuration will not fix",
// and those need different responses.
//
// # It decides, it does not act
//
// Like its siblings `thn verify`, `thn health`, `thn rollout` and
// `thn rollback`, this command reads and reports. It cannot change the host,
// and activation.CanApply() is false regardless of what it prints.

import (
	"fmt"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/deployment"
	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/planner"
	"github.com/venth/thn-gateway/internal/validation"
)

// runReadiness implements `thn readiness`.
func runReadiness(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn readiness: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}
	if len(rest) > 1 {
		return env.fatalf("thn readiness: expected at most one configuration path, got %d\n", len(rest))
	}

	path := env.resolveConfigPath(*configPath)
	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn readiness: %v\n", err)
		return ExitProblems
	}

	input := readinessInput(cfg, path)
	gates := activation.Evaluate(input)
	ready := gates.AllSatisfied

	if env.IsJSON {
		out := map[string]any{
			"config":               path,
			"readiness":            readinessVerdict(ready),
			"all_gates_satisfied":  gates.AllSatisfied,
			"blocking":             gates.Blocking,
			"gates":                gates.Gates,
			"deployment":           readinessDeployment(cfg),
			"can_apply":            activation.CanApply(),
			"implemented_stages":   activation.ImplementedStages(),
			"unimplemented_stages": activation.UnsupportedStages(),
			"network_untouched":    true,
			"statement":            "Current network remains untouched.",
		}
		if err := env.printJSON(out); err != nil {
			env.errorf("thn readiness: %v\n", err)
			return ExitProblems
		}
		if ready {
			return ExitOK
		}
		return ExitProblems
	}

	printReadiness(env, path, gates, readinessDeployment(cfg))
	if ready {
		return ExitOK
	}
	return ExitProblems
}

// readinessVerdict maps the gate result onto the two words an operator needs.
//
// "BLOCKED" covers both "not ready yet" and "not ready in this build". They
// are distinguished by the gates themselves, which is the point: the operator
// should not have to infer from prose which one they are in.
func readinessVerdict(ready bool) string {
	if ready {
		return "READY"
	}
	return "BLOCKED"
}

// readinessInput gathers the facts activation.Evaluate reads.
//
// Every field is derived from the configuration, the plan or a read-only host
// observation. Nothing is assumed satisfied because nothing objected.
func readinessInput(cfg config.Config, path string) activation.GateInput {
	in := activation.GateInput{}

	// config-valid uses exactly the validation `thn validate` runs, so the
	// two commands cannot disagree about whether a document is coherent.
	// PresenceConfirmed is deliberately left false: it records an operator
	// physically confirming something, and no CLI invocation can do that on
	// the operator's behalf.
	//
	// ConfigValid starts TRUE and is narrowed. Starting from the zero value
	// would make this expression `false && ...` for every subsystem, and the
	// gate would report an invalid configuration that validates cleanly.
	in.ConfigValid = true
	for _, sub := range subsystemValidations(cfg) {
		if sub.Valid {
			continue
		}
		in.ConfigValid = false
		for _, f := range sub.Errors() {
			if in.ConfigProblem == "" {
				in.ConfigProblem = fmt.Sprintf("%s: %s", f.Field, f.Message)
			}
			break
		}
	}
	if combined := validation.Combined(cfg, nil, diff.Result{}); !combined.Valid {
		in.ConfigValid = false
		if in.ConfigProblem == "" {
			for _, f := range combined.Errors() {
				in.ConfigProblem = fmt.Sprintf("%s: %s", f.Field, f.Message)
				break
			}
		}
	}
	if in.ConfigProblem == "" && !in.ConfigValid {
		in.ConfigProblem = "the configuration does not validate; run `thn validate`"
	}

	// wan-present, lan-identified and plan-validated all need a host
	// observation. observeHost is read-only and goes through internal/guard.
	obs, _, _ := observeHost(cfg)

	in.WANPresent = obs.WANPresent
	if !obs.WANPresent {
		in.WANProblem = fmt.Sprintf("the configured WAN interface (%s) was not found on this host",
			orUnset(cfg.Network.WAN))
	}

	in.LANPresent = obs.LANPresent
	switch {
	case !obs.LANPresent && cfg.Network.LAN == "":
		in.LANProblem = "network.lan is not set, so no downstream interface is identified"
	case !obs.LANPresent:
		in.LANProblem = fmt.Sprintf("the configured LAN interface (%s) was not found on this host",
			cfg.Network.LAN)
	}

	in.PlanValidated = planIsRunnable(cfg, obs)

	// recoverable is left unsatisfied with a reason, not silently true.
	//
	// A gateway with no recorded revision history has nothing to roll back
	// to. Claiming the gate is satisfied because "rollback machinery exists"
	// would be a statement about the build rather than about this gateway,
	// and it is the kind of claim that is still true when an activation has
	// already gone wrong.
	in.RecoveryOK = false
	in.RecoveryProblem = "no recorded configuration history; nothing has been rolled back from yet"

	return in
}

// planIsRunnable reports whether the planner would produce a plan with nothing
// blocking. It uses the same planner `thn plan` does, on the same observation.
func planIsRunnable(cfg config.Config, obs diff.Observed) bool {
	d := diff.Compare(obs, desiredFor(desired.FromConfig(cfg)))
	p := planner.Build(d, planner.Options{
		Generation: cfg.Gateway.Generation,
		Source:     "thn readiness",
		Live:       obs.Supported,
		Now:        time.Now(),
	})
	return len(p.Blocked) == 0
}

// readinessDeployment reports whether this host looks like an approved
// gateway, using the same detector `thn activate` uses.
func readinessDeployment(cfg config.Config) deployment.Status {
	o := deployment.Observation{
		HostPlatform:  hostPlatform(),
		GatewayName:   cfg.Gateway.Name,
		ConfiguredWAN: cfg.Network.WAN,
		ConfiguredLAN: cfg.Network.LAN,
	}
	// observeHost is read-only and goes through internal/guard, so this
	// observes exactly what `thn activate` and `thn diagnostics` observe.
	if _, snap, _ := observeHost(cfg); snap != nil && snap.Supported {
		o.HostSupported = true
		for _, i := range snap.Interfaces {
			o.Interfaces = append(o.Interfaces, i.Name)
		}
	}
	return deployment.Detect(o)
}

// printReadiness renders the verdict.
func printReadiness(env *Env, path string, gates activation.GateResult, deploy deployment.Status) {
	env.printf("Activation readiness\n")
	env.printf("─────────────────────\n")
	env.printf("Configuration: %s\n", path)
	env.printf("Verdict:        %s\n", readinessVerdict(gates.AllSatisfied))
	env.printf("Can apply:      %t\n", activation.CanApply())
	env.printf("\n")

	env.printf("Gates\n")
	env.printf("  %-6s %-22s %s\n", "", "GATE", "DETAIL")
	for _, g := range gates.Gates {
		mark, detail := "ok", "satisfied"
		if !g.Satisfied {
			mark, detail = "BLOCK", g.Reason
		}
		env.printf("  %-6s %-22s %s\n", mark, g.Name, detail)
	}

	if len(gates.Blocking) > 0 {
		env.printf("\nBlocking\n")
		for _, b := range gates.Blocking {
			env.printf("  - %s\n", b)
		}
		env.printf("\n")
		env.printf("%s\n", blockingAdvice(gates.Blocking))
	}

	env.printf("Deployment\n")
	env.printf("  %s\n", deploy.Reason)
	for _, s := range deploy.Signals {
		mark := "no"
		if s.Met {
			mark = "yes"
		}
		env.printf("  [%s] %-18s %s\n", mark, s.Name, s.Detail)
	}

	env.printf("\nStages\n")
	env.printf("  implementable:   %s\n", stageList(activation.ImplementedStages()))
	env.printf("  not implemented: %s\n", stageList(activation.UnsupportedStages()))

	env.printf("\nCurrent network remains untouched.\n")
}

// blockingAdvice says which of the blocking gates no amount of configuration
// will fix.
//
// Without this an operator reads "BLOCKED: apply-path-available" and goes
// looking for a setting. Naming the build as the reason is the difference
// between a useful report and a frustrating one.
func blockingAdvice(blocking []string) string {
	if !containsName(blocking, "apply-path-available") {
		return "Every gate that blocks can be satisfied by configuration or by this host.\n" +
			"Nothing here needs a different build."
	}
	return "apply-path-available is blocked by the BUILD, not by this configuration.\n" +
		"No setting changes it. Readiness cannot reach READY on this build even with a\n" +
		"perfect configuration."
}

// containsName reports whether a slice holds a value.
func containsName(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// orUnset renders an empty string as a placeholder.
func orUnset(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// readinessSummary renders the verdict in one line, for tests and prose.
func readinessSummary(gates activation.GateResult) string {
	if gates.AllSatisfied {
		return readinessVerdict(true)
	}
	return readinessVerdict(false) + ": " + strings.Join(gates.Blocking, ", ")
}

var _ = orNone // orNone already exists in this package
