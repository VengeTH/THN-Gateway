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
	"sort"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/deployment"
	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/planner"
	"github.com/venth/thn-gateway/internal/state"
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
	obs, _, _, device := observeHost(cfg)

	// # Which bindings apply
	//
	// Two statements can name a role's hardware: the configuration document
	// (network.wan / network.lan) and the operator's assignment store. They
	// are different statements, not two copies of one, and mergeBindings
	// defines the precedence in a single place: the document wins where both
	// speak, and a disagreement is reported rather than resolved.
	//
	// Before this milestone the store did not exist and only the document was
	// consulted. That is not a behaviour anyone can observe on a machine with
	// no assignments, which is why it is worth a comment.
	_, stored := storedAssignments(cfg)
	bindings, _, _ := mergeBindings(cfg, stored)

	res := host.Resolve(device, bindings)
	in.WAN = roleGate(device, res, host.RoleWAN, bindingSelector(cfg, stored, host.RoleWAN))
	in.LAN = roleGate(device, res, host.RoleLAN, bindingSelector(cfg, stored, host.RoleLAN))
	in.Capabilities = capabilityGates(device)

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

// storedAssignments returns the operator's bindings and the path they came
// from.
//
// The path is returned so a caller can tell "the store is empty" from "there
// is no store", which are different situations for an operator: the first
// means nothing has been assigned, the second means THN has never run.
func storedAssignments(cfg config.Config) (string, []state.InterfaceAssignment) {
	path := resolveStorePath(cfg, "")
	return path, loadBindings(path)
}

// roleGate turns a role resolution into the value activation.Evaluate reads.
//
// # The shape of the explanation is the product
//
// The requirement in Part 13 is that an operator be told more than "interface
// not found". The gate reason below carries all four facts a human or a future
// UI needs: what was asked for, what was actually seen, why the chosen
// interface is unsuitable, and what they could do about it.
//
// The structured form of those facts already exists as host.Problem. This
// function only flattens one into a sentence — it does not decide anything, so
// there is exactly one place where the decision lives.
func roleGate(d *host.Device, res host.Resolution, r host.Role, asked string) activation.RoleGate {
	g := activation.RoleGate{Role: string(r), Selector: asked}

	if iface, ok := res.Assigned[r]; ok {
		g.Satisfied = true
		g.Interface = iface.SystemName
		g.Capability = string(host.CapRouting)
		g.Reason = fmt.Sprintf("role %s is filled by %s (identity %s)", r, iface.SystemName, iface.ID)
		return g
	}

	g.Reason = unresolvedRoleReason(d, res, r, asked)
	return g
}

// unresolvedRoleReason explains, in one sentence, why a role is unfilled.
//
// The order of the questions is deliberate: it distinguishes "you have not
// said" from "you said something that is not there" from "you said something
// that cannot work", because those need three different fixes and an operator
// who is told only the last one will keep changing the wrong thing.
func unresolvedRoleReason(d *host.Device, res host.Resolution, r host.Role, asked string) string {
	if d == nil || !d.Supported {
		return fmt.Sprintf("this host could not be inspected, so no interface can fill role %s; "+
			"run `thn discover` on the gateway itself", r)
	}

	observed := strings.Join(d.SystemNames(), ", ")

	if strings.TrimSpace(asked) == "" {
		return fmt.Sprintf("role %s is not assigned; observed interfaces are %s. "+
			"Run `thn discover` and assign one", r, observed)
	}

	// A structured problem, when there is one, already knows the precise
	// cause — wrong kind, already claimed, not assignable. Prefer its
	// wording over anything reconstructed here, so the reason never drifts
	// from the rule that produced it.
	//
	// # The next action is appended, not swallowed
	//
	// This branch used to return the problem's message alone. That message
	// states the FAULT accurately and stops there:
	//
	//	no observed interface matches "eth9" for role lan
	//
	// which is a correct description of a condition the operator cannot see
	// the inside of. It names no observed interface, offers no next step, and
	// reads like a THN malfunction rather than a thing to go and look at.
	//
	// The fall-through below DID carry the guidance, which made the early
	// return a silent regression: the structured-problem path is the COMMON
	// one, so almost every real diagnostic lost its next action while the
	// uncommon one kept it.
	//
	// Discovery is named as the way to SEE the options, never as something
	// that will choose for you. THN does not decide which NIC is the uplink,
	// and a message implying otherwise would be a lie about the product.
	for _, p := range res.Problems {
		if p.Role != r {
			continue
		}
		var b strings.Builder
		b.WriteString(p.Message)
		if len(p.Observed) > 0 {
			fmt.Fprintf(&b, ". Observed: %s", strings.Join(p.Observed, ", "))
		}
		if len(p.Candidates) > 0 {
			fmt.Fprintf(&b, ". Possible: %s", strings.Join(p.Candidates, ", "))
		}
		fmt.Fprintf(&b, ". Run `thn discover` to see this host's interfaces, then assign role %s", r)
		return b.String()
	}

	return fmt.Sprintf("the interface assigned to role %s (%s) was not found; "+
		"observed interfaces are %s. Run `thn discover` and assign a different one",
		r, asked, observed)
}

// capabilityGates projects observed host capabilities onto the gate model.
//
// internal/activation deliberately does not import internal/host: the package
// that owns the safety boundary should not inherit the bugs of the package that
// reads the machine. This projection is the seam.
func capabilityGates(d *host.Device) []activation.CapabilityGate {
	out := make([]activation.CapabilityGate, 0, len(host.AllCapabilities()))
	for _, c := range host.AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			continue
		}
		out = append(out, activation.CapabilityGate{
			Name:       string(c),
			Available:  s.Available,
			Confidence: s.Confidence,
			Reason:     s.Reason,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
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
	if _, snap, _, _ := observeHost(cfg); snap != nil && snap.Supported {
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
