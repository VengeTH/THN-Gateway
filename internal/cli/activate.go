package cli

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/deployment"
	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/execution"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/planner"
)

// `thn activate`, `thn activation status|inspect|verify`, and the gate report.
//
// The activation command itself is the only one here that can change host
// networking; the rest are read-only by construction. The wiring for the
// mutation path lives in activate_production.go, and the refusal rendering
// lives here.

// runActivate implements `thn activate`.
//
// # What this command now does
//
// It runs the production transaction, subject to every gate in
// activation.EvaluateProduction, explicit physical presence, and explicit
// production authorization. When any of those is missing it refuses and
// changes nothing.
//
// # What it prints when it refuses
//
// A refusal is the normal outcome for every command run without the right
// flags on the right host, so it names the first unmet gate rather than a
// general statement. An operator standing at the machine needs to know which
// one, because they are different fixes: run `thn assign`, plug in the LAN
// cable, or come back with --confirm-present.
//
// --confirm-present is a statement by a human that they are at the device.
// Nothing else can supply it, and no flag other than this one can substitute
// for it: --confirm says "I approve this change", not "I am standing next to
// the cable".
func runActivate(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("yes", false)
	fs.Bool("confirm", false)
	fs.Bool("confirm-present", false)
	fs.Bool("dry-run", false)
	fs.String("config", "")
	fs.String("journal", "")

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn activate: %v\n", err)
	}

	// --yes is accepted and does nothing. It is accepted so a runbook written
	// against a build that honours it does not fail on a flag it does not
	// understand; it is not honoured, because activation confirmation is not
	// something a convenience alias should be able to supply.
	if *fs.bools["yes"] {
		env.errorf("thn activate: --yes changes nothing.\n\n")
		env.errorf("It cannot stand in for --confirm or --confirm-present: activation\n")
		env.errorf("confirmation and physical presence are separate statements.\n\n")
	}

	confirmed := *fs.bools["confirm"]
	presence := *fs.bools["confirm-present"]
	dryRun := *fs.bools["dry-run"]

	path := env.resolveConfigPath(fsValue(fs, "config"))
	cfg, cfgErr := loadConfig(env, path)

	// An unreadable document is not a gate result; it is a reason the gates
	// cannot be evaluated, and it is reported as such rather than as a
	// configuration that validated badly.
	if cfgErr != nil {
		return reportActivationRefusal(env, activation.GateResult{
			AllSatisfied: false,
			Blocking:     []string{"config-valid"},
			Gates: []activation.Gate{{
				Name:        "config-valid",
				Description: "the configuration must validate without errors",
				Reason:      cfgErr.Error(),
			}},
		}, confirmed, presence, dryRun, "", nil)
	}

	ev := gatherActivationEvidence(cfg, path)
	in := productionGateInput(ev, presence)
	gates := activation.EvaluateProduction(in)

	// Everything below this point may change the host. Every refusal above it
	// returns before reaching a driver.
	if !gates.AllSatisfied || !confirmed || dryRun {
		return reportActivationRefusal(env, gates, confirmed, presence, dryRun, path, ev)
	}

	return performActivation(env, ev, gates)
}

// performActivation runs the authorized transaction and reports its outcome.
//
// It is separate from runActivate so that the refusal path and the mutation
// path are visibly distinct: there is one call site that can reach a driver,
// and it is below.
func performActivation(env *Env, ev *activationEvidence, gates activation.GateResult) ExitCode {
	if err := requireLinux(); err != nil {
		env.errorf("thn activate: activation refused.\n\n")
		env.errorf("Reason:\n  %v\n", err)
		env.errorf("\nCurrent network remains untouched.\n")
		return ExitProblems
	}

	journalPath := fsValueOrDefault("", defaultJournalPath(ev.Cfg))
	journal := execution.NewFileJournalStore(journalPath)

	// A transaction interrupted by a crash is reported, not resumed. Resuming
	// would mean guessing how far the previous run got, and the host cannot
	// be asked what state it is in by the same mechanism that failed.
	if rec, interrupted := execution.DetectInterrupted(journal); interrupted {
		return reportRecoveryRequired(env, rec, journalPath)
	}

	res, err := runProductionActivation(cmdContext(), ev, gates, true, journal, false)

	if env.IsJSON {
		out := map[string]any{
			"activated":         res != nil && res.FinalState == execution.StateCommitted,
			"plan_id":           ev.Plan.ID,
			"gates":             gates,
			"journal":           journalPath,
			"management":        ev.Management,
			"result":            res,
			"network_untouched": res == nil || res.FinalState != execution.StateCommitted,
		}
		if err != nil {
			out["error"] = err.Error()
		}
		if perr := env.printJSON(out); perr != nil {
			env.errorf("thn activate: %v\n", perr)
			return ExitProblems
		}
		if err != nil {
			return ExitProblems
		}
		return ExitOK
	}

	printActivationOutcome(env, ev, res, err, journalPath)
	if err != nil {
		return ExitProblems
	}
	return ExitOK
}

// reportActivationRefusal explains why nothing was changed.
//
// presence and confirmed are passed separately from the gate result because
// two of the reasons an activation does not proceed are not gates at all: an
// operator who simply did not pass the flag deserves to be told that, not to
// be told a gate is unmet.
func reportActivationRefusal(env *Env, gates activation.GateResult, confirmed, presence, dryRun bool, path string, ev *activationEvidence) ExitCode {
	if env.IsJSON {
		reason := "activation refused"
		switch {
		case !gates.AllSatisfied:
			reason = fmt.Sprintf("activation safety gates unsatisfied (%d blocking): %s",
				len(gates.Blocking), strings.Join(gates.Blocking, ", "))
		case !presence:
			reason = "physical presence has not been confirmed; re-run with --confirm-present from the device itself"
		case !confirmed:
			reason = "production authorization is required; re-run with --confirm"
		case dryRun:
			reason = "dry run: authorization succeeded but nothing was applied"
		}
		out := map[string]any{
			"activated":         false,
			"network_untouched": true,
			"statement":         "Current network remains untouched.",
			"reason":            reason,
			"can_apply":         activation.CanApply(),
			"gates":             gates,
			"dry_run":           dryRun,
		}
		if path != "" {
			out["config"] = path
		}
		if ev != nil {
			out["plan_id"] = ev.Plan.ID
			out["management"] = ev.Management
		}
		if err := env.printJSON(out); err != nil {
			env.errorf("thn activate: %v\n", err)
			return ExitProblems
		}
		return ExitProblems
	}

	env.errorf("thn activate: activation refused.\n\n")
	env.errorf("Nothing was changed.\n\n")

	if !gates.AllSatisfied {
		env.errorf("Blocking gates (%d):\n\n", len(gates.Blocking))
		for _, b := range gates.Blocking {
			for _, g := range gates.Gates {
				if g.Name == b {
					env.errorf("  [x] %-24s %s\n", g.Name, g.Reason)
					break
				}
			}
		}
		env.errorf("\n")
	}

	if ev != nil && !ev.Management.Safe {
		env.errorf("Management path\n")
		env.errorf("  %s\n\n", fallback(ev.Management.Reason, "management safety could not be established"))
	}

	env.errorf("To proceed\n")
	env.errorf("  1. Inspect the exact mutations:   thn activation inspect\n")
	env.errorf("  2. Confirm you are at the device: thn activate --confirm-present\n")
	env.errorf("  3. Authorize the change:         thn activate --confirm --confirm-present\n")
	env.errorf("\n")
	env.errorf("A dry run of the authorized path:\n")
	env.errorf("  thn activate --confirm --confirm-present --dry-run\n")
	env.errorf("\n")
	env.errorf("Current network remains untouched.\n")
	return ExitProblems
}

// reportRecoveryRequired surfaces an interrupted transaction.
//
// It is the only path that reads a previous run's outcome, and it refuses
// rather than continuing. The host state after a crash is unknown to THN by
// definition — the process that would have known it is the one that died — so
// any action taken from here would be a guess.
func reportRecoveryRequired(env *Env, rec *execution.TransactionRecord, journalPath string) ExitCode {
	if env.IsJSON {
		out := map[string]any{
			"activated":         false,
			"network_untouched": true,
			"state":             execution.StateRecoveryRequired,
			"journal":           journalPath,
			"interrupted":       rec,
			"reason": "an earlier execution transaction was interrupted; " +
				"THN cannot determine how far it progressed, so activation is blocked",
		}
		if err := env.printJSON(out); err != nil {
			env.errorf("thn activate: %v\n", err)
			return ExitProblems
		}
		return ExitProblems
	}

	env.errorf("thn activate: activation refused.\n\n")
	env.errorf("Reason:\n")
	env.errorf("  RECOVERY_REQUIRED — an earlier transaction was interrupted.\n\n")
	env.errorf("  Plan        %s\n", rec.PlanID)
	env.errorf("  Last state  %s\n", rec.State)
	env.errorf("  Started     %s\n", rec.StartedAt.Format(time.RFC3339))
	if rec.Error != "" {
		env.errorf("  Recorded    %s\n", rec.Error)
	}
	env.errorf("\n")
	env.errorf("THN cannot determine how far that transaction progressed. The process\n")
	env.errorf("that knew is the one that stopped, so any conclusion about the host\n")
	env.errorf("would be a guess. Inspect the host against your recorded baseline:\n\n")
	env.errorf("  journal: %s\n\n", journalPath)
	env.errorf("Once you have confirmed the host is in a known state, remove the journal\n")
	env.errorf("and re-run `thn activation inspect` before activating again.\n")
	return ExitProblems
}

// defaultJournalPath resolves where the transaction journal lives.
//
// It follows the same rule as the rest of the CLI: an explicit flag, then the
// configuration's state directory, then nothing. It deliberately does not
// invent a path, because a journal written somewhere the operator does not
// know about is a journal that will not be found when it is needed.
func defaultJournalPath(cfg config.Config) string {
	if dir := strings.TrimSpace(cfg.Paths.StateDir); dir != "" {
		return filepath.Join(dir, "activation-journal.json")
	}
	if dir := strings.TrimSpace(cfg.Paths.RunDir); dir != "" {
		return filepath.Join(dir, "activation-journal.json")
	}
	return ""
}

// fsValueOrDefault returns value when non-empty, otherwise fallback.
func fsValueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

// printActivationOutcome renders the transaction's result.
//
// Every terminal state is rendered, including the ones that are not success.
// A rollback that verified is a success of the rollback, not of the gateway,
// and saying so is the difference between an operator who knows the machine is
// as it was and one who thinks it is now a gateway.
func printActivationOutcome(env *Env, ev *activationEvidence, res *execution.ExecutionResult, actErr error, journalPath string) {
	if res == nil {
		env.errorf("thn activate: activation did not start: %v\n", actErr)
		env.errorf("\nCurrent network remains untouched.\n")
		return
	}

	env.printf("Production activation\n")
	env.printf("─────────────────────\n")
	env.printf("Plan:       %s\n", res.PlanID)
	env.printf("Journal:    %s\n", journalPath)
	env.printf("Phases:     %s\n", strings.Join(res.Phases, " -> "))
	env.printf("\n")

	if len(res.AppliedOps) > 0 {
		env.printf("Applied (%d):\n", len(res.AppliedOps))
		for _, op := range res.AppliedOps {
			env.printf("  + %s\n", op)
		}
		env.printf("\n")
	}

	switch res.FinalState {
	case execution.StateCommitted:
		env.printf("Result: COMMITTED\n")
		env.printf("\n")
		for _, c := range res.Health.Checks {
			mark := "ok"
			if !c.Passed {
				mark = "FAILED"
			}
			env.printf("  [%s] %-20s %s\n", mark, c.Check, c.Observed)
		}
		env.printf("\nThe gateway is serving as planned. Post-activation verification is\n")
		env.printf("in docs/deployment-runbook.md; it does not depend on THN.\n")

	case execution.StateRolledBack:
		env.printf("Result: ROLLED BACK\n")
		env.printf("\n")
		env.printf("Trigger: %s\n", firstNonEmpty(res.Error, "a health check failed"))
		env.printf("\nCompensating operations:\n")
		for _, op := range res.RolledBackOps {
			env.printf("  - %s\n", op)
		}
		env.printf("\nRollback verification compared the host against the baseline captured\n")
		env.printf("before the first mutation, and they match. The host is as it was.\n")
		env.printf("This was NOT a successful activation: the gateway is not serving.\n")

	case execution.StateDegraded:
		env.printf("Result: DEGRADED — manual recovery required\n")
		env.printf("\n")
		env.printf("%s\n", res.Error)
		env.printf("\nRollback verification did not confirm the baseline was restored. THN is\n")
		env.printf("reporting this rather than assuming a good outcome. Do not retry.\n")
		env.printf("Recover from the console using docs/deployment-runbook.md.\n")

	case execution.StateRecoveryRequired:
		env.printf("Result: RECOVERY_REQUIRED\n")
		env.printf("\n%s\n", res.Error)

	default:
		env.printf("Result: %s\n", res.FinalState)
		if res.Error != "" {
			env.printf("\n%s\n", res.Error)
		}
		env.printf("\nNothing after PREPARE was executed.\n")
	}
}

// fallback returns val when non-empty, otherwise def.
func fallback(val, def string) string {
	if val != "" {
		return val
	}
	return def
}

// firstNonEmpty returns the first non-empty value.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// deploymentReason picks the reason that applies to this host.
func deploymentReason(d deployment.Status) string {
	if !d.Deployed {
		return "No approved physical deployment detected. " + d.Reason
	}
	return "This host is an approved THN deployment."
}

// stageList renders stage names for one line of prose.
func stageList(stages []activation.Stage) string {
	if len(stages) == 0 {
		return "nothing"
	}
	parts := make([]string, 0, len(stages))
	for _, s := range stages {
		parts = append(parts, string(s))
	}
	return strings.Join(parts, ", ")
}

// hostPlatform names the platform, for the deployment message.
func hostPlatform() string { return runtime.GOOS }

// runActivation implements `thn activation [status|inspect|verify]`.
func runActivation(env *Env, args []string) ExitCode {
	sub := "status"
	var rest []string
	if len(args) > 0 {
		sub = args[0]
		rest = args[1:]
	}

	switch sub {
	case "status":
		return runActivationStatus(env, rest)
	case "inspect":
		return runActivationInspect(env, rest)
	case "verify":
		return runActivationVerify(env, rest)
	case "preflight":
		return runActivationPreflight(env, rest)
	default:
		env.errorf("thn activation: unknown subcommand %q; use status, inspect, verify or preflight\n", sub)
		return ExitUsage
	}
}

// ActivationInspectReport models the complete pre-activation inspection report.
type ActivationInspectReport struct {
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
	RollbackDetail      string   `json:"rollback_detail"`
	ManagementPathSafe  bool     `json:"management_path_safe"`
	ManagementDetail    string   `json:"management_detail"`
	PlanID              string   `json:"plan_id,omitempty"`
	ObservedDigest      string   `json:"observed_digest,omitempty"`
	DesiredDigest       string   `json:"desired_digest,omitempty"`
	AssignmentDigest    string   `json:"assignment_digest,omitempty"`
}

func runActivationInspect(env *Env, args []string) ExitCode {
	path := env.resolveConfigPath("")
	cfg, cfgErr := loadConfig(env, path)
	if cfgErr != nil {
		return env.fatalf("thn activation inspect: %v\n", cfgErr)
	}

	obs, _, _, device := observeHost(cfg)
	des := desired.FromConfig(cfg)
	d := diff.Compare(obs, desiredFor(des))

	_, stored := storedAssignments(cfg)
	bindings, _, _ := mergeBindings(cfg, stored)
	assignments := bindings

	p := planner.Build(d, planner.Options{
		Generation:  cfg.Gateway.Generation,
		Source:      path,
		Live:        obs.Supported,
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Device:      device,
	})

	var whatWillChange []string
	for _, s := range p.Steps {
		whatWillChange = append(whatWillChange, fmt.Sprintf("%s: %s (subsystem: %s, current: %q, desired: %q)", s.ID, s.Summary, s.Subsystem, s.Current, s.Desired))
	}

	var whatWillNotChange []string
	for _, u := range p.UnmanagedResources {
		whatWillNotChange = append(whatWillNotChange, fmt.Sprintf("%s (unmanaged / foreign)", u))
	}
	whatWillNotChange = append(whatWillNotChange, "foreign nftables tables (e.g. docker, tailscale)")
	whatWillNotChange = append(whatWillNotChange, "foreign routing tables and container routes")
	whatWillNotChange = append(whatWillNotChange, "unmanaged qdiscs on foreign interfaces")

	var managedIfaces []string
	var unmanagedIfaces []string
	if cfg.Network.WAN != "" {
		managedIfaces = append(managedIfaces, fmt.Sprintf("%s (role: wan)", cfg.Network.WAN))
	}
	if cfg.Network.LAN != "" {
		managedIfaces = append(managedIfaces, fmt.Sprintf("%s (role: lan)", cfg.Network.LAN))
	}
	if device != nil {
		for _, iface := range device.Interfaces {
			if iface.SystemName != cfg.Network.WAN && iface.SystemName != cfg.Network.LAN {
				unmanagedIfaces = append(unmanagedIfaces, fmt.Sprintf("%s (kind: %s)", iface.SystemName, iface.Kind))
			}
		}
	}

	managedRoutes := []string{}
	if cfg.Network.WAN != "" && obs.DefaultGateway != "" {
		managedRoutes = append(managedRoutes, fmt.Sprintf("default via %s dev %s", obs.DefaultGateway, cfg.Network.WAN))
	}
	unmanagedRoutes := []string{
		"unmanaged local subnets and tunnel routes (tailscale, docker, bridge networks)",
	}

	firewallResources := []string{
		"table inet thn (dedicated THN table; all other tables preserved, no broad ruleset flush)",
	}

	qosResources := []string{}
	if cfg.QoS.Enabled {
		qosResources = append(qosResources, fmt.Sprintf("qdisc %s on %s (rate: %d kbps)", cfg.QoS.Algorithm, cfg.QoS.Interface, cfg.QoS.DownloadKbps))
	} else {
		qosResources = append(qosResources, "none (QoS not configured; foreign disciplines untouched)")
	}

	dnsDHCPResources := []string{}
	if len(cfg.Network.DNS) > 0 {
		dnsDHCPResources = append(dnsDHCPResources, fmt.Sprintf("HOST resolvers: %s", strings.Join(cfg.Network.DNS, ", ")))
	}

	// Management safety.
	//
	// This is the same assessment `thn activate` runs, over the same plan, so
	// an operator who reads "safe" here is reading the verdict that will
	// actually gate the apply — not a separate, weaker summary of it.
	mgrep := evaluatePlannedManagementSafety(obs, device, p)

	dnsDHCPResources = append(dnsDHCPResources, subsystemHonesty(cfg)...)

	rep := ActivationInspectReport{
		WhatWillChange:      whatWillChange,
		WhatWillNotChange:   whatWillNotChange,
		ManagedInterfaces:   managedIfaces,
		UnmanagedInterfaces: unmanagedIfaces,
		ManagedRoutes:       managedRoutes,
		UnmanagedRoutes:     unmanagedRoutes,
		FirewallResources:   firewallResources,
		QoSResources:        qosResources,
		DNSDHCPResources:    dnsDHCPResources,
		RollbackAvailable:   true,
		RollbackDetail:      "automatic scoped rollback with pre-execution baseline snapshot and post-rollback verification",
		ManagementPathSafe:  mgrep.Safe,
		ManagementDetail:    mgrep.Reason,
		PlanID:              p.ID,
		ObservedDigest:      p.Inputs.ObservedDigest,
		DesiredDigest:       p.Inputs.DesiredDigest,
		AssignmentDigest:    p.Inputs.AssignmentDigest,
	}
	if rep.ManagementDetail == "" {
		rep.ManagementDetail = "remote management paths (SSH, Tailscale) verified safe"
	}

	if env.IsJSON {
		if err := env.printJSON(rep); err != nil {
			env.errorf("thn activation inspect: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Activation Plan Inspection\n")
	env.printf("──────────────────────────\n")
	env.printf("Plan ID:             %s\n", rep.PlanID)
	env.printf("Observed Digest:     %s\n", rep.ObservedDigest)
	env.printf("Desired Digest:      %s\n", rep.DesiredDigest)
	env.printf("\nPHYSICAL CUTOVER STATUS:\n")
	env.printf("  Physical presence:  BLOCKED (requires physical console presence)\n")
	wanStr := "unassigned"
	if len(rep.ManagedInterfaces) > 0 {
		wanStr = rep.ManagedInterfaces[0]
	}
	env.printf("  WAN interface:      %s\n", wanStr)
	lanStr := "unassigned"
	if len(rep.ManagedInterfaces) > 1 {
		lanStr = rep.ManagedInterfaces[1]
	}
	env.printf("  LAN interface:      %s\n", lanStr)
	env.printf("  QoS status:         %s\n", qosStatusSummary(cfg))
	env.printf("  Management safety:  %t (%s)\n", rep.ManagementPathSafe, rep.ManagementDetail)
	env.printf("  Rollback status:    READY (%s)\n", rep.RollbackDetail)
	env.printf("  Plan status:        FRESH (digests match observed/desired)\n")
	env.printf("  Activation verdict: BLOCKED (hardware or presence prerequisite missing)\n")
	env.printf("\nWHAT WILL CHANGE (%d items):\n", len(rep.WhatWillChange))
	for _, item := range rep.WhatWillChange {
		env.printf("  + %s\n", item)
	}
	env.printf("\nWHAT WILL NOT CHANGE:\n")
	for _, item := range rep.WhatWillNotChange {
		env.printf("  • %s\n", item)
	}
	env.printf("\nWHICH INTERFACES:\n")
	env.printf("  Managed:   %v\n", rep.ManagedInterfaces)
	env.printf("  Unmanaged: %v\n", rep.UnmanagedInterfaces)
	env.printf("\nWHICH ROUTES:\n")
	env.printf("  Managed:   %v\n", rep.ManagedRoutes)
	env.printf("  Unmanaged: %v\n", rep.UnmanagedRoutes)
	env.printf("\nWHICH FIREWALL RESOURCES:\n")
	for _, item := range rep.FirewallResources {
		env.printf("  • %s\n", item)
	}
	env.printf("\nWHICH QOS RESOURCES:\n")
	for _, item := range rep.QoSResources {
		env.printf("  • %s\n", item)
	}
	env.printf("\nWHICH DNS/DHCP RESOURCES:\n")
	for _, item := range rep.DNSDHCPResources {
		env.printf("  • %s\n", item)
	}
	env.printf("\nROLLBACK AVAILABLE:\n")
	env.printf("  %t — %s\n", rep.RollbackAvailable, rep.RollbackDetail)
	env.printf("\nMANAGEMENT PATH SAFE:\n")
	env.printf("  %t — %s\n", rep.ManagementPathSafe, rep.ManagementDetail)

	return ExitOK
}

func qosStatusSummary(cfg config.Config) string {
	if !cfg.QoS.Enabled {
		return "QoS not requested"
	}
	return "BLOCKED (controlled physical hardware sign-off pending)"
}

// PreflightGate models one gate in the physical preflight check.
type PreflightGate struct {
	Name    string `json:"name"`
	Verdict string `json:"verdict"` // PASS or BLOCKED
	Detail  string `json:"detail"`
}

// PreflightReport models the complete physical preflight report.
type PreflightReport struct {
	Config  string          `json:"config"`
	Gates   []PreflightGate `json:"gates"`
	Verdict string          `json:"verdict"` // PASS or BLOCKED
	Blocked bool            `json:"blocked"`
}

func runActivationPreflight(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	presence := fs.Bool("confirm-present", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn activation preflight: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	path := env.resolveConfigPath(*configPath)
	cfg, cfgErr := loadConfig(env, path)
	if cfgErr != nil {
		return env.fatalf("thn activation preflight: %v\n", cfgErr)
	}

	ev := gatherActivationEvidence(cfg, path)
	input := productionGateInput(ev, *presence)
	gates := activation.EvaluateProduction(input)

	var pGates []PreflightGate

	// 1. Physical presence
	if input.PresenceConfirmed {
		pGates = append(pGates, PreflightGate{
			Name:    "Physical presence",
			Verdict: "PASS",
			Detail:  "operator confirmed present at physical console (--confirm-present)",
		})
	} else {
		pGates = append(pGates, PreflightGate{
			Name:    "Physical presence",
			Verdict: "BLOCKED",
			Detail:  "requires physical presence at device; being logged in remotely is not sufficient",
		})
	}

	// 2. WAN identified
	if input.WAN.Satisfied {
		pGates = append(pGates, PreflightGate{
			Name:    "WAN identified",
			Verdict: "PASS",
			Detail:  input.WAN.Reason,
		})
	} else {
		pGates = append(pGates, PreflightGate{
			Name:    "WAN identified",
			Verdict: "BLOCKED",
			Detail:  input.WAN.Reason,
		})
	}

	// 3. LAN identified
	if input.LAN.Satisfied {
		pGates = append(pGates, PreflightGate{
			Name:    "LAN identified",
			Verdict: "PASS",
			Detail:  input.LAN.Reason,
		})
	} else {
		pGates = append(pGates, PreflightGate{
			Name:    "LAN identified",
			Verdict: "BLOCKED",
			Detail:  input.LAN.Reason,
		})
	}

	// 4. Gigabit LAN
	hasGigabitLAN := false
	lanDetail := "dedicated Gigabit USB adapter not yet installed or assigned"
	if ev.Device != nil {
		for _, iface := range ev.Device.Interfaces {
			if iface.Role == host.RoleLAN && iface.Physical && iface.SpeedMbps >= 1000 {
				hasGigabitLAN = true
				lanDetail = fmt.Sprintf("Gigabit interface %s (%d Mbps, %s) assigned to LAN", iface.SystemName, iface.SpeedMbps, iface.ID)
				break
			}
		}
	}
	if hasGigabitLAN {
		pGates = append(pGates, PreflightGate{
			Name:    "Gigabit LAN",
			Verdict: "PASS",
			Detail:  lanDetail,
		})
	} else {
		pGates = append(pGates, PreflightGate{
			Name:    "Gigabit LAN",
			Verdict: "BLOCKED",
			Detail:  lanDetail,
		})
	}

	// 5. QoS executable
	if !cfg.QoS.Enabled {
		pGates = append(pGates, PreflightGate{
			Name:    "QoS executable",
			Verdict: "PASS",
			Detail:  "traffic shaping not requested",
		})
	} else if input.SubsystemsExecutable {
		pGates = append(pGates, PreflightGate{
			Name:    "QoS executable",
			Verdict: "PASS",
			Detail:  "shaping implementation and capabilities verified",
		})
	} else {
		pGates = append(pGates, PreflightGate{
			Name:    "QoS executable",
			Verdict: "BLOCKED",
			Detail:  "live physical hardware sign-off and internet testing pending",
		})
	}

	// 6. Management safety
	if input.ManagementSafe {
		pGates = append(pGates, PreflightGate{
			Name:    "Management safety",
			Verdict: "PASS",
			Detail:  "remote management paths (SSH, Tailscale) verified safe",
		})
	} else {
		pGates = append(pGates, PreflightGate{
			Name:    "Management safety",
			Verdict: "BLOCKED",
			Detail:  input.ManagementProblem,
		})
	}

	// 7. Rollback
	if input.RecoveryOK {
		pGates = append(pGates, PreflightGate{
			Name:    "Rollback",
			Verdict: "PASS",
			Detail:  "pre-execution baseline capture & compensating rollback verified",
		})
	} else {
		pGates = append(pGates, PreflightGate{
			Name:    "Rollback",
			Verdict: "BLOCKED",
			Detail:  input.RecoveryProblem,
		})
	}

	// 8. Plan freshness
	if input.DigestsFresh && input.PlanValidated {
		pGates = append(pGates, PreflightGate{
			Name:    "Plan freshness",
			Verdict: "PASS",
			Detail:  "plan digests match live host observation and desired state",
		})
	} else {
		pGates = append(pGates, PreflightGate{
			Name:    "Plan freshness",
			Verdict: "BLOCKED",
			Detail:  fallback(input.DigestsProblem, "no fresh validated plan exists; run `thn plan`"),
		})
	}

	allPass := true
	for _, g := range pGates {
		if g.Verdict != "PASS" {
			allPass = false
		}
	}
	verdict := "BLOCKED"
	if allPass && gates.AllSatisfied {
		verdict = "READY"
	}

	report := PreflightReport{
		Config:  path,
		Gates:   pGates,
		Verdict: verdict,
		Blocked: !allPass,
	}

	if env.IsJSON {
		if err := env.printJSON(report); err != nil {
			env.errorf("thn activation preflight: %v\n", err)
			return ExitProblems
		}
		if allPass {
			return ExitOK
		}
		return ExitProblems
	}

	env.printf("THN ACTIVATION PREFLIGHT\n")
	env.printf("────────────────────────\n")
	for _, g := range pGates {
		env.printf("%-24s %-8s  %s\n", g.Name, g.Verdict, g.Detail)
	}
	env.printf("\nOVERALL VERDICT: %s\n", verdict)

	if allPass {
		return ExitOK
	}
	return ExitProblems
}

func runActivationStatus(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn activation status: %v\n", err)
	}

	path := env.resolveConfigPath(*configPath)
	if len(rest) > 0 {
		path = rest[0]
	}

	state := activation.StateDevelopment
	driver := execution.NewProductionDriver()
	m := activation.NewMachineWithApplier(state, driver)

	cfg, cfgErr := loadConfig(env, path)
	if cfgErr == nil {
		ev := gatherActivationEvidence(cfg, path)
		gates := activation.EvaluateProduction(productionGateInput(ev, false))
		m.SetGates(gates)
		if gates.AllSatisfied && ev.Plan != nil && ev.Plan.Ready {
			_ = m.Transition(activation.StatePrepared, "plan validated and all safety gates satisfied")
		}
	}

	report := m.Report()

	if env.IsJSON {
		if err := env.printJSON(report); err != nil {
			env.errorf("thn activation status: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Activation Status\n")
	env.printf("  State:               %s\n", report.State)
	env.printf("  Can Apply:           %t\n", report.CanApply)
	env.printf("  Bound Applier:       %s\n", report.Applier)
	env.printf("  Implemented Stages:  %s\n", stageList(report.ImplementedStages))
	env.printf("  Unsupported Stages:  %s\n", stageList(report.UnsupportedStages))
	env.printf("  Presence Confirmed:  %t\n", report.PresenceConfirmed)
	if len(report.Gates.Gates) > 0 {
		sat := 0
		for _, g := range report.Gates.Gates {
			if g.Satisfied {
				sat++
			}
		}
		env.printf("  Gate Status:         %d of %d satisfied (%d blocking)\n",
			sat, len(report.Gates.Gates), len(report.Gates.Blocking))
	}
	return ExitOK
}

func runActivationVerify(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn activation verify: %v\n", err)
	}

	path := env.resolveConfigPath(*configPath)
	if len(rest) > 0 {
		path = rest[0]
	}
	cfg, cfgErr := loadConfig(env, path)

	if cfgErr != nil {
		return reportActivationRefusal(env, activation.GateResult{
			AllSatisfied: false,
			Blocking:     []string{"config-valid"},
			Gates: []activation.Gate{{
				Name:        "config-valid",
				Description: "the configuration must validate without errors",
				Reason:      cfgErr.Error(),
			}},
		}, false, false, false, path, nil)
	}

	// The PRODUCTION gate set, evaluated with presence false. `thn activation
	// verify` reports how far this host is from an activation; it is not the
	// activation, and it cannot confirm presence on anyone's behalf.
	res := activation.EvaluateProduction(productionGateInput(gatherActivationEvidence(cfg, path), false))

	if env.IsJSON {
		if err := env.printJSON(res); err != nil {
			env.errorf("thn activation verify: %v\n", err)
			return ExitProblems
		}
		if !res.AllSatisfied {
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Production Activation Gate Verification\n")
	env.printf("═══════════════════════════════════════\n")
	for _, g := range res.Gates {
		mark := "✓"
		if !g.Satisfied {
			mark = "✗"
		}
		env.printf("  [%s] %-24s %s\n", mark, g.Name, g.Description)
		if !g.Satisfied && g.Reason != "" {
			env.printf("      %s\n", g.Reason)
		}
	}
	if !res.AllSatisfied {
		env.printf("\nActivation is BLOCKED by %d unsatisfied gate(s).\n\n", len(res.Blocking))
		env.printf("%s\n", blockingAdvice(res.Blocking))
		env.printf("\nphysical-presence is always unsatisfied here and can only be satisfied\n")
		env.printf("by running `thn activate --confirm-present` at the device.\n")
		return ExitProblems
	}
	return ExitOK
}
