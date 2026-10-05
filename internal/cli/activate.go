package cli

import (
	"runtime"
	"strings"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/deployment"
	"github.com/venth/thn-gateway/internal/network"
)

// This file implements `thn activate`, which refuses.
//
// # Why the refusal leads with deployment rather than with the build
//
// There are two situations an operator can be in when they type `thn activate`,
// and they need different answers.
//
//   - The machine is not a gateway. A laptop, a CI runner, a development box.
//     Nothing here was ever supposed to change, and the useful answer says so
//     and says the network is untouched.
//   - The machine is a gateway, running a build that cannot apply. Real
//     hardware, software limitation. A different sentence, with a different
//     remedy.
//
// Leading with "this build has no apply path" answers the second on a box where
// the first is true, which is talking about the software when the operator asked
// about their machine. Leading with deployment answers the first correctly and
// the second accurately too, because on a deployed box the deployment check
// passes and the message moves on to the real reason.
//
// # "Current network remains untouched" is a contract, not a reassurance
//
// It is the most important sentence in the output, because the person deciding
// whether to be afraid needs it before they read anything else. There is no code
// path through this command that changes anything, so there is no branch in
// which the sentence would be false — and it is printed unconditionally rather
// than only in the case that happens to apply today.

// runActivate implements `thn activate`.
func runActivate(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("yes", false)
	fs.Bool("confirm-present", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn activate: %v\n", err)
	}

	// --yes is accepted and does nothing. It is accepted so a runbook written
	// against a future build does not fail on a flag it does not understand; it
	// is not honoured because there is nothing to confirm.
	if *fs.bools["yes"] {
		env.errorf("thn activate: --yes is accepted for forward compatibility and " +
			"changes nothing.\n")
		env.errorf("There is no apply path for it to confirm.\n\n")
	}

	deploy := detectDeployment(env)

	if env.IsJSON {
		out := map[string]any{
			"activated":            false,
			"deployment":           deploy,
			"can_apply":            activation.CanApply(),
			"network_untouched":    true,
			"statement":            "Current network remains untouched.",
			"reason":               deploymentReason(deploy),
			"implemented_stages":   activation.ImplementedStages(),
			"unimplemented_stages": activation.UnsupportedStages(),
		}
		if err := env.printJSON(out); err != nil {
			env.errorf("thn activate: %v\n", err)
			return ExitProblems
		}
		return ExitProblems
	}

	printActivationRefusal(env, deploy)
	return ExitProblems
}

// deploymentReason picks the reason that applies to this host.
func deploymentReason(d deployment.Status) string {
	if !d.Deployed {
		return "No approved physical deployment detected. " + d.Reason
	}
	return "This build has no apply path; it contains no code that can modify host networking."
}

// detectDeployment asks whether this host is an approved deployment.
//
// A configuration that will not load, or a host that cannot be inspected, is
// not a deployment. Both are reported as such rather than producing a confusing
// failure somewhere later.
func detectDeployment(env *Env) deployment.Status {
	path := env.resolveConfigPath("")

	cfg, err := loadConfig(env, path)
	if err != nil {
		// The configuration is unreadable, so nothing about this host is known.
		return deployment.Detect(deployment.Observation{HostPlatform: hostPlatform()})
	}

	o := deployment.Observation{
		HostPlatform:  hostPlatform(),
		GatewayName:   cfg.Gateway.Name,
		ConfiguredWAN: cfg.Network.WAN,
		ConfiguredLAN: cfg.Network.LAN,
	}

	snap, err := network.NewInspector().Inspect(cmdContext())
	if err != nil || snap == nil || !snap.Supported {
		return deployment.Detect(o)
	}

	o.HostSupported = true
	for _, i := range snap.Interfaces {
		o.Interfaces = append(o.Interfaces, i.Name)
	}
	return deployment.Detect(o)
}

// printActivationRefusal writes the refusal.
//
// The two branches are deliberately different sentences. A box that is not a
// gateway should not be told about apply paths; a gateway should not be told it
// is not deployed.
func printActivationRefusal(env *Env, deploy deployment.Status) {
	env.errorf("thn activate: activation refused.\n\n")

	if !deploy.Deployed {
		env.errorf("THN Gateway is not physically deployed.\n")
		env.errorf("\n")
		env.errorf("Activation refused.\n")
		env.errorf("\n")
		env.errorf("Reason:\n")
		env.errorf("No approved physical deployment detected.\n")
		env.errorf("\n")
		env.errorf("  %s\n", deploy.Reason)
		env.errorf("\n")
		env.errorf("Current network remains untouched.\n")
		env.errorf("\n")

		// Both facts are true here and both are worth stating.
		//
		// The box is not a gateway, and separately this build could not apply
		// anything even on one that were. Leading with deployment says the
		// useful thing; omitting the apply path would leave an operator who
		// moves this build to real hardware without knowing that the refusal
		// would simply change its wording rather than its outcome.
		env.errorf("Also, independently of the above:\n")
		env.errorf("  no apply path: this build has no code path that can modify host networking.\n")
		env.errorf("  It implements: %s\n", stageList(activation.ImplementedStages()))
		env.errorf("  Not implemented: %s\n", stageList(activation.UnsupportedStages()))
		env.errorf("\n")
		env.errorf("Evidence\n")
		env.errorf("--------\n")
		for _, s := range deploy.Signals {
			mark := "no"
			if s.Met {
				mark = "yes"
			}
			env.errorf("  [%s] %-18s %s\n", mark, s.Name, s.Detail)
		}
		env.errorf("\n")
		env.errorf("This build can, on any host:\n")
		env.errorf("  thn status            what the configuration asks for\n")
		env.errorf("  thn diagnostics       system and THN health\n")
		env.errorf("  thn network inspect   the host's network, read-only\n")
		env.errorf("  thn config validate   whether the configuration is coherent\n")
		env.errorf("  thn plan              what a change would consist of, without making one\n")
		return
	}

	// Real hardware, software limitation. Saying "not deployed" here would be
	// the mirror-image mistake.
	env.errorf("This host is an approved THN deployment.\n")
	env.errorf("\n")
	env.errorf("Activation refused.\n")
	env.errorf("\n")
	env.errorf("Reason:\n")
	env.errorf("This build has no apply path: there is no code path that can modify host networking.\n")
	env.errorf("  It implements: %s\n", stageList(activation.ImplementedStages()))
	env.errorf("  Not implemented: %s\n", stageList(activation.UnsupportedStages()))
	env.errorf("\n")
	env.errorf("Current network remains untouched.\n")
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

// runActivation implements `thn activation [status|verify]`.
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
	case "verify":
		return runActivationVerify(env, rest)
	default:
		env.errorf("thn activation: unknown subcommand %q; use status or verify\n", sub)
		return ExitUsage
	}
}

func runActivationStatus(env *Env, args []string) ExitCode {
	m := activation.NewMachine(activation.StateDevelopment)
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
	return ExitOK
}

func runActivationVerify(env *Env, args []string) ExitCode {
	path := env.resolveConfigPath("")
	cfg, cfgErr := loadConfig(env, path)

	var in activation.GateInput
	if cfgErr != nil {
		in.ConfigValid = false
		in.ConfigProblem = cfgErr.Error()
	} else {
		in.ConfigValid = true
		in.WAN = activation.RoleGate{Role: "wan", Satisfied: cfg.Network.WAN != "", Interface: cfg.Network.WAN}
		in.LAN = activation.RoleGate{Role: "lan", Satisfied: cfg.Network.LAN != "", Interface: cfg.Network.LAN}
	}

	res := activation.Evaluate(in)

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

	env.printf("Activation Gate Verification\n")
	for _, g := range res.Gates {
		mark := "✓"
		if !g.Satisfied {
			mark = "✗"
		}
		env.printf("  [%s] %-22s %s\n", mark, g.Name, g.Description)
		if !g.Satisfied && g.Reason != "" {
			env.printf("      Reason: %s\n", g.Reason)
		}
	}
	if !res.AllSatisfied {
		env.printf("\nActivation is BLOCKED by %d unsatisfied gate(s).\n", len(res.Blocking))
		return ExitProblems
	}
	return ExitOK
}
