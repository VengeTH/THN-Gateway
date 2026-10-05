package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/dhcp"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/dns"
	"github.com/venth/thn-gateway/internal/firewall"
	fwpolicy "github.com/venth/thn-gateway/internal/firewall/policy"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/netconfig"
	"github.com/venth/thn-gateway/internal/network"
	"github.com/venth/thn-gateway/internal/planner"
	"github.com/venth/thn-gateway/internal/schema"
	"github.com/venth/thn-gateway/internal/validation"
)

// commands is the dispatch table.
//
// Tier is the important field: it is what tells a reader which commands are
// safe to run unattended, and it is asserted by TestCommandTiersMatchSafety.
var commands = map[string]Command{
	"validate": {
		Name:    "validate",
		Tier:    TierPure,
		Summary: "check a configuration for coherence, optionally against this host",
		Run:     runValidate,
	},
	"plan": {
		Name:    "plan",
		Tier:    TierPure,
		Summary: "show what would change to reach the configured state",
		Run:     runPlan,
	},
	"config": {
		Name:    "config",
		Tier:    TierPure,
		Summary: "inspect configuration (show, validate, plan)",
		Run:     runConfig,
	},
	"status": {
		Name:    "status",
		Tier:    TierLive,
		Summary: "report live gateway state from thnd",
		Run:     runStatus,
	},
	"diagnostics": {
		Name:    "diagnostics",
		Tier:    TierLive,
		Summary: "report system and THN health",
		Run:     runDiagnostics,
	},
	"activate": {
		Name:    "activate",
		Tier:    TierDestructive,
		Summary: "apply the configuration (not available in this build)",
		Run:     runActivate,
	},
	"activation": {
		Name:    "activation",
		Tier:    TierPure,
		Summary: "report activation status or verify safety gates (status, verify)",
		Run:     runActivation,
	},
	"schema": {
		Name:    "schema",
		Tier:    TierPure,
		Summary: "print the configuration schema catalogue",
		Run:     runSchema,
	},
	"firewall": {
		Name:    "firewall",
		Tier:    TierPure,
		Summary: "render the firewall ruleset (render, validate, show)",
		Run:     runFirewall,
	},
	"net": {
		Name:    "net",
		Tier:    TierPure,
		Summary: "render, validate or simulate routing, NAT and forwarding",
		Run:     runNet,
	},
	"network": {
		Name:    "network",
		Tier:    TierPure,
		Summary: "inspect the host's network, read-only",
		Run:     runNetwork,
	},
	"simulate": {
		Name:    "simulate",
		Tier:    TierPure,
		Summary: "trace a packet through the data plane",
		Run:     runSimulate,
	},
	"dhcp": {
		Name:    "dhcp",
		Tier:    TierPure,
		Summary: "render or inspect DHCP (render, validate, leases)",
		Run:     runDHCP,
	},
	"dns": {
		Name:    "dns",
		Tier:    TierPure,
		Summary: "render or inspect DNS (render, validate, lookup)",
		Run:     runDNS,
	},
	"qos": {
		Name:    "qos",
		Tier:    TierPure,
		Summary: "render or inspect traffic shaping (render, validate, stats, available)",
		Run:     runQoS,
	},
	"rules": {
		Name:    "rules",
		Tier:    TierPure,
		Summary: "list the shipped rules, or evaluate them against an observation",
		Run:     runRules,
	},
	"policy": {
		Name:    "policy",
		Tier:    TierPure,
		Summary: "list per-device policies, or resolve what applies to a device",
		Run:     runPolicy,
	},
	"incidents": {
		Name:    "incidents",
		Tier:    TierPure,
		Summary: "show what the current observations imply",
		Run:     runIncidents,
	},
	"explain": {
		Name:    "explain",
		Tier:    TierPure,
		Summary: "explain the current observations in prose, with reasons and remedies",
		Run:     runExplain,
	},
	"ask": {
		Name:    "ask",
		Tier:    TierPure,
		Summary: "ask a question about the current observations in plain language",
		Run:     runAsk,
	},
	"suggest": {
		Name:    "suggest",
		Tier:    TierPure,
		Summary: "propose correlation rules from what has been observed, for review",
		Run:     runSuggest,
	},
	"authority": {
		Name:    "authority",
		Tier:    TierPure,
		Summary: "show what may be changed, by whom, and under what approval",
		Run:     runAuthority,
	},
	"reconcile": {
		Name:    "reconcile",
		Tier:    TierPure,
		Summary: "ask the gateway whether it would accept the configured state",
		Run:     runReconcile,
	},
	"verify": {
		Name:    "verify",
		Tier:    TierPure,
		Summary: "check a signed artifact's provenance and refuse it if anything is wrong",
		Run:     runVerify,
	},
	"health": {
		Name:    "health",
		Tier:    TierPure,
		Summary: "assess the gateway against a change set, including what cannot be read",
		Run:     runHealth,
	},
	"rollout": {
		Name:    "rollout",
		Tier:    TierPure,
		Summary: "report what a staged deployment should do next, and stop on deterioration",
		Run:     runRollout,
	},
	"rollback": {
		Name:    "rollback",
		Tier:    TierPure,
		Summary: "describe what returning to a previous configuration would involve",
		Run:     runRollback,
	},
	"readiness": {
		Name:    "readiness",
		Tier:    TierPure,
		Summary: "report whether this gateway could be activated, and what blocks it",
		Run:     runReadiness,
	},
	"discover": {
		Name:    "discover",
		Tier:    TierPure,
		Summary: "report this machine's interfaces, roles and capabilities",
		Run:     runDiscover,
	},
	"interface": {
		Name:    "interface",
		Tier:    TierPure,
		Summary: "list interfaces and bind them to logical roles (records intent only)",
		Run:     runInterface,
	},
	"appliance": {
		Name:    "appliance",
		Tier:    TierPure,
		Summary: "describe and verify the appliance image (manifest, verify, status)",
		Run:     runAppliance,
	},
}

// Run dispatches a command line and returns the process exit code.
func Run(env *Env) ExitCode {
	// --json is documented as a global flag, so it has to work before the verb
	// as well as after it. `thn --json status` used to be read as a command
	// called "--json" and fail with the usage text, which is the first thing
	// anyone writes after seeing "Global flags: --json" in --help.
	args := env.Args
	if len(args) > 0 && args[0] == "--json" {
		env.IsJSON = true
		args = args[1:]
	}

	if len(args) == 0 {
		printUsage(env.Stdout)
		return ExitUsage
	}

	name := args[0]
	cmd, ok := commands[name]
	if !ok {
		env.errorf("thn: unknown command %q\n\n", name)
		printUsage(env.Stderr)
		return ExitUsage
	}

	rest := args[1:]

	// The same flag after the verb, which is where it has always worked.
	if hasJSONFlag(rest) {
		env.IsJSON = true
		rest = stripJSONFlag(rest)
	}

	return cmd.Run(env, rest)
}

// hasJSONFlag reports whether the arguments request JSON output.
func hasJSONFlag(args []string) bool {
	for _, a := range args {
		if a == "--json" {
			return true
		}
	}
	return false
}

// stripJSONFlag removes the --json flag from the arguments.
func stripJSONFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--json" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// printUsage renders the command list.
func printUsage(w interface{ Write([]byte) (int, error) }) {
	fmt.Fprintln(w, "thn — THN gateway control")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: thn <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")

	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		c := commands[n]
		fmt.Fprintf(w, "  %-12s %-14s %s\n", c.Name, "["+string(c.Tier)+"]", c.Summary)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tiers:")
	fmt.Fprintln(w, "  pure        runs in-process; no daemon, no root, no network changes")
	fmt.Fprintln(w, "  live        asks thnd for the real gateway state")
	fmt.Fprintln(w, "  destructive changes host networking; refused in this build")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Global flags:")
	fmt.Fprintln(w, "  --json      emit machine-readable JSON")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  thn validate /etc/thn/config.yaml")
	fmt.Fprintln(w, "  thn plan --config /etc/thn/config.yaml")
	fmt.Fprintln(w, "  thn validate --live")
}

// loadConfig reads and normalises the configuration at path.
func loadConfig(env *Env, path string) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return cfg, err
	}
	if err := schema.CheckVersion(cfg.SchemaVersion); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// observeHost gathers a read-only snapshot of this host.
//
// Every external command it might run goes through internal/guard, so this
// function is incapable of changing host networking.
//
// The observed device is returned as well as the diff view, because the roles
// the operator asked for are resolved against it exactly once. Resolving them
// in two places would mean two answers to the same question, and they would
// drift the first time one of them gained a rule.
//
// Observation goes through host.NewDiscovery rather than calling the inspector
// directly. That is what makes `thn readiness`, `thn discover` and `thn plan`
// see the SAME machine in the SAME shape: one translation, one place that
// decides what a link is, and no command with a private idea of what an
// interface means.
func observeHost(cfg config.Config) (diff.Observed, *network.Snapshot, *firewall.FirewallState, *host.Device) {
	obs := diff.Observed{
		Supported: false,
		HostName:  hostname(),
	}

	snap, device, _ := host.NewDiscovery().Observe(cmdContext())
	if snap != nil {
		obs.Supported = snap.Supported
	}

	network.ApplyRoles(snap, network.InterfaceRoles{
		WAN: cfg.Network.WAN,
		LAN: cfg.Network.LAN,
	})

	// # Roles are resolved through assignment, never by guessing.
	//
	// This code previously did this:
	//
	//	if cfg.Network.LAN != "" { look it up by name } else {
	//	    adopt the first non-loopback interface that is not the WAN
	//	}
	//
	// `snap.Interfaces` is sorted by NAME, so "first" meant whichever
	// interface sorted first: routinely `bond0`, `docker0` or `tailscale0`
	// on a host that has any of those. It set LANPresent = true, and
	// readiness fed that straight into the `lan-identified` activation gate.
	// The gate therefore reported SATISFIED on an interface nobody named,
	// which is the exact failure the role model exists to prevent: a gateway
	// that would apply its LAN to the wrong link and look correct doing so.
	//
	// Unassigned now means unassigned. `thn discover` shows the host; it
	// does not decide for it.
	res := host.Resolve(device, roleAssignments(cfg))
	applyResolutionTo(device, res)

	// The WAN's addresses are observed but not recorded: THN does not manage
	// uplink addressing, so the diff must not compare it.
	if wan, ok := roleInterface(res, host.RoleWAN); ok {
		obs.WANPresent, obs.WANName, obs.WANUp = true, wan.SystemName, wan.LinkUp
	}

	if lan, ok := roleInterface(res, host.RoleLAN); ok {
		obs.LANPresent, obs.LANName, obs.LANUp = true, lan.SystemName, lan.LinkUp
		obs.LANAddresses = append(obs.LANAddresses, lan.Addresses...)
	}

	if r := snap.DefaultRoute(); r != nil {
		obs.HasDefaultRoute, obs.DefaultGateway = true, r.Gateway
	}

	if v, ok := snap.SysctlValue("net.ipv4.ip_forward"); ok {
		obs.IPv4Forwarding, obs.IPv4ForwardingKnown = v == "1", true
	}

	fw := firewall.NewObserver().ObserveFirewall(cmdContext())
	obs.FirewallActive = fw.Status == firewall.StatusActive
	obs.FirewallRuleCount = fw.RuleCount

	qos := firewall.NewObserver().ObserveQoS(cmdContext(), cfg.QoS.Interface)
	obs.QoSActive = qos.Status == firewall.StatusActive
	obs.QoSAlgorithm = qos.Algorithm

	return obs, snap, fw, device
}

// roleInterface returns the interface an assignment bound to a role.
//
// It reads the RESOLUTION rather than the device, because the resolution is
// the single place where "this interface holds this role" was decided. Reading
// the device directly would be a second implementation of that decision, and
// the two would disagree the first time Resolve gained a rule.
func roleInterface(res host.Resolution, r host.Role) (host.Interface, bool) {
	i, ok := res.Assigned[r]
	return i, ok
}

// roleAssignments translates configuration into role bindings.
//
// # Where the translation lives, and why
//
// It is here, in the CLI wiring layer, and not in internal/host.
//
// internal/host is the device model. It must be usable by a future UI, by
// `thnd`, and by a test that has no configuration file at all — so it takes
// selectors, not documents. The moment it imports internal/config, every one
// of those callers inherits a dependency on the YAML layer, and the model stops
// being testable on its own.
//
// This function is therefore the single seam between "what the operator wrote"
// and "what THN asked the host for". Changing the configuration surface means
// changing this function and nothing else.
//
// # Both keys are read
//
// network.wan and network.lan remain the advanced, explicit override: an
// operator may name a kernel interface directly. They are read here and become
// assignments like any other selector, so they take exactly the same path
// through validation as everything else. That is deliberate — an override that
// skipped the role model would be an override that skipped the checks.
func roleAssignments(cfg config.Config) []host.Assignment {
	storePath := resolveStorePath(cfg, "")
	stored := loadBindings(storePath)
	bindings, _, _ := mergeBindings(cfg, stored)
	return bindings
}

// desiredFor projects the diff package's structural view from desired.State.
//
// The conversion lives here rather than in internal/diff so that the diff
// package stays independent of the desired model and can be tested without it.
func desiredFor(d desired.State) diff.Desired {
	return diff.Desired{
		WANName:         d.WAN.Name,
		WANPresent:      d.WAN.Present,
		WANUp:           d.WAN.Up,
		LANName:         d.LAN.Name,
		LANPresent:      d.LAN.Present,
		LANUp:           d.LAN.Up,
		LANAddresses:    d.LAN.Addresses,
		DefaultGateway:  d.Addressing.DefaultGateway,
		UpstreamPresent: d.Addressing.UpstreamPresent,
		IPv4Forwarding:  d.Addressing.IPv4Forwarding,
		NATEnabled:      d.NAT.Enabled,
		NATResolved:     d.NAT.Resolved,
		FirewallEnabled: d.Firewall.Enabled,
		FirewallBackend: d.Firewall.Backend,
		FirewallPolicy:  d.Firewall.DefaultInboundPolicy,
		QoSEnabled:      d.QoS.Enabled,
		QoSResolved:     d.QoS.Resolved,
		QoSAlgorithm:    d.QoS.Algorithm,
		QoSInterface:    d.QoS.Interface,
		QoSDownloadKbps: d.QoS.DownloadKbps,
		QoSUploadKbps:   d.QoS.UploadKbps,
		DNSPresent:      d.DNS.Present,
		DNSServers:      d.DNS.Servers,
	}
}

// runValidate implements `thn validate`.
func runValidate(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	live := fs.Bool("live", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn validate: %v\n", err)
	}

	// A positional argument is accepted as the configuration path, which is
	// what makes `thn validate ./configs/home.yaml` read naturally.
	path := env.resolveConfigPath(*configPath)
	if len(rest) > 0 {
		path = rest[0]
	}
	if len(rest) > 1 {
		return env.fatalf("thn validate: expected at most one configuration path, got %d\n", len(rest))
	}

	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn validate: %v\n", err)
		return ExitProblems
	}

	// Check stored assignments for conflicts with declared configuration.
	storePath := resolveStorePath(cfg, "")
	stored := loadBindings(storePath)
	_, conflicts, _ := mergeBindings(cfg, stored)

	// A live run needs an observation; a static run does not, and must work
	// with no network, no root and no daemon.
	var obs *diff.Observed
	var dev *host.Device
	if *live {
		o, _, _, d := observeHost(cfg)
		obs = &o
		dev = d
	}

	var d diff.Result
	if obs != nil {
		res := host.Resolve(dev, roleAssignments(cfg))
		d = diff.Compare(*obs, desiredFor(desired.FromConfigWithResolution(cfg, res)))
	}

	result := validation.Combined(cfg, obs, d)

	// Report conflicts between declared configuration and stored assignments.
	if len(conflicts) > 0 {
		var conflictFindings []validation.Finding
		for _, c := range conflicts {
			conflictFindings = append(conflictFindings, validation.Finding{
				Layer:    validation.LayerStatic,
				Field:    "network." + c.Role,
				Severity: validation.SeverityError,
				Message:  fmt.Sprintf("configuration (%s) and stored assignment (%s) conflict for role %s", c.Declared, c.Stored, c.Role),
				Hint:     "resolve the conflict by aligning the configuration and stored assignment, or unassigning the stored role",
			})
		}
		result = result.Merge(validation.Result{
			Findings: conflictFindings,
			Layers:   []validation.Layer{validation.LayerStatic},
		})
	}

	// Fold in the subsystems that validate themselves elsewhere.
	//
	// DHCP, DNS, the firewall policy and netconfig each own their rules and
	// each is reached by its own command. Before this, `thn validate`
	// reported "no findings" and exited 0 for a document whose pool ran off
	// the end of the LAN, whose ruleset could not be reached, or whose NAT
	// rule named an interface that does not exist. The gate had never asked
	// the components that know.
	//
	// Every one of these calls the subsystem's own Validate on the policy
	// that subsystem's own command builds from the same document, so the two
	// cannot drift. Copying the checks in instead would create a second
	// implementation, which is the duplication these packages exist to
	// prevent.
	//
	// QoS is absent deliberately: qos.Validate needs a host Availability, and
	// inventing one here would turn every enabled shaping config into an
	// error. See `thn qos validate`.
	for _, sub := range subsystemValidations(cfg) {
		result = result.Merge(sub)
	}

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config":   path,
			"live":     *live,
			"valid":    result.Valid,
			"layers":   result.Layers,
			"findings": result.Findings,
		}); err != nil {
			env.errorf("thn validate: %v\n", err)
			return ExitProblems
		}
	} else {
		printValidation(env, path, result)
	}

	if result.Valid {
		return ExitOK
	}
	return ExitProblems
}

// subsystemValidations runs each foldable subsystem's own validator over one
// configuration document.
//
// Each entry derives its policy with the same translator its own command uses
// and calls the same Validate function, so `thn validate` and
// `thn dhcp validate` cannot reach different conclusions about the same file.
//
// A policy the CLI cannot derive becomes a finding rather than an early
// return: `thn validate` must report everything wrong with a document in one
// pass, and stopping at the first unparseable address would hide the four that
// follow it.
func subsystemValidations(cfg config.Config) []validation.Result {
	var out []validation.Result

	// DHCP.
	if policy, err := dhcpPolicyFromConfig(cfg); err != nil {
		out = append(out, unparseableSubsystem("dhcp.ranges", err,
			"write each pool bound as an address, for example 10.77.0.100"))
	} else {
		out = append(out, validation.FromDHCP(dhcp.Validate(policy)))
	}

	// DNS.
	if policy, err := dnsPolicyFromConfig(cfg); err != nil {
		out = append(out, unparseableSubsystem("dns", err,
			"check the upstream resolvers and local records are addresses"))
	} else {
		out = append(out, validation.FromDNS(dns.Validate(policy)))
	}

	// Firewall policy. The translator cannot fail: it substitutes defaults.
	out = append(out, validation.FromFirewallPolicy(fwpolicy.Validate(policyFromConfig(cfg))))

	// Netconfig, including cross-subsystem coherence between routing, NAT and
	// forwarding. The translator cannot fail.
	netResult, issues := netconfig.Validate(netPolicyFromConfig(cfg))
	out = append(out, validation.FromNetconfig(netResult, issues))

	return out
}

// unparseableSubsystem reports a policy that could not be derived at all.
func unparseableSubsystem(field string, err error, hint string) validation.Result {
	return validation.Result{
		Findings: []validation.Finding{{
			Layer:    validation.LayerStatic,
			Field:    field,
			Severity: validation.SeverityError,
			Message:  err.Error(),
			Hint:     hint,
		}},
		Layers: []validation.Layer{validation.LayerStatic},
	}
}

// printValidation renders a validation result for a human.
func printValidation(env *Env, path string, r validation.Result) {
	env.printf("Configuration: %s\n", path)
	env.printf("Layers:         %s\n", strings.Join(layerNames(r.Layers), ", "))
	env.printf("Result:         %s (%d error, %d warning, %d info)\n",
		passFail(r.Valid), r.ErrorCount, r.WarningCount, r.InfoCount)

	if len(r.Findings) == 0 {
		env.printf("\nNo findings.\n")
		return
	}

	env.printf("\n")
	for _, f := range r.Findings {
		env.printf("  %-8s %-22s %s\n", f.Severity, f.Field, f.Message)
		if f.Hint != "" {
			env.printf("  %-8s %-22s hint: %s\n", "", "", f.Hint)
		}
	}
}

// runPlan implements `thn plan`.
func runPlan(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	live := fs.Bool("live", false)
	explain := fs.Bool("explain", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn plan: %v\n", err)
	}

	path := env.resolveConfigPath(*configPath)
	if len(rest) > 0 {
		path = rest[0]
	}
	if len(rest) > 1 {
		return env.fatalf("thn plan: expected at most one configuration path, got %d\n", len(rest))
	}

	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn plan: %v\n", err)
		return ExitProblems
	}

	// Planning is always computed against this host, because a plan that is
	// not grounded in what the machine actually has is not useful. The
	// --live flag only controls whether the observation is considered
	// authoritative enough to report against.
	obs, _, _, device := observeHost(cfg)
	assignments := roleAssignments(cfg)
	res := host.Resolve(device, assignments)
	des := desired.FromConfigWithResolution(cfg, res)
	d := diff.Compare(obs, desiredFor(des))

	p := planner.Build(d, planner.Options{
		Generation:  cfg.Gateway.Generation,
		Source:      path,
		Live:        *live || obs.Supported,
		Now:         time.Now(),
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Device:      device,
	})

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config":     path,
			"plan":       p,
			"validation": validation.Combined(cfg, &obs, d),
		}); err != nil {
			env.errorf("thn plan: %v\n", err)
			return ExitProblems
		}
	} else {
		printPlan(env, cfg, p, d, obs, *explain)
	}

	if len(p.Blocked) > 0 {
		return ExitProblems
	}
	return ExitOK
}

// printPlan renders a plan for a human.
func printPlan(env *Env, cfg config.Config, p *planner.Plan, d diff.Result, obs diff.Observed, explain bool) {
	env.printf("%s\n", p.Summary)
	env.printf("Source:     %s (generation %d)\n", p.Source, p.Generation)
	env.printf("Host:       %s\n", hostLabel(obs))
	env.printf("Grounding:  %s\n", groundingLabel(obs))
	env.printf("Activation: %s\n", activationLabel(p))

	env.printf("\nDiff\n")
	env.printf("  %s\n\n", d.Summary())
	printChangeTable(env, d)

	if len(p.Steps) == 0 {
		env.printf("Plan\n")
		env.printf("  No actionable steps.\n")
	} else {
		env.printf("Plan\n")
		for _, ph := range phaseTable() {
			steps := p.StepsByPhase(ph.Number)
			if len(steps) == 0 {
				continue
			}
			env.printf("  %d. %s — %s\n", ph.Number, ph.Name, ph.Purpose)
			for _, s := range steps {
				marker := " "
				if s.Disruptive {
					marker = "!"
				}
				env.printf("     %s [%-8s] %s\n", marker, s.Risk, s.Summary)
				if explain {
					env.printf("         action:  %s\n", s.Action)
					env.printf("         current: %s\n", orNone(s.Current))
					env.printf("         desired: %s\n", orNone(s.Desired))
					env.printf("         why:     %s\n", s.Reason)
					for _, c := range s.Commands {
						env.printf("         $ %s\n", c)
					}
					if s.Rollback != nil && len(s.Rollback.RestoreCommands) > 0 {
						for _, rc := range s.Rollback.RestoreCommands {
							env.printf("         rollback: $ %s\n", rc)
						}
					}
				}
			}
		}
	}

	sim := p.Simulation
	env.printf("\nSimulation (nothing has been changed)\n")
	env.printf("  %s\n", sim.Headline)
	printList(env, "Would apply", sim.WouldApply)
	printList(env, "Pending", sim.Pending)
	printList(env, "Blocked", sim.Blocked)
	printList(env, "Consequences", sim.Consequences)
	printList(env, "Disruptions", sim.Disruptions)
	printList(env, "Out of order", sim.OutOfOrder)
}

// printChangeTable renders the diff as an aligned table.
func printChangeTable(env *Env, d diff.Result) {
	if len(d.Changes) == 0 {
		return
	}
	env.printf("  %-9s %-9s %-28s %s\n", "KIND", "RISK", "FIELD", "REASON")
	for _, c := range d.Changes {
		env.printf("  %-9s %-9s %-28s %s\n", c.Kind, c.Risk, c.Field, c.Reason)
	}
}

// runConfig implements the `thn config` group.
func runConfig(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn config: expected a subcommand (show, validate, plan)\n")
	}

	switch args[0] {
	case "show":
		return runConfigShow(env, args[1:])
	case "validate":
		return runValidate(env, args[1:])
	case "plan":
		return runPlan(env, args[1:])
	default:
		return env.fatalf("thn config: unknown subcommand %q; expected show, validate or plan\n", args[0])
	}
}

// runConfigShow implements `thn config show`.
func runConfigShow(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	desiredOnly := fs.Bool("desired", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn config show: %v\n", err)
	}

	path := env.resolveConfigPath(*configPath)
	if len(rest) > 0 {
		path = rest[0]
	}

	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn config show: %v\n", err)
		return ExitProblems
	}

	if *desiredOnly {
		d := desired.FromConfig(cfg)
		if env.IsJSON {
			if err := env.printJSON(d); err != nil {
				env.errorf("thn config show: %v\n", err)
				return ExitProblems
			}
		} else {
			env.printf("%s", d.Summary())
		}
		return ExitOK
	}

	if env.IsJSON {
		if err := env.printJSON(cfg); err != nil {
			env.errorf("thn config show: %v\n", err)
			return ExitProblems
		}
	} else {
		raw, err := cfg.Marshal()
		if err != nil {
			env.errorf("thn config show: %v\n", err)
			return ExitProblems
		}
		env.printf("%s", raw)
	}
	return ExitOK
}

// runSchema implements `thn schema`.
func runSchema(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("mutating", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn schema: %v\n", err)
	}

	keys := schema.Keys()
	if fs.Seen("mutating") || *fs.bools["mutating"] {
		keys = schema.MutatingKeys()
	}

	if env.IsJSON {
		if err := env.printJSON(schema.Catalogue()); err != nil {
			env.errorf("thn schema: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Schema version %d (supported: %d-%d)\n\n", schema.Version, schema.MinimumVersion, schema.Version)
	env.printf("%-42s %-10s %-8s %s\n", "KEY", "TYPE", "MUTATES", "DESCRIPTION")
	for _, k := range keys {
		f, _ := schema.Lookup(k)
		mutates := ""
		if f.Mutating {
			mutates = "yes"
		}
		env.printf("%-42s %-10s %-8s %s\n", f.Key, f.Type, mutates, f.Description)
	}
	return ExitOK
}

// runStatus implements `thn status`, which requires the daemon.
func runStatus(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("local", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn status: %v\n", err)
	}

	// --local exists so the command is usable before thnd is running. It
	// reports only what can be determined from the configuration and a
	// read-only observation, and says plainly that it is not talking to the
	// daemon.
	if *fs.bools["local"] {
		return runStatusLocal(env)
	}

	// Ask the daemon first. It is the only thing that can say what the gateway
	// is actually doing, and it holds the state database this command would
	// otherwise have to guess about.
	client := newDaemonClient(env)

	st, err := client.statusFrom()
	if err == nil {
		if env.IsJSON {
			if err := env.printJSON(st); err != nil {
				return env.fatalf("thn status: %v\n", err)
			}
			return ExitOK
		}
		renderDaemonStatus(env, st)
		return ExitOK
	}

	// The daemon did not answer. Report why in the daemon's terms before the
	// CLI's, because "permission denied" and "no such file" need different
	// things done about them, and flattening both into "not running" is what
	// sends somebody to restart a healthy daemon.
	env.errorf("thn status: %v\n", err)
	env.errorf("\n")
	env.errorf("thnd is not running, or its socket is not readable by this user.\n")
	env.errorf("Expected socket: %s\n", client.path)
	env.errorf("\n")
	env.errorf("Use `thn status --local` for configuration-derived status without the daemon.\n")
	return ExitUnavailable
}

// runStatusLocal renders status from configuration and observation only.
func runStatusLocal(env *Env) ExitCode {
	path := env.resolveConfigPath("")
	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn status: %v\n", err)
		return ExitProblems
	}

	obs, _, fw, _ := observeHost(cfg)
	d := desired.FromConfig(cfg)
	pending := d.Pending()

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"source":   "local",
			"gateway":  cfg.Gateway.Name,
			"state":    activation.StateDevelopment.String(),
			"canApply": activation.CanApply(),
			"wan":      ifaceStatus(cfg.Network.WAN, obs.WANPresent, obs.WANName, obs.WANUp),
			"lan":      ifaceStatus(cfg.Network.LAN, obs.LANPresent, obs.LANName, obs.LANUp),
			"firewall": string(fw.Status),
			"pending":  pending,
		}); err != nil {
			env.errorf("thn status: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("THN Gateway\n")
	env.printf("────────────\n")
	env.printf("Mode:          %s\n", activation.StateDevelopment.String())
	env.printf("State:         %s\n", activation.StateDevelopment.String())
	env.printf("Generation:    %d\n", cfg.Gateway.Generation)
	env.printf("Config:        %s\n", path)
	env.printf("Daemon:        not consulted (--local)\n")
	env.printf("\n")
	env.printf("WAN:           %s\n", ifaceStatus(cfg.Network.WAN, obs.WANPresent, obs.WANName, obs.WANUp))
	env.printf("LAN:           %s\n", ifaceStatus(cfg.Network.LAN, obs.LANPresent, obs.LANName, obs.LANUp))
	env.printf("Firewall:      %s\n", strings.ToLower(string(fw.Status)))
	env.printf("NAT:           %s\n", enabledLabel(cfg.NAT.Enabled, d.NAT.Resolved))
	env.printf("QoS:           %s\n", enabledLabel(cfg.QoS.Enabled, d.QoS.Resolved))
	env.printf("\n")
	env.printf("Network apply: DISABLED (no apply path in this build)\n")

	if len(pending) > 0 {
		env.printf("\nPending\n")
		for _, k := range sortedKeys(pending) {
			env.printf("  %-8s %s\n", k, pending[k])
		}
	}
	return ExitOK
}

// runDiagnostics implements `thn diagnostics`, which requires the daemon.
func runDiagnostics(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("local", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn diagnostics: %v\n", err)
	}

	if *fs.bools["local"] {
		return runDiagnosticsLocal(env)
	}

	// The daemon owns the state database, so it is the only thing that can
	// report whether it is readable. As with `status`, the daemon is asked
	// before anything is concluded about it.
	client := newDaemonClient(env)

	if err := client.reachable(); err != nil {
		env.errorf("thn diagnostics: %v\n", err)
		env.errorf("\n")
		env.errorf("Live diagnostics are reported by the daemon, which owns the state\n")
		env.errorf("database and the gateway's own view of itself.\n")
		env.errorf("Expected socket: %s\n", client.path)
		env.errorf("\n")
		env.errorf("Use `thn diagnostics --local` for host-level checks without the daemon.\n")
		return ExitUnavailable
	}

	st, err := client.statusFrom()
	if err != nil {
		// It answered ping but not status, so it is running and unhappy. That
		// is a different situation from unreachable and deserves its own text.
		env.errorf("thn diagnostics: thnd answered but did not report its status: %v\n", err)
		return ExitProblems
	}

	if env.IsJSON {
		if err := env.printJSON(st); err != nil {
			return env.fatalf("thn diagnostics: %v\n", err)
		}
		return ExitOK
	}

	env.printf("thnd: reachable\n")
	renderDaemonStatus(env, st)

	// The most recent observation is a best-effort extra. A daemon that has
	// just started has not taken one yet, and that is normal rather than a
	// fault, so it is reported as absent instead of failing the command.
	env.printf("\n")
	if raw, lerr := client.call("last"); lerr != nil {
		env.printf("Last observation: none yet (%v)\n", lerr)
	} else {
		env.printf("Last observation:\n%s\n", prettyJSON(raw))
	}

	return ExitOK
}

// prettyJSON re-indents a raw JSON value for display under a heading.
func prettyJSON(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "  ", "  "); err != nil {
		// The daemon always marshals its own results, so this cannot normally
		// happen. Printing the bytes as they came is better than losing them.
		return string(raw)
	}
	return buf.String()
}

// runDiagnosticsLocal renders host-level diagnostics.
func runDiagnosticsLocal(env *Env) ExitCode {
	path := env.resolveConfigPath("")
	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn diagnostics: %v\n", err)
		return ExitProblems
	}

	obs, snap, fw, _ := observeHost(cfg)
	stat := validation.Static(cfg)

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"source":     "local",
			"host":       obs.HostName,
			"supported":  obs.Supported,
			"interfaces": len(snap.Interfaces),
			"addresses":  len(snap.Addresses),
			"routes":     len(snap.Routes),
			"firewall":   string(fw.Status),
			"valid":      stat.Valid,
			"canApply":   activation.CanApply(),
		}); err != nil {
			env.errorf("thn diagnostics: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("THN Diagnostics (local, read-only)\n")
	env.printf("────────────\n\n")
	env.printf("Host\n")
	env.printf("  Host:              %s\n", obs.HostName)
	env.printf("  Inspection:        %s\n", supportedLabel(obs.Supported))
	env.printf("  Interfaces:        %d\n", len(snap.Interfaces))
	env.printf("  Addresses:         %d\n", len(snap.Addresses))
	env.printf("  Routes:            %d\n", len(snap.Routes))
	env.printf("  IPv4 forwarding:   %s\n", forwardingLabel(obs))
	env.printf("\n")
	env.printf("Services\n")
	env.printf("  Firewall:          %s\n", strings.ToLower(string(fw.Status)))
	env.printf("  NAT:               %s\n", enabledLabel(cfg.NAT.Enabled, desired.FromConfig(cfg).NAT.Resolved))
	env.printf("\n")
	env.printf("Configuration\n")
	env.printf("  Path:              %s\n", path)
	env.printf("  Generation:        %d\n", cfg.Gateway.Generation)
	env.printf("  Validation:        %s\n", passFail(stat.Valid))
	env.printf("  Findings:          %d error, %d warning\n", stat.ErrorCount, stat.WarningCount)
	env.printf("\n")
	env.printf("Safety\n")
	env.printf("  Network apply:     DISABLED\n")
	env.printf("  Implementable:     %v\n", activation.ImplementedStages())
	env.printf("  Not implementable: %v\n", activation.UnsupportedStages())

	if !stat.Valid {
		env.printf("\nConfiguration findings\n")
		for _, f := range stat.Errors() {
			env.printf("  %s %s\n", f.Field, f.Message)
		}
	}

	return ExitOK
}

// phaseTable returns the planner's phase table for rendering.
func phaseTable() []planner.Phase {
	return planner.Phases()
}

// layerNames renders validation layer names.
func layerNames(layers []validation.Layer) []string {
	out := make([]string, len(layers))
	for i, l := range layers {
		out[i] = string(l)
	}
	return out
}

// printList renders a labelled list, or nothing when empty.
func printList(env *Env, label string, items []string) {
	if len(items) == 0 {
		return
	}
	env.printf("  %s:\n", label)
	for _, i := range items {
		env.printf("    - %s\n", i)
	}
}

// passFail renders a boolean as PASS or FAIL.
func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// orNone renders an empty value as a placeholder.
func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// hostLabel renders the observed host name.
func hostLabel(obs diff.Observed) string {
	if obs.HostName == "" {
		return "(unknown)"
	}
	return obs.HostName
}

// groundingLabel explains whether the plan is grounded in a real observation.
func groundingLabel(obs diff.Observed) string {
	if obs.Supported {
		return "observed from this host"
	}
	return "configuration only — host inspection is unavailable on this platform"
}

// supportedLabel renders inspection availability.
func supportedLabel(supported bool) string {
	if supported {
		return "available"
	}
	return "not available on this platform"
}

// forwardingLabel renders the forwarding state.
func forwardingLabel(obs diff.Observed) string {
	switch {
	case !obs.IPv4ForwardingKnown:
		return "unknown (could not be read)"
	case obs.IPv4Forwarding:
		return "enabled"
	default:
		return "disabled"
	}
}

// enabledLabel renders an enabled/pending pair.
func enabledLabel(enabled, resolved bool) string {
	switch {
	case !enabled:
		return "not configured"
	case resolved:
		return "configured"
	default:
		return "configured (pending: incomplete)"
	}
}

// ifaceStatus renders an interface's status line.
func ifaceStatus(configured string, present bool, name string, up bool) string {
	switch {
	case configured == "":
		return "not configured"
	case !present:
		return fmt.Sprintf("%s (not attached)", configured)
	case name != configured:
		return fmt.Sprintf("%s (host has %s)", configured, name)
	case !up:
		return fmt.Sprintf("%s (down)", configured)
	default:
		return fmt.Sprintf("%s (up)", configured)
	}
}

// activationLabel explains whether the plan could be acted on.
func activationLabel(p *planner.Plan) string {
	switch {
	case !activation.CanApply():
		return "BLOCKED (no apply path in this build)"
	case p.Ready:
		return "available"
	default:
		return "BLOCKED (plan is not ready)"
	}
}

// socketPath reports where thnd is expected to be listening.
//
// Resolved the same way every other path is — an explicit flag, then
// THN_CONFIG, then the default. This used to load a hardcoded
// /etc/thn/config.yaml directly, so a run against any other configuration
// printed an "expected socket" that was simply wrong, which is the least
// useful thing an error message can do.
func socketPath(env *Env) string {
	if v := env.Getenv("THN_SOCKET"); v != "" {
		return v
	}
	cfg, err := loadConfig(env, env.resolveConfigPath(""))
	if err != nil || cfg.Paths.Socket == "" {
		return "/run/thn/thnd.sock"
	}
	return cfg.Paths.Socket
}

// sortedKeys returns a map's keys in sorted order.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
