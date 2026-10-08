package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/firewall/nft"
	fwpolicy "github.com/VengeTH/THN-Gateway/internal/firewall/policy"
	"github.com/VengeTH/THN-Gateway/internal/host"
)

// policyFromConfig derives a firewall policy from a configuration document.
//
// The derivation lives here rather than in the policy package because the
// mapping is a policy decision about how THN's configuration surfaces, not a
// property of the policy model. The policy package stays free of the
// configuration document so it can be used with a hand-written policy.
//
// The result is a *starting point*: validation may reject it, and the operator
// may want services that configuration has no field for yet.
func policyFromConfig(cfg config.Config) fwpolicy.Policy {
	p := fwpolicy.Default()

	storePath := resolveStorePath(cfg, "")
	stored := loadBindings(storePath)
	wanSel := bindingSelector(cfg, stored, host.RoleWAN)
	lanSel := bindingSelector(cfg, stored, host.RoleLAN)

	p.Interfaces.WAN = wanSel
	p.Interfaces.LAN = lanSel
	p.AntiSpoofing.LANPrefix = cfg.Network.LANPrefix

	// The configuration's inbound policy maps onto the admin source
	// restriction: a drop policy still needs a reachable admin path, and
	// THN always emits one. The policy's own validation is what decides
	// whether that path is adequate.
	p.Admin.Enabled = true
	p.Admin.Service = fwpolicy.SSH

	// The administrative source restriction. This is the only place it can
	// come from: the policy models, validates and renders it, but until this
	// existed no configuration document could carry it, so the rendered admin
	// rule was always the open one and policy validation warned about it on
	// every single run.
	//
	// A nil slice and an empty slice are equivalent here. The distinction
	// that matters is whether an operator narrowed it, and empty means they
	// have not — which is a warning, not an error.
	p.Admin.Source = cfg.Firewall.AdminSources

	if !cfg.Firewall.Enabled {
		// Disabled means disabled: no masquerade and no forwarding, which
		// validation will report as an error because a gateway that forwards
		// nothing is not a gateway. Reporting it is more useful than quietly
		// rendering an inert ruleset.
		p.Forward.LANToWAN = false
		p.Masquerade.Enabled = false
	}

	// NAT is a separate switch from the firewall, and the two are configured
	// separately. Honouring it here matters because the masquerade rule is
	// what makes the LAN reachable from the internet: leaving it in place
	// after NAT was turned off would keep rewriting source addresses for a
	// configuration that asked not to be rewritten.
	//
	// The data plane is told the same thing in netPolicyFromConfig, so the
	// two models cannot drift apart on this.
	if !cfg.NAT.Enabled {
		p.Masquerade.Enabled = false
	}

	// The masquerade rule's outbound interface.
	//
	// This was previously never set, which meant the rendered masquerade
	// rule applied to EVERY interface — including the LAN. That rewrites
	// LAN-to-LAN source addresses and presents as intermittent hardware
	// failure rather than as the misconfiguration it is.
	//
	// The value may name a logical role or an interface. A role is the
	// operator-friendly form and is resolved here against the interfaces the
	// configuration has bound; a name is taken literally, which is what an
	// advanced operator writing a specific interface expects.
	if cfg.NAT.Masquerade.Enabled {
		p.Masquerade.OutInterface = resolveOutbound(cfg)
	}

	// A drop-by-default inbound policy is what THN emits. An accept policy is
	// a genuine operator choice, and it is recorded as a warning by policy
	// validation rather than silently ignored here.
	if cfg.Firewall.DefaultInboundPolicy == "accept" {
		p.Forward.WANToLAN = true
	}

	if cfg.QoS.Enabled && cfg.QoS.Interface != "" {
		p.Logging.Enabled = false // shaping and logging are independent
	}

	if cfg.Activation.RequirePhysicalPresence {
		p.Comments = append(p.Comments,
			"Administrative access is required by the configuration's physical-presence gate:",
			"rendering this ruleset does not activate it.",
			fmt.Sprintf("Policy derived from configuration generation %d.", cfg.Gateway.Generation))
	}

	return p
}

// runFirewall implements the `thn firewall` group.
func runFirewall(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn firewall: expected a subcommand (render, validate, show)\n")
	}

	switch args[0] {
	case "render":
		return runFirewallRender(env, args[1:])
	case "validate":
		return runFirewallValidate(env, args[1:])
	case "show":
		return runFirewallShow(env, args[1:])
	default:
		return env.fatalf("thn firewall: unknown subcommand %q; expected render, validate or show\n", args[0])
	}
}

// resolvePolicy loads the configuration and derives the policy.
func resolvePolicy(env *Env, configPath string) (fwpolicy.Policy, string, ExitCode) {
	path := env.resolveConfigPath(configPath)

	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn firewall: %v\n", err)
		return fwpolicy.Policy{}, path, ExitProblems
	}

	return policyFromConfig(cfg), path, ExitOK
}

// runFirewallValidate implements `thn firewall validate`.
func runFirewallValidate(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn firewall validate: %v\n", err)
	}
	if len(rest) > 0 {
		positional := rest[0]
		*configPath = positional
	}

	p, path, code := resolvePolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	result := fwpolicy.Validate(p)

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config":          path,
			"policy":          p,
			"valid":           result.Valid,
			"admin_reachable": result.Reachable,
			"findings":        result.Findings,
			"admin_trace":     result.Trace,
		}); err != nil {
			env.errorf("thn firewall validate: %v\n", err)
			return ExitProblems
		}
	} else {
		printFirewallValidation(env, path, p, result)
	}

	if !result.Valid {
		return ExitProblems
	}
	return ExitOK
}

// printFirewallValidation renders a validation result.
func printFirewallValidation(env *Env, path string, p fwpolicy.Policy, r fwpolicy.Result) {
	env.printf("Firewall policy (from %s)\n", path)
	env.printf("────────────\n")
	env.printf("%s\n", p)
	env.printf("\n")
	env.printf("Result:    %s (%d error, %d warning, %d info)\n",
		passFail(r.Valid), r.ErrorCount, r.WarningCount, r.InfoCount)
	env.printf("Admin:     %s\n", reachableLabel(r.Reachable))

	if len(r.Trace) > 0 {
		env.printf("\nReachability trace\n")
		for _, line := range r.Trace {
			env.printf("  %s\n", line)
		}
	}

	if len(r.Findings) == 0 {
		env.printf("\nNo findings.\n")
		return
	}

	env.printf("\nFindings\n")
	for _, f := range r.Findings {
		env.printf("  %-8s %-28s %s\n", f.Severity, f.Field, f.Message)
		if f.Hint != "" {
			env.printf("  %-8s %-28s hint: %s\n", "", "", f.Hint)
		}
	}
}

// runFirewallRender implements `thn firewall render`.
func runFirewallRender(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	out := fs.String("out", "")
	force := fs.Bool("force", false)
	skipValidate := fs.Bool("no-validate", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn firewall render: %v\n", err)
	}
	if len(rest) > 0 {
		positional := rest[0]
		*configPath = positional
	}

	p, path, code := resolvePolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	// Validation gates rendering by default. Rendering a ruleset that would
	// lock the operator out, and then printing it for them to install, would
	// be a poor way to deliver bad news.
	if !*skipValidate {
		result := fwpolicy.Validate(p)
		if !result.Valid {
			env.errorf("thn firewall render: the policy is not valid; not rendering.\n\n")
			printFirewallValidation(env, path, p, result)
			env.errorf("\nFix the findings above, or pass --no-validate to render anyway.\n")
			return ExitProblems
		}
	}

	ruleset := nft.Render(p)

	// Writing to a file is opt-in. The default is stdout so that the common
	// case — reviewing a ruleset — cannot accidentally modify anything.
	if *out == "" {
		if env.IsJSON {
			if err := env.printJSON(map[string]any{
				"config":  path,
				"policy":  p,
				"ruleset": ruleset,
				"written": false,
				"note":    "ruleset was printed, not written; pass --out to write a file",
			}); err != nil {
				env.errorf("thn firewall render: %v\n", err)
				return ExitProblems
			}
			return ExitOK
		}
		env.printf("%s", ruleset)
		return ExitOK
	}

	if err := writeRuleset(*out, ruleset, *force); err != nil {
		env.errorf("thn firewall render: %v\n", err)
		return ExitProblems
	}

	if !env.IsJSON {
		env.errorf("Wrote %d bytes to %s\n", len(ruleset), *out)
		env.errorf("Nothing has been applied. Review the file, then load it with:\n")
		env.errorf("  nft -c -f %s    # check\n", *out)
		env.errorf("  nft -f %s        # load\n", *out)
	}
	return ExitOK
}

// writeRuleset writes a rendered ruleset to disk.
//
// An existing file is never overwritten without --force, because the rendered
// file is usually hand-corrected and silently replacing it loses work that no
// amount of regeneration can recover.
func writeRuleset(path, content string, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists; pass --force to overwrite it", path)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}

	// 0644: the ruleset contains no secrets and must be readable by root and
	// by anyone auditing it. It does describe the firewall's exposure, so it
	// is not world-writable.
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// runFirewallShow implements `thn firewall show`, printing the policy without
// rendering it.
func runFirewallShow(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn firewall show: %v\n", err)
	}
	if len(rest) > 0 {
		positional := rest[0]
		*configPath = positional
	}

	p, path, code := resolvePolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	if env.IsJSON {
		if err := env.printJSON(map[string]any{"config": path, "policy": p}); err != nil {
			env.errorf("thn firewall show: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Firewall policy (from %s)\n", path)
	env.printf("────────────\n")
	env.printf("%s\n\n", p)
	env.printf("Interfaces\n")
	env.printf("  WAN:        %s\n", orNone(p.Interfaces.WAN))
	env.printf("  LAN:        %s\n", orNone(p.Interfaces.LAN))
	env.printf("  Loopback:   %s\n", orNone(p.Interfaces.Loopback))
	env.printf("\nAdministration\n")
	env.printf("  Enabled:    %t\n", p.Admin.Enabled)
	env.printf("  Service:    %s\n", adminServiceLabel(p))
	env.printf("  Sources:    %s\n", sourceLabel(p.Admin.Source))
	env.printf("\nTraffic\n")
	env.printf("  ICMP:       wan=%t lan=%t forward=%t echo-limit=%d/s\n",
		p.ICMP.AllowWAN, p.ICMP.AllowLAN, p.ICMP.AllowForward, p.ICMP.RateLimitEcho)
	env.printf("  Forward:    lan->wan=%t wan->lan=%t lan->lan=%t\n",
		p.Forward.LANToWAN, p.Forward.WANToLAN, p.Forward.LANToLAN)
	env.printf("  Masquerade: %t%s\n", p.Masquerade.Enabled, outIfaceLabel(p.Masquerade.OutInterface))
	env.printf("  Spoofing:   %t\n", p.AntiSpoofing.Enabled)
	env.printf("\nServices exposed to the WAN\n")
	if len(p.Services) == 0 {
		env.printf("  (none beyond administration)\n")
	}
	for _, s := range p.Services {
		env.printf("  %-16s %s/%s\n", s.Name, s.Protocol, portsLabel(s.Ports))
	}
	env.printf("\nLogging:       %t\n", p.Logging.Enabled)
	return ExitOK
}

// adminServiceLabel renders the admin service for display.
func adminServiceLabel(p fwpolicy.Policy) string {
	if !p.Admin.Enabled {
		return "disabled"
	}
	s := p.Admin.Service
	if s.Name == "" {
		return "(unset)"
	}
	return fmt.Sprintf("%s/%s", s.Name, portsLabel(s.Ports))
}

// sourceLabel renders a source list.
func sourceLabel(src []string) string {
	if len(src) == 0 {
		return "any"
	}
	return strings.Join(src, ", ")
}

// portsLabel renders a port list.
func portsLabel(ports []fwpolicy.PortRange) string {
	if len(ports) == 0 {
		return "(none)"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

// resolveOutbound turns nat.masquerade.outbound into an interface name.
//
// An empty result means "unset", and policy validation reports it. A role that
// cannot be resolved also yields empty rather than a guess: substituting the
// wrong interface here would masquerade traffic onto the LAN.
func resolveOutbound(cfg config.Config) string {
	raw := strings.TrimSpace(cfg.NAT.Masquerade.Outbound)
	if raw == "" {
		return ""
	}

	storePath := resolveStorePath(cfg, "")
	stored := loadBindings(storePath)

	switch strings.ToLower(raw) {
	case string(host.RoleWAN):
		return bindingSelector(cfg, stored, host.RoleWAN)
	case string(host.RoleLAN):
		return bindingSelector(cfg, stored, host.RoleLAN)
	case string(host.RoleMGMT), string(host.RoleGuest), string(host.RoleDMZ):
		return bindingSelector(cfg, stored, host.Role(strings.ToLower(raw)))
	default:
		return raw
	}
}

func outIfaceLabel(iface string) string {
	if iface == "" {
		return " (unscoped)"
	}
	return " via " + iface
}

// reachableLabel renders the admin reachability verdict.
func reachableLabel(ok bool) string {
	if ok {
		return "REACHABLE"
	}
	return "UNREACHABLE — do not install this ruleset on an unattended device"
}
