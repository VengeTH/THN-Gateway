package cli

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/netconfig"
	netnft "github.com/venth/thn-gateway/internal/netconfig/nft"
)

// policyFromConfig derives a data-plane policy from configuration.
//
// The mapping lives here rather than in the policy package so that
// internal/netconfig stays independent of the configuration document and can
// be driven from a hand-written policy in tests.
func netPolicyFromConfig(cfg config.Config) netconfig.Policy {
	p := netconfig.Default()

	p.Interfaces.WAN = cfg.Network.WAN
	p.Interfaces.LAN = cfg.Network.LAN
	p.Interfaces.Loopback = "lo"

	p.Forwarding.IPv4Enabled = true
	p.Forwarding.IPv6Enabled = false
	p.Forwarding.DropInvalid = true
	p.Forwarding.AntiSpoofing = cfg.Network.LANPrefix != ""

	// A drop-by-default inbound policy does not imply the WAN may reach the
	// LAN; that is a separate decision the firewall renderer owns.
	p.Forwarding.Rules = []netconfig.ForwardRule{
		{
			Direction: netconfig.LANToWAN,
			Action:    "accept",
			Comment:   "the purpose of a gateway: LAN clients reaching the internet",
		},
		{
			Direction: netconfig.WANToLAN,
			Action:    "drop",
			Comment:   "unsolicited inbound traffic is not permitted",
		},
	}

	// A disabled firewall means no forwarding at all, and the data plane has
	// to say so.
	//
	// Without this the two models disagree in the worst possible direction:
	// policyFromConfig drops lan-to-wan when the firewall is off, so the
	// rendered ruleset black-holes the LAN, while this policy keeps reporting
	// that traffic forwards. Every simulation would then describe a gateway
	// that does not work. The intent is documented in policyFromConfig; this
	// is the other half of it.
	if !cfg.Firewall.Enabled {
		p.Forwarding.Rules = []netconfig.ForwardRule{
			{
				Direction: netconfig.LANToWAN,
				Action:    "drop",
				Comment:   "the firewall is disabled, so no direction is forwarded",
			},
			{
				Direction: netconfig.WANToLAN,
				Action:    "drop",
				Comment:   "the firewall is disabled, so no direction is forwarded",
			},
		}
	}

	if cfg.Network.LANPrefix != "" {
		if prefix, err := netip.ParsePrefix(cfg.Network.LANPrefix); err == nil {
			// A route needs an interface to leave through, so the directly
			// connected LAN network is only a route once the LAN interface is
			// known.
			//
			// It used to be added regardless, carrying an empty interface, and
			// validation then reported that as an error — which turned "the LAN
			// NIC has not been identified yet" into a blocking failure. That is
			// backwards, and it contradicts what the configuration comments
			// promise: absent hardware is pending, not broken. It also made
			// `thn net render` refuse outright on the shipped example, which
			// sets `lan: ""` on purpose.
			//
			// Omitting it is not silence. The coherence check already reports a
			// configured forwarding rule with no LAN interface, `thn plan`
			// reports the LAN as pending, and `p.Interfaces.LAN` stays empty —
			// so the gap is reported in the three places that report gaps, and
			// not by emitting a route that cannot be installed.
			if cfg.Network.LAN != "" {
				// The LAN network is directly connected, so it is a route with
				// no next hop. Without it, traffic from the LAN has nowhere to
				// go.
				p.Routing.Routes = append(p.Routing.Routes, netconfig.Route{
					Destination: prefix.Masked(),
					Interface:   cfg.Network.LAN,
					Scope:       "link",
					Protocol:    "thn",
					Comment:     "the directly connected LAN network",
				})
			}

			// Restrict the NAT ingress to the LAN rather than any interface.
			p.NAT.InInterface = cfg.Network.LAN

			// The gateway's own LAN address. Traffic addressed to it is
			// delivered locally and must not be run through the forward
			// chain's rules, which would report a client reaching the
			// gateway as dropped.
			p.LocalAddresses = append(p.LocalAddresses, prefix.Addr())
		}
	}

	p.NAT.Enabled = cfg.NAT.Enabled
	p.NAT.OutInterface = cfg.Network.WAN

	if !cfg.NAT.Enabled {
		p.NAT.Mode = netconfig.NATNone
	}

	if cfg.Network.UpstreamGateway != "" {
		if gw, err := netip.ParseAddr(cfg.Network.UpstreamGateway); err == nil {
			p.Routing.DefaultGateway = gw
			p.Routing.DefaultGatewayInterface = cfg.Network.WAN
		}
	}

	p.Routing.Comments = append(p.Routing.Comments,
		fmt.Sprintf("Derived from configuration generation %d.", cfg.Gateway.Generation),
		"Rendering this does not change host networking.",
	)

	return p
}

// runNet implements the `thn net` group.
func runNet(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn net: expected a subcommand (render, validate, simulate)\n")
	}

	switch args[0] {
	case "render":
		return runNetRender(env, args[1:])
	case "validate":
		return runNetValidate(env, args[1:])
	case "simulate":
		return runNetSimulate(env, args[1:])
	default:
		return env.fatalf("thn net: unknown subcommand %q; expected render, validate or simulate\n", args[0])
	}
}

// resolveNetPolicy loads configuration and derives the data-plane policy.
func resolveNetPolicy(env *Env, configPath string) (netconfig.Policy, string, ExitCode) {
	path := env.resolveConfigPath(configPath)

	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn net: %v\n", err)
		return netconfig.Policy{}, path, ExitProblems
	}

	return netPolicyFromConfig(cfg), path, ExitOK
}

// runNetValidate implements `thn net validate`.
func runNetValidate(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn net validate: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	p, path, code := resolveNetPolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	result, issues := netconfig.Validate(p)

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config":    path,
			"policy":    p,
			"valid":     result.Valid,
			"coherent":  result.Coherent,
			"findings":  result.Findings,
			"coherence": issues,
		}); err != nil {
			env.errorf("thn net validate: %v\n", err)
			return ExitProblems
		}
	} else {
		printNetValidation(env, path, p, result, issues)
	}

	if !result.Valid || !result.Coherent {
		return ExitProblems
	}
	return ExitOK
}

// printNetValidation renders a validation result.
func printNetValidation(env *Env, path string, p netconfig.Policy, r netconfig.Result, issues []netconfig.CoherenceIssue) {
	env.printf("Data-plane policy (from %s)\n", path)
	env.printf("────────────\n")
	env.printf("%s\n", p)
	env.printf("\n")
	env.printf("Result:   %s (%d error, %d warning, %d info)\n",
		passFail(r.Valid), r.ErrorCount, r.WarningCount, r.InfoCount)
	env.printf("Coherent: %s\n", coherenceLabel(r.Coherent))

	if len(issues) > 0 {
		env.printf("\nCoherence issues\n")
		env.printf("  These are correct in isolation but contradictory in combination.\n\n")
		for _, i := range issues {
			env.printf("  [%s] %s\n", i.Subsystems, i.Message)
		}
	}

	if len(r.Findings) == 0 {
		if len(issues) == 0 {
			env.printf("\nNo findings.\n")
		}
		return
	}

	env.printf("\nFindings\n")
	for _, f := range r.Findings {
		env.printf("  %-8s %-32s %s\n", f.Severity, f.Field, f.Message)
		if f.Hint != "" {
			env.printf("  %-8s %-32s hint: %s\n", "", "", f.Hint)
		}
	}
}

// runNetRender implements `thn net render`.
func runNetRender(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	out := fs.String("out", "")
	force := fs.Bool("force", false)
	skipValidate := fs.Bool("no-validate", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn net render: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	p, path, code := resolveNetPolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	if !*skipValidate {
		result, issues := netconfig.Validate(p)
		if !result.Valid || !result.Coherent {
			env.errorf("thn net render: the policy is not usable; not rendering.\n\n")
			printNetValidation(env, path, p, result, issues)
			env.errorf("\nFix the findings above, or pass --no-validate to render anyway.\n")
			return ExitProblems
		}
	}

	script := netnft.Render(p)

	if *out == "" {
		if env.IsJSON {
			if err := env.printJSON(map[string]any{
				"config":  path,
				"policy":  p,
				"script":  script,
				"written": false,
				"note":    "script was printed, not written; pass --out to write a file",
			}); err != nil {
				env.errorf("thn net render: %v\n", err)
				return ExitProblems
			}
			return ExitOK
		}
		env.printf("%s", script)
		return ExitOK
	}

	if err := writeScript(*out, script, *force); err != nil {
		env.errorf("thn net render: %v\n", err)
		return ExitProblems
	}

	if !env.IsJSON {
		env.errorf("Wrote %d bytes to %s\n", len(script), *out)
		env.errorf("Nothing has been applied. These commands would CHANGE host networking.\n")
		env.errorf("Review them, then apply by hand:\n")
		env.errorf("  sh -n %s      # syntax check only\n", *out)
		env.errorf("  sh %s          # apply\n", *out)
	}
	return ExitOK
}

// writeScript writes a rendered script to disk, refusing to overwrite without
// --force.
func writeScript(path, content string, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists; pass --force to overwrite it", path)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	// 0644: the script contains no secrets but describes the gateway's
	// routing and translation, so it is readable but not writable by others.
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// runNetSimulate implements `thn net simulate`.
func runNetSimulate(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	from := fs.String("from", "")
	to := fs.String("to", "")
	proto := fs.String("proto", "tcp")
	port := fs.String("port", "")
	via := fs.String("via", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn net simulate: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	if *from == "" || *to == "" {
		return env.fatalf("thn net simulate: --from and --to are required\n")
	}

	src, err := netip.ParseAddr(*from)
	if err != nil {
		return env.fatalf("thn net simulate: --from %q is not an IP address\n", *from)
	}
	dst, err := netip.ParseAddr(*to)
	if err != nil {
		return env.fatalf("thn net simulate: --to %q is not an IP address\n", *to)
	}

	pkt := netconfig.Packet{
		Source:      src,
		Destination: dst,
		Protocol:    *proto,
		Ingress:     *via,
	}

	if *port != "" {
		p, err := parsePort(*port)
		if err != nil {
			return env.fatalf("thn net simulate: %v\n", err)
		}
		pkt.DestinationPort = p
	}

	p, path, code := resolveNetPolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	sim := netconfig.Simulate(p, pkt)

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config":     path,
			"simulation": sim,
		}); err != nil {
			env.errorf("thn net simulate: %v\n", err)
			return ExitProblems
		}
	} else {
		printSimulation(env, path, sim)
	}

	if sim.Verdict == netconfig.VerdictDropped {
		return ExitProblems
	}
	return ExitOK
}

// runSimulate implements `thn simulate`, an alias for `thn net simulate`.
func runSimulate(env *Env, args []string) ExitCode {
	return runNetSimulate(env, args)
}

// printSimulation renders a packet trace.
func printSimulation(env *Env, path string, sim netconfig.Simulation) {
	pkt := sim.Packet

	env.printf("Packet simulation (from %s)\n", path)
	env.printf("────────────\n")
	env.printf("%s → %s  %s\n", pkt.Source, pkt.Destination, protocolLabel(pkt))
	if pkt.Ingress != "" {
		env.printf("Ingress: %s\n", pkt.Ingress)
	}
	env.printf("Verdict: %s\n", verdictLabel(sim.Verdict))
	env.printf("\n%s\n", sim.Summary)

	env.printf("\nPath\n")
	for i, step := range sim.Steps {
		env.printf("  %d. %-11s %-14s %s\n", i+1, step.Stage, step.Outcome, step.Detail)
		if step.Rule != "" {
			env.printf("     %-11s rule:         %s\n", "", step.Rule)
		}
	}

	if sim.EgressInterface != "" {
		env.printf("\nResult\n")
		env.printf("  Egress interface: %s\n", sim.EgressInterface)
		if sim.NextHop.IsValid() {
			env.printf("  Next hop:         %s\n", sim.NextHop)
		}
		env.printf("  Source translated: %t\n", sim.Translated)
		if sim.Translated {
			// Only report a concrete translated address when the policy
			// actually specifies one. Masquerade substitutes the uplink's
			// address, which is not known here, so printing the original
			// address back would be misleading.
			if sim.TranslatedSource.IsValid() && sim.TranslatedSource != pkt.Source {
				env.printf("  Translated source: %s\n", sim.TranslatedSource)
			} else {
				env.printf("  Translated source: the address assigned to %s (not known until activation)\n",
					sim.EgressInterface)
			}
		}
	}
}

// parsePort parses a port number.
func parsePort(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("--port %q is not a number", s)
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("--port %d is outside 0-65535", n)
	}
	return n, nil
}

// protocolLabel renders a packet's protocol for display.
func protocolLabel(p netconfig.Packet) string {
	switch p.Protocol {
	case "icmp", "icmpv6":
		return p.Protocol
	default:
		if p.DestinationPort != 0 {
			return fmt.Sprintf("%s/%d", p.Protocol, p.DestinationPort)
		}
		return p.Protocol
	}
}

// verdictLabel renders a verdict.
func verdictLabel(v netconfig.Verdict) string {
	switch v {
	case netconfig.VerdictForwarded:
		return "FORWARDED"
	case netconfig.VerdictAccepted:
		return "ACCEPTED"
	case netconfig.VerdictDropped:
		return "DROPPED"
	default:
		return "UNDETERMINED"
	}
}

// coherenceLabel renders the coherence verdict.
func coherenceLabel(ok bool) string {
	if ok {
		return "yes — routing, NAT and forwarding agree"
	}
	return "NO — the subsystems contradict each other"
}
