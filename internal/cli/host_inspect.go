package cli

// `thn host` — what this machine is, and whether it could be a gateway.
//
// # Why this exists alongside `thn discover`
//
// The two commands answer different questions, and the distinction is worth
// keeping rather than merging.
//
//	thn discover   what hardware is here, and what could I assign?
//	thn host       what has THN established about this host, and what is
//	               it still unsure about?
//
// `discover` is the operator choosing an interface. `host` is THN reporting on
// itself: the platform, the observed network subsystems, the capability table
// with its confidence column, and a readiness verdict that says plainly which
// facts were confirmed and which were not.
//
// Merging them would produce a command whose output length depends on whether
// a config file happens to exist — `discover` gains profile sections from one
// and `host` does not. Keeping them apart means each output is a fixed shape
// for a given host, which is what a monitoring agent or a CI job needs.
//
// # Read-only, and it says so
//
// Like every other command in this CLI, it observes and reports. It cannot
// change a route, install a qdisc, or assign a role. The last line of the
// human output says so, because an operator running discovery on a live
// gateway for the first time is exactly the person who needs telling.

import (
	"fmt"
	"strings"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/network"
)

// hostOptions are the parsed options for `thn host`.
type hostOptions struct {
	// ShowMAC includes hardware addresses in the output.
	ShowMAC bool

	// ConfigPath is the configuration to resolve roles against. Empty means
	// no configuration was named.
	ConfigPath string

	// Requires is how many physical interfaces the intended topology needs.
	// It is passed straight to readiness evaluation, so it changes the
	// verdict rather than only the rendering.
	Requires int

	// Help asks for the usage text instead of a report.
	Help bool
}

// parseHostOptions parses the arguments of `thn host`.
//
// It is separated from the command body because everything after parsing
// observes the real host, and a test cannot assert that a flag reached
// readiness evaluation on a machine that is not a gateway. Parsing on its own
// is also where the flag kinds are declared, which makes it obvious that
// `--requires` is an int flag and not a string one parsed by hand.
func parseHostOptions(args []string) (hostOptions, error) {
	fs := newFlagSet()
	fs.Bool("mac", false)
	fs.String("config", "")
	requires := fs.Int("requires", 2)
	fs.Bool("help", false)

	if _, err := fs.Parse(args); err != nil {
		return hostOptions{}, err
	}
	opts := hostOptions{
		ShowMAC:    *fs.bools["mac"],
		ConfigPath: *fs.strings["config"],
		Requires:   *requires,
		Help:       *fs.bools["help"],
	}
	if !opts.Help && opts.Requires < 1 {
		return hostOptions{}, fmt.Errorf("--requires must be at least 1, got %d", opts.Requires)
	}
	return opts, nil
}

// runHost implements `thn host`.
func runHost(env *Env, args []string) ExitCode {
	opts, err := parseHostOptions(args)
	if err != nil {
		return env.fatalf("thn host: %v\n", err)
	}
	if opts.Help {
		env.printf("%s", hostUsage())
		return ExitOK
	}

	// The same discovery seam `thn discover` and `thn readiness` use. Three
	// commands assembling snapshots independently would eventually disagree,
	// and the disagreement would show up as `host` reporting one capability
	// set while `readiness` gated on another.
	_, d, err := host.NewDiscovery().Observe(cmdContext())
	if err != nil {
		env.errorf("thn host: %v\n", err)
		return ExitProblems
	}

	// Roles are resolved when a configuration exists and skipped when it does
	// not, so that `thn host` works on a machine that has never been
	// configured. Readiness on unconfigured hardware is still useful: it is
	// how an operator finds out whether this box could be a gateway before
	// they have decided that it should be.
	var resolutions map[host.Role]host.Resolution
	if cfg, cerr := loadConfigIfPresent(env, opts.ConfigPath); cerr == nil {
		resolutions = roleResolutions(d, cfg)
	}

	ready := host.EvaluateReadiness(d, host.ReadinessRequest{
		RequiredInterfaces: opts.Requires,
		Resolutions:        resolutions,
	})

	if env.IsJSON {
		if err := env.printJSON(hostJSON(d, opts.ShowMAC, ready, opts.Requires)); err != nil {
			env.errorf("thn host: %v\n", err)
			return ExitProblems
		}
		return hostExit(ready, d)
	}

	env.printf("%s", RenderHost(d, opts.ShowMAC, ready))
	return hostExit(ready, d)
}

// hostUsage renders the help text for `thn host`.
//
// It is written out rather than generated from the flagSet, because the
// generated form of a flag says what type it is and not what it means. The
// meaning of `--requires` — how many physical ports the intended topology
// needs, and that it changes only the readiness verdict — is the part an
// operator has to get right.
func hostUsage() string {
	return `thn host - report this host's platform, subsystems, capabilities and readiness

Usage: thn host [flags]

Flags:
  --requires <n>   physical interfaces the intended topology needs (default 2)
  --mac            include hardware addresses in the output
  --config <path>  configuration file to resolve roles against (optional)
  --json           emit machine-readable JSON
  --help           show this help

Exit codes:
  0  ready, or ready with warnings
  1  blocked, or something could not be observed
  2  usage error

This command is read-only. It observes and reports; it cannot change a route,
install a qdisc, assign a role, or modify host networking in any way.
`
}

// roleResolutions resolves every configured role separately.
//
// Resolution is done per-role because readiness asks about roles
// independently: an unresolved LAN is its own finding with its own candidate
// list, and reporting "some roles did not resolve" without saying which would
// be the less useful of the two answers.
func roleResolutions(d *host.Device, cfg config.Config) map[host.Role]host.Resolution {
	assignments := roleAssignments(cfg)
	out := make(map[host.Role]host.Resolution, len(assignments))
	for _, a := range assignments {
		out[a.Role] = host.Resolve(d, []host.Assignment{a})
	}
	return out
}

// hostExit maps a readiness verdict onto a process exit code.
//
// BLOCKED is ExitProblems and everything else is ExitOK. A host that is ready
// with warnings exits zero: the warnings are worth reading, and an operator
// scripting this does not want a warning about an unconfirmable CAKE module to
// fail their run. The distinction a script actually depends on — can this be a
// gateway or not — is preserved exactly.
func hostExit(ready host.Readiness, d *host.Device) ExitCode {
	if !d.Supported || ready.Blocked {
		return ExitProblems
	}
	return ExitOK
}

// hostJSON renders the host report for a machine consumer.
func hostJSON(d *host.Device, showMAC bool, ready host.Readiness, required int) map[string]any {
	ifaces := make([]map[string]any, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		m := map[string]any{
			"id":          i.ID,
			"id_kind":     string(i.IDKind),
			"system_name": i.SystemName,
			"kind":        i.Kind,
			"physical":    i.Physical,
			"admin_up":    i.AdminUp,
			"link_up":     i.LinkUp,
			"state":       string(i.State),
			"mtu":         i.MTU,
			"assignable":  i.Assignable,
			"role":        string(i.Role),
		}
		if showMAC {
			m["mac"] = i.MAC
		}
		if i.SpeedMbps > 0 {
			m["speed_mbps"] = i.SpeedMbps
		}
		if i.Master != "" {
			m["master"] = i.Master
		}
		if i.WirelessMode != "" {
			m["wireless_mode"] = i.WirelessMode
		}
		if len(i.Addresses) > 0 {
			m["addresses"] = i.Addresses
		}
		ifaces = append(ifaces, m)
	}

	caps := make([]map[string]any, 0, len(host.AllCapabilities()))
	for _, c := range host.AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			caps = append(caps, map[string]any{
				"name":           string(c),
				"available":      false,
				"confidence":     string(host.ConfidenceUnknown),
				"reason":         "not determined",
				"satisfies_gate": false,
			})
			continue
		}
		caps = append(caps, map[string]any{
			"name":       string(c),
			"available":  s.Available,
			"confidence": string(s.Confidence),
			"reason":     s.Reason,
			// satisfies_gate is the field that matters most to automation,
			// and the one most easily got wrong by reading `available`
			// alone. It is reported separately so a consumer does not have
			// to know the confidence rule to use a gate correctly.
			"satisfies_gate": s.Satisfies(),
		})
	}

	findings := make([]map[string]any, 0, len(ready.Findings))
	for _, f := range ready.Findings {
		findings = append(findings, map[string]any{
			"severity":   string(f.Severity),
			"code":       f.Code,
			"subject":    f.Subject,
			"message":    f.Message,
			"candidates": f.Candidates,
			"confidence": string(f.Confidence),
		})
	}

	return map[string]any{
		"supported":    d.Supported,
		"hostname":     d.Hostname,
		"platform":     d.System,
		"interfaces":   ifaces,
		"capabilities": caps,
		"forwarding": map[string]any{
			"enabled": d.ForwardingEnabled,
			"known":   d.ForwardingKnown,
		},
		"routes":          d.Routes,
		"nftables":        d.NFTables,
		"traffic_control": d.TrafficControl,
		"dns":             d.DNS,
		"readiness": map[string]any{
			"status":                 string(ready.Status),
			"summary":                ready.Summary,
			"blocked":                ready.Blocked,
			"facts":                  ready.Facts,
			"findings":               findings,
			"required_interfaces":    required,
			"uncertain_capabilities": ready.UncertainCapabilities,
		},
		"diagnostics":       d.Diagnostics,
		"observed_at":       d.ObservedAt,
		"network_untouched": true,
		"statement":         "Current network remains untouched. This command is read-only.",
	}
}

// RenderHost renders the human-readable host report.
//
// Exported for the same reason RenderDiscovery is: a test asserts on what an
// operator actually sees, and a renderer that only exists inside a command
// function cannot be tested without running the whole CLI.
func RenderHost(d *host.Device, showMAC bool, ready host.Readiness) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("THN Host\n")
	w("════════\n\n")

	if !d.Supported {
		w("Platform\n")
		w("────────\n")
		w("  host inspection is not available on this platform\n")
		w("  no interfaces, capabilities or readiness facts were observed\n")
		w("\nCurrent network remains untouched. This command is read-only.\n")
		return b.String()
	}

	w("Platform\n")
	w("────────\n")
	w("  %s\n", orNone(d.System.Describe()))
	if d.System.Kernel != "" {
		w("  kernel %s\n", d.System.Kernel)
	}
	w("  %s\n", orNone(d.System.Architecture))
	if d.Hostname != "" {
		w("  hostname %s\n", d.Hostname)
	}

	w("\nInterfaces\n")
	w("──────────\n")
	if len(d.Interfaces) == 0 {
		w("  none observed\n")
	}
	for _, i := range d.Interfaces {
		physical := "virtual"
		if i.Physical {
			physical = "physical"
		}
		w("  %-16s %-10s %s\n", i.SystemName, describeKind(i.Kind), physical)
		w("      %s\n", hostLinkSummary(i, showMAC))
	}

	w("\nNetwork state\n")
	w("──────────────\n")
	switch {
	case !d.ForwardingKnown:
		w("  IPv4 forwarding    unknown (could not be read)\n")
	case d.ForwardingEnabled:
		w("  IPv4 forwarding    enabled\n")
	default:
		w("  IPv4 forwarding    disabled\n")
	}
	w("  %s\n", hostDefaultRoute(d))
	w("  nftables           %s\n", nftWord(d.NFTables))
	for _, t := range d.NFTables.Tables {
		owner := "unmanaged"
		if t.IsTHNTable() {
			owner = "THN-owned"
		}
		w("    table %s %s (%s)\n", t.Family, t.Name, owner)
	}
	w("  tc                 %s\n", tcWord(d.TrafficControl))
	for _, q := range d.TrafficControl.Qdiscs {
		w("    qdisc %s %s", q.Kind, q.Handle)
		if q.Device != "" {
			w(" on %s", q.Device)
		}
		w("\n")
	}
	w("  DNS                %s\n", orNone(d.DNS.Mechanism))
	if len(d.DNS.Nameservers) > 0 {
		w("    nameservers %s\n", strings.Join(d.DNS.Nameservers, " "))
	}
	if !d.DNS.Authoritative && d.DNS.Reason != "" {
		w("    %s\n", d.DNS.Reason)
	}

	w("\nCapabilities\n")
	w("─────────────\n")
	for _, c := range host.AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			w("  %-20s %-12s %s\n", c, "not determined", string(host.ConfidenceUnknown))
			continue
		}
		word := "unavailable"
		if s.Available {
			word = "available"
		}
		// The confidence column is what makes this table honest:
		// "available" beside "inferred" means THN concluded so without
		// having asked.
		w("  %-20s %-12s %s\n", c, word, s.Confidence)
	}

	w("\nReadiness\n")
	w("─────────\n")
	w("  STATUS: %s\n", ready.Status)
	w("  %s\n", ready.Summary)
	for _, f := range ready.Facts {
		w("  %s\n", f)
	}
	for _, f := range ready.Blocking() {
		w("\n  BLOCKED  %s\n", f.Message)
	}
	for _, f := range ready.Warnings() {
		w("\n  WARN     %s\n", f.Message)
	}
	for _, f := range ready.Notes() {
		w("\n  NOTE     %s\n", f.Message)
	}

	w("\nCurrent network remains untouched. This command is read-only.\n")
	return b.String()
}

// hostDefaultRoute renders the observed default route, or says there is none.
func hostDefaultRoute(d *host.Device) string {
	rt, ok := d.DefaultRoute()
	if !ok {
		return "default route      none observed"
	}
	proto := rt.Protocol
	if proto == "" {
		proto = "unknown"
	}
	if rt.Gateway != "" {
		return fmt.Sprintf("default route      via %s dev %s (%s)", rt.Gateway, rt.Interface, proto)
	}
	return fmt.Sprintf("default route      dev %s (%s)", rt.Interface, proto)
}

// nftWord renders the nftables subsystem state as a short phrase.
func nftWord(st network.NFTablesState) string {
	switch {
	case !st.Checked:
		return "not probed"
	case st.QuerySucceeded:
		return "available"
	case st.Available:
		return "installed, not queryable"
	default:
		return "unavailable"
	}
}

// tcWord renders the traffic control state as a short phrase.
func tcWord(st network.TCState) string {
	switch {
	case !st.Checked:
		return "not probed"
	case st.QuerySucceeded:
		return "available"
	case st.Available:
		return "installed, not queryable"
	default:
		return "unavailable"
	}
}

// hostLinkSummary renders the per-interface detail line.
func hostLinkSummary(i host.Interface, showMAC bool) string {
	parts := []string{fmt.Sprintf("carrier: %s", yesNo(i.LinkUp))}
	if i.SpeedMbps > 0 {
		parts = append(parts, fmt.Sprintf("%d Mbps", i.SpeedMbps))
	}
	parts = append(parts, fmt.Sprintf("mtu %d", i.MTU))
	if i.Master != "" {
		parts = append(parts, "master "+i.Master)
	}
	if i.WirelessMode != "" {
		parts = append(parts, "mode "+i.WirelessMode)
	}
	if showMAC && i.MAC != "" {
		parts = append(parts, i.MAC)
	}
	if len(i.Addresses) > 0 {
		parts = append(parts, strings.Join(i.Addresses, " "))
	}
	return strings.Join(parts, " · ")
}
