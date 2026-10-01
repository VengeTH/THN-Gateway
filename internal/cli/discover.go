package cli

// `thn discover` — what this machine is.
//
// # Why this exists
//
// An operator configuring a gateway for the first time does not know this
// machine's interface names, and should not have to. This command reports what
// was observed, what each observed interface could be used for, and what the
// host can do — so that choosing which NIC is the uplink is an informed act
// rather than a guess about what "eth0" means on this box.
//
// # Read-only
//
// It observes and renders. It assigns nothing, changes nothing, and activates
// nothing. Like `thn network inspect` it runs only guarded read-only commands.
//
// # MAC addresses are not printed
//
// A hardware address is a stable identifier and half of it is a network
// identifier. It is useful for configuration and it is not something to put
// on a screen in a shared terminal. The stable ID is shown instead, and the
// raw MAC is available behind --mac for the case where it is genuinely needed
// to write a configuration.

import (
	"fmt"
	"strings"

	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/network"
)

// runDiscover implements `thn discover`.
func runDiscover(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("mac", false)
	fs.Bool("json", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn discover: %v\n", err)
	}
	showMAC := *fs.bools["mac"]

	snap, err := network.NewInspector().Inspect(cmdContext())
	if err != nil && snap == nil {
		env.errorf("thn discover: %v\n", err)
		return ExitProblems
	}

	d := host.FromSnapshot(snap)

	if env.IsJSON {
		if err := env.printJSON(discoveryJSON(d, showMAC)); err != nil {
			env.errorf("thn discover: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	printDiscovery(env, d, showMAC)

	if !d.Supported {
		// Reporting nothing successfully would be the wrong answer: the
		// operator asked what this machine is and was not told.
		return ExitProblems
	}
	return ExitOK
}

// discoveryJSON renders the device for a machine consumer.
func discoveryJSON(d *host.Device, showMAC bool) map[string]any {
	ifaces := make([]map[string]any, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		entry := map[string]any{
			"id":          i.ID,
			"id_kind":     string(i.IDKind),
			"system_name": i.SystemName,
			"kind":        i.Kind,
			"state":       string(i.State),
			"link_up":     i.LinkUp,
			"mtu":         i.MTU,
			"assignable":  i.Assignable,
			"role":        string(i.Role),
		}
		if i.SpeedMbps > 0 {
			entry["speed_mbps"] = i.SpeedMbps
		}
		if len(i.Addresses) > 0 {
			entry["addresses"] = i.Addresses
		}
		if showMAC && i.MAC != "" {
			entry["mac"] = i.MAC
		}
		ifaces = append(ifaces, entry)
	}

	caps := make(map[string]any, len(d.Capabilities))
	for c, s := range d.Capabilities {
		caps[string(c)] = map[string]any{
			"available":  s.Available,
			"confidence": s.Confidence,
			"reason":     s.Reason,
		}
	}

	return map[string]any{
		"hostname":           d.Hostname,
		"os":                 d.OS,
		"arch":               d.Arch,
		"supported":          d.Supported,
		"observed_at":        d.ObservedAt,
		"forwarding_enabled": d.ForwardingEnabled,
		"interfaces":         ifaces,
		"capabilities":       caps,
		"diagnostics":        d.Diagnostics,
		"network_untouched":  true,
		"roles_available":    roleNames(),
		"statement":          "Current network remains untouched.",
	}
}

// roleNames lists assignable roles for a consumer.
func roleNames() []string {
	roles := host.KnownRoles()
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, string(r))
	}
	return out
}

// printDiscovery renders the device for a human.
func printDiscovery(env *Env, d *host.Device, showMAC bool) {
	env.printf("%s", RenderDiscovery(d, showMAC))
}

// RenderDiscovery renders a device as the operator sees it.
//
// It is separate from printDiscovery so that a test can show the exact output
// a simulated host produces without a second implementation drifting from this
// one. Two renderers that format the same model differently is precisely how a
// CLI starts telling an operator something the model does not say.
func RenderDiscovery(d *host.Device, showMAC bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("THN Host\n")
	w("────────\n")
	w("  OS:           %s/%s\n", d.OS, d.Arch)
	if d.Hostname != "" {
		w("  Loopback:     %s\n", d.Hostname)
	}
	w("  Observed:     %s\n", d.ObservedAt.Format("2006-01-02T15:04:05Z"))
	w("  Inspection:   %s\n", supportedWord(d.Supported))
	w("  IPv4 forward: %t\n\n", d.ForwardingEnabled)

	if len(d.Interfaces) == 0 {
		w("No network interfaces were observed.\n")
	}

	for n, i := range d.Interfaces {
		w("%d. %s\n", n+1, describeKind(i.Kind))
		w("   System:  %s\n", i.SystemName)
		w("   ID:      %s (%s)\n", i.ID, i.IDKind)
		w("   Link:    %s\n", linkLabel(i))
		w("   Speed:   %s\n", speedLabel(i.SpeedMbps))
		w("   MTU:     %d\n", i.MTU)
		if showMAC && i.MAC != "" {
			w("   MAC:     %s\n", i.MAC)
		}
		if i.Role != "" && i.Role != host.RoleUnassigned {
			w("   Role:    %s\n", i.Role)
		}
		if !i.Assignable {
			w("   Assign:  no — %s cannot hold a role\n", i.Kind)
		}
		if len(i.Addresses) > 0 {
			w("   Addrs:   %s\n", strings.Join(i.Addresses, ", "))
		}
		w("\n")
	}

	w("Capabilities\n")
	w("─────────────\n")
	for _, c := range host.AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			w("  %-18s UNKNOWN\n", c)
			continue
		}
		word := "NOT AVAILABLE"
		if s.Available {
			word = "AVAILABLE"
		}
		w("  %-18s %-14s (%s)\n", c, word, s.Confidence)
		if s.Reason != "" {
			w("      %s\n", s.Reason)
		}
	}

	w("\nRoles you can assign: %s\n", strings.Join(roleNames(), ", "))

	if len(d.Diagnostics) > 0 {
		w("\nDiagnostics\n")
		w("───────────\n")
		for _, diag := range d.Diagnostics {
			w("  - %s\n", diag)
		}
	}

	w("\nCurrent network remains untouched.\n")
	return b.String()
}

func supportedWord(ok bool) string {
	if ok {
		return "available"
	}
	return "unavailable on this platform — nothing was observed"
}

// describeKind renders an interface kind for a human.
func describeKind(kind string) string {
	switch kind {
	case "":
		return "Interface"
	case "ethernet":
		return "Ethernet"
	case "loopback":
		return "Loopback"
	case "wireless":
		return "Wireless"
	case "vlan":
		return "VLAN"
	case "bridge":
		return "Bridge"
	case "tunnel":
		return "Tunnel"
	default:
		return strings.ToUpper(kind[:1]) + kind[1:]
	}
}

func linkLabel(i host.Interface) string {
	if i.LinkUp {
		return "UP"
	}
	if i.State == network.LinkDown {
		return "DOWN (no carrier)"
	}
	if i.Kind == "loopback" {
		return "UP (loopback, no carrier)"
	}
	return "UNKNOWN"
}

func speedLabel(mbps int) string {
	switch {
	case mbps <= 0:
		return "not reported"
	case mbps >= 1000:
		return fmt.Sprintf("%d Gbps", mbps/1000)
	default:
		return fmt.Sprintf("%d Mbps", mbps)
	}
}
