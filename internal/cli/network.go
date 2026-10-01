package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/venth/thn-gateway/internal/network"
)

// This file implements `thn network inspect`.
//
// # What it is for
//
// The first command somebody runs on a new machine. It answers one question —
// what can THN see of this host's network — and it answers it by reading, not
// by interpreting a configuration.
//
// The distinction matters at this stage. `thn net render` and `thn plan` show
// what the configuration would produce. `inspect` shows what is actually
// there. On a laptop they say very different things, and the second is the one
// an operator needs first.
//
// # Read-only, and visibly so
//
// It calls exactly one guard-permitted command per subsystem and writes
// nothing. It opens no socket to anything, contacts nothing, and has no flag
// that changes anything. That is why it is safe to run first on an unknown
// machine, which is the point of having it.

// runNetwork implements the `thn network` group.
func runNetwork(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		env.errorf("thn network: expected a subcommand.\n\n")
		env.errorf("  inspect   what THN can see of this host's network (read-only)\n")
		return ExitUsage
	}

	switch args[0] {
	case "inspect":
		return runNetworkInspect(env, args[1:])
	default:
		return env.fatalf(
			"thn network: unknown subcommand %q; expected inspect\n", args[0])
	}
}

// runNetworkInspect implements `thn network inspect`.
func runNetworkInspect(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.String("interface", "")

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn network inspect: %v\n", err)
	}

	snap, err := network.NewInspector().Inspect(cmdContext())
	if err != nil {
		return env.fatalf("thn network inspect: %v\n", err)
	}

	if want := fsValue(fs, "interface"); want != "" {
		iface := snap.Interface(want)
		if iface == nil {
			return env.fatalf("thn network inspect: no interface named %q on this host.\n", want)
		}
		if env.IsJSON {
			if err := env.printJSON(iface); err != nil {
				env.errorf("thn network inspect: %v\n", err)
				return ExitProblems
			}
			return ExitOK
		}
		env.printf("%s", renderInterface(*iface))
		return ExitOK
	}

	if env.IsJSON {
		if err := env.printJSON(snap); err != nil {
			env.errorf("thn network inspect: %v\n", err)
			return ExitProblems
		}
		if !snap.Supported {
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("%s", renderSnapshot(snap))

	if !snap.Supported {
		// Not an error in the command: the host simply is not one THN can read.
		// It is a problem for the operator, so it exits non-zero, and it says
		// why rather than leaving an empty table to be interpreted.
		return ExitProblems
	}
	return ExitOK
}

func renderSnapshot(snap *network.Snapshot) string {
	var sb strings.Builder

	if !snap.Supported {
		sb.WriteString("THN cannot inspect this host's network.\n\n")
		sb.WriteString("Reason\n")
		sb.WriteString("------\n")
		for _, d := range snap.Diagnostics {
			fmt.Fprintf(&sb, "  %s\n", d.Message)
		}
		sb.WriteString("\n")
		sb.WriteString("Host inspection reads the network through ip(8) on Linux. On any\n")
		sb.WriteString("other platform THN reports nothing rather than guessing, because a\n")
		sb.WriteString("host it cannot see is a host it must not claim to understand.\n")
		return sb.String()
	}

	fmt.Fprintf(&sb, "Host:     %s\n", hostName())
	fmt.Fprintf(&sb, "Platform: %s\n", orDash(snap.Platform))
	fmt.Fprintf(&sb, "Read at:  %s\n\n", snap.CapturedAt.Format("2006-01-02 15:04:05Z"))

	if len(snap.Diagnostics) > 0 {
		sb.WriteString("Diagnostics\n")
		sb.WriteString("-----------\n")
		for _, d := range snap.Diagnostics {
			fmt.Fprintf(&sb, "  [%-7s] %s: %s\n", d.Severity, d.Subject, d.Message)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Interfaces\n")
	sb.WriteString("----------\n")
	if len(snap.Interfaces) == 0 {
		sb.WriteString("  none were found\n")
	}
	for _, i := range snap.Interfaces {
		fmt.Fprintf(&sb, "  %-16s %-6s %-8s %-17s %s\n",
			i.Name, ifIndex(i.Index), i.State, orDash(i.MAC), orDash(i.Kind))
		for _, a := range i.Addresses {
			fmt.Fprintf(&sb, "  %-16s       %-24s %s\n", "", a.CIDR, orDash(a.Scope))
		}
		if i.MTU > 0 {
			fmt.Fprintf(&sb, "  %-16s       mtu %d\n", "", i.MTU)
		}
	}

	sb.WriteString("\nRoutes\n")
	sb.WriteString("------\n")
	if len(snap.Routes) == 0 {
		sb.WriteString("  none were found\n")
	}
	for _, r := range snap.Routes {
		gw := ""
		if r.Gateway != "" {
			gw = " via " + r.Gateway
		}
		metric := ""
		if r.Metric > 0 {
			metric = fmt.Sprintf(" metric %d", r.Metric)
		}
		fmt.Fprintf(&sb, "  %-20s dev %-14s%s%s\n", r.Destination, r.Interface, gw, metric)
	}

	if def := snap.DefaultRoute(); def != nil {
		fmt.Fprintf(&sb, "\nDefault route: via %s out %s\n",
			orDash(def.Gateway), orDash(def.Interface))
	} else {
		sb.WriteString("\nDefault route: none\n")
	}

	sb.WriteString("\nNeighbours\n")
	sb.WriteString("----------\n")
	if len(snap.Neighbours) == 0 {
		sb.WriteString("  none were found\n")
	}
	for _, n := range snap.Neighbours {
		fmt.Fprintf(&sb, "  %-16s %-18s %-17s %s\n",
			n.Interface, n.Address, orDash(n.LinkLayer), orDash(n.State))
	}

	sb.WriteString("\nKernel tunables\n")
	sb.WriteString("---------------\n")
	for _, s := range snap.Sysctl {
		v := s.Value
		if s.Error != "" {
			v = "unreadable: " + s.Error
		}
		fmt.Fprintf(&sb, "  %-38s %s\n", s.Key, orDash(v))
	}

	sb.WriteString("\nThis command reads and writes nothing.\n")
	return sb.String()
}

func renderInterface(i network.Interface) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n\n", i.Name)
	fmt.Fprintf(&sb, "  index    %d\n", i.Index)
	fmt.Fprintf(&sb, "  state    %s\n", i.State)
	fmt.Fprintf(&sb, "  kind     %s\n", orDash(i.Kind))
	fmt.Fprintf(&sb, "  mac      %s\n", orDash(i.MAC))
	fmt.Fprintf(&sb, "  mtu      %d\n", i.MTU)
	if len(i.Flags) > 0 {
		fmt.Fprintf(&sb, "  flags    %s\n", strings.Join(i.Flags, " "))
	}
	for _, a := range i.Addresses {
		fmt.Fprintf(&sb, "  address  %-24s %s\n", a.CIDR, orDash(a.Scope))
	}
	return sb.String()
}

// hostName is the machine's own name, read separately from the snapshot.
//
// The snapshot deliberately carries no hostname: it reports the network, and a
// name is not part of that. Reading it here rather than widening the snapshot
// keeps that boundary.
func hostName() string {
	name, err := os.Hostname()
	if err != nil {
		return "-"
	}
	return name
}

// ifIndex renders an interface index for the table.
//
// An interface without an index — a tunnel, for instance — reports zero from
// the kernel, and printing "0" reads like a real index belonging to something
// else. The marker is a dash, which the rest of the table already uses for
// "not present".
func ifIndex(n int) string {
	if n <= 0 {
		return "-"
	}
	return strconv.Itoa(n)
}
func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
