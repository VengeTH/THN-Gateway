package cli

import (
	"fmt"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

// Rendering for `thn interface`.
//
// Three renderers live here and each is separate from the command so that a
// test can assert the exact text an operator sees without a second
// implementation drifting from it. Two renderers that format one model
// differently is how a CLI starts telling an operator something the model
// does not say.

// RenderInterfaceTable renders the list.
//
// The columns are chosen for one decision: which interface to select. That
// means the stable ID comes first, because that is what an operator pastes
// into an assign command, and because it is the only column that keeps
// meaning after the machine is renamed.
func RenderInterfaceTable(d *host.Device, res host.Resolution, stored []state.InterfaceAssignment,
	conflicts []bindingConflict, fromConfig map[host.Role]bool, showMAC bool) string {

	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	w("INTERFACES\n")
	w("──────────\n")
	if !d.Supported {
		w("  This host could not be inspected, so nothing below is known.\n")
		for _, diag := range d.Diagnostics {
			w("  - %s\n", diag)
		}
		w("\nCurrent network remains untouched.\n")
		return b.String()
	}

	w("\n")
	w("  %-20s %-16s %-9s %-10s %-9s %-6s %s\n",
		"ID", "NAME", "TYPE", "STATE", "SPEED", "ROLE", "STATUS")
	w("  %s %s %s %s %s %s %s\n",
		rule(20), rule(16), rule(9), rule(10), rule(9), rule(6), rule(10))

	for _, i := range d.Interfaces {
		role := "-"
		status := string(bindingUnassigned)
		if i.Role != host.RoleUnassigned && i.Role != "" {
			role = strings.ToUpper(string(i.Role))
			status = string(bindingResolved)
			if fromConfig[i.Role] {
				status = string(bindingDeclared)
			}
		}

		w("  %-20s %-16s %-9s %-10s %-9s %-6s %s\n",
			truncateCell(i.ID, 20),
			truncateCell(i.SystemName, 16),
			truncateCell(i.Kind, 9),
			truncateCell(ifaceStateLabel(i), 10),
			truncateCell(speedCell(i.SpeedMbps), 9),
			truncateCell(role, 6),
			status)

		// The qualifiers that decide assignability go on their own line so
		// they cannot be missed in a wide table.
		var notes []string
		if !i.Physical {
			notes = append(notes, "virtual")
		}
		if i.WirelessMode != "" {
			notes = append(notes, "wireless:"+i.WirelessMode)
		}
		if i.Master != "" {
			notes = append(notes, "master:"+i.Master)
		}
		if showMAC && i.MAC != "" {
			notes = append(notes, "mac:"+i.MAC)
		}
		if !i.Assignable {
			notes = append(notes, "NOT assignable")
		}
		if len(notes) > 0 {
			w("      %s\n", strings.Join(notes, ", "))
		}
	}

	// Assigned but not present is the state that must be loud. It is the
	// whole reason this table shows OBSERVED and ASSIGNED side by side.
	unresolved := unresolvedBindings(stored, res)
	if len(unresolved) > 0 {
		w("\nASSIGNED BUT NOT PRESENT\n")
		w("───────────────────────\n")
		for _, s := range unresolved {
			w("  %s -> %s\n", strings.ToUpper(s.Role), s.Selector)
		}
		w("\n  These bindings are recorded and are NOT resolved.\n")
		w("  No other interface was substituted, and none will be:\n")
		w("  choosing different hardware is an operator's decision.\n")
	}

	if len(conflicts) > 0 {
		w("\nCONFLICTS\n")
		w("─────────\n")
		for _, c := range conflicts {
			w("  role %s is claimed twice with different hardware:\n", c.Role)
			w("    network.%s in the configuration: %s\n", c.Role, c.Declared)
			w("    stored assignment:               %s\n", c.Stored)
			w("    the configuration wins; the disagreement is reported, not resolved.\n")
		}
	}

	if len(stored) > 0 {
		w("\nSTORED ASSIGNMENTS\n")
		w("──────────────────\n")
		for _, s := range stored {
			w("  %-6s -> %-20s %s\n", s.Role, s.Selector, assignedAtLabel(s))
		}
	}

	if len(res.Problems) > 0 {
		w("\nPROBLEMS\n")
		w("────────\n")
		for _, p := range res.Problems {
			w("  %s\n", p.Message)
			if len(p.Observed) > 0 {
				w("    observed: %s\n", strings.Join(p.Observed, ", "))
			}
			if len(p.Candidates) > 0 {
				w("    possible: %s\n", strings.Join(p.Candidates, ", "))
			}
		}
	}

	w("\nAssign with:  thn interface assign <ID> --role <")
	w("%s>\n", strings.Join(roleNames(), "|"))
	w("\nThis listed the host. It changed nothing.\n")
	return b.String()
}

// unresolvedBindings returns stored roles whose hardware was not observed.
func unresolvedBindings(stored []state.InterfaceAssignment, res host.Resolution) []state.InterfaceAssignment {
	observed := map[string]bool{}
	for _, iface := range res.Assigned {
		observed[iface.ID] = true
		observed[iface.SystemName] = true
	}

	var out []state.InterfaceAssignment
	for _, s := range stored {
		if !observed[s.Selector] {
			out = append(out, s)
		}
	}
	return out
}

// RenderAssignmentRefusal explains why an interface cannot be assigned.
//
// It follows the shape the milestone asks for, and it renders the structured
// host.Problem rather than inventing a second error format — the model holds
// the facts, and a future UI renders the same facts differently.
func RenderAssignmentRefusal(d *host.Device, selector string, role host.Role, p host.Problem) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	w("Cannot assign %s as %s.\n\n", selector, strings.ToUpper(string(role)))
	w("Reason:\n  %s\n", p.Message)

	if iface, ok := interfaceBySelector(d, selector); ok {
		w("\nObserved:\n")
		w("  kind       = %s\n", iface.Kind)
		w("  physical   = %t\n", iface.Physical)
		w("  assignable = %t\n", iface.Assignable)
	}

	if len(p.Observed) > 0 {
		w("\nInterfaces on this host:\n")
		for _, n := range p.Observed {
			w("  %s\n", n)
		}
	}

	w("\nSuggested action:\n")
	switch p.Code {
	case "unknown-interface":
		w("  Run `thn interface list` and use an ID from the first column.\n")
		w("  Note: assigning hardware that is not currently present is not an\n")
		w("  error - it records an intent. Run `thn readiness` to see whether\n")
		w("  it resolves.\n")
	case "not-assignable":
		w("  Choose an assignable interface. A container endpoint or the\n")
		w("  loopback cannot hold a role: the first disappears with its\n")
		w("  container, and the second is not a network segment.\n")
		w("  Note: THN does not require a role to be Ethernet. A wireless\n")
		w("  client or a bridge is acceptable where the topology wants one.\n")
	default:
		w("  Run `thn interface list` and review the assignable interfaces.\n")
	}

	w("\nNothing was changed.\n")
	return b.String()
}

// RenderAssignmentConflict explains a refused write that contradicted a
// stored one.
func RenderAssignmentConflict(c *state.AssignmentConflict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Cannot assign %s to role %s.\n\n", c.Selector, c.WantedRole)
	fmt.Fprintf(&b, "Reason:\n  that interface is already assigned to role %s.\n\n", c.ExistingRole)
	fmt.Fprintf(&b, "Observed:\n  %s -> %s\n  %s -> (requested, not recorded)\n\n",
		c.ExistingRole, c.Selector, c.WantedRole)
	fmt.Fprintf(&b, "An interface cannot hold two roles. The second assignment was\n")
	fmt.Fprintf(&b, "NOT recorded, because recording it would leave a contradiction\n")
	fmt.Fprintf(&b, "that only surfaced at readiness time.\n\n")
	fmt.Fprintf(&b, "Suggested action:\n")
	fmt.Fprintf(&b, "  thn interface unassign --role %s\n", c.ExistingRole)
	fmt.Fprintf(&b, "  thn interface assign %s --role %s\n\n", c.Selector, c.WantedRole)
	fmt.Fprintf(&b, "Nothing was changed.\n")
	return b.String()
}

// ifaceStateLabel renders admin state and carrier together.
//
// Two columns collapsed into one would lose the distinction an operator
// actually needs: a cable that is unplugged is not an interface that is off.
func ifaceStateLabel(i host.Interface) string {
	switch {
	case i.AdminUp && i.LinkUp:
		return "up"
	case i.AdminUp:
		return "no-carrier"
	default:
		return "down"
	}
}

// speedCell renders a speed, or says plainly that there is none.
func speedCell(mbps int) string {
	switch {
	case mbps <= 0:
		return "unknown"
	case mbps >= 1000:
		return fmt.Sprintf("%d Gbps", mbps/1000)
	default:
		return fmt.Sprintf("%d Mbps", mbps)
	}
}

// assignedAtLabel renders when a binding was made, compactly.
func assignedAtLabel(s state.InterfaceAssignment) string {
	if s.AssignedAt == "" {
		return ""
	}
	if s.Note != "" {
		return fmt.Sprintf("%s  (%s)", s.AssignedAt, s.Note)
	}
	return s.AssignedAt
}

// rule returns n box-drawing characters for a table underline.
func rule(n int) string { return strings.Repeat("─", n) }

// truncateCell shortens a string to n columns, marking that it was shortened.
//
// Silently cutting an identifier would be worse than useless in a table whose
// whole purpose is copying a value into a command.
func truncateCell(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "~"
}
