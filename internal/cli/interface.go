package cli

// `thn interface` — see this machine's interfaces, and declare what they are for.
//
// # Read-only with respect to Linux
//
// Everything here observes. `thn interface list` runs the same read-only
// inspection as `thn discover`; `thn interface assign` writes one row into
// THN's own SQLite state database.
//
// No subcommand of this family can change an address, a route, a firewall, a
// DNS or DHCP server, an interface's administrative state, or a radio's mode.
// The only write is `state.PutAssignment`, and that is a table THN owns.
//
// The distinction is asserted, not just documented: TestInterfaceCommandsHold
// no networking tool, and every subcommand is TierPure, which the tier gate
// already requires to be incapable of reaching privileged code.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

// runInterface implements the `thn interface` group.
//
// The shape follows `thn network`: a group verb that dispatches to
// subcommands, prints its own usage when given none, and rejects anything it
// does not recognise rather than guessing.
func runInterface(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		env.errorf("thn interface: expected a subcommand.\n\n")
		env.errorf("  list       this machine's interfaces and what they are assigned to\n")
		env.errorf("  assign     bind an interface to a logical role\n")
		env.errorf("  unassign   remove a role binding\n")
		env.printf("\nNone of these change the host's network. They record\n")
		env.printf("what an interface is FOR. Applying anything is a different,\n")
		env.printf("separately gated operation that this build does not have.\n")
		return ExitUsage
	}

	switch args[0] {
	case "list":
		return runInterfaceList(env, args[1:])
	case "assign":
		return runInterfaceAssign(env, args[1:])
	case "unassign":
		return runInterfaceUnassign(env, args[1:])
	default:
		return env.fatalf(
			"thn interface: unknown subcommand %q; expected list, assign or unassign\n", args[0])
	}
}

// interfaceLoad performs the shared loading every subcommand needs.
//
// Configuration is optional here, not required. `thn interface list` is most
// useful on a machine that has never been configured, and refusing to run
// because /etc/thn/config.yaml is absent would make the one command that
// helps an operator start useless at exactly the moment they need it.
func interfaceLoad(env *Env, configFlag, stateFlag string) (config.Config, string) {
	cfg, err := loadConfigIfPresent(env, configFlag)
	if err != nil {
		// A malformed document is worth reporting, but it must not stop an
		// operator from LISTING hardware.
		env.errorf("thn interface: %v\n", err)
		env.errorf("  continuing without a configuration; assignments are unaffected.\n\n")
		cfg = config.Defaults()
	}
	return cfg, resolveStorePath(cfg, stateFlag)
}

// runInterfaceList implements `thn interface list`.
func runInterfaceList(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	statePath := fs.String("state-db", "")
	fs.Bool("mac", false)
	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn interface list: %v\n", err)
	}
	if len(rest) > 0 {
		return env.fatalf("thn interface list: expected no arguments, got %d\n", len(rest))
	}
	showMAC := *fs.bools["mac"]

	cfg, storePath := interfaceLoad(env, *configPath, *statePath)

	device, err := host.NewDiscovery().DiscoverContext(cmdContext())
	if err != nil {
		env.errorf("thn interface list: %v\n", err)
		return ExitProblems
	}

	stored := loadBindings(storePath)
	bindings, conflicts, fromConfig := mergeBindings(cfg, stored)
	res := host.Resolve(device, bindings)
	applyResolutionTo(device, res)

	if env.IsJSON {
		return interfaceListJSON(env, device, res, stored, conflicts)
	}

	env.printf("%s", RenderInterfaceTable(device, res, stored, conflicts, fromConfig, showMAC))

	if !device.Supported {
		return ExitProblems
	}
	// Conflicts and unresolved assignments are findings, not successes.
	if len(conflicts) > 0 || len(res.Problems) > 0 {
		return ExitProblems
	}
	return ExitOK
}

// interfaceListJSON renders the machine-readable form.
func interfaceListJSON(env *Env, d *host.Device, res host.Resolution,
	stored []state.InterfaceAssignment, conflicts []bindingConflict) ExitCode {

	rows := make([]map[string]any, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		row := map[string]any{
			"id":            i.ID,
			"id_kind":       string(i.IDKind),
			"system_name":   i.SystemName,
			"kind":          i.Kind,
			"physical":      i.Physical,
			"admin_up":      i.AdminUp,
			"carrier":       i.LinkUp,
			"speed_mbps":    i.SpeedMbps,
			"assignable":    i.Assignable,
			"role":          string(i.Role),
			"wireless_mode": i.WirelessMode,
			"mtu":           i.MTU,
			"ipv4":          i.IPv4(),
			"ipv6":          i.IPv6(),
		}
		if i.Role != host.RoleUnassigned && i.Role != "" {
			row["role_status"] = string(bindingResolved)
		} else {
			row["role_status"] = string(bindingUnassigned)
		}
		rows = append(rows, row)
	}

	assigned := make([]map[string]any, 0, len(stored))
	for _, s := range stored {
		assigned = append(assigned, map[string]any{
			"role":        s.Role,
			"selector":    s.Selector,
			"id_kind":     s.IDKind,
			"note":        s.Note,
			"assigned_at": s.AssignedAt,
			"assigned_by": s.AssignedBy,
		})
	}

	problems := make([]map[string]any, 0, len(res.Problems))
	for _, p := range res.Problems {
		problems = append(problems, map[string]any{
			"role":       string(p.Role),
			"selector":   p.Selector,
			"code":       p.Code,
			"message":    p.Message,
			"observed":   p.Observed,
			"candidates": p.Candidates,
		})
	}

	conf := make([]map[string]any, 0, len(conflicts))
	for _, c := range conflicts {
		conf = append(conf, map[string]any{
			"role":     c.Role,
			"declared": c.Declared,
			"stored":   c.Stored,
		})
	}

	if err := env.printJSON(map[string]any{
		"supported":         d.Supported,
		"interfaces":        rows,
		"assignments":       assigned,
		"problems":          problems,
		"conflicts":         conf,
		"network_untouched": true,
		"statement":         "Current network remains untouched.",
	}); err != nil {
		env.errorf("thn interface list: %v\n", err)
		return ExitProblems
	}
	return ExitOK
}

// runInterfaceAssign implements `thn interface assign`.
//
// The selector may be a stable identity or a kernel name. Both are accepted
// and BOTH are stored exactly as given; THN does not silently rewrite one into
// the other. An operator who typed a kernel name knows it may break on a
// rename, and the list output tells them which kind of binding they made.
func runInterfaceAssign(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	statePath := fs.String("state-db", "")
	roleFlag := fs.String("role", "")
	note := fs.String("note", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn interface assign: %v\n", err)
	}
	if len(rest) != 1 {
		env.errorf("thn interface assign: expected exactly one interface selector.\n\n")
		env.errorf("  thn interface assign hw:0123456789abcdef --role wan\n")
		env.errorf("  thn interface assign enp0s31f6 --role lan\n\n")
		env.errorf("  A selector is the stable ID from `thn interface list` or\n")
		env.errorf("  `thn discover`. A kernel name also works, but does not\n")
		env.errorf("  survive the interface being renamed or moved.\n")
		return ExitUsage
	}
	selector := strings.TrimSpace(rest[0])

	role, err := host.ParseRole(*roleFlag)
	if err != nil {
		return env.fatalf("thn interface assign: %v\n", err)
	}
	if role == host.RoleUnassigned {
		env.errorf("thn interface assign: --role is required.\n\n")
		env.errorf("  thn interface assign: expected one of %s\n", strings.Join(roleNames(), ", "))
		return ExitUsage
	}

	// `assign` needs only the store location. The configuration is loaded by
	// interfaceLoad for its side effect — resolving paths.StateDB — and is
	// deliberately not consulted for the role: assignment writes THN state,
	// not the document.
	_, storePath := interfaceLoad(env, *configPath, *statePath)
	device, derr := host.NewDiscovery().DiscoverContext(cmdContext())
	if derr != nil {
		env.errorf("thn interface assign: %v\n", derr)
		return ExitProblems
	}
	if device.Supported {
		if problem, bad := checkAssignable(device, selector); bad {
			env.printf("%s", RenderAssignmentRefusal(device, selector, role, problem))
			return ExitProblems
		}
	}

	st, err := openStore(storePath)
	if err != nil {
		env.errorf("thn interface assign: %v\n", err)
		return ExitProblems
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	previous, conflict, err := st.PutAssignment(ctx, state.InterfaceAssignment{
		Role:     string(role),
		Selector: selector,
		IDKind:   selectorIDKind(device, selector),
		Note:     *note,
	})
	if err != nil {
		if conflict != nil {
			env.printf("%s", RenderAssignmentConflict(conflict))
			return ExitProblems
		}
		env.errorf("thn interface assign: %v\n", err)
		return ExitProblems
	}

	if previous != nil && previous.Selector != selector {
		env.printf("role %s was bound to %s; it is now bound to %s.\n",
			role, previous.Selector, selector)
	} else if previous != nil {
		env.printf("role %s re-bound to %s.\n", role, selector)
	} else {
		env.printf("role %s bound to %s.\n", role, selector)
	}

	if device.Supported {
		if iface, ok := interfaceBySelector(device, selector); ok {
			env.printf("%s\n", iface.SystemName)
		}
	}

	env.printf("\nThis records an intent. Nothing on this host was changed.\n")
	env.printf("Run `thn readiness` to see whether it currently resolves.\n")
	return ExitOK
}

// runInterfaceUnassign implements `thn interface unassign`.
//
// It accepts either a selector or --role, because the case that matters most
// is the one where the hardware is GONE: then the selector is no longer
// anything the machine has, and the role is the only handle the operator has.
func runInterfaceUnassign(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	statePath := fs.String("state-db", "")
	roleFlag := fs.String("role", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn interface unassign: %v\n", err)
	}
	if len(rest) > 1 {
		return env.fatalf("thn interface unassign: expected at most one selector, got %d\n", len(rest))
	}
	selector := ""
	if len(rest) == 1 {
		selector = strings.TrimSpace(rest[0])
	}
	roleName := strings.TrimSpace(*roleFlag)
	if selector == "" && roleName == "" {
		env.errorf("thn interface unassign: name an interface, a role, or both.\n\n")
		env.errorf("  thn interface unassign --role wan\n")
		env.errorf("  thn interface unassign hw:0123456789abcdef\n\n")
		env.errorf("  --role works even when the hardware is missing, which is\n")
		env.errorf("  exactly when you most need to clear it.\n")
		return ExitUsage
	}

	// `unassign` also needs only the store. It must work when the hardware is
	// gone, which is exactly when an operator most needs to clear a binding,
	// so it deliberately consults no observation at all.
	_, storePath := interfaceLoad(env, *configPath, *statePath)

	st, err := openStore(storePath)
	if err != nil {
		env.errorf("thn interface unassign: %v\n", err)
		return ExitProblems
	}
	defer st.Close()
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var removed bool
	var clearedRole string

	switch {
	case roleName != "" && selector != "":
		// Both: require that they agree, so a typo cannot clear something
		// other than what was named.
		a, err := st.AssignmentFor(ctx, roleName)
		if err != nil || a.Selector != selector {
			env.errorf("thn interface unassign: role %s is not bound to %s.\n", roleName, selector)
			if a != nil {
				env.errorf("  it is bound to %s.\n", a.Selector)
			}
			return ExitProblems
		}
		removed, err = st.DeleteAssignment(ctx, roleName)
		clearedRole = roleName
		if err != nil {
			env.errorf("thn interface unassign: %v\n", err)
			return ExitProblems
		}
	case roleName != "":
		removed, err = st.DeleteAssignment(ctx, roleName)
		clearedRole = roleName
		if err != nil {
			env.errorf("thn interface unassign: %v\n", err)
			return ExitProblems
		}
	default:
		clearedRole, removed, err = st.DeleteAssignmentBySelector(ctx, selector)
		if err != nil {
			env.errorf("thn interface unassign: %v\n", err)
			return ExitProblems
		}
	}

	if !removed {
		env.errorf("thn interface unassign: nothing was assigned that way.\n")
		if clearedRole != "" {
			env.errorf("  no stored assignment for role %s.\n", clearedRole)
		}
		return ExitProblems
	}

	env.printf("role %s is no longer bound to any interface.\n", clearedRole)
	env.printf("\nThis changed THN's records only. The host is untouched.\n")
	return ExitOK
}

// checkAssignable decides whether a selector may hold a role.
//
// # What is rejected, and what is deliberately not
//
// Only two things are refused: an interface the model already marks
// unassignable, and one that does not exist.
//
// Notably ABSENT is any check of the form "WAN must be Ethernet". A wireless
// client is a perfectly good uplink for a topology that wants one, and a
// bridge is a perfectly good LAN. Rejecting an unusual interface because it
// is unusual would be THN inventing a topology policy, and the brief for this
// milestone is explicit that it must not.
//
// That also means this function does NOT refuse a wireless interface, and a
// test asserts it.
func checkAssignable(d *host.Device, selector string) (host.Problem, bool) {
	iface, ok := interfaceBySelector(d, selector)
	if !ok {
		return host.Problem{
			Code:     "unknown-interface",
			Selector: selector,
			Message:  fmt.Sprintf("no interface on this host matches %q", selector),
			Observed: d.SystemNames(),
		}, true
	}
	if !iface.Assignable {
		return host.Problem{
			Code:     "not-assignable",
			Selector: selector,
			Message:  fmt.Sprintf("%s is %s and cannot hold a role", iface.SystemName, iface.Kind),
			Observed: d.SystemNames(),
		}, true
	}
	return host.Problem{}, false
}

// interfaceBySelector finds an interface by stable ID or by kernel name.
//
// It delegates to the same matching rule internal/host.Resolve uses, so a
// selector accepted here is a selector that will resolve later. Checking
// assignability against a DIFFERENT matching rule would mean an interface
// could be refused by one and accepted by the other.
func interfaceBySelector(d *host.Device, selector string) (host.Interface, bool) {
	for _, i := range d.Interfaces {
		if i.ID == selector {
			return i, true
		}
	}
	for _, i := range d.Interfaces {
		if i.SystemName == selector {
			return i, true
		}
	}
	return host.Interface{}, false
}

// selectorIDKind reports what kind of selector this is, for the record.
//
// It is advisory metadata so a human reading the store can tell a durable
// binding from a fragile one. It is NOT a decision: a kernel name is accepted
// either way, because refusing it would remove the only form an operator can
// read off `ip link`.
func selectorIDKind(d *host.Device, selector string) string {
	if d == nil {
		return ""
	}
	if i, ok := interfaceBySelector(d, selector); ok {
		return string(i.IDKind)
	}
	return ""
}
