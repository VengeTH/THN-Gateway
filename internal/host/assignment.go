package host

import (
	"fmt"
	"sort"
	"strings"
)

// Assignment binds a logical role to an interface.
//
// # Two forms, and why
//
//	Selector: mac:aa:bb:cc:dd:ee:ff    stable; survives a rename
//	Selector: enp0s31f6                the kernel name; does not
//
// Both are accepted because both are legitimate. The hardware-address form is
// what an operator should use and what THN should migrate toward; the system
// name remains because it is what `ip link` prints, it is what the existing
// configuration already uses, and removing it before there is something better
// to replace it with would break every deployment for no gain.
//
// # Never guessed
//
// If a selector matches nothing, this returns a Problem. It does not fall back
// to "the only remaining interface", and it does not treat an unmatched role
// as unassigned-and-fine. Silently picking something is how a gateway ends up
// applying its LAN to the uplink.
type Assignment struct {
	// Role is the logical role being filled.
	Role Role

	// Selector is the interface identifier: a stable ID or a system name.
	Selector string
}

// Problem is a structured reason an assignment could not be satisfied.
//
// This is machine-readable on purpose. The CLI renders one sentence; a future
// UI renders a selector list; an automated remediation reads the Candidates
// field. All three need the same underlying facts, and a single string error
// gives them only prose.
type Problem struct {
	// Role is the role that could not be filled.
	Role Role `json:"role"`

	// Selector is what was asked for.
	Selector string `json:"selector,omitempty"`

	// Code is a stable machine-readable reason.
	//
	//	unknown-interface   the selector matched nothing observed
	//	not-assignable      the interface can never hold a role (loopback)
	//	duplicate-role      two selectors claim the same role
	//	duplicate-interface one interface is claimed by two roles
	//	capability          the interface cannot satisfy what the role needs
	Code string `json:"code"`

	// Message is the human sentence.
	Message string `json:"message"`

	// Observed lists what was actually seen, for the UI to render.
	Observed []string `json:"observed,omitempty"`

	// Candidates are the interfaces that COULD take this role.
	Candidates []string `json:"candidates,omitempty"`
}

// Resolution is the outcome of applying assignments to a device.
type Resolution struct {
	// Assigned maps each satisfied role to its interface.
	Assigned map[Role]Interface `json:"assigned"`

	// Problems are every assignment that could not be satisfied.
	//
	// All of them are reported, not just the first. An operator fixing a
	// topology wants the whole list.
	Problems []Problem `json:"problems,omitempty"`
}

// OK reports whether every assignment was satisfied.
func (r Resolution) OK() bool { return len(r.Problems) == 0 }

// Resolve binds assignments to a device's observed interfaces.
//
// It assigns nothing that cannot be matched, and it reports every failure.
func Resolve(d *Device, assignments []Assignment) Resolution {
	res := Resolution{Assigned: map[Role]Interface{}}

	if d == nil || !d.Supported {
		res.Problems = append(res.Problems, Problem{
			Code:    "unknown-interface",
			Message: "this host could not be inspected, so no interface can be assigned to a role",
		})
		return res
	}

	claimed := map[string]Role{}

	for _, a := range assignments {
		if a.Role == RoleUnassigned || strings.TrimSpace(a.Selector) == "" {
			continue // explicitly not filling this role
		}

		iface, ok := match(d, a.Selector)
		if !ok {
			res.Problems = append(res.Problems, Problem{
				Role:     a.Role,
				Selector: a.Selector,
				Code:     "unknown-interface",
				Message: fmt.Sprintf("no observed interface matches %q for role %s",
					a.Selector, a.Role),
				Observed:   d.SystemNames(),
				Candidates: candidatesFor(d, res.Assigned),
			})
			continue
		}

		if !iface.Assignable {
			res.Problems = append(res.Problems, Problem{
				Role:     a.Role,
				Selector: a.Selector,
				Code:     "not-assignable",
				Message: fmt.Sprintf("interface %s is %s and cannot hold a role",
					iface.SystemName, iface.Kind),
				Observed: d.SystemNames(),
			})
			continue
		}

		if other, dup := claimed[iface.ID]; dup {
			res.Problems = append(res.Problems, Problem{
				Role:     a.Role,
				Selector: a.Selector,
				Code:     "duplicate-interface",
				Message: fmt.Sprintf("interface %s is already assigned to role %s",
					iface.SystemName, other),
				Observed: d.SystemNames(),
			})
			continue
		}

		if existing, dup := res.Assigned[a.Role]; dup {
			res.Problems = append(res.Problems, Problem{
				Role:     a.Role,
				Selector: a.Selector,
				Code:     "duplicate-role",
				Message: fmt.Sprintf("role %s is already assigned to %s",
					a.Role, existing.SystemName),
				Observed: d.SystemNames(),
			})
			continue
		}

		claimed[iface.ID] = a.Role
		iface.Role = a.Role
		res.Assigned[a.Role] = iface
	}

	// Deterministic order, so two runs report the same problems in the same
	// sequence and an operator can diff two runs.
	sort.Slice(res.Problems, func(i, j int) bool {
		if res.Problems[i].Role != res.Problems[j].Role {
			return res.Problems[i].Role < res.Problems[j].Role
		}
		return res.Problems[i].Selector < res.Problems[j].Selector
	})

	return res
}

// match finds an interface by stable ID or by system name.
func match(d *Device, selector string) (Interface, bool) {
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
	return Interface{}, false
}

// candidatesFor lists interfaces that could still take a role.
//
// Already-claimed interfaces are excluded, so the list an operator is shown
// does not include the one that is already the WAN.
func candidatesFor(d *Device, assigned map[Role]Interface) []string {
	taken := map[string]bool{}
	for _, i := range assigned {
		taken[i.ID] = true
	}

	out := make([]string, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		if i.Assignable && !taken[i.ID] {
			out = append(out, i.SystemName)
		}
	}
	sort.Strings(out)
	return out
}

// Suggestions renders the Problems a UI would show for an unresolved set.
//
// It exists so the shape of that output is decided once, in a testable place,
// rather than growing differently in each surface.
func Suggestions(res Resolution) []string {
	out := make([]string, 0, len(res.Problems))
	for _, p := range res.Problems {
		out = append(out, fmt.Sprintf("%s — %s. Observed: %s. Possible: %s",
			p.Role, p.Message,
			strings.Join(p.Observed, ", "),
			strings.Join(p.Candidates, ", ")))
	}
	return out
}
