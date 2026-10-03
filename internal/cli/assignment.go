package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/state"
)

// Explicit interface assignment.
//
// # What this command family does, and what it deliberately does not
//
// It records a statement: "this hardware performs this logical role". It
// writes that statement to THN's own state database and nothing else.
//
// It does NOT touch Linux. No address, no route, no firewall, no interface
// state, no wireless mode. `thn interface assign` and `ip link set` share
// nothing but the word "interface", and the difference is the entire safety
// argument: this one writes a row in a SQLite table that happens to live
// under /var/lib.
//
// # The three concepts, kept separate
//
//	OBSERVED   internal/network, internal/host      what the machine has
//	ASSIGNED   internal/state, this file            what the operator said
//	DESIRED    internal/config                       what the document wants
//
// `thn interface list` prints all three side by side and never lets them
// collapse into one another. In particular an OBSERVED interface never
// acquires a role by existing, and an ASSIGNED role never acquires hardware
// by being written down.
//
// # Why the store and not the configuration file
//
// The configuration document already carries `network.wan` and `network.lan`,
// and they already accept a stable identity. So there are two places that can
// name a role's hardware, and two is one too many — the last milestone's DNS
// incident was exactly that shape, and the cost was a field nobody could tell
// was inert.
//
// They are therefore not two authorities for the same thing. They are
// different statements:
//
//	network.wan: "…"    the DESIRED document says which interface it wants
//	thn interface assign    the OPERATOR says which hardware that is
//
// The document wins where both speak, because a document is reviewed,
// versioned and diffed, while the store is a convenience for the common case
// of "I looked at this machine and picked one". Where both speak about the
// same role and name DIFFERENT hardware, that is a CONFLICT and it is
// reported rather than resolved silently — see mergeBindings.

// # Precedence, stated once
//
//	declared (config)  →  wins, and is reported as declared
//	stored  (assign)   →  used for any role the document leaves empty
//	neither           →  unassigned, and readiness says so
//
// An operator who wants the document to stop overriding simply clears the key
// or unsets the stored binding; neither is hidden and neither is inferred.

// bindingState is the four-way status of a role, which is the distinction the
// milestone turns on.
//
//	observed   a suitable interface exists
//	assigned   the operator declared one
//	resolved   the declared hardware is present right now
//	ready      the activation gate is also satisfied
//
// The four are genuinely different and collapsing any pair produces a lie. A
// machine with two NICs and no assignments is observed-and-ready-looking but
// has neither assigned nor resolved anything. A gateway whose uplink was
// unplugged is assigned and was ready, and is now not.
type bindingState string

const (
	// bindingUnassigned means no operator statement exists for the role.
	bindingUnassigned bindingState = "unassigned"

	// bindingAssigned means a statement exists, but the hardware it names
	// was not observed on this host.
	//
	// This is the state that must never be allowed to quietly become
	// something else. It is reported as unresolved and left alone.
	bindingAssigned bindingState = "assigned-unresolved"

	// bindingResolved means the declared hardware is present and bound.
	bindingResolved bindingState = "resolved"

	// bindingDeclared means the configuration document names this role's
	// hardware, overriding the store.
	bindingDeclared bindingState = "resolved (declared in config)"
)

// bindingConflict is a role claimed twice with different hardware.
type bindingConflict struct {
	Role     string
	Declared string
	Stored   string
}

// mergeBindings combines the document's declaration with the operator's store.
//
// It returns the bindings to resolve, the conflicts, and whether each role
// came from the document.
//
// The conflict case is the interesting one. When `network.wan` names one
// interface and the store names another, THN has two statements about one
// role. The document wins — it is the reviewed artefact — but the
// disagreement is returned rather than swallowed, because an operator who
// assigned an uplink and then wrote a different one in the config has made a
// mistake worth seeing, not a situation to resolve quietly.
func mergeBindings(cfg config.Config, stored []state.InterfaceAssignment) (
	bindings []host.Assignment,
	conflicts []bindingConflict,
	fromConfig map[host.Role]bool,
) {
	fromConfig = map[host.Role]bool{}

	storedByRole := map[string]state.InterfaceAssignment{}
	for _, s := range stored {
		storedByRole[s.Role] = s
	}

	// Only the roles the configuration model actually has a key for can be
	// declared. mgmt, guest and dmz have no key yet, so an assignment is
	// the ONLY way to bind them — which is the honest state of the document,
	// not an omission to paper over.
	declared := map[host.Role]string{
		host.RoleWAN: cfg.Network.WAN,
		host.RoleLAN: cfg.Network.LAN,
	}

	for _, r := range host.KnownRoles() {
		doc := strings.TrimSpace(declared[r])
		var storedSel string
		if s, ok := storedByRole[string(r)]; ok {
			storedSel = strings.TrimSpace(s.Selector)
		}

		switch {
		case doc == string(r):
			// The document states the logical role name, delegating hardware
			// resolution to stored assignments.
			if storedSel != "" {
				bindings = append(bindings, host.Assignment{Role: r, Selector: storedSel})
			} else {
				bindings = append(bindings, host.Assignment{Role: r, Selector: ""})
			}
			fromConfig[r] = true
		case doc != "" && storedSel != "" && doc != storedSel:
			conflicts = append(conflicts, bindingConflict{
				Role: string(r), Declared: doc, Stored: storedSel,
			})
			bindings = append(bindings, host.Assignment{Role: r, Selector: doc})
			fromConfig[r] = true
		case doc != "":
			bindings = append(bindings, host.Assignment{Role: r, Selector: doc})
			fromConfig[r] = true
		case storedSel != "":
			bindings = append(bindings, host.Assignment{Role: r, Selector: storedSel})
		}
	}

	return bindings, conflicts, fromConfig
}

// bindingSelector reports what a role is being resolved against, in the form
// an operator wrote it.
//
// It exists so the gate reason and subsystems quote the SELECTOR the operator
// used — a stable identity, a logical role, or a kernel name.
func bindingSelector(cfg config.Config, stored []state.InterfaceAssignment, r host.Role) string {
	declared := map[host.Role]string{
		host.RoleWAN: cfg.Network.WAN,
		host.RoleLAN: cfg.Network.LAN,
	}
	if d := strings.TrimSpace(declared[r]); d != "" {
		if d == string(r) {
			for _, s := range stored {
				if s.Role == string(r) {
					return s.Selector
				}
			}
			return ""
		}
		return d
	}
	for _, s := range stored {
		if s.Role == string(r) {
			return s.Selector
		}
	}
	return ""
}

// loadBindings reads the operator's assignments.
//
// A missing or unreadable database is NOT an error: it means no assignments
// have been made yet, which is the normal state of a fresh install. Treating
// it as a failure would make `thn readiness` unusable before the daemon has
// ever run.
func loadBindings(path string) []state.InterfaceAssignment {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}

	st, err := state.Open(path)
	if err != nil {
		return nil
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := st.ListAssignments(ctx)
	if err != nil {
		return nil
	}
	return out
}

// openStore opens the state database for writing.
//
// It is separate from loadBindings because a missing database is fine for
// reading and is the normal case for writing too: `thn interface assign` on a
// fresh install CREATES it. The permission error is reported, because a
// directory THN cannot write to is a real problem the operator must see.
func openStore(path string) (*state.Store, error) {
	if path == "" {
		return nil, fmt.Errorf("no state database is configured; set paths.state_db")
	}
	st, err := state.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening the state database: %w", err)
	}
	return st, nil
}

// resolveStorePath finds the state database for this invocation.
//
// It follows the same resolution the rest of the CLI uses: an explicit
// --state-db, then the loaded configuration, then nothing. It deliberately
// does not invent a default, because writing a database to a path nobody
// chose is how a tool ends up with two sources of truth in two directories.
func resolveStorePath(cfg config.Config, explicit string) string {
	if p := strings.TrimSpace(explicit); p != "" {
		return p
	}
	return strings.TrimSpace(cfg.Paths.StateDB)
}
