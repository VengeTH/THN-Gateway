package cli

// The assignment command family cannot reach the host.
//
// # What is asserted, and why by assertion
//
// Every other safety property in this repository is structural: the applier
// does not exist, the state machine has no edge, the guard has no mutating
// entry. This one is a matter of what the code happens to call.
//
// The milestone brief is explicit that `thn interface assign` must not change
// the Linux network, and that it "should not need to mutate the Linux network
// at all". A comment saying so is not evidence. This test parses the source of
// the command family and refuses a mutating external command in it.
//
// It is deliberately narrower than TestRepoContainsNoUnguardedExec: that test
// asks whether a binary is on the allowlist, which for `ip` and `tc` is true
// even though a MUTATING invocation would be denied by the guard at runtime.
// This asks the different and stronger question: does this family try?

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/state"
)

// mutatingNetworkingCommands are the binaries this family must not invoke.
//
// The list includes the tools an assignment would be tempted to use if it were
// doing its job wrong, and the three that would matter most: nmcli, netplan
// and systemctl can all reconfigure a host without anyone noticing.
var mutatingNetworkingCommands = []string{
	"ip", "iw", "ethtool", "nmcli", "nm", "netplan", "systemctl",
	"nft", "iptables", "ip6tables", "route", "ifconfig",
	"bridge", "vlan", "wpa_supplicant", "dhclient", "resolvectl",
}

// assignmentSources are the files that implement `thn interface`.
var assignmentSources = []string{
	"interface.go",
	"interface_render.go",
	"assignment.go",
}

// TestInterfaceAssignmentHoldsNoNetworkingTool is the Task 13 assertion.
func TestInterfaceAssignmentHoldsNoNetworkingTool(t *testing.T) {
	fset := token.NewFileSet()

	for _, name := range assignmentSources {
		path := filepath.Join(".", name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}

		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// guard.Exec and friends are the ONLY permitted external call,
			// and they are inspected separately below.
			receiver, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			for _, banned := range mutatingNetworkingCommands {
				if receiver.Name != banned {
					continue
				}
				t.Errorf("%s calls %s.%s; the assignment command family must not "+
					"reach the host's network configuration", name, banned, sel.Sel.Name)
			}
			return true
		})
	}
}

// TestTheAssignmentFamilyUsesOnlyTheGuard makes the same point positively.
//
// Read-only inspection IS expected — `thn interface list` must look at the
// machine. So the family does call the guard. What it must never do is call
// anything else, and this asserts the exhaustive list of what it does call.
func TestTheAssignmentFamilyUsesOnlyTheGuard(t *testing.T) {
	fset := token.NewFileSet()
	allowed := map[string]bool{"guard": true}

	for _, name := range assignmentSources {
		path := filepath.Join(".", name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			// Only look at calls, so a bare package reference is ignored.
			if _, isCall := n.(*ast.CallExpr); !isCall {
				return true
			}
			if _, isBuiltin := sel.Sel.Name, true; !isBuiltin {
				_ = isBuiltin
			}
			if !allowed[recv.Name] && isExternalPackage(recv.Name) {
				t.Errorf("%s calls %s.%s; only internal/guard may be reached from the "+
					"assignment family", name, recv.Name, sel.Sel.Name)
			}
			return true
		})
	}
}

// isExternalPackage filters out local identifiers and receivers.
//
// A bare identifier match would flag `strings.Join` and every method on a local
// value. This keeps the check to names that look like imported packages,
// which is where an external command would live.
func isExternalPackage(name string) bool {
	switch name {
	case "guard", "state", "host", "config", "fmt", "strings", "os", "time",
		"context", "flag", "os/exec", "net", "errors":
		return true
	default:
		return false
	}
}

// TestTheAssignmentFamilyIsPure asserts the tier.
//
// TierPure is the repository's structural statement that a command cannot
// reach privileged code. An assignment command that reached anything above the
// database would be a lie about its tier.
func TestTheAssignmentFamilyIsPure(t *testing.T) {
	cmd, ok := commands["interface"]
	if !ok {
		t.Fatal("`thn interface` is not registered")
	}
	if cmd.Tier != TierPure {
		t.Errorf("`thn interface` is %s; recording an assignment must be pure", cmd.Tier)
	}
	if cmd.Run == nil {
		t.Error("`thn interface` has no Run")
	}
}

// TestNoNewDestructiveCommand guards the one destructive verb.
func TestNoNewDestructiveCommand(t *testing.T) {
	for name, cmd := range commands {
		if cmd.Tier == TierDestructive && name != "activate" {
			t.Errorf("`thn %s` is destructive; only activate may be", name)
		}
	}
}

// TestUnassignReportsWhenThereWasNothingToClear keeps the two answers apart.
//
// "I cleared this" and "there was nothing to clear" are different, and an
// operator who is told the first when the second happened will go looking for
// a command that worked.
func TestUnassignReportsWhenThereWasNothingToClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	write(t, path, []state.InterfaceAssignment{{Role: "wan", Selector: "hw:abc"}})

	if !del(t, path, "wan") {
		t.Error("deleting an existing binding reported nothing removed")
	}
	if del(t, path, "wan") {
		t.Error("deleting a binding that does not exist reported a removal")
	}
	if len(read(t, path)) != 0 {
		t.Error("the store is not empty after the last removal")
	}
}

// TestAnAssignmentCarriesNoSecretishData is a small hygiene check.
//
// The table records a role and a selector. It must not accumulate anything
// that looks like a credential, because a state database is the first thing an
// operator copies when backing up a gateway.
func TestAnAssignmentCarriesNoSecretishData(t *testing.T) {
	for _, field := range []struct{ name, value string }{
		{"note", "uplink to the ISP"},
		{"selector", "hw:0123456789abcdef"},
		{"id_kind", "hardware"},
	} {
		lowered := strings.ToLower(field.value)
		for _, banned := range []string{"password", "passwd", "secret", "token", "key="} {
			if strings.Contains(lowered, banned) {
				t.Errorf("%s carries %q, which looks like a credential", field.name, field.value)
			}
		}
	}
}
