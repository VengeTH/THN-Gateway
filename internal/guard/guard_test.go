package guard

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestPermittedReadOnlyInvocations(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"ip", []string{"-j", "addr", "show"}},
		{"ip", []string{"-j", "-d", "link", "show"}},
		{"ip", []string{"-j", "route", "show", "table", "all"}},
		{"ip", []string{"route", "get", "10.77.0.1"}},
		{"ip", []string{"-4", "-o", "addr", "show", "scope", "global"}},
		{"nft", []string{"list", "ruleset"}},
		{"nft", []string{"-j", "list", "ruleset"}},
		{"tc", []string{"qdisc", "show"}},
		{"tc", []string{"-j", "class", "show", "dev", "enp0s31f6"}},
		{"sysctl", []string{"-n", "net.ipv4.ip_forward"}},
	}

	for _, c := range cases {
		if err := Check(c.name, c.args...); err != nil {
			t.Errorf("Check(%q, %v) = %v, want nil", c.name, c.args, err)
		}
	}
}

// TestMutatingInvocationsDenied is the core safety test. Each case is a real
// command that WOULD change host networking. None may ever be permitted.
func TestMutatingInvocationsDenied(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		// Addresses
		{"ip", []string{"addr", "add", "10.77.0.1/24", "dev", "enx1234"}},
		{"ip", []string{"addr", "flush", "dev", "enx1234"}},
		{"ip", []string{"-4", "addr", "add", "10.77.0.1/24"}},
		// Routing
		{"ip", []string{"route", "add", "default", "via", "192.168.1.1"}},
		{"ip", []string{"route", "replace", "10.0.0.0/8", "dev", "enx1234"}},
		{"ip", []string{"route", "del", "10.0.0.0/8"}},
		{"ip", []string{"route", "flush"}},
		{"ip", []string{"rule", "add", "from", "10.77.0.0/24", "table", "100"}},
		// Links
		{"ip", []string{"link", "set", "enx1234", "up"}},
		{"ip", []string{"link", "set", "enx1234", "down"}},
		{"ip", []string{"link", "add", "dummy0", "type", "dummy"}},
		// Firewall
		{"nft", []string{"add", "table", "inet", "thn"}},
		{"nft", []string{"flush", "ruleset"}},
		{"nft", []string{"delete", "table", "inet", "thn"}},
		{"nft", []string{"insert", "rule", "inet", "thn", "input", "accept"}},
		{"nft", []string{"-f", "/etc/thn/firewall.nft"}},
		// Traffic control
		{"tc", []string{"qdisc", "replace", "dev", "enx1234", "root", "cake"}},
		{"tc", []string{"qdisc", "del", "dev", "enx1234", "root"}},
		{"tc", []string{"filter", "add", "dev", "enx1234"}},
		// Kernel tunables
		{"sysctl", []string{"-w", "net.ipv4.ip_forward=1"}},
		{"sysctl", []string{"net.ipv4.ip_forward=1"}},
		{"sysctl", []string{"-p", "/etc/thn/sysctl.conf"}},
		// Privilege escalation vectors
		{"sh", []string{"-c", "ip addr add 10.77.0.1/24 dev enx1234"}},
		{"bash", []string{"-c", "nft flush ruleset"}},
		{"systemctl", []string{"restart", "NetworkManager"}},
		{"nmcli", []string{"connection", "modify", "eth0", "ipv4.gateway", "10.0.0.1"}},
	}

	for _, c := range cases {
		err := Check(c.name, c.args...)
		if err == nil {
			t.Errorf("Check(%q, %v) = nil, want denial", c.name, c.args)
			continue
		}
		if !errors.Is(err, ErrDenied) {
			t.Errorf("Check(%q, %v) = %v, want ErrDenied", c.name, c.args, err)
		}
	}
}

// TestMutatingErrorsAreClassified verifies that genuinely state-changing
// commands are reported as ErrMutating rather than generic ErrDenied, so the
// audit trail distinguishes "unsupported" from "deliberately forbidden".
func TestMutatingErrorsAreClassified(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"ip", []string{"addr", "add", "10.77.0.1/24", "dev", "eth0"}},
		{"ip", []string{"route", "replace", "default", "via", "10.0.0.1"}},
		{"ip", []string{"link", "set", "eth0", "down"}},
		{"nft", []string{"flush", "ruleset"}},
		{"tc", []string{"qdisc", "replace", "dev", "eth0"}},
	}

	for _, c := range cases {
		err := Check(c.name, c.args...)
		if !errors.Is(err, ErrMutating) {
			t.Errorf("Check(%q, %v) = %v, want ErrMutating", c.name, c.args, err)
		}
	}
}

func TestMalformedInvocationsDenied(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"ip", nil},
		{"ip", []string{"-j"}},
		{"ip", []string{"--exec", "rm", "-rf", "/"}},
		{"nft", []string{}},
		{"tc", []string{"qdisc"}},
		{"sysctl", []string{}},
		{"unknown-binary", []string{"show"}},
	}

	for _, c := range cases {
		if err := Check(c.name, c.args...); err == nil {
			t.Errorf("Check(%q, %v) = nil, want denial", c.name, c.args)
		}
	}
}

// TestNoMutatingEntryInAllowlist is a defensive assertion on the allowlist
// itself. It fails if anyone adds a mutating verb while updating policy, even
// if that verb is not yet reachable from any call site.
func TestNoMutatingEntryInAllowlist(t *testing.T) {
	for bin, p := range allowlist {
		for _, v := range p.verbs {
			if isMutatingVerb(v) {
				t.Errorf("allowlist[%q] contains mutating verb %q", bin, v)
			}
		}
		for _, v := range p.flags {
			if isMutatingVerb(v) {
				t.Errorf("allowlist[%q] contains mutating flag %q", bin, v)
			}
		}
		if isMutatingVerb(p.verbFlag) && p.verbFlag != "" {
			t.Errorf("allowlist[%q] verbFlag %q is mutating", bin, p.verbFlag)
		}
	}
}

// TestRepoContainsNoUnguardedExec is the repository-wide enforcement layer.
//
// It parses every Go file in the module and locates direct calls to
// os/exec.Command, os/exec.CommandContext, exec.Cmd.Start and
// exec.Cmd.Run. Any such call that passes a statically-known binary name must
// reference a binary on the guard allowlist.
//
// The intent is that adding an apply path requires deliberately deleting or
// rewriting this test, which is a visible, reviewable act rather than a
// silent one. The threat model is an absent-minded engineer on a laptop
// 100km from an unattended gateway, not a determined adversary: an adversary
// who wants to mutate networking has root on the host and can skip THN.
func TestRepoContainsNoUnguardedExec(t *testing.T) {
	root := moduleRoot(t)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		return checkFileForExec(t, root, path)
	})
	if err != nil {
		t.Fatalf("walking module: %v", err)
	}
}

// checkFileForExec parses one file and validates every statically-resolvable
// process-spawning call site.
func checkFileForExec(t *testing.T, root, path string) error {
	t.Helper()

	rel, _ := filepath.Rel(root, path)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil // unparseable files are caught by the compiler
	}

	allowed := map[string]bool{}
	for bin := range allowlist {
		allowed[bin] = true
	}

	// Package-level aliases that legitimately reference the exec package.
	execAliases := map[string]bool{}

	ast.Inspect(f, func(n ast.Node) bool {
		// Track aliases: var run = exec.Command, etc.
		switch s := n.(type) {
		case *ast.ValueSpec:
			for i, name := range s.Names {
				if len(s.Values) <= i {
					continue
				}
				if isExecSelector(s.Values[i], "Command", "CommandContext") {
					execAliases[name.Name] = true
				}
			}
		}
		return true
	})

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		var binary string
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if isExecSelector(fun, "Command", "CommandContext") && len(call.Args) > 0 {
				binary = literalString(call.Args[0])
			}
			if fun.Sel != nil && (fun.Sel.Name == "Start" || fun.Sel.Name == "Run") {
				if id, ok := fun.X.(*ast.Ident); ok && execAliases[id.Name] {
					t.Errorf("%s: unguarded process spawn via alias %q (.%s)",
						rel, id.Name, fun.Sel.Name)
				}
			}
		case *ast.Ident:
			if execAliases[fun.Name] && len(call.Args) > 0 {
				binary = literalString(call.Args[0])
			}
		}

		if binary == "" {
			return true // not statically resolvable; guarded Exec is the norm
		}

		relPath, _ := filepath.Rel(root, path)
		if relPath == filepath.Join("internal", "guard", "guard.go") {
			return true // the guard package must construct the process
		}
		if _, ok := execExemptions[filepath.ToSlash(relPath)]; ok {
			return true
		}

		if !allowed[binary] {
			t.Errorf("%s: unguarded exec of %q — host mutation must go through internal/guard",
				rel, binary)
		}
		return true
	})

	return nil
}

// execExemptions are the files permitted to construct processes outside guard.
//
// Each entry is a deliberate exception, listed by path so that adding another
// is a visible diff rather than something a test happens not to catch. There
// is exactly one, and the reason is structural rather than procedural: the
// file cannot reach the host, because every command it runs is scoped to a
// network namespace created and destroyed inside a single call.
//
// Adding a second entry should be treated as a change to THN's central safety
// property, not as a routine refactor.
var execExemptions = map[string]string{
	"internal/netns/netns.go": "namespace test harness; every command is scoped to a " +
		"namespace created and destroyed within the call, so the host is unreachable",
}

// TestExecExemptionsAreJustified asserts every exemption names a file that
// exists and gives a reason.
//
// An exemption pointing at a deleted file, or carrying no explanation, is an
// exemption that has stopped meaning anything. Both are silent failures
// otherwise: the test above would keep passing long after the justification
// was no longer attached to anything.
func TestExecExemptionsAreJustified(t *testing.T) {
	root := moduleRoot(t)

	for path, reason := range execExemptions {
		if reason == "" {
			t.Errorf("exemption for %s has no reason; state why it is safe", path)
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); err != nil {
			t.Errorf("exemption names %s, which does not exist: %v", path, err)
		}
	}

	// The invariant has a small, closed set of exceptions. If that set grows,
	// it is a decision about THN's safety posture and belongs in a commit
	// message, not a quiet edit to a map.
	const wantExemptions = 1
	if len(execExemptions) != wantExemptions {
		names := make([]string, 0, len(execExemptions))
		for p := range execExemptions {
			names = append(names, p)
		}
		sort.Strings(names)
		t.Errorf("execExemptions has %d entries, want %d: %v\n"+
			"Adding an entry widens what THN can do outside guard. "+
			"That is a change to the project's central safety property.",
			len(execExemptions), wantExemptions, names)
	}
}

// isExecSelector reports whether expr is <pkg>.Command / <pkg>.CommandContext
// where pkg is an alias for os/exec.
func isExecSelector(expr ast.Expr, names ...string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	for _, n := range names {
		if sel.Sel.Name == n && ident.Name == "exec" {
			return true
		}
	}
	return false
}

// literalString extracts a constant string literal, returning "" when the
// expression is not one (a variable, concatenation, or function call).
func literalString(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

// moduleRoot locates the directory containing go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}
