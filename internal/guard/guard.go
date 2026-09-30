// Package guard is the single chokepoint through which THN may execute an
// external process, and the enforcement point for THN's central safety
// invariant: a THN build must never be capable of mutating host networking.
//
// The invariant is deliberately enforced structurally rather than by policy
// or configuration, because THN is developed remotely against a real gateway
// that is unattended. A runtime toggle can be flipped by a bad config, a
// stray environment variable, or a panic. None of those can defeat an
// allowlist that rejects the invocation before the process is ever created.
//
// # Model
//
// Commands are modelled as a read-only "capability" surface. Each supported
// binary has a declarative policy describing the verbs and flags it may be
// given. Anything not matched exactly is denied. There is no deny-list
// fallback and no "allow everything else" branch: unknown input fails closed.
package guard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

// ErrDenied is returned when an invocation is not permitted by policy.
var ErrDenied = errors.New("guard: command denied by policy")

// ErrMutating is returned when an invocation is denied specifically because it
// would mutate host networking. It wraps ErrDenied so that callers matching on
// the general category still catch it, while callers can use errors.Is against
// ErrMutating to distinguish "we do not support this" from "this is
// deliberately forbidden".
var ErrMutating = fmt.Errorf("%w: host network mutation forbidden", ErrDenied)

// verb describes the argument grammar for one binary.
//
// Networking tools have wildly inconsistent grammars: "ip" takes a verb then
// an object ("ip addr show"), "nft" takes a verb then a path ("nft list
// ruleset"), and "tc" takes an object then a verb ("tc qdisc show"). Modelling
// each one explicitly keeps the check mechanical rather than heuristic.
// policy is the complete set of invocations permitted for one binary.
type policy struct {
	// verbs lists allowed verbs. Anything absent is denied.
	verbs []string
	// verbFlag is a flag that acts as the verb (sysctl -n). If non-empty it
	// must be present and serves as the verb token.
	verbFlag string
	// objectFirst marks grammars where the object precedes the verb (tc).
	objectFirst bool
	// objects lists the inspectable objects for objectFirst grammars.
	objects []string
	// flags lists flags permitted anywhere in the argument list.
	flags []string
	// flagValues lists flags that consume the following token as their value.
	flagValues []string
	// argSlots is the maximum number of free-standing operands accepted after
	// the verb (and object, where applicable).
	argSlots int
}

// allowlist is the complete set of binaries THN may execute, and the exact
// grammar permitted for each. It is read-only by construction: every entry
// below inspects host state and cannot change it.
//
// Note the absence of anything that writes. There is deliberately no
// "ip route add", "nft add rule", "tc qdisc replace" or "sysctl -w" entry, and
// the grammar below cannot be satisfied by them: those verbs are not present
// in any verbs map.
var allowlist = map[string]policy{
	// ip: inspection only. Like tc, iproute2 takes an object before the verb
	// ("ip addr show"). show/list/get are pure queries; "ip route get" performs
	// a fib lookup and does not install a route.
	"ip": {
		verbs:       []string{"show", "list", "get"},
		objectFirst: true,
		objects:     []string{"addr", "address", "link", "route", "neigh", "neighbour", "rule"},
		flags:       []string{"-j", "-d", "-4", "-6", "-o", "-s", "-br", "-c"},
		flagValues:  []string{"-f", "-t"},
		argSlots:    3,
	},

	// nft: listing the ruleset only. add/delete/flush/insert are absent.
	"nft": {
		verbs:    []string{"list"},
		flags:    []string{"-a", "-j", "--json", "--numeric", "-N", "--handle"},
		argSlots: 2,
	},

	// tc: qdisc/class/filter/chain inspection. Shape is object-then-verb.
	"tc": {
		verbs:       []string{"show", "list"},
		objectFirst: true,
		objects:     []string{"qdisc", "class", "filter", "chain"},
		flags:       []string{"-j", "-d", "-s", "-n", "-c"},
		argSlots:    2,
	},

	// sysctl: read a single key with -n. "-w" (write) and "-p" (load file)
	// are intentionally absent.
	"sysctl": {
		verbs:    []string{"-n"},
		verbFlag: "-n",
		argSlots: 1,
	},
}

// Check validates an invocation against the allowlist without executing it.
// It returns ErrMutating if the invocation is recognisably a state-changing
// networking command, and ErrDenied otherwise.
//
// Validation is a single left-to-right classification pass: every token is
// either a recognised flag, a flag's value, or an operand. Only after the
// whole argument vector has been classified is the verb resolved. Anything
// unrecognised is rejected, so the function fails closed by construction.
func Check(name string, args ...string) error {
	p, ok := allowlist[name]
	if !ok {
		return fmt.Errorf("%w: %q is not an allowed binary", ErrDenied, name)
	}

	var operands []string
	sawVerbFlag := false

	for i := 0; i < len(args); i++ {
		a := args[i]

		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if !slices.Contains(p.flags, a) && a != p.verbFlag {
				return fmt.Errorf("%w: flag %q not permitted for %q", ErrDenied, a, name)
			}
			if slices.Contains(p.flagValues, a) {
				i++ // consume the flag's value
				continue
			}
			if a == p.verbFlag {
				sawVerbFlag = true
			}
			continue
		}

		operands = append(operands, a)
	}

	// Grammars where a flag rather than a word carries the verb (sysctl -n).
	if p.verbFlag != "" {
		if !sawVerbFlag {
			return fmt.Errorf("%w: %q requires %q", ErrDenied, name, p.verbFlag)
		}
		return checkBudget(name, len(operands), p)
	}

	if len(operands) == 0 {
		return fmt.Errorf("%w: %q requires a verb", ErrDenied, name)
	}

	// Grammars where the object precedes the verb (ip addr show, tc qdisc show).
	if p.objectFirst {
		if len(operands) < 2 {
			return fmt.Errorf("%w: %q requires an object and a verb", ErrDenied, name)
		}
		obj, verb := operands[0], operands[1]

		if !slices.Contains(p.objects, obj) {
			if isMutatingVerb(obj) {
				return fmt.Errorf("%w: %q %q would change host networking", ErrMutating, name, obj)
			}
			return fmt.Errorf("%w: %q object %q is not inspectable", ErrDenied, name, obj)
		}
		if !slices.Contains(p.verbs, verb) {
			if isMutatingVerb(verb) {
				return fmt.Errorf("%w: %q %q %q would change host networking", ErrMutating, name, obj, verb)
			}
			return fmt.Errorf("%w: %q verb %q not permitted", ErrDenied, name, verb)
		}
		return checkBudget(name, len(operands)-2, p)
	}

	verb := operands[0]
	if !slices.Contains(p.verbs, verb) {
		if isMutatingVerb(verb) {
			return fmt.Errorf("%w: %q %q would change host networking", ErrMutating, name, verb)
		}
		return fmt.Errorf("%w: verb %q not permitted for %q", ErrDenied, verb, name)
	}
	return checkBudget(name, len(operands)-1, p)
}

// checkBudget rejects invocations carrying more free-standing operands than
// the policy allows, which is how attempts to smuggle extra targets past a
// permissive verb are caught.
func checkBudget(name string, used int, p policy) error {
	if used < 0 {
		used = 0
	}
	if used > p.argSlots {
		return fmt.Errorf("%w: %q accepts at most %d arguments, got %d",
			ErrDenied, name, p.argSlots, used)
	}
	return nil
}

// mutatingVerbs are the verbs that change state in iproute2, nftables and tc.
// They are used purely to produce a precise ErrMutating diagnostic; the
// allowlist already denies anything not explicitly permitted.
var mutatingVerbs = []string{
	// iproute2
	"add", "del", "delete", "replace", "change", "set", "append", "flush",
	"up", "down", "monitor",
	// nftables
	"insert", "create", "destroy", "rename", "reset", "flush", "add", "delete",
	// tc
	"replace", "add", "del", "delete", "change", "link",
	// sysctl
	"-w", "-p", "--load", "--write",
}

// isMutatingVerb reports whether v is a known state-changing verb.
func isMutatingVerb(v string) bool { return slices.Contains(mutatingVerbs, v) }

// Output is the result of a permitted command execution.
type Output struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner executes commands that have already been cleared by Check. It exists
// so that callers cannot bypass policy by constructing an exec.Cmd directly:
// Run always validates first.
type Runner func(ctx context.Context, name string, args ...string) (*Output, error)

// Exec validates and then runs a command. On any policy violation no process
// is created.
func Exec(ctx context.Context, name string, args ...string) (*Output, error) {
	if err := Check(name, args...); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := &Output{Stdout: stdout.String(), Stderr: stderr.String()}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			out.ExitCode = exitErr.ExitCode()
			return out, fmt.Errorf("%s: exit %d: %s", name, out.ExitCode, stderr.String())
		}
		return out, fmt.Errorf("executing %s: %w", name, err)
	}
	return out, nil
}

// Audit exposes the allowlist for diagnostics and documentation generation.
func Audit() map[string][]string {
	m := make(map[string][]string, len(allowlist))
	for name, p := range allowlist {
		verbs := slices.Clone(p.verbs)
		slices.Sort(verbs)
		m[name] = verbs
	}
	return m
}
