package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strings"
)

// Allowed networking binaries for structured operations.
var allowedBinaries = []string{"ip", "nft", "sysctl", "tc"}

// ErrDisallowedCommand is returned when a command is rejected by safety validation.
var ErrDisallowedCommand = errors.New("execution: command rejected by safety policy")

// CommandRunner abstracts process execution for networking drivers.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout string, stderr string, err error)
	LookPath(file string) (string, error)
}

// DefaultCommandRunner executes permitted networking binaries via os/exec.
type DefaultCommandRunner struct{}

func NewDefaultCommandRunner() *DefaultCommandRunner {
	return &DefaultCommandRunner{}
}

func (r *DefaultCommandRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (r *DefaultCommandRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if err := ValidateCommand(name, args...); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrDisallowedCommand, err)
	}

	var cmd *exec.Cmd
	switch name {
	case "ip":
		cmd = exec.CommandContext(ctx, "ip", args...)
	case "nft":
		cmd = exec.CommandContext(ctx, "nft", args...)
	case "sysctl":
		cmd = exec.CommandContext(ctx, "sysctl", args...)
	case "tc":
		cmd = exec.CommandContext(ctx, "tc", args...)
	default:
		return "", "", fmt.Errorf("%w: %q is not an authorized binary", ErrDisallowedCommand, name)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	outStr := stdout.String()
	errStr := stderr.String()

	if err != nil {
		return outStr, errStr, fmt.Errorf("%s %s failed: %w (stderr: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(errStr))
	}

	return outStr, errStr, nil
}

// ValidateCommand enforces structured parameter safety without shell interpretation.
func ValidateCommand(name string, args ...string) error {
	if !slices.Contains(allowedBinaries, name) {
		return fmt.Errorf("binary %q is not permitted", name)
	}

	if len(args) == 0 {
		return fmt.Errorf("command %q requires arguments", name)
	}

	// Reject dangerous shell metacharacters across all arguments.
	for _, arg := range args {
		if err := validateNoShellMetachars(arg); err != nil {
			return err
		}
	}

	switch name {
	case "ip":
		return validateIPArgs(args)
	case "nft":
		return validateNFTArgs(args)
	case "sysctl":
		return validateSysctlArgs(args)
	case "tc":
		return validateTCArgs(args)
	}

	return nil
}

func validateNoShellMetachars(arg string) error {
	for _, ch := range []string{";", "&", "|", "$", "`", "<", ">", "\n", "\r", "\x00"} {
		// Semicolon is permitted only if the argument is exactly ";" (nft statement delimiter token)
		if ch == ";" && arg == ";" {
			continue
		}
		if strings.Contains(arg, ch) {
			return fmt.Errorf("dangerous shell character %q in argument %q", ch, arg)
		}
	}
	return nil
}

func validateIPArgs(args []string) error {
	// A leading run of flags precedes the subsystem. `ip -j -d link show` is a
	// read-only inspection that the guard allowlist permits outright, so a
	// validator that stopped at the first flag would refuse a command the
	// rest of THN considers safe — and the caller would have no way to tell
	// that from a malformed command.
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		i++
	}
	if i >= len(args) {
		return fmt.Errorf("ip requires a subsystem after its flags")
	}

	switch args[i] {
	case "link":
		// ip link set <dev> up|down, or ip link show
		return nil
	case "addr", "address":
		// ip addr add/del/show
		return nil
	case "route":
		// ip route add/replace/del/show
		return nil
	default:
		return fmt.Errorf("unsupported ip subsystem %q", args[i])
	}
}

func validateNFTArgs(args []string) error {
	// THN only operates on table inet thn.
	// Reject any attempt to flush ruleset or operate on other tables!
	joined := strings.Join(args, " ")

	if strings.Contains(joined, "flush ruleset") {
		return fmt.Errorf("nft flush ruleset is forbidden; THN may only manage table inet thn")
	}

	// Listing can be ruleset or table
	if args[0] == "list" || (len(args) > 1 && (args[0] == "-j" || args[0] == "--json") && args[1] == "list") {
		return nil
	}

	// Any mutating nft command must explicitly reference inet thn
	if !strings.Contains(joined, "inet thn") && !strings.Contains(joined, "table inet thn") {
		return fmt.Errorf("nft command %q does not target inet thn; foreign tables are forbidden", joined)
	}

	return nil
}

func validateSysctlArgs(args []string) error {
	// Inspection: -n net.ipv4.ip_forward
	if args[0] == "-n" {
		if len(args) != 2 {
			return fmt.Errorf("sysctl -n requires exactly one key")
		}
		return nil
	}

	// Mutation: -w net.ipv4.ip_forward=1
	if args[0] == "-w" {
		if len(args) != 2 {
			return fmt.Errorf("sysctl -w requires key=val")
		}
		kv := strings.Split(args[1], "=")
		if len(kv) != 2 {
			return fmt.Errorf("sysctl -w requires key=val format")
		}
		key := kv[0]
		if key != "net.ipv4.ip_forward" && key != "net.ipv6.conf.all.forwarding" {
			return fmt.Errorf("sysctl key %q not permitted", key)
		}
		val := kv[1]
		if val != "0" && val != "1" {
			return fmt.Errorf("sysctl value %q not permitted (only 0 or 1)", val)
		}
		return nil
	}

	return fmt.Errorf("unsupported sysctl arguments %v", args)
}

// validateTCArgs enforces the tc grammar structurally.
//
// # Why this is now a grammar check and not a length check
//
// It used to be:
//
//	if len(args) < 2 { return fmt.Errorf("tc requires at least object and action") }
//	return nil
//
// which accepts anything of sufficient length, including commands this file's
// callers never intended to be constructible. The allowlist's job on the write
// path is not to be exhaustive — a new caller will want verbs that do not
// exist yet — it is to make the shapes that are dangerous impossible to spell
// by accident.
//
// # The three rules
//
//  1. The object must be one of qdisc, class, filter, classmap, chain, mangle.
//  2. The verb must be a known tc verb. Unknown verbs are refused rather
//     than passed through, because a typo in a verb produces a command that
//     fails at the kernel with a message that names neither the typo nor THN.
//  3. A qdisc/class/filter that acts must name a device, and the device must
//     look like a device name.
//
// # What this does not do
//
// It does not enumerate every tc verb, and it is not a general tc grammar.
// It refuses the shapes that mutate more than the operation asked for and
// lets the structured Operation types carry the intent. The write path is
// reached only through OpQDiscApply, OpQDiscReplace and OpQDiscDelete, which
// build their own arguments; this function is the backstop for the case where
// one of those is wrong.
func validateTCArgs(args []string) error {
	// A leading run of flags precedes the object, exactly as with `ip`. tc
	// takes its inspection flags the same way (`tc -j -s qdisc show dev eth0`
	// is what the statistics path issues), so reading args[0] as the object
	// turned `-j` into an "unsupported tc object" refusal for a read-only
	// query the guard allowlist permits.
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		i++
	}
	args = args[i:]

	if len(args) < 2 {
		return fmt.Errorf("tc requires at least an object and a verb")
	}

	obj := args[0]
	switch obj {
	case "qdisc", "class", "filter", "classmap", "chain", "mangle":
	default:
		return fmt.Errorf("unsupported tc object %q; permitted: qdisc, class, filter, "+
			"classmap, chain, mangle", obj)
	}

	verb := args[1]
	switch verb {
	case "add", "replace", "del", "delete", "change", "show", "list":
	default:
		return fmt.Errorf("unsupported tc verb %q for object %q", verb, obj)
	}

	// Every acting verb names a device. A `tc qdisc replace` without one has
	// no target, which the kernel resolves against nothing and which would
	// read as a successful no-op.
	if verb != "show" && verb != "list" {
		dev := ""
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "dev" {
				dev = args[i+1]
				break
			}
		}
		if dev == "" {
			return fmt.Errorf("tc %s %s names no device", obj, verb)
		}
		if !ifaceRegex.MatchString(dev) {
			return fmt.Errorf("tc %s %s names an invalid device %q", obj, verb, dev)
		}
	}

	// A qdisc that attaches a discipline must state which kind it is
	// installing. Without a kind, tc rejects it — and the rejection is the
	// only thing standing between this and an unshaped discipline, so it is
	// checked here where the error can name the cause.
	//
	// Only the verbs that install are subject to this. del and delete remove a
	// discipline and show and list only read, so none of them can leave an
	// interface unshaped, and all of them legitimately name no root or parent.
	// Demanding a kind of those verbs refused `tc qdisc show`, which is the
	// probe DetectCapabilities issues to decide whether tc exists; the driver
	// then reported every host as lacking tc and blocked every QoS plan with a
	// message naming a missing package instead of the command THN had refused.
	if obj == "qdisc" && tcInstallsDiscipline(verb) {
		kind := ""
		for i := 0; i < len(args); i++ {
			if args[i] == "root" {
				// root [handle <h>] <kind> OR root <kind>
				if i+1 < len(args) {
					if args[i+1] == "handle" && i+3 < len(args) {
						kind = args[i+3]
						break
					} else if args[i+1] != "handle" {
						kind = args[i+1]
						break
					}
				}
			}
			if args[i] == "parent" {
				// parent <parent_id> [handle <h>] <kind> OR parent <parent_id> <kind>
				if i+2 < len(args) {
					if args[i+2] == "handle" && i+4 < len(args) {
						kind = args[i+4]
						break
					} else if args[i+2] != "handle" {
						kind = args[i+2]
						break
					}
				}
			}
		}
		if kind == "" {
			return fmt.Errorf("tc %s %s names neither a root nor a parent qdisc kind; "+
				"an unshaped discipline would install successfully and report success", obj, verb)
		}
		if !tcQdiscKind.MatchString(kind) {
			return fmt.Errorf("unsupported qdisc kind %q", kind)
		}
	}

	return nil
}

// tcQdiscKind matches a discipline name tc recognises.
//
// A conservative set rather than a pattern: an unknown kind is refused here
// rather than reaching the kernel, and refusing is the correct outcome for a
// name this build has no reason to believe in.
var tcQdiscKind = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// tcInstallsDiscipline reports whether a tc verb attaches a qdisc to a device.
//
// add, replace and change install one, so each must name the kind it installs;
// that is the only way `tc qdisc replace dev eth0 root` can be caught before
// the kernel reports success on an interface it left unshaped. del and delete
// remove, and show and list read. Those verbs name no kind, and requiring one
// of them is what made the read-only capability probe unusable.
func tcInstallsDiscipline(verb string) bool {
	switch verb {
	case "add", "replace", "change":
		return true
	default:
		return false
	}
}
