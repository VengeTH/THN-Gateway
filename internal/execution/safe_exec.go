package execution

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
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
	if len(args) < 2 {
		return fmt.Errorf("ip requires at least subsystem and action")
	}

	subsystem := args[0]
	switch subsystem {
	case "-j", "-br", "-d", "-o", "-4", "-6":
		// Flag prefix; subsystem is next token
		if len(args) > 1 {
			subsystem = args[1]
		}
	}

	switch subsystem {
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
		return fmt.Errorf("unsupported ip subsystem %q", subsystem)
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

func validateTCArgs(args []string) error {
	// tc qdisc replace/del/show dev <iface> ...
	if len(args) < 2 {
		return fmt.Errorf("tc requires at least object and action")
	}
	return nil
}
