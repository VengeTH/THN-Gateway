// Package cli implements the thn command line interface.
//
// # Command tiers
//
// Commands are grouped by what they need, and the grouping is a safety
// property rather than a documentation convenience:
//
//	Pure         validate, plan, config show. Run in-process. No daemon, no
//	             root, no network mutation. These work in CI and offline.
//	Live         status, diagnostics. Ask thnd, because they report the real
//	             gateway state, which only the daemon's own observation can.
//	Destructive  activate. Refused in this build; see internal/activation.
//
// The separation exists because THN is developed remotely against an
// unattended device. Running `thn validate` or `thn plan` must be incapable
// of changing the gateway, whatever the configuration says. Because those
// commands never construct an activation context and never touch a socket,
// there is no code path from them to a privileged operation.
//
// # Exit codes
//
// Exit codes are part of the interface, because CI reads them:
//
//	0  success
//	1  the operation found problems (invalid config, blocked plan)
//	2  usage error
//	3  the daemon could not be reached
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ExitCode is a process exit status.
type ExitCode int

const (
	// ExitOK indicates success.
	ExitOK ExitCode = 0
	// ExitProblems indicates the operation completed but found problems.
	// This is distinct from a usage error so that CI can gate on it.
	ExitProblems ExitCode = 1
	// ExitUsage indicates the command line was wrong.
	ExitUsage ExitCode = 2
	// ExitUnavailable indicates the daemon could not be reached.
	ExitUnavailable ExitCode = 3
)

// Tier classifies a command by what it needs.
type Tier string

const (
	// TierPure commands run in-process with no daemon.
	TierPure Tier = "pure"
	// TierLive commands require the daemon.
	TierLive Tier = "live"
	// TierDestructive commands change host networking and are refused.
	TierDestructive Tier = "destructive"
)

// Command is one CLI verb.
type Command struct {
	// Name is the verb as typed.
	Name string
	// Tier classifies what the command needs.
	Tier Tier
	// Summary is the one-line description shown in help.
	Summary string
	// Run executes the command.
	Run func(*Env, []string) ExitCode
}

// Env carries the process environment a command runs in.
//
// Commands take their streams from Env rather than from the os package so
// that output can be captured in tests without redirecting global state.
type Env struct {
	// Stdout receives normal output.
	Stdout io.Writer
	// Stderr receives errors and diagnostics.
	Stderr io.Writer
	// Stdin receives piped input.
	Stdin io.Reader
	// Args are the arguments after the verb.
	Args []string
	// Getenv reads an environment variable.
	Getenv func(string) string
	// Getwd returns the working directory.
	Getwd func() (string, error)
	// IsJSON requests machine-readable output.
	IsJSON bool
}

// NewEnv builds an Env bound to the real process.
func NewEnv(args []string) *Env {
	return &Env{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Stdin:  os.Stdin,
		Args:   args,
		Getenv: os.Getenv,
		Getwd:  os.Getwd,
	}
}

// OutputFormat is a rendering mode for structured results.
type OutputFormat string

const (
	// FormatText renders for a human reading a terminal.
	FormatText OutputFormat = "text"
	// FormatJSON renders machine-readable JSON.
	FormatJSON OutputFormat = "json"
)

// printJSON writes an indented JSON document.
func (e *Env) printJSON(v any) error {
	enc := json.NewEncoder(e.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printf writes formatted output to stdout.
func (e *Env) printf(format string, args ...any) {
	fmt.Fprintf(e.Stdout, format, args...)
}

// errorf writes to stderr.
func (e *Env) errorf(format string, args ...any) {
	fmt.Fprintf(e.Stderr, format, args...)
}

// fatalf writes an error to stderr and returns the usage exit code.
func (e *Env) fatalf(format string, args ...any) ExitCode {
	fmt.Fprintf(e.Stderr, format, args...)
	return ExitUsage
}

// flagSet is a tiny flag parser.
//
// The CLI has a handful of boolean flags and no configuration files of its
// own, so a dependency on a flag-parsing library would buy nothing. Unknown
// flags are rejected rather than ignored, consistent with the strictness the
// configuration loader applies to the document itself.
type flagSet struct {
	bools   map[string]*bool
	strings map[string]*string
	seen    map[string]bool
}

// newFlagSet creates an empty flag set.
func newFlagSet() *flagSet {
	return &flagSet{
		bools:   map[string]*bool{},
		strings: map[string]*string{},
		seen:    map[string]bool{},
	}
}

// Bool registers a boolean flag and returns a pointer to its value.
func (f *flagSet) Bool(name string, def bool) *bool {
	v := new(bool)
	*v = def
	f.bools[name] = v
	return v
}

// String registers a string flag and returns a pointer to its value.
func (f *flagSet) String(name, def string) *string {
	v := new(string)
	*v = def
	f.strings[name] = v
	return v
}

// Parse consumes flags from args and returns the remaining positional
// arguments.
//
// Both "--name value" and "--name=value" are accepted. A bare "--" stops flag
// parsing, which lets a future command pass through arguments that begin with
// a dash.
func (f *flagSet) Parse(args []string) ([]string, error) {
	var positional []string

	for i := 0; i < len(args); i++ {
		a := args[i]

		if a == "--" {
			positional = append(positional, args[i+1:]...)
			return positional, nil
		}

		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}

		name := strings.TrimLeft(a, "-")
		value := ""
		hasInline := false
		if idx := strings.Index(name, "="); idx >= 0 {
			name, value, hasInline = name[:idx], name[idx+1:], true
		}

		if p, ok := f.bools[name]; ok {
			if hasInline {
				switch value {
				case "true", "1":
					*p = true
				case "false", "0":
					*p = false
				default:
					return nil, fmt.Errorf("flag --%s expects true or false, got %q", name, value)
				}
			} else {
				*p = true
			}
			f.seen[name] = true
			continue
		}

		if p, ok := f.strings[name]; ok {
			if !hasInline {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("flag --%s requires a value", name)
				}
				i++
				value = args[i]
			}
			*p = value
			f.seen[name] = true
			continue
		}

		return nil, fmt.Errorf("unknown flag --%s", name)
	}

	return positional, nil
}

// Seen reports whether a flag was provided explicitly.
func (f *flagSet) Seen(name string) bool { return f.seen[name] }

// resolveConfigPath determines which configuration file to load.
//
// Precedence is: an explicit --config flag, then THN_CONFIG, then the default
// path. An explicit argument wins over the environment because a person
// typing a path is more deliberate than a shell left over from earlier.
func (e *Env) resolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := e.Getenv("THN_CONFIG"); v != "" {
		return v
	}
	return defaultConfigPath
}

// defaultConfigPath mirrors the compiled default. It is duplicated as a
// constant rather than imported from internal/config so that the CLI's
// no-dependency-startup property is preserved; the config package asserts in
// its own tests that the two agree.
const defaultConfigPath = "/etc/thn/config.yaml"
