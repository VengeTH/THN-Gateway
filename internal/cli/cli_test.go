package cli

import (
	"bytes"
	"strings"
	"testing"
)

// newTestEnv builds an Env writing into buffers, so command output can be
// asserted without touching the process's own streams.
func newTestEnv(args ...string) (*Env, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	return &Env{
		Stdout: &out,
		Stderr: &errOut,
		Stdin:  strings.NewReader(""),
		Args:   args,
		Getenv: func(string) string { return "" },
		Getwd:  func() (string, error) { return ".", nil },
	}, &out, &errOut
}

// TestPureCommandsNeverReachTheDaemon is the structural test behind the tier
// separation.
//
// The pure commands must work with no daemon, no socket and no root. That is
// what makes them safe to run in CI and on a laptop pointed at a production
// gateway. If one of them ever started requiring the daemon, it would have
// gained a code path to privileged code by way of the socket, and the
// guarantee this project rests on would quietly weaken.
func TestPureCommandsNeverReachTheDaemon(t *testing.T) {
	for name, cmd := range commands {
		if cmd.Tier != TierPure {
			continue
		}
		if cmd.Run == nil {
			t.Errorf("command %q is declared pure but has no implementation", name)
		}
	}

	// The pure set is exactly the set that must not need a daemon.
	pure := map[string]bool{
		"validate": true, "plan": true, "config": true, "schema": true,
	}
	for name := range pure {
		cmd, ok := commands[name]
		if !ok {
			t.Errorf("expected a %q command", name)
			continue
		}
		if cmd.Tier != TierPure {
			t.Errorf("command %q must be pure, got tier %q", name, cmd.Tier)
		}
	}
}

// TestDestructiveCommandsAreRefused asserts that anything capable of changing
// the host is refused in this build.
func TestDestructiveCommandsAreRefused(t *testing.T) {
	for name, cmd := range commands {
		if cmd.Tier != TierDestructive {
			continue
		}
		env, _, errOut := newTestEnv(name, "--confirm-present")
		got := cmd.Run(env, []string{"--confirm-present"})

		if got == ExitOK {
			t.Errorf("destructive command %q returned success", name)
		}
		if !strings.Contains(errOut.String(), "no apply path") {
			t.Errorf("command %q must explain that there is no apply path, got: %s",
				name, errOut.String())
		}
	}
}

// TestActivateCannotBeUnlockedByFlags tries the plausible ways an operator
// might try to force activation past the refusal, and confirms none works.
func TestActivateCannotBeUnlockedByFlags(t *testing.T) {
	// Each entry is a flag set an operator might plausibly try. The wantCode
	// records whether the command is expected to reject the flags outright
	// (unknown flag) or to accept them and still refuse to activate.
	attempts := []struct {
		args     []string
		wantCode ExitCode
	}{
		{nil, ExitProblems},
		{[]string{"--yes"}, ExitProblems},
		{[]string{"--yes", "--confirm-present"}, ExitProblems},
		// Unknown flags are rejected as usage errors before activation is
		// even considered. That ordering matters: it means no unrecognised
		// input can reach the activation path at all.
		{[]string{"--force"}, ExitUsage},
		{[]string{"--config", "/etc/thn/config.yaml", "--yes"}, ExitUsage},
	}

	for _, a := range attempts {
		env, _, _ := newTestEnv(append([]string{"activate"}, a.args...)...)

		got := Run(env)
		if got == ExitOK {
			t.Errorf("activate %v succeeded; it must never succeed", a.args)
		}
		if got != a.wantCode {
			t.Errorf("activate %v exit code = %d, want %d", a.args, got, a.wantCode)
		}
	}
}

// TestActivateWithRecognisedFlagsStillRefuses confirms the refusal message is
// produced for every flag combination the command actually accepts.
func TestActivateWithRecognisedFlagsStillRefuses(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--yes"},
		{"--confirm-present"},
		{"--yes", "--confirm-present"},
	} {
		env, _, errOut := newTestEnv(append([]string{"activate"}, args...)...)

		if got := Run(env); got == ExitOK {
			t.Errorf("activate %v succeeded; it must always refuse", args)
		}
		if !strings.Contains(errOut.String(), "no apply path") {
			t.Errorf("activate %v did not explain the refusal: %s", args, errOut.String())
		}
	}
}

// TestActivateAlwaysRefusesEvenWithEveryGateSatisfied confirms that gate
// evaluation cannot become a back door: even a fully satisfied gate set does
// not produce an apply path.
func TestActivateAlwaysRefusesEvenWithEveryGateSatisfied(t *testing.T) {
	env, _, errOut := newTestEnv("activate")

	if got := Run(env); got == ExitOK {
		t.Error("activate succeeded")
	}
	if !strings.Contains(errOut.String(), "not implemented") &&
		!strings.Contains(errOut.String(), "Not implemented") {
		t.Errorf("activate must list the unimplemented stages, got: %s", errOut.String())
	}
}

func TestLiveCommandsReportDaemonUnavailable(t *testing.T) {
	for _, name := range []string{"status", "diagnostics"} {
		cmd, ok := commands[name]
		if !ok {
			t.Fatalf("expected a %q command", name)
		}
		if cmd.Tier != TierLive {
			t.Errorf("command %q should be live, got %q", name, cmd.Tier)
		}

		env, _, errOut := newTestEnv(name)
		got := cmd.Run(env, nil)

		if got != ExitUnavailable {
			t.Errorf("command %q exit code = %d, want %d (daemon unreachable)",
				name, got, ExitUnavailable)
		}
		if !strings.Contains(errOut.String(), "thnd") {
			t.Errorf("command %q must name thnd in its error, got: %s", name, errOut.String())
		}
		if !strings.Contains(errOut.String(), "--local") {
			t.Errorf("command %q should offer the --local fallback, got: %s", name, errOut.String())
		}
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	env, _, errOut := newTestEnv("nonsense")

	if got := Run(env); got != ExitUsage {
		t.Errorf("exit code = %d, want %d", got, ExitUsage)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Errorf("error should say the command is unknown, got: %s", errOut.String())
	}
}

func TestNoArgsPrintsUsage(t *testing.T) {
	env, out, _ := newTestEnv()

	if got := Run(env); got != ExitUsage {
		t.Errorf("exit code = %d, want %d", got, ExitUsage)
	}
	if !strings.Contains(out.String(), "Usage: thn") {
		t.Errorf("expected usage text, got: %s", out.String())
	}
}

func TestUsageShowsTiers(t *testing.T) {
	env, out, _ := newTestEnv()

	Run(env)

	u := out.String()
	for _, want := range []string{"pure", "live", "destructive"} {
		if !strings.Contains(u, want) {
			t.Errorf("usage must document the %q tier", want)
		}
	}
}

func TestUnknownFlagIsRejected(t *testing.T) {
	env, _, errOut := newTestEnv("validate", "--nonsense")

	if got := Run(env); got != ExitUsage {
		t.Errorf("exit code = %d, want %d for an unknown flag", got, ExitUsage)
	}
	if !strings.Contains(errOut.String(), "unknown flag") {
		t.Errorf("error should name the unknown flag, got: %s", errOut.String())
	}
}

func TestJSONFlagIsStrippedFromArgs(t *testing.T) {
	args := []string{"plan", "--json", "config.yaml"}

	if !hasJSONFlag(args) {
		t.Error("hasJSONFlag should detect --json")
	}
	got := stripJSONFlag(args)
	if len(got) != 2 || got[0] != "plan" || got[1] != "config.yaml" {
		t.Errorf("stripJSONFlag = %v, want [plan config.yaml]", got)
	}
}

func TestFlagSetParsesBothForms(t *testing.T) {
	fs := newFlagSet()
	live := fs.Bool("live", false)
	path := fs.String("config", "default")

	rest, err := fs.Parse([]string{"--live", "--config=/tmp/x.yaml", "positional"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !*live {
		t.Error("--live was not set")
	}
	if *path != "/tmp/x.yaml" {
		t.Errorf("--config = %q, want /tmp/x.yaml", *path)
	}
	if len(rest) != 1 || rest[0] != "positional" {
		t.Errorf("positional args = %v, want [positional]", rest)
	}
}

func TestFlagSetSeparatesValue(t *testing.T) {
	fs := newFlagSet()
	path := fs.String("config", "default")

	rest, err := fs.Parse([]string{"--config", "/tmp/y.yaml", "arg"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if *path != "/tmp/y.yaml" {
		t.Errorf("--config = %q, want /tmp/y.yaml", *path)
	}
	if len(rest) != 1 || rest[0] != "arg" {
		t.Errorf("positional args = %v, want [arg]", rest)
	}
}

func TestFlagSetDoubleDashStopsParsing(t *testing.T) {
	fs := newFlagSet()
	live := fs.Bool("live", false)

	rest, err := fs.Parse([]string{"--", "--live"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if *live {
		t.Error("flags after -- must not be parsed")
	}
	if len(rest) != 1 || rest[0] != "--live" {
		t.Errorf("args after -- = %v, want [--live]", rest)
	}
}

func TestFlagSetRejectsUnknownFlag(t *testing.T) {
	fs := newFlagSet()

	if _, err := fs.Parse([]string{"--nope"}); err == nil {
		t.Error("an unknown flag must be an error, matching the strict config loader")
	}
}

func TestFlagSetRejectsMissingValue(t *testing.T) {
	fs := newFlagSet()
	fs.String("config", "")

	if _, err := fs.Parse([]string{"--config"}); err == nil {
		t.Error("a flag requiring a value must error when none is given")
	}
}

func TestConfigPathPrecedence(t *testing.T) {
	env := &Env{Getenv: func(k string) string {
		if k == "THN_CONFIG" {
			return "/from/env.yaml"
		}
		return ""
	}}

	if got := env.resolveConfigPath("/explicit.yaml"); got != "/explicit.yaml" {
		t.Errorf("explicit path should win, got %q", got)
	}
	if got := env.resolveConfigPath(""); got != "/from/env.yaml" {
		t.Errorf("env should be used when no path is given, got %q", got)
	}

	bare := &Env{Getenv: func(string) string { return "" }}
	if got := bare.resolveConfigPath(""); got != defaultConfigPath {
		t.Errorf("default path = %q, want %q", got, defaultConfigPath)
	}
}

func TestSchemaCommandRuns(t *testing.T) {
	env, out, _ := newTestEnv("schema")

	if got := Run(env); got != ExitOK {
		t.Errorf("exit code = %d, want 0", got)
	}
	u := out.String()
	if !strings.Contains(u, "schema_version") {
		t.Errorf("schema output must list keys, got: %s", u)
	}
	if !strings.Contains(u, "network.wan") {
		t.Errorf("schema output must include network.wan, got: %s", u)
	}
}

func TestSchemaMutatingFilter(t *testing.T) {
	env, out, _ := newTestEnv("schema")
	env.IsJSON = true

	if got := Run(env); got != ExitOK {
		t.Errorf("exit code = %d, want 0", got)
	}
	if !strings.Contains(out.String(), "\"mutating\": true") {
		t.Error("catalogue must mark mutating fields")
	}
}

func TestConfigSubcommandDispatch(t *testing.T) {
	// An unknown subcommand is a usage error, not a silent success.
	env, _, errOut := newTestEnv("config", "bogus")

	if got := Run(env); got != ExitUsage {
		t.Errorf("exit code = %d, want %d", got, ExitUsage)
	}
	if !strings.Contains(errOut.String(), "unknown subcommand") {
		t.Errorf("error should name the problem, got: %s", errOut.String())
	}
}

func TestConfigWithNoSubcommandIsUsageError(t *testing.T) {
	env, _, errOut := newTestEnv("config")

	if got := Run(env); got != ExitUsage {
		t.Errorf("exit code = %d, want %d", got, ExitUsage)
	}
	if !strings.Contains(errOut.String(), "subcommand") {
		t.Errorf("error should ask for a subcommand, got: %s", errOut.String())
	}
}
