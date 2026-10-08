package main

// Tests for thnd's argument and path resolution.
//
// The bug this file exists for: the daemon resolved its socket and state
// database from two hardcoded constants plus THN_SOCKET/THN_STATE_DB, and read
// the configuration file only for the shaping interface. An operator who set
// `paths.socket` in /etc/thn/config.yaml got a daemon listening on the default
// path and a `thn status` looking at the configured one, so the two binaries
// disagreed and the daemon could never be reached. Everything here exists to
// keep the daemon and the CLI resolving the same path by the same rules.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/daemon"
)

// hermetic removes the THN_* overrides so a developer's exported shell does
// not decide what these tests see. Empty counts as unset to the loader.
func hermetic(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"THN_SOCKET", "THN_STATE_DB", "THN_CONFIG",
		"THN_RUN_DIR", "THN_LOG_LEVEL", "THN_LOG_FORMAT", "THN_LOG_FILE",
		"THN_WAN", "THN_LAN",
	} {
		t.Setenv(k, "")
	}
}

// writeConfig writes a configuration document and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// --------------------------------------------------- path resolution

// With nothing said anywhere, the compiled defaults apply — and they come from
// internal/config rather than being restated here, so there is one definition.
func TestDefaultsComeFromTheConfigPackage(t *testing.T) {
	hermetic(t)

	cfg, _, _, err := parseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}

	want := config.Defaults()
	if cfg.Socket != want.Paths.Socket {
		t.Errorf("socket = %q, want the compiled default %q", cfg.Socket, want.Paths.Socket)
	}
	if cfg.StateDB != want.Paths.StateDB {
		t.Errorf("state db = %q, want the compiled default %q", cfg.StateDB, want.Paths.StateDB)
	}
}

// The defect itself: the configuration file names the socket, and the daemon
// must listen there.
func TestTheConfigurationFileSelectsTheSocket(t *testing.T) {
	hermetic(t)
	dir := t.TempDir()
	sock := filepath.ToSlash(filepath.Join(dir, "from-config.sock"))
	db := filepath.ToSlash(filepath.Join(dir, "config", "state.db"))

	path := writeConfig(t, "schema_version: 1\npaths:\n  socket: "+sock+"\n  state_db: "+db+"\n")
	t.Setenv("THN_CONFIG", path)

	cfg, _, _, err := parseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Socket != sock {
		t.Errorf("socket = %q, want %q from the configuration", cfg.Socket, sock)
	}
	if cfg.StateDB != db {
		t.Errorf("state db = %q, want %q from the configuration", cfg.StateDB, db)
	}
}

// The whole precedence order, in one place: flag beats environment beats file
// beats default. If this ever changes, the CLI has to change with it.
func TestPathPrecedenceIsFlagThenEnvironmentThenFile(t *testing.T) {
	hermetic(t)
	dir := t.TempDir()
	fromConfig := filepath.ToSlash(filepath.Join(dir, "config.sock"))
	fromEnv := filepath.ToSlash(filepath.Join(dir, "env.sock"))
	fromFlag := filepath.ToSlash(filepath.Join(dir, "flag.sock"))

	path := writeConfig(t, "schema_version: 1\npaths:\n  socket: "+fromConfig+"\n")
	t.Setenv("THN_CONFIG", path)

	// File only.
	cfg, _, _, err := parseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Socket != fromConfig {
		t.Fatalf("socket = %q, want the configured %q", cfg.Socket, fromConfig)
	}

	// Environment beats the file.
	t.Setenv("THN_SOCKET", fromEnv)
	cfg, _, _, err = parseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Socket != fromEnv {
		t.Fatalf("socket = %q, want the environment value %q", cfg.Socket, fromEnv)
	}

	// Flag beats the environment.
	cfg, _, _, err = parseArgs([]string{"--socket", fromFlag})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Socket != fromFlag {
		t.Fatalf("socket = %q, want the flag value %q", cfg.Socket, fromFlag)
	}
}

// The same ordering for the state database.
func TestStateDBPrecedenceMatchesTheSocket(t *testing.T) {
	hermetic(t)
	dir := t.TempDir()
	fromConfig := filepath.ToSlash(filepath.Join(dir, "config.db"))
	fromEnv := filepath.ToSlash(filepath.Join(dir, "env.db"))
	fromFlag := filepath.ToSlash(filepath.Join(dir, "flag.db"))

	path := writeConfig(t, "schema_version: 1\npaths:\n  state_db: "+fromConfig+"\n")
	t.Setenv("THN_CONFIG", path)

	cfg, _, _, err := parseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDB != fromConfig {
		t.Fatalf("state db = %q, want %q", cfg.StateDB, fromConfig)
	}

	t.Setenv("THN_STATE_DB", fromEnv)
	cfg, _, _, err = parseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDB != fromEnv {
		t.Fatalf("state db = %q, want %q", cfg.StateDB, fromEnv)
	}

	cfg, _, _, err = parseArgs([]string{"--state-db", fromFlag})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDB != fromFlag {
		t.Fatalf("state db = %q, want %q", cfg.StateDB, fromFlag)
	}
}

// The shaping interface still comes from the configuration. It did before this
// change, and losing it would be a regression in exchange for a fix.
func TestTheShapingInterfaceStillComesFromTheConfiguration(t *testing.T) {
	hermetic(t)
	path := writeConfig(t, "schema_version: 1\nqos:\n  enabled: true\n  interface: enp0s31f6\n")
	t.Setenv("THN_CONFIG", path)

	cfg, _, _, err := parseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QoSInterface != "enp0s31f6" {
		t.Errorf("shaping interface = %q, want enp0s31f6", cfg.QoSInterface)
	}
}

// A daemon that will not start is a gateway nobody can ask anything, so an
// unreadable configuration is reported and then stepped over — it must never be
// the reason the process dies, and it must never silently produce empty paths.
func TestAnUnreadableConfigurationFallsBackWithoutLosingTheEnvironment(t *testing.T) {
	hermetic(t)
	envSock := filepath.ToSlash(filepath.Join(t.TempDir(), "from-env.sock"))

	t.Setenv("THN_CONFIG", filepath.Join(t.TempDir(), "does-not-exist", "config.yaml"))
	t.Setenv("THN_SOCKET", envSock)

	cfg, _, _, err := parseArgs(nil)
	if err != nil {
		t.Fatalf("a missing configuration file must not stop the daemon: %v", err)
	}
	if cfg.Socket != envSock {
		t.Errorf("socket = %q, want the environment value %q to survive the fallback", cfg.Socket, envSock)
	}
	if cfg.Socket == "" || cfg.StateDB == "" {
		t.Errorf("the fallback left a path empty: socket %q state db %q", cfg.Socket, cfg.StateDB)
	}
}

// Malformed YAML is handled the same way: reported, then stepped over.
func TestAMalformedConfigurationDoesNotStopTheDaemon(t *testing.T) {
	hermetic(t)
	path := writeConfig(t, "network:\n  wan: [unclosed\n\tbad: :\n")
	t.Setenv("THN_CONFIG", path)

	cfg, _, _, err := parseArgs(nil)
	if err != nil {
		t.Fatalf("a malformed configuration must not stop the daemon: %v", err)
	}
	if cfg.Socket == "" {
		t.Error("the fallback produced an empty socket path")
	}
}

// ----------------------------------------------------------- arguments

func TestNoStateDisablesPersistence(t *testing.T) {
	hermetic(t)
	path := writeConfig(t, "schema_version: 1\npaths:\n  state_db: /somewhere/state.db\n")
	t.Setenv("THN_CONFIG", path)

	cfg, _, _, err := parseArgs([]string{"--no-state"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDB != "" {
		t.Errorf("state db = %q, want it disabled", cfg.StateDB)
	}
}

func TestTheIntervalFlagIsParsed(t *testing.T) {
	hermetic(t)

	cfg, _, _, err := parseArgs([]string{"--interval", "90s"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interval.String() != "1m30s" {
		t.Errorf("interval = %s, want 1m30s", cfg.Interval)
	}
}

func TestAnUnparseableIntervalIsRejected(t *testing.T) {
	hermetic(t)

	if _, _, _, err := parseArgs([]string{"--interval", "soon"}); err == nil {
		t.Error("an unparseable interval was accepted")
	}
}

func TestAFlagMissingItsValueIsRejected(t *testing.T) {
	hermetic(t)

	if _, _, _, err := parseArgs([]string{"--socket"}); err == nil {
		t.Error("--socket with no value was accepted")
	}
}

func TestAnUnknownFlagIsRejected(t *testing.T) {
	hermetic(t)

	if _, _, _, err := parseArgs([]string{"--apply-everything"}); err == nil {
		t.Error("an unknown flag was accepted")
	}
}

// ACTIVE is refused by the daemon package, and reaching that refusal requires
// being asked for it explicitly.
func TestActiveModeIsParsedButNotSupported(t *testing.T) {
	hermetic(t)

	cfg, _, _, err := parseArgs([]string{"--mode", "active"})
	if err != nil {
		t.Fatalf("ACTIVE should parse and be refused later, not at the parser: %v", err)
	}
	if cfg.Mode != daemon.ModeActive {
		t.Errorf("mode = %q, want ACTIVE", cfg.Mode)
	}
	if cfg.Mode.Supported() {
		t.Error("ACTIVE must not be supported in this build")
	}
	if cfg.Mode.Applies() {
		t.Error("no mode may apply anything in this build")
	}
}

// Asking what the daemon may do must not start it.
func TestAskingForVerbsDoesNotProduceARunnableConfig(t *testing.T) {
	hermetic(t)

	_, verbList, _, err := parseArgs([]string{"--verbs"})
	if err != nil {
		t.Fatal(err)
	}
	if !verbList {
		t.Error("--verbs was not honoured")
	}
}

// Every verb the daemon can serve must still be one that reads.
func TestNoVerbCanChangeTheHost(t *testing.T) {
	for _, v := range daemon.Verbs() {
		lower := strings.ToLower(v.Name + " " + v.Description)
		for _, forbidden := range []string{"apply", "delete", "remove", "write", "set", "restart", "down"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("verb %q reads like it can change the host: %s", v.Name, v.Description)
			}
		}
	}
}
