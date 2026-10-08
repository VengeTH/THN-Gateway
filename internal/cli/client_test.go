package cli

// Tests for the CLI half of the thnd socket protocol.
//
// The bug these exist for: `thn status` and `thn diagnostics` printed
// "cannot reach thnd" without ever opening the socket, so a healthy daemon
// answering queries was reported to the operator as a gateway that was down.
// A test that only checked the error path would have kept passing.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/daemon"
	"github.com/VengeTH/THN-Gateway/internal/logging"
)

// startDaemon brings a real thnd up on a temporary socket.
//
// A real socket rather than a stub listener, because the property under test
// is that the CLI and the daemon agree on the wire format — a stub written
// against the same assumption proves nothing.
func startDaemon(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "thnd.sock")
	lg, err := logging.New(logging.Options{
		Config:    config.LoggingConfig{Level: "error", Format: "text"},
		Component: "thnd",
	})
	if err != nil {
		t.Fatalf("building the logger: %v", err)
	}

	d, err := daemon.New(daemon.Config{
		Socket: path,
		Now:    func() time.Time { return time.Now() },
		Logger: lg,
	})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = d.Run(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the daemon did not stop within five seconds")
		}
		_ = d.Close()
	})

	// Wait for the daemon to ACCEPT connections, not for the socket file to
	// appear.
	//
	// The previous version polled os.Stat and returned as soon as the file
	// existed. That is the wrong readiness signal: a Unix socket is created
	// by the bind, which can happen before the listener is serving. The test
	// would hand back a path the daemon had not begun accepting on, and the
	// CLI under test would fail with ECONNREFUSED — a failure in the test
	// rather than in the code, which is what made this intermittently red
	// under load.
	//
	// Dialling is the same check the CLI itself performs, so the test waits
	// for exactly the condition it is about to depend on. It is stricter than
	// the file check, not looser.
	if err := waitForSocket(path, 10*time.Second); err != nil {
		t.Fatalf("the daemon never accepted a connection on %s: %v", path, err)
	}
	return path
}

// waitForSocket dials path until it connects or the deadline passes.
func waitForSocket(path string, within time.Duration) error {
	deadline := time.Now().Add(within)

	var last error
	for {
		conn, err := net.Dial("unix", path)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		last = err

		if time.Now().After(deadline) {
			return fmt.Errorf("after %s: %w", within, last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// cliFor builds an Env pointed at a socket, capturing output.
func cliFor(t *testing.T, socket string) (*Env, *strings.Builder, *strings.Builder) {
	t.Helper()

	var out, errOut strings.Builder
	env := &Env{
		Stdout: &out,
		Stderr: &errOut,
		Getenv: func(k string) string {
			if k == "THN_SOCKET" {
				return socket
			}
			return ""
		},
		Getwd: func() (string, error) { return t.TempDir(), nil },
	}
	return env, &out, &errOut
}

// ------------------------------------------------------------- happy path

// The whole point: with a daemon running, `thn status` asks it rather than
// declaring it unreachable.
func TestStatusAsksTheRunningDaemon(t *testing.T) {
	socket := startDaemon(t)
	env, out, errOut := cliFor(t, socket)

	code := runStatus(env, nil)

	if code != ExitOK {
		t.Fatalf("exit = %v, want %v\nstderr: %s", code, ExitOK, errOut.String())
	}
	if strings.Contains(errOut.String(), "cannot reach") {
		t.Errorf("a running daemon must not be reported unreachable: %s", errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "applies:") {
		t.Errorf("status did not report whether the daemon can change the host:\n%s", got)
	}
	if !strings.Contains(got, "no") {
		t.Errorf("applies should read no in this build:\n%s", got)
	}
}

func TestStatusRendersJSONFromTheDaemon(t *testing.T) {
	socket := startDaemon(t)
	env, out, _ := cliFor(t, socket)
	env.IsJSON = true

	if code := runStatus(env, nil); code != ExitOK {
		t.Fatalf("exit = %v, want %v", code, ExitOK)
	}

	var st daemon.Status
	if err := json.Unmarshal([]byte(out.String()), &st); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if st.Applies {
		t.Error("applies must be false in this build")
	}
	if len(st.Verbs) == 0 {
		t.Error("the daemon should have advertised its verbs")
	}
}

func TestDiagnosticsAsksTheRunningDaemon(t *testing.T) {
	socket := startDaemon(t)
	env, out, errOut := cliFor(t, socket)

	code := runDiagnostics(env, nil)

	if code != ExitOK {
		t.Fatalf("exit = %v, want %v\nstderr: %s", code, ExitOK, errOut.String())
	}
	if !strings.Contains(out.String(), "thnd: reachable") {
		t.Errorf("diagnostics did not report reachability:\n%s", out.String())
	}
}

// ---------------------------------------------------------- failure path

// No daemon: the old message, and a non-zero exit. This is the case that has
// to keep working, and it now carries the dial error rather than a guess.
func TestStatusReportsAnUnreachableDaemon(t *testing.T) {
	env, _, errOut := cliFor(t, filepath.Join(t.TempDir(), "absent.sock"))

	code := runStatus(env, nil)

	if code != ExitUnavailable {
		t.Errorf("exit = %v, want %v", code, ExitUnavailable)
	}
	for _, want := range []string{"thn status:", "Expected socket:", "--local"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr is missing %q:\n%s", want, errOut.String())
		}
	}
}

// The refusal and the unreachable case must stay distinguishable: one means
// "start the daemon", the other means "your request was wrong".
func TestARefusalIsNotReportedAsUnreachable(t *testing.T) {
	c := daemonClient{path: startDaemon(t), timeout: 2 * time.Second}

	_, err := c.call("no-such-verb")
	if err == nil {
		t.Fatal("an unknown verb was accepted")
	}
	if strings.Contains(err.Error(), "not reachable") {
		t.Errorf("a refusal was reported as unreachability: %v", err)
	}
	if !strings.Contains(err.Error(), "no-such-verb") {
		t.Errorf("the refusal should name the verb: %v", err)
	}
}

func TestAnEmptySocketPathIsUnreachableRatherThanAPanic(t *testing.T) {
	c := daemonClient{path: "  ", timeout: time.Second}

	if _, err := c.call("ping"); err == nil {
		t.Fatal("an empty socket path should not connect")
	}
}

// The socket path has to come from the resolved configuration, not a
// hardcoded path. A run against any other config used to report an
// "expected socket" that was simply wrong.
func TestSocketPathFollowsTheResolvedConfig(t *testing.T) {
	// config.Load reads THN_SOCKET through os.Getenv, so an ambient value in
	// the developer's shell would win over the configuration this test is
	// about. Emptying it is enough — the loader treats empty as unset.
	t.Setenv("THN_SOCKET", "")
	t.Setenv("THN_STATE_DB", "")
	t.Setenv("THN_RUN_DIR", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "schema_version: 1\npaths:\n  socket: /tmp/from-config.sock\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	env := &Env{
		Getenv: func(k string) string {
			if k == "THN_CONFIG" {
				return path
			}
			return ""
		},
		Getwd: func() (string, error) { return dir, nil },
	}

	if got := socketPath(env); got != "/tmp/from-config.sock" {
		t.Errorf("socketPath = %q, want /tmp/from-config.sock", got)
	}
}

// THN_SOCKET is the documented escape hatch and must win over the config file,
// because that is what it exists for.
func TestSocketPathPrefersTheEnvironment(t *testing.T) {
	env := &Env{
		Getenv: func(k string) string {
			if k == "THN_SOCKET" {
				return "/tmp/from-env.sock"
			}
			return ""
		},
		Getwd: func() (string, error) { return t.TempDir(), nil },
	}

	if got := socketPath(env); got != "/tmp/from-env.sock" {
		t.Errorf("socketPath = %q, want /tmp/from-env.sock", got)
	}
}
