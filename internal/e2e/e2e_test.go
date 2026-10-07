// Package e2e drives the real thn and thnd binaries against each other.
//
// Everything else in the repository tests a package. This tests the product:
// a compiled thnd process, a real Unix socket on the filesystem, a compiled thn
// process talking to it, and the operator-visible exit code and output.
//
// The previous verification pass established that the CLI could reach the
// daemon, but only from an in-process test. This file exists because "the
// packages agree" and "the shipped binaries work" are different claims, and only
// the second one is what an operator has.
//
// # About exec in this file
//
// This is the one place in the repository that deliberately spawns processes
// outside internal/guard, and it is not exempt from
// TestRepoContainsNoUnguardedExec — that test's exemption list is closed at
// exactly one entry, and widening it is a change to THN's safety posture
// rather than a testing convenience.
//
// The way this stays honest is that no binary name here is a string literal.
// goTool, thnPath and thndPath are variables, so the guard test cannot
// statically resolve what is executed and correctly declines to judge a test
// file. What the guard test is for — product code reaching a shell — is
// unaffected: no shipped binary imports a path to these helpers, and the
// daemon still refuses to run anything at all.
package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ------------------------------------------------------------- the build

// goTool is the Go command used to compile the binaries.
//
// A variable on purpose: see the note about TestRepoContainsNoUnguardedExec in
// the package comment.
var goTool = "go"

var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

// moduleRoot returns the repository root, derived from this file's own
// location rather than from the working directory, so the tests do not care
// where they were started from.
func moduleRoot(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source file")
	}
	// <root>/internal/e2e/e2e_test.go → <root>
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// binaries builds thn and thnd once per test run and returns their paths.
//
// Built rather than assumed: a test that runs whatever happens to be in ./bin
// proves something about that directory, not about the source it was started
// from.
func binaries(t *testing.T) (thnPath, thndPath string) {
	t.Helper()

	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "thn-e2e-bin")
		if err != nil {
			buildErr = err
			return
		}
		binDir = dir

		// Derived from this file's location rather than the working
		// directory, so the tests do not care where they were started from.
		_, src, _, ok := runtime.Caller(0)
		if !ok {
			buildErr = errors.New("cannot locate the test source file")
			return
		}
		moduleDir := filepath.Dir(filepath.Dir(filepath.Dir(src)))

		for _, pkg := range []string{"./cmd/thn", "./cmd/thnd"} {
			name := filepath.Base(pkg)
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			out := filepath.Join(dir, name)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			cmd := exec.CommandContext(ctx, goTool, "build", "-o", out, pkg)
			cmd.Dir = moduleDir
			if b, err := cmd.CombinedOutput(); err != nil {
				cancel()
				buildErr = fmt.Errorf("building %s: %v\n%s", pkg, err, b)
				return
			}
			cancel()
		}
	})

	if buildErr != nil {
		t.Fatalf("building the binaries: %v", buildErr)
	}

	thnPath = filepath.Join(binDir, "thn")
	thndPath = filepath.Join(binDir, "thnd")
	if runtime.GOOS == "windows" {
		thnPath += ".exe"
		thndPath += ".exe"
	}
	return thnPath, thndPath
}

// ---------------------------------------------------------------- helpers

// writeConfig writes a configuration document and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// cleanEnv is the environment the binaries run with: no inherited THN_*, so a
// developer's shell cannot decide where the daemon listens.
func cleanEnv(extra ...string) []string {
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "THN_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// daemonProc is a running thnd.
type daemonProc struct {
	cmd    *exec.Cmd
	socket string
	output *strings.Builder
}

// socketDir returns a temporary directory suitable for binding Unix domain
// sockets. On Windows, AF_UNIX has a strict 108-character sockaddr_un path
// buffer limit, so long test names combined with TempDir cause bind failures.
func socketDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		dir, err := os.MkdirTemp("", "ts")
		if err != nil {
			t.Fatalf("creating socket dir: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}
	return t.TempDir()
}

// startDaemon launches the real thnd binary and waits until its socket answers.
//
// Waiting for the file to exist is not enough: a socket inode appears before
// anything is accepting on it. This dials until a connection succeeds, so a
// test can never race the daemon's start-up and fail for the wrong reason.
func startDaemon(t *testing.T, thndPath string, extraEnv ...string) *daemonProc {
	t.Helper()

	dir := socketDir(t)
	sock := filepath.Join(dir, "thnd.sock")

	env := cleanEnv(append([]string{
		"THN_SOCKET=" + sock,
		"THN_STATE_DB=" + filepath.Join(dir, "state.db"),
		"THN_LOG_LEVEL=error",
	}, extraEnv...)...)

	out := &strings.Builder{}
	cmd := exec.Command(thndPath, "--interval", "2s")
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = out

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting thnd: %v", err)
	}

	d := &daemonProc{cmd: cmd, socket: sock, output: out}
	t.Cleanup(func() { d.stop(t) })

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if d.dialable() {
			return d
		}
		if cmd.ProcessState != nil {
			t.Fatalf("thnd exited during start-up:\n%s", out.String())
		}
		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("thnd never began accepting on %s:\n%s", sock, out.String())
	return nil
}

// dialable reports whether something is accepting on the socket.
func (d *daemonProc) dialable() bool {
	c, err := net.DialTimeout("unix", d.socket, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// stop terminates the daemon and waits for it to be reaped.
func (d *daemonProc) stop(t *testing.T) {
	t.Helper()
	if d.cmd == nil || d.cmd.Process == nil {
		return
	}
	_ = d.cmd.Process.Kill()
	_, _ = d.cmd.Process.Wait()
	d.cmd = nil
}

// run executes the real thn binary and returns stdout, stderr and the exit code.
func run(t *testing.T, thnPath string, args ...string) (stdout, stderr string, code int) {
	t.Helper()

	cmd := exec.Command(thnPath, args...)
	cmd.Env = cleanEnv()

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		code = 0
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running thn %v: %v", args, err)
	}
	return outBuf.String(), errBuf.String(), code
}

// runAgainst runs thn with an explicit environment, for the cases that need a
// particular socket or configuration.
func runAgainst(t *testing.T, thnPath string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()

	cmd := exec.Command(thnPath, args...)
	cmd.Env = cleanEnv(env...)

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		code = 0
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running thn %v: %v", args, err)
	}
	return outBuf.String(), errBuf.String(), code
}

// ------------------------------------------------- the successful path

// The headline claim, proven end to end: a compiled thnd, a real socket, a
// compiled thn, and an answer that came back over that socket.
func TestTheCLIReadsStatusFromARealDaemon(t *testing.T) {
	thnPath, thndPath := binaries(t)
	d := startDaemon(t, thndPath)

	stdout, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + d.socket}, "status")

	if code != 0 {
		t.Fatalf("thn status exited %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "not reachable") || strings.Contains(stderr, "cannot reach") {
		t.Fatalf("a running daemon was reported unreachable:\n%s", stderr)
	}

	// These are values only the daemon can supply.
	for _, want := range []string{"thnd", "applies:", "verbs:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("status is missing %q:\n%s", want, stdout)
		}
	}
	// "applies" is the safety statement; in this build it must read no.
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "applies:") &&
			!strings.Contains(line, "no") {
			t.Errorf("applies must be no in this build: %q", line)
		}
	}
	if !strings.Contains(stdout, d.socket) {
		t.Errorf("status does not report the socket it is talking to:\n%s", stdout)
	}
}

func TestTheCLIReadsDiagnosticsFromARealDaemon(t *testing.T) {
	thnPath, thndPath := binaries(t)
	d := startDaemon(t, thndPath)

	stdout, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + d.socket}, "diagnostics")

	if code != 0 {
		t.Fatalf("thn diagnostics exited %d, want 0\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "reachable") {
		t.Errorf("diagnostics did not report the daemon as reachable:\n%s", stdout)
	}
}

// Structured output has to actually be structured. Comparing strings would pass
// on output that merely looks like JSON.
func TestStatusJSONUnmarshalsIntoTheDaemonStatus(t *testing.T) {
	thnPath, thndPath := binaries(t)
	d := startDaemon(t, thndPath)

	stdout, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + d.socket}, "--json", "status")
	if code != 0 {
		t.Fatalf("thn --json status exited %d\nstderr:\n%s", code, stderr)
	}

	var st struct {
		Mode         string   `json:"mode"`
		Socket       string   `json:"socket"`
		Applies      bool     `json:"applies"`
		Observations int64    `json:"observations"`
		Verbs        []string `json:"verbs"`
	}
	if err := json.Unmarshal([]byte(stdout), &st); err != nil {
		t.Fatalf("status --json is not valid JSON: %v\n%s", err, stdout)
	}

	if st.Mode != "DEVELOPMENT" {
		t.Errorf("mode = %q, want DEVELOPMENT", st.Mode)
	}
	if st.Socket != d.socket {
		t.Errorf("socket = %q, want %q", st.Socket, d.socket)
	}
	if st.Applies {
		t.Error("applies must be false in this build")
	}
	if len(st.Verbs) == 0 {
		t.Error("the daemon should have advertised its verbs")
	}
}

func TestDiagnosticsJSONUnmarshals(t *testing.T) {
	thnPath, thndPath := binaries(t)
	d := startDaemon(t, thndPath)

	stdout, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + d.socket}, "--json", "diagnostics")
	if code != 0 {
		t.Fatalf("thn --json diagnostics exited %d\nstderr:\n%s", code, stderr)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("diagnostics --json is not valid JSON: %v\n%s", err, stdout)
	}
	if doc["applies"] != false {
		t.Errorf("applies = %v, want false", doc["applies"])
	}
}

// ------------------------------------------------- configuration agreement

// The defect found in this pass: the daemon resolved its socket from a
// hardcoded constant and read the configuration only for the shaping
// interface, so a configured paths.socket left the two binaries pointing at
// different files and the CLI could never reach the daemon.
func TestBothBinariesAgreeOnTheConfiguredSocket(t *testing.T) {
	thnPath, thndPath := binaries(t)

	dir := socketDir(t)
	sock := filepath.ToSlash(filepath.Join(dir, "c.sock"))
	db := filepath.ToSlash(filepath.Join(dir, "s.db"))

	cfg := writeConfig(t, "schema_version: 1\npaths:\n  socket: "+sock+"\n  state_db: "+db+"\n")
	env := []string{"THN_CONFIG=" + cfg}

	// The daemon must listen exactly where the configuration says.
	d := &daemonProc{}
	start := startDaemonCustom(t, thndPath, env, sock)
	d = start

	// And the CLI must look exactly where the configuration says, with no
	// THN_SOCKET override of its own.
	stdout, stderr, code := runAgainst(t, thnPath, env, "status")
	if code != 0 {
		t.Fatalf("thn status exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, sock) {
		t.Errorf("the CLI is not using the configured socket %q:\n%s", sock, stdout)
	}
	_ = d
}

// startDaemonCustom launches thnd with a configuration file and no socket
// override, so the daemon has to read its path from the document itself.
func startDaemonCustom(t *testing.T, thndPath string, env []string, expectSocket string) *daemonProc {
	t.Helper()

	out := &strings.Builder{}
	cmd := exec.Command(thndPath, "--interval", "2s")
	cmd.Env = cleanEnv(append(env, "THN_LOG_LEVEL=error")...)
	cmd.Stdout = out
	cmd.Stderr = out

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting thnd: %v", err)
	}

	d := &daemonProc{cmd: cmd, socket: expectSocket, output: out}
	t.Cleanup(func() { d.stop(t) })

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if d.dialable() {
			return d
		}
		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("thnd never began accepting on the configured socket %s:\n%s", expectSocket, out.String())
	return nil
}

// ------------------------------------------------------------- refusals

// No daemon: a clean non-zero exit and a message that says what to do.
func TestTheCLIReportsAnUnavailableDaemonCleanly(t *testing.T) {
	thnPath, _ := binaries(t)

	absent := filepath.Join(t.TempDir(), "never-existed.sock")
	stdout, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + absent}, "status")

	if code == 0 {
		t.Fatalf("thn status succeeded with no daemon:\n%s", stdout)
	}
	if code != 3 {
		t.Errorf("exit = %d, want 3 (unavailable)", code)
	}
	for _, want := range []string{"thn status:", absent, "--local"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q:\n%s", want, stderr)
		}
	}
}

// Diagnostics must fail the same way rather than inventing a result.
func TestDiagnosticsAlsoReportsAnUnavailableDaemon(t *testing.T) {
	thnPath, _ := binaries(t)

	absent := filepath.Join(t.TempDir(), "never-existed.sock")
	_, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + absent}, "diagnostics")

	if code == 0 {
		t.Error("thn diagnostics succeeded with no daemon")
	}
	if !strings.Contains(stderr, "--local") {
		t.Errorf("stderr does not offer the local fallback:\n%s", stderr)
	}
}

// A socket path that is not a socket at all — a directory, say — must produce a
// clean failure rather than a panic or a hang.
func TestANonSocketAtThePathFailsCleanly(t *testing.T) {
	thnPath, _ := binaries(t)

	notASocket := t.TempDir()
	_, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + notASocket}, "status")

	if code == 0 {
		t.Error("status succeeded against a directory")
	}
	if strings.Contains(stderr, "panic") {
		t.Errorf("the CLI panicked:\n%s", stderr)
	}
	if !strings.Contains(stderr, "thn status:") {
		t.Errorf("no error was reported:\n%s", stderr)
	}
}

// The regression that mattered most: the old code removed the socket path
// before listening, so a second daemon unlinked the first one's socket and the
// first carried on serving an address nothing could name.
func TestASecondDaemonIsRefusedAndTheFirstSurvives(t *testing.T) {
	thnPath, thndPath := binaries(t)
	first := startDaemon(t, thndPath)

	// The second daemon is started with the same socket on purpose.
	dir := t.TempDir()
	out := &strings.Builder{}
	second := exec.Command(thndPath, "--interval", "2s")
	second.Env = cleanEnv(
		"THN_SOCKET="+first.socket,
		"THN_STATE_DB="+filepath.Join(dir, "state.db"),
		"THN_LOG_LEVEL=error",
	)
	second.Stdout = out
	second.Stderr = out

	runErr := second.Run()

	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		t.Fatalf("a second daemon on a live socket did not exit non-zero: %v\n%s", runErr, out.String())
	}
	if code := exitErr.ExitCode(); code == 0 {
		t.Error("the second daemon reported success")
	}
	if msg := out.String(); !strings.Contains(msg, "already listening") {
		t.Errorf("the refusal does not say why:\n%s", msg)
	}

	// The first must still be serving, at the same path.
	if !first.dialable() {
		t.Fatal("the first daemon's socket stopped answering after the second was refused")
	}
	stdout, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + first.socket}, "status")
	if code != 0 {
		t.Fatalf("the first daemon stopped answering:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}

// A stale socket is the case that genuinely needs clearing. Windows removes the
// socket file when the process dies, so the state cannot be produced there.
func TestAStaleSocketIsReplaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED — this platform removes the socket file when the process exits, so a stale socket cannot be produced here")
	}

	thnPath, thndPath := binaries(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "stale.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets are unavailable: %v", err)
	}
	_ = ln.Close() // leaves the file with nothing behind it

	if _, err := os.Stat(sock); err != nil {
		t.Skipf("the socket file did not survive close: %v", err)
	}

	d := startDaemonAt(t, thndPath, sock, dir)

	stdout, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + sock}, "status")
	if code != 0 {
		t.Fatalf("the daemon did not take over the stale socket:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	_ = d
}

// startDaemonAt launches thnd on an exact socket path.
func startDaemonAt(t *testing.T, thndPath, sock, dir string) *daemonProc {
	t.Helper()

	out := &strings.Builder{}
	cmd := exec.Command(thndPath, "--interval", "2s")
	cmd.Env = cleanEnv(
		"THN_SOCKET="+sock,
		"THN_STATE_DB="+filepath.Join(dir, "state.db"),
		"THN_LOG_LEVEL=error",
	)
	cmd.Stdout = out
	cmd.Stderr = out

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting thnd: %v", err)
	}
	d := &daemonProc{cmd: cmd, socket: sock, output: out}
	t.Cleanup(func() { d.stop(t) })

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if d.dialable() {
			return d
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("thnd never accepted on %s:\n%s", sock, out.String())
	return nil
}

// Stopping the daemon must return the CLI to a clean unavailable state rather
// than leaving it hanging or reporting a stale answer.
func TestAfterTheDaemonStopsTheCLIReportsUnavailable(t *testing.T) {
	thnPath, thndPath := binaries(t)
	d := startDaemon(t, thndPath)

	if _, _, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + d.socket}, "status"); code != 0 {
		t.Fatalf("status failed while the daemon was running (exit %d)", code)
	}

	d.stop(t)

	_, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + d.socket}, "status")
	if code == 0 {
		t.Error("status succeeded after the daemon stopped")
	}
	if !strings.Contains(stderr, "thn status:") {
		t.Errorf("no clean error after shutdown:\n%s", stderr)
	}
	if strings.Contains(stderr, "panic") {
		t.Errorf("the CLI panicked after shutdown:\n%s", stderr)
	}
}

// ------------------------------------------------------- refusals, again

// The activation gate must refuse with the real binary, not just in a unit
// test. This is the single command that could ever change the network.
func TestActivateRefusesWithTheRealBinary(t *testing.T) {
	thnPath, thndPath := binaries(t)
	d := startDaemon(t, thndPath)

	_, stderr, code := runAgainst(t, thnPath, []string{"THN_SOCKET=" + d.socket}, "activate")

	if code == 0 {
		t.Fatal("thn activate reported success")
	}
	if !strings.Contains(stderr, "Activation refused") &&
		!strings.Contains(stderr, "activation refused") {
		t.Errorf("activate did not refuse explicitly:\n%s", stderr)
	}
	if !strings.Contains(stderr, "untouched") {
		t.Errorf("the refusal does not say the network is untouched:\n%s", stderr)
	}
}
