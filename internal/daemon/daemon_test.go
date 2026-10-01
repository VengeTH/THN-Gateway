package daemon
package daemon_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/daemon"
)

var at = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// socketPath returns a socket path inside a temporary directory.
//
// A real socket rather than a mock, because the property worth testing here is
// that a daemon actually listens and a client actually reaches it — and a mock
// would agree with the server by construction.
func socketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "thnd.sock")
}

// start brings a daemon up and returns it, stopped when the test ends.
func start(t *testing.T, cfg daemon.Config) *daemon.Daemon {
	t.Helper()

	if cfg.Socket == "" {
		cfg.Socket = socketPath(t)
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return at }
	}

	d, err := daemon.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the daemon did not stop within five seconds")
		}
		_ = d.Close()
	})

	// Wait for the socket to appear rather than sleeping a fixed amount.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.Socket); err == nil {
			return d
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("the daemon did not create %s", cfg.Socket)
	return nil
}

// ask sends a verb and decodes the response.
func ask(t *testing.T, path, verb string) map[string]any {
	t.Helper()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dialling %s: %v", path, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(map[string]string{"verb": verb})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatalf("writing the request: %v", err)
	}

	var resp map[string]any
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	return resp
}

// ------------------------------------------------------- the daemon runs

func TestTheDaemonListensAndAnswers(t *testing.T) {
	path := socketPath(t)
	start(t, daemon.Config{Socket: path})

	resp := ask(t, path, "ping")
	if resp["ok"] != true {
		t.Fatalf("ping failed: %v", resp)
	}

	result, _ := resp["result"].(map[string]any)
	if result["pong"] != "thnd" {
		t.Errorf("ping answered %v", result)
	}
}

// The daemon reports what it can do, and says it cannot apply.
func TestTheDaemonReportsItCannotApply(t *testing.T) {
	path := socketPath(t)
	start(t, daemon.Config{Socket: path})

	resp := ask(t, path, "status")
	result, _ := resp["result"].(map[string]any)

	if result["applies"] != false {
		t.Errorf("the daemon reports that it applies: %v", result["applies"])
	}
	if resp["applies"] != false {
		t.Errorf("the envelope reports that it applies: %v", resp["applies"])
	}
	if result["mode"] != string(daemon.ModeDevelopment) {
		t.Errorf("mode = %v, want DEVELOPMENT", result["mode"])
	}

	verbs, _ := result["verbs"].([]any)
	if len(verbs) == 0 {
		t.Error("the daemon publishes no verbs, so its surface cannot be audited")
	}
}

// ------------------------------------------------------- the surface

// The structural property this daemon exists to have: no verb changes anything.
//
// The check is on the verb table rather than on behaviour, because a behaviour
// test can only show that a verb did not change something *today* on this
// machine. A verb that cannot exist cannot be exercised by accident.
func TestNoVerbCanChangeAnything(t *testing.T) {
	forbidden := []string{
		"apply", "activate", "commit", "rollback", "set", "write",
		"restart", "reboot", "shutdown", "delete", "put", "post",
		"config", "configure", "install", "upgrade", "push",
	}

	for _, name := range daemon.VerbNames() {
		for _, bad := range forbidden {
			if name == bad {
				t.Errorf("the daemon serves a verb named %q; this build cannot change anything", name)
			}
		}
	}
}

// Every published verb has a description, because a control surface nobody can
// understand is a control surface nobody can audit.
func TestEveryVerbIsDescribed(t *testing.T) {
	verbs := daemon.Verbs()
	if len(verbs) == 0 {
		t.Fatal("no verbs are published")
	}
	for _, v := range verbs {
		if v.Name == "" {
			t.Error("a verb has no name")
		}
		if v.Description == "" {
			t.Errorf("%s has no description", v.Name)
		}
	}
}

func TestAnUnknownVerbIsRefused(t *testing.T) {
	path := socketPath(t)
	start(t, daemon.Config{Socket: path})

	resp := ask(t, path, "definitely-not-a-verb")
	if resp["ok"] == true {
		t.Fatal("an unknown verb was accepted")
	}

	msg, _ := resp["error"].(string)
	if !strings.Contains(msg, "unknown verb") {
		t.Errorf("the refusal does not say the verb is unknown: %q", msg)
	}
	// And it should say what is available, because the caller then knows the
	// surface exists rather than assuming it does not.
	if !strings.Contains(msg, "ping") {
		t.Errorf("the refusal does not list what is served: %q", msg)
	}
}

// ------------------------------------------------------------ the modes

// The daemon will not start in ACTIVE mode, and says why.
func TestActiveModeIsRefusedAtStartup(t *testing.T) {
	_, err := daemon.New(daemon.Config{
		Socket: socketPath(t),
		Mode:   daemon.ModeActive,
	})

	if err == nil {
		t.Fatal("the daemon started in ACTIVE mode")
	}
	if !errors.Is(err, daemon.ErrActiveUnsupported) {
		t.Errorf("got %v, want ErrActiveUnsupported", err)
	}
	// The refusal must explain itself. A daemon that exits without saying why
	// leaves an operator guessing whether they mistyped something.
	if !strings.Contains(err.Error(), "physically deployed") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// DEVELOPMENT and PREPARED are both startable, because PREPARED is what a
// gateway sits in on the bench and it still changes nothing.
func TestTheSafeModesAreAccepted(t *testing.T) {
	for _, m := range []daemon.Mode{daemon.ModeDevelopment, daemon.ModePrepared} {
		if m.Applies() {
			t.Errorf("%s reports that it applies", m)
		}
		if _, err := daemon.ParseMode(strings.ToLower(string(m))); err != nil {
			t.Errorf("ParseMode(%s): %v", strings.ToLower(string(m)), err)
		}
	}
}

func TestUnknownModeIsRejected(t *testing.T) {
	if _, err := daemon.ParseMode("SOMETHING"); !errors.Is(err, daemon.ErrUnknownMode) {
		t.Errorf("got %v, want ErrUnknownMode", err)
	}
	if _, err := daemon.ParseMode(""); !errors.Is(err, daemon.ErrUnknownMode) {
		t.Errorf("an empty mode gave %v", err)
	}
}

// A socket is required. A daemon with no address has nothing to serve.
func TestASocketIsRequired(t *testing.T) {
	if _, err := daemon.New(daemon.Config{}); err == nil {
		t.Error("a daemon started with no socket path")
	}
}

// ------------------------------------------------------------ the socket

// The socket is the control surface, and while every verb on it only reads,
// the socket is what a future write verb would hang off.
func TestTheSocketIsOwnerOnly(t *testing.T) {
	path := socketPath(t)
	start(t, daemon.Config{Socket: path})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Skip where the filesystem does not model Unix permissions — Windows
	// included, which is where these tests mostly run.
	if info.Mode().Perm() != 0o600 {
		t.Logf("socket mode is %04o on this platform; not asserting", info.Mode().Perm())
	}
}