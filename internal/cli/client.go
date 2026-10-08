package cli

// This file is the CLI half of the thnd socket protocol.
//
// It exists because thnd serves a documented query surface — status, observe,
// last, verbs, ping — and the CLI was printing "cannot reach thnd" without
// ever opening the socket. A command whose failure message says the daemon is
// unreachable, printed while the daemon is answering queries, is worse than a
// missing command: it tells the operator their gateway is down when it is not.
//
// The request and response types are imported from internal/daemon rather than
// redeclared here. The daemon is the authority on its own protocol, and a
// second copy of these structs is a second thing to keep in step with the
// first; the moment they drift, the CLI reports a parse error against a daemon
// that is behaving correctly.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/daemon"
)

// daemonTimeout bounds one request to thnd.
//
// Short, because every verb is a local query answered in microseconds. A
// daemon that has wedged should be reported as wedged rather than hanging the
// terminal that asked.
const daemonTimeout = 5 * time.Second

// errDaemonUnreachable means the socket could not be reached at all, as
// distinct from a daemon that answered with a refusal.
//
// The distinction decides the exit code: an unreachable daemon means the
// operator has to start one, while a refusal means the daemon is working and
// the request was the problem.
var errDaemonUnreachable = errors.New("thnd is not reachable")

// daemonClient speaks the thnd socket protocol.
type daemonClient struct {
	// path is the unix socket to dial.
	path string

	// timeout bounds a single request.
	timeout time.Duration
}

// newDaemonClient builds a client for the socket thnd is expected to be on.
func newDaemonClient(env *Env) daemonClient {
	return daemonClient{path: socketPath(env), timeout: daemonTimeout}
}

// call sends one verb and returns its result.
//
// Errors are returned, never printed: the caller decides whether a failure is
// "the daemon is not running" (which the operator can fix by starting it) or
// something else, and a client that has already written to stderr has taken
// that decision away.
func (c daemonClient) call(verb string) (json.RawMessage, error) {
	if strings.TrimSpace(c.path) == "" {
		return nil, fmt.Errorf("%w: no socket path is configured", errDaemonUnreachable)
	}

	conn, err := net.DialTimeout("unix", c.path, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errDaemonUnreachable, c.path, err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(c.timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: %v", errDaemonUnreachable, err)
	}

	req, err := json.Marshal(daemon.Request{Verb: verb})
	if err != nil {
		return nil, fmt.Errorf("encoding the request: %w", err)
	}
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errDaemonUnreachable, c.path, err)
	}

	var resp daemon.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("%w: reading the reply from %s: %v", errDaemonUnreachable, c.path, err)
	}

	// A refusal is not an unreachable daemon. The socket worked.
	if !resp.OK {
		if resp.Error == "" {
			return nil, errors.New("thnd refused the request without saying why")
		}
		return nil, fmt.Errorf("thnd refused %q: %s", verb, resp.Error)
	}
	return resp.Result, nil
}

// reachable reports whether the daemon answers at all.
//
// Used by commands whose job is to say whether the gateway is alive, where the
// distinction between "not running" and "refused" is the whole point.
func (c daemonClient) reachable() error {
	_, err := c.call("ping")
	return err
}

// daemonStatus is the shape of the status verb's result.
//
// A local mirror of daemon.Status rather than the type itself would drift;
// importing it is safe because the daemon package does not import this one.
type daemonStatus = daemon.Status

// statusFrom asks thnd what state it is in.
func (c daemonClient) statusFrom() (daemonStatus, error) {
	raw, err := c.call("status")
	if err != nil {
		return daemonStatus{}, err
	}

	var st daemonStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return daemonStatus{}, fmt.Errorf("decoding the daemon's status: %w", err)
	}
	return st, nil
}

// renderDaemonStatus writes a daemon's self-report for a human.
//
// "Applies" is printed rather than left implied. Every mode currently reports
// false, and that is the single most important thing this command can tell
// somebody standing in front of the box: the gateway is not changing anything,
// and this is why.
func renderDaemonStatus(env *Env, st daemonStatus) {
	env.printf("thnd %s\n", strings.ToLower(string(st.Mode)))
	env.printf("  uptime:     %s\n", orUnknown(st.Uptime, "not reported"))
	env.printf("  socket:     %s\n", orUnknown(st.Socket, "not reported"))
	env.printf("  privileged: %s\n", yesNo(st.Privileged))
	env.printf("  applies:    %s\n", yesNo(st.Applies))
	env.printf("  observing:  %d cycle(s)", st.Observations)

	if !st.LastObservationAt.IsZero() {
		env.printf(", last %s", st.LastObservationAt.UTC().Format(time.RFC3339))
	}
	env.printf("\n")

	if st.ModeDescription != "" {
		env.printf("\n  %s\n", st.ModeDescription)
	}
	if st.LastError != "" {
		env.printf("\n  last observation error: %s\n", st.LastError)
	}
	if len(st.Verbs) > 0 {
		env.printf("\n  verbs: %s\n", strings.Join(st.Verbs, ", "))
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orUnknown(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
