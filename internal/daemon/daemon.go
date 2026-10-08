package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/logging"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

// Config is how the daemon is started.
type Config struct {
	// Mode is the operating mode. Cannot be ModeActive in this build.
	Mode Mode

	// Socket is the unix socket path to listen on.
	Socket string

	// StateDB is the state database path. Empty disables persistence.
	StateDB string

	// QoSInterface is the interface to read shaping state from. Empty skips it.
	QoSInterface string

	// Interval is how often to observe the host.
	Interval time.Duration

	// Now supplies the clock, for tests.
	Now func() time.Time

	// Logger receives daemon events.
	Logger *logging.Logger
}

// DefaultInterval is the observation cadence when none is given.
const DefaultInterval = time.Minute

// socketProbeTimeout bounds the liveness check made against an existing
// socket before it is treated as stale.
//
// Short on purpose. The peer is either listening or gone, both of which
// resolve immediately; a timeout here means start-up is delayed rather than
// that the answer is slow.
const socketProbeTimeout = 250 * time.Millisecond

// Daemon is thnd.
type Daemon struct {
	cfg      Config
	log      *logging.Logger
	observer Observer
	loop     *loop
	store    *state.Store

	mu        sync.Mutex
	startedAt time.Time

	ln net.Listener
}

// New builds a daemon.
//
// It does not listen, connect or observe. Construction is separate from running
// so that a misconfiguration is reported before anything is created, and so
// that a daemon which will refuse to start has done nothing by the time it says
// so.
func New(cfg Config) (*Daemon, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeDevelopment
	}
	if cfg.Mode == ModeActive || cfg.Mode.Applies() {
		return nil, ErrActiveUnsupported
	}
	if cfg.Socket == "" {
		return nil, errors.New("thnd: a socket path is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now() }
	}
	if cfg.Logger == nil {
		// Not silently ignored: a daemon that cannot log is a daemon nobody
		// can diagnose, and returning the error matches the house style.
		lg, lerr := logging.New(logging.Options{
			Config:    config.LoggingConfig{Level: "info", Format: "text"},
			Component: "thnd",
		})
		if lerr != nil {
			return nil, fmt.Errorf("thnd: configuring logging: %w", lerr)
		}
		cfg.Logger = lg
	}

	d := &Daemon{
		cfg:      cfg,
		log:      cfg.Logger,
		observer: NewObserver(cfg.QoSInterface),
	}

	if cfg.StateDB != "" {
		store, err := state.Open(cfg.StateDB)
		if err != nil {
			return nil, fmt.Errorf("thnd: opening the state database: %w", err)
		}
		d.store = store
		d.loop = newLoop(d.observer, NewRecorder(store, 0), cfg.Interval, privileged())
	} else {
		d.loop = newLoop(d.observer, NewRecorder(nil, 0), cfg.Interval, privileged())
	}

	return d, nil
}

// Status describes the daemon.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	started := d.startedAt
	d.mu.Unlock()

	uptime := ""
	if !started.IsZero() {
		uptime = d.cfg.Now().Sub(started).Round(time.Second).String()
	}

	count, lastAt, lastErr := d.loop.counters()
	return Status{
		Mode:              d.cfg.Mode,
		ModeDescription:   d.cfg.Mode.Description(),
		StartedAt:         started,
		Uptime:            uptime,
		Socket:            d.cfg.Socket,
		Privileged:        privileged(),
		Observations:      count,
		LastObservationAt: lastAt,
		LastError:         lastErr,
		Applies:           d.cfg.Mode.Applies(),
		Verbs:             VerbNames(),
	}
}

// Run starts the daemon and blocks until the context is cancelled or a signal
// arrives.
//
// The observation loop starts before the socket does, so a client which
// connects immediately gets an answer rather than a refused connection.
func (d *Daemon) Run(ctx context.Context) error {
	d.mu.Lock()
	d.startedAt = d.cfg.Now()
	d.mu.Unlock()

	d.log.Info("thnd starting",
		"mode", string(d.cfg.Mode),
		"socket", d.cfg.Socket,
		"interval", d.cfg.Interval.String(),
		"privileged", privileged(),
		"applies", d.cfg.Mode.Applies(),
	)

	// Shut down cleanly on a signal. A daemon killed with SIGKILL leaves a
	// stale socket behind, and the next start then fails on a file with nobody
	// listening — which is the kind of failure that gets worked around by
	// deleting things, which is how sockets end up deleted while still in use.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The observation loop lives exactly as long as the socket does.
	loopCtx, stopLoop := context.WithCancel(ctx)
	defer stopLoop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.loop.run(loopCtx, d.cfg.Now)
	}()

	serveErr := d.serve(ctx)

	// Serving is over, so the loop has nothing left to observe through. This
	// matters most when serving ended in a refusal: without it, Run blocked in
	// wg.Wait until the caller cancelled a context it may not know is still
	// open, so a daemon that decided not to start looked exactly like a daemon
	// that started and was working quietly.
	stopLoop()
	wg.Wait()

	if serveErr != nil {
		return serveErr
	}

	count, _, _ := d.loop.counters()
	d.log.Info("thnd stopped", "observations", count)
	return nil
}

// Close releases resources.
func (d *Daemon) Close() error {
	if d.ln != nil {
		_ = d.ln.Close()
		d.ln = nil
	}
	if d.store != nil {
		return d.store.Close()
	}
	return nil
}

// ----------------------------------------------------------- the surface

// ErrUnknownVerb is returned for a verb the daemon does not serve.
var ErrUnknownVerb = errors.New("thnd: unknown verb")

// Verb is one query the daemon serves.
//
// Exported so the surface can be listed and asserted on from outside the
// package. A control surface that cannot be enumerated from outside is a
// control surface that can only be discovered by trying things.
//
// Handlers return values and never take them. There is deliberately no verb
// that writes, applies, activates or restarts anything, and the absence is
// structural: adding one means adding a function to this table, and that diff
// is what a reviewer sees.
type Verb struct {
	// Name is what a client sends.
	Name string

	// Description explains what it does.
	Description string

	run func(d *Daemon) (any, error)
}

// verbs is the complete query surface.
//
// Every entry here reads. If a future build needs one that writes, it is a
// different table in a different package behind the authority and reconciliation
// gates, and not an addition to this one.
//
// Populated in init rather than as a var literal because Status calls
// VerbNames, VerbNames reads this map, and one handler returns a Status — which
// Go reports as an initialisation cycle in a package-level initialiser. Moving
// the assignment into init breaks the static edge without changing what runs.
var verbs map[string]Verb

func init() {
	verbs = map[string]Verb{
		"status": {
			Name:        "status",
			Description: "what this daemon is and what it can do",
			run:         func(d *Daemon) (any, error) { return d.Status(), nil },
		},
		"observe": {
			Name:        "observe",
			Description: "take one observation of the host now and return it",
			run: func(d *Daemon) (any, error) {
				return d.loop.once(context.Background(), d.cfg.Now()), nil
			},
		},
		"last": {
			Name:        "last",
			Description: "the most recent observation, without taking a new one",
			run: func(d *Daemon) (any, error) {
				obs, ok := d.loop.latest()
				if !ok {
					return nil, errors.New("thnd: no observation has been taken yet")
				}
				return obs, nil
			},
		},
		"verbs": {
			Name:        "verbs",
			Description: "list the verbs this daemon serves",
			run:         func(d *Daemon) (any, error) { return VerbNames(), nil },
		},
		"ping": {
			Name:        "ping",
			Description: "confirm the daemon is answering",
			run: func(d *Daemon) (any, error) {
				return map[string]string{"pong": "thnd"}, nil
			},
		},
	}
}

// VerbNames returns the served verbs, sorted.
func VerbNames() []string {
	out := make([]string, 0, len(verbs))
	for name := range verbs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Verbs returns every verb with its description, sorted by name.
func Verbs() []Verb {
	out := make([]Verb, 0, len(verbs))
	for _, name := range VerbNames() {
		out = append(out, verbs[name])
	}
	return out
}

// Dispatch runs a verb and returns the JSON response.
//
// One entry point, used by the socket handler and by tests, so that what the
// tests exercise is what a client reaches.
func (d *Daemon) Dispatch(name string) ([]byte, error) {
	v, ok := verbs[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q; this daemon serves %v",
			ErrUnknownVerb, name, VerbNames())
	}

	result, err := v.run(d)
	if err != nil {
		return nil, err
	}

	body, merr := json.Marshal(map[string]any{
		"verb":    v.Name,
		"ok":      true,
		"result":  result,
		"served":  d.cfg.Now(),
		"applies": d.cfg.Mode.Applies(),
	})
	if merr != nil {
		return nil, merr
	}
	return body, nil
}

// --------------------------------------------------------- the socket

// Request is what a client sends.
//
// One field. A request that could carry a configuration or a command would be a
// request that could be doing something, and this one cannot.
type Request struct {
	// Verb is what to ask for.
	Verb string `json:"verb"`
}

// Response is what the daemon sends.
type Response struct {
	// Verb that was asked for.
	Verb string `json:"verb"`

	// OK reports success.
	OK bool `json:"ok"`

	// Result is the verb's value.
	Result json.RawMessage `json:"result,omitempty"`

	// Error explains a refusal.
	Error string `json:"error,omitempty"`

	// Served is when it was answered.
	Served time.Time `json:"served"`

	// Applies reports whether this daemon can change the host.
	Applies bool `json:"applies"`
}

// serve listens on the unix socket until the context is cancelled.
func (d *Daemon) serve(ctx context.Context) error {
	if err := clearStaleSocket(d.cfg.Socket); err != nil {
		return err
	}

	ln, err := net.Listen("unix", d.cfg.Socket)
	if err != nil {
		return fmt.Errorf("thnd: listening on %s: %w", d.cfg.Socket, err)
	}
	d.ln = ln

	// Owner-only. The socket is a control surface, and while every verb on it
	// only reads, the socket is what a future write verb would hang off.
	if err := os.Chmod(d.cfg.Socket, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("thnd: restricting the socket: %w", err)
	}

	defer func() {
		_ = ln.Close()
		_ = os.Remove(d.cfg.Socket)
	}()

	d.log.Info("thnd listening", "socket", d.cfg.Socket, "verbs", VerbNames())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("thnd: accept: %w", err)
		}
		go d.handle(conn)
	}
}

// clearStaleSocket prepares the socket path for listening.
//
// A socket left behind by an unclean exit would otherwise make Listen fail with
// "address already in use" for a file that nobody is listening on. That case is
// worth handling, but it is not the only case, and the code this replaced —
// removing the path unconditionally — could not tell the two apart.
//
// Unconditional removal trades a rare start-up failure for a worse one. A
// second daemon silently takes the path; the first keeps running on an unlinked
// socket that no client can reach; the operator sees exactly one daemon in ps
// and cannot connect to it. Probing first is the only way to tell a stale
// socket from a live one, so this fails closed on a live socket.
//
// Two things are refused outright rather than deleted:
//
//   - A live socket, because somebody is serving on it.
//   - Anything that is not a socket at all. The path comes from configuration,
//     and a regular file sitting there is somebody's data. Removing it is not
//     this daemon's decision to make.
//
// The check and the removal are not atomic. A daemon starting in exactly that
// window can still be displaced, which is why the answer is logged rather than
// assumed: the displaced daemon is visible as "already listening" in its own
// output.
func clearStaleSocket(path string) error {
	info, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return fmt.Errorf("thnd: inspecting %s: %w", path, err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("thnd: %s exists and is not a socket (mode %s); "+
			"refusing to remove it. Point paths.socket somewhere else, or remove it yourself",
			path, info.Mode())
	}

	conn, err := net.DialTimeout("unix", path, socketProbeTimeout)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("thnd: another daemon is already listening on %s; "+
			"refusing to start", path)
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("thnd: clearing the stale socket at %s: %w", path, err)
	}
	return nil
}

// handle answers one connection.
//
// One request per connection, then close. There is no persistent session and no
// pipelining, because a control surface with a session is a control surface
// with state, and state is where the interesting failures live.
func (d *Daemon) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResponse(conn, Response{
			Error:  fmt.Sprintf("could not read the request: %v", err),
			Served: d.cfg.Now(),
		})
		return
	}

	body, err := d.Dispatch(req.Verb)
	if err != nil {
		writeResponse(conn, Response{
			Verb:    req.Verb,
			Error:   err.Error(),
			Served:  d.cfg.Now(),
			Applies: d.cfg.Mode.Applies(),
		})
		return
	}

	var resp Response
	if uerr := json.Unmarshal(body, &resp); uerr != nil {
		writeResponse(conn, Response{
			Verb:    req.Verb,
			Error:   fmt.Sprintf("could not encode the result: %v", uerr),
			Served:  d.cfg.Now(),
			Applies: d.cfg.Mode.Applies(),
		})
		return
	}
	writeResponse(conn, resp)
}

func writeResponse(w net.Conn, r Response) {
	_ = w.SetDeadline(time.Now().Add(10 * time.Second))
	_ = json.NewEncoder(w).Encode(r)
}

// privileged reports whether the process can read privileged network state.
//
// Reported rather than assumed, because a daemon started unprivileged still has
// to work: it observes what it can and names what it could not. A build that
// refused to start without CAP_NET_ADMIN would be less useful on a machine
// where it is only ever going to observe.
func privileged() bool { return os.Geteuid() == 0 }

// currentOS reports the operating system.
//
// A variable so that tests can reason about an observation without the loop
// reaching for a real host.
var currentOS = func() string { return runtime.GOOS }
