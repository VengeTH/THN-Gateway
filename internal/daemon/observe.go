package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/venth/thn-gateway/internal/firewall"
	"github.com/venth/thn-gateway/internal/network"
	"github.com/venth/thn-gateway/internal/state"
)

// Observation is one look at the host.
//
// Every field is optional. That is not sloppiness: which fields are populated
// depends on what the daemon is privileged to read, and a daemon started
// unprivileged still gets a useful observation of the network. The fields it
// could not read are named in Unreadable rather than being left nil and
// silently indistinguishable from "nothing to report".
type Observation struct {
	// At is when the observation finished.
	At time.Time `json:"at"`

	// Platform is the operating system, for the record.
	Platform string `json:"platform"`

	// HostSupported reports whether the network could be read at all.
	HostSupported bool `json:"host_supported"`

	// Network is the host's network state, when readable.
	Network *network.Snapshot `json:"network,omitempty"`

	// Firewall is the loaded ruleset, when the daemon could read it.
	//
	// Reading nftables state needs CAP_NET_ADMIN. An unprivileged daemon
	// leaves this nil and names it in Unreadable.
	Firewall *firewall.FirewallState `json:"firewall,omitempty"`

	// QoS is the queue-discipline state, when readable.
	QoS *firewall.QoSState `json:"qos,omitempty"`

	// Unreadable names what this observation could not see.
	//
	// A list rather than a flag, because the interesting case is partial: a
	// daemon that can read the network but not the firewall has half an
	// observation, and "half" is more useful than "no".
	Unreadable []string `json:"unreadable,omitempty"`
}

// Completeness describes how much of the host this observation covered.
//
// Used by callers that need to know whether a gap is a fault or a privilege.
// An observation missing the firewall because the daemon is unprivileged is a
// normal state; one missing it because nft is not installed is a finding.
func (o Observation) Completeness() string {
	switch {
	case !o.HostSupported:
		return "none: the host network could not be read"
	case len(o.Unreadable) == 0:
		return "full"
	case len(o.Unreadable) == 1 && o.Unreadable[0] == ReasonFirewall:
		return "network only: firewall and shaping were not readable"
	default:
		return "partial: " + joinReasons(o.Unreadable)
	}
}

// Reason names for things an observation could not see.
const (
	// ReasonFirewall means the nftables state was unreadable.
	ReasonFirewall = "firewall state"

	// ReasonQoS means the queue-discipline state was unreadable.
	ReasonQoS = "shaping state"

	// ReasonHost means the host network itself was unreadable.
	ReasonHost = "host network"
)

func joinReasons(rs []string) string {
	out := ""
	for i, r := range rs {
		switch {
		case i == 0:
			out = r
		case i == len(rs)-1:
			out += " and " + r
		default:
			out += ", " + r
		}
	}
	return out
}

// Observer takes observations of the host.
//
// An interface rather than a direct call so that the daemon's loop can be
// tested without a Linux host — which matters more here than usual, because
// the loop is the only thing in the daemon that runs unattended on a machine
// nobody can reach.
type Observer interface {
	Observe(ctx context.Context, at time.Time) Observation
}

// observer is the real implementation, reading through internal/guard.
type observer struct {
	// qosDevice is the interface to read shaping state from, if configured.
	qosDevice string
}

// NewObserver returns an Observer reading the host.
//
// qosDevice may be empty, in which case shaping is not observed: asking tc
// about a device that is not there produces a failure rather than an answer.
func NewObserver(qosDevice string) Observer {
	return &observer{qosDevice: qosDevice}
}

// Observe takes one look at the host.
//
// It never returns an error. A host that cannot be read produces an Observation
// saying so, because an observer that fails makes the daemon's loop decide
// what a failure means, and "the host is unreadable" is a fact the loop should
// be recording rather than handling.
func (o *observer) Observe(ctx context.Context, at time.Time) Observation {
	obs := Observation{
		At:       at.UTC(),
		Platform: currentOS(),
	}

	snap, err := network.NewInspector().Inspect(ctx)
	switch {
	case err != nil:
		obs.Unreadable = append(obs.Unreadable, ReasonHost)
	case snap == nil || !snap.Supported:
		obs.Unreadable = append(obs.Unreadable, ReasonHost)
	default:
		obs.HostSupported = true
		obs.Network = snap
	}

	// The firewall and shaping observers both shell out through internal/guard
	// and both need privilege the daemon may not have. A failure here is a
	// partial observation, not a failed one.
	fo := firewall.NewObserver()

	if fw := fo.ObserveFirewall(ctx); fw != nil && fw.Status != firewall.StatusUnknown {
		obs.Firewall = fw
	} else {
		obs.Unreadable = append(obs.Unreadable, ReasonFirewall)
	}

	if o.qosDevice != "" {
		if qs := fo.ObserveQoS(ctx, o.qosDevice); qs != nil && qs.Status != firewall.StatusUnknown {
			obs.QoS = qs
		} else {
			obs.Unreadable = append(obs.Unreadable, ReasonQoS)
		}
	} else {
		obs.Unreadable = append(obs.Unreadable, ReasonQoS)
	}

	return obs
}

// Recorder persists observations so that history survives a restart.
//
// Durable history is the reason the daemon exists at all in this phase. An
// operator asking what this host was doing at three in the morning cannot be
// answered by a process that was not running then.
type Recorder interface {
	Record(ctx context.Context, o Observation) error
}

// storeRecorder writes to the state database.
//
// The observation is stored as a JSON document under a single kind rather than
// as columns, because the shape of an observation is still changing and a
// schema migration for every field added to a periodic record would be a poor
// trade this early.
type storeRecorder struct {
	store      *state.Store
	generation uint64
	mu         sync.Mutex
}

// NewRecorder returns a Recorder writing to a state store.
//
// A nil store yields a recorder that discards, because an unconfigured daemon
// is a legitimate thing to run for its observation loop alone, and refusing to
// start would make the first run the most awkward one.
func NewRecorder(store *state.Store, generation uint64) Recorder {
	return &storeRecorder{store: store, generation: generation}
}

// Record writes one observation.
func (r *storeRecorder) Record(ctx context.Context, o Observation) error {
	if r.store == nil {
		return nil
	}

	doc, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("thnd: encoding observation: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return r.store.PutObservation(ctx, state.Observation{
		Kind:       "host",
		TS:         o.At,
		Document:   string(doc),
		Generation: int(r.generation),
	})
}

// loop runs an Observer on an interval and keeps the latest result.
//
// The interval is not a constant here because it is a deployment decision, not
// a code one: a gateway on a metered link and a gateway on a bench want
// different cadences.
type loop struct {
	observer   Observer
	recorder   Recorder
	interval   time.Duration
	privileged bool

	mu       sync.Mutex
	last     Observation
	count    int64
	lastErr  string
	lastAt   time.Time
	haveLast bool
}

func newLoop(o Observer, r Recorder, interval time.Duration, privileged bool) *loop {
	return &loop{observer: o, recorder: r, interval: interval, privileged: privileged}
}

// once takes a single observation and stores it.
//
// Exported through the daemon's `observe` verb so that an operator can ask for
// a reading now rather than waiting for the next tick — which is the difference
// between a diagnostic and a guess.
func (l *loop) once(ctx context.Context, at time.Time) Observation {
	obs := l.observer.Observe(ctx, at)

	l.mu.Lock()
	l.last = obs
	l.lastAt = obs.At
	l.haveLast = true
	l.count++
	l.mu.Unlock()

	if l.recorder != nil {
		if err := l.recorder.Record(ctx, obs); err != nil {
			l.mu.Lock()
			l.lastErr = err.Error()
			l.mu.Unlock()
		} else {
			l.mu.Lock()
			l.lastErr = ""
			l.mu.Unlock()
		}
	}

	return obs
}

// run ticks until the context is cancelled.
//
// It observes immediately rather than after the first interval, because a
// daemon that reports nothing for its first interval has answered the operator
// who started it with silence.
func (l *loop) run(ctx context.Context, now func() time.Time) {
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()

	l.once(ctx, now())

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.once(ctx, now())
		}
	}
}

// latest returns the most recent observation.
func (l *loop) latest() (Observation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last, l.haveLast
}

// counters returns how many observations have run and the last error.
func (l *loop) counters() (int64, time.Time, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count, l.lastAt, l.lastErr
}
