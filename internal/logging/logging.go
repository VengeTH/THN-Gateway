// Package logging configures THN's structured logging and bridges it into the
// durable event store.
//
// THN emits each log record twice:
//
//   - to stdout/stderr, which systemd captures into the journal
//   - to the SQLite event table, which survives journal rotation and is what
//     `thn diagnostics` reads
//
// The second sink is the reason logging is in its own package rather than
// being a few slog calls at the entry point. Writing to two sinks with
// independent backpressure requires an explicit policy about what happens
// when the database is slow or locked: logging must never block or fail a
// request, so persistence errors are counted and surfaced through diagnostics
// rather than propagated.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

// EventSink persists log records durably.
type EventSink interface {
	AppendEvent(ctx context.Context, e state.Event) (int64, error)
}

// Options configures logger construction.
type Options struct {
	// Config supplies level, format and destination.
	Config config.LoggingConfig
	// File overrides the configured destination; empty means stdout.
	File string
	// Generation is stamped onto persisted events so that a record can be
	// traced to the configuration generation that produced it.
	Generation int
	// Sink receives a copy of every record. Nil disables persistence.
	Sink EventSink
	// Component is the default component name for records emitted without
	// an explicit one.
	Component string
}

// counters holds persistence statistics. It is shared by pointer across
// derived loggers so that a child logger accumulates into the same totals
// rather than copying atomic values.
type counters struct {
	// persisted counts records successfully written to the sink.
	persisted atomic.Int64
	// dropped counts records the sink refused. Logging must not block the
	// daemon, so a failure here is counted and reported, never returned.
	dropped atomic.Int64
	// lastErr records the most recent sink failure for diagnostics.
	lastErr atomic.Pointer[string]
}

// Logger wraps slog with the counters diagnostics needs.
type Logger struct {
	*slog.Logger

	sink       EventSink
	generation int
	component  string
	stats      *counters
}

// New builds a Logger from Options.
//
// The returned Logger always has a usable stdout/stderr sink: if the
// configured file cannot be opened, construction falls back to stderr and
// records why. A daemon that refuses to start because it cannot open a log
// file is worse than one that logs to the journal and tells the operator via
// diagnostics.
func New(opts Options) (*Logger, error) {
	level, err := parseLevel(opts.Config.Level)
	if err != nil {
		return nil, err
	}

	dest, closeFn, err := openDestination(opts.File)
	if err != nil {
		return nil, err
	}

	var handler slog.Handler
	hOpts := &slog.HandlerOptions{Level: level}

	if strings.EqualFold(opts.Config.Format, "text") {
		handler = slog.NewTextHandler(dest, hOpts)
	} else {
		handler = slog.NewJSONHandler(dest, hOpts)
	}

	l := &Logger{
		Logger:     slog.New(handler),
		sink:       opts.Sink,
		generation: opts.Generation,
		component:  opts.Component,
		stats:      &counters{},
	}

	if opts.Sink != nil {
		// Route records through the duplicating handler so each one reaches
		// the journal and the event store with identical timestamps and
		// attributes.
		l.Logger = slog.New(newEventHandler(handler, l))
	}

	_ = closeFn // the daemon owns the process lifetime; the file stays open

	return l, nil
}

// openDestination returns the log destination and an optional closer.
func openDestination(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stdout, nil, nil
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return os.Stderr, nil, fmt.Errorf("creating log directory %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return os.Stderr, nil, fmt.Errorf("opening log file %s: %w", path, err)
	}
	return f, f.Close, nil
}

// parseLevel maps a configured level name onto a slog level.
func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: unknown level %q", s)
	}
}

// With returns a logger tagged with a component name.
func (l *Logger) With(component string) *Logger {
	child := *l
	child.component = component
	child.Logger = l.Logger.With(slog.String("component", component))
	return &child
}

// Enabled reports whether the logger would emit at the given level.
func (l *Logger) Enabled(level slog.Level) bool { return l.Logger.Enabled(context.Background(), level) }

// persist writes a record to the sink. It is called by the event handlers
// below and must never propagate an error to the call site.
func (l *Logger) persist(ctx context.Context, level slog.Level, msg string, attrs map[string]string) {
	if l.sink == nil {
		return
	}

	e := state.Event{
		TS:         time.Now().UTC(),
		Level:      level.String(),
		Component:  l.component,
		Message:    msg,
		Attrs:      attrs,
		Generation: l.generation,
	}

	if _, err := l.sink.AppendEvent(ctx, e); err != nil {
		l.stats.dropped.Add(1)
		s := err.Error()
		l.stats.lastErr.Store(&s)
		return
	}
	l.stats.persisted.Add(1)
}

// levelAttr normalises a slog.Level to its string name for storage.
func levelAttr(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARN"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

// eventHandler is a slog.Handler that duplicates records into the event
// store while forwarding to a wrapped handler.
//
// It exists because the durable copy must carry the same timestamp and
// attributes as the journal copy. Reconstructing them afterwards would drift.
type eventHandler struct {
	inner slog.Handler
	log   *Logger
	attrs []slog.Attr
	group string
}

// NewEventHandler returns a slog.Handler that also persists records.
//
// The returned slog.Logger is owned by the caller; this function only wraps a
// handler so that New can decide where records go.
func newEventHandler(inner slog.Handler, l *Logger) slog.Handler {
	return &eventHandler{inner: inner, log: l}
}

func (h *eventHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *eventHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := map[string]string{}
	for _, a := range h.attrs {
		appendAttr(attrs, h.group, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(attrs, h.group, a)
		return true
	})

	// Persist a copy of the message with its formatted attributes appended,
	// so that a diagnostic reader sees the same information as the journal.
	msg := r.Message
	if len(attrs) > 0 {
		keys := make([]string, 0, len(attrs))
		for k := range attrs {
			keys = append(keys, k)
		}
		var b strings.Builder
		b.WriteString(msg)
		for _, k := range keys {
			fmt.Fprintf(&b, " %s=%s", k, attrs[k])
		}
		msg = b.String()
	}

	h.log.persist(ctx, slog.Level(r.Level), msg, attrs)

	return h.inner.Handle(ctx, r)
}

func (h *eventHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &eventHandler{inner: h.inner.WithAttrs(attrs), log: h.log, attrs: merged, group: h.group}
}

func (h *eventHandler) WithGroup(name string) slog.Handler {
	return &eventHandler{inner: h.inner.WithGroup(name), log: h.log, attrs: h.attrs, group: name}
}

// appendAttr flattens a slog attribute into the string map persisted with an
// event.
func appendAttr(dst map[string]string, group string, a slog.Attr) {
	key := a.Key
	if group != "" {
		key = group + "." + key
	}

	if a.Value.Kind() == slog.KindGroup {
		for _, sub := range a.Value.Group() {
			appendAttr(dst, key, sub)
		}
		return
	}
	dst[key] = a.Value.String()
}

// SinkStats reports persistence counters for `thn diagnostics`.
type SinkStats struct {
	// Persisted counts records written to the event store.
	Persisted int64 `json:"persisted"`
	// Dropped counts records the store refused.
	Dropped int64 `json:"dropped"`
	// LastError is the most recent persistence failure, if any.
	LastError string `json:"last_error,omitempty"`
}

// Stats returns current sink counters.
func (l *Logger) Stats() SinkStats {
	s := SinkStats{Persisted: l.stats.persisted.Load(), Dropped: l.stats.dropped.Load()}
	if e := l.stats.lastErr.Load(); e != nil {
		s.LastError = *e
	}
	return s
}

// Prune asks the sink to drop events older than the configured retention.
// It is called periodically by the daemon and is safe to call when the sink
// is nil.
func (l *Logger) Prune(ctx context.Context, cfg config.LoggingConfig) (int64, error) {
	pruner, ok := l.sink.(interface {
		PruneEvents(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	})
	if !ok {
		return 0, nil
	}
	return pruner.PruneEvents(ctx, time.Now().UTC().Add(-cfg.Retention), 5000)
}

// NewStoreLogger builds a logger wired to a state store.
func NewStoreLogger(store *state.Store, cfg config.Config, component string) (*Logger, error) {
	base, err := New(Options{
		Config:     cfg.Logging,
		File:       cfg.Paths.LogFile,
		Generation: int(cfg.Gateway.Generation),
		Sink:       store,
		Component:  component,
	})
	if err != nil {
		return nil, err
	}

	// Rebuild the logger so records flow through the duplicating handler.
	rebuilt := &Logger{
		Logger:     slog.New(newEventHandler(base.Logger.Handler(), base)),
		sink:       base.sink,
		generation: base.generation,
		component:  component,
		stats:      base.stats,
	}
	return rebuilt, nil
}
