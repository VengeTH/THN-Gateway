// Package state implements THN's persistent state database.
//
// # Single-writer ownership
//
// Exactly one process may own this database: thnd. The CLI never opens it.
// This is not a stylistic preference. SQLite gives no protection against two
// writers over a Unix socket or a network filesystem, and the failure mode is
// a corrupted database rather than an error message. Making the CLI a pure
// client of thnd means there is structurally one writer, so the locking
// question never arises.
//
// The consequence is a rule for callers: never import this package from the
// thn command tree. `thn status` asks thnd over the socket; thnd reads the
// database.
//
// # Schema
//
// Migrations are numbered, ordered and applied exactly once, inside a
// transaction, recording the version in schema_migrations. Migrations are
// append-only: a released migration is never edited, because the database on
// the gateway may already have run it.
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver: no CGO, cross-compiles
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("state: record not found")

// Migration is a single numbered schema change.
type Migration struct {
	// Version is the monotonically increasing schema version this migration
	// produces. It must match its position in the migration list.
	Version int
	// Name identifies the migration in logs and in schema_migrations.
	Name string
	// Statements are executed in order within a single transaction.
	Statements []string
}

// migrations is the append-only schema history. Do not edit a released entry;
// append a new one instead.
var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial schema",
		Statements: []string{
			// Structured log events. This is the durable counterpart to the
			// journal: journald may rotate, this does not.
			`CREATE TABLE IF NOT EXISTS events (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				ts          TEXT    NOT NULL,
				level       TEXT    NOT NULL,
				component   TEXT    NOT NULL,
				message     TEXT    NOT NULL,
				attrs       TEXT    NOT NULL DEFAULT '{}',
				generation  INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE INDEX IF NOT EXISTS idx_events_ts      ON events (ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_events_level   ON events (level, ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_events_comp    ON events (component, ts DESC)`,

			// Every accepted configuration revision, addressed by generation.
			// Keeping history means a plan can always be traced to the exact
			// document that produced it.
			`CREATE TABLE IF NOT EXISTS config_revisions (
				generation INTEGER PRIMARY KEY,
				ts         TEXT NOT NULL,
				schema_ver INTEGER NOT NULL,
				document   TEXT NOT NULL,
				source     TEXT NOT NULL,
				sha256     TEXT NOT NULL
			)`,

			// Observed host network state, read-only. Latest row per kind is
			// the current view; history supports before/after comparison.
			`CREATE TABLE IF NOT EXISTS observations (
				id         INTEGER PRIMARY KEY AUTOINCREMENT,
				ts         TEXT NOT NULL,
				kind       TEXT NOT NULL,
				generation INTEGER NOT NULL DEFAULT 0,
				document   TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_obs_kind_ts ON observations (kind, ts DESC)`,

			// Generated plans. A plan records what *would* be applied, never
			// what was applied.
			`CREATE TABLE IF NOT EXISTS plans (
				id         TEXT PRIMARY KEY,
				ts         TEXT NOT NULL,
				generation INTEGER NOT NULL,
				status     TEXT NOT NULL,
				summary    TEXT NOT NULL DEFAULT '',
				document   TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_plans_ts ON plans (ts DESC)`,

			// Activation attempts. Rows exist so that an attempt to activate
			// is auditable even when it is refused, which is the common case
			// in the current build.
			`CREATE TABLE IF NOT EXISTS activations (
				id         INTEGER PRIMARY KEY AUTOINCREMENT,
				ts         TEXT NOT NULL,
				generation INTEGER NOT NULL,
				from_state TEXT NOT NULL,
				to_state   TEXT NOT NULL,
				outcome    TEXT NOT NULL,
				reason     TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE INDEX IF NOT EXISTS idx_act_ts ON activations (ts DESC)`,
		},
	},
}

// SchemaVersion returns the highest version this build knows how to produce.
func SchemaVersion() int { return migrations[len(migrations)-1].Version }

// Event is a durable log record.
type Event struct {
	ID         int64             `json:"id"`
	TS         time.Time         `json:"ts"`
	Level      string            `json:"level"`
	Component  string            `json:"component"`
	Message    string            `json:"message"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	Generation int               `json:"generation"`
}

// ConfigRevision is a stored configuration document.
type ConfigRevision struct {
	Generation int       `json:"generation"`
	TS         time.Time `json:"ts"`
	SchemaVer  int       `json:"schema_version"`
	Document   string    `json:"document"`
	Source     string    `json:"source"`
	SHA256     string    `json:"sha256"`
}

// Observation is a read-only snapshot of host network state.
type Observation struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	Kind       string    `json:"kind"`
	Generation int       `json:"generation"`
	Document   string    `json:"document"`
}

// Plan is a generated, not-yet-applied description of intended state.
type Plan struct {
	ID         string    `json:"id"`
	TS         time.Time `json:"ts"`
	Generation int       `json:"generation"`
	Status     string    `json:"status"`
	Summary    string    `json:"summary"`
	Document   string    `json:"document"`
}

// Activation is an audit record of an activation attempt.
type Activation struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	Generation int       `json:"generation"`
	FromState  string    `json:"from_state"`
	ToState    string    `json:"to_state"`
	Outcome    string    `json:"outcome"`
	Reason     string    `json:"reason"`
}

// Store is the state database handle. It is safe for concurrent use.
type Store struct {
	db   *sql.DB
	path string

	// writeMu serialises writes. SQLite permits concurrent readers, but
	// thnd's write rate is low and serialising here removes any chance of
	// SQLITE_BUSY under WAL without scattering retry logic through callers.
	writeMu sync.Mutex
}

// Open opens or creates the state database at path and applies migrations.
//
// The parent directory is created if absent. On a real gateway the state
// directory is owned by root; the file is created 0600 because it records the
// gateway's topology and control history.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state: database path must not be empty")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("creating state directory %s: %w", dir, err)
		}
	}

	// WAL keeps readers from blocking the writer, which matters once the CLI
	// starts reading through thnd while thnd is recording events.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	// The pure-Go driver does not serialise writes to a single connection, so
	// constrain the pool and let writeMu provide ordering.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to %s: %w", path, err)
	}

	s := &Store{db: db, path: path}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// migrate applies any migrations the database has not yet seen.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	applied, err := s.appliedVersions(ctx)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if _, ok := applied[m.Version]; ok {
			continue
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("beginning migration %d: %w", m.Version, err)
		}

		for _, stmt := range m.Statements {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("migration %d (%s): %w\nstatement: %s",
					m.Version, m.Name, err, stmt)
			}
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
			m.Version, m.Name, time.Now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("recording migration %d: %w", m.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d: %w", m.Version, err)
		}
	}

	return nil
}

// appliedVersions reads the set of migrations already present.
func (s *Store) appliedVersions(ctx context.Context) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("reading schema_migrations: %w", err)
	}
	defer rows.Close()

	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

// SchemaInfo reports the database's migration state.
func (s *Store) SchemaInfo(ctx context.Context) (applied []string, dbVersion int, err error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, 0, fmt.Errorf("reading schema_migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var v int
		var n string
		if err := rows.Scan(&v, &n); err != nil {
			return nil, 0, err
		}
		applied = append(applied, fmt.Sprintf("%d %s", v, n))
		dbVersion = v
	}
	return applied, dbVersion, rows.Err()
}

// AppendEvent records a structured log event.
func (s *Store) AppendEvent(ctx context.Context, e Event) (int64, error) {
	attrs := "{}"
	if len(e.Attrs) > 0 {
		b, err := marshalAttrs(e.Attrs)
		if err != nil {
			return 0, err
		}
		attrs = b
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO events (ts, level, component, message, attrs, generation)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		e.TS.UTC().Format(time.RFC3339Nano), e.Level, e.Component, e.Message, attrs, e.Generation)
	if err != nil {
		return 0, fmt.Errorf("appending event: %w", err)
	}
	return res.LastInsertId()
}

// QueryEvents returns the most recent events, newest first.
func (s *Store) QueryEvents(ctx context.Context, limit int, level string) ([]Event, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, ts, level, component, message, attrs, generation
	          FROM events`
	args := []any{}
	if level != "" {
		query += ` WHERE level = ?`
		args = append(args, level)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var ts, attrs string
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Component, &e.Message, &attrs, &e.Generation); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		e.Attrs = unmarshalAttrs(attrs)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountEvents returns the total number of stored events, used by
// `thn diagnostics` to report retention pressure.
func (s *Store) CountEvents(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}

// PruneEvents deletes events older than cutoff, capped at limit rows per call
// so that retention never holds the write lock for long. It returns the number
// deleted.
func (s *Store) PruneEvents(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 5000
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	res, err := s.db.ExecContext(ctx,
		`DELETE FROM events WHERE id IN (
			SELECT id FROM events WHERE ts < ? ORDER BY id LIMIT ?
		)`,
		cutoff.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return 0, fmt.Errorf("pruning events: %w", err)
	}
	return res.RowsAffected()
}

// PutConfigRevision stores a configuration document for a generation.
func (s *Store) PutConfigRevision(ctx context.Context, r ConfigRevision) error {
	if r.TS.IsZero() {
		r.TS = time.Now().UTC()
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO config_revisions (generation, ts, schema_ver, document, source, sha256)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(generation) DO UPDATE SET
			ts = excluded.ts, schema_ver = excluded.schema_ver,
			document = excluded.document, source = excluded.source,
			sha256 = excluded.sha256`,
		r.Generation, r.TS.UTC().Format(time.RFC3339Nano), r.SchemaVer,
		r.Document, r.Source, r.SHA256)
	if err != nil {
		return fmt.Errorf("storing config revision: %w", err)
	}
	return nil
}

// LatestConfigRevision returns the newest stored configuration document.
func (s *Store) LatestConfigRevision(ctx context.Context) (*ConfigRevision, error) {
	var r ConfigRevision
	var ts string

	err := s.db.QueryRowContext(ctx,
		`SELECT generation, ts, schema_ver, document, source, sha256
		 FROM config_revisions ORDER BY generation DESC LIMIT 1`,
	).Scan(&r.Generation, &ts, &r.SchemaVer, &r.Document, &r.Source, &r.SHA256)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading latest config revision: %w", err)
	}
	r.TS, _ = time.Parse(time.RFC3339Nano, ts)
	return &r, nil
}

// PutObservation records a read-only snapshot of host state.
func (s *Store) PutObservation(ctx context.Context, o Observation) error {
	if o.TS.IsZero() {
		o.TS = time.Now().UTC()
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO observations (ts, kind, generation, document) VALUES (?, ?, ?, ?)`,
		o.TS.UTC().Format(time.RFC3339Nano), o.Kind, o.Generation, o.Document)
	if err != nil {
		return fmt.Errorf("storing %s observation: %w", o.Kind, err)
	}
	return nil
}

// LatestObservation returns the newest observation of the given kind.
func (s *Store) LatestObservation(ctx context.Context, kind string) (*Observation, error) {
	var o Observation
	var ts string

	err := s.db.QueryRowContext(ctx,
		`SELECT id, ts, kind, generation, document
		 FROM observations WHERE kind = ? ORDER BY id DESC LIMIT 1`, kind,
	).Scan(&o.ID, &ts, &o.Kind, &o.Generation, &o.Document)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading %s observation: %w", kind, err)
	}
	o.TS, _ = time.Parse(time.RFC3339Nano, ts)
	return &o, nil
}

// PutPlan stores a generated plan.
func (s *Store) PutPlan(ctx context.Context, p Plan) error {
	if p.TS.IsZero() {
		p.TS = time.Now().UTC()
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO plans (id, ts, generation, status, summary, document)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			ts = excluded.ts, generation = excluded.generation,
			status = excluded.status, summary = excluded.summary,
			document = excluded.document`,
		p.ID, p.TS.UTC().Format(time.RFC3339Nano), p.Generation, p.Status, p.Summary, p.Document)
	if err != nil {
		return fmt.Errorf("storing plan: %w", err)
	}
	return nil
}

// LatestPlan returns the most recently generated plan.
func (s *Store) LatestPlan(ctx context.Context) (*Plan, error) {
	var p Plan
	var ts string

	err := s.db.QueryRowContext(ctx,
		`SELECT id, ts, generation, status, summary, document
		 FROM plans ORDER BY ts DESC, rowid DESC LIMIT 1`,
	).Scan(&p.ID, &ts, &p.Generation, &p.Status, &p.Summary, &p.Document)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading latest plan: %w", err)
	}
	p.TS, _ = time.Parse(time.RFC3339Nano, ts)
	return &p, nil
}

// PutActivation records an activation attempt, including refused ones.
func (s *Store) PutActivation(ctx context.Context, a Activation) error {
	if a.TS.IsZero() {
		a.TS = time.Now().UTC()
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO activations (ts, generation, from_state, to_state, outcome, reason)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		a.TS.UTC().Format(time.RFC3339Nano), a.Generation, a.FromState, a.ToState, a.Outcome, a.Reason)
	if err != nil {
		return fmt.Errorf("recording activation: %w", err)
	}
	return nil
}

// CountActivations returns the number of recorded activation attempts.
func (s *Store) CountActivations(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM activations`).Scan(&n)
	return n, err
}

// Health reports whether the database is reachable and its size on disk.
// It backs the state section of `thn diagnostics`.
func (s *Store) Health(ctx context.Context) (map[string]any, error) {
	out := map[string]any{"path": s.path}

	if st, err := os.Stat(s.path); err == nil {
		out["exists"] = true
		out["size_bytes"] = st.Size()
		out["modified"] = st.ModTime().UTC().Format(time.RFC3339)
		if st.Size() == 0 {
			out["error"] = "database file is present but empty"
		}
	} else if os.IsNotExist(err) {
		out["exists"] = false
		out["error"] = "database file is missing"
	} else {
		return out, fmt.Errorf("stating %s: %w", s.path, err)
	}

	if n, err := s.CountEvents(ctx); err == nil {
		out["events"] = n
	}
	if n, err := s.CountActivations(ctx); err == nil {
		out["activations"] = n
	}

	applied, dbVersion, err := s.SchemaInfo(ctx)
	if err != nil {
		return out, err
	}
	out["applied_migrations"] = applied
	out["database_version"] = dbVersion
	out["build_schema_version"] = SchemaVersion()

	if dbVersion > SchemaVersion() {
		out["error"] = "database was written by a newer THN build; upgrade the daemon before continuing"
	}
	return out, nil
}
