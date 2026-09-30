package state

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenCreatesDirectoryAndSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "state.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	applied, version, err := s.SchemaInfo(context.Background())
	if err != nil {
		t.Fatalf("SchemaInfo: %v", err)
	}
	if version != SchemaVersion() {
		t.Errorf("version = %d, want %d", version, SchemaVersion())
	}
	if len(applied) != len(migrations) {
		t.Errorf("applied %d migrations, want %d", len(applied), len(migrations))
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer second.Close()

	_, version, err := second.SchemaInfo(context.Background())
	if err != nil {
		t.Fatalf("SchemaInfo: %v", err)
	}
	if version != SchemaVersion() {
		t.Errorf("re-opening applied version %d, want %d", version, SchemaVersion())
	}
}

func TestEventRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	want := Event{
		TS:         time.Now().UTC(),
		Level:      "warn",
		Component:  "network",
		Message:    "LAN interface not attached",
		Attrs:      map[string]string{"wan": "enp0s31f6", "detail": "not found"},
		Generation: 3,
	}

	if _, err := s.AppendEvent(ctx, want); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	got, err := s.QueryEvents(ctx, 10, "")
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}

	e := got[0]
	if e.Level != want.Level || e.Component != want.Component || e.Message != want.Message {
		t.Errorf("event = %+v, want %+v", e, want)
	}
	if e.Generation != want.Generation {
		t.Errorf("generation = %d, want %d", e.Generation, want.Generation)
	}
	if e.Attrs["wan"] != "enp0s31f6" {
		t.Errorf("attrs = %v, want wan=enp0s31f6", e.Attrs)
	}
}

func TestQueryEventsRespectsLevelFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, lvl := range []string{"info", "error", "info"} {
		if _, err := s.AppendEvent(ctx, Event{Level: lvl, Component: "test", Message: lvl}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.QueryEvents(ctx, 10, "error")
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != 1 || got[0].Level != "error" {
		t.Errorf("filtered events = %+v, want exactly one error event", got)
	}
}

func TestQueryEventsReturnsNewestFirst(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		msg := string(rune('a' + i))
		if _, err := s.AppendEvent(ctx, Event{Level: "info", Component: "t", Message: msg}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.QueryEvents(ctx, 3, "")
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3 (limit honoured)", len(got))
	}
	if got[0].Message != "e" {
		t.Errorf("newest event = %q, want %q", got[0].Message, "e")
	}
}

func TestPruneEventsRespectsCutoffAndLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	old := time.Now().UTC().Add(-48 * time.Hour)
	for i := 0; i < 5; i++ {
		if _, err := s.AppendEvent(ctx, Event{TS: old, Level: "info", Component: "t", Message: "old"}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := s.AppendEvent(ctx, Event{Level: "info", Component: "t", Message: "fresh"}); err != nil {
			t.Fatal(err)
		}
	}

	// A limit below the number of eligible rows proves pruning is bounded.
	deleted, err := s.PruneEvents(ctx, time.Now().UTC().Add(-24*time.Hour), 2)
	if err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted %d, want 2 (limit must bound each pass)", deleted)
	}

	deleted, err = s.PruneEvents(ctx, time.Now().UTC().Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
	if deleted != 3 {
		t.Errorf("deleted %d, want 3 remaining", deleted)
	}

	remaining, err := s.QueryEvents(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 3 {
		t.Errorf("remaining = %d, want 3 fresh events", len(remaining))
	}
}

func TestConfigRevisionUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.PutConfigRevision(ctx, ConfigRevision{
		Generation: 1, SchemaVer: 1, Document: "gen one", Source: "file", SHA256: "aaa",
	}); err != nil {
		t.Fatalf("PutConfigRevision: %v", err)
	}
	if err := s.PutConfigRevision(ctx, ConfigRevision{
		Generation: 1, SchemaVer: 1, Document: "gen one amended", Source: "file", SHA256: "bbb",
	}); err != nil {
		t.Fatalf("upsert PutConfigRevision: %v", err)
	}

	got, err := s.LatestConfigRevision(ctx)
	if err != nil {
		t.Fatalf("LatestConfigRevision: %v", err)
	}
	if got.Document != "gen one amended" {
		t.Errorf("document = %q, want the amended revision", got.Document)
	}
}

func TestLatestConfigRevisionNotFound(t *testing.T) {
	s := newTestStore(t)

	_, err := s.LatestConfigRevision(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestObservationLatestByKind(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, doc := range []string{"first", "second"} {
		if err := s.PutObservation(ctx, Observation{Kind: "interfaces", Document: doc}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutObservation(ctx, Observation{Kind: "routes", Document: "route-doc"}); err != nil {
		t.Fatal(err)
	}

	got, err := s.LatestObservation(ctx, "interfaces")
	if err != nil {
		t.Fatalf("LatestObservation: %v", err)
	}
	if got.Document != "second" {
		t.Errorf("document = %q, want %q", got.Document, "second")
	}

	if _, err := s.LatestObservation(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestPlanUpsertAndLatest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.PutPlan(ctx, Plan{ID: "p1", Generation: 1, Status: "ready", Summary: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPlan(ctx, Plan{ID: "p1", Generation: 1, Status: "superseded", Summary: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPlan(ctx, Plan{ID: "p2", Generation: 2, Status: "ready", Summary: "s2"}); err != nil {
		t.Fatal(err)
	}

	got, err := s.LatestPlan(ctx)
	if err != nil {
		t.Fatalf("LatestPlan: %v", err)
	}
	if got.ID != "p2" {
		t.Errorf("latest plan = %q, want p2", got.ID)
	}
}

func TestActivationRecorded(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.PutActivation(ctx, Activation{
		Generation: 1, FromState: "PREPARED", ToState: "ACTIVATING",
		Outcome: "refused", Reason: "no apply path in this build",
	}); err != nil {
		t.Fatalf("PutActivation: %v", err)
	}

	n, err := s.CountActivations(ctx)
	if err != nil {
		t.Fatalf("CountActivations: %v", err)
	}
	if n != 1 {
		t.Errorf("activations = %d, want 1 (refusals must still be audited)", n)
	}
}

func TestHealthReportsSchema(t *testing.T) {
	s := newTestStore(t)

	h, err := s.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h["exists"] != true {
		t.Error("Health should report the database as existing")
	}
	if h["database_version"] != SchemaVersion() {
		t.Errorf("database_version = %v, want %d", h["database_version"], SchemaVersion())
	}
	if _, ok := h["size_bytes"]; !ok {
		t.Error("Health should report a size")
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Error("Open(\"\") must fail")
	}
}

func TestOpenDoesNotLeakPreviousDatabase(t *testing.T) {
	// Each store must see its own data; a shared handle would let a test
	// observe another test's rows.
	a := newTestStore(t)
	b := newTestStore(t)
	ctx := context.Background()

	if _, err := a.AppendEvent(ctx, Event{Level: "info", Component: "t", Message: "only in a"}); err != nil {
		t.Fatal(err)
	}

	got, err := b.QueryEvents(ctx, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("store b sees %d events, want 0", len(got))
	}

	if !strings.HasSuffix(a.Path(), "state.db") {
		t.Errorf("unexpected path %q", a.Path())
	}
}
