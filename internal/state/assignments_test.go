package state

// Assignment persistence, asserted at the storage layer.
//
// The CLI tests cover the command surface; these cover the guarantees the
// storage itself makes, because a caller that reaches this package directly —
// thnd, a future tool, a script — must get the same semantics the CLI
// documents. A guarantee that lives only in a command is not a guarantee.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// put is a small helper for the write paths the tests exercise.
func put(t *testing.T, s *Store, a InterfaceAssignment) (*InterfaceAssignment, *AssignmentConflict, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.PutAssignment(ctx, a)
}

// TestAssignmentsSurviveReopening is the persistence claim.
func TestAssignmentsSurviveReopening(t *testing.T) {
	path := t.TempDir() + "/state.db"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, _, err := first.PutAssignment(ctx, InterfaceAssignment{
		Role: "wan", Selector: "hw:0123456789abcdef", IDKind: "hardware",
	}); err != nil {
		t.Fatalf("PutAssignment: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer second.Close()

	got, err := second.ListAssignments(ctx)
	if err != nil {
		t.Fatalf("ListAssignments: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d assignments after reopening, want 1", len(got))
	}
	if got[0].Selector != "hw:0123456789abcdef" {
		t.Errorf("selector = %q", got[0].Selector)
	}
	if got[0].AssignedAt == "" {
		t.Error("no timestamp was recorded")
	}
}

// TestAnAssignmentTableMigratesOnAnExistingDatabase is the upgrade path.
//
// A gateway deployed before this milestone already has a database. Opening it
// must apply migration 2 without disturbing anything.
func TestAnAssignmentTableMigratesOnAnExistingDatabase(t *testing.T) {
	path := t.TempDir() + "/state.db"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Build a database as version 1 would have left it.
	old, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := old.AppendEvent(ctx, Event{Level: "info", Component: "test", Message: "before"}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	if _, err := old.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version > 1`); err != nil {
		t.Fatalf("rewinding the schema: %v", err)
	}
	if _, err := old.db.ExecContext(ctx, `DROP TABLE interface_assignments`); err != nil {
		t.Fatalf("dropping the new table: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopening after downgrade: %v", err)
	}
	defer reopened.Close()

	if _, _, err := put(t, reopened, InterfaceAssignment{Role: "lan", Selector: "hw:aa"}); err != nil {
		t.Fatalf("the assignment table was not migrated: %v", err)
	}
	n, err := reopened.CountEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("the migration discarded existing data")
	}
}

// TestRoleIsThePrimaryKey is single-valued-ness as a storage guarantee.
func TestRoleIsThePrimaryKey(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	put(t, s, InterfaceAssignment{Role: "wan", Selector: "hw:aa"})
	put(t, s, InterfaceAssignment{Role: "wan", Selector: "hw:bb"})

	got, err := s.ListAssignments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("a single role produced %d rows; it is single-valued", len(got))
	}
	if got[0].Selector != "hw:bb" {
		t.Errorf("selector = %q, want the replacement hw:bb", got[0].Selector)
	}
}

// TestOneInterfaceCannotHoldTwoRoles is the other half of the constraint.
func TestOneInterfaceCannotHoldTwoRoles(t *testing.T) {
	s := newTestStore(t)

	put(t, s, InterfaceAssignment{Role: "wan", Selector: "hw:aa"})

	prev, conflict, err := put(t, s, InterfaceAssignment{Role: "lan", Selector: "hw:aa"})
	if !errors.Is(err, ErrAssignmentConflict) {
		t.Fatalf("err = %v, want ErrAssignmentConflict", err)
	}
	if conflict == nil {
		t.Fatal("no conflict was described")
	}
	if conflict.ExistingRole != "wan" || conflict.WantedRole != "lan" {
		t.Errorf("conflict = %+v", conflict)
	}
	if prev != nil {
		t.Errorf("a refused write reported a replacement: %+v", prev)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, _ := s.ListAssignments(ctx)
	if len(got) != 1 || got[0].Role != "wan" {
		t.Errorf("the store changed despite the refusal: %+v", got)
	}
}

// TestAMoveReportsWhatItReplaced is the audit requirement.
func TestAMoveReportsWhatItReplaced(t *testing.T) {
	s := newTestStore(t)

	put(t, s, InterfaceAssignment{Role: "wan", Selector: "hw:aa"})
	prev, conflict, err := put(t, s, InterfaceAssignment{Role: "wan", Selector: "hw:bb"})

	if err != nil || conflict != nil {
		t.Fatalf("moving a role must succeed: err=%v conflict=%+v", err, conflict)
	}
	if prev == nil || prev.Selector != "hw:aa" || prev.AssignedAt == "" {
		t.Errorf("the replaced binding was not described: %+v", prev)
	}
}

// TestEmptyFieldsAreRefused rather than stored as blank rows.
func TestEmptyFieldsAreRefused(t *testing.T) {
	s := newTestStore(t)

	if _, _, err := put(t, s, InterfaceAssignment{Role: "", Selector: "hw:aa"}); err == nil {
		t.Error("an assignment with no role was accepted")
	}
	if _, _, err := put(t, s, InterfaceAssignment{Role: "wan", Selector: "   "}); err == nil {
		t.Error("an assignment with a blank selector was accepted")
	}
}

// TestDeleteReportsWhetherAnythingWasRemoved keeps the two answers apart.
func TestDeleteReportsWhetherAnythingWasRemoved(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if removed, err := s.DeleteAssignment(ctx, "wan"); err != nil || removed {
		t.Errorf("removing a binding that never existed: removed=%v err=%v", removed, err)
	}

	put(t, s, InterfaceAssignment{Role: "wan", Selector: "hw:aa"})
	if removed, err := s.DeleteAssignment(ctx, "wan"); err != nil || !removed {
		t.Errorf("removing an existing binding: removed=%v err=%v", removed, err)
	}
}

// TestDeleteBySelectorWorksWhenTheHardwareIsGone is the case the selector
// form exists for: the operator can no longer look the interface up, because
// it is not there, and the stored selector is all they have.
func TestDeleteBySelectorWorksWhenTheHardwareIsGone(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	put(t, s, InterfaceAssignment{Role: "wan", Selector: "hw:missing"})

	role, removed, err := s.DeleteAssignmentBySelector(ctx, "hw:missing")
	if err != nil || !removed {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	if role != "wan" {
		t.Errorf("role = %q, want wan", role)
	}

	if _, removed, _ := s.DeleteAssignmentBySelector(ctx, "hw:missing"); removed {
		t.Error("a second removal reported success")
	}
}

// TestListOrderingIsStableByRole makes two runs diffable.
func TestListOrderingIsStableByRole(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, r := range []string{"wan", "mgmt", "lan", "dmz", "guest"} {
		put(t, s, InterfaceAssignment{Role: r, Selector: "hw:" + r})
	}

	first, _ := s.ListAssignments(ctx)
	second, _ := s.ListAssignments(ctx)
	if len(first) != 5 {
		t.Fatalf("got %d assignments", len(first))
	}
	for i := range first {
		if first[i].Role != second[i].Role {
			t.Fatalf("two listings disagree at %d: %q vs %q", i, first[i].Role, second[i].Role)
		}
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].Role >= first[i].Role {
			t.Errorf("assignments are not sorted by role: %q before %q", first[i-1].Role, first[i].Role)
		}
	}
}

// TestAssignmentForDistinguishesAbsentFromEmpty.
func TestAssignmentForDistinguishesAbsentFromEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := s.AssignmentFor(ctx, "wan"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}

	put(t, s, InterfaceAssignment{Role: "wan", Selector: "hw:aa"})
	a, err := s.AssignmentFor(ctx, "wan")
	if err != nil {
		t.Fatalf("AssignmentFor: %v", err)
	}
	if a.Selector != "hw:aa" {
		t.Errorf("selector = %q", a.Selector)
	}
}
