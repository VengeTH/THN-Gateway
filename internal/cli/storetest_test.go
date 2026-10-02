package cli

import (
	"context"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/state"
)

// Store helpers for the assignment tests.
//
// They open a REAL database in a temp directory and reopen it, because
// "survives a restart" is the claim and a fake would agree with it by
// construction. Every function here is a thin wrapper; the behaviour under
// test lives in internal/state and in the commands.

// write records assignments directly through the store.
func write(t *testing.T, path string, rows []state.InterfaceAssignment) {
	t.Helper()
	st, err := state.Open(path)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, r := range rows {
		if _, _, err := st.PutAssignment(ctx, r); err != nil {
			t.Fatalf("writing %s -> %s: %v", r.Role, r.Selector, err)
		}
	}
}

// read reopens the store and returns everything recorded.
//
// The store is closed and a NEW handle opened, which is the closest thing to
// a process restart available in a test.
func read(t *testing.T, path string) []state.InterfaceAssignment {
	t.Helper()
	st, err := state.Open(path)
	if err != nil {
		t.Fatalf("reopening the store: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := st.ListAssignments(ctx)
	if err != nil {
		t.Fatalf("listing assignments: %v", err)
	}
	return out
}

// put performs a single write and returns its outcomes without asserting.
func put(t *testing.T, path string, a state.InterfaceAssignment) (*state.InterfaceAssignment, *state.AssignmentConflict, error) {
	t.Helper()
	st, err := state.Open(path)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return st.PutAssignment(ctx, a)
}

// del removes a role binding and reports whether a row went away.
func del(t *testing.T, path, role string) bool {
	t.Helper()
	st, err := state.Open(path)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	removed, err := st.DeleteAssignment(ctx, role)
	if err != nil {
		t.Fatalf("deleting %s: %v", role, err)
	}
	return removed
}
