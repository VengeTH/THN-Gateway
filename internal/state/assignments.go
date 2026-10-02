package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Persisted interface assignments.
//
// # What is stored here, and what is not
//
// This file stores what an ADMINISTRATOR DECIDED: that a particular piece of
// hardware performs a particular logical role. It stores nothing Linux told
// us and nothing a configuration document said.
//
// That separation is the whole point of the assignment concept, and it is why
// this is its own table rather than a field on an observation or a revision:
//
//	observed   internal/network + internal/host   what the machine has
//	assigned   this file                          what the operator said
//	desired    internal/config                     what the document wants
//
// Collapsing any two of them produces a failure the architecture has already
// hit once: `network.wan` in a document was doing duty as an observation, as
// an intent, and as a declaration of which physical NIC existed, and no two of
// those survive the first reboot.
//
// # The selector is normally a stable identity
//
// `hw:…` is derived from the hardware address and survives a NIC moving slots
// or predictable naming being turned off. A kernel name is accepted and stored
// as given, because it is what an operator reads off `ip link` and because
// deleting their assignment because the kernel renamed the interface is worse
// than making them re-state it.
//
// Nothing here resolves a selector. Resolution against the observed host is
// internal/host.Resolve's job, and keeping it there means the store cannot
// grow its own idea of what an interface is.

// InterfaceAssignment is one operator-declared role binding.
//
// Role is a plain string at this layer on purpose. internal/state is a
// persistence package with no domain dependencies, and importing
// internal/host to obtain a Role type would make the store depend on the
// discovery model — which is the coupling this file exists to avoid. The
// domain owns the type; the store owns the string.
type InterfaceAssignment struct {
	// Role is the logical role: "wan", "lan", "mgmt", "guest", "dmz".
	//
	// It is the primary key, so a role holds exactly one assignment.
	Role string `json:"role"`

	// Selector identifies the interface: a stable ID or a kernel name.
	Selector string `json:"selector"`

	// IDKind records how the selector was derived ("hardware" or
	// "ephemeral") at the time it was assigned.
	//
	// It is advisory. It is kept so that a human reading the store can tell
	// a durable binding from a fragile one, and so a future tool can warn
	// about an ephemeral selector without re-deriving anything.
	IDKind string `json:"id_kind,omitempty"`

	// Note is free text the operator supplied. It carries no meaning to THN.
	Note string `json:"note,omitempty"`

	// AssignedAt is when the binding was last written.
	AssignedAt string `json:"assigned_at"`

	// AssignedBy records who made it, for the audit trail.
	AssignedBy string `json:"assigned_by,omitempty"`
}

// ErrAssignmentConflict is returned when a write would put one interface in
// two roles.
//
// It is distinct from ErrNotFound so that a caller can tell "nothing to
// change" from "your change contradicts something already recorded", which
// need different messages.
var ErrAssignmentConflict = errors.New("state: interface is already assigned to another role")

// AssignmentConflict describes the contradiction a write would create.
type AssignmentConflict struct {
	// Selector is the interface both writes name.
	Selector string `json:"selector"`
	// ExistingRole is the role it already holds.
	ExistingRole string `json:"existing_role"`
	// WantedRole is the role the new write asks for.
	WantedRole string `json:"wanted_role"`
}

// PutAssignment records a role binding.
//
// # Re-assignment is a replacement, and it is explicit
//
// role is the primary key, so assigning the same role twice REPLACES the
// selector rather than adding a second row. That is deliberate: the operator
// typed the command, so the outcome is unambiguous and no confirmation
// prompt can be second-guessed. The previous binding is returned so a caller
// can tell the operator what it replaced.
//
// # One interface cannot hold two roles
//
// An interface in two roles is exactly the ambiguity internal/host.Resolve
// refuses to resolve, and a store that permitted it would create the
// contradiction on disk and only discover it at readiness time. The write is
// refused here, with ErrAssignmentConflict and the role already held.
//
// The fix is to unassign first, which is one command and is visible in the
// audit trail. A --force flag would make the correction a matter of typing a
// word, and this is not a mistake worth making by reflex.
func (s *Store) PutAssignment(ctx context.Context, a InterfaceAssignment) (*InterfaceAssignment, *AssignmentConflict, error) {
	role := strings.TrimSpace(a.Role)
	selector := strings.TrimSpace(a.Selector)
	if role == "" {
		return nil, nil, errors.New("state: assignment requires a role")
	}
	if selector == "" {
		return nil, nil, errors.New("state: assignment requires a selector")
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Refuse an interface that already holds a DIFFERENT role.
	var existingRole, existingSelector string
	err := s.db.QueryRowContext(ctx,
		`SELECT role, selector FROM interface_assignments WHERE selector = ? AND role <> ?`,
		selector, role).Scan(&existingRole, &existingSelector)
	switch {
	case err == nil:
		return nil, &AssignmentConflict{
			Selector:     selector,
			ExistingRole: existingRole,
			WantedRole:   role,
		}, ErrAssignmentConflict
	case !errors.Is(err, sql.ErrNoRows):
		return nil, nil, fmt.Errorf("checking interface assignments: %w", err)
	}

	// What this write replaces, if anything.
	var previous *InterfaceAssignment
	var prevSelector, prevIDKind, prevNote, prevAt, prevBy string
	err = s.db.QueryRowContext(ctx,
		`SELECT selector, id_kind, note, assigned_at, assigned_by
		   FROM interface_assignments WHERE role = ?`, role).
		Scan(&prevSelector, &prevIDKind, &prevNote, &prevAt, &prevBy)
	switch {
	case err == nil:
		previous = &InterfaceAssignment{
			Role: role, Selector: prevSelector, IDKind: prevIDKind,
			Note: prevNote, AssignedAt: prevAt, AssignedBy: prevBy,
		}
	case !errors.Is(err, sql.ErrNoRows):
		return nil, nil, fmt.Errorf("reading the existing assignment: %w", err)
	}

	ts := a.AssignedAt
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO interface_assignments (role, selector, id_kind, note, assigned_at, assigned_by)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(role) DO UPDATE SET
			selector    = excluded.selector,
			id_kind     = excluded.id_kind,
			note        = excluded.note,
			assigned_at = excluded.assigned_at,
			assigned_by = excluded.assigned_by`,
		role, selector, a.IDKind, a.Note, ts, a.AssignedBy)
	if err != nil {
		return nil, nil, fmt.Errorf("writing the interface assignment: %w", err)
	}

	// A role moved to different hardware can leave the old hardware holding
	// nothing, which is correct. But if the PREVIOUS selector is still held
	// by another row, that row now contradicts this one.
	if previous != nil && previous.Selector != selector {
		var stillHeld string
		err := s.db.QueryRowContext(ctx,
			`SELECT role FROM interface_assignments WHERE selector = ?`, previous.Selector).
			Scan(&stillHeld)
		switch {
		case err == nil:
			return nil, &AssignmentConflict{
				Selector:     previous.Selector,
				ExistingRole: stillHeld,
				WantedRole:   role,
			}, ErrAssignmentConflict
		case !errors.Is(err, sql.ErrNoRows):
			return nil, nil, fmt.Errorf("re-checking the previous selector: %w", err)
		}
	}

	return previous, nil, nil
}

// DeleteAssignment removes one role binding.
//
// It reports whether a row was removed, so a caller can distinguish "I
// cleared this" from "there was nothing to clear" — which are different
// answers and an operator should not be told they unassigned something they
// did not.
func (s *Store) DeleteAssignment(ctx context.Context, role string) (bool, error) {
	role = strings.TrimSpace(role)
	if role == "" {
		return false, errors.New("state: unassign requires a role")
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	res, err := s.db.ExecContext(ctx, `DELETE FROM interface_assignments WHERE role = ?`, role)
	if err != nil {
		return false, fmt.Errorf("deleting the interface assignment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("deleting the interface assignment: %w", err)
	}
	return n > 0, nil
}

// DeleteAssignmentBySelector removes whichever role a selector holds.
//
// It is how an operator clears an assignment for hardware that is no longer
// present, which is precisely the case where looking it up by selector rather
// than by role is the only thing that can work.
func (s *Store) DeleteAssignmentBySelector(ctx context.Context, selector string) (string, bool, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", false, errors.New("state: unassign requires a selector")
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var role string
	err := s.db.QueryRowContext(ctx,
		`SELECT role FROM interface_assignments WHERE selector = ?`, selector).Scan(&role)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("reading the interface assignment: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `DELETE FROM interface_assignments WHERE role = ?`, role)
	if err != nil {
		return "", false, fmt.Errorf("deleting the interface assignment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", false, fmt.Errorf("deleting the interface assignment: %w", err)
	}
	return role, n > 0, nil
}

// ListAssignments returns every recorded binding, ordered by role.
//
// Ordering is by role so that two runs produce identical output and an
// operator can diff them. It is NOT a statement about interfaces: nothing in
// this package knows or cares which interface comes first.
func (s *Store) ListAssignments(ctx context.Context) ([]InterfaceAssignment, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT role, selector, id_kind, note, assigned_at, assigned_by
		  FROM interface_assignments ORDER BY role`)
	if err != nil {
		return nil, fmt.Errorf("listing interface assignments: %w", err)
	}
	defer rows.Close()

	out := []InterfaceAssignment{}
	for rows.Next() {
		var a InterfaceAssignment
		if err := rows.Scan(&a.Role, &a.Selector, &a.IDKind, &a.Note, &a.AssignedAt, &a.AssignedBy); err != nil {
			return nil, fmt.Errorf("reading an interface assignment: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AssignmentFor returns the binding for a role, or ErrNotFound.
func (s *Store) AssignmentFor(ctx context.Context, role string) (*InterfaceAssignment, error) {
	rows, err := s.ListAssignments(ctx)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Role == strings.TrimSpace(role) {
			return &rows[i], nil
		}
	}
	return nil, ErrNotFound
}
