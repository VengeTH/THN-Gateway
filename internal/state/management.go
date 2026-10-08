package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ClientRecord stores persistent client attributes and operator overrides.
type ClientRecord struct {
	ID        string    `json:"id"`
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	NetworkID string    `json:"network_id"`
	QoSPolicy string    `json:"qos_policy"`
	Blocked   bool      `json:"blocked"`
	Notes     string    `json:"notes"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AlertRecord stores a dashboard alert or event notification.
type AlertRecord struct {
	ID           string    `json:"id"`
	TS           time.Time `json:"ts"`
	Severity     string    `json:"severity"`
	Category     string    `json:"category"`
	Message      string    `json:"message"`
	Source       string    `json:"source"`
	Acknowledged bool      `json:"acknowledged"`
	AckBy        string    `json:"ack_by,omitempty"`
	AckAt        string    `json:"ack_at,omitempty"`
}

// ManagementAuditEntry logs actions taken through the management API or dashboard.
type ManagementAuditEntry struct {
	ID      int64     `json:"id"`
	TS      time.Time `json:"ts"`
	Actor   string    `json:"actor"`
	Role    string    `json:"role"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Detail  string    `json:"detail"`
	Success bool      `json:"success"`
}

// PutClientRecord creates or updates a client entry in the database.
func (s *Store) PutClientRecord(ctx context.Context, c ClientRecord) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = time.Now().UTC()
	}

	blockedInt := 0
	if c.Blocked {
		blockedInt = 1
	}

	query := `
		INSERT INTO client_records (id, mac, ip, hostname, network_id, qos_policy, blocked, notes, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			mac = excluded.mac,
			ip = excluded.ip,
			hostname = excluded.hostname,
			network_id = excluded.network_id,
			qos_policy = excluded.qos_policy,
			blocked = excluded.blocked,
			notes = excluded.notes,
			updated_at = excluded.updated_at
	`
	_, err := s.db.ExecContext(ctx, query,
		c.ID, c.MAC, c.IP, c.Hostname, c.NetworkID, c.QoSPolicy, blockedInt, c.Notes,
		c.UpdatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("state: putting client record %s: %w", c.ID, err)
	}
	return nil
}

// GetClientRecord fetches a single client by its identifier.
func (s *Store) GetClientRecord(ctx context.Context, id string) (*ClientRecord, error) {
	query := `
		SELECT id, mac, ip, hostname, network_id, qos_policy, blocked, notes, updated_at
		FROM client_records WHERE id = ?
	`
	var c ClientRecord
	var blockedInt int
	var updatedStr string

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&c.ID, &c.MAC, &c.IP, &c.Hostname, &c.NetworkID, &c.QoSPolicy, &blockedInt, &c.Notes, &updatedStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("state: reading client record %s: %w", id, err)
	}

	c.Blocked = blockedInt == 1
	if t, err := time.Parse(time.RFC3339Nano, updatedStr); err == nil {
		c.UpdatedAt = t
	}
	return &c, nil
}

// ListClientRecords returns all stored clients sorted by IP.
func (s *Store) ListClientRecords(ctx context.Context) ([]ClientRecord, error) {
	query := `
		SELECT id, mac, ip, hostname, network_id, qos_policy, blocked, notes, updated_at
		FROM client_records ORDER BY ip ASC
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("state: listing client records: %w", err)
	}
	defer rows.Close()

	var clients []ClientRecord
	for rows.Next() {
		var c ClientRecord
		var blockedInt int
		var updatedStr string

		if err := rows.Scan(
			&c.ID, &c.MAC, &c.IP, &c.Hostname, &c.NetworkID, &c.QoSPolicy, &blockedInt, &c.Notes, &updatedStr,
		); err != nil {
			return nil, fmt.Errorf("state: scanning client record: %w", err)
		}
		c.Blocked = blockedInt == 1
		if t, err := time.Parse(time.RFC3339Nano, updatedStr); err == nil {
			c.UpdatedAt = t
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

// SetClientBlocked updates the blocked status of a client.
func (s *Store) SetClientBlocked(ctx context.Context, id string, blocked bool) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	blockedInt := 0
	if blocked {
		blockedInt = 1
	}

	query := `
		UPDATE client_records
		SET blocked = ?, updated_at = ?
		WHERE id = ?
	`
	res, err := s.db.ExecContext(ctx, query, blockedInt, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("state: updating client blocked %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PutAlertRecord stores an alert record.
func (s *Store) PutAlertRecord(ctx context.Context, a AlertRecord) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if a.TS.IsZero() {
		a.TS = time.Now().UTC()
	}

	ackInt := 0
	if a.Acknowledged {
		ackInt = 1
	}

	query := `
		INSERT INTO alert_records (id, ts, severity, category, message, source, acknowledged, ack_by, ack_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			severity = excluded.severity,
			category = excluded.category,
			message = excluded.message,
			source = excluded.source,
			acknowledged = excluded.acknowledged,
			ack_by = excluded.ack_by,
			ack_at = excluded.ack_at
	`
	_, err := s.db.ExecContext(ctx, query,
		a.ID, a.TS.Format(time.RFC3339Nano), a.Severity, a.Category, a.Message, a.Source, ackInt, a.AckBy, a.AckAt,
	)
	if err != nil {
		return fmt.Errorf("state: putting alert record %s: %w", a.ID, err)
	}
	return nil
}

// ListAlertRecords returns recent alert records.
func (s *Store) ListAlertRecords(ctx context.Context, limit int, unackOnly bool) ([]AlertRecord, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, ts, severity, category, message, source, acknowledged, ack_by, ack_at
		FROM alert_records
	`
	var args []any
	if unackOnly {
		query += ` WHERE acknowledged = 0`
	}
	query += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("state: listing alert records: %w", err)
	}
	defer rows.Close()

	var alerts []AlertRecord
	for rows.Next() {
		var a AlertRecord
		var tsStr string
		var ackInt int

		if err := rows.Scan(
			&a.ID, &tsStr, &a.Severity, &a.Category, &a.Message, &a.Source, &ackInt, &a.AckBy, &a.AckAt,
		); err != nil {
			return nil, fmt.Errorf("state: scanning alert record: %w", err)
		}
		a.Acknowledged = ackInt == 1
		if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
			a.TS = t
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// AcknowledgeAlert marks an alert as acknowledged by an operator.
func (s *Store) AcknowledgeAlert(ctx context.Context, id, ackBy string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	nowStr := time.Now().UTC().Format(time.RFC3339Nano)
	query := `
		UPDATE alert_records
		SET acknowledged = 1, ack_by = ?, ack_at = ?
		WHERE id = ?
	`
	res, err := s.db.ExecContext(ctx, query, ackBy, nowStr, id)
	if err != nil {
		return fmt.Errorf("state: acknowledging alert %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordManagementAudit writes an audit record for an operator action.
func (s *Store) RecordManagementAudit(ctx context.Context, e ManagementAuditEntry) (int64, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}

	successInt := 0
	if e.Success {
		successInt = 1
	}

	query := `
		INSERT INTO management_audit (ts, actor, role, action, target, detail, success)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	res, err := s.db.ExecContext(ctx, query,
		e.TS.Format(time.RFC3339Nano), e.Actor, e.Role, e.Action, e.Target, e.Detail, successInt,
	)
	if err != nil {
		return 0, fmt.Errorf("state: recording management audit: %w", err)
	}
	return res.LastInsertId()
}

// ListManagementAudit returns the most recent management audit entries.
func (s *Store) ListManagementAudit(ctx context.Context, limit int) ([]ManagementAuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT id, ts, actor, role, action, target, detail, success
		FROM management_audit
		ORDER BY ts DESC
		LIMIT ?
	`
	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("state: listing management audit: %w", err)
	}
	defer rows.Close()

	var entries []ManagementAuditEntry
	for rows.Next() {
		var e ManagementAuditEntry
		var tsStr string
		var succInt int

		if err := rows.Scan(
			&e.ID, &tsStr, &e.Actor, &e.Role, &e.Action, &e.Target, &e.Detail, &succInt,
		); err != nil {
			return nil, fmt.Errorf("state: scanning management audit entry: %w", err)
		}
		e.Success = succInt == 1
		if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
			e.TS = t
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
