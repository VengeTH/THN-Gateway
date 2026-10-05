package execution

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TransactionRecord captures durable state of an in-flight execution transaction.
type TransactionRecord struct {
	PlanID          string         `json:"plan_id"`
	Generation      uint64         `json:"generation"`
	State           ExecutionState `json:"state"`
	StartedAt       time.Time      `json:"started_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	PhasesAttempted []string       `json:"phases_attempted"`
	AppliedOps      []string       `json:"applied_ops,omitempty"`
	RolledBackOps   []string       `json:"rolled_back_ops,omitempty"`
	Completed       bool           `json:"completed"`
	Error           string         `json:"error,omitempty"`
}

// JournalStore defines persistence for transaction tracking across process lifetimes.
type JournalStore interface {
	RecordState(rec TransactionRecord) error
	LastTransaction() (*TransactionRecord, error)
	Clear() error
}

// MemoryJournalStore provides in-memory journal tracking for testing.
type MemoryJournalStore struct {
	mu   sync.RWMutex
	last *TransactionRecord
}

func NewMemoryJournalStore() *MemoryJournalStore {
	return &MemoryJournalStore{}
}

func (s *MemoryJournalStore) RecordState(rec TransactionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyRec := rec
	s.last = &copyRec
	return nil
}

func (s *MemoryJournalStore) LastTransaction() (*TransactionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.last == nil {
		return nil, nil
	}
	copyRec := *s.last
	return &copyRec, nil
}

func (s *MemoryJournalStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = nil
	return nil
}

// FileJournalStore persists transaction progress to a local JSON file.
type FileJournalStore struct {
	path string
	mu   sync.Mutex
}

func NewFileJournalStore(path string) *FileJournalStore {
	return &FileJournalStore{path: path}
}

func (s *FileJournalStore) RecordState(rec TransactionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating journal directory: %w", err)
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding journal: %w", err)
	}

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("writing journal: %w", err)
	}
	return os.Rename(tmpPath, s.path)
}

func (s *FileJournalStore) LastTransaction() (*TransactionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading journal: %w", err)
	}

	var rec TransactionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parsing journal: %w", err)
	}
	return &rec, nil
}

func (s *FileJournalStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DetectInterrupted checks whether an uncompleted transaction was interrupted mid-flight.
func DetectInterrupted(store JournalStore) (*TransactionRecord, bool) {
	if store == nil {
		return nil, false
	}
	rec, err := store.LastTransaction()
	if err != nil || rec == nil {
		return nil, false
	}

	if !rec.Completed {
		switch rec.State {
		case StateApply, StateHealthCheck, StateRollingBack, StateRollbackVerification:
			return rec, true
		}
	}
	return rec, false
}
