package execution

import (
	"context"
)

// ExecutorDriver abstracts execution mechanics for networking operations.
//
// Different implementations represent different execution environments:
//   - ProductionDriver: permanently disabled (CanApply == false) for production safety
//   - SimulatedDriver: in-memory execution for unit and failure testing
//   - LinuxDriver: real Linux driver operating via guarded system tools, authorized only in disposable labs
type ExecutorDriver interface {
	// Name returns the driver identifier.
	Name() string

	// CanApply reports whether this driver is authorized to mutate host state.
	CanApply() bool

	// DetectCapabilities probes and returns currently available system facilities.
	DetectCapabilities(ctx context.Context) (Capabilities, error)

	// Execute carries out a single structured operation.
	Execute(ctx context.Context, op Operation) error

	// CaptureState reads the current kernel state for resources within scope.
	CaptureState(ctx context.Context, scope BackupScope) (*StateSnapshot, error)

	// VerifyHealth evaluates post-apply health checks against current observed state.
	VerifyHealth(ctx context.Context, checks []HealthCheck) (HealthResult, error)
}
