package execution

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Common execution errors.
var (
	// ErrCannotApply is returned when an execution driver cannot apply changes.
	ErrCannotApply = errors.New("execution: driver cannot apply changes")

	// ErrProductionActivationDisabled is returned when attempting to mutate a production host.
	ErrProductionActivationDisabled = fmt.Errorf("%w: production activation is permanently disabled in this build", ErrCannotApply)

	// ErrLabVerificationFailed is returned when disposable lab verification fails.
	ErrLabVerificationFailed = errors.New("execution: disposable lab verification failed; host not authorized for live mutation")

	// ErrStalePlan is returned when a plan's input digests no longer match live state.
	ErrStalePlan = errors.New("execution: plan is stale; live host or desired state has drifted")

	// ErrCapabilityMissing is returned when a required kernel or tool capability is absent.
	ErrCapabilityMissing = errors.New("execution: required system capability is missing")

	// ErrOperationFailed is returned when an operation fails during apply.
	ErrOperationFailed = errors.New("execution: structured operation failed")

	// ErrRollbackFailed is returned when one or more operations fail during rollback.
	ErrRollbackFailed = errors.New("execution: rollback operation failed")

	// ErrHealthCheckFailed is returned when post-apply verification checks fail.
	ErrHealthCheckFailed = errors.New("execution: post-apply health check failed")

	// ErrRecoveryRequired is returned when an interrupted transaction is detected.
	ErrRecoveryRequired = errors.New("execution: interrupted transaction detected; recovery required")
)

// ExecutionState represents a state in the execution transaction lifecycle.
type ExecutionState string

const (
	StateUninitialised ExecutionState = "UNINITIALISED"
	StatePrepare       ExecutionState = "PREPARE"

	// StatePrepared means the transaction was authorized and prepared but
	// nothing was applied. It is the terminal state of a dry run, and is
	// distinct from StateCommitted: nothing about the host changed.
	StatePrepared ExecutionState = "PREPARED"

	StateBackup               ExecutionState = "BACKUP"
	StateValidate             ExecutionState = "VALIDATE"
	StateApply                ExecutionState = "APPLY"
	StateHealthCheck          ExecutionState = "HEALTH_CHECK"
	StateCommit               ExecutionState = "COMMIT"
	StateCommitted            ExecutionState = "COMMITTED"
	StateRollingBack          ExecutionState = "ROLLING_BACK"
	StateRollbackVerification ExecutionState = "ROLLBACK_VERIFICATION"
	StateRolledBack           ExecutionState = "ROLLED_BACK"
	StateDegraded             ExecutionState = "DEGRADED"
	StateRecoveryRequired     ExecutionState = "RECOVERY_REQUIRED"
	StateBlocked              ExecutionState = "BLOCKED"
)

// String returns the string representation of an ExecutionState.
func (s ExecutionState) String() string {
	return string(s)
}

// Capabilities tracks observed host capabilities for networking execution.
type Capabilities struct {
	IP      bool              `json:"ip"`
	NFT     bool              `json:"nft"`
	Sysctl  bool              `json:"sysctl"`
	TC      bool              `json:"tc"`
	Details map[string]string `json:"details,omitempty"`
}

// Satisfies reports whether all required capabilities are available.
func (c Capabilities) Satisfies(required []string) (bool, string) {
	for _, req := range required {
		switch req {
		case "ip":
			if !c.IP {
				return false, "iproute2 (ip) utility is unavailable"
			}
		case "nft":
			if !c.NFT {
				return false, "nftables (nft) utility or kernel facility is unavailable"
			}
		case "sysctl":
			if !c.Sysctl {
				return false, "sysctl utility is unavailable"
			}
		case "tc":
			if !c.TC {
				return false, "iproute2 traffic control (tc) utility is unavailable"
			}
		default:
			if d, ok := c.Details[req]; !ok || d != "available" {
				return false, fmt.Sprintf("capability %s is unavailable", req)
			}
		}
	}
	return true, ""
}

// HealthCheck defines one post-apply health check assertion.
type HealthCheck struct {
	Target      string `json:"target"`
	Check       string `json:"check"`
	Expectation string `json:"expectation"`
}

// ProbeSide names which side of the gateway a real-traffic probe starts from.
const (
	// ProbeSideLAN originates in the downstream segment.
	ProbeSideLAN = "lan"
	// ProbeSideWAN originates on the upstream segment.
	ProbeSideWAN = "wan"
)

// ProbeResult reports what actually happened when a connection was attempted.
//
// This is the difference between "the firewall loaded" and "the firewall
// permits the traffic it was installed for". Only a real connection produces
// these fields.
type ProbeResult struct {
	// Reachable reports whether the connection completed.
	Reachable bool `json:"reachable"`
	// SourceAddress is the address the probe left from, which is how a NAT
	// translation is confirmed from the near side.
	SourceAddress string `json:"source_address,omitempty"`
	// ObservedSource is the source address the far end reported seeing, which
	// is how a NAT translation is confirmed from the far side.
	ObservedSource string `json:"observed_source,omitempty"`
	// Error carries the connection failure, so a blocked path and a broken
	// path can be told apart in a failure message.
	Error string `json:"error,omitempty"`
}

// TrafficProber performs real network connections on behalf of a health check.
//
// It is an interface rather than a concrete type because the driver must not
// know how the lab is built: a disposable namespace harness, an operator's
// manual client VM and a future remote prober are all the same dependency.
//
// A driver without one is not broken — it simply cannot evaluate a check that
// requires real traffic, and says so instead of reporting a pass.
type TrafficProber interface {
	// Probe opens a TCP connection to endpoint from the given side of the
	// gateway. It must return a result rather than an error for an ordinary
	// connection refusal: a firewall blocking traffic is a finding, not a
	// failure of the probe.
	Probe(ctx context.Context, side, endpoint string, timeout time.Duration) (ProbeResult, error)
}

// HealthCheckResult reports the outcome of a single health check.
type HealthCheckResult struct {
	Target      string `json:"target"`
	Check       string `json:"check"`
	Expectation string `json:"expectation"`
	Passed      bool   `json:"passed"`
	Observed    string `json:"observed"`
	Error       string `json:"error,omitempty"`
}

// HealthResult aggregates health check results.
type HealthResult struct {
	Healthy       bool                `json:"healthy"`
	Checks        []HealthCheckResult `json:"checks"`
	FailureReason string              `json:"failure_reason,omitempty"`
}

// ExecutionResult records the outcome of an execution transaction.
type ExecutionResult struct {
	PlanID        string         `json:"plan_id"`
	Generation    uint64         `json:"generation"`
	FinalState    ExecutionState `json:"final_state"`
	Phases        []string       `json:"phases"`
	AppliedOps    []string       `json:"applied_ops,omitempty"`
	RolledBackOps []string       `json:"rolled_back_ops,omitempty"`
	Error         string         `json:"error,omitempty"`
	Health        HealthResult   `json:"health"`
	Timestamp     time.Time      `json:"timestamp"`
}
