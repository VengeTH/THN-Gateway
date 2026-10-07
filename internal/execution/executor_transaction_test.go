package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/planner"
)

func labFixtures() (diff.Observed, desired.State, []host.Assignment, *planner.Plan) {
	obs := diff.Observed{
		Supported:           true,
		HostName:            "thn-lab-vm",
		WANName:             "eth0",
		WANPresent:          true,
		WANUp:               true,
		LANName:             "eth1",
		LANPresent:          true,
		LANUp:               false,
		LANAddresses:        []string{},
		DefaultGateway:      "192.168.100.1",
		HasDefaultRoute:     true,
		IPv4Forwarding:      false,
		IPv4ForwardingKnown: true,
		FirewallActive:      false,
	}

	des := desired.State{
		Name:       "thn-gateway",
		Generation: 1,
		WAN: desired.Interface{
			Name:    "eth0",
			Role:    desired.RoleWAN,
			MTU:     1500,
			Up:      true,
			Present: true,
		},
		LAN: desired.Interface{
			Name:      "eth1",
			Role:      desired.RoleLAN,
			MTU:       1500,
			Up:        true,
			Present:   true,
			Addresses: []string{"10.77.0.1/24"},
		},
		Addressing: desired.Addressing{
			DefaultGateway:  "192.168.100.1",
			UpstreamPresent: true,
			IPv4Forwarding:  true,
		},
		NAT: desired.NAT{
			Enabled:    true,
			Resolved:   true,
			Interfaces: []string{"eth0"},
		},
		Firewall: desired.Firewall{
			Enabled:              true,
			Backend:              "nftables",
			DefaultInboundPolicy: "drop",
			AllowEstablished:     true,
			AllowLoopback:        true,
		},
	}

	d := diff.Compare(obs, diff.Desired{
		WANName:         des.WAN.Name,
		WANPresent:      des.WAN.Present,
		WANUp:           des.WAN.Up,
		LANName:         des.LAN.Name,
		LANPresent:      des.LAN.Present,
		LANUp:           des.LAN.Up,
		LANAddresses:    des.LAN.Addresses,
		DefaultGateway:  des.Addressing.DefaultGateway,
		IPv4Forwarding:  des.Addressing.IPv4Forwarding,
		FirewallEnabled: des.Firewall.Enabled,
	})

	assignments := []host.Assignment{
		{Role: host.RoleWAN, Selector: "eth0"},
		{Role: host.RoleLAN, Selector: "eth1"},
	}

	p := planner.Build(d, planner.Options{
		Generation:  1,
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Live:        true,
	})

	return obs, des, assignments, p
}

// 1. Full successful live transaction
func TestSuccessfulFullTransaction(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	journal := NewMemoryJournalStore()
	executor := NewExecutor()

	opts := ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Journal:     journal,
	}

	res, err := executor.ExecutePlan(ctx, plan, driver, opts)
	if err != nil {
		t.Fatalf("ExecutePlan failed: %v", err)
	}

	if res.FinalState != StateCommitted {
		t.Errorf("expected final state %s, got %s", StateCommitted, res.FinalState)
	}

	wantPhases := []string{
		string(StatePrepare),
		string(StateBackup),
		string(StateValidate),
		string(StateApply),
		string(StateHealthCheck),
		string(StateCommit),
	}
	if len(res.Phases) != len(wantPhases) {
		t.Errorf("phases count mismatch: got %v, want %v", res.Phases, wantPhases)
	}
	for i, wp := range wantPhases {
		if i < len(res.Phases) && res.Phases[i] != wp {
			t.Errorf("phase %d: got %s, want %s", i, res.Phases[i], wp)
		}
	}

	// Verify executed operations in driver
	executed := driver.ExecutedOps()
	if len(executed) == 0 {
		t.Fatal("expected driver to have executed operations")
	}

	// Verify resulting state in driver
	snap, _ := driver.CaptureState(ctx, BackupScope{Interfaces: []string{"eth1"}, Sysctls: []string{"net.ipv4.ip_forward"}, NFTables: true})
	if snap.Links["eth1"] != "up" {
		t.Errorf("expected eth1 UP, got %s", snap.Links["eth1"])
	}
	if len(snap.Addresses["eth1"]) == 0 || snap.Addresses["eth1"][0] != "10.77.0.1/24" {
		t.Errorf("expected 10.77.0.1/24 on eth1, got %v", snap.Addresses["eth1"])
	}
	if snap.Sysctls["net.ipv4.ip_forward"] != "1" {
		t.Errorf("expected net.ipv4.ip_forward=1, got %s", snap.Sysctls["net.ipv4.ip_forward"])
	}
	if !snap.NFTablesTHNPresent {
		t.Error("expected table inet thn to be present")
	}

	// Verify journal
	rec, err := journal.LastTransaction()
	if err != nil || rec == nil {
		t.Fatalf("reading journal failed: %v", err)
	}
	if !rec.Completed || rec.State != StateCommitted {
		t.Errorf("expected journal State=%s Completed=true, got %+v", StateCommitted, rec)
	}
}

// 2. Apply failure rollback
func TestApplyFailureRollback(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	// Injected failure at 3rd operation (e.g. index 2)
	driver.SetFailAtOpIndex(2)

	journal := NewMemoryJournalStore()
	executor := NewExecutor()

	opts := ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Journal:     journal,
	}

	res, err := executor.ExecutePlan(ctx, plan, driver, opts)
	if err == nil {
		t.Fatal("expected ExecutePlan to fail on injected apply error")
	}

	if res.FinalState != StateRolledBack {
		t.Errorf("expected final state %s, got %s", StateRolledBack, res.FinalState)
	}

	// Verify phases traversed
	expectedPhases := []string{
		string(StatePrepare),
		string(StateBackup),
		string(StateValidate),
		string(StateApply),
		string(StateRollingBack),
		string(StateRollbackVerification),
	}
	for _, ep := range expectedPhases {
		found := false
		for _, p := range res.Phases {
			if p == ep {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected phase %s in %v", ep, res.Phases)
		}
	}

	// Verify compensating operations were executed in reverse order
	rolledBack := driver.RollbackOps()
	if len(rolledBack) != 2 {
		t.Errorf("expected 2 rollback operations, got %d: %v", len(rolledBack), rolledBack)
	}

	// Verify post-rollback state returned to baseline
	snap, _ := driver.CaptureState(ctx, BackupScope{Interfaces: []string{"eth1"}, Sysctls: []string{"net.ipv4.ip_forward"}, NFTables: true})
	if snap.Links["eth1"] != "" && snap.Links["eth1"] != "down" {
		t.Errorf("expected eth1 returned to baseline, got %s", snap.Links["eth1"])
	}
	if len(snap.Addresses["eth1"]) != 0 {
		t.Errorf("expected eth1 addresses cleared, got %v", snap.Addresses["eth1"])
	}

	// Verify journal records ROLLED_BACK
	rec, _ := journal.LastTransaction()
	if rec == nil || rec.State != StateRolledBack || !rec.Completed {
		t.Errorf("expected journal State=%s Completed=true, got %+v", StateRolledBack, rec)
	}
}

// 3. Health failure rollback
func TestHealthFailureRollback(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	driver.SetFailHealthCheck(true, "carrier down on LAN interface")

	journal := NewMemoryJournalStore()
	executor := NewExecutor()

	opts := ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Journal:     journal,
	}

	res, err := executor.ExecutePlan(ctx, plan, driver, opts)
	if err == nil {
		t.Fatal("expected ExecutePlan to fail on health check failure")
	}

	if res.FinalState != StateRolledBack {
		t.Errorf("expected final state %s, got %s", StateRolledBack, res.FinalState)
	}

	// Verify HEALTH_CHECK phase was entered
	hasHealthCheck := false
	for _, p := range res.Phases {
		if p == string(StateHealthCheck) {
			hasHealthCheck = true
			break
		}
	}
	if !hasHealthCheck {
		t.Error("expected HEALTH_CHECK phase to be attempted")
	}

	// All applied operations must have been rolled back
	if len(driver.RollbackOps()) != len(driver.ExecutedOps()) {
		t.Errorf("mismatch between executed ops (%d) and rollback ops (%d)",
			len(driver.ExecutedOps()), len(driver.RollbackOps()))
	}
}

// 4. Partial rollback failure results in DEGRADED
func TestPartialRollbackFailureReportsDegraded(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	// Fail apply at op 2
	driver.SetFailAtOpIndex(2)
	// Fail rollback at op 1
	driver.SetFailRollbackAtOpIndex(0)

	journal := NewMemoryJournalStore()
	executor := NewExecutor()

	opts := ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Journal:     journal,
	}

	res, err := executor.ExecutePlan(ctx, plan, driver, opts)
	if err == nil {
		t.Fatal("expected error")
	}

	if res.FinalState != StateDegraded {
		t.Errorf("expected final state %s on rollback failure, got %s", StateDegraded, res.FinalState)
	}

	if !errors.Is(err, ErrRollbackFailed) {
		t.Errorf("expected ErrRollbackFailed, got %v", err)
	}

	rec, _ := journal.LastTransaction()
	if rec == nil || rec.State != StateDegraded {
		t.Errorf("expected journal to record DEGRADED, got %+v", rec)
	}
}

// 5. Crash recovery: interrupted execution detection
func TestCrashRecoveryInterruptedExecution(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	journal := NewMemoryJournalStore()

	// Simulate an interrupted transaction recorded during APPLY
	_ = journal.RecordState(TransactionRecord{
		PlanID:     plan.ID,
		Generation: plan.Generation,
		State:      StateApply,
		StartedAt:  time.Now().UTC().Add(-5 * time.Minute),
		UpdatedAt:  time.Now().UTC().Add(-4 * time.Minute),
		Completed:  false,
	})

	executor := NewExecutor()
	opts := ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Journal:     journal,
	}

	res, err := executor.ExecutePlan(ctx, plan, driver, opts)
	if err == nil {
		t.Fatal("expected execution to fail when interrupted transaction is detected")
	}

	if !errors.Is(err, ErrRecoveryRequired) {
		t.Errorf("expected ErrRecoveryRequired, got %v", err)
	}

	if res.FinalState != StateRecoveryRequired {
		t.Errorf("expected final state %s, got %s", StateRecoveryRequired, res.FinalState)
	}

	// Verify driver executed 0 operations
	if len(driver.ExecutedOps()) > 0 {
		t.Error("executor must not run any new operations while recovery is required")
	}
}

// 6. Stale plan rejection
func TestStalePlanRejection(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	executor := NewExecutor()

	// Case A: Observed digest changed
	driftedObs := obs
	driftedObs.LANUp = true // host changed since plan generation!

	optsA := ExecutionOptions{
		Observed:    driftedObs,
		Desired:     des,
		Assignments: assignments,
	}

	resA, errA := executor.ExecutePlan(ctx, plan, driver, optsA)
	if errA == nil {
		t.Fatal("expected stale plan error for drifted observed state")
	}
	if !errors.Is(errA, ErrStalePlan) {
		t.Errorf("expected ErrStalePlan, got %v", errA)
	}
	if resA.FinalState != StateBlocked {
		t.Errorf("expected final state %s, got %s", StateBlocked, resA.FinalState)
	}

	// Case B: Desired digest changed
	driftedDes := des
	driftedDes.Addressing.DefaultGateway = "10.0.0.1"

	optsB := ExecutionOptions{
		Observed:    obs,
		Desired:     driftedDes,
		Assignments: assignments,
	}

	resB, errB := executor.ExecutePlan(ctx, plan, driver, optsB)
	if errB == nil {
		t.Fatal("expected stale plan error for changed desired state")
	}
	if !errors.Is(errB, ErrStalePlan) {
		t.Errorf("expected ErrStalePlan, got %v", errB)
	}
	if resB.FinalState != StateBlocked {
		t.Errorf("expected final state %s, got %s", StateBlocked, resB.FinalState)
	}
}

// 7. Ownership isolation: unmanaged resources remain untouched
func TestOwnershipIsolation(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	// Set up unmanaged resources in driver
	driver.UnmanagedNFTables["table inet docker"] = true
	driver.UnmanagedNFTables["table inet custom_firewall"] = true
	driver.UnmanagedRoutes["172.17.0.0/16 via docker0"] = true
	driver.UnmanagedInterfaces["docker0"] = true
	driver.UnmanagedInterfaces["tailscale0"] = true

	executor := NewExecutor()
	opts := ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
	}

	// 1. Run apply
	res, err := executor.ExecutePlan(ctx, plan, driver, opts)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.FinalState != StateCommitted {
		t.Fatalf("expected COMMITTED, got %s", res.FinalState)
	}

	// Verify unmanaged resources remain untouched
	if !driver.UnmanagedNFTables["table inet docker"] || !driver.UnmanagedNFTables["table inet custom_firewall"] {
		t.Error("unmanaged nftables tables were modified during apply")
	}
	if !driver.UnmanagedRoutes["172.17.0.0/16 via docker0"] {
		t.Error("unmanaged routes were modified during apply")
	}
	if !driver.UnmanagedInterfaces["docker0"] || !driver.UnmanagedInterfaces["tailscale0"] {
		t.Error("unmanaged interfaces were modified during apply")
	}

	// 2. Now test rollback isolation
	driverRollback := NewSimulatedDriver()
	driverRollback.UnmanagedNFTables["table inet docker"] = true
	driverRollback.SetFailAtOpIndex(2) // trigger rollback

	resRB, _ := executor.ExecutePlan(ctx, plan, driverRollback, opts)
	if resRB.FinalState != StateRolledBack {
		t.Fatalf("expected ROLLED_BACK, got %s", resRB.FinalState)
	}

	// Verify unmanaged table survived rollback
	if !driverRollback.UnmanagedNFTables["table inet docker"] {
		t.Error("unmanaged nftables table was modified or flushed during rollback")
	}
}

// 8. Failure C2: Rollback verification failure results in DEGRADED
func TestRollbackVerificationFailureReportsDegraded(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	// Fail apply at operation 2 to trigger rollback
	driver.SetFailAtOpIndex(2)

	// Custom driver subclass / mock where post-rollback state does not match baseline
	tamperedDriver := &tamperedStateDriver{
		SimulatedDriver: driver,
	}

	journal := NewMemoryJournalStore()
	executor := NewExecutor()

	opts := ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Journal:     journal,
	}

	res, err := executor.ExecutePlan(ctx, plan, tamperedDriver, opts)
	if err == nil {
		t.Fatal("expected error on rollback verification failure")
	}

	if res.FinalState != StateDegraded {
		t.Fatalf("expected final state %s, got %s", StateDegraded, res.FinalState)
	}

	if !errors.Is(err, ErrRollbackFailed) {
		t.Errorf("expected ErrRollbackFailed, got %v", err)
	}
}

type tamperedStateDriver struct {
	*SimulatedDriver
}

func (d *tamperedStateDriver) CaptureState(ctx context.Context, scope BackupScope) (*StateSnapshot, error) {
	snap, err := d.SimulatedDriver.CaptureState(ctx, scope)
	if err != nil {
		return nil, err
	}
	// Tamper state if in rollback phase
	if d.SimulatedDriver.inRollback {
		snap.Sysctls["net.ipv4.ip_forward"] = "1" // baseline wanted 0!
	}
	return snap, nil
}

// 9. Failure F: Assignment drift rejection
func TestAssignmentDriftRejection(t *testing.T) {
	ctx := context.Background()
	obs, des, _, plan := labFixtures()

	driver := NewSimulatedDriver()
	executor := NewExecutor()

	driftedAssignments := []host.Assignment{
		{Role: host.RoleWAN, Selector: "eth0"},
		{Role: host.RoleLAN, Selector: "eth99"}, // changed after plan generation!
	}

	opts := ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: driftedAssignments,
	}

	res, err := executor.ExecutePlan(ctx, plan, driver, opts)
	if err == nil {
		t.Fatal("expected stale plan error on assignment drift")
	}
	if !errors.Is(err, ErrStalePlan) {
		t.Errorf("expected ErrStalePlan, got %v", err)
	}
	if res.FinalState != StateBlocked {
		t.Errorf("expected StateBlocked, got %s", res.FinalState)
	}
}

// 10. Failure G: Missing or inferred capability rejection
func TestMissingOrInferredCapabilityRejection(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	executor := NewExecutor()

	// Inferred capability: must NOT satisfy hard activation gate
	caps := []activation.CapabilityGate{
		{Name: "ip", Available: true, Confidence: "observed"},
		{Name: "nft", Available: true, Confidence: "inferred"}, // INFERRED, NOT OBSERVED!
		{Name: "sysctl", Available: true, Confidence: "observed"},
	}

	opts := ExecutionOptions{
		Observed:     obs,
		Desired:      des,
		Assignments:  assignments,
		Capabilities: caps,
	}

	res, err := executor.ExecutePlan(ctx, plan, driver, opts)
	if err == nil {
		t.Fatal("expected capability error on inferred capability")
	}
	if !errors.Is(err, ErrCapabilityMissing) {
		t.Errorf("expected ErrCapabilityMissing, got %v", err)
	}
	if res.FinalState != StateBlocked {
		t.Errorf("expected StateBlocked, got %s", res.FinalState)
	}
}

// 11. Failure H: Management safety failure rejection
func TestManagementSafetyFailureRejection(t *testing.T) {
	ctx := context.Background()
	obs, des, assignments, plan := labFixtures()

	driver := NewSimulatedDriver()
	executor := NewExecutor()

	opts := ExecutionOptions{
		Observed:          obs,
		Desired:           des,
		Assignments:       assignments,
		ExpectedPlanID:    plan.ID,
		ManagementSafe:    false,
		ManagementProblem: "plan mutates Tailscale remote management path",
	}

	res, err := executor.ExecutePlan(ctx, plan, driver, opts)
	if err == nil {
		t.Fatal("expected execution to fail when management path cannot be proven safe")
	}
	if !errors.Is(err, ErrCannotApply) {
		t.Errorf("expected ErrCannotApply, got %v", err)
	}
	if res.FinalState != StateBlocked {
		t.Errorf("expected StateBlocked, got %s", res.FinalState)
	}
}
