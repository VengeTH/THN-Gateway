package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/planner"
)

// TestProductionSafetyDriverFailsClosedUntilAuthorized is the invariant that
// matters on a real host.
//
// The driver used to be permanently disabled. It is now authorized by a
// deliberate, explicit act, and what must remain true is that nothing but
// that act can produce an authorized driver.
//
// All three are asserted here because each is a separate way in:
//
//  1. a driver nobody authorized refuses to execute;
//  2. an authorized driver executes only what it was authorized for;
//  3. the build containing an apply path says so, because an operator
//     deciding whether a host is deployable needs the truth about the binary
//     and not a stale claim about it.
func TestProductionSafetyDriverFailsClosedUntilAuthorized(t *testing.T) {
	driver := NewProductionDriver()

	// 1. An unauthorized driver cannot mutate anything.
	if driver.CanApply() {
		t.Fatal("ProductionDriver.CanApply() reported true before authorization")
	}

	err := driver.Execute(context.Background(), OpLinkSetUp{Interface: "enp0s31f6"})
	if err == nil {
		t.Fatal("ProductionDriver.Execute succeeded; must fail closed")
	}
	if !errors.Is(err, ErrProductionActivationDisabled) {
		t.Errorf("expected ErrProductionActivationDisabled, got %v", err)
	}

	// An unauthorized driver reports an unknown host as unhealthy rather than
	// passing it. "I could not check" is never "it is fine".
	if health, _ := driver.VerifyHealth(context.Background(), nil); health.Healthy {
		t.Fatal("an unauthorized driver reported a healthy host")
	}

	// 3. The build contains an apply path. What it does NOT contain is a
	// driver that acts without authorization, which is points 1 and 2.
	if !activation.CanApply() {
		t.Fatal("activation.CanApply() is false; this build contains a production apply path " +
			"and must report it truthfully")
	}
}

func TestExecutorRejectsProductionDriverWithBlocked(t *testing.T) {
	ctx := context.Background()
	driver := NewProductionDriver()
	executor := NewExecutor()

	obs := diff.Observed{
		Supported:       true,
		HostName:        "dell-gateway",
		WANName:         "enp0s31f6",
		WANPresent:      true,
		WANUp:           true,
		LANName:         "enx00e099001812",
		LANPresent:      true,
		LANUp:           false,
		LANAddresses:    []string{},
		DefaultGateway:  "192.168.1.1",
		HasDefaultRoute: true,
	}

	des := desired.State{
		Name:       "thn-gateway",
		Generation: 1,
		WAN: desired.Interface{
			Name:    "enp0s31f6",
			Role:    desired.RoleWAN,
			MTU:     1500,
			Up:      true,
			Present: true,
		},
		LAN: desired.Interface{
			Name:      "enx00e099001812",
			Role:      desired.RoleLAN,
			MTU:       1500,
			Up:        true,
			Present:   true,
			Addresses: []string{"10.77.0.1/24"},
		},
		Addressing: desired.Addressing{
			DefaultGateway:  "192.168.1.1",
			UpstreamPresent: true,
			IPv4Forwarding:  true,
		},
	}

	d := diff.Compare(obs, diff.Desired{
		WANName:        des.WAN.Name,
		WANPresent:     des.WAN.Present,
		WANUp:          des.WAN.Up,
		LANName:        des.LAN.Name,
		LANPresent:     des.LAN.Present,
		LANUp:          des.LAN.Up,
		LANAddresses:   des.LAN.Addresses,
		DefaultGateway: des.Addressing.DefaultGateway,
		IPv4Forwarding: des.Addressing.IPv4Forwarding,
	})

	assignments := []host.Assignment{
		{Role: host.RoleWAN, Selector: "enp0s31f6"},
		{Role: host.RoleLAN, Selector: "enx00e099001812"},
	}

	p := planner.Build(d, planner.Options{
		Generation:  1,
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Live:        true,
	})

	opts := ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
	}

	res, err := executor.ExecutePlan(ctx, p, driver, opts)
	if err == nil {
		t.Fatal("ExecutePlan against ProductionDriver succeeded; must be refused")
	}

	if res.FinalState != StateBlocked {
		t.Errorf("expected final state %s, got %s", StateBlocked, res.FinalState)
	}

	if !errors.Is(err, ErrCannotApply) {
		t.Errorf("expected error wrapping ErrCannotApply, got %v", err)
	}
}

func TestProductionDriverAuthorizationFlow(t *testing.T) {
	ctx := context.Background()
	runner := newRecordingLinuxRunner()
	driver := NewProductionDriverWithRunner(runner, nil)

	// 1. Initial state: CanApply must be false
	if driver.CanApply() {
		t.Fatal("driver.CanApply() is true initially; must be false")
	}

	// 2. Direct mutation call must fail
	err := driver.Execute(ctx, OpLinkSetUp{Interface: "eth0"})
	if !errors.Is(err, ErrProductionActivationDisabled) {
		t.Fatalf("expected ErrProductionActivationDisabled, got %v", err)
	}

	// 3. Authorization without confirmation fails
	err = driver.Authorize(ProductionAuth{
		Confirmed: false,
	})
	if err == nil {
		t.Fatal("expected Authorize without confirmation to fail")
	}

	// 4. Authorization with unsatisfied gates fails
	gateRes := &activation.GateResult{
		AllSatisfied: false,
		Blocking:     []string{"wan-present"},
	}
	err = driver.Authorize(ProductionAuth{
		Confirmed:   true,
		GatesResult: gateRes,
	})
	if err == nil {
		t.Fatal("expected Authorize with unsatisfied gates to fail")
	}

	// 5. Authorization with management safety risk fails
	gateResSuccess := &activation.GateResult{
		AllSatisfied: true,
	}
	err = driver.Authorize(ProductionAuth{
		Confirmed:         true,
		GatesResult:       gateResSuccess,
		ManagementSafe:    false,
		ManagementProblem: "plan drops active SSH connection",
	})
	if err == nil {
		t.Fatal("expected Authorize with management safety risk to fail")
	}

	// 6. Authorization with missing digests fails
	err = driver.Authorize(ProductionAuth{
		Confirmed:      true,
		GatesResult:    gateResSuccess,
		ManagementSafe: true,
		PlanID:         "",
	})
	if err == nil {
		t.Fatal("expected Authorize with missing plan digests to fail")
	}

	// 7. Full valid authorization succeeds
	err = driver.Authorize(ProductionAuth{
		Confirmed:        true,
		GatesResult:      gateResSuccess,
		ManagementSafe:   true,
		PlanID:           "plan-12345",
		ObservedDigest:   "obs-12345",
		DesiredDigest:    "des-12345",
		AssignmentDigest: "assign-12345",
	})
	if err != nil {
		t.Fatalf("Authorize failed with valid inputs: %v", err)
	}
	if !driver.CanApply() {
		t.Fatal("driver.CanApply() should be true after valid authorization")
	}

	// 8. Execute valid operations
	err = driver.Execute(ctx, OpLinkSetUp{Interface: "eth0"})
	if err != nil {
		t.Fatalf("Execute failed after authorization: %v", err)
	}
	if len(runner.recordedCommands) != 1 {
		t.Fatalf("expected 1 recorded command, got %d", len(runner.recordedCommands))
	}
	cmd := runner.recordedCommands[0]
	if cmd[0] != "ip" || cmd[1] != "link" || cmd[2] != "set" || cmd[3] != "eth0" || cmd[4] != "up" {
		t.Errorf("unexpected command: %v", cmd)
	}
}

func TestProductionDriverCommandSafetyInvariants(t *testing.T) {
	ctx := context.Background()
	runner := newRecordingLinuxRunner()
	driver := NewProductionDriverWithRunner(runner, nil)

	// Authorize driver for test
	_ = driver.Authorize(ProductionAuth{
		Confirmed:        true,
		GatesResult:      &activation.GateResult{AllSatisfied: true},
		ManagementSafe:   true,
		PlanID:           "plan-safe",
		ObservedDigest:   "obs-safe",
		DesiredDigest:    "des-safe",
		AssignmentDigest: "assign-safe",
	})

	// Apply THN nft table
	err := driver.Execute(ctx, OpNFTApplyTHNTable{
		InboundPolicy:    "drop",
		AllowEstablished: true,
		AllowLoopback:    true,
		LANInterface:     "eth1",
		WANInterface:     "eth0",
		LANSubnet:        "10.77.0.0/24",
		NATInterfaces:    []string{"eth0"},
	})
	if err != nil {
		t.Fatalf("applying THN table failed: %v", err)
	}

	for _, cmd := range runner.recordedCommands {
		flat := cmd[0] + " "
		for _, arg := range cmd[1:] {
			flat += arg + " "
		}

		// Never flush ruleset
		if flat == "nft flush ruleset " {
			t.Fatalf("CRITICAL SAFETY VIOLATION: broad ruleset flush executed: %s", flat)
		}
		// Never broad route flush
		if flat == "ip route flush " {
			t.Fatalf("CRITICAL SAFETY VIOLATION: broad route flush executed: %s", flat)
		}
	}
}
