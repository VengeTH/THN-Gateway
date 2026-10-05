package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/planner"
)

func TestProductionSafetyDriverIsDisabled(t *testing.T) {
	driver := NewProductionDriver()

	// 1. CanApply must permanently report false
	if driver.CanApply() {
		t.Fatal("ProductionDriver.CanApply() reported true; must permanently be false")
	}

	// 2. Direct mutation call must fail with ErrProductionActivationDisabled
	err := driver.Execute(context.Background(), OpLinkSetUp{Interface: "enp0s31f6"})
	if err == nil {
		t.Fatal("ProductionDriver.Execute succeeded; must fail closed")
	}
	if !errors.Is(err, ErrProductionActivationDisabled) {
		t.Errorf("expected ErrProductionActivationDisabled, got %v", err)
	}

	// 3. Central activation package constant must be false
	if activation.CanApply() {
		t.Fatal("activation.CanApply() is true; MUST remain false for production safety")
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
