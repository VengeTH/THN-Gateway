package execution

import (
	"context"
)

// ProductionDriver represents the default execution driver for production hosts (including the Dell server).
//
// In this build, live activation is strictly disabled: CanApply() permanently reports false,
// and any mutation request returns ErrProductionActivationDisabled.
type ProductionDriver struct{}

func NewProductionDriver() *ProductionDriver {
	return &ProductionDriver{}
}

func (d *ProductionDriver) Name() string {
	return "production"
}

func (d *ProductionDriver) CanApply() bool {
	return false
}

func (d *ProductionDriver) DetectCapabilities(ctx context.Context) (Capabilities, error) {
	return Capabilities{
		IP:     true,
		NFT:    true,
		Sysctl: true,
		TC:     true,
		Details: map[string]string{
			"production_status": "observation-only",
		},
	}, nil
}

func (d *ProductionDriver) Execute(ctx context.Context, op Operation) error {
	return ErrProductionActivationDisabled
}

func (d *ProductionDriver) CaptureState(ctx context.Context, scope BackupScope) (*StateSnapshot, error) {
	// Read-only inspection is permitted
	snap := NewStateSnapshot()
	for _, iface := range scope.Interfaces {
		snap.Links[iface] = "down"
		snap.Addresses[iface] = nil
	}
	snap.Sysctls["net.ipv4.ip_forward"] = "0"
	snap.NFTablesTHNPresent = false
	return snap, nil
}

func (d *ProductionDriver) VerifyHealth(ctx context.Context, checks []HealthCheck) (HealthResult, error) {
	// Verification without mutation
	return HealthResult{
		Healthy:       false,
		FailureReason: "production activation is disabled",
	}, nil
}
