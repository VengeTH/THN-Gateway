package execution

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// SimulatedDriver provides an in-memory execution driver for unit and fault-injection testing.
type SimulatedDriver struct {
	mu                    sync.RWMutex
	canApply              bool
	capabilities          Capabilities
	state                 *StateSnapshot
	executedOps           []Operation
	rollbackOps           []Operation
	inRollback            bool
	failAtOpIndex         int
	failAtOpKind          OpKind
	failRollbackAtOpIndex int
	failHealthCheck       bool
	healthCheckFailReason string

	// Unmanaged state tracking to prove isolation
	UnmanagedNFTables   map[string]bool
	UnmanagedRoutes     map[string]bool
	UnmanagedInterfaces map[string]bool
}

func NewSimulatedDriver() *SimulatedDriver {
	snap := NewStateSnapshot()
	return &SimulatedDriver{
		canApply:              true,
		capabilities:          Capabilities{IP: true, NFT: true, Sysctl: true, TC: true},
		state:                 snap,
		failAtOpIndex:         -1,
		failRollbackAtOpIndex: -1,
		UnmanagedNFTables:     make(map[string]bool),
		UnmanagedRoutes:       make(map[string]bool),
		UnmanagedInterfaces:   make(map[string]bool),
	}
}

func (d *SimulatedDriver) Name() string {
	return "simulated"
}

func (d *SimulatedDriver) CanApply() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.canApply
}

func (d *SimulatedDriver) SetCanApply(v bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.canApply = v
}

func (d *SimulatedDriver) SetCapabilities(c Capabilities) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.capabilities = c
}

func (d *SimulatedDriver) SetFailAtOpIndex(idx int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failAtOpIndex = idx
}

func (d *SimulatedDriver) SetFailAtOpKind(k OpKind) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failAtOpKind = k
}

func (d *SimulatedDriver) SetFailRollbackAtOpIndex(idx int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failRollbackAtOpIndex = idx
}

func (d *SimulatedDriver) SetFailHealthCheck(fail bool, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failHealthCheck = fail
	d.healthCheckFailReason = reason
}

func (d *SimulatedDriver) SetInRollback(v bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inRollback = v
}

func (d *SimulatedDriver) ExecutedOps() []Operation {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Operation, len(d.executedOps))
	copy(out, d.executedOps)
	return out
}

func (d *SimulatedDriver) RollbackOps() []Operation {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Operation, len(d.rollbackOps))
	copy(out, d.rollbackOps)
	return out
}

func (d *SimulatedDriver) DetectCapabilities(ctx context.Context) (Capabilities, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.capabilities, nil
}

func (d *SimulatedDriver) Execute(ctx context.Context, op Operation) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.canApply {
		return ErrCannotApply
	}

	if d.inRollback {
		idx := len(d.rollbackOps)
		if d.failRollbackAtOpIndex >= 0 && idx == d.failRollbackAtOpIndex {
			return fmt.Errorf("%w: injected rollback failure at op %d (%s)", ErrRollbackFailed, idx, op.Kind())
		}
		d.rollbackOps = append(d.rollbackOps, op)
	} else {
		idx := len(d.executedOps)
		if d.failAtOpIndex >= 0 && idx == d.failAtOpIndex {
			d.inRollback = true
			return fmt.Errorf("%w: injected failure at op %d (%s)", ErrOperationFailed, idx, op.Kind())
		}
		if d.failAtOpKind != "" && op.Kind() == d.failAtOpKind {
			d.inRollback = true
			return fmt.Errorf("%w: injected failure at op kind %s", ErrOperationFailed, op.Kind())
		}
		d.executedOps = append(d.executedOps, op)
	}

	// Apply mutation to in-memory state
	return d.applyStateMutation(op)
}

func (d *SimulatedDriver) applyStateMutation(op Operation) error {
	switch o := op.(type) {
	case OpLinkSetUp:
		d.state.Links[o.Interface] = "up"
	case OpLinkSetDown:
		d.state.Links[o.Interface] = "down"
	case OpAddressAdd:
		addrs := d.state.Addresses[o.Interface]
		if !slices.Contains(addrs, o.CIDR) {
			d.state.Addresses[o.Interface] = append(addrs, o.CIDR)
		}
	case OpAddressDelete:
		addrs := d.state.Addresses[o.Interface]
		var filtered []string
		for _, a := range addrs {
			if a != o.CIDR {
				filtered = append(filtered, a)
			}
		}
		d.state.Addresses[o.Interface] = filtered
	case OpRouteAdd:
		if o.Destination == "default" {
			d.state.DefaultRoute = o.Gateway
		}
	case OpRouteReplace:
		if o.Destination == "default" {
			d.state.DefaultRoute = o.Gateway
		}
	case OpRouteDelete:
		if o.Destination == "default" {
			d.state.DefaultRoute = ""
		}
	case OpSysctlSet:
		d.state.Sysctls[o.Key] = o.Value
	case OpNFTApplyTHNTable:
		d.state.NFTablesTHNPresent = true
		d.state.NFTablesTHNContent = fmt.Sprintf("policy %s", o.InboundPolicy)
	case OpNFTDeleteTHNTable:
		d.state.NFTablesTHNPresent = false
		d.state.NFTablesTHNContent = ""
	case OpQDiscApply:
		// QDisc applied
	case OpQDiscReplace:
		// Captured qdisc restored
	case OpQDiscDelete:
		// QDisc removed
	case OpTCClassApply:
		// TC class applied
	case OpTCClassDelete:
		// TC class removed
	case OpTCFilterApply:
		// TC filter applied
	case OpTCFilterDelete:
		// TC filter removed
	case OpTCStateRestore:
		// Captured state restored
	}
	return nil
}

func (d *SimulatedDriver) CaptureState(ctx context.Context, scope BackupScope) (*StateSnapshot, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	snapshot := d.state.Clone()
	if scope.QDiscs {
		for _, iface := range scope.Interfaces {
			if _, ok := snapshot.QDiscs[iface]; !ok {
				snapshot.QDiscs[iface] = TcBaseline{
					Device:   iface,
					Captured: true,
				}
			}
		}
		snapshot.MarkCaptured("qdiscs")
	}
	return snapshot, nil
}

func (d *SimulatedDriver) VerifyHealth(ctx context.Context, checks []HealthCheck) (HealthResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.failHealthCheck {
		d.inRollback = true
		reason := d.healthCheckFailReason
		if reason == "" {
			reason = "injected health check failure"
		}
		return HealthResult{
			Healthy:       false,
			FailureReason: reason,
		}, nil
	}

	var results []HealthCheckResult
	allPassed := true

	for _, hc := range checks {
		res := HealthCheckResult{
			Target:      hc.Target,
			Check:       hc.Check,
			Expectation: hc.Expectation,
			Passed:      true,
		}

		switch hc.Check {
		case "link_carrier":
			link := d.state.Links[hc.Target]
			if link != "up" {
				res.Passed = false
				res.Observed = fmt.Sprintf("link is %s", link)
				allPassed = false
			} else {
				res.Observed = "link is UP"
			}

		case "address_assigned":
			parts := strings.Split(hc.Target, ":")
			iface := parts[0]
			addrs := d.state.Addresses[iface]
			found := false
			for _, a := range addrs {
				if strings.Contains(hc.Expectation, a) {
					found = true
					break
				}
			}
			if !found {
				res.Passed = false
				res.Observed = fmt.Sprintf("addresses: %v", addrs)
				allPassed = false
			} else {
				res.Observed = "address is assigned"
			}

		case "kernel_forwarding":
			val := d.state.Sysctls["net.ipv4.ip_forward"]
			if val != "1" {
				res.Passed = false
				res.Observed = fmt.Sprintf("net.ipv4.ip_forward = %q", val)
				allPassed = false
			} else {
				res.Observed = "net.ipv4.ip_forward = 1"
			}

		case "firewall_active":
			if !d.state.NFTablesTHNPresent {
				res.Passed = false
				res.Observed = "table inet thn is absent"
				allPassed = false
			} else {
				res.Observed = "table inet thn is active"
			}
		}

		results = append(results, res)
	}

	failReason := ""
	if !allPassed {
		failReason = "one or more post-apply health checks failed"
	}

	return HealthResult{
		Healthy:       allPassed,
		Checks:        results,
		FailureReason: failReason,
	}, nil
}
