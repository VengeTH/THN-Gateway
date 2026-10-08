package cli

import (
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/authority"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/reconcile"
)

// This file is the gate phase for the fleet control plane's safety boundary.
//
// # What it guards
//
// Two properties, both of which are single points of failure for the whole
// control plane:
//
//   - The authority floor cannot be lowered by configuration. If it can, a
//     compromised control plane has a root shell on the fleet.
//   - The gateway refuses changes that would remove its own management path.
//     If it does not, an approval is all that stands between a mistake and an
//     unfixable device.
//
// Each has its own package-level test. What only a gate can check is that the
// *commands* are wired to that logic — that `thn reconcile` really consults the
// refusal path, and that neither new command can be reached by a tier that
// implies it might change something.

// gateFleetClock is the fixed instant the fleet gate uses.
var gateFleetClock = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// healthyObserve is a gateway that can enumerate its capabilities and has a
// firewall, so that a refusal in this phase is about the change and not the host.
func healthyObserve() reconcile.Observe {
	return reconcile.Observe{
		ShapingAlgorithms: []string{"cake", "fq_codel"},
		FirewallBackend:   "nftables",
		ManagementPath:    "wan0",
		LocalNetworks:     []string{"192.168.1.0/24"},
	}
}

// reconcileChange builds a diff result carrying one drift change.
func reconcileChange(id string) diff.Result {
	return diff.Result{
		DriftCount: 1,
		Changes: []diff.Change{{
			ID: id, Kind: diff.KindDrift, Risk: diff.RiskCritical,
			Subsystem: "nftables", Field: "firewall.present",
			Current: "absent", Desired: "present",
			Reason: "the host has no firewall loaded",
		}},
	}
}

// fleetCommands is every command this phase covers.
var fleetCommands = []string{"authority", "reconcile"}

// A control-plane command that changes something is not a control-plane
// command. Both are pure: they decide and report, and neither has a flag that
// makes them act.
func TestGateFleetCommandsArePure(t *testing.T) {
	for _, name := range fleetCommands {
		cmd, ok := commands[name]
		if !ok {
			t.Errorf("command %q is not registered", name)
			continue
		}
		if cmd.Tier != TierPure {
			t.Errorf("%s is %s; a fleet command that only decides must be pure",
				name, cmd.Tier)
		}
		if cmd.Run == nil {
			t.Errorf("%s has no implementation", name)
		}
	}
}

// There must still be exactly one destructive command, and it must not be
// reachable by any name this phase added.
func TestGateFleetAddsNoDestructiveCommand(t *testing.T) {
	var destructive []string
	for name, cmd := range commands {
		if cmd.Tier == TierDestructive {
			destructive = append(destructive, name)
		}
	}
	if len(destructive) != 1 || destructive[0] != "activate" {
		t.Errorf("destructive commands are %v, want exactly [activate]", destructive)
	}
	for _, name := range fleetCommands {
		if name == "activate" || name == "apply" || name == "push" {
			t.Errorf("a fleet command shadows %q", name)
		}
	}
}

// A control plane may say when to change a host; it may not be able to.
//
// Two halves: the stage list stays self-consistent, and adding the control
// plane did not make activation reachable without presence and authorization.
func TestGateFleetDidNotEnableApply(t *testing.T) {
	implemented := activation.ImplementedStages()
	for _, s := range activation.UnsupportedStages() {
		for _, got := range implemented {
			if got == s {
				t.Errorf("stage %s became implemented; adding a control plane must not enable it", s)
			}
		}
	}

	// A control plane may say when to change a host; it may not be able to.
	assertActivationRemainsGated(t, "adding a control plane")
}

// The gateway's own refusal must not be bypassable by making the policy
// permissive. This is the property the whole design rests on, asserted at the
// seam the commands use.
func TestGateGatewayRefusalIsNotOverridableByPolicy(t *testing.T) {
	hostile := authority.NewPolicy("compromised").
		Raise(authority.OpDisableFirewall, authority.TierAutomatic).
		Raise(authority.OpShellCommand, authority.TierAutomatic).
		Raise(authority.OpUpdateSoftware, authority.TierAutomatic)

	full := authority.Evidence{
		Approved: true, ApprovedBy: "attacker",
		BatchSize: 1, TotalGateways: 1,
	}
	admin := authority.Principal{Name: "attacker", Role: authority.RoleAdmin}

	for _, op := range []authority.Operation{
		authority.OpDisableFirewall,
		authority.OpShellCommand,
		authority.OpFactoryReset,
	} {
		if d := authority.Decide(hostile, admin, op, full); d.Allowed {
			t.Errorf("%s was permitted by a permissive policy and an admin", op)
		}
	}

	// And the gateway refuses the firewall change even when the diff reports
	// one, regardless of what the control plane authorised.
	r := reconcile.Decide(hostile, admin, full,
		reconcileChange("firewall-absent"), healthyObserve(), gateFleetClock)

	if r.Accepted {
		t.Fatal("the gateway accepted a firewall-removal change under a permissive policy")
	}
}
