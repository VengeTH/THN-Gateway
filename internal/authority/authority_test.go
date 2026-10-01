package authority_test

import (
	"testing"

	"github.com/venth/thn-gateway/internal/authority"
)

// admin is the principal used where the role is not the subject of the test.
func admin() authority.Principal {
	return authority.Principal{Name: "t", Role: authority.RoleAdmin}
}

func approved() authority.Evidence {
	return authority.Evidence{
		Approved: true, ApprovedBy: "a-human",
		BatchSize: 1, TotalGateways: 100,
	}
}

// ------------------------------------------------- the floor cannot be lowered

// This is the package's central property. If a policy can lower a floor, then a
// compromised control plane can write any policy it likes and the floor is
// decoration.
func TestPolicyCannotLowerTheFloor(t *testing.T) {
	p := authority.NewPolicy("permissive")

	// Ask for the least demanding tier for each forbidden operation.
	p = p.Raise(authority.OpShellCommand, authority.TierAutomatic).
		Raise(authority.OpFactoryReset, authority.TierAutomatic).
		Raise(authority.OpDisableFirewall, authority.TierAutomatic).
		Raise(authority.OpChangeWAN, authority.TierAutomatic)

	for _, op := range []authority.Operation{
		authority.OpShellCommand,
		authority.OpFactoryReset,
		authority.OpDisableFirewall,
	} {
		if got := p.Effective(op); got != authority.TierForbidden {
			t.Errorf("%s: a policy lowered the floor to %s", op, got)
		}
		if d := authority.Decide(p, admin(), op, approved()); d.Allowed {
			t.Errorf("%s was permitted by a policy that asked for it to be", op)
		}
	}

	if p.LoweringAttempts() != 4 {
		t.Errorf("LoweringAttempts = %d, want 4; the refusal must be counted, not silent",
			p.LoweringAttempts())
	}
}

func TestPolicyMayRaiseTheFloor(t *testing.T) {
	base := authority.NewPolicy("default")
	strict := base.Raise(authority.OpChangeQoS, authority.TierControlled)

	if base.Effective(authority.OpChangeQoS) != authority.TierApproval {
		t.Error("the base policy is not approval for QoS")
	}
	if strict.Effective(authority.OpChangeQoS) != authority.TierControlled {
		t.Error("a policy failed to raise a requirement")
	}
	if strict.LoweringAttempts() != 0 {
		t.Error("raising a requirement was counted as a lowering")
	}
}

// Every operation outside the vocabulary must be forbidden. A permissive
// default here would make forgetting to classify something the safe choice.
func TestUnknownOperationsAreForbidden(t *testing.T) {
	p := authority.NewPolicy("any")
	for _, op := range []authority.Operation{
		"", "exec", "run.shell", "DEBUG", "system.reboot", "firewall.disable ",
	} {
		if got := p.Effective(op); got != authority.TierForbidden {
			t.Errorf("operation %q defaulted to %s, want forbidden", op, got)
		}
	}
}

func TestEveryOperationHasAFloorAndAMinimumRole(t *testing.T) {
	p := authority.NewPolicy("default")

	for _, op := range authority.AllOperations() {
		if _, ok := authority.Floor[op]; !ok {
			t.Errorf("operation %s has no floor entry", op)
		}
		// The floor a default policy produces is the floor itself, which is
		// what makes "a policy cannot lower a requirement" checkable.
		if got, want := p.Effective(op), authority.FloorFor(op); got != want {
			t.Errorf("%s: a default policy reports %s, want the floor %s", op, got, want)
		}
		if authority.MinimumRole(op) == "" {
			t.Errorf("operation %s has no minimum role", op)
		}

		// Nothing but a read may be free to everybody. A write that is
		// automatic for a viewer is a bug in the table, not a decision.
		if authority.FloorFor(op) == authority.TierAutomatic &&
			authority.MinimumRole(op) == authority.RoleViewer &&
			op != authority.OpReadTelemetry && op != authority.OpReadConfiguration {
			t.Errorf("operation %s is free for anyone; that should be deliberate", op)
		}
	}
}

// ---------------------------------------------------------- role is a second gate

// A permissive policy is not a grant to everybody.
func TestRoleGatesIndependentlyOfPolicy(t *testing.T) {
	permissive := authority.NewPolicy("permissive").
		Raise(authority.OpAddFirewallRule, authority.TierAutomatic)

	viewer := authority.Principal{Name: "v", Role: authority.RoleViewer}
	d := authority.Decide(permissive, viewer, authority.OpAddFirewallRule, approved())

	if d.Allowed {
		t.Error("a viewer was permitted to change the firewall")
	}
	if d.Satisfied {
		t.Error("a refused request was reported as satisfied")
	}
	if d.Reason == "" {
		t.Error("a refusal must state a reason")
	}
}

// A strong role does not override the floor.
func TestRoleDoesNotOverrideTheFloor(t *testing.T) {
	p := authority.NewPolicy("permissive").Raise(authority.OpShellCommand, authority.TierAutomatic)

	d := authority.Decide(p, admin(), authority.OpShellCommand,
		authority.Evidence{Approved: true, ApprovedBy: "root", BatchSize: 1, TotalGateways: 1})

	if d.Allowed || d.Satisfied {
		t.Errorf("an admin performed a forbidden operation: %+v", d)
	}
}

// -------------------------------------------- approval versus not-yet

// The distinction between "no" and "not yet" is the difference between a system
// that can support an approval workflow and one that can only say yes or no.
func TestPermittedWithoutApprovalIsAllowedButNotSatisfied(t *testing.T) {
	p := authority.NewPolicy("default")
	who := authority.Principal{Name: "op", Role: authority.RoleNetworkOperator}

	d := authority.Decide(p, who, authority.OpChangeQoS, authority.Evidence{})

	if !d.Allowed {
		t.Errorf("the policy should permit this operation: %s", d.Reason)
	}
	if d.Satisfied {
		t.Error("a change needing approval was satisfied without any")
	}
	if d.Required != authority.TierApproval {
		t.Errorf("Required = %s, want approval", d.Required)
	}
}

func TestApprovalSatisfiesAnApprovalTier(t *testing.T) {
	p := authority.NewPolicy("default")
	who := authority.Principal{Name: "op", Role: authority.RoleNetworkOperator}

	d := authority.Decide(p, who, authority.OpChangeQoS, approved())
	if !d.Satisfied {
		t.Errorf("an approved change was not satisfied: %s", d.Reason)
	}
}

// -------------------------------------------------------------- rollouts

// A canary must actually be small. A batch of one from a fleet of one is not a
// canary, and treating it as one lets a fleet-wide change pass the check.
func TestControlledTierRejectsAFirstStageThatIsNotSmall(t *testing.T) {
	p := authority.NewPolicy("default").Raise(authority.OpAddFirewallRule, authority.TierControlled)
	who := authority.Principal{Name: "sec", Role: authority.RoleSecurityOperator}

	wide := authority.Evidence{Approved: true, ApprovedBy: "h", BatchSize: 900, TotalGateways: 1000}
	if d := authority.Decide(p, who, authority.OpAddFirewallRule, wide); d.Satisfied {
		t.Error("a batch of 900/1000 was accepted as a first rollout stage")
	}

	narrow := authority.Evidence{Approved: true, ApprovedBy: "h", BatchSize: 1, TotalGateways: 1000}
	if d := authority.Decide(p, who, authority.OpAddFirewallRule, narrow); !d.Satisfied {
		t.Errorf("a batch of 1/1000 was refused: %s", d.Reason)
	}
}

// A halted rollout stays halted. Continuing is a new decision.
func TestHaltedRolloutIsNotSatisfied(t *testing.T) {
	p := authority.NewPolicy("default").Raise(authority.OpAddFirewallRule, authority.TierControlled)
	who := authority.Principal{Name: "sec", Role: authority.RoleSecurityOperator}

	ev := authority.Evidence{
		Approved: true, ApprovedBy: "h",
		BatchSize: 1, TotalGateways: 1000,
		RolloutHalted: true,
	}

	if d := authority.Decide(p, who, authority.OpAddFirewallRule, ev); d.Satisfied {
		t.Error("a halted rollout was allowed to continue")
	}
}

func TestStrongTierAlsoConstrainsTheBatch(t *testing.T) {
	p := authority.NewPolicy("default")
	ev := authority.Evidence{Approved: true, ApprovedBy: "h", BatchSize: 400, TotalGateways: 1000}

	if d := authority.Decide(p, admin(), authority.OpChangeWAN, ev); d.Satisfied {
		t.Error("strong approval covered a batch of 400/1000")
	}
}

// ------------------------------------------------------------ tier ordering

func TestTierOrderingIsTotal(t *testing.T) {
	ordered := []authority.Tier{
		authority.TierAutomatic,
		authority.TierRecorded,
		authority.TierNotified,
		authority.TierApproval,
		authority.TierControlled,
		authority.TierStrong,
		authority.TierForbidden,
	}
	for i := 1; i < len(ordered); i++ {
		if !(ordered[i-1] < ordered[i]) {
			t.Errorf("tier %s is not below %s", ordered[i-1], ordered[i])
		}
	}
}

func TestInvalidTierIsNotAValidOverride(t *testing.T) {
	p := authority.NewPolicy("x").Raise(authority.OpChangeQoS, authority.Tier(99))
	if got := p.Effective(authority.OpChangeQoS); got != authority.TierApproval {
		t.Errorf("an unparseable tier changed the effective requirement to %s", got)
	}
}

// ------------------------------------------------------------- rendering

func TestRenderPolicyShowsTheFloorAndTheOverrides(t *testing.T) {
	p := authority.NewPolicy("org-a").
		Raise(authority.OpChangeQoS, authority.TierControlled)

	out := authority.RenderPolicy(p)
	for _, want := range []string{
		"cannot lower",                   // the invariant, stated where an operator reads
		string(authority.OpShellCommand), // every operation listed
		"never performed",                // the forbidden ones marked
		"Raised by this policy",          // and what the policy added
	} {
		if !contains(out, want) {
			t.Errorf("the rendered policy does not mention %q", want)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
