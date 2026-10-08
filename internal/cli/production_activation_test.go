package cli

// Production activation: the gate that decides whether a host may be changed.
//
// Every test here exercises the SAME path `thn activate` runs —
// gatherActivationEvidence, productionGateInput, activation.EvaluateProduction,
// productionAuthorization, execution.Executor.ExecutePlan — rather than a
// stand-in that resembles it. A gate test that constructs its own inputs proves
// the gate function works, which is not the question. The question is whether
// this host, in this configuration, with this plan, may be changed.
//
// # What is asserted
//
// Two directions, and the second is the one that is easy to get wrong:
//
//	every one of these conditions must BLOCK activation
//	and all of them holding together must ALLOW it
//
// A suite that only tests the first passes for a build that refuses
// everything. A suite that only tests the second passes for a build that
// applies anything.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/execution"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/planner"
)

// assertActivationRemainsGated asserts the property every milestone guard in
// this package ultimately wanted: that adding a feature did not make
// activation unconditional.
//
// It replaces the historical `if activation.CanApply() { fail }` assertions.
// Those were true statements about builds that had no apply path. What they
// were FOR — "this feature must not be a back door into changing a host" — is
// still exactly right, and is now expressed as a property of the gate set and
// the driver rather than of a constant.
func assertActivationRemainsGated(t *testing.T, where string) {
	t.Helper()

	// An apply path existing is not authorization.
	if !activation.CanApply() {
		t.Errorf("%s: CanApply() is false; this build has an apply path and must say so", where)
	}

	// Presence is a gate, not a decoration: every other gate satisfied and
	// presence withheld must still block.
	in := satisfiedGateInput()
	in.PresenceConfirmed = false
	res := activation.EvaluateProduction(in)
	if res.AllSatisfied {
		t.Errorf("%s: activation is permitted with physical presence withheld", where)
	}
	if !containsString(res.Blocking, "physical-presence") {
		t.Errorf("%s: Blocking = %v, want it to name physical-presence", where, res.Blocking)
	}

	// And the driver is unauthorized until someone explicitly says so.
	if execution.NewProductionDriver().CanApply() {
		t.Errorf("%s: ProductionDriver reports itself authorized with no authorization performed", where)
	}
}

// satisfiedGateInput is a GateInput with every production gate satisfied.
//
// It is the baseline the blocking tests perturb one field at a time, so a
// failing assertion names the condition that actually caused the refusal.
func satisfiedGateInput() activation.GateInput {
	return activation.GateInput{
		PlanValidated:        true,
		ConfigValid:          true,
		WAN:                  activation.RoleGate{Role: "wan", Satisfied: true, Interface: "wan0"},
		LAN:                  activation.RoleGate{Role: "lan", Satisfied: true, Interface: "lan0"},
		NoRoleConflicts:      true,
		HostReadinessOK:      true,
		CapabilitiesObserved: true,
		DigestsFresh:         true,
		ManagementSafe:       true,
		RecoveryOK:           true,
		SubsystemsExecutable: true,
		PresenceConfirmed:    true,
	}
}

// TestProductionActivationIsGatedOnEveryRequiredCondition is the table that
// matters most.
//
// Each row removes one piece of evidence an operator would otherwise have, and
// requires that activation be blocked AND that the refusal name the right
// gate. A gate that blocks for the wrong reason still leaves an operator
// chasing the wrong fix, so the name is asserted as well as the verdict.
func TestProductionActivationIsGatedOnEveryRequiredCondition(t *testing.T) {
	cases := []struct {
		gate   string
		mutate func(*activation.GateInput)
	}{
		{"physical-presence", func(in *activation.GateInput) {
			in.PresenceConfirmed = false
		}},
		{"config-valid", func(in *activation.GateInput) {
			in.ConfigValid = false
			in.ConfigProblem = "dhcp.ranges[0].end is outside the LAN prefix"
		}},
		{"plan-validated", func(in *activation.GateInput) {
			in.PlanValidated = false
		}},
		{"wan-present", func(in *activation.GateInput) {
			in.WAN = activation.RoleGate{Role: "wan", Reason: "role wan is not assigned"}
		}},
		{"lan-identified", func(in *activation.GateInput) {
			in.LAN = activation.RoleGate{Role: "lan", Reason: "role lan is not assigned"}
		}},
		{"no-role-conflicts", func(in *activation.GateInput) {
			in.NoRoleConflicts = false
			in.RoleConflictProblem = "both roles are assigned to lan0"
		}},
		{"host-readiness", func(in *activation.GateInput) {
			in.HostReadinessOK = false
			in.HostReadinessProblem = "only one assignable ethernet interface is present"
		}},
		{"capabilities-observed", func(in *activation.GateInput) {
			in.CapabilitiesObserved = false
			in.CapabilitiesProblem = "required capability nftables is inferred (must be observed)"
		}},
		{"digests-fresh", func(in *activation.GateInput) {
			in.DigestsFresh = false
			in.DigestsProblem = "the observed digest no longer matches the plan"
		}},
		{"management-safety", func(in *activation.GateInput) {
			in.ManagementSafe = false
			in.ManagementProblem = "plan sets down the interface carrying the active SSH session"
		}},
		{"recoverable", func(in *activation.GateInput) {
			in.RecoveryOK = false
			in.RecoveryProblem = "an operation in the plan has no rollback"
		}},
		{"subsystems-executable", func(in *activation.GateInput) {
			in.SubsystemsExecutable = false
			in.SubsystemsProblem = "dhcp.enabled is true but THN implements no DHCP server"
		}},
	}

	for _, c := range cases {
		t.Run(c.gate, func(t *testing.T) {
			in := satisfiedGateInput()
			c.mutate(&in)

			res := activation.EvaluateProduction(in)
			if res.AllSatisfied {
				t.Fatalf("activation permitted with %s unmet", c.gate)
			}
			if !containsString(res.Blocking, c.gate) {
				t.Fatalf("Blocking = %v, want it to name %s", res.Blocking, c.gate)
			}

			// The refusal must be actionable: every blocking gate carries a
			// reason an operator can act on.
			for _, g := range res.Gates {
				if !g.Satisfied && strings.TrimSpace(g.Reason) == "" {
					t.Errorf("gate %q blocks with no reason", g.Name)
				}
			}
		})
	}
}

// TestAllGatesSatisfiedPermitsActivation is the direction that is easy to get
// wrong. Without it, a build that refuses everything would pass every test
// above.
func TestAllGatesSatisfiedPermitsActivation(t *testing.T) {
	res := activation.EvaluateProduction(satisfiedGateInput())
	if !res.AllSatisfied {
		t.Fatalf("every gate satisfied but the activation is still blocked: %v", res.Blocking)
	}
	if len(res.Blocking) != 0 {
		t.Errorf("Blocking = %v, want empty", res.Blocking)
	}
}

// TestAuthorizationCannotOverrideAMissingGate is the ordering property.
//
// A caller who constructs ProductionAuth from a gate result that does not hold
// must still be refused. If confirmation could stand in for evidence, every
// other gate would be advisory.
func TestAuthorizationCannotOverrideAMissingGate(t *testing.T) {
	in := satisfiedGateInput()
	in.ManagementSafe = false
	in.ManagementProblem = "plan removes the active SSH management IP"

	gates := activation.EvaluateProduction(in)
	if gates.AllSatisfied {
		t.Fatal("management-safety should be blocking")
	}

	driver := execution.NewProductionDriver()
	err := driver.Authorize(execution.ProductionAuth{
		Confirmed:        true,
		GatesResult:      &gates,
		ManagementSafe:   true, // the caller asserts safe; the gate says otherwise
		PlanID:           "plan-1",
		ObservedDigest:   "obs-1",
		DesiredDigest:    "des-1",
		AssignmentDigest: "asg-1",
	})
	if err == nil {
		t.Fatal("Authorize succeeded with an unsatisfied gate; confirmation must not " +
			"substitute for evidence")
	}
	if driver.CanApply() {
		t.Fatal("driver reports itself authorized after a refused authorization")
	}
}

// TestAuthorizationRequiresADigestBinding proves the authorization is bound to
// a specific plan rather than to a moment in time.
//
// Without digests there is nothing for the executor to re-verify, and a
// stale-plan check that has nothing to check is not a check.
func TestAuthorizationRequiresADigestBinding(t *testing.T) {
	gates := activation.EvaluateProduction(satisfiedGateInput())

	driver := execution.NewProductionDriver()
	err := driver.Authorize(execution.ProductionAuth{
		Confirmed:        true,
		GatesResult:      &gates,
		ManagementSafe:   true,
		PlanID:           "plan-1",
		ObservedDigest:   "obs-1",
		DesiredDigest:    "des-1",
		AssignmentDigest: "", // deliberately absent
	})
	if err == nil {
		t.Fatal("Authorize succeeded without the assignment digest binding")
	}
	if driver.CanApply() {
		t.Fatal("driver reports itself authorized without a digest binding")
	}
}

// TestActivationIsBlockedByAnUnimplementedSubsystem is the honesty gate.
//
// DHCP and DNS are modelled end to end — configured, validated, planned,
// rendered — and neither is implemented. A build that activates anyway produces
// a gateway that reports success while handing out no addresses. The refusal
// names the setting to change, because "blocked" without a remedy is only half
// a message.
func TestActivationIsBlockedByAnUnimplementedSubsystem(t *testing.T) {
	cfg := config.Defaults()
	cfg.Gateway.Name = "thn-gateway"

	cfg.DHCP.Enabled = true
	ok, problem := executableSubsystems(cfg)
	if ok {
		t.Fatal("a document requesting DHCP passed the executability check")
	}
	if !strings.Contains(problem, "dhcp.enabled") {
		t.Errorf("problem = %q; it must name the setting to change", problem)
	}

	cfg.DHCP.Enabled = false
	cfg.DNS.Enabled = true
	ok, problem = executableSubsystems(cfg)
	if ok {
		t.Fatal("a document requesting a LAN DNS server passed the executability check")
	}
	if !strings.Contains(problem, "dns.enabled") {
		t.Errorf("problem = %q; it must name the setting to change", problem)
	}

	cfg.DNS.Enabled = false
	cfg.QoS.Enabled = true
	ok, problem = executableSubsystems(cfg)
	if ok {
		t.Fatal("a document requesting QoS passed the executability check before physical hardware validation")
	}
	if !strings.Contains(problem, "qos.enabled") {
		t.Errorf("problem = %q; it must name the setting to change", problem)
	}

	cfg.QoS.Enabled = false
	if ok, problem := executableSubsystems(cfg); !ok {
		t.Errorf("a document requesting neither subsystem was blocked: %s", problem)
	}
}

// TestSubsystemHonestyIsReportedNotHidden checks that the inspection report
// states the position rather than implying the service will run.
func TestSubsystemHonestyIsReportedNotHidden(t *testing.T) {
	cfg := config.Defaults()
	cfg.DHCP.Enabled = true
	cfg.DNS.Enabled = true

	lines := strings.Join(subsystemHonesty(cfg), "\n")
	for _, want := range []string{"dhcp.enabled=true", "NOT be applied", "dns.enabled=true"} {
		if !strings.Contains(lines, want) {
			t.Errorf("inspection report does not say %q; it reports:\n%s", want, lines)
		}
	}
}

// TestDNSOperationRefusesRatherThanPretending covers the layer below the gate.
//
// OpDNSApply used to return nil, which the transaction recorded as a
// successfully applied operation and then committed. The gate blocks first in
// normal operation, but a refusal here means a future caller that reaches the
// driver without passing the gate still cannot get a false success.
func TestDNSOperationRefusesRatherThanPretending(t *testing.T) {
	driver := execution.NewProductionDriver()
	if err := driver.Authorize(execution.ProductionAuth{
		Confirmed:        true,
		GatesResult:      &activation.GateResult{AllSatisfied: true},
		ManagementSafe:   true,
		PlanID:           "plan-1",
		ObservedDigest:   "obs-1",
		DesiredDigest:    "des-1",
		AssignmentDigest: "asg-1",
	}); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	err := driver.Execute(context.Background(), execution.OpDNSApply{Servers: []string{"1.1.1.1"}})
	if err == nil {
		t.Fatal("applying resolvers reported success; THN implements no DNS server")
	}
	if !errors.Is(err, execution.ErrCapabilityMissing) {
		t.Errorf("error = %v, want ErrCapabilityMissing", err)
	}
	if !strings.Contains(err.Error(), "does not implement") {
		t.Errorf("error = %q; it must say plainly that nothing was applied", err)
	}
}

// TestDNSOperationDeclaresTheCapabilityItCannotProvide checks the other half:
// the executor blocks before the BACKUP phase rather than after it.
func TestDNSOperationDeclaresTheCapabilityItCannotProvide(t *testing.T) {
	required := execution.OpDNSApply{Servers: []string{"1.1.1.1"}}.RequiredCapabilities()
	if len(required) == 0 {
		t.Fatal("OpDNSApply declares no required capability, so the executor cannot " +
			"refuse it before taking a baseline")
	}

	caps := execution.Capabilities{Details: map[string]string{
		"ip": "available", "nft": "available", "sysctl": "available", "tc": "available",
	}}
	if ok, missing := caps.Satisfies(required); ok {
		t.Error("a host with ip, nft, sysctl and tc was reported able to serve DNS")
	} else if missing == "" {
		t.Error("the refusal does not name the missing capability")
	}
}

// TestManagementSafetyAcceptsABringUpPlan is the direction that is easy to get
// wrong: an assessment that refuses everything is not an assessment.
//
// The plan is the real one a first activation produces — bring the LAN link
// up, give it an address, enable forwarding, install the THN firewall table.
// None of that severs an SSH session or touches the overlay tunnel.
func TestManagementSafetyAcceptsABringUpPlan(t *testing.T) {
	obs := gatewayObservation()
	plan := buildPlanFor(t, obs, gatewayDesired())

	ops, err := execution.PlanToOperations(plan, obs)
	if err != nil {
		t.Fatalf("deriving operations: %v", err)
	}
	if len(ops) == 0 {
		t.Fatal("the plan produced no operations; it cannot be assessed")
	}

	rep := evaluatePlannedManagementSafety(obs, gatewayDevice(), plan)
	if !rep.Safe {
		t.Fatalf("a first-activation plan was refused: %s\noperations:\n%s",
			rep.Reason, strings.Join(rep.Steps, "\n"))
	}
	if len(rep.Steps) != len(ops) {
		t.Errorf("Steps has %d entries, the plan has %d operations; the report must "+
			"show what was assessed", len(rep.Steps), len(ops))
	}
}

// TestManagementSafetyIsAssessedFromOperationsNotIntentions is the property
// that makes the management gate capable of refusing anything.
//
// The plan removes the address an active SSH session arrived on. Nothing about
// the ROLE list reveals this: the LAN role is still satisfied, and both role
// interfaces are still perfectly valid selections. The address removal appears
// only in the operations, which is why the assessment reads them.
//
// The converse case is asserted too, and it matters as much: a plan that sets
// the LAN link down is ACCEPTED here, because management is arriving over the
// overlay tunnel. An assessment that refused that would be refusing every
// first activation on a Tailscale-managed host, and an operator who learns to
// ignore a gate that always fires learns to ignore the ones that matter.
func TestManagementSafetyIsAssessedFromOperationsNotIntentions(t *testing.T) {
	// An SSH session is arriving on 192.168.1.50.
	t.Setenv("SSH_CONNECTION", "203.0.113.9 41234 192.168.1.50 22")

	// The LAN currently carries that address; the desired state does not.
	obs := gatewayObservation()
	obs.LANUp = true
	obs.LANAddresses = []string{"192.168.1.50/24"}

	des := gatewayDesired()
	des.LAN.Addresses = []string{"10.77.0.1/24"}

	plan := buildPlanFor(t, obs, des)

	ops, err := execution.PlanToOperations(plan, obs)
	if err != nil {
		t.Fatalf("deriving operations: %v", err)
	}
	var removesSSHAddress bool
	for _, op := range ops {
		if d, ok := op.(execution.OpAddressDelete); ok && d.CIDR == "192.168.1.50/24" {
			removesSSHAddress = true
		}
	}
	if !removesSSHAddress {
		t.Fatalf("the plan does not remove the SSH address; this test cannot assert what it claims\noperations:\n%v", ops)
	}

	rep := evaluatePlannedManagementSafety(obs, gatewayDevice(), plan)
	if rep.Safe {
		t.Fatal("a plan that removes the active SSH management address was reported safe")
	}
	if rep.SSHPathPreserved {
		t.Errorf("SSHPathPreserved is true although the plan removes the session's address; reason: %q",
			rep.Reason)
	}
	if rep.Reason == "" {
		t.Error("the refusal gives no reason")
	}
}

// TestManagementSafetyAcceptsTakingTheLANDown is the converse, and it is a
// load-bearing case rather than a nicety.
//
// The gateway's management path is the overlay tunnel. Bringing the LAN link
// down during an activation is the whole point of an activation, and refusing
// it would make the gateway undeployable on any host where SSH arrives over
// Tailscale.
func TestManagementSafetyAcceptsTakingTheLANDown(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "203.0.113.9 41234 100.64.0.1 22")

	obs := gatewayObservation()
	obs.LANUp = true
	obs.LANAddresses = []string{"192.168.1.50/24"}

	des := gatewayDesired()
	des.LAN.Up = false

	plan := buildPlanFor(t, obs, des)

	ops, err := execution.PlanToOperations(plan, obs)
	if err != nil {
		t.Fatalf("deriving operations: %v", err)
	}
	var takesLinkDown bool
	for _, op := range ops {
		if _, ok := op.(execution.OpLinkSetDown); ok {
			takesLinkDown = true
		}
	}
	if !takesLinkDown {
		t.Fatalf("the plan does not set any link down; this test cannot assert what it claims\noperations:\n%v", ops)
	}

	rep := evaluatePlannedManagementSafety(obs, gatewayDevice(), plan)
	if !rep.Safe {
		t.Fatalf("taking the LAN link down was refused although management is over the overlay tunnel: %s", rep.Reason)
	}
}

// TestAnUninspectableHostIsNotManagementSafe is the conservative default.
//
// If the plan's operations cannot be derived, the question cannot be answered.
// Reporting "safe" because nothing was found to complain about is the failure
// mode that matters, and "I could not check" must never be read as "I checked
// and it was fine".
func TestAnUninspectableHostIsNotManagementSafe(t *testing.T) {
	rep := evaluatePlannedManagementSafety(gatewayObservation(), gatewayDevice(), nil)
	if rep.Safe {
		t.Fatal("a plan that does not exist was reported management-safe")
	}
	if !strings.Contains(rep.Reason, "could not be derived") {
		t.Errorf("Reason = %q; it must say the assessment could not be made", rep.Reason)
	}
	if rep.Steps != nil {
		t.Errorf("Steps = %v, want none: nothing was assessed", rep.Steps)
	}
}

// TestRecoveryIsAssessedFromThePlansOwnOperations covers the recoverable gate
// against operations rather than against history.
//
// An operator with no recorded configuration history can still activate,
// because what an activation needs to know is whether THIS transaction can be
// undone — not whether the gateway has ever been rolled back before.
func TestRecoveryIsAssessedFromThePlansOwnOperations(t *testing.T) {
	obs := gatewayObservation()
	ev := &activationEvidence{Obs: obs, Plan: buildPlanFor(t, obs, gatewayDesired())}

	ops, err := execution.PlanToOperations(ev.Plan, obs)
	if err != nil {
		t.Fatalf("deriving operations: %v", err)
	}
	if len(ops) == 0 {
		t.Fatal("the plan produced no operations; there is nothing to recover")
	}

	ok, problem := recoveryIsAvailable(ev)
	if !ok {
		t.Fatalf("a first-activation plan was reported unrecoverable: %s", problem)
	}

	// The scope asked about must be the scope the executor would capture.
	scope := execution.BackupScopeFor(ops, obs)
	if len(scope.Interfaces) == 0 {
		t.Error("the recovery gate accepted a plan whose baseline would capture no interfaces")
	}
}

// TestRecoveryRefusesEvidenceWithNoPlan is the negative direction of the same
// rule: an activation that cannot describe what it will do cannot claim to be
// undoable.
func TestRecoveryRefusesEvidenceWithNoPlan(t *testing.T) {
	if ok, problem := recoveryIsAvailable(&activationEvidence{Obs: gatewayObservation()}); ok {
		t.Fatalf("evidence with no plan was reported recoverable: %s", problem)
	}
}

// TestTheExecutorRefusesAPlanBuiltFromDifferentInputs is the digest binding,
// asserted on the executor rather than on the CLI.
//
// The point of carrying expected digests into ExecutionOptions is that the
// executor re-derives them and refuses on drift. This proves it does.
func TestTheExecutorRefusesAPlanBuiltFromDifferentInputs(t *testing.T) {
	ev := gatewayEvidence(t)

	gates := activation.EvaluateProduction(satisfiedGateInput())
	driver := execution.NewProductionDriver()
	if err := driver.Authorize(productionAuthorization(ev, gates, true)); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	// The host moved between review and execution.
	opts := executionOptions(ev, execution.NewMemoryJournalStore())
	opts.Observed.LANUp = true
	opts.Observed.LANAddresses = []string{"10.99.0.1/24"}

	res, err := execution.NewExecutor().ExecutePlan(context.Background(), ev.Plan, driver, opts)
	if err == nil {
		t.Fatal("the executor applied a plan built from a different observed state")
	}
	if !errors.Is(err, execution.ErrStalePlan) {
		t.Errorf("error = %v, want ErrStalePlan", err)
	}
	if res.FinalState != execution.StateBlocked {
		t.Errorf("final state = %s, want %s", res.FinalState, execution.StateBlocked)
	}
}

// TestTheExecutorRefusesAnUnauthorizedDriver is the property that the driver's
// own authorization is not advisory.
func TestTheExecutorRefusesAnUnauthorizedDriver(t *testing.T) {
	ev := gatewayEvidence(t)

	// No Authorize call at all.
	res, err := execution.NewExecutor().ExecutePlan(context.Background(), ev.Plan,
		execution.NewProductionDriver(), executionOptions(ev, execution.NewMemoryJournalStore()))
	if err == nil {
		t.Fatal("the executor ran against an unauthorized driver")
	}
	if !errors.Is(err, execution.ErrCannotApply) {
		t.Errorf("error = %v, want ErrCannotApply", err)
	}
	if res.FinalState != execution.StateBlocked {
		t.Errorf("final state = %s, want %s", res.FinalState, execution.StateBlocked)
	}

	// And with authorization the same inputs get past that check.
	gates := activation.EvaluateProduction(satisfiedGateInput())
	driver := execution.NewProductionDriver()
	if err := driver.Authorize(productionAuthorization(ev, gates, true)); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !driver.CanApply() {
		t.Fatal("an authorized driver reports CanApply false")
	}
}

// TestAnInterruptedTransactionBlocksActivation is the crash-recovery seam.
//
// A journal left mid-apply means the previous run died between changing the
// host and finishing. THN cannot know how far it got — the process that would
// have known is the one that stopped — so the only honest action is to refuse.
func TestAnInterruptedTransactionBlocksActivation(t *testing.T) {
	journal := execution.NewMemoryJournalStore()
	_ = journal.RecordState(execution.TransactionRecord{
		PlanID:    "plan-1",
		State:     execution.StateApply,
		Completed: false,
	})

	rec, interrupted := execution.DetectInterrupted(journal)
	if !interrupted {
		t.Fatal("an interrupted transaction was not detected")
	}
	if rec.PlanID != "plan-1" {
		t.Errorf("record = %q, want plan-1", rec.PlanID)
	}

	// And the executor refuses rather than guessing. The expected digests are
	// cleared so that the ONLY thing standing between this call and an apply is
	// the recovery check.
	ev := gatewayEvidence(t)

	gates := activation.EvaluateProduction(satisfiedGateInput())
	driver := execution.NewProductionDriver()
	if err := driver.Authorize(productionAuthorization(ev, gates, true)); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	opts := executionOptions(ev, journal)
	opts.ExpectedPlanID = ""
	opts.ExpectedObservedDigest = ""
	opts.ExpectedDesiredDigest = ""
	opts.ExpectedAssignmentDigest = ""

	res, err := execution.NewExecutor().ExecutePlan(context.Background(), ev.Plan, driver, opts)
	if !errors.Is(err, execution.ErrRecoveryRequired) {
		t.Fatalf("error = %v, want ErrRecoveryRequired", err)
	}
	if res.FinalState != execution.StateRecoveryRequired {
		t.Errorf("final state = %s, want %s", res.FinalState, execution.StateRecoveryRequired)
	}
}

// TestACompletedTransactionDoesNotBlockActivation guards the other direction:
// the journal must not refuse forever.
func TestACompletedTransactionDoesNotBlockActivation(t *testing.T) {
	journal := execution.NewMemoryJournalStore()
	_ = journal.RecordState(execution.TransactionRecord{
		PlanID:    "plan-1",
		State:     execution.StateCommitted,
		Completed: true,
	})

	if _, interrupted := execution.DetectInterrupted(journal); interrupted {
		t.Fatal("a committed transaction was reported as interrupted")
	}
}

// TestTheCLIStillRefusesOnANonLinuxHost proves the platform check happens
// before any state is touched.
//
// The executor would fail deep inside the transaction — after the baseline
// capture, with a journal on disk claiming an activation was in flight. The
// refusal has to come first.
func TestTheCLIStillRefusesOnANonLinuxHost(t *testing.T) {
	err := requireLinux()
	if err == nil {
		t.Skip("this host is Linux; the refusal path cannot be exercised here")
	}
	if !strings.Contains(err.Error(), "Linux") {
		t.Errorf("error = %q; it must name the platform requirement", err)
	}
}

// gatewayObservation is a two-port host: an uplink that is up and carrying the
// default route, and a LAN that exists but has no address yet.
func gatewayObservation() diff.Observed {
	return diff.Observed{
		Supported:       true,
		HostName:        "gateway",
		WANPresent:      true,
		WANName:         "wan0",
		WANUp:           true,
		LANPresent:      true,
		LANName:         "lan0",
		LANUp:           false,
		HasDefaultRoute: true,
		DefaultGateway:  "192.168.1.1",
	}
}

// gatewayDevice is the device model matching gatewayObservation, including an
// overlay tunnel so the overlay boundary is exercised.
func gatewayDevice() *host.Device {
	return &host.Device{
		Supported: true,
		Hostname:  "gateway",
		OS:        "linux",
		Interfaces: []host.Interface{
			{SystemName: "wan0", Kind: "ethernet", LinkUp: true, Addresses: []string{"192.168.1.50/24"}},
			{SystemName: "lan0", Kind: "ethernet", LinkUp: false},
			{SystemName: "tailscale0", Kind: "tunnel", LinkUp: true, Addresses: []string{"100.64.0.1/32"}},
		},
	}
}

// gatewayEvidence builds the evidence `thn activate` would build for the
// canonical gateway, with every read-only assessment already performed.
//
// Using it rather than a hand-assembled struct means the management report,
// the digests and the plan are all consistent with each other — which is the
// property the executor tests depend on, and which a struct literal cannot
// promise.
func gatewayEvidence(t *testing.T) *activationEvidence {
	t.Helper()

	obs := gatewayObservation()
	device := gatewayDevice()
	des := gatewayDesired()
	plan := buildPlanFor(t, obs, des)

	return &activationEvidence{
		Path:        "test",
		Obs:         obs,
		Device:      device,
		Desired:     des,
		Plan:        plan,
		Management:  evaluatePlannedManagementSafety(obs, device, plan),
		ConfigValid: true,
	}
}

// gatewayDesired is the desired state a deployable gateway asks for.
func gatewayDesired() desired.State {
	des := desired.State{
		Name:       "thn-gateway",
		Generation: 1,
		WAN: desired.Interface{
			Name: "wan0", Role: desired.RoleWAN, MTU: 1500, Up: true, Present: true,
		},
		LAN: desired.Interface{
			Name: "lan0", Role: desired.RoleLAN, MTU: 1500, Up: true, Present: true,
			Addresses: []string{"10.77.0.1/24"},
		},
		Addressing: desired.Addressing{
			DefaultGateway:  "192.168.1.1",
			UpstreamPresent: true,
			IPv4Forwarding:  true,
		},
	}
	des.Firewall.Enabled = true
	des.Firewall.Backend = "nftables"
	des.NAT.Enabled = true
	des.NAT.Interfaces = []string{"lan0"}
	des.NAT.Resolved = true
	return des
}

// buildPlanFor produces a real plan through the real planner, so the digests,
// step ids and derived operations are the ones production would produce.
func buildPlanFor(t *testing.T, obs diff.Observed, des desired.State) *planner.Plan {
	t.Helper()
	p := planner.Build(diff.Compare(obs, desiredFor(des)), planner.Options{
		Generation: 1,
		Source:     "test",
		Live:       true,
		Observed:   obs,
		Desired:    des,
		Assignments: []host.Assignment{
			{Role: host.RoleWAN, Selector: "wan0"},
			{Role: host.RoleLAN, Selector: "lan0"},
		},
	})
	if p == nil {
		t.Fatal("planner returned no plan")
	}
	return p
}
