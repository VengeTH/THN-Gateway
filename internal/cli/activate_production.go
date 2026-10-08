package cli

// The production activation path.
//
// `thn activate` is the only command in THN that can change host networking.
// Everything else — plan, inspect, readiness, reconcile, health, rollback —
// reads. This file holds the code that gathers the evidence the safety gates
// read, and the wiring that turns a reviewed plan into a transaction.
//
// # The ordering is the safety property
//
// Each step below exists because the next one is unsafe without it:
//
//	observe (read-only)
//	  -> build the plan and read its digests
//	    -> evaluate the full production gate set
//	      -> require explicit physical presence
//	        -> require explicit production authorization
//	          -> bind the reviewed plan ID and all three input digests
//	            -> capture a scoped baseline BEFORE the first mutation
//	              -> apply scoped operations
//	                -> verify health
//	                  -> commit, or compensate and re-verify
//
// In particular, nothing is re-observed between authorization and apply. The
// digests authorized here are the digests the executor recomputes against the
// same inputs, and any drift is a refusal rather than a warning.
//
// # What this file deliberately does not do
//
// It does not re-derive the plan, re-implement any operation, or reach around
// the executor. internal/execution owns the transaction; this file owns the
// evidence and the wiring. A second implementation of the apply path would be
// a second set of safety rules, and only one of them would be reviewed.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/execution"
	"github.com/VengeTH/THN-Gateway/internal/gateway"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/planner"
	"github.com/VengeTH/THN-Gateway/internal/validation"
)

// activationEvidence is everything the safety gates read, gathered once.
//
// It is gathered read-only and before any authorization, so the gates are
// evaluated against the same observation the executor will later re-derive
// digests from. Gathering it lazily, or rebuilding it after authorization,
// would let the thing authorized differ from the thing executed.
type activationEvidence struct {
	// Path is the configuration the evidence came from.
	Path string

	// Cfg is the loaded configuration.
	Cfg config.Config

	// Obs is the read-only host observation.
	Obs diff.Observed

	// Device is the observed device, for role resolution and capability
	// confidence.
	Device *host.Device

	// Desired is the desired network state.
	Desired desired.State

	// Diff is the observed/desired difference the plan was built from.
	Diff diff.Result

	// Plan is the plan under consideration.
	Plan *planner.Plan

	// Assignments are the role bindings the plan was built over.
	Assignments []host.Assignment

	// Conflicts are role bindings where the document and the assignment store
	// disagree.
	Conflicts []bindingConflict

	// Management is the assessment of whether the plan preserves the current
	// remote management path.
	Management activation.ManagementSafetyReport

	// ConfigValid reports whether the document validates.
	ConfigValid bool

	// ConfigProblem explains an invalid document.
	ConfigProblem string
}

// gatherActivationEvidence performs every read the gates need.
//
// It cannot change anything: observeHost goes through internal/guard, which is
// read-only by construction, and planner.Build is pure.
func gatherActivationEvidence(cfg config.Config, path string) *activationEvidence {
	ev := &activationEvidence{Path: path, Cfg: cfg}

	ev.ConfigValid, ev.ConfigProblem = documentIsValid(cfg)

	obs, _, _, device := observeHost(cfg)
	ev.Obs, ev.Device = obs, device
	ev.Desired = desired.FromConfig(cfg)
	ev.Diff = diff.Compare(obs, desiredFor(ev.Desired))

	_, stored := storedAssignments(cfg)
	bindings, conflicts, _ := mergeBindings(cfg, stored)
	ev.Assignments = bindings
	ev.Conflicts = conflicts

	ev.Plan = planner.Build(ev.Diff, planner.Options{
		Generation:  cfg.Gateway.Generation,
		Source:      path,
		Live:        obs.Supported,
		Observed:    obs,
		Desired:     ev.Desired,
		Assignments: bindings,
		Device:      device,
	})

	ev.Management = evaluatePlannedManagementSafety(obs, device, ev.Plan)
	return ev
}

// subsystemHonesty renders, for `thn activation inspect`, exactly what will and
// will not be running for DNS and DHCP.
//
// The inspection report is where an operator goes to find out what the plan
// would actually leave running. Listing "DHCP server: domain x" for a service
// this build does not implement would make the report worse than useless, so
// each requested-but-unimplemented subsystem is stated as blocking, with the
// setting to change.
func subsystemHonesty(cfg config.Config) []string {
	var out []string

	if cfg.DHCP.Enabled {
		out = append(out, fmt.Sprintf(
			"DHCP REQUESTED BUT NOT IMPLEMENTED: dhcp.enabled=true (domain %s). "+
				"THN starts no DHCP server, so this will NOT be applied. "+
				"Activation is blocked until dhcp.enabled is false.", cfg.DHCP.Domain))
	} else {
		out = append(out, "DHCP: not requested; LAN clients must be addressed statically")
	}

	if cfg.DNS.Enabled {
		out = append(out, fmt.Sprintf(
			"LAN DNS REQUESTED BUT NOT IMPLEMENTED: dns.enabled=true (upstream %s). "+
				"THN starts no DNS server, so this will NOT be applied. "+
				"Activation is blocked until dns.enabled is false.",
			strings.Join(cfg.DNS.Upstream, ", ")))
	} else {
		out = append(out, "LAN DNS: not requested; clients use their own upstream resolvers")
	}

	return out
}

// documentIsValid runs exactly the validation `thn validate` runs.
//
// Sharing the function is the point: a safety gate and the command that tells
// an operator what is wrong about their document must not be able to disagree.
func documentIsValid(cfg config.Config) (bool, string) {
	// The gateway report is built with no host observation because this is a
	// document check. That is the correct report for it: it answers what the
	// document says, and names the selectors nothing has verified against.
	gwReport := gateway.Validate(gateway.FromConfig(cfg, host.Resolution{}), gateway.Observed{})

	valid := true
	problem := ""

	for _, sub := range subsystemValidations(cfg, gwReport, false) {
		if sub.Valid {
			continue
		}
		valid = false
		for _, f := range sub.Errors() {
			problem = fmt.Sprintf("%s: %s", f.Field, f.Message)
			break
		}
		break
	}

	if combined := validation.Combined(cfg, nil, diff.Result{}); !combined.Valid {
		valid = false
		if problem == "" {
			for _, f := range combined.Errors() {
				problem = fmt.Sprintf("%s: %s", f.Field, f.Message)
				break
			}
		}
	}
	if !valid && problem == "" {
		problem = "the configuration does not validate; run `thn validate`"
	}
	return valid, problem
}

// executableSubsystems reports which requested subsystems THN cannot bring up.
//
// # Why this blocks rather than warns
//
// The planner represents DHCP and DNS intent as steps so an operator can see
// what was asked for. Representing something is not doing it. THN's execution
// layer implements neither a DHCP server nor a DNS server, and OpDNSApply
// refuses rather than pretending.
//
// So the honest outcomes are: refuse the activation, or apply and report
// clearly that the subsystem was not applied. Refusing is chosen, because a
// gateway that commits an activation while handing out no addresses is
// indistinguishable from one that does — until a device fails to get on the
// network, and the operator investigating that failure has no reason to
// suspect the activation log.
//
// Disabling dhcp.enabled and dns.enabled in the document removes the
// requirement and unblocks activation. The LAN then uses static addressing,
// which the deployment runbook covers.
func executableSubsystems(cfg config.Config) (bool, string) {
	var missing []string

	if cfg.DHCP.Enabled {
		missing = append(missing,
			"dhcp.enabled is true but THN implements no DHCP server; "+
				"set dhcp.enabled=false and address LAN clients statically")
	}
	if cfg.DNS.Enabled {
		missing = append(missing,
			"dns.enabled is true but THN implements no DNS server; "+
				"set dns.enabled=false and let clients use their upstream resolvers")
	}
	if cfg.QoS.Enabled {
		// Production QoS activation remains strictly blocked until every
		// required enforcement condition is satisfied on real hardware.
		//
		// Even though Phase 2 implements per-client shaping, class trees,
		// filters, and isolated namespace traffic tests, this machine has not
		// yet undergone controlled real-hardware traffic verification.
		// Activating without that would claim demonstrated enforcement where
		// only code and lab tests exist.
		missing = append(missing,
			"qos.enabled is true, but production QoS activation remains strictly blocked until all enforcement gates pass: "+
				"[1] algorithm supported, [2] kernel modules (sch_cake/sch_htb) verified, [3] tc class/filter capabilities observed, "+
				"[4] download enforcement verified, [5] upload enforcement verified, [6] priority enforcement verified, "+
				"[7] fairness verified, [8] latency/bufferbloat verified, [9] baseline capture verified, "+
				"[10] compensating rollback verified, [11] management traffic path protected (SSH/Tailscale), "+
				"[12] foreign qdiscs confirmed absent/conflict-free. "+
				"Set qos.enabled=false to activate, or complete controlled physical hardware testing.")
	}
	if len(missing) == 0 {
		return true, ""
	}
	return false, strings.Join(missing, "; ")
}

// evaluatePlannedManagementSafety assesses the ACTUAL plan against the ACTUAL
// management path.
//
// Passing the WAN and LAN interface names is not enough, and was not enough
// before. A plan that sets the LAN link down, or deletes the address an SSH
// session arrives on, never mentions the management interface in its role
// list — it mentions it in its operations. Reading operations rather than
// intentions is what makes this assessment capable of refusing anything.
//
// The conservative default matters as much as the checks. If the operations
// cannot be derived, the question cannot be answered, and the report says so
// instead of reporting "safe" because nothing was found to complain about.
func evaluatePlannedManagementSafety(obs diff.Observed, device *host.Device, plan *planner.Plan) activation.ManagementSafetyReport {
	ops, err := operationsFor(plan, obs)
	if err != nil {
		return activation.ManagementSafetyReport{
			Safe:   false,
			Reason: fmt.Sprintf("the plan's operations could not be derived (%v), so management safety cannot be established; re-run `thn plan`", err),
		}
	}

	var touched []string
	var downActions []string
	removed := map[string][]string{}

	// Whether the plan leaves the gateway with a default route.
	//
	// This starts TRUE and is only cleared by a plan that actually removes the
	// route without installing one. It does not start false, because a plan
	// that never mentions routes leaves the existing default route exactly
	// where it was — and reading "the plan did not install a route" as "the
	// plan removed the route" would refuse every activation on a host that
	// already has a working uplink.
	retainsDefaultRoute := true

	for _, op := range ops {
		switch o := op.(type) {
		case execution.OpLinkSetUp:
			touched = append(touched, o.Interface)
		case execution.OpLinkSetDown:
			touched = append(touched, o.Interface)
			downActions = append(downActions, o.Interface)
		case execution.OpAddressAdd:
			touched = append(touched, o.Interface)
		case execution.OpAddressDelete:
			touched = append(touched, o.Interface)
			removed[o.Interface] = append(removed[o.Interface], o.CIDR)
		case execution.OpRouteAdd:
			touched = append(touched, o.Device)
		case execution.OpRouteReplace:
			touched = append(touched, o.Device)
		case execution.OpRouteDelete:
			// A delete carrying a gateway is compensated by a route add, so
			// the route is re-establishable. One without is not.
			if o.Target() == "default" && o.Gateway == "" {
				retainsDefaultRoute = false
			}
		case execution.OpQDiscApply:
			touched = append(touched, o.Interface)
		case execution.OpQDiscDelete:
			touched = append(touched, o.Interface)
		}
	}

	in := activation.ManagementSafetyInput{
		HasDefaultRoute:      obs.HasDefaultRoute,
		PlannedDefaultRoute:  retainsDefaultRoute,
		TouchedInterfaces:    touched,
		InterfaceDownActions: downActions,
		RemovedAddresses:     removed,
		ActiveSSHIP:          activeSSHAddress(),
	}
	in.ActiveSSHInterface = interfaceCarryingAddress(device, in.ActiveSSHIP)

	// The overlay tunnel is identified by what the host reports, not by a
	// hard-coded name. A host without one must not be judged as though it had
	// one, and a renamed tunnel must not silently escape the check.
	if device != nil {
		for _, iface := range device.Interfaces {
			if isOverlayInterface(iface.SystemName) {
				in.TailscalePresent = true
				in.TailscaleInterface = iface.SystemName
				break
			}
		}
	}

	rep := activation.EvaluateManagementSafety(in)
	rep.Steps = summariseOperations(ops)
	return rep
}

// isOverlayInterface reports whether a kernel name looks like a user-space
// overlay tunnel rather than physical hardware.
//
// It is a name-shape test used only to decide whether to apply the stricter
// protection — never to decide that an interface is safe to touch. The
// protection runs in both directions: a recognised overlay the plan touches
// is refused, and an unrecognised one gets no exemption. A renamed tunnel is
// therefore not granted a pass, which is the failure direction that matters.
func isOverlayInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"tailscale", "tun", "tap", "wg", "zt", "vpn"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// summariseOperations renders the plan's operations so the verdict is
// auditable: an operator told "safe" can see what was assessed.
func summariseOperations(ops []execution.Operation) []string {
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		out = append(out, op.RenderCommand())
	}
	return out
}

// activeSSHAddress reports the local address an active SSH session arrived on.
//
// sshd sets SSH_CONNECTION for every session. The third field is the local
// address the connection landed on, which is the one a plan would have to
// remove to sever the session.
//
// An empty result is not a failure: a console session, a local run, and an SSH
// session from an address THN cannot see all produce one. The consequence of a
// false negative is stated rather than hidden — a gateway whose only
// management path is a session THN cannot identify is not protected by the SSH
// checks — which is why the runbook requires a console or local session to
// remain available for the whole activation, and why physical presence is a
// gate in its own right rather than a formality attached to this one.
func activeSSHAddress() string {
	conn := os.Getenv("SSH_CONNECTION")
	if conn == "" {
		return ""
	}
	fields := strings.Fields(conn)
	if len(fields) < 3 {
		return ""
	}
	return fields[2]
}

// interfaceCarryingAddress reports which observed interface holds addr.
//
// It matches on the address prefix rather than the exact string, because
// kernel output reports "10.77.0.5/24" where the kernel reports the bare
// address. Returning "" means "not identified", which callers must treat as
// unknown rather than as absent.
func interfaceCarryingAddress(device *host.Device, addr string) string {
	if device == nil || addr == "" {
		return ""
	}
	for _, iface := range device.Interfaces {
		for _, a := range iface.Addresses {
			candidate := a
			if i := strings.Index(candidate, "/"); i >= 0 {
				candidate = candidate[:i]
			}
			if candidate == addr {
				return iface.SystemName
			}
		}
	}
	return ""
}

// productionGateInput builds the input to activation.EvaluateProduction.
//
// It is the ONLY place the production gate set is populated. `thn readiness`,
// `thn activation verify` and `thn activate` all read through here, so the
// three cannot disagree about whether this host is ready.
func productionGateInput(ev *activationEvidence, presence bool) activation.GateInput {
	cfg := ev.Cfg

	in := activation.GateInput{
		PlanValidated:     ev.ConfigValid && ev.Plan != nil && ev.Plan.Live && len(ev.Plan.Blocked) == 0,
		ConfigValid:       ev.ConfigValid,
		ConfigProblem:     ev.ConfigProblem,
		Capabilities:      capabilityGates(ev.Device),
		PresenceConfirmed: presence,
	}

	// Role gates, from the same resolution `thn discover` shows.
	_, stored := storedAssignments(cfg)
	res := host.Resolve(ev.Device, ev.Assignments)
	in.WAN = roleGate(ev.Device, res, host.RoleWAN, bindingSelector(cfg, stored, host.RoleWAN))
	in.LAN = roleGate(ev.Device, res, host.RoleLAN, bindingSelector(cfg, stored, host.RoleLAN))

	// Role conflicts: the document and the store disagree; the resolution
	// found a collision; or both roles landed on one interface.
	switch {
	case len(ev.Conflicts) > 0:
		in.NoRoleConflicts = false
		in.RoleConflictProblem = fmt.Sprintf("role %s is declared as %s but stored as %s",
			ev.Conflicts[0].Role, ev.Conflicts[0].Declared, ev.Conflicts[0].Stored)
	case len(res.Problems) > 0:
		in.NoRoleConflicts = false
		in.RoleConflictProblem = res.Problems[0].Message
	case in.WAN.Satisfied && in.LAN.Satisfied && in.WAN.Interface != "" && in.WAN.Interface == in.LAN.Interface:
		in.NoRoleConflicts = false
		in.RoleConflictProblem = fmt.Sprintf("LAN and WAN roles are both assigned to %s", in.WAN.Interface)
	default:
		in.NoRoleConflicts = true
	}

	// Host readiness.
	if ready := host.EvaluateReadiness(ev.Device, host.ReadinessRequest{RequiredInterfaces: 2}); ready.Blocked {
		in.HostReadinessOK = false
		in.HostReadinessProblem = ready.Summary
		if len(ready.Findings) > 0 {
			in.HostReadinessProblem = ready.Findings[0].Message
		}
	} else {
		in.HostReadinessOK = true
	}

	// Capability confidence, digest freshness and recovery.
	in.CapabilitiesObserved, in.CapabilitiesProblem = requiredCapabilitiesObserved(ev)
	in.DigestsFresh, in.DigestsProblem = planDigestsPresent(ev.Plan)
	in.RecoveryOK, in.RecoveryProblem = recoveryIsAvailable(ev)

	// Management safety, assessed against the plan's operations.
	in.ManagementSafe = ev.Management.Safe
	in.ManagementProblem = ev.Management.Reason

	// Subsystem executability.
	in.SubsystemsExecutable, in.SubsystemsProblem = executableSubsystems(cfg)

	return in
}

// executionCapabilityHostCapability maps an execution-layer capability name
// onto the host capability whose observation speaks to it.
//
// The two vocabularies are deliberately different: the executor asks what TOOLS
// it needs, the host reports what the SYSTEM was seen to support. A required
// capability absent from this map has no observation to check against, and
// requiredCapabilitiesObserved refuses it rather than assuming one.
var executionCapabilityHostCapability = map[string]string{
	"ip":     string(host.CapRouting),
	"nft":    string(host.CapNFTables),
	"sysctl": string(host.CapForwarding),
	"tc":     string(host.CapTC),
}

// requiredCapabilitiesObserved reports whether every capability the plan needs
// was OBSERVED rather than inferred.
//
// The required set is derived from the plan's own operations rather than
// hard-coded, so a plan that installs a qdisc is not refused for lacking a
// capability it never uses, and a plan that installs a firewall is not waved
// through by one.
func requiredCapabilitiesObserved(ev *activationEvidence) (bool, string) {
	ops, err := operationsFor(ev.Plan, ev.Obs)
	if err != nil {
		return false, fmt.Sprintf("the plan's operations could not be derived (%v), so its required capabilities are unknown", err)
	}

	var required []string
	for _, op := range ops {
		for _, rc := range op.RequiredCapabilities() {
			if !containsString(required, rc) {
				required = append(required, rc)
			}
		}
	}
	if len(required) == 0 {
		// Nothing to apply means nothing to be capable of.
		return true, ""
	}

	observed := capabilityGates(ev.Device)
	for _, req := range required {
		name, ok := executionCapabilityHostCapability[req]
		if !ok {
			return false, fmt.Sprintf("required capability %q has no host observation to check against; "+
				"activation requires an observed capability", req)
		}

		found := false
		for _, cg := range observed {
			if cg.Name != name {
				continue
			}
			found = true
			if !cg.Satisfied() {
				return false, fmt.Sprintf("required capability %s is %s (must be observed)", name, cg.Confidence)
			}
			break
		}
		if !found {
			return false, fmt.Sprintf("required capability %s is unknown on this host", name)
		}
	}
	return true, ""
}

// operationsFor derives a plan's operations, treating a missing plan as a
// derivation failure rather than an empty operation set.
//
// A nil plan reaching a safety boundary is a wiring bug. Returning an empty
// slice would let that bug read as "there is nothing to do, therefore
// nothing at risk" — the one interpretation that turns a crash into a
// permission.
func operationsFor(plan *planner.Plan, obs diff.Observed) ([]execution.Operation, error) {
	if plan == nil {
		return nil, errors.New("no plan was generated")
	}
	return execution.PlanToOperations(plan, obs)
}

// planDigestsPresent reports whether a plan carries the digest bindings the
// executor needs in order to reject a stale plan.
//
// The comparison that protects the operator is performed by the executor,
// against the inputs the plan was built over. This gate guards the weaker
// precondition that makes that comparison mean anything: a plan carrying no
// digests at all would make it vacuous.
func planDigestsPresent(p *planner.Plan) (bool, string) {
	if p == nil {
		return false, "no plan exists; run `thn plan`"
	}
	switch {
	case p.Inputs.ObservedDigest == "":
		return false, "the plan carries no observed-state digest; regenerate it with `thn plan`"
	case p.Inputs.DesiredDigest == "":
		return false, "the plan carries no desired-state digest; regenerate it with `thn plan`"
	default:
		return true, ""
	}
}

// recoveryIsAvailable reports whether this transaction can be undone.
//
// # Why this is not "has the gateway ever been rolled back"
//
// The previous answer was: it has not, so the gate can never be satisfied, and
// a first deployment is therefore impossible. That was a true answer to a
// different question — is there a recorded configuration history to roll back
// to — and the wrong question for an activation gate.
//
// What an activation needs to know is whether THIS transaction can be undone.
// That has two parts, and both are checked here:
//
//  1. a scoped baseline is captured before the first mutation and compared
//     afterwards, so rollback verification is a real check rather than an
//     assertion. The scope asked about here is the same one the executor will
//     use, because both call BackupScopeFor.
//  2. every operation that WILL be applied has a defined compensation.
//
// Part 2 is the one that matters. An operation with no rollback is not a
// slightly worse operation; it is one the gateway cannot take back, and an
// operator told "recovery is available" must be able to rely on that. An
// operation with no compensation is reported as blocking and named, rather
// than silently accepted.
func recoveryIsAvailable(ev *activationEvidence) (bool, string) {
	ops, err := operationsFor(ev.Plan, ev.Obs)
	if err != nil {
		return false, fmt.Sprintf("the plan's operations could not be derived (%v), so no rollback can be modelled", err)
	}

	var unrecoverable []string
	for _, op := range ops {
		if op.RollbackOp() != nil {
			continue
		}
		// A few operations have nothing to restore because they remove
		// something THN owns, or belong to a subsystem that refuses to run.
		switch op.(type) {
		case execution.OpNFTDeleteTHNTable, execution.OpQDiscDelete, execution.OpDNSApply:
			continue
		}
		unrecoverable = append(unrecoverable, op.RenderCommand())
	}
	if len(unrecoverable) > 0 {
		return false, fmt.Sprintf("these operations have no rollback and cannot be undone by THN: %s",
			strings.Join(unrecoverable, "; "))
	}

	// The baseline must cover what the transaction touches. A scope narrower
	// than the mutation set would restore nothing while still reporting
	// success, so an empty scope is a refusal rather than an optimisation.
	scope := execution.BackupScopeFor(ops, ev.Obs)
	if len(scope.Interfaces) == 0 && !scope.NFTables && !scope.Routes {
		return false, "the rollback baseline would capture nothing, so nothing could be restored"
	}
	return true, ""
}

// productionAuthorization is the input to execution.ProductionAuth.
//
// It binds the authorization to a specific plan by carrying that plan's ID and
// all three input digests. The driver refuses an authorization that carries no
// digests, so the binding cannot be forgotten: there is no way to produce an
// authorized driver that has not been told what it is authorized to apply.
func productionAuthorization(ev *activationEvidence, gates activation.GateResult, confirmed bool) execution.ProductionAuth {
	return execution.ProductionAuth{
		Confirmed:         confirmed,
		GatesResult:       &gates,
		ManagementSafe:    ev.Management.Safe,
		ManagementProblem: ev.Management.Reason,
		PlanID:            ev.Plan.ID,
		ObservedDigest:    ev.Plan.Inputs.ObservedDigest,
		DesiredDigest:     ev.Plan.Inputs.DesiredDigest,
		AssignmentDigest:  ev.Plan.Inputs.AssignmentDigest,
	}
}

// executionOptions binds the plan to the inputs it was built over.
//
// Every Expected* field is populated unconditionally, not conditionally. An
// empty Expected*Digest tells the executor to skip that comparison entirely,
// so making these conditional on some flag would create a way to apply a plan
// with its digest binding switched off.
func executionOptions(ev *activationEvidence, journal execution.JournalStore) execution.ExecutionOptions {
	return execution.ExecutionOptions{
		Observed:                 ev.Obs,
		Desired:                  ev.Desired,
		Assignments:              ev.Assignments,
		Journal:                  journal,
		ExpectedPlanID:           ev.Plan.ID,
		ExpectedObservedDigest:   ev.Plan.Inputs.ObservedDigest,
		ExpectedDesiredDigest:    ev.Plan.Inputs.DesiredDigest,
		ExpectedAssignmentDigest: ev.Plan.Inputs.AssignmentDigest,
		ManagementSafe:           ev.Management.Safe,
		ManagementProblem:        ev.Management.Reason,
		Capabilities:             capabilityGates(ev.Device),
	}
}

// runProductionActivation authorizes the driver and executes the transaction.
//
// It returns the executor's result and error rather than deciding what they
// mean, so this stays a straight line of "authorize, then apply" and the
// caller owns the rendering.
func runProductionActivation(ctx context.Context, ev *activationEvidence, gates activation.GateResult, confirmed bool, journal execution.JournalStore, dryRun bool) (*execution.ExecutionResult, error) {
	driver := execution.NewProductionDriver()

	if err := driver.Authorize(productionAuthorization(ev, gates, confirmed)); err != nil {
		return nil, fmt.Errorf("production authorization refused: %w", err)
	}

	if dryRun {
		return &execution.ExecutionResult{
			PlanID:     ev.Plan.ID,
			Generation: ev.Plan.Generation,
			FinalState: execution.StatePrepared,
			Phases:     []string{string(execution.StatePrepare)},
		}, nil
	}

	return execution.NewExecutor().ExecutePlan(ctx, ev.Plan, driver, executionOptions(ev, journal))
}

// requireLinux refuses production activation on a platform that cannot execute
// it.
//
// This is a check on where the code is running, not a claim about what the host
// can do. internal/execution executes `ip`, `nft`, `sysctl` and `tc`; none of
// them exist off Linux, so a non-Linux host would fail deep inside the
// transaction — after the baseline capture, with a journal on disk recording
// an activation in flight. Refusing here means the refusal happens before any
// state is touched and before any journal exists.
func requireLinux() error {
	if runtime.GOOS == "linux" {
		return nil
	}
	return fmt.Errorf("production activation executes Linux networking tools and can only run "+
		"on Linux; this host is %s", runtime.GOOS)
}

// containsString reports whether a slice holds a value.
func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
