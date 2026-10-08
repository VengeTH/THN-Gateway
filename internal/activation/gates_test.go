package activation

// The seven readiness gates.
//
// Evaluate is the function an operator consults before a cutover, and it is
// the thing that decides whether THN is deployable. It is not modified here.
// These tests exist because internal/activation had no test file at all, so
// the gate logic was only ever exercised indirectly, through a CLI test that
// asserts on the summary rather than on individual gates.
//
// # Static versus host-dependent
//
// Five gates read facts THN holds about itself or about the document: whether
// a validated plan exists, whether the configuration is valid, whether
// recovery is possible, whether an operator confirmed presence, and whether
// the running build contains an apply path. Two read the host: wan-present
// and lan-identified, which come from an observation.
//
// That split is what makes Evaluate safe to call before deployment. A gate
// that failed closed because it could not reach the network would report
// BLOCKED on a laptop for the wrong reason, and an operator would learn to
// ignore it.

import (
	"errors"
	"strings"
	"testing"
)

// satisfiedInput is a GateInput with every satisfiable gate satisfied.
//
// The role gates are satisfied through RoleGate, not through a boolean: the
// point of the change was that a gate can say WHICH interface filled the role,
// and a test input that cannot express that cannot check that it does.
func satisfiedInput() GateInput {
	return GateInput{
		PlanValidated:        true,
		ConfigValid:          true,
		WAN:                  RoleGate{Role: "wan", Satisfied: true, Interface: "uplink0", Reason: "role wan is filled by uplink0"},
		LAN:                  RoleGate{Role: "lan", Satisfied: true, Interface: "downlink0", Reason: "role lan is filled by downlink0"},
		NoRoleConflicts:      true,
		HostReadinessOK:      true,
		CapabilitiesObserved: true,
		DigestsFresh:         true,
		ManagementSafe:       true,
		RecoveryOK:           true,
		SubsystemsExecutable: true,

		PresenceConfirmed: true,
	}
}

// gateCase is one row: a gate name and the GateInput field that drives it.
//
// The table is written out rather than derived. A derived table would grow
// silently as gates were added, and the completeness check would then only be
// checking that the code agrees with itself — which is always true, and proves
// nothing.
type gateCase struct {
	name  string
	field string
}

// allGates enumerates the seven readiness gates and the field each reads.
//
// apply-path-available has no field: it is driven by CanApply(), which is a
// package constant and therefore cannot be varied per test.
var allGates = []gateCase{
	{"apply-path-available", ""},
	{"plan-validated", "PlanValidated"},
	{"config-valid", "ConfigValid"},
	{"wan-present", "WAN"},
	{"lan-identified", "LAN"},
	{"recoverable", "RecoveryOK"},
	{"physical-presence", "PresenceConfirmed"},
}

// allProductionGates enumerates the full set of M7.6 production activation gates.
var allProductionGates = []gateCase{
	{"apply-path-available", ""},
	{"plan-validated", "PlanValidated"},
	{"config-valid", "ConfigValid"},
	{"wan-present", "WAN"},
	{"lan-identified", "LAN"},
	{"no-role-conflicts", "NoRoleConflicts"},
	{"host-readiness", "HostReadinessOK"},
	{"capabilities-observed", "CapabilitiesObserved"},
	{"digests-fresh", "DigestsFresh"},
	{"management-safety", "ManagementSafe"},
	{"recoverable", "RecoveryOK"},
	{"subsystems-executable", "SubsystemsExecutable"},
	{"physical-presence", "PresenceConfirmed"},
}

// unsatisfiable clears one field of a GateInput.
func unsatisfiable(in GateInput, field string) GateInput {
	switch field {
	case "PlanValidated":
		in.PlanValidated = false
	case "ConfigValid":
		in.ConfigValid = false
	case "WAN":
		in.WAN = RoleGate{Role: "wan", Reason: "role wan is not assigned"}
	case "LAN":
		in.LAN = RoleGate{Role: "lan", Reason: "role lan is not assigned"}
	case "NoRoleConflicts":
		in.NoRoleConflicts = false
		in.RoleConflictProblem = "roles are in conflict"
	case "HostReadinessOK":
		in.HostReadinessOK = false
		in.HostReadinessProblem = "host readiness not met"
	case "CapabilitiesObserved":
		in.CapabilitiesObserved = false
		in.CapabilitiesProblem = "required capabilities not observed"
	case "DigestsFresh":
		in.DigestsFresh = false
		in.DigestsProblem = "plan digests are stale"
	case "ManagementSafe":
		in.ManagementSafe = false
		in.ManagementProblem = "management path not proven safe"
	case "RecoveryOK":
		in.RecoveryOK = false
	case "SubsystemsExecutable":
		in.SubsystemsExecutable = false
		in.SubsystemsProblem = "a required subsystem has no runtime implementation"
	case "PresenceConfirmed":
		in.PresenceConfirmed = false
	}
	return in
}

// TestEveryGateIsAccountedFor proves the enumeration is complete and ordered.
//
// If a gate is added to Evaluate and not to allGates, this fails. The check is
// on names and order, which is what the result actually reports.
func TestEveryGateIsAccountedFor(t *testing.T) {
	got := Evaluate(satisfiedInput())

	if len(got.Gates) != len(allGates) {
		t.Fatalf("Evaluate reported %d gates, the table describes %d: %v",
			len(got.Gates), len(allGates), gateNames(got))
	}
	for i, want := range allGates {
		if got.Gates[i].Name != want.name {
			t.Errorf("gate %d = %q, want %q", i, got.Gates[i].Name, want.name)
		}
		if got.Gates[i].Description == "" {
			t.Errorf("gate %q has no description", got.Gates[i].Name)
		}
	}
}

// TestEveryProductionGateIsAccountedFor proves all 12 M7.6 gates are present in EvaluateProduction.
func TestEveryProductionGateIsAccountedFor(t *testing.T) {
	got := EvaluateProduction(satisfiedInput())

	if len(got.Gates) != len(allProductionGates) {
		t.Fatalf("EvaluateProduction reported %d gates, expected %d: %v",
			len(got.Gates), len(allProductionGates), gateNames(got))
	}
	for i, want := range allProductionGates {
		if got.Gates[i].Name != want.name {
			t.Errorf("production gate %d = %q, want %q", i, got.Gates[i].Name, want.name)
		}
		if got.Gates[i].Description == "" {
			t.Errorf("production gate %q has no description", got.Gates[i].Name)
		}
	}
}

// TestEveryProductionGateCanBlock proves each M7.6 gate is individually load-bearing.
func TestEveryProductionGateCanBlock(t *testing.T) {
	for _, c := range allProductionGates {
		if c.field == "" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			got := EvaluateProduction(unsatisfiable(satisfiedInput(), c.field))
			if got.AllSatisfied {
				t.Fatalf("%q did not block", c.name)
			}
			if !containsString(got.Blocking, c.name) {
				t.Fatalf("Blocking = %v, want it to name %q", got.Blocking, c.name)
			}
		})
	}
}

// TestEveryGateCanBlock proves every gate is individually load-bearing.
//
// A gate that cannot fail costs a reader confidence and changes no outcome.
// Each row clears one field and requires exactly that gate in Blocking.
func TestEveryGateCanBlock(t *testing.T) {
	for _, c := range allGates {
		if c.field == "" {
			continue // driven by CanApply(); asserted separately
		}

		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(unsatisfiable(satisfiedInput(), c.field))

			if got.AllSatisfied {
				t.Fatalf("%q did not block; a gate that cannot fail is not a gate", c.name)
			}
			if !containsString(got.Blocking, c.name) {
				t.Fatalf("Blocking = %v, want it to name %q", got.Blocking, c.name)
			}

			// apply-path-available blocks unconditionally in this build, so
			// it is expected in every result. Anything beyond the gate under
			// test and that one would mean clearing a field did not isolate
			// the failure.
			for _, b := range got.Blocking {
				if b != c.name && b != "apply-path-available" {
					t.Errorf("clearing %s also blocked %q; the gates are not independent",
						c.field, b)
				}
			}

			for _, g := range got.Gates {
				if g.Name == c.name && g.Reason == "" {
					t.Errorf("gate %q blocks without giving a reason", c.name)
				}
			}
		})
	}
}

// TestApplyPathGateReflectsTheBuild pins the apply-path gate to a statement
// about the build and nothing else.
//
// It is driven by CanApply() rather than by a GateInput field, so it is the one
// gate a test cannot vary per input. That makes it the gate most worth pinning
// precisely: it must report the truth about the binary, and it must never be a
// place where an operator's input could make activation look possible.
func TestApplyPathGateReflectsTheBuild(t *testing.T) {
	if !CanApply() {
		t.Fatal("CanApply() is false; this build contains a production apply path " +
			"and the gate must say so, or `thn readiness` reports a build problem " +
			"that does not exist")
	}

	got := Evaluate(satisfiedInput())

	// The gate reads CanApply() and nothing in GateInput, so it must be
	// satisfied here and must be absent from Blocking.
	if containsString(got.Blocking, "apply-path-available") {
		t.Errorf("Blocking = %v; apply-path-available must not block in a build that has one",
			got.Blocking)
	}
	if !got.AllSatisfied {
		t.Errorf("with every gate satisfied, %v still blocks; EvaluateProduction is the "+
			"production contract and every remaining gate must be able to hold",
			got.Blocking)
	}

	// A satisfied gate set is evidence, not permission. GateResult carries no
	// method that authorizes anything, and Machine.Activate separately requires
	// a bound applier that reports itself authorized — asserted in
	// dryrun_test.go. This comment marks the boundary so a future reader does
	// not mistake AllSatisfied for a green light.
}

// TestPhysicalPresenceIsSeparateFromApplyPath documents a deliberate decision.
//
// Confirming presence records a flag and surfaces it, but it cannot make
// activation possible on its own. An operator standing in the room has
// satisfied one gate of twelve, and a machine is still refused unless the rest
// hold and an applier is bound.
func TestPhysicalPresenceIsSeparateFromApplyPath(t *testing.T) {
	m := NewMachine(StateDevelopment)
	if m.PresenceConfirmed() {
		t.Error("a new machine reports confirmed presence")
	}

	m.ConfirmPresence()
	if !m.PresenceConfirmed() {
		t.Error("ConfirmPresence did not record the confirmation")
	}
	if !m.Report().PresenceConfirmed {
		t.Error("the report does not carry the confirmation")
	}

	// Presence on a satisfied gate set still does not authorize: the machine
	// has no applier bound, so Activate refuses before it reaches a driver.
	m.SetGates(Evaluate(satisfiedInput()))
	err := m.Activate(Context{Generation: 1, PlanID: "plan-1", RequestedBy: "test"})
	if err == nil {
		t.Fatal("Activate succeeded on a machine with no applier bound")
	}
	if !errors.Is(err, ErrNoApplyPath) {
		t.Errorf("error = %v, want ErrNoApplyPath", err)
	}
}

// TestGateReasonsAreDistinct guards against a copy-paste in the reason text.
//
// Each gate is given its own problem text, because that is the case where the
// operator reads a reason: with a specific explanation per gate, a shared
// reason would mean one gate is reporting another's problem.
func TestGateReasonsAreDistinct(t *testing.T) {
	got := Evaluate(GateInput{
		// PlanValidated is left false so every host- and document-dependent
		// gate blocks. It carries no Problem field of its own, so its reason
		// is the fixed explanatory string rather than caller text.
		//
		// apply-path-available is the one gate a GateInput cannot block: it
		// reads CanApply(), which this build answers honestly. It is excluded
		// from the "every gate blocks" assertion below rather than forced
		// false, because forcing it would be asserting something untrue about
		// the binary in order to make a test tidy.
		ConfigProblem: "dhcp.ranges[0].end is outside the LAN prefix",
		WAN: RoleGate{
			Role:     "wan",
			Selector: "hw:0011223344aabbcc",
			Reason:   "no observed interface matches the uplink selector; observed: eno1, eno2",
		},
		LAN: RoleGate{
			Role:     "lan",
			Selector: "hw:ffeeddccbbaa9988",
			Reason:   "role lan is not assigned; observed: eno1, eno2",
		},
		RecoveryProblem:   "the prior configuration cannot be reconstructed",
		SubsystemsProblem: "dhcp is requested but THN implements no DHCP server",
		PresenceConfirmed: false,
	})

	seen := map[string]string{}
	for _, g := range got.Gates {
		if g.Name == "apply-path-available" {
			if !g.Satisfied {
				t.Error("apply-path-available reports unsatisfied in a build that has an apply path")
			}
			continue
		}
		if g.Satisfied {
			t.Errorf("gate %q reports satisfied but should not", g.Name)
		}
		if g.Reason == "" {
			t.Errorf("gate %q has no reason", g.Name)
			continue
		}
		if prev, dup := seen[g.Reason]; dup {
			t.Errorf("gates %q and %q share the reason %q", prev, g.Name, g.Reason)
		}
		seen[g.Reason] = g.Name
	}

	if len(got.Blocking) != len(allGates)-1 {
		t.Errorf("Blocking = %v, want all %d gate-dependent gates named",
			got.Blocking, len(allGates)-1)
	}
}

// TestReasonsFallBackWhenNoProblemIsGiven documents the degenerate case.
//
// reasonUnless returns "condition not satisfied" when a gate fails and the
// caller supplied no explanation. That is intentional: an empty reason would
// leave an operator with a blocking gate and nothing to act on. The cost is
// that several unsatisfied gates can read identically, so the CALLER is
// responsible for supplying problem text.
func TestReasonsFallBackWhenNoProblemIsGiven(t *testing.T) {
	got := Evaluate(GateInput{})

	for _, g := range got.Gates {
		if g.Reason == "" {
			t.Errorf("gate %q blocked with an empty reason; an operator would have "+
				"nothing to act on", g.Name)
		}
	}
}

// TestGateProblemTextReachesTheReason checks a caller's explanation survives.
//
// ConfigValid alone says "the configuration is invalid". The operator needs
// to know which field, and GateInput exists to carry that.
func TestGateProblemTextReachesTheReason(t *testing.T) {
	got := Evaluate(GateInput{
		PlanValidated: true,
		ConfigProblem: "dhcp.ranges[0].end is outside the LAN prefix",
	})

	for _, g := range got.Gates {
		if g.Name != "config-valid" {
			continue
		}
		if !strings.Contains(g.Reason, "dhcp.ranges[0].end") {
			t.Errorf("reason = %q; it does not carry the caller's explanation", g.Reason)
		}
		return
	}
	t.Fatal("the config-valid gate is missing")
}

// TestEvaluateIsDeterministic guards a summary an operator reads twice.
//
// If two runs disagree, an operator cannot tell whether readiness changed or
// the report is noisy, and a report that changes when nothing changed gets
// ignored.
func TestEvaluateIsDeterministic(t *testing.T) {
	in := GateInput{
		PlanValidated: true,
		ConfigValid:   false,
		ConfigProblem: "dhcp.ranges[0].end is outside the LAN",
		WAN:           RoleGate{Role: "wan", Selector: "hw:0011223344aabbcc", Reason: "the uplink selector matched no observed interface"},
		LAN:           RoleGate{Role: "lan", Satisfied: true, Interface: "eno2", Reason: "role lan is filled by eno2"},
		RecoveryOK:    true,

		PresenceConfirmed: true,
	}

	first := Evaluate(in)
	if !containsString(first.Blocking, "config-valid") || !containsString(first.Blocking, "wan-present") {
		t.Fatalf("Blocking = %v, want it to name config-valid and wan-present", first.Blocking)
	}
	if containsString(first.Blocking, "plan-validated") {
		t.Errorf("Blocking = %v; plan-validated was satisfied", first.Blocking)
	}

	for i := 0; i < 16; i++ {
		next := Evaluate(in)
		if len(next.Blocking) != len(first.Blocking) {
			t.Fatalf("run %d reported %v, first run reported %v", i, next.Blocking, first.Blocking)
		}
		for j := range first.Blocking {
			if next.Blocking[j] != first.Blocking[j] {
				t.Fatalf("run %d blocking[%d] = %q, first = %q",
					i, j, next.Blocking[j], first.Blocking[j])
			}
		}
	}
}

// gateNames renders a result's gate names for a message.
func gateNames(r GateResult) []string {
	out := make([]string, 0, len(r.Gates))
	for _, g := range r.Gates {
		out = append(out, g.Name)
	}
	return out
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
