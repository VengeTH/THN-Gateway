package cli

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
)

// The development Fast Ethernet LAN exception.
//
// # What these tests are for
//
// A speed check that can be switched off is a check that will eventually be
// switched off by somebody who did not mean to. So the property worth
// testing is not "the override works" — it is "the override works ONLY for
// the adapter that was named, and the default still refuses".
//
// Each test below pins one boundary of that claim.

// devApprovedCfg is the document an operator writes to approve one adapter.
func devApprovedCfg(ids ...string) config.Config {
	cfg := config.Defaults()
	cfg.Activation.Development.AllowFastEthernetLAN = true
	cfg.Activation.Development.ApprovedFastEthernetLAN = ids
	return cfg
}

// TestProductionPolicyRejectsUnapprovedFastEthernetLAN is the default, tested
// directly rather than as an absence of the override.
func TestProductionPolicyRejectsUnapprovedFastEthernetLAN(t *testing.T) {
	dev := hostWith100MbpsUSBNIC()
	usbID := host.IDFor("2c:88:6f:45:ad:0c")

	res := host.Resolve(dev, []host.Assignment{
		{Role: host.RoleWAN, Selector: host.IDFor("7c:61:70:fd:7f:34")},
		{Role: host.RoleLAN, Selector: usbID},
	})

	// An empty document — the shape of every configuration that predates
	// this feature — must block.
	gate := roleGate(dev, res, host.RoleLAN, usbID, lanPolicyFromConfig(config.Defaults()))
	if gate.Satisfied {
		t.Fatal("a 100 Mbps adapter satisfied the LAN gate under default configuration")
	}
	if gate.DevelopmentOverride {
		t.Error("default configuration reported a development override")
	}
}

// TestExplicitDevelopmentOverridePermitsNamedAdapter is the positive case.
func TestExplicitDevelopmentOverridePermitsNamedAdapter(t *testing.T) {
	dev := hostWith100MbpsUSBNIC()
	usbID := host.IDFor("2c:88:6f:45:ad:0c")

	res := host.Resolve(dev, []host.Assignment{
		{Role: host.RoleWAN, Selector: host.IDFor("7c:61:70:fd:7f:34")},
		{Role: host.RoleLAN, Selector: usbID},
	})

	pol := lanPolicyFromConfig(devApprovedCfg(usbID))
	gate := roleGate(dev, res, host.RoleLAN, usbID, pol)

	if !gate.Satisfied {
		t.Fatalf("the named adapter was rejected under an explicit approval: %s", gate.Reason)
	}
	if !gate.DevelopmentOverride {
		t.Error("a gate satisfied by an exception did not record the exception")
	}
}

// TestOverrideIsScopedToNamedAdapter is the most important test in this file.
//
// A blanket relaxation is the failure mode that matters. If approving one
// adapter admits any Fast Ethernet adapter, the control is decoration.
//
// The host here really does carry two assignable 100 Mbps adapters. That is
// what makes the assertion bite: with a single adapter, "the other one was
// rejected" would pass under any policy at all, including a blanket one,
// because the selector simply resolves to nothing.
func TestOverrideIsScopedToNamedAdapter(t *testing.T) {
	dev := hostWithTwoFastEthernetNICs()
	namedID := host.IDFor("2c:88:6f:45:ad:0c")
	otherID := host.IDFor("2c:88:6f:45:ad:0d")

	// Precondition: both adapters are present and assignable. Without this,
	// the rejection below would prove nothing.
	for _, id := range []string{namedID, otherID} {
		if _, ok := host.Resolve(dev, []host.Assignment{{Role: host.RoleLAN, Selector: id}}).Assigned[host.RoleLAN]; !ok {
			t.Fatalf("precondition failed: %s does not resolve to an interface", id)
		}
	}

	// Only one adapter is named in the document.
	pol := lanPolicyFromConfig(devApprovedCfg(namedID))

	approved := roleGate(dev, host.Resolve(dev, []host.Assignment{
		{Role: host.RoleLAN, Selector: namedID},
	}), host.RoleLAN, namedID, pol)
	if !approved.Satisfied {
		t.Fatalf("precondition failed: the named adapter should pass: %s", approved.Reason)
	}

	unapproved := roleGate(dev, host.Resolve(dev, []host.Assignment{
		{Role: host.RoleLAN, Selector: otherID},
	}), host.RoleLAN, otherID, pol)
	if unapproved.Satisfied {
		t.Fatal("an UNNAMED 100 Mbps adapter satisfied the LAN gate; the approval is not scoped")
	}
	if unapproved.DevelopmentOverride {
		t.Error("an unapproved adapter was reported as an approved exception")
	}
}

// TestApprovalDoesNotSurviveAFlagRemoval is the revert path.
//
// Restoring production policy has to actually restore it. This is the test
// that fails if someone later makes the approval list sticky.
func TestApprovalDoesNotSurviveAFlagRemoval(t *testing.T) {
	dev := hostWith100MbpsUSBNIC()
	usbID := host.IDFor("2c:88:6f:45:ad:0c")
	res := host.Resolve(dev, []host.Assignment{
		{Role: host.RoleWAN, Selector: host.IDFor("7c:61:70:fd:7f:34")},
		{Role: host.RoleLAN, Selector: usbID},
	})

	cfg := devApprovedCfg(usbID)
	if gate := roleGate(dev, res, host.RoleLAN, usbID, lanPolicyFromConfig(cfg)); !gate.Satisfied {
		t.Fatalf("precondition failed, the approved adapter should pass: %s", gate.Reason)
	}

	// The documented revert: flip one field to false.
	cfg.Activation.Development.AllowFastEthernetLAN = false

	gate := roleGate(dev, res, host.RoleLAN, usbID, lanPolicyFromConfig(cfg))
	if gate.Satisfied {
		t.Fatal("the override survived allow_fast_ethernet_lan: false; production policy was not restored")
	}
}

// TestFlagWithoutListIsRefusedAtValidation stops the blanket bypass being
// expressed in configuration at all, rather than merely ignored.
func TestFlagWithoutListIsRefusedAtValidation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Activation.Development.AllowFastEthernetLAN = true
	cfg.Activation.Development.ApprovedFastEthernetLAN = nil

	res := cfg.Validate()
	if !hasFindingAt(res, "activation.development.approved_fast_ethernet_lan", config.SeverityError) {
		t.Error("allow_fast_ethernet_lan with no approved list was not reported as an error")
	}

	// And it must fail closed at the gate even if validation is bypassed.
	dev := hostWith100MbpsUSBNIC()
	usbID := host.IDFor("2c:88:6f:45:ad:0c")
	res2 := host.Resolve(dev, []host.Assignment{{Role: host.RoleLAN, Selector: usbID}})
	if gate := roleGate(dev, res2, host.RoleLAN, usbID, lanPolicyFromConfig(cfg)); gate.Satisfied {
		t.Error("a flag with no named adapter permitted every Fast Ethernet adapter")
	}
}

// TestListWithoutFlagIsRefused covers the contradictory document: a list that
// reads as "approved" and approves nothing.
func TestListWithoutFlagIsRefused(t *testing.T) {
	cfg := config.Defaults()
	cfg.Activation.Development.AllowFastEthernetLAN = false
	cfg.Activation.Development.ApprovedFastEthernetLAN = []string{"hw:abc"}

	res := cfg.Validate()
	if !hasFindingAt(res, "activation.development.approved_fast_ethernet_lan", config.SeverityError) {
		t.Error("an approved list with the flag off was not reported as an error")
	}
}

// TestUnidentifiedInterfaceIsNeverApproved covers an interface THN could not
// identify. An empty identity must never match an approval list.
func TestUnidentifiedInterfaceIsNeverApproved(t *testing.T) {
	pol := lanPolicyFromConfig(devApprovedCfg(""))
	if pol.permitsFastEthernetLAN(host.Interface{}) {
		t.Error("an interface with no identity was approved by an empty list")
	}
}

// TestOverrideDoesNotBypassUnrelatedGates is the containment test.
//
// The override relaxes LAN hardware. It must not become a general exemption:
// every other gate has to keep failing on its own terms even while it is
// active.
func TestOverrideDoesNotBypassUnrelatedGates(t *testing.T) {
	// Everything except the LAN role is missing or hostile: no presence, no
	// recovery, stale digests, unsafe management, unobserved capabilities.
	in := activation.GateInput{
		PlanValidated:        false,
		ConfigValid:          false,
		ConfigProblem:        "invalid",
		CapabilitiesObserved: false,
		DigestsFresh:         false,
		ManagementSafe:       false,
		RecoveryOK:           false,
		PresenceConfirmed:    false,
		NoRoleConflicts:      true,
		HostReadinessOK:      true,
		LAN: activation.RoleGate{
			Role:                "lan",
			Satisfied:           true,
			Interface:           "enx00e099001812",
			DevelopmentOverride: true,
			Reason:              "approved for development",
		},
	}

	res := activation.EvaluateProduction(in)
	if res.AllSatisfied {
		t.Fatal("activation reported READY with every gate but LAN failing")
	}

	if !res.GatesBlockedOn("physical-presence") {
		t.Error("physical presence stopped blocking under a development override")
	}
	if !res.GatesBlockedOn("recoverable") {
		t.Error("rollback readiness stopped blocking under a development override")
	}
	if !res.GatesBlockedOn("management-safety") {
		t.Error("management safety stopped blocking under a development override")
	}

	// Explicitly: the override must not have leaked onto any other gate.
	for _, g := range res.Gates {
		if g.Name != "lan-identified" && g.DevelopmentOverride {
			t.Errorf("gate %q is marked as a development override; the exception leaked", g.Name)
		}
	}
}

// TestMissingOrConflictingAssignmentStaysBlocked proves the override only
// ever relaxes speed, never the existence of an assignment.
func TestMissingOrConflictingAssignmentStaysBlocked(t *testing.T) {
	dev := hostWith100MbpsUSBNIC()
	pol := lanPolicyFromConfig(devApprovedCfg(host.IDFor("2c:88:6f:45:ad:0c")))

	t.Run("unassigned", func(t *testing.T) {
		gate := roleGate(dev, host.Resolve(dev, []host.Assignment{}), host.RoleLAN, "", pol)
		if gate.Satisfied {
			t.Error("an unassigned LAN satisfied the gate under a development override")
		}
	})

	t.Run("missing interface", func(t *testing.T) {
		gate := roleGate(dev, host.Resolve(dev, []host.Assignment{
			{Role: host.RoleLAN, Selector: "hw:doesnotexist"},
		}), host.RoleLAN, "hw:doesnotexist", pol)
		if gate.Satisfied {
			t.Error("a LAN selector matching nothing satisfied the gate under a development override")
		}
	})

	t.Run("wan and lan on one interface", func(t *testing.T) {
		same := host.IDFor("7c:61:70:fd:7f:34")
		gate := roleGate(dev, host.Resolve(dev, []host.Assignment{
			{Role: host.RoleWAN, Selector: same},
			{Role: host.RoleLAN, Selector: same},
		}), host.RoleLAN, same, pol)
		if gate.DevelopmentOverride {
			t.Error("a role collision was reported as an approved development exception")
		}
	})
}

// TestGigabitBehaviourIsUnchanged confirms the production path for real
// Gigabit hardware is untouched by any of this.
func TestGigabitBehaviourIsUnchanged(t *testing.T) {
	dev := hostWithGigabitUSBNIC()
	gigID := host.IDFor("00:e0:4c:68:01:23")

	for _, cfg := range []config.Config{
		config.Defaults(),
		devApprovedCfg(gigID),
	} {
		res := host.Resolve(dev, []host.Assignment{
			{Role: host.RoleWAN, Selector: host.IDFor("7c:61:70:fd:7f:34")},
			{Role: host.RoleLAN, Selector: gigID},
		})
		gate := roleGate(dev, res, host.RoleLAN, gigID, lanPolicyFromConfig(cfg))
		if !gate.Satisfied {
			t.Errorf("a Gigabit adapter was rejected: %s", gate.Reason)
		}
		if gate.DevelopmentOverride {
			t.Error("a Gigabit adapter needed no override, but one was reported")
		}
	}
}

// TestOverrideReasonIsExplicit guards the operator-facing requirement: an
// operator reading only the reason must be told the throughput limit and that
// this is not production-approved.
func TestOverrideReasonIsExplicit(t *testing.T) {
	dev := hostWith100MbpsUSBNIC()
	usbID := host.IDFor("2c:88:6f:45:ad:0c")
	res := host.Resolve(dev, []host.Assignment{
		{Role: host.RoleWAN, Selector: host.IDFor("7c:61:70:fd:7f:34")},
		{Role: host.RoleLAN, Selector: usbID},
	})

	gate := roleGate(dev, res, host.RoleLAN, usbID, lanPolicyFromConfig(devApprovedCfg(usbID)))

	for _, want := range []string{
		"DEVELOPMENT OVERRIDE",
		"100 Mbps",
		"NOT approved for production",
		"allow_fast_ethernet_lan: false",
	} {
		if !strings.Contains(gate.Reason, want) {
			t.Errorf("the reason does not mention %q:\n%s", want, gate.Reason)
		}
	}
}

// TestValidationWarnsWhenDevelopmentModeIsActive makes sure the document
// itself carries the warning, so an operator reading `thn validate` sees it
// without having to run a gate.
func TestValidationWarnsWhenDevelopmentModeIsActive(t *testing.T) {
	cfg := devApprovedCfg(host.IDFor("2c:88:6f:45:ad:0c"))
	if !hasFindingAt(cfg.Validate(), "activation.development", config.SeverityWarning) {
		t.Error("an active development override did not produce a validation warning")
	}
}

// TestProductionPolicyZeroValueDenies guards the fail-closed direction: a
// zero lanPolicy must deny, so any future caller that forgets to read the
// configuration gets production behaviour rather than a bypass.
func TestProductionPolicyZeroValueDenies(t *testing.T) {
	var zero lanPolicy
	iface := host.Interface{
		SystemName: "eth0",
		ID:         "hw:abc",
		SpeedMbps:  100,
		Physical:   true,
		Kind:       host.KindEthernet,
	}
	if zero.permitsFastEthernetLAN(iface) {
		t.Error("the zero lanPolicy approved an adapter; the safe default is inverted")
	}
}

// TestDryRunCompletedWhenOverrideActive verifies that an authorized dry-run
// with the development override active reports completion and prominently
// displays the development override warning banner.
func TestDryRunCompletedWhenOverrideActive(t *testing.T) {
	gates := activation.GateResult{
		AllSatisfied: true,
		Gates: []activation.Gate{
			{Name: "lan-identified", Satisfied: true, DevelopmentOverride: true},
			{Name: "physical-presence", Satisfied: true},
		},
	}

	env, out, errOut := newTestEnv()
	code := reportActivationRefusal(env, gates, true, true, true, "configs/physical_dell_lab.yaml", nil)
	if code != ExitOK {
		t.Fatalf("dry run exit code = %d, want ExitOK (%d); stderr: %s", code, ExitOK, errOut.String())
	}

	combined := out.String() + errOut.String()
	for _, want := range []string{
		"dry run completed: all gates satisfied",
		"DEVELOPMENT OVERRIDE ACTIVE",
		"LAN throughput is limited to Fast Ethernet (100 Mbps)",
		"NOT approved for production",
		"Current network remains untouched",
	} {
		if !strings.Contains(combined, want) {
			t.Errorf("dry run output missing %q:\n%s", want, combined)
		}
	}
}

// TestDryRunRefusalWhenOverrideInactive verifies that under production policy
// with an unapproved 100 Mbps adapter, an authorized dry-run is refused and
// names the blocking lan-identified gate.
func TestDryRunRefusalWhenOverrideInactive(t *testing.T) {
	gates := activation.GateResult{
		AllSatisfied: false,
		Blocking:     []string{"lan-identified"},
		Gates: []activation.Gate{
			{
				Name:      "lan-identified",
				Satisfied: false,
				Reason:    "production LAN requires a Gigabit Ethernet interface (>= 1000 Mbps); install the dedicated Gigabit USB adapter",
			},
		},
	}

	env, out, errOut := newTestEnv()
	code := reportActivationRefusal(env, gates, true, true, true, "configs/physical_dell_lab.yaml", nil)
	if code == ExitOK {
		t.Fatalf("dry run exit code = %d, want non-zero refusal", code)
	}

	combined := out.String() + errOut.String()
	for _, want := range []string{
		"activation refused",
		"Blocking gates",
		"lan-identified",
		"Current network remains untouched",
	} {
		if !strings.Contains(combined, want) {
			t.Errorf("refusal output missing %q:\n%s", want, combined)
		}
	}
}

// hasFindingAt reports whether a validation result carries a finding of the
// given severity on a field.
func hasFindingAt(res config.ValidationResult, field string, sev config.Severity) bool {
	for _, f := range res.Findings {
		if f.Field == field && f.Severity == sev {
			return true
		}
	}
	return false
}
