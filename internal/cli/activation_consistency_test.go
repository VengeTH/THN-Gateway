package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/execution"
	"github.com/VengeTH/THN-Gateway/internal/gateway"
	"github.com/VengeTH/THN-Gateway/internal/host"
)

// Regression coverage ensuring activation status consistency, truthfulness,
// and safety invariant preservation across CLI commands.

// 1. Prove readiness and activation status agree about whether an apply path exists.
func TestActivationReadinessAndStatusAgreeOnApplyPath(t *testing.T) {
	// JSON contract check
	envStatus, outStatus, _ := newTestEnv("activation", "status", "--json")
	envStatus.IsJSON = true
	if code := Run(envStatus); code != ExitOK {
		t.Fatalf("thn activation status --json failed with exit code %d", code)
	}

	var statusData struct {
		CanApply bool   `json:"can_apply"`
		Applier  string `json:"applier"`
	}
	if err := json.Unmarshal([]byte(outStatus.String()), &statusData); err != nil {
		t.Fatalf("failed to parse activation status JSON: %v", err)
	}

	envReady, outReady, _ := newTestEnv("readiness", "--json")
	envReady.IsJSON = true
	// Readiness returns ExitProblems when not all gates are satisfied (e.g. no config loaded in test),
	// but JSON output still contains valid readiness data.
	_ = Run(envReady)

	var readyData struct {
		CanApply bool `json:"can_apply"`
	}
	if err := json.Unmarshal([]byte(outReady.String()), &readyData); err != nil {
		t.Fatalf("failed to parse readiness JSON: %v", err)
	}

	if !readyData.CanApply {
		t.Errorf("readiness reported can_apply=false; this build has an apply path")
	}
	if !statusData.CanApply {
		t.Errorf("activation status reported can_apply=false; this build has an apply path")
	}
	if readyData.CanApply != statusData.CanApply {
		t.Errorf("readiness (can_apply=%t) and activation status (can_apply=%t) disagree on apply path",
			readyData.CanApply, statusData.CanApply)
	}

	// Human-readable output check
	envStatusText, outStatusText, _ := newTestEnv("activation", "status")
	if code := Run(envStatusText); code != ExitOK {
		t.Fatalf("thn activation status failed with exit code %d", code)
	}
	if !strings.Contains(outStatusText.String(), "Can Apply:           true") {
		t.Errorf("thn activation status text output missing 'Can Apply:           true':\n%s", outStatusText.String())
	}

	envReadyText, outReadyText, _ := newTestEnv("readiness")
	_ = Run(envReadyText)
	if !strings.Contains(outReadyText.String(), "Can apply:      true") {
		t.Errorf("thn readiness text output missing 'Can apply:      true':\n%s", outReadyText.String())
	}
}

// 2. Prove production CLI binds the real production execution path.
func TestActivationStatusBindsProductionDriver(t *testing.T) {
	env, out, _ := newTestEnv("activation", "status", "--json")
	env.IsJSON = true
	if code := Run(env); code != ExitOK {
		t.Fatalf("thn activation status --json failed with exit code %d", code)
	}

	var data struct {
		CanApply          bool     `json:"can_apply"`
		Applier           string   `json:"applier"`
		ImplementedStages []string `json:"implemented_stages"`
		UnsupportedStages []string `json:"unsupported_stages"`
	}
	if err := json.Unmarshal([]byte(out.String()), &data); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if !strings.Contains(data.Applier, "ProductionDriver") {
		t.Errorf("bound applier does not name ProductionDriver: %q", data.Applier)
	}
	if strings.Contains(data.Applier, "activation is disabled in this build") {
		t.Errorf("bound applier falsely claims activation is disabled: %q", data.Applier)
	}
	if len(data.ImplementedStages) != 9 {
		t.Errorf("implemented stages count = %d, want 9: %v", len(data.ImplementedStages), data.ImplementedStages)
	}
	if len(data.UnsupportedStages) != 0 {
		t.Errorf("unsupported stages should be empty, got: %v", data.UnsupportedStages)
	}
}

// 3. Prove activation remains blocked without physical presence.
func TestActivationBlockedWithoutPhysicalPresence(t *testing.T) {
	env, _, errOut := newTestEnv("activate", "--confirm")
	code := Run(env)
	if code == ExitOK {
		t.Fatalf("thn activate --confirm succeeded without --confirm-present")
	}
	errStr := errOut.String()
	if !strings.Contains(errStr, "--confirm-present") {
		t.Errorf("expected refusal to mention --confirm-present, got:\n%s", errStr)
	}
	if !strings.Contains(errStr, "Current network remains untouched") {
		t.Errorf("expected 'Current network remains untouched' in output, got:\n%s", errStr)
	}

	// Conversely, --confirm-present without --confirm must also refuse
	env2, _, errOut2 := newTestEnv("activate", "--confirm-present")
	code2 := Run(env2)
	if code2 == ExitOK {
		t.Fatalf("thn activate --confirm-present succeeded without --confirm")
	}
	errStr2 := errOut2.String()
	if !strings.Contains(errStr2, "--confirm") {
		t.Errorf("expected refusal to mention --confirm, got:\n%s", errStr2)
	}
	if !strings.Contains(errStr2, "Current network remains untouched") {
		t.Errorf("expected 'Current network remains untouched' in output, got:\n%s", errStr2)
	}
}

// 4. Prove activation remains blocked when DHCP/DNS are enabled.
func TestActivationBlockedWhenDHCPOrDNSEnabled(t *testing.T) {
	inDHCP := satisfiedGateInput()
	var cfgDHCP config.Config
	cfgDHCP.DHCP.Enabled = true
	cfgDHCP.DHCP.Domain = "lan.local"
	okDHCP, probDHCP := executableSubsystems(cfgDHCP)
	inDHCP.SubsystemsExecutable = okDHCP
	inDHCP.SubsystemsProblem = probDHCP

	resDHCP := activation.EvaluateProduction(inDHCP)
	if resDHCP.AllSatisfied {
		t.Error("activation permitted with dhcp.enabled=true")
	}
	if !containsString(resDHCP.Blocking, "subsystems-executable") {
		t.Errorf("expected blocking gate subsystems-executable, got: %v", resDHCP.Blocking)
	}

	inDNS := satisfiedGateInput()
	var cfgDNS config.Config
	cfgDNS.DNS.Enabled = true
	cfgDNS.DNS.Upstream = []string{"1.1.1.1"}
	okDNS, probDNS := executableSubsystems(cfgDNS)
	inDNS.SubsystemsExecutable = okDNS
	inDNS.SubsystemsProblem = probDNS

	resDNS := activation.EvaluateProduction(inDNS)
	if resDNS.AllSatisfied {
		t.Error("activation permitted with dns.enabled=true")
	}
	if !containsString(resDNS.Blocking, "subsystems-executable") {
		t.Errorf("expected blocking gate subsystems-executable, got: %v", resDNS.Blocking)
	}
}

// 5. Prove failed gates cannot be bypassed by confirmation.
func TestFailedGatesCannotBeBypassedByConfirmation(t *testing.T) {
	driver := execution.NewProductionDriver()

	failedGates := activation.GateResult{
		AllSatisfied: false,
		Blocking:     []string{"wan-present", "management-safe"},
	}

	auth := execution.ProductionAuth{
		Confirmed:         true, // human confirmation supplied
		GatesResult:       &failedGates,
		ManagementSafe:    false,
		ManagementProblem: "management interface in down list",
		PlanID:            "plan-123",
		ObservedDigest:    "obs-digest",
		DesiredDigest:     "des-digest",
		AssignmentDigest:  "assign-digest",
	}

	err := driver.Authorize(auth)
	if err == nil {
		t.Fatal("driver.Authorize succeeded despite failed gates")
	}
	if driver.CanApply() {
		t.Fatal("driver.CanApply() is true despite authorization refusal")
	}
	if !strings.Contains(err.Error(), "activation safety gates unsatisfied") {
		t.Errorf("expected error to mention unsatisfied gates, got: %v", err)
	}
}

// 6. Prove status accurately reflects the actual activation implementation and help text is truthful.
func TestActivationStatusReflectsActualImplementation(t *testing.T) {
	env, out, _ := newTestEnv("activation", "status")
	if code := Run(env); code != ExitOK {
		t.Fatalf("thn activation status failed: %d", code)
	}

	str := out.String()
	for _, expected := range []string{
		"Activation Status",
		"Can Apply:           true",
		"Bound Applier:       production Linux driver: execution.ProductionDriver",
		"Implemented Stages:  observe, model, plan, validate, simulate, apply, health-check, commit, rollback",
		"Unsupported Stages:  nothing",
		"Presence Confirmed:  false",
	} {
		if !strings.Contains(str, expected) {
			t.Errorf("activation status output missing %q:\n%s", expected, str)
		}
	}

	// Verify root help text has no stale "refused in this build" claim
	var helpBuf strings.Builder
	printUsage(&helpBuf)
	helpStr := helpBuf.String()
	if strings.Contains(helpStr, "refused in this build") {
		t.Errorf("root help text still contains stale 'refused in this build':\n%s", helpStr)
	}
	if !strings.Contains(helpStr, "destructive changes host networking; requires confirmation and presence") {
		t.Errorf("root help text missing updated tier description:\n%s", helpStr)
	}
}

// 7. Prove production activation does not become reachable merely because CanApply() is true.
func TestProductionActivationNotReachableMerelyBecauseCanApplyIsTrue(t *testing.T) {
	// Build-level constant is true
	if !activation.CanApply() {
		t.Fatal("activation.CanApply() must be true for this build")
	}

	// Fresh driver is fail-closed and cannot apply
	freshDriver := execution.NewProductionDriver()
	if freshDriver.CanApply() {
		t.Fatal("fresh driver has CanApply() == true; must be fail-closed")
	}
	if freshDriver.Available() {
		t.Fatal("fresh driver has Available() == true; must be false")
	}

	// Direct execution attempts fail closed
	err := freshDriver.Execute(context.Background(), execution.OpLinkSetUp{Interface: "eth0"})
	if err == nil {
		t.Fatal("fresh driver Execute() succeeded without authorization")
	}

	// CLI activate invocation without flags fails closed
	env, _, errOut := newTestEnv("activate")
	code := Run(env)
	if code == ExitOK {
		t.Fatal("thn activate without flags exited 0")
	}
	if !strings.Contains(errOut.String(), "Current network remains untouched") {
		t.Errorf("expected network remains untouched message, got:\n%s", errOut.String())
	}
}

// 8. Prove no-role-conflicts gate passes when roles do not collide, even if interfaces are uninspected.
func TestNoRoleConflictsGatePassesWithoutCollision(t *testing.T) {
	in := satisfiedGateInput()
	in.NoRoleConflicts = true
	res := activation.EvaluateProduction(in)
	for _, g := range res.Gates {
		if g.Name == "no-role-conflicts" && !g.Satisfied {
			t.Errorf("no-role-conflicts gate should be satisfied when there is no collision, got: %s", g.Reason)
		}
	}
}

// 9. Prove no-role-conflicts gate blocks when WAN and LAN roles collide.
func TestNoRoleConflictsGateBlocksOnWANLANCollision(t *testing.T) {
	var cfg config.Config
	cfg.Gateway.Enabled = true
	cfg.Network.WAN = "eth0"
	cfg.Network.LAN = "eth0"
	ev := &activationEvidence{Cfg: cfg}
	in := productionGateInput(ev, false)
	if in.NoRoleConflicts {
		t.Fatal("expected productionGateInput to detect WAN and LAN collision")
	}
	res := activation.EvaluateProduction(in)
	if !containsString(res.Blocking, "no-role-conflicts") {
		t.Errorf("expected no-role-conflicts to block, got: %v", res.Blocking)
	}
}

// 10. Prove no-role-conflicts gate blocks when Management role collides with WAN or LAN.
func TestNoRoleConflictsGateBlocksOnManagementCollision(t *testing.T) {
	var cfg config.Config
	cfg.Gateway.Enabled = true
	cfg.Network.WAN = "eth0"
	cfg.Network.LAN = "eth1"
	cfg.Network.Management = "eth0"
	ev := &activationEvidence{Cfg: cfg}
	in := productionGateInput(ev, false)
	if in.NoRoleConflicts {
		t.Fatal("expected productionGateInput to detect Management and WAN collision")
	}
	res := activation.EvaluateProduction(in)
	if !containsString(res.Blocking, "no-role-conflicts") {
		t.Errorf("expected no-role-conflicts to block, got: %v", res.Blocking)
	}
}

// 11. Prove isolated lab configuration validates and passes subsystems-executable gate.
func TestIsolatedLabConfigurationPassesSubsystemsGate(t *testing.T) {
	cfg, err := config.Load("../../configs/isolated_lab.yaml")
	if err != nil {
		t.Fatalf("loading isolated_lab.yaml: %v", err)
	}
	ev := gatherActivationEvidence(cfg, "../../configs/isolated_lab.yaml")
	in := productionGateInput(ev, false)
	res := activation.EvaluateProduction(in)
	for _, g := range res.Gates {
		if g.Name == "subsystems-executable" && !g.Satisfied {
			t.Errorf("subsystems-executable should be satisfied for isolated_lab.yaml, got reason: %s", g.Reason)
		}
		if g.Name == "no-role-conflicts" && !g.Satisfied {
			t.Errorf("no-role-conflicts should be satisfied for isolated_lab.yaml, got reason: %s", g.Reason)
		}
		if g.Name == "config-valid" && !g.Satisfied {
			t.Errorf("config-valid should be satisfied for isolated_lab.yaml, got reason: %s", g.Reason)
		}
	}
}

// 12. Prove config validation rejects missing roles, duplicate assignments, invalid CIDRs, conflicting subnets, and management conflicts.
func TestConfigValidationMatrixRules(t *testing.T) {
	// Missing WAN role when gateway enabled
	c1 := config.Defaults()
	c1.Gateway.Enabled = true
	c1.Network.WAN = ""
	c1.Network.LAN = "eth1"
	if !c1.Validate().HasErrors() {
		t.Error("expected error for missing WAN role")
	}

	// Missing LAN role when gateway enabled
	c2 := config.Defaults()
	c2.Gateway.Enabled = true
	c2.Network.WAN = "eth0"
	c2.Network.LAN = ""
	// With gateway intent, gateway.Validate and activation gates reject missing LAN role
	gwReport := gateway.Validate(gateway.FromConfig(c2, host.Resolution{}), gateway.Observed{})
	if gwReport.Verdict != gateway.VerdictBlocked {
		t.Errorf("expected gateway.Validate to report BLOCKED for missing LAN role, got %s", gwReport.Verdict)
	}

	// Duplicate assignments
	c3 := config.Defaults()
	c3.Network.WAN = "eth0"
	c3.Network.LAN = "eth0"
	if !c3.Validate().HasErrors() {
		t.Error("expected error for duplicate WAN and LAN interfaces")
	}

	c4 := config.Defaults()
	c4.Network.WAN = "eth0"
	c4.Network.LAN = "eth1"
	c4.Network.Management = "eth0"
	if !c4.Validate().HasErrors() {
		t.Error("expected error for duplicate WAN and Management interfaces")
	}

	// Invalid CIDR
	c5 := config.Defaults()
	c5.Network.LANPrefix = "999.999.999.999/24"
	if !c5.Validate().HasErrors() {
		t.Error("expected error for invalid CIDR")
	}

	// Overlapping subnets between LAN and Management
	c6 := config.Defaults()
	c6.Network.LAN = "eth1"
	c6.Network.LANPrefix = "10.77.0.1/24"
	c6.Network.Management = "eth2"
	c6.Network.ManagementPrefix = "10.77.0.128/25"
	if !c6.Validate().HasErrors() {
		t.Error("expected error for overlapping LAN and Management subnets")
	}

	// Management path conflict: upstream gateway inside management subnet
	c7 := config.Defaults()
	c7.Network.LANPrefix = "10.77.0.1/24"
	c7.Network.ManagementPrefix = "10.99.0.1/24"
	c7.Network.UpstreamGateway = "10.99.0.5"
	if !c7.Validate().HasErrors() {
		t.Error("expected error for upstream gateway inside management subnet")
	}

	// Masquerade outbound pointing to management interface
	c8 := config.Defaults()
	c8.Network.LAN = "eth1"
	c8.Network.Management = "eth2"
	c8.NAT.Enabled = true
	c8.NAT.Masquerade.Enabled = true
	c8.NAT.Masquerade.Outbound = "eth2"
	if !c8.Validate().HasErrors() {
		t.Error("expected error for masquerade outbound pointing to management interface")
	}
}
