package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/dhcp"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/netconfig"
	"github.com/venth/thn-gateway/internal/network"
	"github.com/venth/thn-gateway/internal/state"
	"github.com/venth/thn-gateway/internal/validation"
)

// dellHostFixture simulates the real Dell host observed in M3.
//
// WAN: stable ID hw:7c6170fd7f34317a, kernel name enp0s31f6, physical Ethernet, 1 Gbps, UP.
// LAN: stable ID hw:2c886f45ad0cb12f, kernel name enx00e099001812, physical Ethernet, DOWN.
func dellHostFixture() *host.Device {
	snap := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simIface("enp0s31f6", 2, "7c:61:70:fd:7f:34", "ether", true),
			simIface("enx00e099001812", 3, "2c:88:6f:45:ad:0c", "ether", false),
			simIface("docker0", 4, "02:42:8a:1b:2c:3d", "bridge", true),
			simIface("lo", 1, "", "loopback", true),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
	return host.FromSnapshot(snap)
}

// writeStateDB creates a temporary state database populated with assignments.
func writeStateDB(t *testing.T, dir string, assignments []state.InterfaceAssignment) string {
	t.Helper()
	dbPath := filepath.Join(dir, "state.db")
	st, err := state.Open(dbPath)
	if err != nil {
		t.Fatalf("opening state db: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, a := range assignments {
		if _, _, err := st.PutAssignment(ctx, a); err != nil {
			t.Fatalf("putting assignment %+v: %v", a, err)
		}
	}
	return dbPath
}

// writeTestConfig writes a configuration YAML file in dir.
func writeTestConfig(t *testing.T, dir string, cfg config.Config) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	if err := cfg.Write(path); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

// =============================================================================
// Requirement 1: Canonical Configuration
// A complete canonical configuration must validate successfully.
// =============================================================================

func TestM4CanonicalConfigurationValidates(t *testing.T) {
	cfg := mustLoadCanonical(t)

	// Static validation of the canonical document
	res := validation.Static(cfg)
	if !res.Valid {
		t.Fatalf("canonical configuration must validate cleanly, got findings: %+v", res.Findings)
	}
	if res.ErrorCount > 0 {
		t.Errorf("canonical configuration produced %d errors", res.ErrorCount)
	}

	// CLI validate command on canonical config
	path := canonicalConfigPath(t)
	stdout, stderr, code := runGateCLI(t, "validate", path)
	if code != ExitOK {
		t.Fatalf("thn validate on canonical config failed with exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stdout, "error  ") {
		t.Errorf("validate reported error finding:\n%s", stdout)
	}

	// CLI config validate command on canonical config
	cStdout, cStderr, cCode := runGateCLI(t, "config", "validate", path)
	if cCode != ExitOK {
		t.Fatalf("thn config validate failed with exit %d\nstdout:\n%s\nstderr:\n%s", cCode, cStdout, cStderr)
	}
	if strings.Contains(cStdout, "error  ") {
		t.Errorf("config validate reported error finding:\n%s", cStdout)
	}
}

// =============================================================================
// Requirement 2: Missing WAN
// Removing WAN assignment must produce an unresolved result rather than
// selecting another interface.
// =============================================================================

func TestM4MissingWANLeavesRoleUnresolvedAndRefusesSubstitution(t *testing.T) {
	dev := dellHostFixture()

	// Only LAN is assigned; WAN is left unassigned
	lanID := host.IDFor("2c:88:6f:45:ad:0c")
	assignments := []host.Assignment{
		{Role: host.RoleLAN, Selector: lanID},
	}

	res := host.Resolve(dev, assignments)

	// WAN must not be assigned to anything (not to enp0s31f6, not to docker0, etc.)
	if iface, ok := res.Assigned[host.RoleWAN]; ok {
		t.Fatalf("unassigned WAN was silently substituted by %s", iface.SystemName)
	}

	// Desired state with resolution
	cfg := config.Defaults()
	cfg.Network.WAN = ""
	cfg.Network.LAN = lanID
	cfg.Network.LANPrefix = "10.77.0.1/24"

	des := desired.FromConfigWithResolution(cfg, res)
	if des.WAN.Present {
		t.Error("desired WAN must be marked as not present")
	}
	if des.WAN.Name != "" {
		t.Errorf("desired WAN name = %q, want empty", des.WAN.Name)
	}

	// Readiness evaluation must report wan-present gate as unsatisfied
	gate := roleGate(dev, res, host.RoleWAN, "")
	if gate.Satisfied {
		t.Error("wan-present gate must not be satisfied when WAN is unassigned")
	}
	if !strings.Contains(gate.Reason, "not assigned") && !strings.Contains(gate.Reason, "wan") {
		t.Errorf("gate reason %q must explain that WAN is unassigned", gate.Reason)
	}
}

// =============================================================================
// Requirement 3: Missing LAN
// Removing LAN assignment must produce an unresolved result.
// =============================================================================

func TestM4MissingLANLeavesRoleUnresolvedAndNATPending(t *testing.T) {
	dev := dellHostFixture()

	// Only WAN is assigned; LAN is left unassigned
	wanID := host.IDFor("7c:61:70:fd:7f:34")
	assignments := []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
	}

	res := host.Resolve(dev, assignments)

	// LAN must not be assigned
	if iface, ok := res.Assigned[host.RoleLAN]; ok {
		t.Fatalf("unassigned LAN was silently substituted by %s", iface.SystemName)
	}

	cfg := config.Defaults()
	cfg.Network.WAN = wanID
	cfg.Network.LAN = ""
	cfg.NAT.Enabled = true

	des := desired.FromConfigWithResolution(cfg, res)
	if des.LAN.Present {
		t.Error("desired LAN must not be marked present when LAN is unassigned")
	}
	if des.NAT.Resolved {
		t.Error("NAT must be pending when LAN is unassigned")
	}

	// Readiness gate
	gate := roleGate(dev, res, host.RoleLAN, "")
	if gate.Satisfied {
		t.Error("lan-identified gate must not be satisfied when LAN is unassigned")
	}
}

// =============================================================================
// Requirement 4: Assignment Resolution
// Given: WAN -> hw:<id>, LAN -> hw:<id>, the desired configuration must resolve
// these roles correctly.
// =============================================================================

func TestM4AssignmentResolutionBindsHardwareToLogicalRoles(t *testing.T) {
	dev := dellHostFixture()

	wanID := host.IDFor("7c:61:70:fd:7f:34")
	lanID := host.IDFor("2c:88:6f:45:ad:0c")

	assignments := []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
		{Role: host.RoleLAN, Selector: lanID},
	}

	res := host.Resolve(dev, assignments)
	if !res.OK() {
		t.Fatalf("resolution failed: %+v", res.Problems)
	}

	if res.Assigned[host.RoleWAN].SystemName != "enp0s31f6" {
		t.Errorf("WAN resolved to %q, want enp0s31f6", res.Assigned[host.RoleWAN].SystemName)
	}
	if res.Assigned[host.RoleLAN].SystemName != "enx00e099001812" {
		t.Errorf("LAN resolved to %q, want enx00e099001812", res.Assigned[host.RoleLAN].SystemName)
	}

	cfg := config.Defaults()
	cfg.Network.WAN = wanID
	cfg.Network.LAN = lanID
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.NAT.Enabled = true

	des := desired.FromConfigWithResolution(cfg, res)
	if !des.WAN.Present || des.WAN.Name != "enp0s31f6" {
		t.Errorf("desired WAN: present=%t name=%q, want enp0s31f6", des.WAN.Present, des.WAN.Name)
	}
	if !des.LAN.Present || des.LAN.Name != "enx00e099001812" {
		t.Errorf("desired LAN: present=%t name=%q, want enx00e099001812", des.LAN.Present, des.LAN.Name)
	}
	if len(des.LAN.Addresses) != 1 || des.LAN.Addresses[0] != "10.77.0.1/24" {
		t.Errorf("desired LAN addresses = %v, want [10.77.0.1/24]", des.LAN.Addresses)
	}
	if !des.NAT.Resolved || len(des.NAT.Interfaces) != 1 || des.NAT.Interfaces[0] != "enx00e099001812" {
		t.Errorf("desired NAT: resolved=%t interfaces=%v, want [enx00e099001812]", des.NAT.Resolved, des.NAT.Interfaces)
	}
}

// =============================================================================
// Requirement 5: Stable Identity
// Changing the Linux kernel name while retaining the stable identity must not
// break the desired model.
// =============================================================================

func TestM4StableIdentitySurvivesKernelRenames(t *testing.T) {
	wanID := host.IDFor("7c:61:70:fd:7f:34")
	lanID := host.IDFor("2c:88:6f:45:ad:0c")

	// Renamed interfaces: NICs swap names or become eth0/eth1
	renamedSnap := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simIface("eth0", 10, "2c:88:6f:45:ad:0c", "ether", false), // LAN MAC renamed to eth0
			simIface("eth1", 11, "7c:61:70:fd:7f:34", "ether", true),  // WAN MAC renamed to eth1
			simIface("lo", 1, "", "loopback", true),
		},
	}
	renamedDev := host.FromSnapshot(renamedSnap)

	assignments := []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
		{Role: host.RoleLAN, Selector: lanID},
	}

	res := host.Resolve(renamedDev, assignments)
	if !res.OK() {
		t.Fatalf("resolution failed after rename: %+v", res.Problems)
	}

	// WAN must resolve to eth1 (where MAC 7c:61:... now is)
	if res.Assigned[host.RoleWAN].SystemName != "eth1" {
		t.Errorf("WAN resolved to %q after rename, want eth1", res.Assigned[host.RoleWAN].SystemName)
	}
	// LAN must resolve to eth0 (where MAC 2c:88:... now is)
	if res.Assigned[host.RoleLAN].SystemName != "eth0" {
		t.Errorf("LAN resolved to %q after rename, want eth0", res.Assigned[host.RoleLAN].SystemName)
	}

	cfg := config.Defaults()
	cfg.Network.WAN = wanID
	cfg.Network.LAN = lanID
	cfg.Network.LANPrefix = "10.77.0.1/24"

	des := desired.FromConfigWithResolution(cfg, res)
	if des.WAN.Name != "eth1" || !des.WAN.Present {
		t.Errorf("desired WAN = %q (present=%t), want eth1", des.WAN.Name, des.WAN.Present)
	}
	if des.LAN.Name != "eth0" || !des.LAN.Present {
		t.Errorf("desired LAN = %q (present=%t), want eth0", des.LAN.Name, des.LAN.Present)
	}
}

// =============================================================================
// Requirement 6: No Positional Inference
// Tests must prove that THN never chooses an interface merely because it
// happens to be first/second/fastest.
// =============================================================================

func TestM4NoPositionalInference(t *testing.T) {
	// A device with varying speeds and alphabetical order
	snap := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simIface("br0", 1, "02:00:00:00:00:01", "bridge", true),      // Index 1, sorted 1st
			simIface("ethFast", 2, "aa:00:00:00:00:01", "ether", true),   // 10 Gbps (fastest)
			simIface("ethSlow", 3, "bb:00:00:00:00:01", "ether", true),   // 100 Mbps
			simIface("ethTarget", 4, "cc:00:00:00:00:01", "ether", true), // 1 Gbps (last)
		},
	}
	snap.Interfaces[1].SpeedMbps = 10000
	snap.Interfaces[2].SpeedMbps = 100
	snap.Interfaces[3].SpeedMbps = 1000

	dev := host.FromSnapshot(snap)

	// With NO assignments: neither WAN nor LAN must be selected
	res := host.Resolve(dev, nil)
	if len(res.Assigned) != 0 {
		t.Fatalf("resolving with no assignments assigned %d roles: %+v", len(res.Assigned), res.Assigned)
	}

	// When assigning only ethTarget: ethTarget must be selected, NOT ethFast or br0
	targetID := host.IDFor("cc:00:00:00:00:01")
	resTarget := host.Resolve(dev, []host.Assignment{{Role: host.RoleWAN, Selector: targetID}})
	if !resTarget.OK() {
		t.Fatalf("resolving target failed: %+v", resTarget.Problems)
	}
	if resTarget.Assigned[host.RoleWAN].SystemName != "ethTarget" {
		t.Errorf("WAN resolved to %q, want ethTarget", resTarget.Assigned[host.RoleWAN].SystemName)
	}
}

// =============================================================================
// Requirement 7: Conflict
// If configuration and stored assignment disagree, validation must report a
// conflict. Do not silently pick one.
// =============================================================================

func TestM4ConflictBetweenConfigAndStoredAssignmentReported(t *testing.T) {
	dir := t.TempDir()

	wanStored := host.IDFor("7c:61:70:fd:7f:34")
	wanDeclared := host.IDFor("2c:88:6f:45:ad:0c") // Conflicting interface!

	dbPath := writeStateDB(t, dir, []state.InterfaceAssignment{
		{Role: "wan", Selector: wanStored, IDKind: "hardware"},
		{Role: "lan", Selector: host.IDFor("aa:bb:cc:dd:ee:01"), IDKind: "hardware"},
	})

	cfg := config.Defaults()
	cfg.Network.WAN = wanDeclared // Disagrees with stored assignment
	cfg.Network.LAN = host.IDFor("aa:bb:cc:dd:ee:01")
	cfg.Paths.StateDB = dbPath
	cfg.Network.LANPrefix = "10.77.0.1/24"

	cfgPath := writeTestConfig(t, dir, cfg)

	stdout, stderr, code := runGateCLI(t, "validate", cfgPath)
	if code == ExitOK {
		t.Fatalf("validate must report conflict error and fail, got exit OK\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "conflict") && !strings.Contains(stderr, "conflict") {
		t.Errorf("expected conflict message in output:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}

	// Check thn config validate agrees
	cStdout, cStderr, cCode := runGateCLI(t, "config", "validate", cfgPath)
	if cCode == ExitOK {
		t.Fatalf("config validate must also report conflict, got exit OK\nstdout:\n%s\nstderr:\n%s", cStdout, cStderr)
	}
	if !strings.Contains(cStdout, "conflict") && !strings.Contains(cStderr, "conflict") {
		t.Errorf("expected conflict in config validate output:\n%s", cStdout)
	}
}

// =============================================================================
// Requirement 8: LAN/WAN Forwarding Coherence
// Forwarding validator accepts configuration where both roles are properly
// resolved, and rejects configuration where LAN or WAN cannot be resolved.
// =============================================================================

func TestM4ForwardingCoherenceRequiresResolvedLANAndWAN(t *testing.T) {
	// 1. Both resolved: Coherent
	coherentPol := netconfig.Default()
	coherentPol.Interfaces.WAN = "enp0s31f6"
	coherentPol.Interfaces.LAN = "enx00e099001812"
	coherentPol.Forwarding.Rules = []netconfig.ForwardRule{
		{Direction: netconfig.LANToWAN, Action: "accept"},
		{Direction: netconfig.WANToLAN, Action: "drop"},
	}
	coherentPol.NAT.Enabled = true
	coherentPol.NAT.InInterface = "enx00e099001812"
	coherentPol.NAT.OutInterface = "enp0s31f6"

	res, issues := netconfig.Validate(coherentPol)
	if !res.Valid || !res.Coherent || len(issues) > 0 {
		t.Errorf("fully resolved forwarding policy must be coherent, got issues: %+v", issues)
	}

	// 2. Missing LAN: Incoherent
	missingLANPol := coherentPol
	missingLANPol.Interfaces.LAN = ""
	_, lanIssues := netconfig.Validate(missingLANPol)
	hasLANIssue := false
	for _, issue := range lanIssues {
		if strings.Contains(issue.Subsystems, "forwarding+interfaces") && strings.Contains(issue.Message, "LAN") {
			hasLANIssue = true
			break
		}
	}
	if !hasLANIssue {
		t.Errorf("missing LAN must fail forwarding coherence, got issues: %+v", lanIssues)
	}

	// 3. Missing WAN: Incoherent
	missingWANPol := coherentPol
	missingWANPol.Interfaces.WAN = ""
	_, wanIssues := netconfig.Validate(missingWANPol)
	hasWANIssue := false
	for _, issue := range wanIssues {
		if strings.Contains(issue.Subsystems, "forwarding+interfaces") && strings.Contains(issue.Message, "WAN") {
			hasWANIssue = true
			break
		}
	}
	if !hasWANIssue {
		t.Errorf("missing WAN must fail forwarding coherence, got issues: %+v", wanIssues)
	}
}

// =============================================================================
// Requirement 9: NAT Explicitness
// Prove that NAT is only present when explicitly configured.
// =============================================================================

func TestM4NATIsOnlyPresentWhenExplicitlyConfigured(t *testing.T) {
	dev := dellHostFixture()
	wanID := host.IDFor("7c:61:70:fd:7f:34")
	lanID := host.IDFor("2c:88:6f:45:ad:0c")

	res := host.Resolve(dev, []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
		{Role: host.RoleLAN, Selector: lanID},
	})

	// When NAT is disabled in config
	cfg := config.Defaults()
	cfg.Network.WAN = wanID
	cfg.Network.LAN = lanID
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.NAT.Enabled = false

	des := desired.FromConfigWithResolution(cfg, res)
	if des.NAT.Enabled {
		t.Error("NAT must not be enabled in desired state when cfg.NAT.Enabled is false")
	}

	// Netconfig policy must have NAT disabled
	netPol := netPolicyFromConfig(cfg)
	if netPol.NAT.Enabled {
		t.Error("netconfig policy must have NAT disabled when cfg.NAT.Enabled is false")
	}
	if netPol.NAT.Mode != netconfig.NATNone {
		t.Errorf("netconfig NAT mode = %v, want NATNone", netPol.NAT.Mode)
	}

	// Firewall policy must have Masquerade disabled
	fwPol := policyFromConfig(cfg)
	if fwPol.Masquerade.Enabled {
		t.Error("firewall policy must have Masquerade disabled when cfg.NAT.Enabled is false")
	}
}

// =============================================================================
// Requirement 10: DHCP Agreement
// The canonical LAN and DHCP configuration must agree.
// =============================================================================

func TestM4DHCPAgreementWithCanonicalLAN(t *testing.T) {
	cfg := mustLoadCanonical(t)

	// Canonical LAN prefix is 10.77.0.1/24
	if cfg.Network.LANPrefix != "10.77.0.1/24" {
		t.Fatalf("canonical LAN prefix = %q, want 10.77.0.1/24", cfg.Network.LANPrefix)
	}

	// Canonical DHCP range is 10.77.0.100 - 10.77.0.250
	if len(cfg.DHCP.Ranges) != 1 {
		t.Fatalf("canonical DHCP ranges count = %d, want 1", len(cfg.DHCP.Ranges))
	}
	rg := cfg.DHCP.Ranges[0]
	if rg.Start != "10.77.0.100" || rg.End != "10.77.0.250" {
		t.Errorf("canonical DHCP range = %s-%s, want 10.77.0.100-10.77.0.250", rg.Start, rg.End)
	}

	// DHCP policy from canonical config validates cleanly
	dhcpPol, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("dhcpPolicyFromConfig: %v", err)
	}
	dhcpRes := dhcp.Validate(dhcpPol)
	if !dhcpRes.Valid {
		t.Fatalf("canonical DHCP validation failed: %+v", dhcpRes.Findings)
	}

	// Negative check: Altering DHCP range to violate canonical subnet bounds must fail
	brokenRanges := []config.DHCPRangeConfig{
		{Start: "10.77.0.0", End: "10.77.0.100"},     // Includes network address .0
		{Start: "10.77.0.100", End: "10.77.0.255"},   // Includes broadcast address .255
		{Start: "10.77.0.200", End: "10.77.0.100"},   // Reversed range
		{Start: "192.168.1.10", End: "192.168.1.50"}, // Outside 10.77.0.0/24 subnet
	}

	for _, badRg := range brokenRanges {
		badCfg := cfg
		badCfg.DHCP.Ranges = []config.DHCPRangeConfig{badRg}
		badPol, err := dhcpPolicyFromConfig(badCfg)
		if err == nil {
			badRes := dhcp.Validate(badPol)
			if badRes.Valid {
				t.Errorf("DHCP range %+v must fail validation against LAN prefix %s", badRg, cfg.Network.LANPrefix)
			}
		}
	}
}

// =============================================================================
// Requirement 11: DNS Agreement
// Existing DNS precedence/conflict semantics must remain intact.
// =============================================================================

func TestM4DNSPrecedenceAndConflictSemantics(t *testing.T) {
	// Case 1: dns.upstream is authoritative
	cfg1 := config.Defaults()
	cfg1.Network.WAN = "eth0"
	cfg1.DNS.Upstream = []string{"1.1.1.1", "9.9.9.9"}
	cfg1.Network.DNS = nil

	pol1, err := dnsPolicyFromConfig(cfg1)
	if err != nil {
		t.Fatalf("dnsPolicyFromConfig: %v", err)
	}
	if len(pol1.Upstream) != 2 || pol1.Upstream[0].String() != "1.1.1.1" {
		t.Errorf("DNS upstreams = %v, want [1.1.1.1, 9.9.9.9]", pol1.Upstream)
	}

	// Case 2: network.dns is fallback when dns.upstream is empty
	cfg2 := config.Defaults()
	cfg2.Network.WAN = "eth0"
	cfg2.DNS.Upstream = nil
	cfg2.Network.DNS = []string{"8.8.8.8"}

	pol2, err := dnsPolicyFromConfig(cfg2)
	if err != nil {
		t.Fatalf("dnsPolicyFromConfig: %v", err)
	}
	if len(pol2.Upstream) != 1 || pol2.Upstream[0].String() != "8.8.8.8" {
		t.Errorf("DNS upstreams fallback = %v, want [8.8.8.8]", pol2.Upstream)
	}

	// Case 3: Both set and identical -> Warning
	cfg3 := config.Defaults()
	cfg3.Network.WAN = "eth0"
	cfg3.DNS.Upstream = []string{"1.1.1.1"}
	cfg3.Network.DNS = []string{"1.1.1.1"}

	res3 := validation.Static(cfg3)
	hasWarn := false
	for _, f := range res3.Warnings() {
		if f.Field == "dns.upstream" {
			hasWarn = true
			break
		}
	}
	if !hasWarn {
		t.Errorf("identical resolvers must produce warning finding, got: %+v", res3.Warnings())
	}

	// Case 4: Both set and different -> Error
	cfg4 := config.Defaults()
	cfg4.Network.WAN = "eth0"
	cfg4.DNS.Upstream = []string{"1.1.1.1"}
	cfg4.Network.DNS = []string{"8.8.8.8"}

	res4 := validation.Static(cfg4)
	hasErr := false
	for _, f := range res4.Errors() {
		if f.Field == "dns.upstream" {
			hasErr = true
			break
		}
	}
	if !hasErr {
		t.Errorf("conflicting resolvers must produce error finding, got: %+v", res4.Errors())
	}
}

// =============================================================================
// Requirement 12: Command Agreement
// thn validate, thn config validate, and thn plan must agree on configuration.
// =============================================================================

func TestM4CommandAgreementAcrossValidateAndPlan(t *testing.T) {
	path := canonicalConfigPath(t)

	// thn validate
	vOut, vErr, vCode := runGateCLI(t, "validate", path)
	if vCode != ExitOK {
		t.Fatalf("thn validate failed: %d\nstdout:\n%s\nstderr:\n%s", vCode, vOut, vErr)
	}

	// thn config validate
	cvOut, cvErr, cvCode := runGateCLI(t, "config", "validate", path)
	if cvCode != ExitOK {
		t.Fatalf("thn config validate failed: %d\nstdout:\n%s\nstderr:\n%s", cvCode, cvOut, cvErr)
	}

	// Both commands must produce identical exit codes and agreement
	if vCode != cvCode {
		t.Errorf("thn validate exit %d != thn config validate exit %d", vCode, cvCode)
	}

	// thn plan (descriptive, pure, no mutation)
	pOut, pErr, pCode := runGateCLI(t, "plan", path)
	if pCode != ExitOK {
		t.Fatalf("thn plan failed: %d\nstdout:\n%s\nstderr:\n%s", pCode, pOut, pErr)
	}
	if !strings.Contains(pOut, "Simulation (nothing has been changed)") {
		t.Errorf("thn plan must include simulation header stating nothing changed:\n%s", pOut)
	}

	// thn config plan
	cpOut, cpErr, cpCode := runGateCLI(t, "config", "plan", path)
	if cpCode != ExitOK {
		t.Fatalf("thn config plan failed: %d\nstdout:\n%s\nstderr:\n%s", cpCode, cpOut, cpErr)
	}
	if pCode != cpCode {
		t.Errorf("thn plan exit %d != thn config plan exit %d", pCode, cpCode)
	}
}
