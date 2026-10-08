package planner

import (
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

func dellDeviceFixture() *host.Device {
	snap := &network.Snapshot{
		CapturedAt: time.Date(2026, 10, 3, 20, 0, 0, 0, time.UTC),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			{Name: "enp0s31f6", Index: 2, MAC: "7c:61:70:fd:7f:34", MTU: 1500, SpeedMbps: 1000, Kind: "ether", Physical: true, State: network.LinkUp, AdminUp: true, Carrier: true},
			{Name: "enx00e099001812", Index: 3, MAC: "2c:88:6f:45:ad:0c", MTU: 1500, SpeedMbps: 0, Kind: "ether", Physical: true, State: network.LinkDown, AdminUp: true, Carrier: false},
			{Name: "docker0", Index: 4, MAC: "02:42:8a:1b:2c:3d", MTU: 1500, Kind: "bridge", Physical: false, State: network.LinkUp, AdminUp: true, Carrier: true},
			{Name: "tailscale0", Index: 5, MAC: "5a:ab:cd:ef:00:01", MTU: 1280, Kind: "tun", Physical: false, State: network.LinkUp, AdminUp: true, Carrier: true},
			{Name: "veth1234", Index: 6, MAC: "9a:1b:2c:3d:4e:5f", MTU: 1500, Kind: "veth", Physical: false, State: network.LinkUp, AdminUp: true, Carrier: true},
			{Name: "lo", Index: 1, MTU: 65536, Kind: "loopback", Physical: false, State: network.LinkUp, AdminUp: true, Carrier: true},
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
	return host.FromSnapshot(snap)
}

func dellObservedFixture() diff.Observed {
	return diff.Observed{
		Supported:           true,
		HostName:            "dell-gateway",
		WANName:             "enp0s31f6",
		WANPresent:          true,
		WANUp:               true,
		LANName:             "enx00e099001812",
		LANPresent:          true,
		LANUp:               false,
		LANAddresses:        []string{},
		DefaultGateway:      "192.168.1.1",
		HasDefaultRoute:     true,
		IPv4Forwarding:      false,
		IPv4ForwardingKnown: true,
		FirewallActive:      false,
		FirewallRuleCount:   0,
		QoSActive:           false,
		Resolvers:           []string{"1.1.1.1", "9.9.9.9"},
		ResolversKnown:      true,
	}
}

func canonicalDesiredFixture() desired.State {
	return desired.State{
		Name:          "thn-gateway",
		Generation:    1,
		SchemaVersion: 1,
		WAN: desired.Interface{
			Name:    "enp0s31f6",
			Role:    desired.RoleWAN,
			MTU:     1500,
			Up:      true,
			Present: true,
		},
		LAN: desired.Interface{
			Name:      "enx00e099001812",
			Role:      desired.RoleLAN,
			MTU:       1500,
			Up:        true,
			Present:   true,
			Addresses: []string{"10.77.0.1/24"},
		},
		Addressing: desired.Addressing{
			DefaultGateway:  "192.168.1.1",
			UpstreamPresent: true,
			IPv4Forwarding:  true,
		},
		NAT: desired.NAT{
			Enabled:    true,
			Resolved:   true,
			Interfaces: []string{"enx00e099001812"},
		},
		Firewall: desired.Firewall{
			Enabled:              true,
			Backend:              "nftables",
			DefaultInboundPolicy: "drop",
			AllowEstablished:     true,
			AllowLoopback:        true,
		},
		QoS: desired.QoS{
			Enabled:  false,
			Resolved: true,
		},
		DNS: desired.DNS{
			Present: true,
			Servers: []string{"1.1.1.1", "9.9.9.9"},
		},
	}
}

// 1. Deterministic plan
func TestM5PlanIsDeterministic(t *testing.T) {
	obs := dellObservedFixture()
	des := canonicalDesiredFixture()
	assignments := []host.Assignment{
		{Role: host.RoleWAN, Selector: "hw:7c6170fd7f34317a"},
		{Role: host.RoleLAN, Selector: "hw:2c886f45ad0cb12f"},
	}

	d := diff.Compare(obs, diff.Desired{
		WANName:         des.WAN.Name,
		WANPresent:      des.WAN.Present,
		WANUp:           des.WAN.Up,
		LANName:         des.LAN.Name,
		LANPresent:      des.LAN.Present,
		LANUp:           des.LAN.Up,
		LANAddresses:    des.LAN.Addresses,
		DefaultGateway:  des.Addressing.DefaultGateway,
		UpstreamPresent: des.Addressing.UpstreamPresent,
		IPv4Forwarding:  des.Addressing.IPv4Forwarding,
		NATEnabled:      des.NAT.Enabled,
		NATResolved:     des.NAT.Resolved,
		FirewallEnabled: des.Firewall.Enabled,
		FirewallBackend: des.Firewall.Backend,
		FirewallPolicy:  des.Firewall.DefaultInboundPolicy,
	})

	fixedTime := time.Date(2026, 10, 3, 20, 30, 0, 0, time.UTC)
	opts := Options{
		Generation:  1,
		Source:      "/etc/thn/config.yaml",
		Live:        true,
		Now:         fixedTime,
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Device:      dellDeviceFixture(),
	}

	plan1 := Build(d, opts)
	plan2 := Build(d, opts)

	if plan1.ID != plan2.ID {
		t.Fatalf("plan IDs differ across identical builds: %q != %q", plan1.ID, plan2.ID)
	}
	if plan1.Summary != plan2.Summary {
		t.Errorf("plan summaries differ: %q != %q", plan1.Summary, plan2.Summary)
	}
	if len(plan1.Steps) != len(plan2.Steps) {
		t.Fatalf("step counts differ: %d != %d", len(plan1.Steps), len(plan2.Steps))
	}
	for i := range plan1.Steps {
		if plan1.Steps[i].ID != plan2.Steps[i].ID || plan1.Steps[i].Action != plan2.Steps[i].Action {
			t.Errorf("step %d mismatch: %+v != %+v", i, plan1.Steps[i], plan2.Steps[i])
		}
	}
}

// 2. Canonical desired state produces valid plan
func TestM5CanonicalDesiredStateGeneratesValidPlan(t *testing.T) {
	obs := dellObservedFixture()
	des := canonicalDesiredFixture()

	d := diff.Compare(obs, diff.Desired{
		WANName:         des.WAN.Name,
		WANPresent:      des.WAN.Present,
		WANUp:           des.WAN.Up,
		LANName:         des.LAN.Name,
		LANPresent:      des.LAN.Present,
		LANUp:           des.LAN.Up,
		LANAddresses:    des.LAN.Addresses,
		DefaultGateway:  des.Addressing.DefaultGateway,
		UpstreamPresent: des.Addressing.UpstreamPresent,
		IPv4Forwarding:  des.Addressing.IPv4Forwarding,
		NATEnabled:      des.NAT.Enabled,
		NATResolved:     des.NAT.Resolved,
		FirewallEnabled: des.Firewall.Enabled,
		FirewallBackend: des.Firewall.Backend,
		FirewallPolicy:  des.Firewall.DefaultInboundPolicy,
	})

	p := Build(d, Options{
		Generation: 1,
		Live:       true,
		Observed:   obs,
		Desired:    des,
	})

	if !p.Ready {
		t.Errorf("canonical plan must be ready, got simulation: %+v", p.Simulation)
	}
	if len(p.Blocked) > 0 {
		t.Errorf("canonical plan has blocked changes: %+v", p.Blocked)
	}
	if len(p.Steps) == 0 {
		t.Error("canonical plan should have actionable drift steps for unconfigured Dell")
	}
}

// 3. No-op on matching state
func TestM5NoopWhenObservedMatchesDesired(t *testing.T) {
	obs := dellObservedFixture()
	// Update obs so it matches desired completely
	obs.LANUp = true
	obs.LANAddresses = []string{"10.77.0.1/24"}
	obs.IPv4Forwarding = true
	obs.FirewallActive = true
	obs.FirewallRuleCount = 5

	des := canonicalDesiredFixture()

	d := diff.Compare(obs, diff.Desired{
		WANName:         des.WAN.Name,
		WANPresent:      des.WAN.Present,
		WANUp:           des.WAN.Up,
		LANName:         des.LAN.Name,
		LANPresent:      des.LAN.Present,
		LANUp:           des.LAN.Up,
		LANAddresses:    des.LAN.Addresses,
		DefaultGateway:  des.Addressing.DefaultGateway,
		UpstreamPresent: des.Addressing.UpstreamPresent,
		IPv4Forwarding:  des.Addressing.IPv4Forwarding,
		NATEnabled:      des.NAT.Enabled,
		NATResolved:     des.NAT.Resolved,
		FirewallEnabled: des.Firewall.Enabled,
		FirewallBackend: des.Firewall.Backend,
		FirewallPolicy:  des.Firewall.DefaultInboundPolicy,
	})

	p := Build(d, Options{
		Generation: 1,
		Observed:   obs,
		Desired:    des,
	})

	if len(p.Steps) != 0 {
		t.Errorf("expected 0 steps for converged state, got %d", len(p.Steps))
	}
	if !p.Ready {
		t.Error("converged plan must be ready")
	}
	if !strings.Contains(p.Simulation.Headline, "already matches") {
		t.Errorf("headline = %q, want 'already matches'", p.Simulation.Headline)
	}
}

// 4. Create operations
func TestM5CreateOperationsGeneratedForAbsentState(t *testing.T) {
	d := result(
		drift("lan-address-add", "address", "lan.address", diff.RiskLow),
		drift("firewall-absent", "nftables", "firewall.enabled", diff.RiskCritical),
	)

	p := Build(d, Options{Generation: 1})

	createSteps := p.StepsByAction(ActionCreate)
	if len(createSteps) != 2 {
		t.Fatalf("expected 2 CREATE steps, got %d", len(createSteps))
	}
	for _, s := range createSteps {
		if s.Action != ActionCreate {
			t.Errorf("step %s action = %v, want CREATE", s.ID, s.Action)
		}
	}
}

// 5. Update operations
func TestM5UpdateOperationsGeneratedForDriftedState(t *testing.T) {
	d := result(
		drift("lan-link-state", "link", "lan.link", diff.RiskMedium),
		drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium),
		drift("default-route-gateway", "route", "addressing.default_gateway", diff.RiskMedium),
	)

	p := Build(d, Options{Generation: 1})

	updateSteps := p.StepsByAction(ActionUpdate)
	if len(updateSteps) != 3 {
		t.Fatalf("expected 3 UPDATE steps, got %d", len(updateSteps))
	}
}

// 6. Delete operations
func TestM5DeleteOperationsGeneratedForObsoleteManagedState(t *testing.T) {
	c := diff.Change{
		ID:        "lan-address-remove",
		Kind:      diff.KindDrift,
		Risk:      diff.RiskHigh,
		Subsystem: "address",
		Field:     "lan.address",
		Current:   "10.77.0.99/24",
		Desired:   "(none)",
		Reason:    "lan carries obsolete address",
	}

	p := Build(result(c), Options{Generation: 1})

	delSteps := p.StepsByAction(ActionDelete)
	if len(delSteps) != 1 {
		t.Fatalf("expected 1 DELETE step, got %d", len(delSteps))
	}
	if delSteps[0].Action != ActionDelete {
		t.Errorf("action = %v, want DELETE", delSteps[0].Action)
	}
	if len(delSteps[0].Commands) == 0 || !strings.Contains(delSteps[0].Commands[0], "ip addr del 10.77.0.99/24") {
		t.Errorf("command = %v, want ip addr del", delSteps[0].Commands)
	}
}

// 7. Unmanaged state protection
func TestM5UnmanagedStateIsProtectedFromDeletion(t *testing.T) {
	dev := dellDeviceFixture()
	des := canonicalDesiredFixture()
	obs := dellObservedFixture()

	p := Build(result(), Options{
		Generation: 1,
		Device:     dev,
		Observed:   obs,
		Desired:    des,
	})

	// Check that unmanaged interfaces are identified
	unmanagedJoined := strings.Join(p.UnmanagedResources, " ")
	for _, expectedUnmanaged := range []string{"docker0", "tailscale0", "veth1234", "lo"} {
		if !strings.Contains(unmanagedJoined, expectedUnmanaged) {
			t.Errorf("expected %s to be listed in UnmanagedResources: %v", expectedUnmanaged, p.UnmanagedResources)
		}
	}

	// Verify no steps exist that delete or alter unmanaged resources
	for _, s := range p.Steps {
		for _, unmanaged := range []string{"docker0", "tailscale0", "veth1234", "lo"} {
			if strings.Contains(s.Summary, unmanaged) || strings.Contains(s.Field, unmanaged) {
				t.Errorf("step %+v touches unmanaged resource %s", s, unmanaged)
			}
		}
	}
}

// 8. Missing WAN blocks execution planning
func TestM5MissingWANBlocksPlanning(t *testing.T) {
	obs := dellObservedFixture()
	obs.WANPresent = false
	obs.WANName = ""

	des := canonicalDesiredFixture()
	des.WAN.Present = false
	des.WAN.Name = ""

	d := diff.Compare(obs, diff.Desired{
		WANPresent: false,
		LANPresent: true,
		LANName:    "enx00e099001812",
	})

	p := Build(d, Options{
		Generation: 1,
		Observed:   obs,
		Desired:    des,
	})

	if p.Ready {
		t.Error("plan with missing WAN must NOT be ready")
	}
	if len(p.Pending) == 0 {
		t.Error("missing WAN must produce pending changes")
	}
}

// 9. Missing LAN blocks execution planning
func TestM5MissingLANBlocksPlanning(t *testing.T) {
	obs := dellObservedFixture()
	obs.LANPresent = false
	obs.LANName = ""

	des := canonicalDesiredFixture()
	des.LAN.Present = false
	des.LAN.Name = ""

	d := diff.Compare(obs, diff.Desired{
		WANPresent: true,
		WANName:    "enp0s31f6",
		LANPresent: false,
	})

	p := Build(d, Options{
		Generation: 1,
		Observed:   obs,
		Desired:    des,
	})

	if p.Ready {
		t.Error("plan with missing LAN must NOT be ready")
	}
	if len(p.Pending) == 0 {
		t.Error("missing LAN must produce pending changes")
	}
}

// 10. Conflict blocks planning
func TestM5ConflictBlocksPlanning(t *testing.T) {
	d := result(blocked("wan-name-mismatch", "link", "wan.interface"))

	p := Build(d, Options{Generation: 1})

	if p.Ready {
		t.Error("plan with conflict must not be ready")
	}
	if len(p.Blocked) != 1 {
		t.Errorf("got %d blocked changes, want 1", len(p.Blocked))
	}
}

// 11. Stable identity survives kernel rename
func TestM5StableIdentitySurvivesKernelRenameInPlan(t *testing.T) {
	wanID := host.IDFor("7c:61:70:fd:7f:34")
	lanID := host.IDFor("2c:88:6f:45:ad:0c")

	// Renamed observation
	renamedObs := dellObservedFixture()
	renamedObs.WANName = "eth1"
	renamedObs.LANName = "eth0"

	// Renamed desired state derived from resolution
	renamedDes := canonicalDesiredFixture()
	renamedDes.WAN.Name = "eth1"
	renamedDes.LAN.Name = "eth0"
	renamedDes.NAT.Interfaces = []string{"eth0"}

	d := diff.Compare(renamedObs, diff.Desired{
		WANName:         "eth1",
		WANPresent:      true,
		WANUp:           true,
		LANName:         "eth0",
		LANPresent:      true,
		LANUp:           true,
		LANAddresses:    []string{"10.77.0.1/24"},
		DefaultGateway:  "192.168.1.1",
		UpstreamPresent: true,
		IPv4Forwarding:  true,
		NATEnabled:      true,
		NATResolved:     true,
		FirewallEnabled: true,
		FirewallBackend: "nftables",
		FirewallPolicy:  "drop",
	})

	p := Build(d, Options{
		Generation: 1,
		Live:       true,
		Observed:   renamedObs,
		Desired:    renamedDes,
		Assignments: []host.Assignment{
			{Role: host.RoleWAN, Selector: wanID},
			{Role: host.RoleLAN, Selector: lanID},
		},
	})

	if !p.Ready {
		t.Errorf("plan after kernel rename must remain ready, got: %+v", p.Simulation)
	}
	for _, s := range p.Steps {
		if strings.Contains(s.Commands[0], "enp0s31f6") || strings.Contains(s.Commands[0], "enx00e099001812") {
			t.Errorf("step refers to old kernel names: %s", s.Commands[0])
		}
	}
}

// 12. Stale state detection
func TestM5StalePlanDetection(t *testing.T) {
	obs1 := dellObservedFixture()
	des := canonicalDesiredFixture()

	p := Build(result(), Options{
		Generation: 1,
		Observed:   obs1,
		Desired:    des,
	})

	// Same observation: valid
	valid, pre := p.ValidatePreconditions(obs1, des)
	if !valid {
		t.Errorf("preconditions should be valid against original state, got: %+v", pre)
	}

	// Host state changes (e.g. WAN goes down or LAN IP is added by third-party)
	obs2 := obs1
	obs2.WANUp = false
	obs2.LANAddresses = []string{"192.168.99.1/24"}

	valid2, pre2 := p.ValidatePreconditions(obs2, des)
	if valid2 {
		t.Error("preconditions must report stale when host state changes")
	}
	foundStale := false
	for _, pr := range pre2 {
		if pr.ID == "observed-state-fresh" && !pr.Satisfied {
			foundStale = true
			if !strings.Contains(pr.Reason, "stale") {
				t.Errorf("reason should mention stale plan: %s", pr.Reason)
			}
			break
		}
	}
	if !foundStale {
		t.Errorf("expected observed-state-fresh to fail, got: %+v", pre2)
	}
}

// 13. Desired-state digest changes plan ID
func TestM5DesiredStateDigestChangesPlanID(t *testing.T) {
	obs := dellObservedFixture()
	des1 := canonicalDesiredFixture()
	des2 := canonicalDesiredFixture()
	des2.LAN.Addresses = []string{"10.88.0.1/24"} // Changed desired LAN prefix

	d1 := result(drift("lan-address-add", "address", "lan.address", diff.RiskLow))
	d2 := result(drift("lan-address-add", "address", "lan.address", diff.RiskLow))

	p1 := Build(d1, Options{Generation: 1, Observed: obs, Desired: des1})
	p2 := Build(d2, Options{Generation: 1, Observed: obs, Desired: des2})

	if p1.Inputs.DesiredDigest == p2.Inputs.DesiredDigest {
		t.Errorf("desired digests must differ for different desired states: %q == %q",
			p1.Inputs.DesiredDigest, p2.Inputs.DesiredDigest)
	}
	if p1.ID == p2.ID {
		t.Errorf("plan IDs must differ when desired state changes: %q == %q", p1.ID, p2.ID)
	}
}

// 14. Dependency order
func TestM5DependencyOrderAcrossPhases(t *testing.T) {
	d := result(
		drift("resolvers", "resolver", "network.dns", diff.RiskLow),
		drift("firewall-absent", "nftables", "firewall.enabled", diff.RiskCritical),
		drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium),
		drift("lan-link-state", "link", "lan.link", diff.RiskMedium),
		drift("lan-address-add", "address", "lan.address", diff.RiskLow),
	)

	p := Build(d, Options{Generation: 1})

	if len(p.Steps) != 5 {
		t.Fatalf("expected 5 steps, got %d", len(p.Steps))
	}

	// Verify phase monotonicity
	for i := 1; i < len(p.Steps); i++ {
		if p.Steps[i].Phase < p.Steps[i-1].Phase {
			t.Fatalf("phase ordering violated: step %d (phase %d) after step %d (phase %d)",
				i, p.Steps[i].Phase, i-1, p.Steps[i-1].Phase)
		}
	}
}

// 15. Rollback metadata
func TestM5RollbackMetadataAttachedToMutatingSteps(t *testing.T) {
	d := result(
		drift("lan-address-add", "address", "lan.address", diff.RiskLow),
		drift("ip-forwarding", "sysctl", "addressing.ipv4_forwarding", diff.RiskMedium),
		drift("firewall-absent", "nftables", "firewall.enabled", diff.RiskCritical),
	)

	p := Build(d, Options{Generation: 1})

	for _, s := range p.Steps {
		if s.Rollback == nil {
			t.Fatalf("step %s missing rollback metadata", s.ID)
		}
		if s.Rollback.Target == "" {
			t.Errorf("step %s rollback missing Target", s.ID)
		}
		if len(s.Rollback.RestoreCommands) == 0 && s.Rollback.Reversibility != "irreversible" {
			t.Errorf("step %s rollback missing RestoreCommands", s.ID)
		}
	}
}

// 16. Pure planning
func TestM5PlanningIsPureAndExecutesNoCommands(t *testing.T) {
	obs := dellObservedFixture()
	des := canonicalDesiredFixture()

	d := diff.Compare(obs, diff.Desired{
		WANName:         des.WAN.Name,
		WANPresent:      des.WAN.Present,
		WANUp:           des.WAN.Up,
		LANName:         des.LAN.Name,
		LANPresent:      des.LAN.Present,
		LANUp:           des.LAN.Up,
		LANAddresses:    des.LAN.Addresses,
		DefaultGateway:  des.Addressing.DefaultGateway,
		UpstreamPresent: des.Addressing.UpstreamPresent,
		IPv4Forwarding:  des.Addressing.IPv4Forwarding,
		NATEnabled:      des.NAT.Enabled,
		NATResolved:     des.NAT.Resolved,
		FirewallEnabled: des.Firewall.Enabled,
		FirewallBackend: des.Firewall.Backend,
		FirewallPolicy:  des.Firewall.DefaultInboundPolicy,
	})

	p := Build(d, Options{
		Generation: 1,
		Observed:   obs,
		Desired:    des,
	})

	if p == nil || p.ID == "" {
		t.Fatal("plan generation failed")
	}
	if !p.Transaction.DryRun {
		t.Error("plan transaction must be marked DryRun = true")
	}
}
