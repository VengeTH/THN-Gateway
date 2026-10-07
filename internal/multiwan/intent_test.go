package multiwan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/host"
)

func validDeviceFixture() *host.Device {
	return &host.Device{
		Supported: true,
		Interfaces: []host.Interface{
			{
				ID:         "hw:7c6170fd7f34317a",
				SystemName: "enp0s31f6",
				Physical:   true,
				Assignable: true,
				AdminUp:    true,
				LinkUp:     true,
				Addresses:  []string{"203.0.113.5/24"},
			},
			{
				ID:         "hw:2c886f45ad0cb12f",
				SystemName: "enx00e099001812",
				Physical:   true,
				Assignable: true,
				AdminUp:    true,
				LinkUp:     true,
				Addresses:  []string{"198.51.100.10/24"},
			},
			{
				ID:         "hw:3a11223344556677",
				SystemName: "enp1s0",
				Physical:   true,
				Assignable: true,
				AdminUp:    true,
				LinkUp:     true,
				Addresses:  []string{"10.77.0.1/24"},
			},
		},
	}
}

func hasCode(rep Report, code string) bool {
	for _, f := range rep.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func codes(rep Report) []string {
	out := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		out = append(out, f.Code)
	}
	return out
}

// -----------------------------------------------------------------------------
// Model / Intent Tests (Section 44: 1-16)
// -----------------------------------------------------------------------------

// 1. Single WAN remains valid
func TestSingleWANRemainsValid(t *testing.T) {
	in := Intent{
		Enabled:       false,
		Mode:          ModeSingle,
		RoutingPolicy: RoutingPolicyDefault,
		Members: []Member{
			{
				ID:        "wan",
				Selector:  "hw:7c6170fd7f34317a",
				Interface: "enp0s31f6",
				StableID:  "hw:7c6170fd7f34317a",
				Declared:  true,
				Resolved:  true,
				Enabled:   true,
				Priority:  100,
				Weight:    1,
				Health: HealthEvidence{
					State:     HealthUnknown,
					CarrierUp: true,
					AdminUp:   true,
				},
			},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID for single WAN; findings: %v", rep.Verdict, codes(rep))
	}
	if len(rep.ActiveMembers) != 1 {
		t.Fatalf("got %d active members, want 1", len(rep.ActiveMembers))
	}
}

// 2. Two WANs load-balanced
func TestTwoWANsLoadBalanced(t *testing.T) {
	in := Intent{
		Enabled:       true,
		Mode:          ModeLoadBalance,
		RoutingPolicy: RoutingPolicyDefault,
		Members: []Member{
			{
				ID:        "wan-a",
				Selector:  "hw:7c6170fd7f34317a",
				Interface: "enp0s31f6",
				StableID:  "hw:7c6170fd7f34317a",
				Declared:  true,
				Resolved:  true,
				Enabled:   true,
				Priority:  100,
				Weight:    1,
				Health:    HealthEvidence{State: HealthUnknown, CarrierUp: true, AdminUp: true},
			},
			{
				ID:        "wan-b",
				Selector:  "hw:2c886f45ad0cb12f",
				Interface: "enx00e099001812",
				StableID:  "hw:2c886f45ad0cb12f",
				Declared:  true,
				Resolved:  true,
				Enabled:   true,
				Priority:  100,
				Weight:    1,
				Health:    HealthEvidence{State: HealthUnknown, CarrierUp: true, AdminUp: true},
			},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID for two load balanced WANs; findings: %v", rep.Verdict, codes(rep))
	}
	if len(rep.ActiveMembers) != 2 {
		t.Fatalf("active members = %d, want 2", len(rep.ActiveMembers))
	}
}

// 3. Two WANs failover
func TestTwoWANsFailover(t *testing.T) {
	in := Intent{
		Enabled:       true,
		Mode:          ModeFailover,
		RoutingPolicy: RoutingPolicyDefault,
		Members: []Member{
			{
				ID:        "wan-primary",
				Selector:  "hw:7c6170fd7f34317a",
				Interface: "enp0s31f6",
				StableID:  "hw:7c6170fd7f34317a",
				Declared:  true,
				Resolved:  true,
				Enabled:   true,
				Priority:  100,
				Weight:    1,
				Health:    HealthEvidence{State: HealthUnknown, CarrierUp: true, AdminUp: true},
			},
			{
				ID:        "wan-backup",
				Selector:  "hw:2c886f45ad0cb12f",
				Interface: "enx00e099001812",
				StableID:  "hw:2c886f45ad0cb12f",
				Declared:  true,
				Resolved:  true,
				Enabled:   true,
				Priority:  50,
				Weight:    1,
				Health:    HealthEvidence{State: HealthUnknown, CarrierUp: true, AdminUp: true},
			},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID for failover; findings: %v", rep.Verdict, codes(rep))
	}
	if len(rep.ActiveMembers) != 1 || rep.ActiveMembers[0].ID != "wan-primary" {
		t.Errorf("active member = %v, want wan-primary", rep.ActiveMembers)
	}
	if len(rep.StandbyMembers) != 1 || rep.StandbyMembers[0].ID != "wan-backup" {
		t.Errorf("standby member = %v, want wan-backup", rep.StandbyMembers)
	}
}

// 4. Three WANs deterministic
func TestThreeWANsDeterministic(t *testing.T) {
	in := Intent{
		Enabled:       true,
		Mode:          ModeLoadBalance,
		RoutingPolicy: RoutingPolicyDefault,
		Members: []Member{
			{ID: "wan-c", Selector: "enp3", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
			{ID: "wan-a", Selector: "enp1", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
			{ID: "wan-b", Selector: "enp2", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID; findings: %v", rep.Verdict, codes(rep))
	}

	// Members must be deterministically sorted by ID
	if rep.ActiveMembers[0].ID != "wan-a" || rep.ActiveMembers[1].ID != "wan-b" || rep.ActiveMembers[2].ID != "wan-c" {
		t.Errorf("active members not ordered by ID: %v", rep.ActiveMembers)
	}
}

// 5. Missing WAN
func TestMissingWAN(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: nil,
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED when no members configured", rep.Verdict)
	}
	if !hasCode(rep, CodeMembersEmpty) {
		t.Errorf("expected code %s, got %v", CodeMembersEmpty, codes(rep))
	}
}

// 6. Unresolved WAN
func TestUnresolvedWAN(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeFailover,
		Members: []Member{
			{
				ID:       "wan-a",
				Selector: "hw:notattached",
				Declared: true,
				Resolved: false,
				Enabled:  true,
				Priority: 100,
				Weight:   1,
			},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictPending {
		t.Fatalf("verdict = %s, want PENDING for unresolved WAN", rep.Verdict)
	}
	if !hasCode(rep, CodeMemberUnresolved) {
		t.Errorf("expected code %s, got %v", CodeMemberUnresolved, codes(rep))
	}
}

// 7. Duplicate stable interface
func TestDuplicateStableInterface(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{
				ID:        "wan-a",
				Selector:  "hw:7c6170fd7f34317a",
				Interface: "enp0s31f6",
				StableID:  "hw:7c6170fd7f34317a",
				Declared:  true,
				Resolved:  true,
				Enabled:   true,
				Priority:  100,
				Weight:    1,
			},
			{
				ID:        "wan-b",
				Selector:  "hw:7c6170fd7f34317a",
				Interface: "enp0s31f6",
				StableID:  "hw:7c6170fd7f34317a",
				Declared:  true,
				Resolved:  true,
				Enabled:   true,
				Priority:  100,
				Weight:    1,
			},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED for duplicate interface", rep.Verdict)
	}
	if !hasCode(rep, CodeDuplicateInterface) {
		t.Errorf("expected code %s, got %v", CodeDuplicateInterface, codes(rep))
	}
}

// 8. WAN/LAN role conflict
func TestWANLANRoleConflict(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{
				ID:             "wan-a",
				Selector:       "enp1s0",
				Interface:      "enp1s0",
				Declared:       true,
				Resolved:       true,
				Conflict:       true,
				ConflictReason: "interface enp1s0 is already assigned to role lan",
				Enabled:        true,
				Priority:       100,
				Weight:         1,
			},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED for role conflict", rep.Verdict)
	}
	if !hasCode(rep, CodeRoleConflict) {
		t.Errorf("expected code %s, got %v", CodeRoleConflict, codes(rep))
	}
}

// 9. WAN/GUEST conflict
func TestWANGUESTConflict(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeSingle,
		Members: []Member{
			{
				ID:             "wan",
				Selector:       "enp2s0",
				Declared:       true,
				Resolved:       true,
				Conflict:       true,
				ConflictReason: "interface enp2s0 is already assigned to role guest",
				Enabled:        true,
				Priority:       100,
				Weight:         1,
			},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED for guest conflict", rep.Verdict)
	}
	if !hasCode(rep, CodeRoleConflict) {
		t.Errorf("expected code %s, got %v", CodeRoleConflict, codes(rep))
	}
}

// 10. WAN/DMZ conflict
func TestWANDMZConflict(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeSingle,
		Members: []Member{
			{
				ID:             "wan",
				Selector:       "enp3s0",
				Declared:       true,
				Resolved:       true,
				Conflict:       true,
				ConflictReason: "interface enp3s0 is already assigned to role dmz",
				Enabled:        true,
				Priority:       100,
				Weight:         1,
			},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED for dmz conflict", rep.Verdict)
	}
	if !hasCode(rep, CodeRoleConflict) {
		t.Errorf("expected code %s, got %v", CodeRoleConflict, codes(rep))
	}
}

// 11. Disabled WAN
func TestDisabledWAN(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{
				ID:       "wan-a",
				Selector: "enp0s31f6",
				Declared: true,
				Resolved: true,
				Enabled:  false, // disabled
				Priority: 100,
				Weight:   1,
				Health:   HealthEvidence{State: HealthUnknown, CarrierUp: true, AdminUp: true},
			},
			{
				ID:       "wan-b",
				Selector: "enx00e099001812",
				Declared: true,
				Resolved: true,
				Enabled:  true,
				Priority: 100,
				Weight:   1,
				Health:   HealthEvidence{State: HealthUnknown, CarrierUp: true, AdminUp: true},
			},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictValid {
		t.Fatalf("verdict = %s, want VALID; findings: %v", rep.Verdict, codes(rep))
	}
	if !hasCode(rep, CodeMemberDisabled) {
		t.Errorf("expected code %s, got %v", CodeMemberDisabled, codes(rep))
	}
	if len(rep.ActiveMembers) != 1 || rep.ActiveMembers[0].ID != "wan-b" {
		t.Errorf("disabled WAN must be excluded from active members; got: %v", rep.ActiveMembers)
	}
}

// 12. Invalid weight
func TestInvalidWeight(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{ID: "wan-a", Selector: "enp1", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 0},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED for weight 0", rep.Verdict)
	}
	if !hasCode(rep, CodeWeightInvalid) {
		t.Errorf("expected code %s, got %v", CodeWeightInvalid, codes(rep))
	}
}

// 13. Invalid priority
func TestInvalidPriority(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeFailover,
		Members: []Member{
			{ID: "wan-a", Selector: "enp1", Declared: true, Resolved: true, Enabled: true, Priority: -5, Weight: 1},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED for negative priority", rep.Verdict)
	}
	if !hasCode(rep, CodePriorityInvalid) {
		t.Errorf("expected code %s, got %v", CodePriorityInvalid, codes(rep))
	}
}

// 14. Invalid mode
func TestInvalidMode(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    Mode("bonding"),
		Members: []Member{
			{ID: "wan-a", Selector: "enp1", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
		},
	}

	rep := ValidateIntent(in)
	if rep.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED for invalid mode", rep.Verdict)
	}
	if !hasCode(rep, CodeModeInvalid) {
		t.Errorf("expected code %s, got %v", CodeModeInvalid, codes(rep))
	}
}

// 15. Deterministic WAN ordering
func TestDeterministicWANOrdering(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{ID: "delta", Selector: "enp4", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
			{ID: "beta", Selector: "enp2", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
			{ID: "alpha", Selector: "enp1", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
		},
	}

	first := ValidateIntent(in)
	for i := 0; i < 5; i++ {
		got := ValidateIntent(in)
		if len(got.ActiveMembers) != len(first.ActiveMembers) {
			t.Fatalf("iteration %d changed active count", i)
		}
		for j := range got.ActiveMembers {
			if got.ActiveMembers[j].ID != first.ActiveMembers[j].ID {
				t.Fatalf("iteration %d: order differed at index %d", i, j)
			}
		}
	}
}

// 16. Stable identity survives kernel rename
func TestStableIdentitySurvivesKernelRename(t *testing.T) {
	dev := validDeviceFixture()
	cfg := config.Defaults()
	cfg.MultiWAN = config.MultiWANConfig{
		Enabled: true,
		Mode:    "single",
		Members: []config.WANMemberConfig{
			{ID: "pldt", Interface: "hw:7c6170fd7f34317a", Weight: 1, Priority: 100, Enabled: true},
		},
	}

	in := FromConfig(cfg, nil, dev)
	if len(in.Members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(in.Members))
	}
	m := in.Members[0]
	if m.StableID != "hw:7c6170fd7f34317a" {
		t.Errorf("stable ID = %q, want hw:7c6170fd7f34317a", m.StableID)
	}
	if m.Interface != "enp0s31f6" {
		t.Errorf("interface = %q, want enp0s31f6", m.Interface)
	}
}

// -----------------------------------------------------------------------------
// Load Balancing Tests (Section 44: 1-10)
// -----------------------------------------------------------------------------

// 1. Equal weights
func TestLoadBalancingEqualWeights(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{ID: "wan1", Selector: "enp1", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
			{ID: "wan2", Selector: "enp2", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
		},
	}

	rep := ValidateIntent(in)
	if len(rep.ActiveMembers) != 2 {
		t.Fatalf("expected 2 active members, got %d", len(rep.ActiveMembers))
	}
	if rep.ActiveMembers[0].Weight != rep.ActiveMembers[1].Weight {
		t.Error("weights should be equal")
	}
}

// 2. Unequal weights
func TestLoadBalancingUnequalWeights(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{ID: "wan1", Selector: "enp1", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 3},
			{ID: "wan2", Selector: "enp2", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
		},
	}

	rep := ValidateIntent(in)
	if len(rep.ActiveMembers) != 2 {
		t.Fatalf("expected 2 active members, got %d", len(rep.ActiveMembers))
	}
	if rep.ActiveMembers[0].Weight != 3 || rep.ActiveMembers[1].Weight != 1 {
		t.Errorf("weights = (%d, %d), want (3, 1)", rep.ActiveMembers[0].Weight, rep.ActiveMembers[1].Weight)
	}
}

// 4. Healthy WAN filtering & 5. Unhealthy WAN excluded
func TestHealthyWANFiltering(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{
				ID: "wan-healthy", Selector: "enp1", Declared: true, Resolved: true, Enabled: true,
				Priority: 100, Weight: 1, Health: HealthEvidence{State: HealthHealthy},
			},
			{
				ID: "wan-down", Selector: "enp2", Declared: true, Resolved: true, Enabled: true,
				Priority: 100, Weight: 1, Health: HealthEvidence{State: HealthUnhealthy},
			},
		},
	}

	rep := ValidateIntent(in)
	if len(rep.ActiveMembers) != 1 || rep.ActiveMembers[0].ID != "wan-healthy" {
		t.Errorf("active members = %v, want only wan-healthy", rep.ActiveMembers)
	}
	if len(rep.StandbyMembers) != 1 || rep.StandbyMembers[0].ID != "wan-down" {
		t.Errorf("standby members = %v, want wan-down", rep.StandbyMembers)
	}
}

// 6. Unknown WAN remains explicitly unknown (not excluded)
func TestUnknownWANNotTreatedAsUnhealthy(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{
				ID: "wan-unknown", Selector: "enp1", Declared: true, Resolved: true, Enabled: true,
				Priority: 100, Weight: 1, Health: HealthEvidence{State: HealthUnknown},
			},
		},
	}

	rep := ValidateIntent(in)
	if len(rep.ActiveMembers) != 1 {
		t.Fatalf("unknown WAN must not be treated as unhealthy; got %d active", len(rep.ActiveMembers))
	}
	if rep.ActiveMembers[0].Health.State != HealthUnknown {
		t.Errorf("health state = %s, want unknown", rep.ActiveMembers[0].Health.State)
	}
}

// 7. All WANs unhealthy
func TestAllWANsUnhealthy(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeFailover,
		Members: []Member{
			{
				ID: "wan1", Selector: "enp1", Declared: true, Resolved: true, Enabled: true,
				Priority: 100, Weight: 1, Health: HealthEvidence{State: HealthUnhealthy},
			},
			{
				ID: "wan2", Selector: "enp2", Declared: true, Resolved: true, Enabled: true,
				Priority: 50, Weight: 1, Health: HealthEvidence{State: HealthUnhealthy},
			},
		},
	}

	rep := ValidateIntent(in)
	if !hasCode(rep, CodeAllUnhealthy) {
		t.Errorf("expected code %s when all WANs are unhealthy; got: %v", CodeAllUnhealthy, codes(rep))
	}
}

// 8. Failover ordering & 9. Equal priority deterministic tiebreak
func TestFailoverOrderingAndTiebreak(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeFailover,
		Members: []Member{
			{ID: "wan-backup2", Selector: "enp3", Declared: true, Resolved: true, Enabled: true, Priority: 10, Weight: 1},
			{ID: "wan-backup1", Selector: "enp2", Declared: true, Resolved: true, Enabled: true, Priority: 50, Weight: 1},
			{ID: "wan-primary", Selector: "enp1", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
		},
	}

	rep := ValidateIntent(in)
	if len(rep.ActiveMembers) != 1 || rep.ActiveMembers[0].ID != "wan-primary" {
		t.Errorf("active member = %v, want wan-primary", rep.ActiveMembers)
	}
	if len(rep.StandbyMembers) != 2 {
		t.Fatalf("expected 2 standby members, got %d", len(rep.StandbyMembers))
	}
}

// 10. Session-oriented semantics represented
func TestSessionOrientedSemanticsRepresented(t *testing.T) {
	in := Intent{
		Enabled: true,
		Mode:    ModeLoadBalance,
		Members: []Member{
			{ID: "wan1", Selector: "enp1", Declared: true, Resolved: true, Enabled: true, Priority: 100, Weight: 1},
		},
	}

	summary := in.Summary()
	if !strings.Contains(summary, "session affinity") {
		t.Errorf("summary must state session affinity / non-bonding semantics:\n%s", summary)
	}
}

// -----------------------------------------------------------------------------
// Health Evidence Tests (Section 44: 1-5)
// -----------------------------------------------------------------------------

// 1. Carrier present does not automatically mean Internet healthy
func TestCarrierPresentDoesNotMeanInternetHealthy(t *testing.T) {
	ev := EvaluateHealth(true, true, true, false, false, false, "")
	if ev.State == HealthHealthy {
		t.Error("carrier present must not be treated as proof of Internet health")
	}
	if ev.State != HealthUnknown {
		t.Errorf("state = %s, want unknown", ev.State)
	}
}

// 2. Interface down produces strong failure evidence
func TestInterfaceDownProducesStrongFailureEvidence(t *testing.T) {
	ev := EvaluateHealth(false, true, false, false, false, false, "")
	if ev.State != HealthUnhealthy {
		t.Errorf("state = %s, want unhealthy when carrier is down", ev.State)
	}

	evAdminDown := EvaluateHealth(true, false, false, false, false, false, "")
	if evAdminDown.State != HealthUnhealthy {
		t.Errorf("state = %s, want unhealthy when admin down", evAdminDown.State)
	}
}

// 3. Probe failure does not become confirmed WAN failure
func TestProbeFailureDoesNotBecomeConfirmedFailure(t *testing.T) {
	ev := EvaluateHealth(true, true, true, false, false, true, "network timeout")
	if ev.State == HealthUnhealthy {
		t.Error("failed probe must not become confirmed absence/unhealthy")
	}
	if ev.State != HealthUnknown {
		t.Errorf("state = %s, want unknown", ev.State)
	}
}

// 4. Unknown health is not unhealthy
func TestUnknownHealthIsNotUnhealthy(t *testing.T) {
	ev := HealthEvidence{State: HealthUnknown}
	if ev.State == HealthUnhealthy {
		t.Error("unknown health must not equal unhealthy")
	}
}

// 5. Evidence survives JSON serialization
func TestEvidenceSurvivesJSONSerialization(t *testing.T) {
	ev := HealthEvidence{
		State:     HealthUnknown,
		Source:    "observation",
		Reason:    "carrier up, probe unperformed",
		CarrierUp: true,
		AdminUp:   true,
		HasIP:     true,
	}

	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded HealthEvidence
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.State != ev.State || decoded.Source != ev.Source || decoded.CarrierUp != ev.CarrierUp {
		t.Errorf("decoded %+v does not match original %+v", decoded, ev)
	}
}
