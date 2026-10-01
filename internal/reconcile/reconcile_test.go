package reconcile_test

import (
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/authority"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/reconcile"
)

var at = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func admin() authority.Principal {
	return authority.Principal{Name: "t", Role: authority.RoleAdmin}
}

func approved() authority.Evidence {
	return authority.Evidence{
		Approved: true, ApprovedBy: "a-human", BatchSize: 1, TotalGateways: 100,
	}
}

func changes(cs ...diff.Change) diff.Result {
	return diff.Result{Changes: cs, DriftCount: len(cs)}
}

// healthy is a gateway that can enumerate its kernel capabilities and has a
// firewall, so that refusals in a test are about the change and not the host.
func healthy() reconcile.Observe {
	return reconcile.Observe{
		ShapingAlgorithms: []string{"cake", "fq_codel"},
		FirewallBackend:   "nftables",
		ManagementPath:    "wan0",
		LocalNetworks:     []string{"192.168.1.0/24", "10.0.0.0/8"},
	}
}

func firewallAbsent() diff.Change {
	return diff.Change{
		ID: "firewall-absent", Kind: diff.KindDrift, Risk: diff.RiskCritical,
		Subsystem: "nftables", Field: "firewall.present",
		Current: "absent", Desired: "present",
		Reason: "the host has no firewall loaded",
	}
}

func wanLinkDown() diff.Change {
	return diff.Change{
		ID: "wan-link-state", Kind: diff.KindDrift, Risk: diff.RiskHigh,
		Subsystem: "link", Field: "wan.up",
		Current: "down", Desired: "up",
		Reason: "the uplink is down",
	}
}

func qosAlgorithm(want string) diff.Change {
	return diff.Change{
		ID: "qos-algorithm", Kind: diff.KindDrift, Risk: diff.RiskMedium,
		Subsystem: "qdisc", Field: "qos.algorithm",
		Current: "fq_codel", Desired: want,
		Reason: "the shaping algorithm differs",
	}
}

func lanAddress(cidr string) diff.Change {
	return diff.Change{
		ID: "lan-address-add", Kind: diff.KindDrift, Risk: diff.RiskHigh,
		Subsystem: "address", Field: "lan.address",
		Desired: cidr,
		Reason:  "the LAN address is missing",
	}
}

// ------------------------------------------------- the gateway can say no

// The whole point of the package. A firewall that is off cannot be turned back
// on by anything that needs the gateway to be reachable.
func TestGatewayRefusesToDisableItsFirewall(t *testing.T) {
	r := reconcile.Decide(
		authority.NewPolicy("permissive"), admin(), approved(),
		changes(firewallAbsent()), healthy(), at)

	if r.Accepted {
		t.Fatal("the gateway accepted a change that disables its firewall")
	}
	if r.Status != reconcile.StatusRefused {
		t.Errorf("Status = %s, want refused", r.Status)
	}

	var found bool
	for _, f := range r.Refusals {
		if f.Reason == reconcile.ReasonManagementPath {
			found = true
			if f.Overridable {
				t.Error("the management-path refusal was marked overridable; it is not")
			}
		}
	}
	if !found {
		t.Errorf("no management-path refusal was raised: %+v", r.Refusals)
	}
}

// Even with the floor lowered and full approval, the gateway still refuses.
// This is the property that makes a compromised control plane survivable.
func TestFirewallRefusalSurvivesAPermissivePolicyAndAnAdmin(t *testing.T) {
	p := authority.NewPolicy("hostile").
		Raise(authority.OpDisableFirewall, authority.TierAutomatic)

	r := reconcile.Decide(p, admin(),
		authority.Evidence{Approved: true, ApprovedBy: "root", BatchSize: 1, TotalGateways: 1},
		changes(firewallAbsent()), healthy(), at)

	if r.Accepted {
		t.Fatal("a permissive policy and an admin overrode the gateway's own refusal")
	}
}

// A shaping policy asking for an algorithm the kernel does not have must be
// refused rather than silently degraded: a degraded rate is better than a
// claimed rate that is not true.
func TestGatewayRefusesAnUnavailableShapingAlgorithm(t *testing.T) {
	obs := healthy()
	obs.ShapingAlgorithms = []string{"fq_codel"} // no cake on this kernel

	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		changes(qosAlgorithm("cake")), obs, at)

	if r.Accepted {
		t.Fatal("the gateway accepted a shaping algorithm its kernel does not offer")
	}

	var found bool
	for _, f := range r.Refusals {
		if f.Reason == reconcile.ReasonCapabilityUnavailable &&
			strings.Contains(f.Detail, "fq_codel") {
			found = true
		}
	}
	if !found {
		t.Errorf("no capability refusal naming what is available: %+v", r.Refusals)
	}
}

// An empty algorithm list means "could not enumerate", not "nothing available",
// and the refusal must say so rather than blaming the kernel.
func TestUnenumerableCapabilitiesAreRefusedDifferently(t *testing.T) {
	obs := healthy()
	obs.ShapingAlgorithms = nil

	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		changes(qosAlgorithm("cake")), obs, at)

	if r.Accepted {
		t.Fatal("accepted a policy the gateway cannot verify it can honour")
	}
	var detail string
	for _, f := range r.Refusals {
		if f.Reason == reconcile.ReasonCapabilityUnavailable {
			detail = f.Detail
		}
	}
	if !strings.Contains(detail, "could not enumerate") {
		t.Errorf("the refusal blames the kernel rather than the enumeration: %q", detail)
	}
}

func TestGatewayRefusesAnOverlappingLAN(t *testing.T) {
	obs := healthy()

	// 10.0.0.0/8 is already behind this host.
	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		changes(lanAddress("10.5.0.1/24")), obs, at)

	if r.Accepted {
		t.Fatal("the gateway accepted a LAN that overlaps an existing network")
	}
	if !hasReason(r, reconcile.ReasonOverlappingNetwork) {
		t.Errorf("no overlap refusal: %+v", r.Refusals)
	}

	// A genuinely disjoint network is fine.
	ok := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		changes(lanAddress("172.16.0.1/24")), obs, at)
	if !ok.Accepted {
		t.Errorf("a disjoint LAN was refused: %s", render(ok))
	}
}

// A malformed address must fail open on the comparison, not panic. A gateway
// that refuses to start because a helper could not parse a string would be a
// self-inflicted outage.
func TestMalformedAddressesDoNotPanicOrRefuse(t *testing.T) {
	for _, bad := range []string{"", "not-a-prefix", "10.0.0.0/99", "999.1.1.1/24"} {
		r := reconcile.Decide(
			authority.NewPolicy("default"), admin(), approved(),
			changes(lanAddress(bad)), healthy(), at)
		if hasReason(r, reconcile.ReasonOverlappingNetwork) {
			t.Errorf("%q was reported as overlapping; a malformed address is not a conflict", bad)
		}
	}
}

// ------------------------------------------------------- reachability

// Altering reachability is escalated but overridable: a gateway is sometimes
// genuinely moved to a new uplink, and a tool that cannot express that is a
// tool people stop using.
func TestReachabilityChangeIsEscalatedNotRefused(t *testing.T) {
	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		changes(wanLinkDown()), healthy(), at)

	if !hasReason(r, reconcile.ReasonReachability) {
		t.Fatalf("a WAN change did not escalate reachability: %+v", r.Refusals)
	}
	if r.Status != reconcile.StatusAcceptedWithRefusals {
		t.Errorf("Status = %s, want accepted-with-refusals", r.Status)
	}
	for _, f := range r.Refusals {
		if f.Reason == reconcile.ReasonReachability && !f.Overridable {
			t.Error("the reachability escalation was marked non-overridable")
		}
	}
}

// Strong approval governs reachability changes from the policy side.
func TestReachabilityChangeStillNeedsStrongApproval(t *testing.T) {
	p := authority.NewPolicy("default")
	who := authority.Principal{Name: "op", Role: authority.RoleNetworkOperator}

	r := reconcile.Decide(p, who, approved(), changes(wanLinkDown()), healthy(), at)
	if r.Accepted {
		t.Error("a network operator changed the WAN; strong approval and admin are required")
	}
}

// ------------------------------------------------------------ operations

func TestOperationForMapsRealChangeIdentifiers(t *testing.T) {
	cases := map[string]authority.Operation{
		"resolvers":             authority.OpChangeResolvers,
		"qos-absent":            authority.OpChangeQoS,
		"qos-algorithm":         authority.OpChangeQoS,
		"firewall-empty":        authority.OpAddFirewallRule,
		"firewall-absent":       authority.OpDisableFirewall,
		"default-route-add":     authority.OpChangeDefaultRoute,
		"default-route-gateway": authority.OpChangeDefaultRoute,
		"wan-name-mismatch":     authority.OpChangeWAN,
		"wan-link-state":        authority.OpChangeWAN,
		"lan-address-add":       authority.OpChangeLAN,
		"lan-link-state":        authority.OpChangeLAN,
	}

	for id, want := range cases {
		got := reconcile.OperationFor(diff.Change{ID: id})
		if got != want {
			t.Errorf("change %q mapped to %s, want %s", id, got, want)
		}
	}
}

// An unrecognised change must be treated as the most cautious operation that
// could apply, never the least demanding one.
func TestUnknownChangeMapsToTheMostCautiousOperation(t *testing.T) {
	got := reconcile.OperationFor(diff.Change{ID: "something-new"})
	if got != authority.OpUpdateSoftware {
		t.Errorf("an unrecognised change mapped to %s, want %s",
			got, authority.OpUpdateSoftware)
	}
}

// ------------------------------------------------------- unobservable is not
// a change
//
// This is the most dangerous mapping in the package, and it was a real bug.
//
// The diff reports six `*-unobservable` pending items when host inspection is
// unavailable: firewall, qos, resolvers, wan, lan, host. Mapped to write
// operations, a gateway that could not see its own firewall would tell the
// fleet "this gateway wants a firewall change" — and the fleet would push one,
// at the worst possible moment, to a device that could not see what it had.
func TestUnobservableSubsystemsAreNotReportedAsOperations(t *testing.T) {
	pending := func(id, field string) diff.Change {
		return diff.Change{
			ID: id, Kind: diff.KindPending, Risk: diff.RiskNone,
			Subsystem: "host", Field: field,
			Reason: "host inspection is unavailable on this platform",
		}
	}

	d := diff.Result{
		PendingCount: 6,
		Changes: []diff.Change{
			pending("host-unobservable", "host.inspection"),
			pending("wan-unobservable", "wan.interface"),
			pending("lan-unobservable", "lan.interface"),
			pending("firewall-unobservable", "firewall.enabled"),
			pending("qos-unobservable", "qos.enabled"),
			pending("resolvers-unobservable", "network.dns"),
		},
	}

	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(), d, healthy(), at)

	for _, op := range r.Operations {
		t.Errorf("an unobservable subsystem produced the write operation %s", op)
	}
	if r.Status != reconcile.StatusUndeterminable {
		t.Errorf("Status = %s, want undeterminable", r.Status)
	}
	if len(r.Unobservable) != 6 {
		t.Errorf("Unobservable = %v, want all six subsystems named", r.Unobservable)
	}
	if !hasReason(r, reconcile.ReasonUnobservable) {
		t.Error("no unobservable refusal was raised")
	}
}

// "Cannot see" must not be reported as "no change", which would tell a control
// plane the gateway matches the desired state.
func TestUnobservableIsDistinctFromNoChange(t *testing.T) {
	blind := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		diff.Result{Changes: []diff.Change{{
			ID: "firewall-unobservable", Kind: diff.KindPending,
			Field: "firewall.enabled",
		}}}, healthy(), at)

	converged := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		diff.Result{Converged: true}, healthy(), at)

	if blind.Status == converged.Status {
		t.Error("an unobservable gateway reports the same status as a converged one")
	}
	if converged.Status != reconcile.StatusNoChange {
		t.Errorf("a converged gateway reported %s", converged.Status)
	}
}

// An approval must not make an unreadable subsystem readable.
func TestApprovalDoesNotMakeAnUnobservableSubsystemSatisfied(t *testing.T) {
	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(),
		authority.Evidence{Approved: true, ApprovedBy: "root",
			BatchSize: 1, TotalGateways: 1},
		diff.Result{Changes: []diff.Change{{
			ID: "firewall-unobservable", Kind: diff.KindPending,
			Field: "firewall.enabled",
		}}}, healthy(), at)

	if r.Accepted {
		t.Fatal("approval turned an unobservable subsystem into an accepted change")
	}
}

// The rendered output must not read as though the gateway were asking for
// something.
func TestUnobservableRenderingDoesNotReadAsAChangeRequest(t *testing.T) {
	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		diff.Result{Changes: []diff.Change{{
			ID: "firewall-unobservable", Kind: diff.KindPending,
			Field: "firewall.enabled",
		}}}, healthy(), at)

	out := render(r)
	if !strings.Contains(out, "is not asking for anything to be changed") {
		t.Errorf("the rendering does not say that nothing is being requested:\n%s", out)
	}
	if strings.Contains(out, "Operations requested") {
		t.Errorf("the rendering lists operations for an unobservable gateway:\n%s", out)
	}
}

// A mixed change set keeps its real operations and still reports what it could
// not see.
func TestRealChangesAndUnobservableItemsCoexist(t *testing.T) {
	d := diff.Result{Changes: []diff.Change{
		{ID: "wan-link-state", Kind: diff.KindDrift, Risk: diff.RiskHigh, Field: "wan.up"},
		{ID: "firewall-unobservable", Kind: diff.KindPending, Field: "firewall.enabled"},
	}}

	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(), d, healthy(), at)

	if len(r.Operations) != 1 || r.Operations[0] != authority.OpChangeWAN {
		t.Errorf("Operations = %v, want only the WAN change", r.Operations)
	}
	if len(r.Unobservable) != 1 {
		t.Errorf("Unobservable = %v, want the firewall", r.Unobservable)
	}
}

func TestOperationsAreDeduplicatedAndSorted(t *testing.T) {
	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		changes(
			diff.Change{ID: "wan-link-state", Kind: diff.KindDrift, Field: "wan.up"},
			diff.Change{ID: "wan-name-mismatch", Kind: diff.KindDrift, Field: "wan.name"},
			diff.Change{ID: "resolvers", Kind: diff.KindDrift, Field: "dns.upstreams"},
		),
		healthy(), at)

	seen := map[authority.Operation]int{}
	for _, op := range r.Operations {
		seen[op]++
	}
	for op, n := range seen {
		if n != 1 {
			t.Errorf("operation %s appears %d times in %v", op, n, r.Operations)
		}
	}
	if len(r.Operations) != 2 {
		t.Errorf("got %v, want two operations", r.Operations)
	}
}

// ------------------------------------------------------------- outcomes

func TestNoChangesIsAcceptedAndSaysSo(t *testing.T) {
	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		diff.Result{Converged: true}, healthy(), at)

	if !r.Accepted || r.Status != reconcile.StatusNoChange {
		t.Errorf("a converged gateway reported %s accepted=%t", r.Status, r.Accepted)
	}
	if r.ChangeCount != 0 {
		t.Errorf("ChangeCount = %d for an empty change set", r.ChangeCount)
	}
}

// A refused request must be distinguishable from a permitted one with nothing to
// do. Both are "no changes were made", and conflating them is how a control
// plane reports success for something the gateway rejected.
func TestRefusedIsDistinctFromNoChange(t *testing.T) {
	refused := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		changes(firewallAbsent()), healthy(), at)

	none := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		diff.Result{Converged: true}, healthy(), at)

	if refused.Status == none.Status {
		t.Error("a refusal and a converged gateway report the same status")
	}
}

// ------------------------------------------------------------ rendering

// The gateway's reasons are printed before the approval state, because the
// gateway is the authority and an interface that leads with approval reads as
// though approval were the decision.
func TestRenderingLeadsWithTheGatewaysOwnRefusals(t *testing.T) {
	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		changes(firewallAbsent()), healthy(), at)

	out := render(r)
	refusalAt := strings.Index(out, "Why")
	opsAt := strings.Index(out, "Operations requested")

	if refusalAt < 0 || opsAt < 0 {
		t.Fatalf("expected both sections in:\n%s", out)
	}
	if refusalAt > opsAt {
		t.Error("the approval summary was printed before the gateway's own reasons")
	}
	if !strings.Contains(out, "NOT overridable") {
		t.Error("the rendering does not distinguish an overridable escalation")
	}
}

func TestRenderedRefusalNamesWhatCanBeDoneInstead(t *testing.T) {
	r := reconcile.Decide(
		authority.NewPolicy("default"), admin(), approved(),
		changes(firewallAbsent()), healthy(), at)

	out := render(r)
	if !strings.Contains(out, "a rule that") {
		t.Errorf("the refusal does not suggest the change to make instead:\n%s", out)
	}
}

func hasReason(r reconcile.Result, want reconcile.Reason) bool {
	for _, f := range r.Refusals {
		if f.Reason == want {
			return true
		}
	}
	return false
}

func render(r reconcile.Result) string { return reconcile.RenderRefusals(r) }
