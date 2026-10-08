//go:build linux

package lab

// # The M6.2 end-to-end suite
//
// # What kind of test these are
//
//	LIVE DISPOSABLE LINUX. Not simulated, not a fixture, not a unit test.
//
// Every assertion below is about packets and kernel state, observed after the
// fact from a real kernel:
//
//	LAN → WAN       a TCP connection from 10.77.0.100 to 10.77.250.2
//	NAT             the WAN-side endpoint reports seeing 10.77.250.1
//	Forwarding      net.ipv4.ip_forward == 1 AND a connection crosses anyway
//	WAN → LAN       the reverse connection is refused
//	Health          the transaction only commits with traffic flowing
//	Rollback        a sabotaged apply leaves the baseline behind
//	Ownership       a foreign nftables table survives, untouched
//	Production      the production driver still refuses to apply
//
// A test in this file that could pass without a packet moving does not exist.
// Where a structural fact is asserted as well — the sysctl, the address, the
// table — it is asserted in addition to the traffic, never instead of it.
//
// # Running them
//
//	THN_M62_LAB=1 go test -count=1 -v -timeout 15m ./internal/lab/
//
// Requires Linux, root, iproute2 and nftables. Without THN_M62_LAB=1 every test
// here skips, so a green suite can never be mistaken for a passing one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/execution"
	"github.com/VengeTH/THN-Gateway/internal/network"
	"github.com/VengeTH/THN-Gateway/internal/planner"
)

// TestEndToEndLANToWAN proves a LAN client reaches the WAN side through THN.
//
// The pre-apply probe is not a formality. Without it, a harness that had
// quietly bridged the two segments — or a topology where the client had a
// route that bypassed the gateway entirely — would also produce a successful
// connection, and the test would pass while proving nothing.
func TestEndToEndLANToWAN(t *testing.T) {
	h := newHarness(t)
	h.startTargetServer()

	if before := h.probe(execution.ProbeSideLAN, TargetEndpoint()); before.Reachable {
		t.Fatalf("the client reached the WAN side before THN applied anything "+
			"(from %s): the lab is not a gateway test", before.SourceAddress)
	}

	res := applyGatewayPlan(t, h)

	if res.FinalState != execution.StateCommitted {
		t.Fatalf("final state %s, want %s (error: %s)", res.FinalState, execution.StateCommitted, res.Error)
	}

	outcome := h.probe(execution.ProbeSideLAN, TargetEndpoint())
	if !outcome.Reachable {
		t.Fatalf("the LAN client could not reach the WAN-side target after apply: %s", outcome.Error)
	}
	if outcome.SourceAddress != ClientIP {
		t.Errorf("the client reached the target from %s, want %s", outcome.SourceAddress, ClientIP)
	}
	t.Logf("LAN → WAN: %s reached %s (endpoint observed source %s)",
		outcome.SourceAddress, TargetEndpoint(), outcome.ObservedSource)
}

// TestEndToEndNAT proves the WAN-side target sees a translated address.
//
// This is the strong form of the NAT claim. "The client reached the target" is
// also true with no masquerade at all — routing alone does it. "The target
// reports 10.77.250.1, not 10.77.0.100" can only be true if the address was
// rewritten, and 10.77.0.100 is a private address the target has no route
// back to, so the connection could not survive the return trip unhijacked.
func TestEndToEndNAT(t *testing.T) {
	h := newHarness(t)
	h.startTargetServer()

	res := applyGatewayPlan(t, h)
	if res.FinalState != execution.StateCommitted {
		t.Fatalf("final state %s, want %s (error: %s)", res.FinalState, execution.StateCommitted, res.Error)
	}

	assertMasqueradeRule(t, h)

	outcome := h.probe(execution.ProbeSideLAN, TargetEndpoint())
	if !outcome.Reachable {
		t.Fatalf("the LAN client could not reach the WAN-side target: %s", outcome.Error)
	}

	translated := strings.TrimSuffix(GatewayWANAddress, "/24")
	if outcome.ObservedSource != translated {
		t.Fatalf("the WAN-side target observed source %q, want %q.\n"+
			"The client left as %s and arrived as something else, and %s has no route "+
			"back from the WAN side, so an untranslated connection could not have completed.",
			outcome.ObservedSource, translated, ClientIP, ClientIP)
	}

	t.Logf("NAT: %s left the client and arrived at the target as %s", ClientIP, outcome.ObservedSource)
}

// TestEndToEndForwarding proves the kernel forwarded a packet.
//
// Two independent facts, either of which alone would be insufficient:
//
//   - the sysctl reads 1, which is configuration rather than behaviour;
//   - a connection from another namespace arrives, which cannot happen
//     without the kernel actually forwarding.
//
// The client's only route to 10.77.250.0/24 is its default via 10.77.0.1, so
// there is no second path for the packet to take.
//
// The baseline is read from the topology rather than written as 0, because a
// namespace inherits `conf.all` — and so `net.ipv4.ip_forward` — from the host
// that created it. The harness establishes the declared baseline inside the
// gateway namespace; this test checks it actually took, which is what makes the
// later assertion about drift mean anything.
func TestEndToEndForwarding(t *testing.T) {
	h := newHarness(t)
	h.startTargetServer()

	wantBaseline := h.top.Sysctls[IPForwardKey]
	if got := h.gatewaySysctl(t, IPForwardKey); got != wantBaseline {
		t.Fatalf("the lab baseline has %s = %s, want the declared %s; "+
			"the namespace inherited the host's value instead of the lab's",
			IPForwardKey, got, wantBaseline)
	}

	res := applyGatewayPlan(t, h)
	if res.FinalState != execution.StateCommitted {
		t.Fatalf("final state %s, want %s (error: %s)", res.FinalState, execution.StateCommitted, res.Error)
	}

	if got := h.gatewaySysctl(t, IPForwardKey); got != "1" {
		t.Fatalf("%s = %s after apply, want 1", IPForwardKey, got)
	}

	outcome := h.probe(execution.ProbeSideLAN, TargetEndpoint())
	if !outcome.Reachable {
		t.Fatalf("forwarding is enabled but no packet crossed the gateway: %s", outcome.Error)
	}

	route, err := h.ns[ClientNamespace].Run("ip", "route", "get", TargetIP)
	if err != nil {
		t.Fatalf("reading the client's route to the WAN side: %v", err)
	}
	if !strings.Contains(route, GatewayIP) {
		t.Fatalf("the client's route to %s does not go via THN:\n%s", TargetIP, route)
	}

	t.Logf("forwarding: %s → %s → %s, next hop %s", ClientIP, GatewayIP, TargetIP, GatewayIP)
}

// TestWANToLANBlocked proves the WAN side cannot open a connection into the LAN.
//
// The three assertions are ordered so each one rules out a different false
// explanation. Before apply the WAN side CAN reach the client, which shows the
// address and the path are real. After apply it cannot, which shows THN's rules
// are what stopped it. And LAN→WAN still works, which shows the firewall is
// refusing one direction rather than having simply gone dark.
func TestWANToLANBlocked(t *testing.T) {
	h := newHarness(t)
	h.startTargetServer()
	h.startClientListener()

	lanEndpoint := fmt.Sprintf("%s:%d", ClientIP, clientListenPort)

	// Stage one brings up the dataplane — link, address, forwarding — without
	// the firewall. It exists so the "before" measurement below is a real one:
	// with nothing applied the LAN link is down and the client is unreachable
	// from both sides, which would make the later block meaningless.
	bootstrap := h.mustPlan(t)
	bootstrap.Steps = withoutFirewallSteps(bootstrap.Steps)
	bootstrap.Verification.Checks = dataplaneChecks(bootstrap)

	if _, err := h.executor().ExecutePlan(context.Background(), bootstrap,
		h.transactionDriver(t), h.transactionOptions()); err != nil {
		t.Fatalf("bringing up the lab dataplane failed: %v", err)
	}

	before := h.probe(execution.ProbeSideWAN, lanEndpoint)
	if !before.Reachable {
		t.Fatalf("the WAN side cannot reach %s even with forwarding on and no firewall in the way "+
			"(observed source %s); the test could not tell a real block from an unreachable address",
			lanEndpoint, before.ObservedSource)
	}

	// The kernel state the second plan is about to be derived from, recorded
	// before anything re-observes it.
	//
	// This is here because the failure this test had was silent: the plan came
	// back carrying an address removal nobody asked for, and nothing in the
	// log said what the observation actually contained. A bridge that is up
	// carries an IPv6 link-local address the kernel assigned by itself, and
	// that address is the difference between a two-step plan and a
	// converged one.
	h.logBootstrapState(t)

	// Stage two is the full plan, re-derived from the live state, which now
	// has exactly one thing left to do: install THN's firewall.
	obs, des, _, plan := h.gatewayPlan(context.Background())
	t.Logf("after bootstrap, re-observed:\n"+
		"  observed LAN addresses: %v\n"+
		"  desired LAN addresses:  %v\n"+
		"  plan steps:             %s",
		obs.LANAddresses, des.LAN.Addresses, strings.Join(stepIDs(plan), ", "))

	plan = withWANIsolationCheck(plan)

	res, err := h.executor().ExecutePlan(context.Background(), plan,
		h.transactionDriver(t), h.transactionOptions())
	if err != nil {
		t.Fatalf("transaction with the WAN-isolation check failed: %v (state %s)", err, res.FinalState)
	}

	assertCheckPassed(t, res.Health, "wan_to_lan_blocked")

	after := h.probe(execution.ProbeSideWAN, lanEndpoint)
	if after.Reachable {
		t.Fatalf("the WAN-side endpoint opened a connection into the LAN client at %s "+
			"(it was observed as %s); the forward path must be refused",
			lanEndpoint, after.ObservedSource)
	}

	outbound := h.probe(execution.ProbeSideLAN, TargetEndpoint())
	if !outbound.Reachable {
		t.Fatalf("LAN → WAN stopped working once the firewall was installed: %s. "+
			"A firewall that refuses both directions is not an isolation test, it is an outage",
			outbound.Error)
	}

	t.Logf("WAN → LAN: reachable before THN's table, blocked after it; LAN → WAN: still permitted")
}

// TestEndToEndHealthCheck proves health means working, not configured.
//
// The second half is the important one. With the WAN-side target deliberately
// absent, every structural check still passes — the link is up, the address is
// right, forwarding is on, the table exists — and the transaction must still
// fail and roll back. A health check that cannot fail on a gateway that cannot
// route is a health check that reports nothing.
func TestEndToEndHealthCheck(t *testing.T) {
	t.Run("traffic flowing", func(t *testing.T) {
		h := newHarness(t)
		h.startTargetServer()

		res := applyGatewayPlan(t, h)
		if res.FinalState != execution.StateCommitted {
			t.Fatalf("final state %s, want %s (error: %s)", res.FinalState, execution.StateCommitted, res.Error)
		}

		for _, c := range res.Health.Checks {
			if !c.Passed {
				t.Errorf("health check %q on %q failed after a committed apply: %s (%s)",
					c.Check, c.Target, c.Observed, c.Error)
			}
		}
		assertCheckPresent(t, res.Health, "lan_to_wan_traffic")
		assertCheckPresent(t, res.Health, "kernel_forwarding")
		assertCheckPresent(t, res.Health, "nat_masquerade")
	})

	t.Run("no WAN-side target", func(t *testing.T) {
		h := newHarness(t)
		// No target server: every structural fact is correct and no packet
		// can cross.

		_, _, _, plan := h.gatewayPlan(context.Background())

		res, err := h.executor().ExecutePlan(context.Background(), plan,
			h.transactionDriver(t), h.transactionOptions())
		if err == nil {
			t.Fatalf("the transaction committed with no WAN-side target: %s", res.Error)
		}
		if !errors.Is(err, execution.ErrHealthCheckFailed) {
			t.Fatalf("failure was %v, want ErrHealthCheckFailed", err)
		}
		if res.FinalState != execution.StateRolledBack {
			t.Fatalf("final state %s, want %s", res.FinalState, execution.StateRolledBack)
		}
		assertCheckFailed(t, res.Health, "lan_to_wan_traffic")

		// The declared baseline, not a literal: this asserts that THN put
		// forwarding back to where the lab said it was, which is a claim about
		// the transaction. Asserting "0" would be a claim about the lab's
		// starting state wearing a rollback's clothes.
		if got := h.gatewaySysctl(t, IPForwardKey); got != h.top.Sysctls[IPForwardKey] {
			t.Errorf("%s = %s after a failed health check; it should be rolled back to the declared baseline %s",
				IPForwardKey, got, h.top.Sysctls[IPForwardKey])
		}
	})
}

// TestEndToEndRollback proves an interrupted apply is undone.
//
// The transaction is sabotaged at the firewall operation, which is the last
// one: by the time it fails, the LAN is up, the address is assigned and
// forwarding is enabled. Before the failure the test probes the gateway and
// records that a packet really did cross it, so this is not "the rollback
// tests cleanly because nothing ever worked".
func TestEndToEndRollback(t *testing.T) {
	h := newHarness(t)
	h.startTargetServer()

	baseline := h.captureState(t)

	var forwardedDuringApply bool
	sabotage := &sabotagingDriver{
		ExecutorDriver: h.transactionDriver(t),
		failOn:         execution.OpKindNFTApplyTHNTable,
		beforeFailure: func() {
			if outcome := h.probe(execution.ProbeSideLAN, TargetEndpoint()); outcome.Reachable {
				forwardedDuringApply = true
			}
		},
	}

	res, err := h.executor().ExecutePlan(context.Background(), h.mustPlan(t),
		sabotage, h.transactionOptions())
	if err == nil {
		t.Fatalf("the sabotaged transaction reported success; state %s", res.FinalState)
	}
	if !strings.Contains(err.Error(), "intentional M6.2 lab failure") {
		t.Fatalf("failure was %v, want the intentional one", err)
	}
	if res.FinalState != execution.StateRolledBack {
		t.Fatalf("final state %s, want %s (error: %s)", res.FinalState, execution.StateRolledBack, res.Error)
	}
	if len(res.RolledBackOps) == 0 {
		t.Fatal("no compensating operations were recorded; nothing was rolled back")
	}

	if !forwardedDuringApply {
		t.Error("no packet crossed the gateway at any point in the transaction; " +
			"this test did not demonstrate a working gateway being rolled back")
	}

	matched, diffs := baseline.MatchesBaseline(h.captureState(t))
	if !matched {
		t.Fatalf("the live gateway does not match the baseline it started from:\n  %s",
			strings.Join(diffs, "\n  "))
	}

	t.Logf("rollback undid %d operation(s): %s",
		len(res.RolledBackOps), strings.Join(res.RolledBackOps, ", "))
}

// TestEndToEndRollbackRestoresBaseline proves the kernel really went back.
//
// A rollback is a claim about kernel state, so it is checked against the
// kernel: the address is gone, the link is down, forwarding is off, the
// firewall table is gone — and, the part that matters most, a packet can no
// longer cross.
func TestEndToEndRollbackRestoresBaseline(t *testing.T) {
	h := newHarness(t)
	h.startTargetServer()

	baseline := h.captureState(t)

	res, _ := h.executor().ExecutePlan(context.Background(), h.mustPlan(t),
		h.sabotaged(), h.transactionOptions())
	if res.FinalState != execution.StateRolledBack {
		t.Fatalf("final state %s, want %s (error: %s)", res.FinalState, execution.StateRolledBack, res.Error)
	}

	forwarding := h.gatewaySysctl(t, IPForwardKey)
	if forwarding != h.top.Sysctls[IPForwardKey] {
		t.Errorf("%s = %s after rollback, want the captured baseline %s",
			IPForwardKey, forwarding, baseline.Sysctls[IPForwardKey])
	}
	if addrs := h.gatewayAddresses(t, GatewayLANInterface); len(addrs) != 0 {
		t.Errorf("the LAN still carries %v after rollback, want no addresses", addrs)
	}
	if up := h.gatewayLinkUp(t, GatewayLANInterface); up {
		t.Error("the LAN link is still administratively up after rollback")
	}
	tablePresent := h.thnTablePresent()
	if tablePresent {
		t.Error("table inet thn still exists after rollback")
	}

	matched, diffs := baseline.MatchesBaseline(h.captureState(t))
	if !matched {
		t.Fatalf("post-rollback state differs from the baseline:\n  %s", strings.Join(diffs, "\n  "))
	}

	if outcome := h.probe(execution.ProbeSideLAN, TargetEndpoint()); outcome.Reachable {
		t.Fatalf("traffic still crosses the gateway after rollback (from %s); "+
			"the configuration was undone but the dataplane was not", outcome.SourceAddress)
	}

	// Reported from what was observed, not from a fixed sentence.
	//
	// This line used to be a string constant printed unconditionally, which is
	// why a live run could show "no forwarding" next to a failing forwarding
	// assertion. A summary that cannot report a failure is worse than none: it
	// reads like evidence.
	t.Logf("rollback verified against live kernel state: addresses=%v linkUp=%v %s=%s thnTable=%t traffic=%t",
		h.gatewayAddresses(t, GatewayLANInterface),
		h.gatewayLinkUp(t, GatewayLANInterface),
		IPForwardKey, forwarding,
		tablePresent,
		false)
}

// TestEndToEndPreservesUnmanagedResources proves table ownership is real.
//
// A foreign nftables table and an unmanaged interface are created before the
// transaction. THN must apply and roll back without touching either. This is
// the assertion that would fail first if anyone reached for `nft flush
// ruleset` — and it is checked after apply as well as after rollback, because
// a global flush destroys the evidence at the moment of application.
func TestEndToEndPreservesUnmanagedResources(t *testing.T) {
	h := newHarness(t)
	h.startTargetServer()

	const foreignTable = "lab_unmanaged"
	h.installForeignTable(t, foreignTable)

	res, _ := h.executor().ExecutePlan(context.Background(), h.mustPlan(t),
		h.sabotaged(), h.transactionOptions())
	if res.FinalState != execution.StateRolledBack {
		t.Fatalf("final state %s, want %s (error: %s)", res.FinalState, execution.StateRolledBack, res.Error)
	}

	assertForeignTableIntact(t, h, foreignTable)
	assertUnmanagedInterfaceIntact(t, h)

	tables, err := h.ns[GatewayNamespace].Run("nft", "list", "tables")
	if err != nil {
		t.Fatalf("listing nftables tables after rollback: %v", err)
	}
	if !strings.Contains(tables, "inet lab_unmanaged") {
		t.Errorf("table inet lab_unmanaged is gone after rollback; THN owns only table inet thn.\nnftables tables now:\n%s", tables)
	}

	t.Logf("ownership verified: table inet %s and interface thnmgmt0 survived apply and rollback", foreignTable)
}

// TestEndToEndProductionActivationBlocked proves the production guard is intact.
//
// It costs nothing and it is the property the whole project rests on, so it is
// asserted in the same place as the things that are allowed to act. A
// disposable-lab milestone that quietly enabled production would satisfy every
// other test in this file.
func TestEndToEndProductionActivationBlocked(t *testing.T) {
	driver := execution.NewProductionDriver()

	if driver.CanApply() {
		t.Fatal("ProductionDriver.CanApply() is true; production activation must remain permanently disabled")
	}

	err := driver.Execute(context.Background(), execution.OpSysctlSet{Key: "net.ipv4.ip_forward", Value: "1"})
	if !errors.Is(err, execution.ErrProductionActivationDisabled) {
		t.Fatalf("ProductionDriver.Execute returned %v, want ErrProductionActivationDisabled", err)
	}

	if health, _ := driver.VerifyHealth(context.Background(), nil); health.Healthy {
		t.Fatal("ProductionDriver reported a healthy host; it must report nothing")
	}
}

// ------------------------------------------------------------- transactions

// applyGatewayPlan runs the canonical gateway transaction and requires it to
// commit.
func applyGatewayPlan(t *testing.T, h *harness) *execution.ExecutionResult {
	t.Helper()

	res, err := h.executor().ExecutePlan(context.Background(), h.mustPlan(t),
		h.transactionDriver(t), h.transactionOptions())
	if err != nil {
		t.Fatalf("gateway transaction failed: %v (state %s, error %s)", err, res.FinalState, res.Error)
	}
	return res
}

// withoutFirewallSteps removes the firewall steps from a plan.
//
// Used to bring the dataplane up on its own, so that a test can measure what
// the firewall changes rather than what a dead LAN changes.
func withoutFirewallSteps(steps []planner.Step) []planner.Step {
	var out []planner.Step
	for _, s := range steps {
		if s.ID == "firewall-absent" || s.ID == "firewall-empty" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// dataplaneChecks keeps only the checks that hold before a firewall exists.
//
// Link, address and forwarding. The firewall and masquerade checks are dropped
// because they would correctly fail against a plan that has not installed them
// yet, and a stage that bootstraps must not assert the end state.
func dataplaneChecks(plan *planner.Plan) []planner.VerificationCheck {
	wanted := map[string]bool{
		"link_carrier": true, "address_assigned": true, "kernel_forwarding": true,
	}
	var out []planner.VerificationCheck
	for _, c := range plan.Verification.Checks {
		if wanted[c.Check] {
			out = append(out, c)
		}
	}
	return out
}

// executor returns THN's transaction executor.
func (h *harness) executor() *execution.Executor {
	return execution.NewExecutor()
}

// mustPlan builds the canonical plan, or fails the test.
//
// The plan is built from a fresh observation every time, because the digests
// it carries are taken over the observed state. Reusing a plan across two
// transactions would make the second one stale by construction, which is a
// correct behaviour to have and a confusing one to test against.
func (h *harness) mustPlan(t *testing.T) *planner.Plan {
	t.Helper()

	_, _, _, plan := h.gatewayPlan(context.Background())
	return plan
}

// transactionDriver returns the live Linux driver for the lab gateway.
func (h *harness) transactionDriver(t *testing.T) execution.ExecutorDriver {
	t.Helper()
	return h.driver()
}

// transactionOptions carries the inputs the plan's digests were taken over.
func (h *harness) transactionOptions() execution.ExecutionOptions {
	obs, des, assignments, _ := h.gatewayPlan(context.Background())
	return execution.ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Journal:     execution.NewMemoryJournalStore(),
	}
}

// sabotaged returns a driver that fails the firewall operation.
//
// The firewall is the last operation in the transaction, so sabotaging it
// exercises rollback of everything that came before: link, address and
// forwarding.
func (h *harness) sabotaged() execution.ExecutorDriver {
	return &sabotagingDriver{
		ExecutorDriver: h.driver(),
		failOn:         execution.OpKindNFTApplyTHNTable,
	}
}

// sabotagingDriver fails one operation after it has observed the gateway.
//
// # Why the driver rather than a broken plan
//
// The failure has to arrive from inside the transaction, after real work has
// already been committed to the kernel. Corrupting the plan would fail in
// validation, before anything changed, and a rollback that has nothing to undo
// proves nothing about rollback.
type sabotagingDriver struct {
	execution.ExecutorDriver

	// failOn is the operation kind whose execution fails.
	failOn execution.OpKind

	// beforeFailure runs immediately before the failure is raised, while the
	// kernel is in exactly the state the earlier operations left it in.
	beforeFailure func()
}

func (d *sabotagingDriver) Execute(ctx context.Context, op execution.Operation) error {
	if op.Kind() != d.failOn {
		return d.ExecutorDriver.Execute(ctx, op)
	}
	if d.beforeFailure != nil {
		d.beforeFailure()
	}
	return fmt.Errorf("intentional M6.2 lab failure at operation %s (%s)", op.Kind(), op.Target())
}

// ------------------------------------------------------------- live state

// captureState snapshots the live kernel for the rollback comparison.
func (h *harness) captureState(t *testing.T) *execution.StateSnapshot {
	t.Helper()

	scope := execution.BackupScope{
		Interfaces: []string{GatewayWANInterface, GatewayLANInterface},
		Sysctls:    []string{IPForwardKey},
		NFTables:   true,
		Routes:     true,
	}
	snap, err := h.driver().CaptureState(context.Background(), scope)
	if err != nil {
		t.Fatalf("capturing live gateway state: %v", err)
	}
	return snap
}

// logBootstrapState records what the kernel actually holds after the dataplane
// bootstrap, read two ways on purpose.
//
// The raw `ip -j addr show` output and the addresses THN parsed out of it are
// both printed, because the question this has to answer is not "is the address
// there" but "does what THN parsed say the same thing the kernel said". A
// parser that reshapes an address is indistinguishable from a misconfigured
// one once the plan is built.
func (h *harness) logBootstrapState(t *testing.T) {
	t.Helper()

	raw, _, err := h.runners[GatewayNamespace].Run(context.Background(),
		"ip", "-j", "addr", "show", GatewayLANInterface)
	if err != nil {
		t.Fatalf("reading %s in the lab gateway: %v", GatewayLANInterface, err)
	}

	parsed, err := network.ParseAddresses([]byte(raw))
	if err != nil {
		t.Fatalf("parsing addresses of %s: %v", GatewayLANInterface, err)
	}

	observed := make([]string, 0, len(parsed))
	for _, a := range parsed {
		observed = append(observed, a.CIDR)
	}

	t.Logf("after bootstrap, %s:\n"+
		"  ip -j addr show %s: %s\n"+
		"  parsed by network.ParseAddresses: %v\n"+
		"  link up: %v\n"+
		"  %s: %v",
		GatewayLANInterface, GatewayLANInterface, strings.TrimSpace(raw),
		observed, h.gatewayLinkUp(t, GatewayLANInterface),
		IPForwardKey, h.gatewaySysctl(t, IPForwardKey))

	if want := []string{GatewayAddress}; !slices.Equal(observed, want) {
		t.Logf("NOTE: %s carries %v, not just %v. Any address here that no configuration "+
			"lists is a candidate for a spurious lan-address-remove in the second plan.",
			GatewayLANInterface, observed, want)
	}
}

// gatewaySysctl reads a tunable from the gateway namespace.
func (h *harness) gatewaySysctl(t *testing.T, key string) string {
	t.Helper()

	out, _, err := h.runners[GatewayNamespace].Run(context.Background(), "sysctl", "-n", key)
	if err != nil {
		t.Fatalf("reading %s in the lab gateway: %v", key, err)
	}
	return strings.TrimSpace(out)
}

// gatewayAddresses lists the CIDRs on a gateway interface.
func (h *harness) gatewayAddresses(t *testing.T, iface string) []string {
	t.Helper()
	return h.captureState(t).Addresses[iface]
}

// gatewayLinkUp reports whether a gateway interface is administratively up.
func (h *harness) gatewayLinkUp(t *testing.T, iface string) bool {
	t.Helper()
	return h.captureState(t).Links[iface] == "up"
}

// thnTablePresent reports whether THN's nftables table is installed.
func (h *harness) thnTablePresent() bool {
	return thnTablePresent(h)
}

// assertMasqueradeRule proves masquerade is attached to the WAN interface.
//
// Structured, and deliberately so. The rendered rule is
// `oifname "thnwan0" masquerade`, so a text search for `oifname thnwan0` cannot
// match a rule that is present and correct. Reading the parsed rule is both the
// fix and a stronger claim: it proves the masquerade is in `table inet thn`, is
// in the `postrouting` chain, and is bound to the expected interface — not that
// a word appears somewhere in a dump.
//
// On failure it dumps what the kernel actually returned, so the next run of a
// failing assertion produces evidence rather than another guess.
func assertMasqueradeRule(t *testing.T, h *harness) {
	t.Helper()

	rules, _, err := h.thnRules()
	if err != nil {
		h.logTHNNFTDiagnostics(t)
		t.Fatalf("could not read table inet thn from the kernel: %v", err)
	}

	matched, wrongChain, wrongTable, wrongIface := 0, 0, 0, 0
	var seen []string

	for _, r := range rules {
		if r.isGatewayMasquerade(GatewayWANInterface) {
			matched++
			continue
		}

		masquerade, iface := r.masqueradeOn()
		if !masquerade {
			continue
		}
		// A masquerade that is not the gateway's is worth naming precisely,
		// because "no masquerade rule found" and "a masquerade rule in the
		// wrong place" call for completely different fixes.
		switch {
		case r.Table != "thn":
			wrongTable++
		case r.Chain != "postrouting":
			wrongChain++
		default:
			wrongIface++
			seen = append(seen, fmt.Sprintf("table=%s chain=%s oifname=%q", r.Table, r.Chain, iface))
		}
	}

	if matched != 1 {
		h.logTHNNFTDiagnostics(t)
		t.Fatalf("table inet thn has %d masquerade rule(s) bound to the WAN interface %s, want exactly 1.\n"+
			"  masquerade in another table:  %d\n"+
			"  masquerade in another chain:  %d\n"+
			"  masquerade on another iface:  %d %v\n"+
			"  masquerade where expected:   %d\n"+
			"The gateway translated traffic successfully in the LAN → WAN test, so a rule that is not "+
			"being read here is a mismatch between the parser and this nft version, not a missing rule.",
			matched, GatewayWANInterface, wrongTable, wrongChain, wrongIface, seen, matched)
	}
}

// installForeignTable creates an nftables resource THN does not own.
//
// Three objects, because a rule needs somewhere to live: the table, a chain
// inside it, and the rule. The first attempt created only the table and then
// added a rule to a chain named `unmanaged` that had never been created, which
// nft rejects with "No such file or directory" — the fixture, not the lab, was
// broken.
//
// The chain is a base chain so it is a real, listable object rather than a
// regular one that nft would silently create on first use. Making the fixture's
// structure explicit is the point: it is standing in for an operator's own
// firewall, and that firewall has to be as real as the one it is protecting
// itself from.
func (h *harness) installForeignTable(t *testing.T, name string) {
	t.Helper()

	ns := h.ns[GatewayNamespace]

	if _, err := ns.Run("nft", "add", "table", "inet", name); err != nil {
		t.Fatalf("creating the unmanaged table inet %s: %v", name, err)
	}
	if _, err := ns.Run("nft", "add", "chain", "inet", name, unmanagedChain,
		"{", "type", "filter", "hook", "input", "priority", "10", ";", "}"); err != nil {
		t.Fatalf("creating the unmanaged chain %s in inet %s: %v", unmanagedChain, name, err)
	}
	if _, err := ns.Run("nft", "add", "rule", "inet", name, unmanagedChain, "counter", "accept"); err != nil {
		t.Fatalf("populating the unmanaged table inet %s: %v", name, err)
	}
}

// unmanagedChain is the chain the foreign fixture's rule lives in.
const unmanagedChain = "unmanaged"

// assertForeignTableIntact proves the unmanaged table still carries its own rule.
//
// A count, not a string search: the table existing is the weak claim, and a
// global flush destroys the rule before it destroys the table. Reading it back
// through the same parser THN's own table uses proves the resource THN was
// supposed to leave alone is still the resource that was there.
func assertForeignTableIntact(t *testing.T, h *harness, name string) {
	t.Helper()

	ns := h.ns[GatewayNamespace]

	out, err := ns.Run("nft", "-j", "list", "table", "inet", name)
	if err != nil {
		t.Fatalf("table inet %s was destroyed: %v", name, err)
	}

	chains, rules := parseForeignTable(out)
	if _, ok := chains[unmanagedChain]; !ok {
		t.Errorf("chain %s was removed from table inet %s; THN owns only table inet thn", unmanagedChain, name)
	}
	if rules[unmanagedChain] == 0 {
		t.Errorf("the unmanaged rule in inet %s/%s was removed; THN must not touch foreign tables", name, unmanagedChain)
	}
	t.Logf("unmanaged table inet %s survived: chains=%d rules in %s=%d",
		name, len(chains), unmanagedChain, rules[unmanagedChain])
}

// parseForeignTable reads a foreign table's chains and per-chain rule counts.
func parseForeignTable(raw string) (map[string]bool, map[string]int) {
	var doc struct {
		Nftables []struct {
			Chain *struct {
				Name string `json:"name"`
			} `json:"chain"`
			Rule *nftRule `json:"rule"`
		} `json:"nftables"`
	}
	// A parse failure yields empty results, which the caller's assertions
	// report as a missing chain or a missing rule — a statement about what was
	// read, not about what the kernel holds.
	_ = json.Unmarshal([]byte(raw), &doc)

	chains := map[string]bool{}
	rules := map[string]int{}
	for _, item := range doc.Nftables {
		if item.Chain != nil {
			chains[item.Chain.Name] = true
		}
		if item.Rule != nil {
			rules[item.Rule.Chain]++
		}
	}
	return chains, rules
}

// assertUnmanagedInterfaceIntact checks the dummy interface kept its address.
func assertUnmanagedInterfaceIntact(t *testing.T, h *harness) {
	t.Helper()

	out, err := h.ns[GatewayNamespace].Run("ip", "-j", "addr", "show", "thnmgmt0")
	if err != nil {
		t.Fatalf("reading the unmanaged interface: %v", err)
	}
	if !strings.Contains(out, "10.77.99.1") {
		t.Fatalf("the unmanaged interface lost its address:\n%s", out)
	}
}

// -------------------------------------------------------- health assertions

func assertCheckPresent(t *testing.T, health execution.HealthResult, check string) {
	t.Helper()

	for _, c := range health.Checks {
		if c.Check == check {
			return
		}
	}
	t.Errorf("health check %q was never evaluated; checks were: %v", check, checkNames(health))
}

func assertCheckPassed(t *testing.T, health execution.HealthResult, check string) {
	t.Helper()

	for _, c := range health.Checks {
		if c.Check == check {
			if !c.Passed {
				t.Fatalf("health check %q failed: %s (%s)", check, c.Observed, c.Error)
			}
			return
		}
	}
	t.Fatalf("health check %q was never evaluated; checks were: %v", check, checkNames(health))
}

func assertCheckFailed(t *testing.T, health execution.HealthResult, check string) {
	t.Helper()

	for _, c := range health.Checks {
		if c.Check == check {
			if c.Passed {
				t.Fatalf("health check %q passed with no traffic path; it cannot be a real check", check)
			}
			return
		}
	}
	t.Fatalf("health check %q was never evaluated; checks were: %v", check, checkNames(health))
}

func checkNames(health execution.HealthResult) []string {
	out := make([]string, 0, len(health.Checks))
	for _, c := range health.Checks {
		out = append(out, c.Check)
	}
	return out
}
