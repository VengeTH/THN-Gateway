//go:build linux

package host

// The one test in the repository that touches a real machine.
//
// # Why this file exists
//
// Every other discovery test is driven by a fixture. A fixture proves that the
// translation is correct for the fixture, and the fixture was written by the
// same person who wrote the translation — so it cannot prove that a real
// kernel emits the fields the parser reads.
//
// That gap is exactly where this milestone's risk lives. The classification
// rule depends on `linkinfo.info_kind`, `link_type` and a `wireless` object
// actually being present in `ip -j -d link show` output. If iproute2 emits
// something different on the gateway than on a laptop, THN finds out here and
// not in production.
//
// # It is read-only, and that is structural
//
// This test calls Discover, which calls network.Inspector.Inspect. That runs
// `ip -j -d link show`, `ip -j addr show`, `ip -j route show`, `ip -j neigh
// show` and reads sysctls — all through internal/guard, whose allowlist
// contains inspection verbs only and fails closed on anything else. There is
// no code path from this test to a mutation, and adding one would break
// TestRepoContainsNoUnguardedExec.
//
// # It skips rather than lies
//
// On a machine with no `ip`, or a container with no network namespace worth
// looking at, this skips with a stated reason. It never reports a pass it did
// not achieve, because "the integration test passed" must mean something.

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestLiveDiscoveryOnLinux runs the real inspector against this machine.
//
// It asserts INVARIANTS, not values. It does not check that a particular NIC
// exists — the suite must pass on any Linux host, and a test that required
// particular hardware would be exactly the device-coupling this product is
// being built to remove.
func TestLiveDiscoveryOnLinux(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("`ip` is not on PATH; the read-only inspector cannot run here")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	d, err := NewDiscovery().DiscoverContext(ctx)
	if err != nil {
		t.Fatalf("live discovery: %v", err)
	}

	if !d.Supported {
		t.Skipf("this host reports itself unsupported: %v", d.Diagnostics)
	}

	if len(d.Interfaces) == 0 {
		t.Fatalf("a supported Linux host reported no interfaces; "+
			"the observer reported diagnostics: %v", d.Diagnostics)
	}

	// Every interface on a running Linux host has at least the loopback.
	sawLoopback := false
	for _, i := range d.Interfaces {
		if i.Kind == KindLoopback {
			sawLoopback = true
		}
	}

	t.Logf("live host: %s/%s, %d interfaces", d.OS, d.Arch, len(d.Interfaces))
	for _, i := range d.Interfaces {
		t.Logf("  %-16s kind=%-9s physical=%-5v admin=%-5v link=%-5v speed=%-6d assignable=%-5v id=%s (%s)",
			i.SystemName, i.Kind, i.Physical, i.AdminUp, i.LinkUp, i.SpeedMbps, i.Assignable, i.ID, i.IDKind)
	}

	// ---- Invariants that must hold on ANY Linux host ----

	// 1. Discovery assigns nothing. Ever.
	for _, i := range d.Interfaces {
		if i.Role != RoleUnassigned {
			t.Errorf("%s was given role %q by discovery", i.SystemName, i.Role)
		}
	}

	// 2. Every interface has an identity, and it is not the kernel name.
	for _, i := range d.Interfaces {
		if i.ID == "" {
			t.Errorf("%s has no identity", i.SystemName)
		}
		if i.ID == i.SystemName {
			t.Errorf("%s: the identity is the kernel name", i.SystemName)
		}
	}

	// 3. Identities are unique. A collision means two distinct links are
	//    indistinguishable to every selector-based consumer.
	seen := map[string]string{}
	for _, i := range d.Interfaces {
		if prev, dup := seen[i.ID]; dup {
			t.Errorf("%s and %s share identity %s", prev, i.SystemName, i.ID)
		}
		seen[i.ID] = i.SystemName
	}

	// 4. Loopback is never physical and never assignable.
	if sawLoopback {
		for _, i := range d.Interfaces {
			if i.Kind != KindLoopback {
				continue
			}
			if i.Physical {
				t.Errorf("%s is loopback and was reported as physical", i.SystemName)
			}
			if i.Assignable {
				t.Errorf("%s is loopback and was offered as a role candidate", i.SystemName)
			}
		}
	}

	// 5. Every capability carries a reason, and every `unknown` carries the
	//    observation that produced it.
	//
	//    # What this used to assert, and why it was wrong
	//
	//    The previous version required every capability on a supported host to
	//    be `observed` or `inferred`, on the reasoning that `unknown` "means we
	//    did not look, and we did". That premise is false, and it failed on
	//    every unprivileged host.
	//
	//    `unknown` has three legitimate sources, and only the third means "we
	//    did not look":
	//
	//      - the probe failed      nft is installed but the query was refused
	//      - no evidence exists    CAKE, and nothing can establish it without
	//                              mutating the host
	//      - nobody looked         a gap in THN, and the only real fault
	//
	//    On a host running this suite as an ordinary user, `nft` and `tc` are
	//    present and unqueryable, so firewall, nftables and cake are all
	//    legitimately `unknown`. The observation was right and the assertion
	//    was wrong — it passed only when the suite happened to run with
	//    CAP_NET_ADMIN.
	//
	//    # What is asserted instead
	//
	//    The real invariant is causal, and it is STRICTLY stronger than the
	//    proxy it replaces: a capability's confidence must follow from the
	//    observation that decided it, in the right direction, every time. The
	//    old test could not detect a capability that was `observed` when its
	//    probe had failed — which is the failure mode that actually matters.
	for _, c := range AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			t.Errorf("capability %s is absent from a supported host", c)
			continue
		}
		if s.Reason == "" {
			t.Errorf("capability %s has no reason", c)
		}
	}

	// 5a. No unexplained unknown. This is the assertion the old version was
	//     reaching for, stated correctly: an unknown that does not name the
	//     observation behind it is a gap in THN, not a fact about the host.
	for _, c := range d.UnknownCapabilitiesExplainThemselves() {
		ev := d.EvidenceFor(c)
		t.Errorf("capability %s is unknown from source %q with no probe record; "+
			"reason given was %q", c, ev.Source, ev.Reason)
	}

	// 5b. Confidence follows the observation, in the direction that is safe.
	//
	//     A capability whose source probe produced NOTHING USABLE must never
	//     claim observed. This is the false-confidence direction — a gateway
	//     reporting "firewall: available, observed" because a query it never
	//     completed was scored as a successful absence — and it is the reason
	//     the old assertion was worth replacing rather than deleting.
	//
	//     tool_unavailable is deliberately NOT in that set: a tool confirmed
	//     absent has been established as absent, which is a finding rather
	//     than a gap, and treating it as undetermined would make a minimal
	//     host indistinguishable from an unexamined one.
	for _, c := range d.FalseConfidenceCapabilities() {
		ev := d.EvidenceFor(c)
		t.Errorf("capability %s claims confidence %q while its %s probe ended %s at stage %s; "+
			"a probe that did not reach a conclusion cannot establish a capability. reason: %q",
			c, ev.Confidence, ev.Source, ev.Probe.Outcome, ev.Probe.Stage, ev.Reason)
	}

	// 5c. A tool that was found and queried successfully is classified
	//     observed. The mirror of 5b, and the one that catches the bug this
	//     milestone exists to fix: an authoritative observation being dropped
	//     somewhere between the probe and the capability table.
	if d.NFTables.QuerySucceeded {
		s := d.Capabilities[CapNFTables]
		if s.Confidence != ConfidenceObserved {
			t.Errorf("nftables answered a query (probe outcome %q) but the capability is %q; "+
				"a successful observation was not carried into the capability table",
				d.NFTables.Probe.Outcome, s.Confidence)
		}
		fw := d.Capabilities[CapFirewall]
		if fw.Confidence != ConfidenceObserved {
			t.Errorf("firewall is derived from nftables, which was observed, but is %q", fw.Confidence)
		}
	}
	if d.TrafficControl.QuerySucceeded {
		s := d.Capabilities[CapTC]
		if s.Confidence != ConfidenceObserved {
			t.Errorf("tc answered a query (probe outcome %q) but the capability is %q",
				d.TrafficControl.Probe.Outcome, s.Confidence)
		}
	}

	// 5d. CAKE stays semantically distinct from tc.
	//
	//     "tc worked and found no CAKE" must never become "CAKE unavailable
	//     because tc failed". Those are different facts with different
	//     consequences, and collapsing them would either report a host with a
	//     working tc as broken, or load sch_cake to find out.
	if d.TrafficControl.QuerySucceeded && !d.TrafficControl.CakeObserved {
		cake := d.Capabilities[CapCake]
		if cake.Confidence != ConfidenceUnknown {
			t.Errorf("tc succeeded with no CAKE discipline attached, so CAKE must be "+
				"unknown; it is %q. THN cannot establish CAKE without attaching a "+
				"discipline, which would mutate the host", cake.Confidence)
		}
		if cake.Available {
			t.Error("CAKE was reported available with no CAKE discipline observed")
		}
	}

	// 5e. Every probe that did not reach a conclusion names a stage and a
	//     detail, so a live-host failure is diagnosable without rerunning
	//     anything.
	for _, p := range d.Probes {
		if p.Outcome.OK() {
			continue
		}
		if p.Stage == "" {
			t.Errorf("probe %s/%s ended %q with no stage recorded",
				p.Subsystem, p.Operation, p.Outcome)
		}
		if p.Detail == "" {
			t.Errorf("probe %s/%s ended %q with no explanation",
				p.Subsystem, p.Operation, p.Outcome)
		}
	}

	// Log the evidence so a failure on the real gateway says what it saw.
	// Read-only, and it is the difference between "the suite failed" and
	// "the suite failed because nft exited 1 with EPERM".
	for _, c := range AllCapabilities() {
		ev := d.EvidenceFor(c)
		if ev.Confidence == ConfidenceObserved {
			continue
		}
		t.Logf("  capability %-18s available=%-5v %-9s source=%-16s probe=%s/%s stage=%s outcome=%s",
			c, ev.Available, ev.Confidence, ev.Source,
			ev.Probe.Subsystem, ev.Probe.Operation, ev.Probe.Stage, ev.Probe.Outcome)
		if ev.Probe.Reason != "" {
			t.Logf("      cause: %s", ev.Probe.Reason)
		}
	}

	// 6. A wireless capability may only be claimed where a radio was seen.
	//    This is the assertion that would catch the model falling back to
	//    "Linux supports wireless" on a machine with no radio.
	client, _ := d.Capabilities[CapWirelessClient]
	ap, _ := d.Capabilities[CapWirelessAP]

	sawWireless := false
	for _, i := range d.Interfaces {
		if i.Kind == KindWireless {
			sawWireless = true
		}
	}
	if !sawWireless && (client.Available || ap.Available) {
		t.Error("a wireless capability was claimed on a host with no wireless interface")
	}

	// 7. Link speeds are observed or absent, never invented.
	for _, i := range d.Interfaces {
		if i.SpeedMbps < 0 {
			t.Errorf("%s reported a negative speed of %d", i.SystemName, i.SpeedMbps)
		}
	}
}

// TestLiveDiscoveryIsRepeatable checks that two observations of the same
// machine agree.
//
// It does not require them to be identical — a DHCP lease can change between
// two reads, and that is legitimate. It requires the HARDWARE to be the same,
// because an identity that changes between two runs of a read-only command is
// not an identity.
func TestLiveDiscoveryIsRepeatable(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("`ip` is not on PATH; the read-only inspector cannot run here")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first, err := NewDiscovery().DiscoverContext(ctx)
	if err != nil || !first.Supported {
		t.Skip("this host cannot be inspected")
	}

	second, err := NewDiscovery().DiscoverContext(ctx)
	if err != nil {
		t.Fatalf("second live discovery: %v", err)
	}

	if len(first.Interfaces) != len(second.Interfaces) {
		t.Errorf("two consecutive observations found %d and %d interfaces",
			len(first.Interfaces), len(second.Interfaces))
		return
	}

	byID := make(map[string]Interface, len(second.Interfaces))
	for _, i := range second.Interfaces {
		byID[i.ID] = i
	}
	for _, i := range first.Interfaces {
		got, ok := byID[i.ID]
		if !ok {
			t.Errorf("%s (%s) vanished between two observations", i.SystemName, i.ID)
			continue
		}
		if got.Kind != i.Kind || got.Physical != i.Physical {
			t.Errorf("%s: classification changed between observations: (%s,%v) -> (%s,%v)",
				i.SystemName, i.Kind, i.Physical, got.Kind, got.Physical)
		}
	}
}

// TestLiveDiscoveryLeavesTheNetworkAlone asserts the property this milestone
// exists to guarantee, from the outside.
//
// It records the interface set and the routing table before and after a
// discovery, and requires them to be identical. It cannot prove nothing was
// changed — a change and its reversal would pass — but it does catch the
// realistic failure, which is a discovery path that touches something.
//
// It is here, on Linux, because it is the only place a real network exists.
func TestLiveDiscoveryLeavesTheNetworkAlone(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("`ip` is not on PATH; the read-only inspector cannot run here")
	}

	before, err := exec.Command("ip", "-j", "link", "show").Output()
	if err != nil {
		t.Skipf("could not read links directly: %v", err)
	}
	routesBefore, err := exec.Command("ip", "-j", "route", "show").Output()
	if err != nil {
		t.Skipf("could not read routes directly: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := NewDiscovery().DiscoverContext(ctx); err != nil {
		t.Skipf("discovery did not run here: %v", err)
	}

	after, err := exec.Command("ip", "-j", "link", "show").Output()
	if err != nil {
		t.Fatalf("could not read links after discovery: %v", err)
	}
	routesAfter, err := exec.Command("ip", "-j", "route", "show").Output()
	if err != nil {
		t.Fatalf("could not read routes after discovery: %v", err)
	}

	if string(before) != string(after) {
		t.Error("the interface set changed across a discovery run")
	}
	if string(routesBefore) != string(routesAfter) {
		t.Error("the routing table changed across a discovery run")
	}
}
