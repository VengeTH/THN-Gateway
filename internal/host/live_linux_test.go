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

	// 5. Every capability carries a known confidence and a reason. On a
	//    supported host nothing may be left "unknown" — that tier means "we
	//    did not look", and we did.
	for _, c := range AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			t.Errorf("capability %s is absent from a supported host", c)
			continue
		}
		switch s.Confidence {
		case "observed", "inferred":
		default:
			t.Errorf("capability %s has confidence %q on an inspected host", c, s.Confidence)
		}
		if s.Reason == "" {
			t.Errorf("capability %s has no reason", c)
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
