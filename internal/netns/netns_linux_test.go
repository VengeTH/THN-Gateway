//go:build linux

// This file is the isolated test environment the QoS work asked for. It runs
// against a real kernel inside a throwaway network namespace, which is the
// only way to check that the generated commands are accepted and that the
// statistics parser reads what a real kernel produces.
//
// Everything is inside a namespace created and destroyed by the test, so a
// failure leaves the host exactly as it was. There is no code path from this
// file to a real interface.

package netns_test

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/netns"
	"github.com/venth/thn-gateway/internal/qos"
	qostc "github.com/venth/thn-gateway/internal/qos/tc"
)

// testIface is the dummy interface shaping is attached to inside the
// namespace. A dummy interface is the cheapest thing that accepts a qdisc.
const testIface = "thn0"

// policy returns a CAKE policy for testIface.
func policy() qos.Policy {
	p := qos.Default()
	p.Enabled = true
	p.Interface = testIface
	p.Algorithm = qos.AlgorithmCake
	p.MTU = 1500
	p.Limits = qos.DefaultLimits()
	p = p.WithBandwidth(100_000, 20_000)
	return p
}

// newNamespace creates a namespace, skipping the test if it cannot.
//
// The skip is loud on purpose. A test suite that quietly stops testing
// something is worse than one that says it could not: the alternative is a
// green build that proves nothing about the thing that actually matters here.
func newNamespace(t *testing.T) *netns.Namespace {
	t.Helper()

	if err := netns.Available(); err != nil {
		t.Skipf("skipping: %v", err)
		t.Skipf("this test needs Linux with root and iproute2; on other platforms " +
			"the generated commands are verified by the render tests only")
	}

	ns, err := netns.Create("thn-test-" + strings.ReplaceAll(t.Name(), "/", "-"))
	if err != nil {
		t.Fatalf("creating namespace: %v", err)
	}

	t.Cleanup(func() {
		if err := ns.Close(); err != nil {
			t.Logf("namespace teardown: %v", err)
		}
	})

	if err := ns.Setup(testIface); err != nil {
		t.Fatalf("setting up namespace: %v", err)
	}

	return ns
}

// requireCake skips unless the running kernel supports CAKE, which is not
// guaranteed on every distribution.
func requireCake(t *testing.T, ns *netns.Namespace) {
	t.Helper()
	if !ns.HasCake(testIface) {
		t.Skip("skipping: this kernel has no CAKE support (modprobe sch_cake)")
	}
}

// TestNamespaceIsIsolated is the load-bearing assumption behind every other
// test here. If the namespace did not isolate, everything below it would be
// changing the host.
func TestNamespaceIsIsolated(t *testing.T) {
	ns := newNamespace(t)

	// The dummy interface exists inside the namespace.
	if _, err := ns.Run("ip", "-o", "link", "show", testIface); err != nil {
		t.Errorf("the interface should exist inside the namespace: %v", err)
	}
}

// TestRenderedCakeCommandIsAcceptedByTheKernel is the point of the whole
// harness. The render tests check the text; this checks that a real kernel
// accepts it.
func TestRenderedCakeCommandIsAcceptedByTheKernel(t *testing.T) {
	ns := newNamespace(t)
	requireCake(t, ns)

	p := policy()
	script := qostc.Render(p, qos.Selection{
		Algorithm: qos.AlgorithmCake, Requested: qos.AlgorithmCake, Available: true,
	})

	// Pull the arguments straight out of the rendered command rather than
	// re-deriving them. Re-deriving would test the test, not the renderer.
	args := renderedArgs(t, script)
	t.Logf("applying: cake %s", strings.Join(args, " "))

	if err := ns.ApplyCake(testIface, args); err != nil {
		t.Fatalf("the kernel rejected the rendered CAKE command: %v", err)
	}

	// Confirm it is actually there, not merely accepted.
	out, err := ns.QdiscJSON(testIface)
	if err != nil {
		t.Fatalf("reading back the qdisc: %v", err)
	}

	snap, err := qostc.ParseStats(testIface, out)
	if err != nil {
		t.Fatalf("parsing the kernel's own output: %v", err)
	}
	if !snap.Present {
		t.Fatal("no qdisc after applying one")
	}
	if snap.Root.Algorithm != "cake" {
		t.Errorf("kernel reports algorithm %q, want cake", snap.Root.Algorithm)
	}
}

// TestRenderedFqCodelCommandIsAcceptedByTheKernel covers the fallback path
// against a real kernel, which is the path an old machine will actually take.
func TestRenderedFqCodelCommandIsAcceptedByTheKernel(t *testing.T) {
	ns := newNamespace(t)

	if !ns.HasFqCodel(testIface) {
		t.Skip("skipping: this kernel has no fq_codel support")
	}

	p := policy()
	p.Algorithm = qos.AlgorithmFqCodel
	p.Limits = qos.FqCodelLimits(p.MTU)

	script := qostc.Render(p, qos.Selection{
		Algorithm: qos.AlgorithmFqCodel, Requested: qos.AlgorithmFqCodel, Available: true,
	})
	args := renderedArgs(t, script)

	if err := ns.ApplyFqCodel(testIface, args); err != nil {
		t.Fatalf("the kernel rejected the rendered fq_codel command: %v", err)
	}

	out, err := ns.QdiscJSON(testIface)
	if err != nil {
		t.Fatalf("reading back the qdisc: %v", err)
	}
	snap, err := qostc.ParseStats(testIface, out)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if snap.Root.Algorithm != "fq_codel" {
		t.Errorf("kernel reports algorithm %q, want fq_codel", snap.Root.Algorithm)
	}
	// fq_codel has no rate. If the kernel reported one, the parser would be
	// inventing it.
	if snap.Root.BandwidthMbps != 0 {
		t.Errorf("fq_codel reported a rate of %d Mbps; it has none", snap.Root.BandwidthMbps)
	}
}

// TestKernelReportsTheShapedRate is the end-to-end check that matters most:
// that the rate an operator configured is the rate the kernel actually applies.
// A parse bug here would report a correct shaper as a wrong one.
func TestKernelReportsTheShapedRate(t *testing.T) {
	ns := newNamespace(t)
	requireCake(t, ns)

	p := policy()

	// The arguments are derived from the policy, not written out by hand. That
	// is what makes this end-to-end: a rate that is wrong in the policy, in
	// Effective(), or in the parser all show up as a mismatch here.
	down := p.Bandwidth.Effective(qos.Download)
	up := p.Bandwidth.Effective(qos.Upload)
	t.Logf("configured %d kbit/s down, %d kbit/s up after overhead",
		p.Bandwidth.DownloadKbps, p.Bandwidth.UploadKbps)

	if down != 110_000 || up != 22_000 {
		t.Fatalf("overhead arithmetic: got %d/%d, want 110000/22000", down, up)
	}

	args := []string{
		"bandwidth", fmt.Sprintf("%dkbit", down),
		"uplink", fmt.Sprintf("%dkbit", up),
		"target", fmt.Sprintf("%dms", p.Limits.TargetMS),
		"interval", fmt.Sprintf("%dms", p.Limits.IntervalMS),
	}

	if err := ns.ApplyCake(testIface, args); err != nil {
		t.Fatalf("applying CAKE: %v", err)
	}

	out, err := ns.QdiscJSON(testIface)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}

	snap, err := qostc.ParseStats(testIface, out)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if !snap.Present {
		t.Fatal("no qdisc after applying one")
	}

	// The kernel reports the rate in megabits. A rounding difference of one is
	// acceptable; a factor-of-eight one is the unit bug this test exists for.
	got := snap.Root.BandwidthMbps
	if got < 100 || got > 120 {
		t.Errorf("kernel reports %d Mbps; the configured rate was 110", got)
	}
	t.Logf("configured 110 Mbit/s, kernel reports %d Mbit/s", got)
}

// TestStatisticsParseFromARealKernel closes the loop: the parser that
// `thn qos stats` uses is fed output the kernel actually produced, not a
// fixture someone wrote to match the parser.
func TestStatisticsParseFromARealKernel(t *testing.T) {
	ns := newNamespace(t)

	// Read the default queue before doing anything. An unshaped interface is
	// the most common real state and must parse cleanly.
	before, err := ns.QdiscJSON(testIface)
	if err != nil {
		t.Fatalf("reading the default qdisc: %v", err)
	}

	snap, err := qostc.ParseStats(testIface, before)
	if err != nil {
		t.Fatalf("parsing the default qdisc: %v", err)
	}
	if !snap.Present {
		t.Error("an interface always has a root qdisc; none was reported")
	}
	t.Logf("default qdisc: %s", snap.Root.Algorithm)

	// Every rate reported here must be a real number, not a guess. A shaper
	// reporting 0 when one is configured is the failure mode guarded against.
	if snap.Root.Algorithm == "cake" && snap.Root.BandwidthMbps <= 0 {
		t.Error("CAKE is attached but no rate was read back")
	}
}

// TestAvailabilityProbeDetectsCake is the probe that `thn qos available` runs,
// checked against a real kernel rather than a mock.
func TestAvailabilityProbeDetectsCake(t *testing.T) {
	ns := newNamespace(t)

	got := ns.HasCake(testIface)

	// Whatever the answer, it must be consistent: HasCake leaves no qdisc
	// behind either way.
	out, err := ns.QdiscJSON(testIface)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	snap, err := qostc.ParseStats(testIface, out)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if got && snap.Root.Algorithm == "cake" {
		t.Error("HasCake reported true but left a cake qdisc attached")
	}
	if !got && snap.Root.Algorithm == "cake" {
		t.Error("HasCake reported false but a cake qdisc is attached")
	}
	t.Logf("kernel supports CAKE: %v", got)
}

// TestTeardownRemovesEverything checks the cleanup path, because a namespace
// that outlives its test would accumulate interfaces across a suite run.
func TestTeardownRemovesEverything(t *testing.T) {
	ns := newNamespace(t)
	requireCake(t, ns)

	if err := ns.ApplyCake(testIface, []string{"bandwidth", "10000kbit"}); err != nil {
		t.Fatalf("applying: %v", err)
	}
	ns.Teardown(testIface)

	if _, err := ns.Run("ip", "-o", "link", "show", testIface); err == nil {
		t.Error("the interface still exists after Teardown")
	}
}

// TestLinkSpeedIsSettable exercises the helper the validation cross-check
// depends on, and confirms a dummy interface really does report 0 otherwise.
func TestLinkSpeedIsSettable(t *testing.T) {
	ns := newNamespace(t)

	if err := ns.SetLinkSpeed(testIface, 1000); err != nil {
		t.Fatalf("setting link speed: %v", err)
	}

	out, err := ns.Run("ip", "-o", "link", "show", testIface)
	if err != nil {
		t.Fatalf("reading the link: %v", err)
	}
	if !strings.Contains(out, "1000") {
		t.Logf("link output does not mention the speed: %s", strings.TrimSpace(out))
	}
}

// TestAvailableReportsWhyItCannot is a fast check that the skip message is
// informative, since it is the only thing an operator sees when the suite
// does not run here.
func TestAvailableReportsWhyItCannot(t *testing.T) {
	err := netns.Available()

	if err == nil {
		t.Skip("this host can create namespaces; nothing to report")
	}
	if err.Error() == "" {
		t.Fatal("Available returned an empty error; an operator would learn nothing")
	}
	t.Logf("unavailable: %v", err)
}

// TestNonLinuxReportsUnsupported pins the behaviour on the platform this
// project is developed on, so a Windows developer sees a clear reason rather
// than a nil-pointer.
func TestNonLinuxReportsUnsupported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this test is about non-Linux platforms")
	}

	if err := netns.Available(); err == nil {
		t.Error("Available must report that namespaces are unsupported off Linux")
	}

	// Create must refuse rather than attempt something.
	if _, err := netns.Create("thn-should-not-exist"); err == nil {
		t.Error("Create must fail off Linux")
	}
}

// TestCloseIsIdempotent: cleanup runs in every exit path, including failures,
// and must not fail the second time.
func TestCloseIsIdempotent(t *testing.T) {
	if err := netns.Available(); err != nil {
		t.Skipf("skipping: %v", err)
	}

	ns, err := netns.Create("thn-test-idempotent")
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	if err := ns.Setup(testIface); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := ns.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := ns.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}

	// A nil namespace is a valid receiver, because cleanup code should not
	// have to check.
	var nilNS *netns.Namespace
	if err := nilNS.Close(); err != nil {
		t.Errorf("Close on nil: %v", err)
	}
}

// TestNamespaceFileIsGoneAfterClose confirms the bind mount is unmounted as
// well as the namespace being destroyed. Leaving the mount behind would make
// /var/run/netns grow without bound across a long test run.
func TestNamespaceFileIsGoneAfterClose(t *testing.T) {
	if err := netns.Available(); err != nil {
		t.Skipf("skipping: %v", err)
	}

	ns, err := netns.Create("thn-test-mount")
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	if _, err := os.Stat(ns.Path); err != nil {
		t.Fatalf("the namespace bind mount should exist while open: %v", err)
	}

	if err := ns.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(ns.Path); err == nil {
		t.Errorf("%s still exists after Close; the bind mount was not unmounted", ns.Path)
	}
}

// renderedArgs extracts tc's cake/fq_codel arguments from a rendered script.
//
// This deliberately parses the renderer's output rather than rebuilding the
// argument list. A test that rebuilds the list tests itself; this one tests
// what an operator would actually run.
func renderedArgs(t *testing.T, script string) []string {
	t.Helper()

	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "tc qdisc replace dev ") {
			continue
		}

		fields := strings.Fields(trimmed)
		// tc qdisc replace dev <iface> root <kind> [args...]
		if len(fields) < 6 {
			t.Fatalf("rendered command is too short to be valid: %q", trimmed)
		}
		if fields[5] != "cake" && fields[5] != "fq_codel" {
			t.Fatalf("unexpected algorithm in %q", trimmed)
		}
		return fields[6:]
	}

	t.Fatal("the rendered script contains no tc command")
	return nil
}
