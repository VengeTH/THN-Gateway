package management

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression tests for the stale-lease bug.
//
// On 2026-10-10 the console reported a laptop as ONLINE at 10.77.0.143 for
// hours after it had left the network, and reported the internet as healthy
// on a machine whose WAN was carrying no traffic. Both were assertions
// compiled into the binary rather than observations of anything.
//
// The lease tests pin the specific behaviour that caused the visible symptom:
// a dnsmasq lease row survives its device, and reading it without comparing
// the expiry column to the wall clock reports an absent device as present.

// writeLeaseFile writes raw lines to a dnsmasq lease fixture.
//
// Takes pre-formatted lines rather than typed fields, because one test writes
// deliberately malformed input and a field-typed helper would not allow it.
func writeLeaseFile(t *testing.T, dir string, lines ...string) string {
	t.Helper()
	p := filepath.Join(dir, "dnsmasq.leases")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatalf("write lease fixture: %v", err)
	}
	return p
}

// leaseLine renders one well-formed dnsmasq lease row:
//
//	<expiry-epoch> <mac> <ip> <hostname> <client-id>
func leaseLine(expiry time.Time, mac, ip, name string) string {
	return fmt.Sprintf("%d %s %s %s %s\n", expiry.Unix(), mac, ip, name, "01:"+mac)
}

// TestExpiredLeaseIsNotReportedAsOnline covers the first half of the rule: an
// expired grant is never presence, however recently the device was heard.
func TestExpiredLeaseIsNotReportedAsOnline(t *testing.T) {
	dir := t.TempDir()
	writeLeaseFile(t, dir, leaseLine(
		time.Now().Add(-8*time.Hour), "08:8f:c3:1b:9c:84", "10.77.0.143", "Venge",
	))

	devices := readLeaseFileForTest(t, dir, true) // neighbour present
	if len(devices) != 1 {
		t.Fatalf("expected the lease to still be readable, got %d devices", len(devices))
	}
	if devices[0].Online {
		t.Fatal("an expired lease was reported Online even with a live neighbour entry")
	}
}

// TestUnexpiredLeaseWithoutCorroborationIsNotOnline is the regression test for
// the symptom actually reported on 2026-10-10.
//
// The lease was valid for another seven hours — and the laptop was gone. That
// is DHCP working as designed: a lease reserves the address after the holder
// leaves. Trusting lease validity alone is what put a disconnected machine on
// a console as Online.
func TestUnexpiredLeaseWithoutCorroborationIsNotOnline(t *testing.T) {
	dir := t.TempDir()
	writeLeaseFile(t, dir, leaseLine(
		time.Now().Add(7*time.Hour), "08:8f:c3:1b:9c:84", "10.77.0.143", "Venge",
	))

	devices := readLeaseFileForTest(t, dir, false) // no neighbour entry
	if len(devices) != 1 {
		t.Fatalf("expected the lease to still be readable, got %d devices", len(devices))
	}
	if devices[0].Online {
		t.Fatal(
			"an unexpired lease with no live neighbour entry was reported Online; " +
				"a lease reserves an address after the device leaves and is not evidence of presence",
		)
	}
}

// TestUnexpiredLeaseWithCorroborationIsOnline is the other half: the fix must
// not simply mark everything offline, which would be its own kind of lie.
func TestUnexpiredLeaseWithCorroborationIsOnline(t *testing.T) {
	dir := t.TempDir()
	writeLeaseFile(t, dir, leaseLine(
		time.Now().Add(2*time.Hour), "08:8f:c3:1b:9c:84", "10.77.0.143", "Venge",
	))

	devices := readLeaseFileForTest(t, dir, true)
	if len(devices) != 1 {
		t.Fatalf("expected one device, got %d", len(devices))
	}
	if !devices[0].Online {
		t.Fatal("a valid lease with a live neighbour entry is evidence of presence and must be Online")
	}
}

// TestLeaseLastSeenIsTheExpiryNotNow guards a subtle companion bug.
//
// The original code set LastSeen to time.Now() for every lease, so an expired
// row from eight hours ago claimed to have been seen this instant. Anything
// rendering "last seen" would therefore show a moment that never happened.
func TestLeaseLastSeenIsTheExpiryNotNow(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(-8 * time.Hour).Truncate(time.Second)
	writeLeaseFile(t, dir, leaseLine(
		expiry, "08:8f:c3:1b:9c:84", "10.77.0.143", "Venge",
	))

	devices := readLeaseFileForTest(t, dir, true)
	if len(devices) != 1 {
		t.Fatalf("expected one device, got %d", len(devices))
	}

	if devices[0].LastSeen.After(time.Now()) {
		t.Fatal("LastSeen is in the future; it must be the lease expiry, not the moment of reading")
	}
	if got, want := devices[0].LastSeen.Unix(), expiry.Unix(); got != want {
		t.Fatalf("LastSeen = %d, want the lease expiry %d", got, want)
	}
}

// TestUnparseableExpiryIsSkipped covers the permissive reading.
//
// A lease whose expiry cannot be parsed cannot be compared to a clock. It
// therefore cannot be called live, and admitting it would reintroduce the
// original bug through a path the fix did not consider.
func TestUnparseableExpiryIsSkipped(t *testing.T) {
	dir := t.TempDir()
	writeLeaseFile(t, dir,
		"not-a-number 08:8f:c3:1b:9c:84 10.77.0.143 Venge 01:08:8f:c3:1b:84\n")

	if devices := readLeaseFileForTest(t, dir, true); len(devices) != 0 {
		t.Fatalf("a lease with no parseable expiry must not be admitted, got %d devices", len(devices))
	}
}

// TestMalformedLinesAreIgnored keeps a truncated or blank line from producing
// a device with an empty MAC.
func TestMalformedLinesAreIgnored(t *testing.T) {
	dir := t.TempDir()
	writeLeaseFile(t, dir,
		"\n",
		"12345 08:8f:c3:1b\n",
		leaseLine(time.Now().Add(time.Hour), "08:8f:c3:1b:9c:84", "10.77.0.150", "Laptop"),
	)

	devices := readLeaseFileForTest(t, dir, true)
	if len(devices) != 1 {
		t.Fatalf("expected exactly the one well-formed lease, got %d", len(devices))
	}
	if devices[0].IPv4 != "10.77.0.150" {
		t.Fatalf("wrong lease parsed: %+v", devices[0])
	}
}

// readLeaseFileForTest runs the production parser against a temp directory.
//
// parseDnsmasqLeases reads from fixed system paths, so the test cannot point
// it at a fixture without either a package-level variable or duplicating the
// logic — and duplicating the logic is precisely how a parser and its test
// come to disagree. The seam below is the production parser with its path
// list injected.
//
// reachable stands in for the kernel neighbour table, which is the half of
// the presence rule that cannot be manufactured on a test host.
func readLeaseFileForTest(t *testing.T, dir string, reachable bool) []ClientDevice {
	t.Helper()

	restorePaths := leasePathOverride
	restoreNeighbour := neighbourReachableOverride
	leasePathOverride = []string{filepath.Join(dir, "dnsmasq.leases")}
	neighbourReachableOverride = func(string) bool { return reachable }
	t.Cleanup(func() {
		leasePathOverride = restorePaths
		neighbourReachableOverride = restoreNeighbour
	})

	return parseDnsmasqLeases()
}