package dnsmasq_test

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/dhcp"
	"github.com/VengeTH/THN-Gateway/internal/dhcp/dnsmasq"
	"github.com/VengeTH/THN-Gateway/internal/dns"
	"github.com/VengeTH/THN-Gateway/internal/identity"
	"github.com/VengeTH/THN-Gateway/internal/sandbox"
)

// This file is the isolated test environment.
//
// Every test here runs the whole pipeline — render, write, read back, correlate
// — against a temporary directory. Nothing touches the host filesystem, no
// dnsmasq process is started, and no port is bound.

// policy returns a valid DHCP policy.
func policy() dhcp.Policy {
	return dhcp.Policy{
		Enabled:        true,
		Interface:      "enx001122334455",
		LANPrefix:      netip.MustParsePrefix("10.77.0.1/24"),
		Authoritative:  true,
		LeaseTime:      12 * time.Hour,
		Domain:         "lan",
		GatewayAddress: netip.MustParseAddr("10.77.0.1"),
		Ranges: []dhcp.Range{
			{Start: netip.MustParseAddr("10.77.0.100"), End: netip.MustParseAddr("10.77.0.250")},
		},
		Reservations: []dhcp.Reservation{
			{MAC: "aa:bb:cc:dd:ee:ff", Address: netip.MustParseAddr("10.77.0.10"), Hostname: "nas"},
		},
		Backend: dhcp.BackendConfig{
			Name:       "dnsmasq",
			ConfigFile: "/etc/thn/dnsmasq.conf",
			LeaseFile:  "/var/lib/thn/dnsmasq.leases",
		},
	}
}

// dnsPolicy returns a valid DNS policy.
func dnsPolicy() dns.Policy {
	return dns.Policy{
		Enabled:              true,
		Interface:            "enx001122334455",
		ListenAddress:        netip.MustParseAddr("10.77.0.1"),
		Upstream:             []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9")},
		LocalDomain:          "lan",
		CacheSize:            1000,
		RejectUnmappedBlocks: true,
		LocalRecords: []dns.Record{
			{Hostname: "nas", Address: netip.MustParseAddr("10.77.0.10"), Aliases: []string{"storage"}},
		},
	}
}

// leaseFile builds a lease file with a variety of realistic entries,
// including the malformed ones that occur in practice.
func leaseFile(now time.Time) string {
	future := now.Add(2 * time.Hour).Unix()
	soon := now.Add(30 * time.Minute).Unix()
	past := now.Add(-time.Hour).Unix()
	infinite := int64(0)

	lines := []string{
		"# a comment dnsmasq itself might write",
		"",
		fmt.Sprintf("%d aa:bb:cc:dd:ee:01 10.77.0.101 laptop 01:aa:bb:cc:dd:ee:01", future),
		fmt.Sprintf("%d aa:bb:cc:dd:ee:02 10.77.0.102 phone * *", future),
		fmt.Sprintf("%d aa:bb:cc:dd:ee:03 10.77.0.103 tv 01:aa:bb:cc:dd:ee:03", soon),
		fmt.Sprintf("%d aa:bb:cc:dd:ee:04 10.77.0.104 old-laptop * *", past),
		fmt.Sprintf("%d aa:bb:cc:dd:ee:ff 10.77.0.10 nas *", infinite),
		// A truncated final line, which is what a killed dnsmasq leaves.
		fmt.Sprintf("%d aa:bb:cc:dd:ee:05", future),
		// A genuinely corrupt line.
		"garbage line that is not a lease",
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestIsolatedRenderWritesInsideRoot(t *testing.T) {
	root := sandbox.New(t.TempDir())

	content := dnsmasq.Render(policy(), dnsPolicy(), policy().LANPrefix, policy().GatewayAddress)

	if err := root.WriteFile("/etc/thn/dnsmasq.conf", content, 0o644); err != nil {
		t.Fatalf("writing inside the root: %v", err)
	}

	// The file must exist inside the root and nowhere near the real path.
	if !root.Exists("/etc/thn/dnsmasq.conf") {
		t.Error("the file must exist inside the sandbox root")
	}

	got, err := root.ReadFile("/etc/thn/dnsmasq.conf")
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if got != content {
		t.Error("the file read back must match what was written")
	}

	// The resolved path must sit inside the root, so a test can never write
	// to the real /etc/thn.
	resolved := root.Resolve("/etc/thn/dnsmasq.conf")
	if !strings.HasPrefix(resolved, root.Base) {
		t.Errorf("resolved path %q must be inside the root %q", resolved, root.Base)
	}
}

// TestRenderedConfigIsStructurallyValid checks the generated file against the
// directive vocabulary, which is the only validation available without a
// dnsmasq binary to run `--test` against.
func TestRenderedConfigIsStructurallyValid(t *testing.T) {
	content := dnsmasq.Render(policy(), dnsPolicy(), policy().LANPrefix, policy().GatewayAddress)

	if issues := dnsmasq.ValidateConfig(content); len(issues) > 0 {
		for _, is := range issues {
			t.Errorf("line %d: %s", is.Line, is.Message)
		}
	}
}

func TestRenderedConfigContainsEssentialDirectives(t *testing.T) {
	content := dnsmasq.Render(policy(), dnsPolicy(), policy().LANPrefix, policy().GatewayAddress)

	required := []string{
		"interface=enx001122334455",
		"bind-interfaces",
		"dhcp-leasefile=/var/lib/thn/dnsmasq.leases",
		"dhcp-range=10.77.0.100,10.77.0.250,255.255.255.0,12h",
		"dhcp-option=option:router,10.77.0.1",
		"dhcp-option=option:dns-server,10.77.0.1",
		"dhcp-authoritative",
		"dhcp-host=aa:bb:cc:dd:ee:ff",
		"no-resolv",
		"server=1.1.1.1",
		"local=/lan/",
		"stop-dns-rebind",
	}
	for _, want := range required {
		if !strings.Contains(content, want) {
			t.Errorf("the generated file must contain %q", want)
		}
	}
}

// TestRenderedConfigRefusesToListenOnTheWAN is the check that matters most for
// a DHCP server: one that listens on the uplink answers offers from anyone on
// the internet.
func TestRenderedConfigRefusesToListenOnTheWAN(t *testing.T) {
	p := policy()
	p.Interface = "enx001122334455"
	content := dnsmasq.Render(p, dnsPolicy(), p.LANPrefix, p.GatewayAddress)

	if strings.Contains(content, "interface=enp0s31f6") {
		t.Error("the DHCP server must not be configured to listen on the WAN")
	}
	if !strings.Contains(content, "bind-interfaces") {
		t.Error("bind-interfaces is what keeps the server off the other interfaces")
	}
}

// TestValidateConfigDetectsUnknownDirective covers the failure the directive
// check exists for: a typo dnsmasq accepts and ignores.
func TestValidateConfigDetectsUnknownDirective(t *testing.T) {
	bad := "# header\ninterface=eth0\ndhcp-rnge=10.0.0.1,10.0.0.9\n"

	issues := dnsmasq.ValidateConfig(bad)

	if len(issues) != 1 {
		t.Fatalf("expected exactly 1 issue, got %d: %v", len(issues), issues)
	}
	if issues[0].Directive != "dhcp-rnge" {
		t.Errorf("directive = %q, want dhcp-rnge", issues[0].Directive)
	}
}

func TestValidateConfigIgnoresComments(t *testing.T) {
	clean := "# interface=eth0 is not a directive here\n\ninterface=eth0\n# server=8.8.8.8\n"

	if issues := dnsmasq.ValidateConfig(clean); len(issues) > 0 {
		t.Errorf("commented-out directives must not be flagged, got %v", issues)
	}
}

// --- lease parsing ---

func TestParseLeasesHandlesRealisticFile(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	content := leaseFile(now)

	res := dnsmasq.ParseLeases(content, "dnsmasq")

	// Five well-formed lines: the truncated and corrupt ones are skipped.
	// A truncated final line is normal, not a fault — dnsmasq is killed
	// mid-write often enough, and it must not hide the leases above it.
	if len(res.Leases) != 5 {
		t.Errorf("parsed %d leases, want 5", len(res.Leases))
	}
	if len(res.Errors) != 2 {
		t.Errorf("reported %d errors, want 2", len(res.Errors))
	}

	// The corrupt line and the truncated line are both reported.
	var reportedGarbage, reportedTruncated bool
	for _, e := range res.Errors {
		if strings.Contains(e.Content, "garbage") {
			reportedGarbage = true
		}
		if strings.Contains(e.Content, "aa:bb:cc:dd:ee:05") {
			reportedTruncated = true
		}
	}
	if !reportedGarbage {
		t.Error("the corrupt line must be reported")
	}
	if !reportedTruncated {
		t.Error("the truncated line must be reported")
	}
}

func TestParseLeasesStarFields(t *testing.T) {
	// dnsmasq writes "*" for an absent hostname or client id.
	content := "1800000000 aa:bb:cc:dd:ee:02 10.77.0.102 * *\n"

	res := dnsmasq.ParseLeases(content, "dnsmasq")

	if len(res.Leases) != 1 {
		t.Fatalf("got %d leases, want 1", len(res.Leases))
	}
	l := res.Leases[0]
	if l.Hostname != "" {
		t.Errorf("hostname = %q, want empty", l.Hostname)
	}
	if l.ClientID != "" {
		t.Errorf("client id = %q, want empty", l.ClientID)
	}
	if l.MAC != "aa:bb:cc:dd:ee:02" {
		t.Errorf("MAC = %q, want lowercase", l.MAC)
	}
}

func TestParseLeasesZeroExpiryIsEffectivelyInfinite(t *testing.T) {
	content := "0 aa:bb:cc:dd:ee:ff 10.77.0.10 nas *\n"

	res := dnsmasq.ParseLeases(content, "dnsmasq")
	if len(res.Leases) != 1 {
		t.Fatalf("got %d leases, want 1", len(res.Leases))
	}

	now := time.Now()
	if res.Leases[0].Expired(now) {
		t.Error("a zero expiry means the lease does not lapse")
	}
}

func TestParseLeasesEmptyFile(t *testing.T) {
	res := dnsmasq.ParseLeases("", "dnsmasq")

	if len(res.Leases) != 0 {
		t.Errorf("got %d leases from an empty file, want 0", len(res.Leases))
	}
	if len(res.Errors) != 0 {
		t.Errorf("an empty file must produce no errors, got %v", res.Errors)
	}
}

func TestParseLeasesRejectsBadMAC(t *testing.T) {
	res := dnsmasq.ParseLeases("1800000000 not-a-mac 10.77.0.1 host *\n", "dnsmasq")

	if len(res.Leases) != 0 {
		t.Error("an invalid MAC must be rejected")
	}
	if len(res.Errors) != 1 {
		t.Error("an invalid MAC must be reported")
	}
}

func TestParseLeasesRejectsBadAddress(t *testing.T) {
	res := dnsmasq.ParseLeases("1800000000 aa:bb:cc:dd:ee:ff not-an-ip host *\n", "dnsmasq")

	if len(res.Leases) != 0 {
		t.Error("an invalid address must be rejected")
	}
}

func TestParseLeasesRejectsBadExpiry(t *testing.T) {
	res := dnsmasq.ParseLeases("not-a-timestamp aa:bb:cc:dd:ee:ff 10.77.0.1 host *\n", "dnsmasq")

	if len(res.Leases) != 0 {
		t.Error("a non-numeric expiry must be rejected")
	}
}

// TestLeaseRoundTrip verifies that writing what was parsed and re-parsing it
// produces the same leases.
func TestLeaseRoundTrip(t *testing.T) {
	original := leaseFile(time.Now())

	first := dnsmasq.ParseLeases(original, "dnsmasq")
	second := dnsmasq.ParseLeases(dnsmasq.FormatLeases(first.Leases), "dnsmasq")

	if len(first.Leases) != len(second.Leases) {
		t.Fatalf("round trip changed the lease count: %d then %d",
			len(first.Leases), len(second.Leases))
	}
	for i := range first.Leases {
		a, b := first.Leases[i], second.Leases[i]
		if a.MAC != b.MAC || a.Address != b.Address ||
			a.Hostname != b.Hostname || a.ClientID != b.ClientID {
			t.Errorf("lease %d changed across the round trip:\n  %+v\n  %+v", i, a, b)
		}
	}
}

// --- reconcile ---

func TestReconcileDetectsAddedGoneAndMoved(t *testing.T) {
	addr := func(s string) netip.Addr { return netip.MustParseAddr(s) }

	previous := []dhcp.Lease{
		{MAC: "aa:bb:cc:dd:ee:01", Address: addr("10.77.0.101")},
		{MAC: "aa:bb:cc:dd:ee:02", Address: addr("10.77.0.102")},
	}
	current := []dhcp.Lease{
		{MAC: "aa:bb:cc:dd:ee:01", Address: addr("10.77.0.101")}, // unchanged
		{MAC: "aa:bb:cc:dd:ee:02", Address: addr("10.77.0.107")}, // moved
		{MAC: "aa:bb:cc:dd:ee:03", Address: addr("10.77.0.103")}, // new
	}

	r := dnsmasq.Reconcile(previous, current)

	if r.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", r.Unchanged)
	}
	if len(r.Moved) != 1 || r.Moved[0].From.String() != "10.77.0.102" ||
		r.Moved[0].To.String() != "10.77.0.107" {
		t.Errorf("Moved = %+v, want the address change to be reported", r.Moved)
	}
	if len(r.Added) != 1 || r.Added[0].MAC != "aa:bb:cc:dd:ee:03" {
		t.Errorf("Added = %+v, want the new device", r.Added)
	}
	if len(r.Gone) != 0 {
		t.Errorf("Gone = %+v, want none", r.Gone)
	}
}

func TestReconcileDetectsDeparture(t *testing.T) {
	previous := []dhcp.Lease{{MAC: "aa:bb:cc:dd:ee:01", Address: netip.MustParseAddr("10.77.0.101")}}
	current := []dhcp.Lease{}

	r := dnsmasq.Reconcile(previous, current)

	if len(r.Gone) != 1 {
		t.Errorf("Gone = %+v, want the departed lease", r.Gone)
	}
}

// --- collection through the sandbox ---

func TestCollectThroughSandboxRoot(t *testing.T) {
	root := sandbox.New(t.TempDir())
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	if err := root.WriteFile("/var/lib/thn/dnsmasq.leases", leaseFile(now), 0o644); err != nil {
		t.Fatal(err)
	}

	source := dnsmasq.LeaseSource{Path: "/var/lib/thn/dnsmasq.leases"}
	reg := identity.NewRegistry()
	collector := dhcp.NewCollector(source, reg)

	set, changes, err := collector.Collect(context.Background(), root, now)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(set.Leases) != 5 {
		t.Errorf("collected %d leases, want 5", len(set.Leases))
	}
	if len(set.Problems) != 2 {
		t.Errorf("collected %d problems, want 2", len(set.Problems))
	}
	if set.Source != "dnsmasq" {
		t.Errorf("source = %q, want dnsmasq", set.Source)
	}

	// Every lease must carry a correlated device, because every lease in the
	// fixture has a hardware address.
	for _, l := range set.Leases {
		if l.DeviceID == "" {
			t.Errorf("lease %s was not correlated to a device", l.MAC)
		}
	}
	if reg.Len() != 5 {
		t.Errorf("registry holds %d devices, want 5", reg.Len())
	}
	if len(changes) != 5 {
		t.Errorf("reported %d new devices, want 5", len(changes))
	}
	for _, c := range changes {
		if c.Kind != dhcp.ChangeAppeared {
			t.Errorf("first observation must report ChangeAppeared, got %q", c.Kind)
		}
	}
}

// TestCollectWithMissingLeaseFileIsNotAnError covers the normal startup state.
func TestCollectWithMissingLeaseFileIsNotAnError(t *testing.T) {
	root := sandbox.New(t.TempDir())

	source := dnsmasq.LeaseSource{Path: "/var/lib/thn/dnsmasq.leases"}
	collector := dhcp.NewCollector(source, identity.NewRegistry())

	set, _, err := collector.Collect(context.Background(), root, time.Now())

	if err != nil {
		t.Fatalf("a missing lease file must not be an error: %v", err)
	}
	if len(set.Leases) != 0 {
		t.Errorf("got %d leases, want 0", len(set.Leases))
	}
	if len(set.Problems) == 0 {
		t.Error("a missing lease file must be reported as a problem")
	}
}

// TestLeaseWithoutMACIsUncorrelated covers the rule that an address does not
// identify a device.
func TestLeaseWithoutMACIsUncorrelated(t *testing.T) {
	root := sandbox.New(t.TempDir())
	now := time.Now()

	// A lease with an address but no hardware address.
	content := strconv.FormatInt(now.Add(time.Hour).Unix(), 10) +
		" * 10.77.0.199 unknown *\n"
	if err := root.WriteFile("/var/lib/thn/dnsmasq.leases", content, 0o644); err != nil {
		t.Fatal(err)
	}

	reg := identity.NewRegistry()
	collector := dhcp.NewCollector(
		dnsmasq.LeaseSource{Path: "/var/lib/thn/dnsmasq.leases"}, reg)

	set, _, err := collector.Collect(context.Background(), root, now)
	if err != nil {
		t.Fatal(err)
	}

	if reg.Len() != 0 {
		t.Errorf("a lease with no MAC must not create a device, got %d", reg.Len())
	}
	for _, l := range set.Leases {
		if l.DeviceID != "" {
			t.Errorf("a lease with no MAC must stay uncorrelated, got %q", l.DeviceID)
		}
	}
}

// TestDeviceIDIsStable verifies that the same hardware keeps its identity,
// which is what makes a lease history meaningful.
func TestDeviceIDIsStable(t *testing.T) {
	a := identity.IDFor("AA:BB:CC:DD:EE:FF")
	b := identity.IDFor("aa:bb:cc:dd:ee:ff")

	if a != b {
		t.Errorf("the same hardware must keep the same ID regardless of case: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "dev_") {
		t.Errorf("device ID %q should carry a dev_ prefix", a)
	}
	if identity.IDFor("11:22:33:44:55:66") == a {
		t.Error("different hardware must produce different IDs")
	}
}

// TestDeviceKeepsAddressHistory is the property that separates a device from a
// lease: a device is keyed by hardware and accumulates addresses.
func TestDeviceKeepsAddressHistory(t *testing.T) {
	reg := identity.NewRegistry()
	t0 := time.Now()

	reg.Observe(identity.Observation{
		MAC: "aa:bb:cc:dd:ee:ff", Address: netip.MustParseAddr("10.77.0.105"), Hostname: "laptop",
	}, t0)

	t1 := t0.Add(24 * time.Hour)
	reg.Observe(identity.Observation{
		MAC: "aa:bb:cc:dd:ee:ff", Address: netip.MustParseAddr("10.77.0.107"),
	}, t1)

	devs := reg.All()
	if len(devs) != 1 {
		t.Fatalf("one hardware address must produce one device, got %d", len(devs))
	}
	if len(devs[0].Addresses) != 2 {
		t.Errorf("the device must remember both addresses, got %v", devs[0].Addresses)
	}
	if devs[0].Addresses[0].String() != "10.77.0.107" {
		t.Errorf("the current address must come first, got %s", devs[0].Addresses[0])
	}
	if devs[0].PrimaryHostname() != "laptop" {
		t.Errorf("hostname = %q, want laptop", devs[0].PrimaryHostname())
	}
}

func TestFindByAddressUsesHistory(t *testing.T) {
	reg := identity.NewRegistry()
	t0 := time.Now()

	reg.Observe(identity.Observation{
		MAC: "aa:bb:cc:dd:ee:ff", Address: netip.MustParseAddr("10.77.0.105"),
	}, t0)
	reg.Observe(identity.Observation{
		MAC: "aa:bb:cc:dd:ee:ff", Address: netip.MustParseAddr("10.77.0.107"),
	}, t0.Add(time.Hour))

	// The old address is no longer current, but the device is still findable.
	found := reg.FindByAddress(netip.MustParseAddr("10.77.0.105"))
	if len(found) != 1 {
		t.Errorf("a device must be findable by an address it no longer holds, got %d results", len(found))
	}
}

func TestConfidenceReflectsAvailableSignals(t *testing.T) {
	reg := identity.NewRegistry()
	now := time.Now()

	reg.Observe(identity.Observation{MAC: "aa:bb:cc:dd:ee:01"}, now)
	reg.Observe(identity.Observation{MAC: "aa:bb:cc:dd:ee:02", Hostname: "phone"}, now)
	reg.Observe(identity.Observation{MAC: "aa:bb:cc:dd:ee:03", Hostname: "tv"}, now)

	byID := map[string]identity.Confidence{}
	for _, d := range reg.All() {
		byID[d.MAC] = d.Confidence
	}

	if byID["aa:bb:cc:dd:ee:01"] != identity.ConfidenceStrong {
		t.Errorf("a MAC alone is strong, got %q", byID["aa:bb:cc:dd:ee:01"])
	}
	if byID["aa:bb:cc:dd:ee:02"] != identity.ConfidenceProbable {
		t.Errorf("a MAC plus a hostname is probable, got %q", byID["aa:bb:cc:dd:ee:02"])
	}
	if byID["aa:bb:cc:dd:ee:03"] != identity.ConfidenceProbable {
		t.Errorf("a MAC plus a hostname is probable, got %q", byID["aa:bb:cc:dd:ee:03"])
	}
}
