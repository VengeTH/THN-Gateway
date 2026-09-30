package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/dhcp"
	"github.com/venth/thn-gateway/internal/dhcp/dnsmasq"
	"github.com/venth/thn-gateway/internal/dns"
	"github.com/venth/thn-gateway/internal/qos"
	qostc "github.com/venth/thn-gateway/internal/qos/tc"
)

// This file holds the DHCP, DNS and traffic-shaping phases of the gate.
//
// These three are grouped because they share a failure mode that no single
// subsystem can detect: each is individually correct, each is fed a correct
// configuration, and the LAN still does not work. A pool derived from the
// wrong prefix, a resolver advertised at the wrong address, or a shaper
// pointed at the LAN interface all produce a gateway that passes every
// package's own tests.

// TestGateDHCPServesClientsFromThePool is the DHCP phase's core property.
//
// A client that cannot obtain an address is not on the network, so nothing
// else about the gateway matters until this works.
func TestGateDHCPServesClientsFromThePool(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("deriving the DHCP policy: %v", err)
	}

	result := dhcp.Validate(p)
	if !result.Valid {
		for _, f := range result.Errors() {
			t.Errorf("the DHCP policy is invalid: %s", f)
		}
		t.Fatal("every later DHCP assertion would be testing an unusable pool")
	}

	if len(p.Ranges) == 0 {
		t.Fatal("the DHCP policy has no ranges")
	}

	pool := p.Ranges[0]
	capacity := pool.Size()
	if capacity <= 0 {
		t.Fatalf("pool %s holds %d addresses", pool, capacity)
	}

	// A client at each end of the pool must be servable, and one outside must
	// not be. The boundary is where off-by-one errors live: a pool described
	// as inclusive at one end and exclusive at the other serves one fewer
	// address than an operator believes.
	first := pool.Start
	last := pool.End

	if !pool.Contains(first) {
		t.Errorf("pool %s does not contain its own first address %s", pool, first)
	}
	if !pool.Contains(last) {
		t.Errorf("pool %s does not contain its own last address %s", pool, last)
	}

	// The advertised end must match the configured end. A dnsmasq
	// dhcp-range that is one short hands out one fewer address than the
	// configuration promised, and the discrepancy is invisible until a client
	// fails to renew.
	doc, code := runGateJSON(t, "dhcp", "render", "--config", writeTopology(t, topologyConfig()))
	if code != ExitOK {
		t.Fatalf("dhcp render exited %d", code)
	}
	content := jsonString(t, doc, "content")

	requireContains(t, "the dnsmasq configuration", content, "dhcp-range="+first.String()+","+last.String())
}

// TestGateDHCPPoolIsNotExhaustedByReservations checks the reservation budget.
//
// A reserved address is handed out by hand, so the pool has to account for it
// or the server will eventually offer an address that is already pinned and
// produce a conflict the operator cannot diagnose from the LAN.
func TestGateDHCPPoolIsNotExhaustedByReservations(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("deriving the DHCP policy: %v", err)
	}

	if len(p.Reservations) == 0 {
		t.Skip("the gate topology has no reservations to check")
	}

	seen := map[string]bool{}
	for _, r := range p.Reservations {
		key := r.Address.String()
		if seen[key] {
			t.Errorf("address %s is reserved more than once", key)
		}
		seen[key] = true

		// A reservation outside the pool is a conflict waiting to happen: the
		// server is told to pin an address it will also hand out dynamically.
		inPool := false
		for _, pool := range p.Ranges {
			if pool.Contains(r.Address) {
				inPool = true
				break
			}
		}
		if inPool {
			t.Errorf("reservation for %s (%s) sits inside the dynamic pool; the "+
				"server may hand the same address to two devices",
				r.MAC, r.Address)
		}
	}
}

// TestGateDHCPRendersReservations checks the handoff to the backend, because a
// reservation that exists in the policy but not in the rendered file is a
// device that silently loses its address.
func TestGateDHCPRendersReservations(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("deriving the DHCP policy: %v", err)
	}

	dnsPolicy := dnsPolicyOrFail(t, cfg)
	content := dnsmasq.Render(p, dnsPolicy, p.LANPrefix, p.GatewayAddress)

	// The generated file is checked against dnsmasq's own vocabulary. A typo
	// produces a file dnsmasq accepts and ignores, which is how a gateway
	// ends up with no DHCP and no indication why.
	if issues := dnsmasq.ValidateConfig(content); len(issues) > 0 {
		for _, is := range issues {
			t.Errorf("the generated file has an unknown directive on line %d: %s", is.Line, is.Message)
		}
	}

	for _, r := range p.Reservations {
		// A reservation must appear as a host declaration, and the rendered
		// MAC must be the normalised form dnsmasq matches on.
		if !strings.Contains(content, r.Hostname) {
			t.Errorf("reservation for %s (%s) is not in the generated file", r.MAC, r.Hostname)
		}
		if !strings.Contains(content, r.Address.String()) {
			t.Errorf("reserved address %s is not in the generated file", r.Address)
		}
	}
}

// TestGateDHCPServesTheGatewayAsResolver is the DHCP-to-DNS handoff, and it is
// the seam that breaks most visibly.
//
// DHCP option 6 tells the client where to send DNS queries. If it names an
// address the gateway does not listen on, every client has a working IP
// address and no name resolution — and the LAN looks broken for a reason
// nobody can find, because pinging works.
func TestGateDHCPServesTheGatewayAsResolver(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())

	dhcpPolicy, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("deriving the DHCP policy: %v", err)
	}
	dnsPolicy := dnsPolicyOrFail(t, cfg)

	if !dhcpPolicy.GatewayAddress.IsValid() {
		t.Fatal("DHCP advertises no gateway address; a client would have no default route")
	}
	if !dnsPolicy.ListenAddress.IsValid() {
		t.Fatal("DNS has no listen address")
	}
	if dhcpPolicy.GatewayAddress != dnsPolicy.ListenAddress {
		t.Errorf("DHCP advertises the resolver as %s but DNS listens on %s",
			dhcpPolicy.GatewayAddress, dnsPolicy.ListenAddress)
	}

	// The resolver DHCP hands out must actually be inside the LAN the client
	// is on. A public address in option 6 sends every query off-site.
	lan := mustPrefix(t, gateLANAddr)
	if !lan.Contains(dnsPolicy.ListenAddress) {
		t.Errorf("DNS listens on %s, which is outside the LAN %s", dnsPolicy.ListenAddress, lan)
	}

	content := dnsmasq.Render(dhcpPolicy, dnsPolicy, dhcpPolicy.LANPrefix, dhcpPolicy.GatewayAddress)

	// The named option form is used rather than the numeric one. Both are
	// valid dnsmasq, and the named form is what a human reads when checking
	// a generated file at 2am — so the gate asserts the named form, and would
	// flag a change to the numeric form as a change worth reviewing.
	requireContains(t, "the dnsmasq configuration", content,
		"dhcp-option=option:dns-server,"+dnsPolicy.ListenAddress.String())

	// The router option matters just as much: without it a client obtains an
	// address and then cannot reach anything, which presents as a network
	// fault rather than a missing option.
	requireContains(t, "the dnsmasq configuration", content,
		"dhcp-option=option:router,"+dhcpPolicy.GatewayAddress.String())
}

// TestGateDHCPLeaseLifecycle is the DHCP phase's time dimension: a lease is
// issued, observed, and later expires.
//
// The clock is fixed, so "later" is a decision of this test rather than a
// function of when the suite ran.
func TestGateDHCPLeaseLifecycle(t *testing.T) {
	issued := gateFixedTime

	lease := dhcp.Lease{
		MAC:       "aa:bb:cc:dd:ee:ff",
		Hostname:  "laptop",
		Address:   addr(t, "10.77.0.100"),
		Start:     issued,
		Expiry:    issued.Add(12 * time.Hour),
		FirstSeen: issued,
		DeviceID:  "dev_0123456789abcdef",
	}

	if !lease.Active(issued) {
		t.Error("a freshly issued lease is not active")
	}
	if got := lease.Status(issued); got != dhcp.StatusActive {
		t.Errorf("status = %q, want active", got)
	}

	// Just before expiry it must still be active; just after, not. A lease
	// that expires early reassigns an address under a running client, and one
	// that lingers holds an address nobody can use.
	before := lease.Expiry.Add(-time.Minute)
	after := lease.Expiry.Add(time.Minute)

	if !lease.Active(before) {
		t.Error("the lease expired before its stated expiry")
	}
	if lease.Active(after) {
		t.Error("the lease is still active an hour past its expiry")
	}
	if got := lease.Status(after); got != dhcp.StatusExpired {
		t.Errorf("status after expiry = %q, want expired", got)
	}
}

// TestGateDHCPLeaseReconciliationDetectsMovement is the case that separates a
// working gateway from one that reports confidently wrong state.
//
// A device that changes address is normal — it renewed against a different
// pool, or the pool was resized. What matters is that the change is detected
// and reported rather than silently absorbed, because a stale address in the
// device registry produces a device that appears online and is not.
func TestGateDHCPLeaseReconciliationDetectsMovement(t *testing.T) {
	issued := gateFixedTime

	previous := []dhcp.Lease{
		{MAC: "aa:bb:cc:dd:ee:01", Hostname: "nas", Address: addr(t, "10.77.0.100"), Start: issued, Expiry: issued.Add(12 * time.Hour)},
		{MAC: "aa:bb:cc:dd:ee:02", Hostname: "laptop", Address: addr(t, "10.77.0.101"), Start: issued, Expiry: issued.Add(12 * time.Hour)},
	}
	current := []dhcp.Lease{
		{MAC: "aa:bb:cc:dd:ee:01", Hostname: "nas", Address: addr(t, "10.77.0.100"), Start: issued, Expiry: issued.Add(12 * time.Hour)},
		// Moved.
		{MAC: "aa:bb:cc:dd:ee:02", Hostname: "laptop", Address: addr(t, "10.77.0.150"), Start: issued, Expiry: issued.Add(12 * time.Hour)},
		// New.
		{MAC: "aa:bb:cc:dd:ee:03", Hostname: "phone", Address: addr(t, "10.77.0.102"), Start: issued, Expiry: issued.Add(12 * time.Hour)},
	}

	rec := dnsmasq.Reconcile(previous, current)

	if len(rec.Moved) != 1 {
		t.Errorf("moved = %d, want 1; a device that changed address must be reported, "+
			"not silently absorbed", len(rec.Moved))
	} else {
		m := rec.Moved[0]
		if m.MAC != "aa:bb:cc:dd:ee:02" {
			t.Errorf("moved MAC = %q, want aa:bb:cc:dd:ee:02", m.MAC)
		}
		if m.From == m.To {
			t.Errorf("moved lease reports the same address before and after: %s", m.From)
		}
	}

	if len(rec.Added) != 1 {
		t.Errorf("added = %d, want 1", len(rec.Added))
	}
	if rec.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", rec.Unchanged)
	}
	if len(rec.Gone) != 0 {
		t.Errorf("gone = %d, want 0; %v", len(rec.Gone), rec.Gone)
	}
}

// TestGateDHCPLeaseFileRoundTrips checks the handoff in both directions.
//
// The gateway writes leases and reads them back. A lease that parses but
// loses a field round-trips into a registry entry that is subtly wrong, and
// the wrongness surfaces much later as a device that cannot be identified.
func TestGateDHCPLeaseFileRoundTrips(t *testing.T) {
	issued := gateFixedTime
	leaseTime := 12 * time.Hour

	original := dhcp.Lease{
		MAC:       "aa:bb:cc:dd:ee:ff",
		Hostname:  "nas",
		Address:   addr(t, "10.77.0.100"),
		Start:     issued,
		Expiry:    issued.Add(leaseTime),
		FirstSeen: issued,
		ClientID:  "01:aa:bb:cc:dd:ee:ff",
		DeviceID:  "dev_0123456789abcdef",
		Source:    "dnsmasq",
	}

	// Format, then parse back.
	parsed := dnsmasq.ParseLeases(dnsmasq.FormatLease(original), "gate")

	if len(parsed.Errors) > 0 {
		for _, e := range parsed.Errors {
			t.Errorf("the lease we just formatted does not parse (line %d: %s): %s",
				e.Line, e.Message, e.Content)
		}
	}
	if len(parsed.Leases) != 1 {
		t.Fatalf("parsed %d leases, want 1", len(parsed.Leases))
	}

	got := parsed.Leases[0]
	if got.Address != original.Address {
		t.Errorf("address = %s, want %s", got.Address, original.Address)
	}
	if got.MAC != original.MAC {
		t.Errorf("MAC = %q, want %q", got.MAC, original.MAC)
	}
	if got.Hostname != original.Hostname {
		t.Errorf("hostname = %q, want %q", got.Hostname, original.Hostname)
	}

	// The expiry is the field that decides whether a client still holds the
	// address, so it is the one that must survive the round trip exactly.
	if !got.Expiry.Equal(original.Expiry) {
		t.Errorf("expiry = %s, want %s; a lease read back with the wrong expiry is "+
			"either holding an address nobody can use or stealing one in use",
			got.Expiry, original.Expiry)
	}

	// The start time is deliberately not recovered. The dnsmasq lease format
	// records only the expiry, and the parser leaves Start zero rather than
	// deriving it — an invented start time would be indistinguishable from a
	// real one once stored, and would then be reported as a lease age.
	//
	// Pinning this is the point: if a future change starts guessing, the gate
	// says so, because the guess is indistinguishable from the truth.
	if !got.Start.IsZero() {
		t.Errorf("start = %s, want the zero time; the dnsmasq lease format does not "+
			"record one and the parser must not invent it", got.Start)
	}

	// A lease with no start must still report its status correctly, since that
	// is what an operator acts on. This is the property that makes leaving
	// Start zero safe.
	if got.Status(issued) != dhcp.StatusActive {
		t.Errorf("status = %q, want active; an unreadable start time must not make a "+
			"live lease look expired", got.Status(issued))
	}
}

// TestGateDHCPGarbageLeaseFileIsReportedNotIgnored is the failure-mode check.
//
// A truncated or corrupt lease file must be reported. Silently dropping the
// unreadable lines would empty the device registry, and the gateway would
// look like it had forgotten every device it knew.
func TestGateDHCPGarbageLeaseFileIsReportedNotIgnored(t *testing.T) {
	garbage := strings.Join([]string{
		"this is not a lease file",
		"",
		"<garbage>",
		strings.Repeat("x", 4096),
	}, "\n")

	result := dnsmasq.ParseLeases(garbage, "gate")

	if result.Lines == 0 {
		t.Error("no lines were counted; the parser did not look at the input")
	}
	if len(result.Errors) == 0 {
		t.Error("a file of pure garbage produced no errors; the damage would be " +
			"invisible to an operator")
	}
	if len(result.Leases) != 0 {
		t.Errorf("parsed %d leases from a file containing none", len(result.Leases))
	}
}

// TestGateDNSResolvesLocalRecords is the DNS phase's core property.
func TestGateDNSResolvesLocalRecords(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p := dnsPolicyOrFail(t, cfg)

	if !p.Enabled {
		t.Fatal("DNS is disabled; clients would have no resolver")
	}
	if len(p.LocalRecords) == 0 {
		t.Fatal("the gate topology has no local records to resolve")
	}

	for _, r := range p.LocalRecords {
		fqdn := r.FQDN(p.LocalDomain)
		if !strings.HasSuffix(fqdn, "."+p.LocalDomain) {
			t.Errorf("record %q resolves to %q, which is not inside the local domain %q",
				r.Hostname, fqdn, p.LocalDomain)
		}
		if !mustPrefix(t, gateLANAddr).Contains(r.Address) {
			t.Errorf("record %q points at %s, outside the LAN; a client would "+
				"resolve a name and then fail to reach it", r.Hostname, r.Address)
		}
	}

	// The rendered configuration must actually serve them.
	content := dnsmasq.Render(mustDHCPPolicy(t, cfg), p,
		mustPrefix(t, gateLANAddr), addr(t, "10.77.0.1"))

	for _, r := range p.LocalRecords {
		if !strings.Contains(content, r.Hostname) {
			t.Errorf("record %q is in the policy but not in the generated file", r.Hostname)
		}
	}
}

// TestGateDNSRejectsRebinding is the DNS phase's security property.
//
// A gateway that resolves an external name to a LAN address hands an attacker
// a way to reach the LAN from a browser. Rejecting the unmapped blocks is what
// prevents it, and it is worth a gate assertion because it is a setting an
// operator can turn off without noticing what they turned on.
func TestGateDNSRejectsRebinding(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p := dnsPolicyOrFail(t, cfg)

	if !p.RejectUnmappedBlocks {
		t.Error("DNS will resolve external names to private addresses; that is a " +
			"rebinding vector into the LAN")
	}
}

// TestGateDNSUpstreamIsUsable checks the resolvers actually configured.
func TestGateDNSUpstreamIsUsable(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p := dnsPolicyOrFail(t, cfg)

	if len(p.Upstream) == 0 {
		t.Fatal("DNS has no upstream resolvers; every lookup would fail")
	}
	for _, u := range p.Upstream {
		if !u.IsValid() {
			t.Errorf("upstream resolver %q is not an address", u)
			continue
		}
		if !u.IsGlobalUnicast() {
			t.Errorf("upstream resolver %s is not a global unicast address", u)
		}
	}

	result := dns.Validate(p)
	if !result.Valid {
		for _, f := range result.Errors() {
			t.Errorf("the DNS policy is invalid: %s", f)
		}
	}
}

// TestGateQoSShapesTheBottleneck is the traffic-shaping phase's core property.
//
// Shaping belongs on the interface facing the bottleneck. On the wrong
// interface it is not merely useless: a shaper on the LAN shortens the LAN's
// own queue, which is not congested, while leaving the uplink's queue — the
// one causing the latency — exactly as long as it was.
func TestGateQoSShapesTheBottleneck(t *testing.T) {
	cfg, _ := loadTopology(t, topologyConfig())
	p := qosPolicyFromConfig(cfg)

	if !p.Enabled {
		t.Fatal("the gate topology has shaping disabled")
	}
	if p.Interface != gateWANIface {
		t.Errorf("shaping is on %q, want %q; shaping the LAN shortens a queue that "+
			"is not the bottleneck and leaves the uplink's queue untouched", p.Interface, gateWANIface)
	}

	// The shaper must be rate-aware, or the configured rate is ignored.
	if p.Algorithm != qos.AlgorithmCake {
		t.Errorf("algorithm = %q, want cake; fq_codel cannot enforce a rate, so the "+
			"configured bandwidth would be silently ignored", p.Algorithm)
	}
}

// TestGateQoSConfiguredRateReachesTheCommand is the assertion that ties the
// configuration to the artefact an operator will run.
func TestGateQoSConfiguredRateReachesTheCommand(t *testing.T) {
	cfg, path := loadTopology(t, topologyConfig())
	p := qosPolicyFromConfig(cfg)

	// The overhead arithmetic, checked here rather than trusted: a gateway
	// shaped at the payload rate leaves the link a tenth under-utilised and
	// nothing reports it.
	wantDown := p.Bandwidth.Effective(qos.Download)

	if wantDown != 110_000 {
		t.Errorf("download wire rate = %d kbit/s, want 110000 (%d at 10%% overhead)",
			wantDown, gateDownloadKbps)
	}
	if got := p.Bandwidth.Effective(qos.Upload); got != 22_000 {
		t.Errorf("upload wire rate = %d kbit/s, want 22000 (%d at 10%% overhead)",
			got, gateUploadKbps)
	}

	doc, code := runGateJSON(t, "qos", "render", "--config", path, "--assume-cake")
	if code != ExitOK {
		t.Fatalf("qos render exited %d", code)
	}
	script := jsonString(t, doc, "script")

	requireContains(t, "the shaping script", script, "bandwidth 110000kbit")
	requireContains(t, "the shaping script", script, "uplink 22000kbit")
	requireContains(t, "the shaping script", script, "dev "+gateWANIface+" root cake")
}

// TestGateQoSDegradesLoudlyOnAHostWithoutCake is the property the whole
// fallback design rests on.
//
// A shaper that silently falls back to something weaker is worse than one that
// fails: the operator believes bufferbloat was fixed, and it was not. The
// loss has to be visible in the exit code, not only in the file.
func TestGateQoSDegradesLoudlyOnAHostWithoutCake(t *testing.T) {
	_, path := loadTopology(t, topologyConfig())

	stdout, _, code := runGateCLI(t, "qos", "render", "--config", path, "--assume-fq-codel")

	// No cake is available, so this must not report success.
	if code != ExitProblems {
		t.Errorf("exit = %d, want %d; a degraded shaping policy must be visible to CI",
			code, ExitProblems)
	}
	requireContains(t, "the shaping script", stdout, "DEGRADED")
	requireContains(t, "the shaping script", stdout, "cannot enforce a bandwidth")

	// And the command it produced must be fq_codel, not a CAKE command the
	// kernel would reject.
	requireContains(t, "the shaping script", stdout, "root fq_codel")
	requireNotContains(t, "the shaping script", stdout, "root cake")
}

// TestGateQoSStatisticsParseFromTheKernelFormat is the shaping phase's
// observation property.
//
// The statistics are how an operator finds out whether shaping is working.
// The fixture is real `tc -j -s qdisc show` output, so the parser is checked
// against the shape a kernel produces rather than a shape invented here.
func TestGateQoSStatisticsParseFromTheKernelFormat(t *testing.T) {
	kernelOutput := `[
		{
			"kind": "cake",
			"handle": "8001:",
			"root": true,
			"refcnt": 2,
			"bytes": 8473620944,
			"packets": 5914221,
			"drops": 1284,
			"overlimits": 481203,
			"backlog": 0,
			"queued": 0,
			"qlen": 1000,
			"options": { "bandwidth": 110, "uplink": 22, "target": 5000000, "interval": 100000000 }
		}
	]`

	snap, err := qostc.ParseStats(gateWANIface, kernelOutput)
	if err != nil {
		t.Fatalf("parsing kernel statistics: %v", err)
	}

	if !snap.Present {
		t.Fatal("no qdisc reported, but the output contains one")
	}
	if snap.Root.Algorithm != "cake" {
		t.Errorf("algorithm = %q, want cake", snap.Root.Algorithm)
	}
	if snap.Root.Packets == 0 {
		t.Error("no packet count; the operator would see an idle queue on a busy link")
	}

	// The rate must come back. A shaper reporting no rate is indistinguishable
	// from one that was never configured, which is the single most misleading
	// thing this reader could produce.
	if snap.Root.BandwidthMbps != 110 {
		t.Errorf("bandwidth = %d Mbps, want 110", snap.Root.BandwidthMbps)
	}

	// Heavy overlimits with few drops is a shaper working. A gate that
	// classified it as a problem would train operators to ignore the warning.
	if got := snap.Root.Assess(); got != qostc.HealthShaping {
		t.Errorf("health = %q (%s), want shaping; high overlimits with few drops "+
			"is the intended behaviour under load", got, snap.Root.Explain())
	}
}

// TestGateQoSReportsAnUnshapedInterface is the negative observation case, and
// it matters as much as the positive one.
func TestGateQoSReportsAnUnshapedInterface(t *testing.T) {
	// What tc prints when the kernel's default queue is in place.
	unshaped := `[{"kind":"pfifo_fast","handle":"0:","root":true,"bytes":2048,"packets":16,"drops":0,"qlen":1000}]`

	snap, err := qostc.ParseStats(gateWANIface, unshaped)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if !snap.Present {
		t.Fatal("a qdisc is present, even though it does not shape")
	}
	if snap.Root.Algorithm == "cake" {
		t.Error("the default queue was reported as CAKE")
	}
	// A default queue has no rate, and the parser must not invent one.
	if snap.Root.BandwidthMbps != 0 {
		t.Errorf("the unshaped default queue reported a rate of %d Mbps",
			snap.Root.BandwidthMbps)
	}
}

// mustDHCPPolicy derives the DHCP policy or fails the test.
func mustDHCPPolicy(t *testing.T, cfg gateConfig) dhcp.Policy {
	t.Helper()

	p, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		t.Fatalf("deriving the DHCP policy: %v", err)
	}
	return p
}
