package cli

// Device independence, seen rather than asserted.
//
// internal/host proves the model resolves against five imaginary hosts. This
// shows what two of them actually look like through the CLI's own renderer, so
// the claim can be checked by reading rather than trusted.
//
// It uses the same RenderDiscovery that `thn discover` calls. A second
// renderer in a test would be a third opinion about the same model, and would
// drift from the one operators see.

import (
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

// simInterface builds one observed interface for a simulated host.
func simInterface(name string, index int, mac, kind string, up bool) network.Interface {
	state := network.LinkDown
	if up {
		state = network.LinkUp
	}
	return network.Interface{
		Name:  name,
		Index: index,
		MAC:   mac,
		MTU:   1500,
		Kind:  kind,
		State: state,
		Role:  network.RoleUnassigned,
	}
}

// hostWithTwoNicsAndWifi is the original deployment shape plus Wi-Fi.
func hostWithTwoNicsAndWifi() *host.Device {
	return host.FromSnapshot(&network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simInterface("enp0s31f6", 2, "aa:bb:cc:dd:ee:01", "ethernet", true),
			simInterface("enp1s0", 3, "aa:bb:cc:dd:ee:02", "ethernet", false),
			simInterface("wlp2s0", 4, "aa:bb:cc:dd:ee:03", "wireless", true),
			simInterface("lo", 1, "", "loopback", true),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	})
}

// hostWithForeignNames shares nothing but its shape with the first.
func hostWithForeignNames() *host.Device {
	return host.FromSnapshot(&network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			simInterface("eth0", 7, "de:ad:be:ef:00:01", "ethernet", true),
			simInterface("eth1", 8, "de:ad:be:ef:00:02", "ethernet", true),
			simInterface("eth2", 9, "de:ad:be:ef:00:03", "wireless", false),
			simInterface("lo", 1, "", "loopback", true),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	})
}

// TestDiscoveryRendersTwoDifferentHosts shows the output for two hosts.
//
// It logs rather than asserting, because the assertion is made in
// internal/host; what this adds is the evidence a reader can check.
func TestDiscoveryRendersTwoDifferentHosts(t *testing.T) {
	cases := []struct {
		name   string
		d      *host.Device
		assign []host.Assignment
	}{
		{"Host A — two Ethernet plus Wi-Fi", hostWithTwoNicsAndWifi(), []host.Assignment{
			{Role: host.RoleWAN, Selector: host.IDFor("aa:bb:cc:dd:ee:01")},
			{Role: host.RoleLAN, Selector: host.IDFor("aa:bb:cc:dd:ee:02")},
		}},
		{"Host D — same shape, unrelated names", hostWithForeignNames(), []host.Assignment{
			{Role: host.RoleWAN, Selector: host.IDFor("de:ad:be:ef:00:01")},
			{Role: host.RoleLAN, Selector: host.IDFor("de:ad:be:ef:00:02")},
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := RenderDiscovery(c.d, false)
			t.Logf("\n%s", out)

			res := host.Resolve(c.d, c.assign)
			if !res.OK() {
				t.Fatalf("the same desired gateway did not resolve: %+v", res.Problems)
			}
			t.Logf("resolved: WAN=%s LAN=%s",
				res.Assigned[host.RoleWAN].SystemName,
				res.Assigned[host.RoleLAN].SystemName)
		})
	}
}

// TestDiscoveryDoesNotPrintHardwareAddressesByDefault is the privacy rule.
func TestDiscoveryDoesNotPrintHardwareAddressesByDefault(t *testing.T) {
	d := hostWithTwoNicsAndWifi()

	without := RenderDiscovery(d, false)
	with := RenderDiscovery(d, true)

	if strings.Contains(without, "aa:bb:cc:dd:ee:01") {
		t.Error("the default rendering exposes a hardware address")
	}
	if !strings.Contains(with, "aa:bb:cc:dd:ee:01") {
		t.Error("--mac did not reveal the hardware address")
	}

	// The stable ID is always shown, because it is how a configuration refers
	// to an interface.
	if !strings.Contains(without, host.IDFor("aa:bb:cc:dd:ee:01")) {
		t.Error("the default rendering omits the stable ID")
	}
}

// TestDiscoveryIsACommandThatExists registers it.
func TestDiscoveryIsACommandThatExists(t *testing.T) {
	cmd, ok := commands["discover"]
	if !ok {
		t.Fatal("discover is not in the command table")
	}
	if cmd.Tier != TierPure {
		t.Errorf("discover tier = %q, want %q", cmd.Tier, TierPure)
	}
	if cmd.Summary == "" {
		t.Error("discover has no summary; it would be undiscoverable in `thn help`")
	}
}

// TestDiscoveryRefusesToClaimAnUninspectableHost is the honesty rule.
func TestDiscoveryRefusesToClaimAnUninspectableHost(t *testing.T) {
	d := host.FromSnapshot(&network.Snapshot{Supported: false, Platform: "windows"})

	out := RenderDiscovery(d, false)
	if strings.Contains(out, "1. Ethernet") {
		t.Error("an uninspected host rendered interfaces")
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("an uninspected host did not say it was unavailable:\n%s", out)
	}
	if !strings.Contains(out, "Current network remains untouched") {
		t.Error("the rendering does not state that the network is untouched")
	}
}

// TestUnresolvedAssignmentProducesAStructuredSuggestion is the PART 13 shape,
// checked in the form a future UI would consume.
func TestUnresolvedAssignmentProducesAStructuredSuggestion(t *testing.T) {
	d := hostWithTwoNicsAndWifi()

	res := host.Resolve(d, []host.Assignment{
		{Role: host.RoleWAN, Selector: "enp0s31f9"}, // does not exist
	})

	if res.OK() {
		t.Fatal("an assignment to a nonexistent interface resolved")
	}
	p := res.Problems[0]
	if p.Code != "unknown-interface" {
		t.Errorf("code = %q, want unknown-interface", p.Code)
	}
	if p.Role != host.RoleWAN {
		t.Errorf("role = %q, want wan", p.Role)
	}
	if len(p.Observed) == 0 {
		t.Error("the problem does not carry what was observed")
	}
	if len(p.Candidates) == 0 {
		t.Error("the problem does not carry candidates")
	}

	suggestions := host.Suggestions(res)
	if len(suggestions) == 0 {
		t.Fatal("no suggestion was produced")
	}
	for _, want := range []string{"wan", "Observed", "Possible"} {
		if !strings.Contains(suggestions[0], want) {
			t.Errorf("the suggestion does not mention %q:\n%s", want, suggestions[0])
		}
	}
}
