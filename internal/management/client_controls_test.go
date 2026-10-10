package management

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
)

// Tests for the live client-control surface.
//
// The Web UI's Devices page is driven entirely by what this package reads out
// of client_controls.json and /proc/net/arp. Both were wrong in ways that made
// the console disagree with the kernel without saying so:
//
//   - only download_mbps was read, so a client limited in both directions was
//     shown as if only the download had a ceiling;
//   - the ARP source matched a literal "10.77.0." and a literal interface
//     name, so on any other LAN addressing every neighbour was dropped and the
//     network looked empty.
//
// The tests below pin both behaviours, because in each case the failure is
// silent: the page renders, and it renders the wrong thing.

// writeControlsFile writes a client_controls.json fixture.
func writeControlsFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client_controls.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write controls fixture: %v", err)
	}
	return p
}

// useControlsFile points the production reader at a fixture for one test.
func useControlsFile(t *testing.T, path string) {
	t.Helper()
	restore := clientControlsPathOverride
	clientControlsPathOverride = &path
	t.Cleanup(func() { clientControlsPathOverride = restore })
}

// TestParseClientControlsReadsBothDirectionsAndTheDirectionField is the
// regression test for the upload half of the limit being invisible.
//
// The engine writes upload_mbps and direction. A reader that only knows about
// download_mbps reports an upload-limited client as unlimited, and the operator
// then has no way to tell an absent limit from an unread one.
func TestParseClientControlsReadsBothDirectionsAndTheDirectionField(t *testing.T) {
	path := writeControlsFile(t, `{
  "10.77.0.50":  {"download_mbps": 30, "upload_mbps": 10, "direction": "both", "policy": "30 Mbps down / 10 Mbps up"},
  "10.77.0.51":  {"download_mbps": 20, "direction": "download", "policy": "20 Mbps down only"},
  "10.77.0.52":  {"upload_mbps": 5, "direction": "upload", "policy": "5 Mbps up only"}
}`)
	useControlsFile(t, path)

	got := parseClientControls()
	if len(got) != 3 {
		t.Fatalf("expected 3 records, got %d", len(got))
	}

	if c := got["10.77.0.50"]; c.DownloadMbps != 30 || c.UploadMbps != 10 || c.Direction != "both" {
		t.Fatalf("10.77.0.50 parsed as %+v", c)
	}
	if c := got["10.77.0.51"]; c.DownloadMbps != 20 || c.UploadMbps != 0 {
		t.Fatalf("10.77.0.51 parsed as %+v", c)
	}
	if c := got["10.77.0.52"]; c.DownloadMbps != 0 || c.UploadMbps != 5 {
		t.Fatalf("10.77.0.52 parsed as %+v", c)
	}
}

// TestParseClientControlsCorruptFileDoesNotClaimNoLimits guards the fail-open
// direction.
//
// A corrupt file must not be reported as "this client has no limit". That
// reading turns an enforced ceiling into an enforced-nothing on the dashboard,
// and the two are indistinguishable on screen.
func TestParseClientControlsCorruptFileDoesNotClaimNoLimits(t *testing.T) {
	path := writeControlsFile(t, `{"10.77.0.50": {"download_mbps": 30`)
	useControlsFile(t, path)

	if got := parseClientControls(); got != nil {
		t.Fatalf("a corrupt controls file produced %d record(s); it must produce none rather than a wrong set", len(got))
	}
}

// TestParseClientControlsMissingFileIsNotAnError pins the ordinary case: no
// file means no controls have ever been applied.
func TestParseClientControlsMissingFileIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	useControlsFile(t, path)

	if got := parseClientControls(); got != nil {
		t.Fatalf("a missing controls file produced %d record(s), want none", len(got))
	}
}

// TestNormalizedDirectionPrefersTheRatesOverTheStoredLabel.
//
// The stored "direction" is written by the enforcement script; the rates are
// what the kernel was actually told. Where they disagree the rates win, since a
// record that says "both" while carrying only a download figure describes a
// limit that does not exist.
func TestNormalizedDirectionPrefersTheRatesOverTheStoredLabel(t *testing.T) {
	cases := []struct {
		name   string
		stored string
		down   int
		up     int
		want   string
	}{
		{"both directions limited", "both", 30, 10, "both"},
		{"download only", "download", 30, 0, "download"},
		{"upload only", "upload", 0, 10, "upload"},
		{"label disagrees with the rates", "both", 30, 0, "download"},
		{"label disagrees, other way", "download", 0, 10, "upload"},
		{"no rates but a label", "upload", 0, 0, "upload"},
		{"nothing recorded", "", 0, 0, "both"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizedDirection(tc.stored, tc.down, tc.up); got != tc.want {
				t.Fatalf("normalizedDirection(%q, %d, %d) = %q, want %q",
					tc.stored, tc.down, tc.up, got, tc.want)
			}
		})
	}
}

// TestQoSPolicyLabelIsBuiltFromTheRates.
//
// The label is derived rather than copied from the record's own prose, so the
// words cannot drift away from the numbers they describe.
func TestQoSPolicyLabelIsBuiltFromTheRates(t *testing.T) {
	cases := []struct {
		name string
		in   clientControlEntry
		want string
	}{
		{
			name: "both",
			in:   clientControlEntry{DownloadMbps: 30, UploadMbps: 30},
			want: "30 Mbps down / 30 Mbps up",
		},
		{
			name: "download only",
			in:   clientControlEntry{DownloadMbps: 20},
			want: "20 Mbps down only",
		},
		{
			name: "upload only",
			in:   clientControlEntry{UploadMbps: 5},
			want: "5 Mbps up only",
		},
		{
			name: "asymmetric",
			in:   clientControlEntry{DownloadMbps: 50, UploadMbps: 10},
			want: "50 Mbps down / 10 Mbps up",
		},
		{
			name: "stale prose is not trusted over the absence of rates",
			in:   clientControlEntry{Policy: "30 Mbps"},
			want: "30 Mbps",
		},
		{
			name: "nothing at all",
			in:   clientControlEntry{},
			want: "Default (Uncapped)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := qosPolicyLabel(tc.in); got != tc.want {
				t.Fatalf("qosPolicyLabel(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// writeArpTable writes a /proc/net/arp fixture.
func writeArpTable(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "arp")
	header := "IP address       HW type     Flags       HW address            Mask     Device\n"
	if err := os.WriteFile(p, []byte(header+strings.Join(lines, "")), 0o600); err != nil {
		t.Fatalf("write arp fixture: %v", err)
	}
	return p
}

// arpLine renders one /proc/net/arp row.
func arpLine(ip, flags, mac, dev string) string {
	return "  " + ip + "       0x1         " + flags + "         " + mac + "     *        " + dev + "\n"
}

func useArpTable(t *testing.T, path string) {
	t.Helper()
	restore := arpPathOverride
	arpPathOverride = path
	t.Cleanup(func() { arpPathOverride = restore })
}

// TestParseArpTableKeepsNeighboursOnTheConfiguredLan is the regression test for
// the hardcoded subnet.
//
// The previous source matched a literal "10.77.0." prefix. On any other LAN the
// filter discarded every entry, so the Devices page was empty while the kernel
// neighbour table was full — the exact shape of "the gateway cannot see my
// devices", reported as a discovery problem but caused by a constant.
func TestParseArpTableKeepsNeighboursOnTheConfiguredLan(t *testing.T) {
	path := writeArpTable(t,
		arpLine("10.77.0.50", "0x2", "08:00:27:aa:bb:cc", "lan0"),
		arpLine("192.168.1.50", "0x2", "08:00:27:aa:bb:cd", "lan0"),
	)
	useArpTable(t, path)

	got := parseArpTable("10.77.0.1/24", "lan0")
	if len(got) != 1 {
		t.Fatalf("expected only the in-subnet neighbour, got %d: %+v", len(got), got)
	}
	if got[0].IPv4 != "10.77.0.50" {
		t.Fatalf("wrong neighbour kept: %+v", got[0])
	}
}

// TestParseArpTableIgnoresEntriesOnForeignInterfaces.
//
// A host running containers has dozens of bridge and veth devices with
// neighbours of their own. None of them is a client of this gateway, and
// listing them as clients is how a Devices page fills with phantom entries.
func TestParseArpTableIgnoresEntriesOnForeignInterfaces(t *testing.T) {
	path := writeArpTable(t,
		arpLine("10.77.0.50", "0x2", "08:00:27:aa:bb:cc", "lan0"),
		arpLine("10.77.0.51", "0x2", "08:00:27:aa:bb:ce", "docker0"),
	)
	useArpTable(t, path)

	got := parseArpTable("10.77.0.1/24", "lan0")
	if len(got) != 1 || got[0].IPv4 != "10.77.0.50" {
		t.Fatalf("expected only the LAN-interface neighbour, got %+v", got)
	}
}

// TestParseArpTableRequiresACompletedEntry.
//
// 0x2 is ATF_COM: the entry was completed by a successful handshake. An
// incomplete or failed entry records that an address was tried, not that
// anything answered, so admitting one reports a device that is not there.
func TestParseArpTableRequiresACompletedEntry(t *testing.T) {
	path := writeArpTable(t,
		arpLine("10.77.0.50", "0x2", "08:00:27:aa:bb:cc", "lan0"),
		arpLine("10.77.0.51", "0x0", "08:00:27:aa:bb:cd", "lan0"),
		arpLine("10.77.0.52", "0x2", "00:00:00:00:00:00", "lan0"),
	)
	useArpTable(t, path)

	got := parseArpTable("10.77.0.1/24", "lan0")
	if len(got) != 1 || got[0].IPv4 != "10.77.0.50" {
		t.Fatalf("expected only the completed entry, got %+v", got)
	}
}

// TestParseArpTableSkipsTheGatewayItself.
//
// The gateway's own address can appear once the interface has talked to it. It
// is not a client, and offering it a speed limit would be offering to shape the
// box against itself.
func TestParseArpTableSkipsTheGatewayItself(t *testing.T) {
	path := writeArpTable(t,
		arpLine("10.77.0.1", "0x2", "08:00:27:aa:bb:cc", "lan0"),
		arpLine("10.77.0.50", "0x2", "08:00:27:aa:bb:cd", "lan0"),
	)
	useArpTable(t, path)

	got := parseArpTable("10.77.0.1/24", "lan0")
	if len(got) != 1 || got[0].IPv4 != "10.77.0.50" {
		t.Fatalf("expected the gateway to be skipped, got %+v", got)
	}
}

// TestParseArpTableWithoutAUsablePrefixDoesNotDiscardEverything.
//
// An unparseable prefix is a misconfiguration, and the honest response is to
// stop filtering by address rather than to drop every neighbour and report an
// empty network. The interface check still applies.
func TestParseArpTableWithoutAUsablePrefixDoesNotDiscardEverything(t *testing.T) {
	path := writeArpTable(t,
		arpLine("172.16.5.9", "0x2", "08:00:27:aa:bb:cc", "lan0"),
	)
	useArpTable(t, path)

	got := parseArpTable("not-a-network", "lan0")
	if len(got) != 1 {
		t.Fatalf("an unparseable prefix must not discard neighbours, got %d", len(got))
	}
}

// TestGatherClientsAppliesBothDirectionsFromTheControlsFile is the end-to-end
// check that the record reaches the device the UI renders.
func TestGatherClientsAppliesBothDirectionsFromTheControlsFile(t *testing.T) {
	dir := t.TempDir()
	writeLeaseFile(t, dir, leaseLine(
		time.Now().Add(4*time.Hour), "08:8f:c3:1b:9c:84", "10.77.0.50", "Laptop",
	))

	restorePaths := leasePathOverride
	restoreNeighbour := neighbourReachableOverride
	leasePathOverride = []string{filepath.Join(dir, "dnsmasq.leases")}
	neighbourReachableOverride = func(string) bool { return true }
	t.Cleanup(func() {
		leasePathOverride = restorePaths
		neighbourReachableOverride = restoreNeighbour
	})

	useControlsFile(t, writeControlsFile(t, `{
  "10.77.0.50": {"download_mbps": 30, "upload_mbps": 10, "direction": "both", "blocked": true}
}`))
	useArpTable(t, writeArpTable(t))

	var cfg config.Config
	cfg.Network.LANPrefix = "10.77.0.1/24"

	col := NewCollector(cfg, nil)
	clients := col.GatherClients(context.Background())

	var found *ClientDevice
	for i := range clients {
		if clients[i].IPv4 == "10.77.0.50" {
			found = &clients[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("the leased client is missing from the inventory: %+v", clients)
	}
	if found.QoSPolicy != "30 Mbps down / 10 Mbps up" {
		t.Fatalf("QoSPolicy = %q, want both directions reported", found.QoSPolicy)
	}
	if found.QoSDirection != "both" {
		t.Fatalf("QoSDirection = %q, want both", found.QoSDirection)
	}
	if found.QoSDownloadMbps != 30 || found.QoSUploadMbps != 10 {
		t.Fatalf("rates reported as down=%d up=%d, want 30/10",
			found.QoSDownloadMbps, found.QoSUploadMbps)
	}
	if !found.Blocked {
		t.Fatal("the blocked flag recorded alongside the limit was not reported")
	}
}
