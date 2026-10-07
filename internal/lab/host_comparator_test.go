package lab

// Tests for the disposable lab host-state safety comparator.
//
// Minimum contract:
//   same semantic route + different harmless metadata  -> equal
//   route added                                         -> different
//   route removed                                       -> different
//   gateway changed                                     -> different
//   device changed                                      -> different
//   destination/prefix changed                          -> different
//   routing table changed                               -> different
//   default route changed                               -> different
//   lab namespace route in host                         -> leak detected

import (
	"strings"
	"testing"
)

func TestCompareHostRoutes_SameSemanticDifferentHarmlessMetadata(t *testing.T) {
	baseline := []HostRoute{
		{
			Destination: "default",
			Gateway:     "192.168.1.1",
			Device:      "eth0",
			Table:       "main",
			Scope:       "global",
			Protocol:    "dhcp",
			Metric:      100,
			Flags:       []string{"onlink"},
		},
		{
			Destination: "192.168.1.0/24",
			Gateway:     "",
			Device:      "eth0",
			Table:       "main",
			Scope:       "link",
			Protocol:    "kernel",
			Metric:      0,
		},
	}

	// Current has different dynamic protocol metadata, different metric churn,
	// ephemeral cache flags, and different order — but identical semantic route path.
	current := []HostRoute{
		{
			Destination: "192.168.1.0/24",
			Gateway:     "",
			Device:      "eth0",
			Table:       "254", // alias for main
			Scope:       "link",
			Protocol:    "systemd", // protocol churn
			Metric:      1024,      // metric churn
			Flags:       []string{"cloned"},
		},
		{
			Destination: "", // empty destination alias for default
			Gateway:     "192.168.1.1",
			Device:      "eth0",
			Table:       "", // default main
			Scope:       "global",
			Protocol:    "boot", // protocol churn
			Metric:      200,    // metric churn
			Flags:       []string{"rt_cache"},
		},
	}

	matched, diffs := CompareHostRoutes(baseline, current)
	if !matched {
		t.Fatalf("expected semantic routes to match despite harmless dynamic metadata churn, got diffs:\n  %s",
			strings.Join(diffs, "\n  "))
	}
}

func TestCompareHostRoutes_RouteAdded(t *testing.T) {
	baseline := []HostRoute{
		{Destination: "default", Gateway: "192.168.1.1", Device: "eth0"},
	}
	current := []HostRoute{
		{Destination: "default", Gateway: "192.168.1.1", Device: "eth0"},
		{Destination: "10.0.0.0/8", Gateway: "192.168.1.254", Device: "eth0"},
	}

	matched, diffs := CompareHostRoutes(baseline, current)
	if matched {
		t.Fatal("expected added route to be detected as different, but comparator reported matched")
	}
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "added route") || !strings.Contains(joined, "10.0.0.0/8") {
		t.Errorf("expected diff to mention added route 10.0.0.0/8, got:\n%s", joined)
	}
}

func TestCompareHostRoutes_RouteRemoved(t *testing.T) {
	baseline := []HostRoute{
		{Destination: "default", Gateway: "192.168.1.1", Device: "eth0"},
		{Destination: "172.16.0.0/12", Gateway: "192.168.1.250", Device: "eth0"},
	}
	current := []HostRoute{
		{Destination: "default", Gateway: "192.168.1.1", Device: "eth0"},
	}

	matched, diffs := CompareHostRoutes(baseline, current)
	if matched {
		t.Fatal("expected removed route to be detected as different, but comparator reported matched")
	}
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "removed route") || !strings.Contains(joined, "172.16.0.0/12") {
		t.Errorf("expected diff to mention removed route 172.16.0.0/12, got:\n%s", joined)
	}
}

func TestCompareHostRoutes_GatewayChanged(t *testing.T) {
	baseline := []HostRoute{
		{Destination: "10.0.0.0/16", Gateway: "192.168.1.1", Device: "eth0"},
	}
	current := []HostRoute{
		{Destination: "10.0.0.0/16", Gateway: "192.168.1.2", Device: "eth0"},
	}

	matched, diffs := CompareHostRoutes(baseline, current)
	if matched {
		t.Fatal("expected gateway change to be detected, but comparator reported matched")
	}
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "gateway changed") && !strings.Contains(joined, "192.168.1.2") {
		t.Errorf("expected diff to mention gateway change, got:\n%s", joined)
	}
}

func TestCompareHostRoutes_DeviceChanged(t *testing.T) {
	baseline := []HostRoute{
		{Destination: "10.0.0.0/16", Gateway: "192.168.1.1", Device: "eth0"},
	}
	current := []HostRoute{
		{Destination: "10.0.0.0/16", Gateway: "192.168.1.1", Device: "eth1"},
	}

	matched, diffs := CompareHostRoutes(baseline, current)
	if matched {
		t.Fatal("expected device change to be detected, but comparator reported matched")
	}
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "device changed") && !strings.Contains(joined, "eth1") {
		t.Errorf("expected diff to mention device change, got:\n%s", joined)
	}
}

func TestCompareHostRoutes_DestinationChanged(t *testing.T) {
	baseline := []HostRoute{
		{Destination: "10.10.0.0/24", Gateway: "192.168.1.1", Device: "eth0"},
	}
	current := []HostRoute{
		{Destination: "10.10.1.0/24", Gateway: "192.168.1.1", Device: "eth0"},
	}

	matched, diffs := CompareHostRoutes(baseline, current)
	if matched {
		t.Fatal("expected destination prefix change to be detected, but comparator reported matched")
	}
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "added route") || !strings.Contains(joined, "removed route") {
		t.Errorf("expected diff to mention destination change via added/removed, got:\n%s", joined)
	}
}

func TestCompareHostRoutes_RoutingTableChanged(t *testing.T) {
	baseline := []HostRoute{
		{Destination: "10.0.0.0/16", Gateway: "192.168.1.1", Device: "eth0", Table: "main"},
	}
	current := []HostRoute{
		{Destination: "10.0.0.0/16", Gateway: "192.168.1.1", Device: "eth0", Table: "100"},
	}

	matched, diffs := CompareHostRoutes(baseline, current)
	if matched {
		t.Fatal("expected routing table change to be detected, but comparator reported matched")
	}
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "table") {
		t.Errorf("expected diff to reflect routing table change, got:\n%s", joined)
	}
}

func TestCompareHostRoutes_DefaultRouteChanged(t *testing.T) {
	baseline := []HostRoute{
		{Destination: "default", Gateway: "192.168.1.1", Device: "eth0"},
	}
	current := []HostRoute{
		{Destination: "default", Gateway: "192.168.1.254", Device: "eth0"},
	}

	matched, diffs := CompareHostRoutes(baseline, current)
	if matched {
		t.Fatal("expected default route change to be detected, but comparator reported matched")
	}
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, "default route changed") && !strings.Contains(joined, "gateway changed") {
		t.Errorf("expected diff to mention default route change, got:\n%s", joined)
	}
}

func TestVerifyNoLabRoutesInHost(t *testing.T) {
	cleanRoutes := []HostRoute{
		{Destination: "default", Gateway: "192.168.1.1", Device: "eth0"},
		{Destination: "192.168.1.0/24", Gateway: "", Device: "eth0"},
	}
	leaks := VerifyNoLabRoutesInHost(cleanRoutes)
	if len(leaks) != 0 {
		t.Fatalf("clean host reported leaks: %v", leaks)
	}

	leakedRoutes := []HostRoute{
		{Destination: "default", Gateway: "192.168.1.1", Device: "eth0"},
		{Destination: "10.77.0.0/24", Gateway: "10.77.0.1", Device: "thnlan0"},
	}
	leaks = VerifyNoLabRoutesInHost(leakedRoutes)
	if len(leaks) == 0 {
		t.Fatal("leaked lab LAN route was not detected in host routing table")
	}
	if !strings.Contains(leaks[0], "10.77.0.0/24") {
		t.Errorf("expected leak to name 10.77.0.0/24, got: %v", leaks)
	}
}
