package execution

import (
	"context"
	"strings"
	"testing"
)

type recordingLinuxRunner struct {
	recordedCommands [][]string
	mockOutputs      map[string]string
}

func newRecordingLinuxRunner() *recordingLinuxRunner {
	return &recordingLinuxRunner{
		mockOutputs: make(map[string]string),
	}
}

func (r *recordingLinuxRunner) LookPath(file string) (string, error) {
	return "/sbin/" + file, nil
}

func (r *recordingLinuxRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := append([]string{name}, args...)
	r.recordedCommands = append(r.recordedCommands, cmd)

	key := strings.Join(cmd, " ")
	for k, out := range r.mockOutputs {
		if strings.HasPrefix(key, k) {
			return out, "", nil
		}
	}
	return "ok", "", nil
}

func TestLinuxDriverOperationsOrder(t *testing.T) {
	ctx := context.Background()
	runner := newRecordingLinuxRunner()
	labCfg := DefaultLabConfig()
	driver := NewLinuxDriver(runner, labCfg)
	driver.labVerified = true // authorized

	// 1. Link state
	err := driver.Execute(ctx, OpLinkSetUp{Interface: "eth1"})
	if err != nil {
		t.Fatalf("link set up failed: %v", err)
	}

	// 2. Address add/delete
	err = driver.Execute(ctx, OpAddressAdd{Interface: "eth1", CIDR: "10.77.0.1/24"})
	if err != nil {
		t.Fatalf("address add failed: %v", err)
	}
	err = driver.Execute(ctx, OpAddressDelete{Interface: "eth1", CIDR: "10.77.0.2/24"})
	if err != nil {
		t.Fatalf("address del failed: %v", err)
	}

	// 3. Sysctl forwarding
	err = driver.Execute(ctx, OpSysctlSet{Key: "net.ipv4.ip_forward", Value: "1"})
	if err != nil {
		t.Fatalf("sysctl set failed: %v", err)
	}

	// 4. Route operations
	err = driver.Execute(ctx, OpRouteAdd{Destination: "default", Gateway: "192.168.100.1", Device: "eth0"})
	if err != nil {
		t.Fatalf("route add failed: %v", err)
	}

	// 5. THN nftables table
	err = driver.Execute(ctx, OpNFTApplyTHNTable{
		InboundPolicy:    "drop",
		AllowEstablished: true,
		AllowLoopback:    true,
		NATInterfaces:    []string{"eth0"},
	})
	if err != nil {
		t.Fatalf("nft apply failed: %v", err)
	}

	// 6. THN nftables delete table (scoped rollback)
	err = driver.Execute(ctx, OpNFTDeleteTHNTable{})
	if err != nil {
		t.Fatalf("nft delete table failed: %v", err)
	}

	// Verify command order and structure
	var flattened []string
	for _, c := range runner.recordedCommands {
		flattened = append(flattened, strings.Join(c, " "))
	}

	expectedPrefixes := []string{
		"ip link set eth1 up",
		"ip addr add 10.77.0.1/24 dev eth1",
		"ip addr del 10.77.0.2/24 dev eth1",
		"sysctl -w net.ipv4.ip_forward=1",
		"ip route add default via 192.168.100.1 dev eth0",
		"nft add table inet thn",
		"nft flush table inet thn",
		"nft add chain inet thn input",
		"nft add chain inet thn forward",
		"nft delete table inet thn",
	}

	for _, ep := range expectedPrefixes {
		found := false
		for _, cmd := range flattened {
			if strings.HasPrefix(cmd, ep) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected command starting with %q in recorded commands:\n%s", ep, strings.Join(flattened, "\n"))
		}
	}

	// Verify that flush ruleset was NEVER recorded!
	for _, cmd := range flattened {
		if strings.Contains(cmd, "flush ruleset") {
			t.Fatalf("CRITICAL SAFETY VIOLATION: flush ruleset was recorded: %s", cmd)
		}
	}
}

func TestLinuxDriverHealthVerification(t *testing.T) {
	ctx := context.Background()
	runner := newRecordingLinuxRunner()
	runner.mockOutputs["ip -j link show eth1"] = `[{"ifname": "eth1", "operstate": "UP", "flags": ["UP", "LOWER_UP"]}]`
	runner.mockOutputs["ip -j addr show eth1"] = `[{"ifname": "eth1", "addr_info": [{"local": "10.77.0.1", "prefixlen": 24}]}]`
	runner.mockOutputs["sysctl -n net.ipv4.ip_forward"] = "1\n"
	runner.mockOutputs["nft list table inet thn"] = "table inet thn { ... }\n"

	driver := NewLinuxDriver(runner, DefaultLabConfig())
	driver.labVerified = true

	checks := []HealthCheck{
		{Target: "eth1", Check: "link_carrier", Expectation: "interface administrative state is UP"},
		{Target: "eth1", Check: "address_assigned", Expectation: "interface eth1 carries CIDR 10.77.0.1/24"},
		{Target: "sysctl:net.ipv4.ip_forward", Check: "kernel_forwarding", Expectation: "net.ipv4.ip_forward equals 1"},
		{Target: "nftables:table inet thn", Check: "firewall_active", Expectation: "table inet thn is active with default policy drop"},
	}

	hr, err := driver.VerifyHealth(ctx, checks)
	if err != nil {
		t.Fatalf("VerifyHealth failed: %v", err)
	}

	if !hr.Healthy {
		t.Errorf("expected healthy, got unhealthy: %s", hr.FailureReason)
	}

	for _, c := range hr.Checks {
		if !c.Passed {
			t.Errorf("check %s on %s failed: %s", c.Check, c.Target, c.Observed)
		}
	}
}
