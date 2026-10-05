package execution

// M6.2 unit coverage for the two production behaviours the end-to-end lab
// depends on: the gateway forwarding rules THN installs, and the real-traffic
// health checks that decide whether a gateway is working.
//
// # What kind of test these are
//
// UNIT. They assert the commands the driver builds and the way the driver
// judges a probe result. They are not a substitute for internal/lab, which
// proves those commands are accepted by a real kernel and carry a real packet.
// The split is deliberate: a unit test that proved the end-to-end claim would
// be the same claim with the evidence removed, and a live test that also
// covered this would be slow for a question about string building.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/planner"
)

// gatewayTable is the THN nftables operation for a resolved gateway.
func gatewayTable() OpNFTApplyTHNTable {
	return OpNFTApplyTHNTable{
		InboundPolicy:    "drop",
		AllowEstablished: true,
		AllowLoopback:    true,
		NATInterfaces:    []string{"thnwan0"},
		LANInterface:     "thnlan0",
		WANInterface:     "thnwan0",
		LANSubnet:        "10.77.0.0/24",
	}
}

// flatten renders recorded commands for substring assertions.
func flatten(cmds [][]string) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// TestNFTApplyInstallsGatewayForwardingRules is the unit half of the
// LAN → WAN / WAN → LAN claim.
//
// The forward chain's policy is drop. A drop policy with no accept rule blocks
// everything, including the traffic a gateway exists to carry, so the presence
// of this rule is the difference between a firewall and a wall.
func TestNFTApplyInstallsGatewayForwardingRules(t *testing.T) {
	ctx := context.Background()
	runner := newRecordingLinuxRunner()
	driver := NewLinuxDriver(runner, DefaultLabConfig())
	driver.labVerified = true

	if err := driver.Execute(ctx, gatewayTable()); err != nil {
		t.Fatalf("applying the THN table failed: %v", err)
	}

	cmds := flatten(runner.recordedCommands)
	joined := strings.Join(cmds, "\n")

	want := []string{
		"add rule inet thn forward iifname thnlan0 oifname thnwan0 ip saddr 10.77.0.0/24 accept",
		"add rule inet thn forward ct state established,related accept",
		"add rule inet thn input iifname thnlan0 ip saddr 10.77.0.0/24 accept",
		"add rule inet thn postrouting oifname thnwan0 masquerade",
	}
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("expected rule not installed:\n  %s\nrecorded:\n%s", w, joined)
		}
	}

	// The reverse direction must have no accept rule at all. With a drop
	// policy, its absence is the isolation — and a test that only asserted
	// the forward rule would pass just as happily if the reverse one existed.
	for _, cmd := range cmds {
		if strings.Contains(cmd, "forward") && strings.Contains(cmd, "iifname thnwan0") {
			t.Errorf("a rule permits traffic from the WAN into the forward chain: %s", cmd)
		}
		if strings.Contains(cmd, "iifname thnlan0 oifname thnlan0") {
			t.Errorf("a rule hairpins the LAN onto itself: %s", cmd)
		}
	}

	for _, cmd := range cmds {
		if strings.Contains(cmd, "flush ruleset") {
			t.Fatalf("CRITICAL SAFETY VIOLATION: %s", cmd)
		}
	}
}

// TestNFTApplyWithoutResolvedRolesInstallsNoForwardingRule pins the failure
// mode where the plan cannot say which way is out.
//
// With only one side resolved there is no direction to permit, so THN must not
// invent one. A rule built from a guessed pair is a rule that could open the
// wrong direction.
func TestNFTApplyWithoutResolvedRolesInstallsNoForwardingRule(t *testing.T) {
	cases := []struct {
		name string
		op   OpNFTApplyTHNTable
	}{
		{"no interfaces at all", OpNFTApplyTHNTable{InboundPolicy: "drop"}},
		{"LAN only", OpNFTApplyTHNTable{InboundPolicy: "drop", LANInterface: "thnlan0"}},
		{"WAN only", OpNFTApplyTHNTable{InboundPolicy: "drop", WANInterface: "thnwan0"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.op.GatewayPath() {
				t.Fatalf("%s reports a gateway path with only one side resolved", c.name)
			}

			ctx := context.Background()
			runner := newRecordingLinuxRunner()
			driver := NewLinuxDriver(runner, DefaultLabConfig())
			driver.labVerified = true

			if err := driver.Execute(ctx, c.op); err != nil {
				t.Fatalf("applying the THN table failed: %v", err)
			}

			for _, cmd := range flatten(runner.recordedCommands) {
				if strings.Contains(cmd, "accept") && strings.Contains(cmd, "iifname") {
					t.Errorf("a rule was installed from an unresolved direction: %s", cmd)
				}
			}
		})
	}
}

// TestNFTApplyRejectsADegenerateGateway keeps a gateway from routing out of its
// own ingress.
func TestNFTApplyRejectsADegenerateGateway(t *testing.T) {
	op := gatewayTable()
	op.WANInterface = op.LANInterface

	if err := op.Validate(); err == nil {
		t.Error("LAN and WAN resolved to the same interface must be rejected")
	}

	op = gatewayTable()
	op.LANSubnet = "not-a-prefix"
	if err := op.Validate(); err == nil {
		t.Error("an unparseable LAN subnet must be rejected")
	}

	op = gatewayTable()
	op.LANInterface = "thnlan0; rm -rf /"
	if err := op.Validate(); err == nil {
		t.Error("an interface name carrying shell metacharacters must be rejected")
	}
}

// stubProber answers with a scripted result.
type stubProber struct {
	result ProbeResult
	err    error
	seen   []string
}

func (p *stubProber) Probe(ctx context.Context, side, endpoint string, _ time.Duration) (ProbeResult, error) {
	p.seen = append(p.seen, side+"->"+endpoint)
	return p.result, p.err
}

func newProbedDriver(result ProbeResult, err error) (*LinuxDriver, *stubProber) {
	runner := newRecordingLinuxRunner()
	prober := &stubProber{result: result, err: err}
	driver := NewLinuxDriver(runner, DefaultLabConfig()).SetTrafficProber(prober)
	driver.labVerified = true
	return driver, prober
}

func TestTrafficHealthCheckPassesOnlyWhenThePathWorks(t *testing.T) {
	cases := []struct {
		name        string
		check       string
		result      ProbeResult
		wantPass    bool
		wantHandled bool
	}{
		{
			name:        "lan to wan reached",
			check:       "lan_to_wan_traffic",
			result:      ProbeResult{Reachable: true, SourceAddress: "10.77.0.100", ObservedSource: "10.77.250.1"},
			wantPass:    true,
			wantHandled: true,
		},
		{
			name:        "lan to wan refused",
			check:       "lan_to_wan_traffic",
			result:      ProbeResult{Reachable: false, Error: "connection refused"},
			wantPass:    false,
			wantHandled: true,
		},
		{
			name:        "wan to lan still reachable",
			check:       "wan_to_lan_blocked",
			result:      ProbeResult{Reachable: true, ObservedSource: "10.77.0.100"},
			wantPass:    false,
			wantHandled: true,
		},
		{
			name:        "wan to lan blocked",
			check:       "wan_to_lan_blocked",
			result:      ProbeResult{Reachable: false, Error: "i/o timeout"},
			wantPass:    true,
			wantHandled: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			driver, _ := newProbedDriver(c.result, nil)
			hr, err := driver.VerifyHealth(context.Background(), []HealthCheck{
				{Target: "10.77.250.2:18080", Check: c.check, Expectation: "the traffic path behaves"},
			})
			if err != nil {
				t.Fatalf("VerifyHealth returned an error: %v", err)
			}
			if len(hr.Checks) != 1 {
				t.Fatalf("got %d check results, want 1", len(hr.Checks))
			}
			if hr.Healthy != c.wantPass {
				t.Errorf("healthy = %v, want %v (observed %q, error %q)",
					hr.Healthy, c.wantPass, hr.Checks[0].Observed, hr.Checks[0].Error)
			}
		})
	}
}

// TestTrafficHealthCheckWithoutAProberIsNotAPass is the check this milestone
// most needed.
//
// A driver that cannot open a connection must say so. Reporting a pass — or
// omitting the check — would let a gateway that routes nothing be declared
// healthy, which is the exact failure mode structural checks alone cannot see.
func TestTrafficHealthCheckWithoutAProberIsNotAPass(t *testing.T) {
	runner := newRecordingLinuxRunner()
	driver := NewLinuxDriver(runner, DefaultLabConfig())
	driver.labVerified = true

	hr, err := driver.VerifyHealth(context.Background(), []HealthCheck{
		{Target: "10.77.250.2:18080", Check: "lan_to_wan_traffic", Expectation: "traffic flows"},
	})
	if err != nil {
		t.Fatalf("VerifyHealth returned an error: %v", err)
	}
	if hr.Healthy {
		t.Error("a traffic check passed with no prober configured")
	}
	if !strings.Contains(hr.FailureReason, "one or more health checks failed") {
		t.Errorf("failure reason = %q, want it to name the failure", hr.FailureReason)
	}
}

// TestTrafficHealthCheckDistinguishesAnUnrunnableProbe keeps "I could not try"
// separate from "it failed". Both are unhealthy, and conflating them would make
// a harness fault look like a firewall verdict.
func TestTrafficHealthCheckDistinguishesAnUnrunnableProbe(t *testing.T) {
	driver, _ := newProbedDriver(ProbeResult{}, errors.New("namespace missing"))

	hr, _ := driver.VerifyHealth(context.Background(), []HealthCheck{
		{Target: "10.77.250.2:18080", Check: "lan_to_wan_traffic", Expectation: "traffic flows"},
	})
	if hr.Healthy {
		t.Fatal("an unrunnable probe reported health")
	}
	if hr.Checks[0].Observed != "probe could not be executed" {
		t.Errorf("observed = %q, want it to distinguish an unrunnable probe", hr.Checks[0].Observed)
	}
}

// TestUnknownHealthCheckFailsClosed closes the hole where a plan could carry a
// check this build does not understand and have it reported as satisfied.
func TestUnknownHealthCheckFailsClosed(t *testing.T) {
	driver, _ := newProbedDriver(ProbeResult{Reachable: true}, nil)

	hr, _ := driver.VerifyHealth(context.Background(), []HealthCheck{
		{Target: "anything", Check: "does_the_moon_turn_around", Expectation: "yes"},
	})
	if hr.Healthy {
		t.Fatal("an unknown health check passed")
	}
	if !strings.Contains(hr.Checks[0].Error, "unsupported health check") {
		t.Errorf("error = %q, want it to name the unsupported check", hr.Checks[0].Error)
	}
}

// TestNATMasqueradeCheckReadsTheRealTable covers the check the planner has
// always emitted and the driver used to accept without looking at anything.
func TestNATMasqueradeCheckReadsTheRealTable(t *testing.T) {
	cases := []struct {
		name     string
		table    string
		wantPass bool
	}{
		{
			name:     "masquerade present",
			table:    "table inet thn {\n chain postrouting {\n  oifname \"thnwan0\" masquerade\n }\n}\n",
			wantPass: true,
		},
		{
			name:     "no masquerade",
			table:    "table inet thn {\n chain postrouting {\n  type nat hook postrouting; accept\n }\n}\n",
			wantPass: false,
		},
		{
			name:     "no postrouting chain",
			table:    "table inet thn {\n chain forward {\n  accept\n }\n}\n",
			wantPass: false,
		},
		{
			name:     "masquerade for a different interface",
			table:    "table inet thn {\n chain postrouting {\n  oifname \"eth0\" masquerade\n }\n}\n",
			wantPass: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runner := newRecordingLinuxRunner()
			runner.mockOutputs["nft list table inet thn"] = c.table
			driver := NewLinuxDriver(runner, DefaultLabConfig())
			driver.labVerified = true

			hr, _ := driver.VerifyHealth(context.Background(), []HealthCheck{{
				Target:      "nftables:masquerade",
				Check:       "nat_masquerade",
				Expectation: "masquerade rule active for thnwan0",
			}})
			if hr.Healthy != c.wantPass {
				t.Errorf("healthy = %v, want %v (observed %q)", hr.Healthy, c.wantPass, hr.Checks[0].Observed)
			}
		})
	}
}

// TestPlanCarriesTheLANSubnetIntoTheFirewall covers both sources the subnet
// can come from.
//
// A gateway's first transaction states the address and installs the firewall
// together; its second installs only the firewall, because the address is
// already right. If the second found no subnet, it would silently install a
// looser forwarding rule than the first — and a test that only exercised the
// first would never see it.
func TestPlanCarriesTheLANSubnetIntoTheFirewall(t *testing.T) {
	cases := []struct {
		name        string
		lanObserved []string
	}{
		{"first transaction also assigns the address", nil},
		{"later transaction only installs the firewall", []string{"10.77.0.1/24"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs := diff.Observed{
				Supported:           true,
				HostName:            "thn-lab",
				WANName:             "thnwan0",
				WANPresent:          true,
				WANUp:               true,
				LANName:             "thnlan0",
				LANPresent:          true,
				LANUp:               true,
				LANAddresses:        c.lanObserved,
				DefaultGateway:      "10.77.250.2",
				HasDefaultRoute:     true,
				IPv4Forwarding:      true,
				IPv4ForwardingKnown: true,
			}
			des := desired.State{
				WAN:        desired.Interface{Name: "thnwan0", Up: true, Present: true},
				LAN:        desired.Interface{Name: "thnlan0", Up: true, Present: true, Addresses: []string{"10.77.0.1/24"}},
				Addressing: desired.Addressing{DefaultGateway: "10.77.250.2", UpstreamPresent: true, IPv4Forwarding: true},
				NAT:        desired.NAT{Enabled: true, Resolved: true, Interfaces: []string{"thnwan0"}},
				Firewall:   desired.Firewall{Enabled: true, Backend: "nftables", DefaultInboundPolicy: "drop"},
				Generation: 1,
			}

			plan := planner.Build(diff.Compare(obs, diff.Desired{
				WANName:         des.WAN.Name,
				WANPresent:      des.WAN.Present,
				WANUp:           des.WAN.Up,
				LANName:         des.LAN.Name,
				LANPresent:      des.LAN.Present,
				LANUp:           des.LAN.Up,
				LANAddresses:    des.LAN.Addresses,
				DefaultGateway:  des.Addressing.DefaultGateway,
				IPv4Forwarding:  des.Addressing.IPv4Forwarding,
				FirewallEnabled: des.Firewall.Enabled,
			}), planner.Options{Generation: 1, Observed: obs, Desired: des, Live: true})

			ops, err := PlanToOperations(plan, obs)
			if err != nil {
				t.Fatalf("translating the plan failed: %v", err)
			}

			var firewall OpNFTApplyTHNTable
			found := false
			for _, op := range ops {
				if o, ok := op.(OpNFTApplyTHNTable); ok {
					firewall, found = o, true
				}
			}
			if !found {
				t.Fatalf("no firewall operation was produced; steps were %d", len(ops))
			}

			if firewall.LANSubnet != "10.77.0.0/24" {
				t.Errorf("firewall LAN subnet = %q, want 10.77.0.0/24", firewall.LANSubnet)
			}
			if !firewall.GatewayPath() {
				t.Errorf("firewall has no gateway path: %+v", firewall)
			}
		})
	}
}

// TestEmptyHealthCheckListIsNotHealth closes the last fail-open in the
// evaluation path.
//
// With no checks the loop below never runs, every flag stays true, and a
// gateway nobody asked a question about gets certified. It is the same
// fail-open as an unrecognised check one step later in the same function, and
// it is reachable from any plan whose verification block is empty.
func TestEmptyHealthCheckListIsNotHealth(t *testing.T) {
	runner := newRecordingLinuxRunner()
	driver := NewLinuxDriver(runner, DefaultLabConfig())
	driver.labVerified = true

	for _, checks := range [][]HealthCheck{nil, {}} {
		hr, err := driver.VerifyHealth(context.Background(), checks)
		if err != nil {
			t.Fatalf("VerifyHealth(%v) returned an error: %v", checks, err)
		}
		if hr.Healthy {
			t.Errorf("VerifyHealth(%v) reported health with nothing to verify", checks)
		}
		if !strings.Contains(hr.FailureReason, "no health checks") {
			t.Errorf("failure reason = %q, want it to say no checks were supplied", hr.FailureReason)
		}
	}
}

// TestAddressCheckReadsThePlannedCIDR pins the change from a hardcoded address
// to the one the plan actually asked for.
func TestAddressCheckReadsThePlannedCIDR(t *testing.T) {
	runner := newRecordingLinuxRunner()
	runner.mockOutputs["ip -j addr show thnlan0"] =
		`[{"ifname":"thnlan0","addr_info":[{"local":"192.168.50.1","prefixlen":24}]}]`
	driver := NewLinuxDriver(runner, DefaultLabConfig())
	driver.labVerified = true

	hr, _ := driver.VerifyHealth(context.Background(), []HealthCheck{
		{Target: "thnlan0", Check: "address_assigned", Expectation: "interface thnlan0 carries CIDR 10.77.0.1/24"},
	})
	if hr.Healthy {
		t.Error("a check passed for an address the interface does not carry")
	}

	runner.mockOutputs["ip -j addr show thnlan0"] =
		`[{"ifname":"thnlan0","addr_info":[{"local":"10.77.0.1","prefixlen":24}]}]`
	hr, _ = driver.VerifyHealth(context.Background(), []HealthCheck{
		{Target: "thnlan0", Check: "address_assigned", Expectation: "interface thnlan0 carries CIDR 10.77.0.1/24"},
	})
	if !hr.Healthy {
		t.Errorf("a check failed for an address the interface does carry: %s", hr.Checks[0].Observed)
	}
}
