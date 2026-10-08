package execution

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/planner"
	qostc "github.com/VengeTH/THN-Gateway/internal/qos/tc"
)

func TestStructuredOperationsValidation(t *testing.T) {
	tests := []struct {
		name    string
		op      Operation
		wantErr bool
	}{
		// Link ops
		{"valid link up", OpLinkSetUp{Interface: "eth1"}, false},
		{"valid link down", OpLinkSetDown{Interface: "eth1"}, false},
		{"invalid link iface name", OpLinkSetUp{Interface: "eth1;rm -rf"}, true},
		{"empty link iface", OpLinkSetUp{Interface: ""}, true},

		// Address ops
		{"valid address add", OpAddressAdd{Interface: "eth1", CIDR: "10.77.0.1/24"}, false},
		{"valid address delete", OpAddressDelete{Interface: "eth1", CIDR: "10.77.0.1/24"}, false},
		{"invalid address CIDR", OpAddressAdd{Interface: "eth1", CIDR: "999.999.999.999/24"}, true},
		{"missing address prefix", OpAddressAdd{Interface: "eth1", CIDR: "10.77.0.1"}, true},

		// Route ops
		{"valid route default", OpRouteAdd{Destination: "default", Gateway: "192.168.1.1", Device: "eth0"}, false},
		{"valid route subnet", OpRouteAdd{Destination: "10.0.0.0/8", Gateway: "10.77.0.254"}, false},
		{"invalid route gateway", OpRouteAdd{Destination: "default", Gateway: "not-an-ip"}, true},
		{"valid route replace", OpRouteReplace{Destination: "default", Gateway: "192.168.1.254"}, false},
		{"valid route delete", OpRouteDelete{Destination: "default"}, false},

		// Sysctl ops
		{"valid forwarding 1", OpSysctlSet{Key: "net.ipv4.ip_forward", Value: "1"}, false},
		{"valid forwarding 0", OpSysctlSet{Key: "net.ipv4.ip_forward", Value: "0"}, false},
		{"invalid sysctl key", OpSysctlSet{Key: "kernel.hostname", Value: "evil"}, true},
		{"invalid sysctl value", OpSysctlSet{Key: "net.ipv4.ip_forward", Value: "2"}, true},

		// NFTables ops
		{"valid nft thn table drop", OpNFTApplyTHNTable{InboundPolicy: "drop", AllowEstablished: true, AllowLoopback: true, NATInterfaces: []string{"eth0"}}, false},
		{"valid nft thn table accept", OpNFTApplyTHNTable{InboundPolicy: "accept", AllowEstablished: true, AllowLoopback: true}, false},
		{"invalid nft inbound policy", OpNFTApplyTHNTable{InboundPolicy: "reject"}, true},
		{"invalid nft NAT iface", OpNFTApplyTHNTable{InboundPolicy: "drop", NATInterfaces: []string{"eth0;evil"}}, true},
		{"valid nft delete table", OpNFTDeleteTHNTable{}, false},

		// QDisc ops.
		//
		// An apply now names ONE direction and carries that direction's rate.
		// The M7.4 form — one operation with both DownloadKbps and
		// UploadKbps, and no direction — could only have produced a
		// single discipline, which on a gateway shapes exactly one of the
		// two rates the operator asked for.
		{"valid qdisc cake upload", OpQDiscApply{Interface: "eth0", Algorithm: "cake", Direction: qostc.DirectionUpload, Kbps: 10000}, false},
		{"valid qdisc cake download", OpQDiscApply{Interface: "eth1", Algorithm: "cake", Direction: qostc.DirectionDownload, Kbps: 50000}, false},
		{"valid qdisc fq_codel", OpQDiscApply{Interface: "eth0", Algorithm: "fq_codel", Direction: qostc.DirectionUpload, Kbps: 10000}, false},
		{"invalid qdisc algorithm", OpQDiscApply{Interface: "eth0", Algorithm: "unknown_algo", Direction: qostc.DirectionUpload, Kbps: 10000}, true},
		// A rate-unaware discipline cannot enforce a limit, so installing
		// one as the requested policy would be a silent downgrade.
		{"qdisc pfifo_fast as an apply", OpQDiscApply{Interface: "eth0", Algorithm: "pfifo_fast", Direction: qostc.DirectionUpload, Kbps: 10000}, true},
		// An apply with no rate is the exact shape PlanToOperations used to
		// produce by dropping the configured figures.
		{"qdisc with no rate", OpQDiscApply{Interface: "eth0", Algorithm: "cake", Direction: qostc.DirectionUpload}, true},
		// A qdisc shapes one direction; an unnamed one cannot be built.
		{"qdisc with no direction", OpQDiscApply{Interface: "eth0", Algorithm: "cake", Kbps: 10000}, true},
		{"valid qdisc delete", OpQDiscDelete{Interface: "eth0"}, false},

		// TC Class ops
		{"valid tc class", OpTCClassApply{Interface: "eth0", Parent: "1:1", ClassID: "1:10", RateKbps: 1000, CeilKbps: 5000, Priority: 1}, false},
		{"invalid tc class iface", OpTCClassApply{Interface: "eth0;evil", Parent: "1:1", ClassID: "1:10", RateKbps: 1000, CeilKbps: 5000}, true},
		{"valid tc class delete", OpTCClassDelete{Interface: "eth0", ClassID: "1:10"}, false},

		// TC Filter ops
		{"valid tc filter fw", OpTCFilterApply{Interface: "eth0", Parent: "1:", Protocol: "ip", Prio: 1, Handle: "0x10", MatchKind: "fw", TargetClassID: "1:10"}, false},
		{"valid tc filter ip", OpTCFilterApply{Interface: "eth0", Parent: "1:", Protocol: "ip", Prio: 2, IP: "10.77.0.100", MatchKind: "src_ip", TargetClassID: "1:10"}, false},
		{"invalid tc filter iface", OpTCFilterApply{Interface: "eth0;evil", Parent: "1:", TargetClassID: "1:10"}, true},
		{"valid tc filter delete", OpTCFilterDelete{Interface: "eth0", Parent: "1:", Prio: 1}, false},

		// DNS ops
		{"valid dns", OpDNSApply{Servers: []string{"1.1.1.1", "9.9.9.9"}}, false},
		{"invalid dns IP", OpDNSApply{Servers: []string{"not-an-ip"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.op.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestStructuredOperationsRollbackGeneration(t *testing.T) {
	// 1. Link Up -> Link Down
	up := OpLinkSetUp{Interface: "eth1"}
	if rb, ok := up.RollbackOp().(OpLinkSetDown); !ok || rb.Interface != "eth1" {
		t.Errorf("expected OpLinkSetDown rollback for OpLinkSetUp, got %v", up.RollbackOp())
	}

	// 2. Link Down -> Link Up
	down := OpLinkSetDown{Interface: "eth1"}
	if rb, ok := down.RollbackOp().(OpLinkSetUp); !ok || rb.Interface != "eth1" {
		t.Errorf("expected OpLinkSetUp rollback for OpLinkSetDown, got %v", down.RollbackOp())
	}

	// 3. Address Add -> Address Delete
	add := OpAddressAdd{Interface: "eth1", CIDR: "10.77.0.1/24"}
	if rb, ok := add.RollbackOp().(OpAddressDelete); !ok || rb.Interface != "eth1" || rb.CIDR != "10.77.0.1/24" {
		t.Errorf("expected OpAddressDelete rollback for OpAddressAdd, got %v", add.RollbackOp())
	}

	// 4. Sysctl Set 1 -> Sysctl Set 0
	fwd := OpSysctlSet{Key: "net.ipv4.ip_forward", Value: "1", PreviousValue: "0"}
	if rb, ok := fwd.RollbackOp().(OpSysctlSet); !ok || rb.Key != "net.ipv4.ip_forward" || rb.Value != "0" {
		t.Errorf("expected OpSysctlSet(0) rollback for OpSysctlSet(1), got %v", fwd.RollbackOp())
	}

	// 5. NFT Apply -> NFT Delete Table (SCOPED TO INET THN ONLY)
	nft := OpNFTApplyTHNTable{InboundPolicy: "drop"}
	if _, ok := nft.RollbackOp().(OpNFTDeleteTHNTable); !ok {
		t.Errorf("expected OpNFTDeleteTHNTable rollback for OpNFTApplyTHNTable, got %v", nft.RollbackOp())
	}

	// 6. Route Add -> Route Delete
	rAdd := OpRouteAdd{Destination: "default", Gateway: "192.168.1.1"}
	if rb, ok := rAdd.RollbackOp().(OpRouteDelete); !ok || rb.Destination != "default" {
		t.Errorf("expected OpRouteDelete rollback for OpRouteAdd, got %v", rAdd.RollbackOp())
	}

	// 7. Route Replace with previous gateway -> Route Replace
	rRep := OpRouteReplace{Destination: "default", Gateway: "192.168.1.100", PreviousGateway: "192.168.1.1"}
	if rb, ok := rRep.RollbackOp().(OpRouteReplace); !ok || rb.Gateway != "192.168.1.1" {
		t.Errorf("expected OpRouteReplace rollback, got %v", rRep.RollbackOp())
	}
}

// TestAddressRemoveDeletesOnlyObsoleteAddresses guards the execution path of
// `lan-address-remove`.
//
// The step's Current and Desired fields are whole SETS, for readability: an
// operator reading `thn plan` needs to see the interface's full observed
// addressing beside the full configured addressing. Acting on Current as though
// it were the deletion list makes the gateway remove the address the desired
// state explicitly asks for — taking its own LAN address off the LAN — and
// then putting it back during rollback.
func TestAddressRemoveDeletesOnlyObsoleteAddresses(t *testing.T) {
	const keep = "10.77.0.1/24"

	obs := diff.Observed{
		Supported:           true,
		LANPresent:          true,
		LANName:             "eth1",
		WANPresent:          true,
		WANName:             "eth0",
		LANUp:               true,
		WANUp:               true,
		IPv4Forwarding:      true,
		IPv4ForwardingKnown: true,
		LANAddresses:        []string{keep, "192.168.99.1/24"},
	}

	p := planner.Build(diff.Compare(obs, diff.Desired{
		WANName:      "eth0",
		WANPresent:   true,
		WANUp:        true,
		LANName:      "eth1",
		LANPresent:   true,
		LANUp:        true,
		LANAddresses: []string{keep},
	}), planner.Options{Generation: 1, Observed: obs})

	var removes []string
	for _, op := range mustOps(t, p, obs) {
		if d, ok := op.(OpAddressDelete); ok {
			removes = append(removes, d.CIDR)
		}
	}

	if len(removes) != 1 || removes[0] != "192.168.99.1/24" {
		t.Fatalf("removed addresses = %v, want exactly [192.168.99.1/24]; the configured "+
			"address %s must never be deleted by an obsolete-address step", removes, keep)
	}
}

// TestAddressRemoveDeletesKernelLinkLocal checks the case the disposable lab
// hit: the interface carries the configured address plus the IPv6 link-local
// the kernel assigns to any link it brings up.
//
// The link-local is not in the desired state, so the diff reports it as extra.
// It is the only address that may be deleted, and deleting it is at worst a
// no-op the kernel immediately reverses.
func TestAddressRemoveDeletesKernelLinkLocal(t *testing.T) {
	const (
		keep      = "10.77.0.1/24"
		linkLocal = "fe80::8a3c:2200:0:2/64"
	)

	obs := diff.Observed{
		Supported:           true,
		LANPresent:          true,
		LANName:             "eth1",
		WANPresent:          true,
		WANName:             "eth0",
		LANUp:               true,
		WANUp:               true,
		IPv4Forwarding:      true,
		IPv4ForwardingKnown: true,
		LANAddresses:        []string{keep, linkLocal},
	}

	p := planner.Build(diff.Compare(obs, diff.Desired{
		WANName:      "eth0",
		WANPresent:   true,
		WANUp:        true,
		LANName:      "eth1",
		LANPresent:   true,
		LANUp:        true,
		LANAddresses: []string{keep},
	}), planner.Options{Generation: 1, Observed: obs})

	var removes []string
	for _, op := range mustOps(t, p, obs) {
		if d, ok := op.(OpAddressDelete); ok {
			removes = append(removes, d.CIDR)
		}
	}

	for _, r := range removes {
		if r == keep {
			t.Errorf("the operation would delete the configured LAN address %s; "+
				"Current is a set, not a deletion list", keep)
		}
	}
	if len(removes) > 1 {
		t.Errorf("removed addresses = %v, want at most the one extra address", removes)
	}
}

func mustOps(t *testing.T, p *planner.Plan, obs diff.Observed) []Operation {
	t.Helper()
	ops, err := PlanToOperations(p, obs)
	if err != nil {
		t.Fatalf("PlanToOperations failed: %v", err)
	}
	return ops
}

func TestPlanToOperationsConversion(t *testing.T) {
	obs := diff.Observed{
		Supported:           true,
		HostName:            "lab-vm",
		WANName:             "eth0",
		WANPresent:          true,
		WANUp:               true,
		LANName:             "eth1",
		LANPresent:          true,
		LANUp:               false,
		LANAddresses:        []string{},
		DefaultGateway:      "192.168.100.1",
		HasDefaultRoute:     true,
		IPv4Forwarding:      false,
		IPv4ForwardingKnown: true,
		FirewallActive:      false,
	}

	des := desired.State{
		Name:       "thn-gateway",
		Generation: 1,
		WAN: desired.Interface{
			Name:    "eth0",
			Role:    desired.RoleWAN,
			MTU:     1500,
			Up:      true,
			Present: true,
		},
		LAN: desired.Interface{
			Name:      "eth1",
			Role:      desired.RoleLAN,
			MTU:       1500,
			Up:        true,
			Present:   true,
			Addresses: []string{"10.77.0.1/24"},
		},
		Addressing: desired.Addressing{
			DefaultGateway:  "192.168.100.1",
			UpstreamPresent: true,
			IPv4Forwarding:  true,
		},
		NAT: desired.NAT{
			Enabled:    true,
			Resolved:   true,
			Interfaces: []string{"eth0"},
		},
		Firewall: desired.Firewall{
			Enabled:              true,
			Backend:              "nftables",
			DefaultInboundPolicy: "drop",
			AllowEstablished:     true,
			AllowLoopback:        true,
		},
	}

	d := diff.Compare(obs, diff.Desired{
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
	})

	assignments := []host.Assignment{
		{Role: host.RoleWAN, Selector: "eth0"},
		{Role: host.RoleLAN, Selector: "eth1"},
	}

	p := planner.Build(d, planner.Options{
		Generation:  1,
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Live:        true,
	})

	ops, err := PlanToOperations(p, obs)
	if err != nil {
		t.Fatalf("PlanToOperations failed: %v", err)
	}

	if len(ops) == 0 {
		t.Fatal("expected operations to be generated, got 0")
	}

	hasLinkUp := false
	hasAddrAdd := false
	hasFwd := false
	hasNFT := false

	for _, op := range ops {
		switch o := op.(type) {
		case OpLinkSetUp:
			if o.Interface == "eth1" {
				hasLinkUp = true
			}
		case OpAddressAdd:
			if o.Interface == "eth1" && o.CIDR == "10.77.0.1/24" {
				hasAddrAdd = true
			}
		case OpSysctlSet:
			if o.Key == "net.ipv4.ip_forward" && o.Value == "1" {
				hasFwd = true
			}
		case OpNFTApplyTHNTable:
			if strings.EqualFold(o.InboundPolicy, "drop") {
				hasNFT = true
			}
		}
	}

	if !hasLinkUp {
		t.Error("missing OpLinkSetUp for eth1")
	}
	if !hasAddrAdd {
		t.Error("missing OpAddressAdd 10.77.0.1/24 for eth1")
	}
	if !hasFwd {
		t.Error("missing OpSysctlSet net.ipv4.ip_forward=1")
	}
	if !hasNFT {
		t.Error("missing OpNFTApplyTHNTable")
	}
}
