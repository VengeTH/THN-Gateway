package execution

import (
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/planner"
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

		// QDisc ops
		{"valid qdisc cake", OpQDiscApply{Interface: "eth0", Algorithm: "cake", DownloadKbps: 50000, UploadKbps: 10000}, false},
		{"valid qdisc fq_codel", OpQDiscApply{Interface: "eth0", Algorithm: "fq_codel"}, false},
		{"invalid qdisc algorithm", OpQDiscApply{Interface: "eth0", Algorithm: "unknown_algo"}, true},
		{"valid qdisc delete", OpQDiscDelete{Interface: "eth0"}, false},

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
