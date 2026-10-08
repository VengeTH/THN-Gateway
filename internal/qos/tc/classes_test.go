package tc

import (
	"strings"
	"testing"
)

func TestHTBRootArgs(t *testing.T) {
	args, err := HTBRootArgs("eth0", "99")
	if err != nil {
		t.Fatalf("HTBRootArgs failed: %v", err)
	}
	want := "qdisc replace dev eth0 root handle 1: htb default 99"
	if Join(args) != want {
		t.Errorf("got %q, want %q", Join(args), want)
	}
}

func TestHTBClassArgs(t *testing.T) {
	args, err := HTBClassArgs("eth0", "1:1", "1:10", 5000, 20000, 1)
	if err != nil {
		t.Fatalf("HTBClassArgs failed: %v", err)
	}
	want := "class replace dev eth0 parent 1:1 classid 1:10 htb rate 5Mbit ceil 20Mbit prio 1"
	if Join(args) != want {
		t.Errorf("got %q, want %q", Join(args), want)
	}
}

func TestFilterFwmarkArgs(t *testing.T) {
	args, err := FilterFwmarkArgs("eth0", "1:", 1, "0x10", "1:10")
	if err != nil {
		t.Fatalf("FilterFwmarkArgs failed: %v", err)
	}
	want := "filter replace dev eth0 parent 1: protocol ip prio 1 handle 0x10 fw classid 1:10"
	if Join(args) != want {
		t.Errorf("got %q, want %q", Join(args), want)
	}
}

func TestFilterIPArgs(t *testing.T) {
	args, err := FilterIPArgs("eth0", "1:", 2, "10.77.0.100", true, "1:10")
	if err != nil {
		t.Fatalf("FilterIPArgs failed: %v", err)
	}
	want := "filter replace dev eth0 parent 1: protocol ip prio 2 u32 match ip src 10.77.0.100/32 flowid 1:10"
	if Join(args) != want {
		t.Errorf("got %q, want %q", Join(args), want)
	}

	argsDst, err := FilterIPArgs("eth1", "1:", 2, "10.77.0.100", false, "1:10")
	if err != nil {
		t.Fatalf("FilterIPArgs dst failed: %v", err)
	}
	wantDst := "filter replace dev eth1 parent 1: protocol ip prio 2 u32 match ip dst 10.77.0.100/32 flowid 1:10"
	if Join(argsDst) != wantDst {
		t.Errorf("got %q, want %q", Join(argsDst), wantDst)
	}
}

func TestCakeLeafArgs(t *testing.T) {
	args, err := CakeLeafArgs("eth0", "1:10", "10:", false)
	if err != nil {
		t.Fatalf("CakeLeafArgs failed: %v", err)
	}
	want := "qdisc replace dev eth0 parent 1:10 handle 10: cake unlimited besteffort"
	if Join(args) != want {
		t.Errorf("got %q, want %q", Join(args), want)
	}

	argsIngress, err := CakeLeafArgs("eth1", "1:10", "10:", true)
	if err != nil {
		t.Fatalf("CakeLeafArgs ingress failed: %v", err)
	}
	if !strings.Contains(Join(argsIngress), "ingress") {
		t.Errorf("expected ingress option: %q", Join(argsIngress))
	}
}
