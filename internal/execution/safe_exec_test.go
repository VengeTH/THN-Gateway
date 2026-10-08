package execution

import (
	"testing"
)

func TestSafeExecRejectsUnauthorizedBinaries(t *testing.T) {
	badBinaries := []string{"sh", "bash", "zsh", "python", "curl", "wget", "rm", "dd", "nc"}
	for _, bin := range badBinaries {
		if err := ValidateCommand(bin, "-c", "echo bad"); err == nil {
			t.Errorf("ValidateCommand(%q) succeeded, want rejection", bin)
		}
	}
}

func TestSafeExecRejectsShellMetacharacters(t *testing.T) {
	dangerousArgs := []struct {
		bin  string
		args []string
	}{
		{"ip", []string{"link", "set", "eth1;rm -rf /", "up"}},
		{"ip", []string{"link", "set", "eth1", "up", "&&", "evil"}},
		{"ip", []string{"addr", "add", "10.77.0.1/24|nc -e /bin/sh", "dev", "eth1"}},
		{"ip", []string{"route", "add", "default", "via", "192.168.1.1`id`"}},
		{"sysctl", []string{"-w", "net.ipv4.ip_forward=1$(whoami)"}},
		{"nft", []string{"add", "table", "inet", "thn", ">/etc/passwd"}},
		{"ip", []string{"link", "set", "eth1\nevil", "up"}},
	}

	for _, tt := range dangerousArgs {
		err := ValidateCommand(tt.bin, tt.args...)
		if err == nil {
			t.Errorf("ValidateCommand(%s, %v) succeeded, want rejection for shell metacharacters", tt.bin, tt.args)
		}
	}
}

func TestSafeExecStrictlyProtectsNFTablesOwnership(t *testing.T) {
	// 1. flush ruleset must be rejected!
	if err := ValidateCommand("nft", "flush", "ruleset"); err == nil {
		t.Error("ValidateCommand(nft, flush, ruleset) succeeded; MUST be rejected to protect foreign tables")
	}

	// 2. Foreign tables must be rejected!
	foreignTables := [][]string{
		{"add", "table", "inet", "filter"},
		{"add", "table", "ip", "nat"},
		{"delete", "table", "inet", "docker"},
		{"flush", "table", "inet", "tailscale"},
	}

	for _, args := range foreignTables {
		if err := ValidateCommand("nft", args...); err == nil {
			t.Errorf("ValidateCommand(nft, %v) succeeded; foreign nftables tables MUST be rejected", args)
		}
	}

	// 3. inet thn table commands must be accepted
	validNFT := [][]string{
		{"add", "table", "inet", "thn"},
		{"flush", "table", "inet", "thn"},
		{"add", "chain", "inet", "thn", "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "drop", ";", "}"},
		{"delete", "table", "inet", "thn"},
	}

	for _, args := range validNFT {
		if err := ValidateCommand("nft", args...); err != nil {
			t.Errorf("ValidateCommand(nft, %v) failed: %v, want success", args, err)
		}
	}
}

func TestSafeExecSysctlSafety(t *testing.T) {
	// Only net.ipv4.ip_forward and net.ipv6.conf.all.forwarding with value 0 or 1
	if err := ValidateCommand("sysctl", "-w", "kernel.hostname=pwned"); err == nil {
		t.Error("ValidateCommand(sysctl, kernel.hostname) succeeded, want rejection")
	}
	if err := ValidateCommand("sysctl", "-w", "net.ipv4.ip_forward=99"); err == nil {
		t.Error("ValidateCommand(sysctl, net.ipv4.ip_forward=99) succeeded, want rejection")
	}
	if err := ValidateCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		t.Errorf("ValidateCommand(sysctl, net.ipv4.ip_forward=1) failed: %v", err)
	}
	if err := ValidateCommand("sysctl", "-n", "net.ipv4.ip_forward"); err != nil {
		t.Errorf("ValidateCommand(sysctl, -n, net.ipv4.ip_forward) failed: %v", err)
	}
}

func TestSafeExecPermittedCommands(t *testing.T) {
	cases := [][]string{
		{"ip", "link", "set", "eth1", "up"},
		{"ip", "link", "set", "eth1", "down"},
		{"ip", "addr", "add", "10.77.0.1/24", "dev", "eth1"},
		{"ip", "addr", "del", "10.77.0.1/24", "dev", "eth1"},
		{"ip", "route", "add", "default", "via", "192.168.1.1"},
		{"ip", "route", "replace", "default", "via", "192.168.1.1"},
		{"ip", "route", "del", "default"},
		{"tc", "qdisc", "replace", "dev", "eth0", "root", "cake"},
		{"tc", "qdisc", "replace", "dev", "eth0", "root", "handle", "1:", "htb", "default", "99"},
		{"tc", "qdisc", "replace", "dev", "eth0", "parent", "1:10", "handle", "10:", "cake", "unlimited", "besteffort"},
		{"tc", "class", "replace", "dev", "eth0", "parent", "1:1", "classid", "1:10", "htb", "rate", "1Mbit", "ceil", "5Mbit", "prio", "1"},
		{"tc", "filter", "replace", "dev", "eth0", "parent", "1:", "protocol", "ip", "prio", "1", "handle", "0x10", "fw", "classid", "1:10"},
		{"tc", "filter", "replace", "dev", "eth0", "parent", "1:", "protocol", "ip", "prio", "2", "u32", "match", "ip", "src", "10.77.0.100/32", "flowid", "1:10"},
		{"tc", "qdisc", "del", "dev", "eth0", "root"},
	}

	for _, c := range cases {
		name := c[0]
		args := c[1:]
		if err := ValidateCommand(name, args...); err != nil {
			t.Errorf("ValidateCommand(%s, %v) failed: %v", name, args, err)
		}
	}
}

// TestSafeExecAcceptsInspectionFlagsBeforeTheSubsystem covers `ip -j -d link
// show`, which the lab's own environment verification issues.
//
// The guard allowlist permits it outright. A validator that stopped at the
// first flag would refuse it, and the caller would be unable to tell a refused
// command from a malformed one — so the topology check inside
// VerifyLabEnvironment would silently stop happening.
func TestSafeExecAcceptsInspectionFlagsBeforeTheSubsystem(t *testing.T) {
	permitted := [][]string{
		{"-j", "-d", "link", "show"},
		{"-j", "link", "show"},
		{"-br", "addr", "show"},
		{"-j", "-d", "addr", "show", "eth1"},
		{"-j", "route", "show", "table", "all"},
		{"-4", "-o", "addr", "show", "scope", "global"},
	}
	for _, args := range permitted {
		if err := ValidateCommand("ip", args...); err != nil {
			t.Errorf("ValidateCommand(ip, %v) failed: %v", args, err)
		}
	}

	// Reading the flags correctly must not open a subsystem that was already
	// refused, and must not accept a bare flag list with nothing after it.
	refused := [][]string{
		{"-j"},
		{"-j", "-d"},
		{"-j", "neigh", "show"},
		{"-j", "rule", "show"},
	}
	for _, args := range refused {
		if err := ValidateCommand("ip", args...); err == nil {
			t.Errorf("ValidateCommand(ip, %v) = nil, want denial", args)
		}
	}
}
