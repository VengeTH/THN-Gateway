package host_test

// M7.0 safety: proving that host observation cannot mutate anything.
//
// # Why this is an external test package
//
// It deliberately lives in `host_test` rather than `host` so that it can only
// reach the package's exported surface. A test inside the package could call
// an unexported function, and the guarantee being defended here — that
// nothing a caller can reach mutates the host — would then be untested.
//
// # What is actually being proved
//
// M7.0 widens what THN looks at: it now reads nftables, tc, DNS and
// os-release, none of which it read before. Each of those is a new way to
// reach a tool that could, in principle, change something. The allowlist in
// internal/guard is what stands between that and the host, and these tests
// check the allowlist rather than trusting it.
//
// The checks are deliberately structural — parsing the guard allowlist and
// the source of every new observation path — because a behavioural test alone
// would only prove the calls made today. The M7.0 requirement is that no such
// call can be added later either.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/guard"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/network"
)

// ------------------------------------------------------------ guard policy

// TestGuardDeniesEveryMutatingNftablesForm proves the nftables chokepoint
// still refuses to write.
//
// M7.0 added an nft observation path. This is the test that says the new
// caller did not come with a new way to change the host: the binary is
// permitted, and every state-changing form of it is not.
func TestGuardDeniesEveryMutatingNftablesForm(t *testing.T) {
	denied := [][]string{
		{"add", "table", "inet", "thn"},
		{"create", "table", "inet", "thn"},
		{"delete", "table", "inet", "thn"},
		{"destroy", "table", "inet", "thn"},
		{"flush", "ruleset"},
		{"flush", "table", "inet", "thn"},
		{"insert", "rule", "inet", "thn", "input"},
		{"replace", "rule", "inet", "thn", "input"},
		{"list", "ruleset", "add", "table"}, // smuggling an extra operand
	}

	for _, args := range denied {
		if err := guard.Check("nft", args...); err == nil {
			t.Errorf("guard allowed %q %v; nftables mutation must be impossible", "nft", args)
		}
	}
}

// TestGuardDeniesEveryMutatingTcForm is the tc half of the same guarantee.
//
// M7.0 added a tc observation path, and tc can shape a link. Every writing
// form must be refused.
func TestGuardDeniesEveryMutatingTcForm(t *testing.T) {
	denied := [][]string{
		{"qdisc", "add", "dev", "wan0", "root", "cake", "bandwidth", "100Mbit"},
		{"qdisc", "replace", "dev", "wan0", "root", "fq_codel"},
		{"qdisc", "del", "dev", "wan0", "root"},
		{"class", "add", "dev", "wan0", "parent", "1:"},
		{"filter", "add", "dev", "wan0", "protocol", "ip"},
		{"qdisc", "change", "dev", "wan0"},
	}

	for _, args := range denied {
		if err := guard.Check("tc", args...); err == nil {
			t.Errorf("guard allowed %q %v; traffic control mutation must be impossible", "tc", args)
		}
	}
}

// TestGuardDeniesEveryMutatingIPForm proves ip remains inspection-only.
//
// Discovery calls `ip` for links, addresses, routes and neighbours. None of
// those may be able to add a route or set an address.
func TestGuardDeniesEveryMutatingIPForm(t *testing.T) {
	denied := [][]string{
		{"route", "add", "default", "via", "192.168.1.1"},
		{"route", "delete", "default"},
		{"route", "replace", "10.0.0.0/8", "dev", "wan0"},
		{"addr", "add", "10.0.0.1/24", "dev", "wan0"},
		{"addr", "flush", "dev", "wan0"},
		{"link", "set", "wan0", "up"},
		{"link", "set", "wan0", "down"},
		{"link", "delete", "wan0"},
	}

	for _, args := range denied {
		if err := guard.Check("ip", args...); err == nil {
			t.Errorf("guard allowed %q %v; ip mutation must be impossible", "ip", args)
		}
	}
}

// TestGuardDeniesSysctlWrites proves the tunables THN reads cannot be written.
func TestGuardDeniesSysctlWrites(t *testing.T) {
	for _, args := range [][]string{
		{"-w", "net.ipv4.ip_forward=1"},
		{"net.ipv4.ip_forward=1"},
		{"-p", "/etc/sysctl.conf"},
		{"--load=/etc/sysctl.conf"},
	} {
		if err := guard.Check("sysctl", args...); err == nil {
			t.Errorf("guard allowed sysctl %v; writing a tunable must be impossible", args)
		}
	}
}

// TestGuardDeniesShellInvocation proves no path to a shell exists.
//
// The M7.0 requirement is explicit that sh -c, bash -c and sudo must not be
// reachable. None of those binaries is in the allowlist at all, which is a
// stronger guarantee than a list of denied arguments.
func TestGuardDeniesShellInvocation(t *testing.T) {
	for _, bin := range []string{"sh", "bash", "zsh", "dash", "sudo", "su", "systemctl", "nmcli", "netplan"} {
		if err := guard.Check(bin); err == nil {
			t.Errorf("guard allowed %q; the allowlist must contain no shell or privilege-escalation binary", bin)
		}
		if err := guard.Check(bin, "-c", "ip route add default via 0.0.0.0"); err == nil {
			t.Errorf("guard allowed %q -c <command>", bin)
		}
	}
}

// TestObservationCommandsAreAllPermitted is the positive half.
//
// A guard that denied the read-only forms too would pass every test above
// while producing a product that observes nothing. These are exactly the
// invocations M7.0 makes, so this pins the permitted surface the observation
// layer depends on.
func TestObservationCommandsAreAllPermitted(t *testing.T) {
	permitted := []struct {
		bin  string
		args []string
	}{
		// What internal/network asks iproute2 for.
		{"ip", []string{"-j", "-d", "link", "show"}},
		{"ip", []string{"-j", "addr", "show"}},
		{"ip", []string{"-j", "route", "show"}},
		{"ip", []string{"-j", "neigh", "show"}},
		// What M7.0 added.
		{"sysctl", []string{"-n", "net.ipv4.ip_forward"}},
		{"nft", []string{"-j", "list", "tables"}},
		{"tc", []string{"-j", "qdisc", "show"}},
		{"iw", []string{"dev"}},
	}

	for _, p := range permitted {
		if err := guard.Check(p.bin, p.args...); err != nil {
			t.Errorf("guard denied the read-only invocation %q %v: %v", p.bin, p.args, err)
		}
	}
}

// ------------------------------------------------------ source-level proof

// forbiddenInObservation is the set of constructs that must never appear in
// the observation layer.
//
// This is a source scan rather than a behavioural test on purpose. A
// behavioural test can only assert about invocations that exist today; the
// M7.0 requirement is that none can be added later, and only reading the
// source can say that about code that has not been written.
var forbiddenInObservation = map[string]string{
	`os/exec`:      "exec must not be imported by the observation layer",
	`"sh"`:         "no shell invocation",
	`"bash"`:       "no shell invocation",
	`os.WriteFile`: "observation must not write files",
	`os.Chmod`:     "observation must not change permissions",
	`os.Mkdir`:     "observation must not create directories",
	`os.Remove`:    "observation must not remove anything",
	`os.Create`:    "observation must not create files",
}

// TestObservationLayerHasNoWritePath scans every file in the observation
// layer for anything that could mutate the host.
//
// The scan is textual and therefore blunt, but bluntness is the point: the
// cost of a false positive here is a comment being reworded, and the cost of
// a false negative is a gateway that changes itself on a read-only code path.
func TestObservationLayerHasNoWritePath(t *testing.T) {
	files := observationFiles(t)
	if len(files) == 0 {
		t.Fatal("no observation source files were found; the scan is not running")
	}

	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		// Strip comments so that prose ABOUT mutation does not trip the
		// scan. This milestone's documentation is dense with "must not
		// mutate" sentences, and a scanner that flagged those would be
		// useless.
		code := stripComments(string(body))

		for needle, why := range forbiddenInObservation {
			if strings.Contains(code, needle) {
				t.Errorf("%s contains %q: %s", filepath.Base(file), needle, why)
			}
		}
	}
}

// TestObservationLayerImportsOnlyTheChokepoint proves every exec path in the
// observation layer goes through guard.
//
// internal/network owns every /sys, ip, nft and tc call. If it imported
// os/exec directly it would have a route around the allowlist, and the
// allowlist tests above would be reassuring about a chokepoint nothing passes
// through.
func TestObservationLayerImportsOnlyTheChokepoint(t *testing.T) {
	files := observationFiles(t)
	sawGuard := false

	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		code := stripComments(string(body))
		if strings.Contains(code, `"os/exec"`) {
			t.Errorf("%s imports os/exec directly; all execution must go through internal/guard",
				filepath.Base(file))
		}
		if strings.Contains(code, "internal/guard") {
			sawGuard = true
		}
	}

	if !sawGuard {
		t.Error("no observation file imports internal/guard; the observation layer " +
			"appears to have no execution path at all, which is not what this layer does")
	}
}

// TestReadinessAndDiscoveryProduceNoOperations is the behavioural half.
//
// Even if the source were clean today, the important claim is structural:
// the types M7.0 added cannot express a mutation. A Snapshot, a Device and a
// Readiness have no operation, driver or executor field, so there is nothing
// for a caller to reach through.
func TestReadinessAndDiscoveryProduceNoOperations(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "wan0", Index: 2, MAC: "3c:ec:ef:11:22:33", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true,
				State: network.LinkUp, SpeedMbps: 1000},
			{Name: "wan1", Index: 3, MAC: "3c:ec:ef:11:22:44", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true,
				State: network.LinkUp, SpeedMbps: 1000},
		},
		Sysctl:         []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
		NFTables:       network.NFTablesState{Checked: true, Available: true, QuerySucceeded: true},
		TrafficControl: network.TCState{Checked: true, Available: true, QuerySucceeded: true},
		System:         network.System{Distribution: "debian", Version: "12", Kernel: "6.1.0"},
	}

	d := host.FromSnapshot(snap)
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})

	// The whole model must survive a JSON round trip unchanged. If any of it
	// carried a live handle, a driver, or an operation, it would not
	// serialise — and THN stores and ships these over IPC.
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("a Device did not serialise: %v", err)
	}
	var decoded host.Device
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("a Device did not deserialise: %v", err)
	}
	if len(decoded.Interfaces) != len(d.Interfaces) {
		t.Errorf("interfaces did not survive serialisation: %d became %d",
			len(d.Interfaces), len(decoded.Interfaces))
	}
	if len(decoded.Capabilities) != len(d.Capabilities) {
		t.Errorf("capabilities did not survive serialisation: %d became %d",
			len(d.Capabilities), len(decoded.Capabilities))
	}

	encodedReady, err := json.Marshal(ready)
	if err != nil {
		t.Fatalf("a Readiness did not serialise: %v", err)
	}
	var decodedReady host.Readiness
	if err := json.Unmarshal(encodedReady, &decodedReady); err != nil {
		t.Fatalf("a Readiness did not deserialise: %v", err)
	}
	if len(decodedReady.Findings) != len(ready.Findings) {
		t.Errorf("findings did not survive serialisation: %d became %d",
			len(ready.Findings), len(decodedReady.Findings))
	}

	// And the round trip must not have changed the verdict.
	if decodedReady.Status != ready.Status {
		t.Errorf("status changed across serialisation: %s became %s",
			ready.Status, decodedReady.Status)
	}
}

// TestDiscoveryNeverAssignsARole proves observation assigns nothing.
//
// Roles are an operator's decision, recorded in configuration. Discovery
// reporting one would mean THN chose it, which is the specific failure the
// role model was built to prevent.
func TestDiscoveryNeverAssignsARole(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "wan0", Index: 2, MAC: "3c:ec:ef:11:22:33", Kind: "ether",
				LinkType: "ether", Physical: true, State: network.LinkUp},
			{Name: "wan1", Index: 3, MAC: "3c:ec:ef:11:22:44", Kind: "ether",
				LinkType: "ether", Physical: true, State: network.LinkUp},
		},
	}

	d := host.FromSnapshot(snap)

	if got := d.RoleAssignments(); len(got) != 0 {
		t.Errorf("discovery produced %d role assignments: %+v; it must assign none", len(got), got)
	}
	for _, i := range d.Interfaces {
		if i.Role != host.RoleUnassigned && i.Role != "" {
			t.Errorf("discovery assigned role %q to %s", i.Role, i.SystemName)
		}
	}
}

// TestNoHardcodedInterfaceNamesInObservation proves discovery is not written
// against one machine.
//
// The M7.0 specification is explicit that enp0s31f6, enx00e099001812 and
// wlp2s0 are examples from one host, not product requirements. Any of them
// appearing in the observation layer would mean the code could only ever have
// been exercised against that host.
func TestNoHardcodedInterfaceNamesInObservation(t *testing.T) {
	// Names from the original development host, plus the common name
	// prefixes that would amount to the same mistake in softer form.
	forbidden := []string{
		"enp0s31f6", "enp1s0", "enx00e099001812", "wlp2s0", "wlp3s0",
		"eth0", "eth1",
	}

	for _, file := range observationFiles(t) {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		code := stripComments(string(body))

		for _, name := range forbidden {
			// Look for the name inside a string literal, which is how a
			// hardcoded name would actually be used.
			if strings.Contains(code, `"`+name+`"`) {
				t.Errorf("%s contains the hardcoded interface name %q; "+
					"observation must work on any supported host", filepath.Base(file), name)
			}
		}
	}
}

// observationFiles lists the non-test Go sources of the observation layer.
func observationFiles(t *testing.T) []string {
	t.Helper()

	var out []string
	for _, dir := range []string{"network", "host"} {
		entries, err := os.ReadDir(filepath.Join("..", dir))
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			out = append(out, filepath.Join("..", dir, name))
		}
	}
	return out
}

// stripComments removes Go comments from source text.
//
// The scan has to see code, not prose. This milestone's documentation is
// dense with sentences like "must not mutate the host", and a scanner that
// flagged those would either be useless or force the documentation to be
// watered down — which is the wrong trade in either direction.
var (
	lineComment  = regexp.MustCompile(`(?m)//.*$`)
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

func stripComments(src string) string {
	return lineComment.ReplaceAllString(blockComment.ReplaceAllString(src, " "), " ")
}
