package cli

// Regression tests for the two defects real-host validation of M7.0 exposed.
//
//	1. `thn host --requires 2` was rejected as an unknown flag.
//	2. `thn host --mac` rendered "hostname 127.0.0.1/8".
//
// Both were repository defects rather than host defects, and both produced a
// confident wrong answer rather than an error: the first stopped the command
// running at all, the second reported an address under a hostname label on
// every Linux host in existence.
//
// # Why these are not only parse tests
//
// A test that asserts `--requires` parses would have passed before the fix if
// it only checked for the absence of an error message, because the original
// bug was that the flag never reached readiness at all. What has to be proved
// is the value's effect: the same observed host must produce a different
// verdict for `--requires 1` than for `--requires 2`. That is what
// TestRequiresReachesReadinessEvaluation does, and it is the assertion that
// would still fail if the flag were parsed and then discarded.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/network"
)

// deviceWithPorts builds a supported host with n physical NICs, named
// test-gateway.
//
// The fixture is built as a network.Snapshot and translated through
// host.FromSnapshot rather than assembled as a host.Device directly. That is
// deliberate: the hostname defect lived in exactly that translation, so a
// fixture that skipped it would not have reproduced the bug.
//
// It is a fixture rather than a live observation so the tests are
// deterministic and do not assume a pristine machine. Nothing here asserts
// anything about Docker bridges, Tailscale, virtual interfaces or how many
// nftables tables a real gateway carries.
func deviceWithPorts(n int) *host.Device {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		System: network.System{
			OS:           "linux",
			Architecture: "amd64",
			PrettyName:   "Ubuntu 24.04.4 LTS",
			Kernel:       "6.8.0-142-generic",
			Hostname:     "test-gateway",
		},
		Sysctl:         []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
		NFTables:       network.NFTablesState{Checked: true, Available: true, QuerySucceeded: true},
		TrafficControl: network.TCState{Checked: true, Available: true, QuerySucceeded: true},
		// Every Linux host has a loopback interface carrying 127.0.0.1/8.
		// It is present here because the hostname defect read the hostname out
		// of exactly this interface, and a fixture without it would not
		// reproduce the bug that was reported.
		Interfaces: []network.Interface{
			{
				Name:      "lo",
				Index:     1,
				Kind:      "loopback",
				AdminUp:   true,
				State:     network.LinkUp,
				MTU:       65536,
				Addresses: []network.Address{{Interface: "lo", CIDR: "127.0.0.1/8", Family: "inet"}},
			},
		},
		Addresses: []network.Address{{Interface: "lo", CIDR: "127.0.0.1/8", Family: "inet"}},
	}

	for i := 0; i < n; i++ {
		name := fmt.Sprintf("eth%d", i)
		snap.Interfaces = append(snap.Interfaces, network.Interface{
			Name:      name,
			Index:     i + 2,
			MAC:       fmt.Sprintf("3c:ec:ef:00:00:%02d", i),
			Kind:      "ether",
			LinkType:  "ether",
			Physical:  true,
			AdminUp:   true,
			State:     network.LinkUp,
			MTU:       1500,
			Addresses: []network.Address{{Interface: name, CIDR: "192.168.1.10/24", Family: "inet"}},
		})
	}

	return host.FromSnapshot(snap)
}

// readinessFor parses args exactly as `thn host` does, then evaluates
// readiness with the resulting option.
//
// Going through parseHostOptions rather than calling EvaluateReadiness with a
// literal is deliberate: it is the only way to prove the operator's flag and
// the readiness request are the same value. A test that constructed its own
// ReadinessRequest would pass even if runHost wired the wrong one.
func readinessFor(t *testing.T, args []string, d *host.Device) (host.Readiness, hostOptions) {
	t.Helper()

	opts, err := parseHostOptions(args)
	if err != nil {
		t.Fatalf("thn host %v: unexpected parse error: %v", args, err)
	}
	return host.EvaluateReadiness(d, host.ReadinessRequest{
		RequiredInterfaces: opts.Requires,
	}), opts
}

// TestHostHelpListsEveryDocumentedFlag is the CLI acceptance case.
//
// `thn host --help` is how an operator discovers that --requires exists at
// all, so a flag that is implemented but unlisted is the same defect from the
// operator's side as one that is not implemented.
func TestHostHelpListsEveryDocumentedFlag(t *testing.T) {
	env, out, errOut := newTestEnv("host", "--help")

	if got := Run(env); got != ExitOK {
		t.Errorf("thn host --help exited %d, want %d; stderr: %s", got, ExitOK, errOut.String())
	}

	for _, flag := range []string{"--requires", "--mac", "--config", "--json"} {
		if !strings.Contains(out.String(), flag) {
			t.Errorf("thn host --help does not document %s:\n%s", flag, out.String())
		}
	}
}

// ------------------------------------------------------- the --requires flag

// TestHostAcceptsRequiresFlag is the acceptance case from the real host.
//
// The defect was that the flag did not parse at all, so this asserts the
// command accepts each documented form rather than only the one from the bug
// report.
func TestHostAcceptsRequiresFlag(t *testing.T) {
	for _, args := range [][]string{
		{"--requires", "1"},
		{"--requires", "2"},
		{"--requires", "3"},
		{"--requires=2"},
		{},
	} {
		if _, err := parseHostOptions(args); err != nil {
			t.Errorf("thn host %v was rejected: %v", args, err)
		}
	}
}

// TestRequiresDefaultsToTwo pins the documented default.
//
// It matters because a gateway topology is two ports by default, and silently
// changing it would change what `thn host` reports on every host.
func TestRequiresDefaultsToTwo(t *testing.T) {
	opts, err := parseHostOptions(nil)
	if err != nil {
		t.Fatalf("thn host with no flags: %v", err)
	}
	if opts.Requires != 2 {
		t.Errorf("default --requires = %d, want 2", opts.Requires)
	}
}

// TestRequiresRejectsInvalidValues proves malformed input is a usage error
// rather than a silently-accepted zero.
//
// The dangerous outcome is not that a bad value is rejected; it is that one is
// accepted as 0, which the readiness code clamps to 1 and which would report
// a one-port gateway as ready.
func TestRequiresRejectsInvalidValues(t *testing.T) {
	for _, args := range [][]string{
		{"--requires", "abc"},
		{"--requires", "2.5"},
		{"--requires", ""},
		{"--requires", "0"},
		{"--requires", "-1"},
		{"--requires"},
	} {
		if _, err := parseHostOptions(args); err == nil {
			t.Errorf("thn host %v was accepted; a malformed --requires must be a usage error", args)
		}
	}
}

// TestRequiresReachesReadinessEvaluation is the test that matters.
//
// The same two-port host is evaluated at two different requirements, and the
// verdict must differ. Before the fix `--requires` was an unknown flag; a
// weaker fix that parsed it and then passed the default through would produce
// identical verdicts here and would be caught.
func TestRequiresReachesReadinessEvaluation(t *testing.T) {
	d := deviceWithPorts(2)

	one, optsOne := readinessFor(t, []string{"--requires", "1"}, d)
	if optsOne.Requires != 1 {
		t.Fatalf("--requires 1 parsed as %d", optsOne.Requires)
	}

	two, optsTwo := readinessFor(t, []string{"--requires", "2"}, d)
	if optsTwo.Requires != 2 {
		t.Fatalf("--requires 2 parsed as %d", optsTwo.Requires)
	}

	// Two ports observed: two required is satisfiable, three is not. The
	// point is that the count changes the verdict, not that either verdict is
	// correct in isolation.
	three, _ := readinessFor(t, []string{"--requires", "3"}, d)

	if hasBlockingCode(two, "insufficient-interfaces") {
		t.Errorf("a two-port host with --requires 2 was blocked for having too few interfaces:\n%s",
			renderFindings(two))
	}
	if !hasBlockingCode(three, "insufficient-interfaces") {
		t.Errorf("a two-port host with --requires 3 was not blocked:\n%s", renderFindings(three))
	}
	if one.Status == three.Status && one.Blocked == three.Blocked {
		t.Errorf("--requires 1 and --requires 3 produced the same verdict (%s); "+
			"the requirement is not reaching readiness evaluation", one.Status)
	}
}

// TestRequiresBelowPhysicalCountBlocks is the operator-facing case: a host
// with fewer ports than the topology needs.
func TestRequiresBelowPhysicalCountBlocks(t *testing.T) {
	d := deviceWithPorts(1)

	ready, _ := readinessFor(t, []string{"--requires", "2"}, d)
	if !ready.Blocked {
		t.Errorf("a one-port host with --requires 2 was not blocked; status %s", ready.Status)
	}
	if !hasBlockingCode(ready, "insufficient-interfaces") {
		t.Errorf("expected an insufficient-interfaces finding, got:\n%s", renderFindings(ready))
	}

	// The same host satisfies a one-port topology, which is what makes the
	// finding about the requirement rather than about the machine.
	relaxed, _ := readinessFor(t, []string{"--requires", "1"}, d)
	if hasBlockingCode(relaxed, "insufficient-interfaces") {
		t.Errorf("a one-port host with --requires 1 was blocked for having too few interfaces:\n%s",
			renderFindings(relaxed))
	}
}

// TestHostJSONReportsRequiredInterfaces proves the value is also visible to a
// machine consumer, so a monitoring agent does not have to re-derive it from
// the finding text.
func TestHostJSONReportsRequiredInterfaces(t *testing.T) {
	d := deviceWithPorts(2)
	opts, err := parseHostOptions([]string{"--requires", "3"})
	if err != nil {
		t.Fatalf("parsing --requires 3: %v", err)
	}
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: opts.Requires})

	out := hostJSON(d, false, ready, opts.Requires)
	got, ok := out["readiness"].(map[string]any)["required_interfaces"]
	if !ok {
		t.Fatal("JSON readiness block has no required_interfaces")
	}
	if got != 3 {
		t.Errorf("JSON required_interfaces = %v, want 3", got)
	}
}

// -------------------------------------------------------- the hostname field

// TestHostRendersObservedHostname is the acceptance case for the second
// defect.
//
// The fixture host is named test-gateway. The renderer must print that, and
// must not print the loopback address that the previous implementation
// substituted for it.
func TestHostRendersObservedHostname(t *testing.T) {
	d := deviceWithPorts(2)
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})

	out := RenderHost(d, false, ready)

	if !strings.Contains(out, "hostname test-gateway") {
		t.Errorf("host report does not report the observed hostname:\n%s", out)
	}

	// The loopback address still appears, in the interface list, where it
	// belongs. What must not happen is it appearing under the hostname
	// label, so the check is scoped to the hostname line rather than to the
	// whole report.
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "hostname ") {
			continue
		}
		if line != "  hostname test-gateway" {
			t.Errorf("hostname line is %q, want %q", strings.TrimSpace(line), "hostname test-gateway")
		}
		if strings.Contains(line, "/") {
			t.Errorf("hostname line carries a prefix address: %q", strings.TrimSpace(line))
		}
	}
}

// TestHostnameIsNotDerivedFromLoopbackAddress states the invariant directly.
//
// A snapshot whose only address is the loopback must not produce that address
// as the hostname. Every Linux host has one, so the previous behaviour was
// indistinguishable from having no hostname observation at all.
func TestHostnameIsNotDerivedFromLoopbackAddress(t *testing.T) {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "lo", Index: 1, Kind: "loopback"},
		},
		Addresses: []network.Address{
			{Interface: "lo", CIDR: "127.0.0.1/8", Family: "inet"},
		},
		System: network.System{Hostname: "test-gateway"},
	}

	d := host.FromSnapshot(snap)

	if d.Hostname != "test-gateway" {
		t.Errorf("hostname = %q, want %q; the loopback address must not be used",
			d.Hostname, "test-gateway")
	}
	if strings.Contains(d.Hostname, "/") {
		t.Errorf("hostname %q is a CIDR, not a hostname", d.Hostname)
	}
}

// TestHostnameIsOmittedWhenUnobserved confirms the honest fallback.
//
// A host that cannot report its name gets no hostname line, rather than a
// blank one or a substituted address.
func TestHostnameIsOmittedWhenUnobserved(t *testing.T) {
	d := deviceWithPorts(1)
	d.Hostname = ""
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 1})

	out := RenderHost(d, false, ready)

	if strings.Contains(out, "hostname") {
		t.Errorf("a host with no observed hostname rendered one:\n%s", out)
	}
}

// TestHostJSONPreservesHostname proves the JSON model keeps a real hostname
// field, which is what automation reads.
func TestHostJSONPreservesHostname(t *testing.T) {
	d := deviceWithPorts(2)
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})

	out := hostJSON(d, false, ready, 2)

	if got := out["hostname"]; got != "test-gateway" {
		t.Errorf("JSON hostname = %v, want %q", got, "test-gateway")
	}

	// The address must still be reported where it belongs, as an interface
	// address. Moving it would mean the hostname field had been renamed
	// rather than repaired.
	snap, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("host JSON did not serialise: %v", err)
	}
	var decoded struct {
		Hostname   string `json:"hostname"`
		Interfaces []struct {
			Addresses []string `json:"addresses"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal(snap, &decoded); err != nil {
		t.Fatalf("host JSON did not deserialise: %v", err)
	}
	if decoded.Hostname != "test-gateway" {
		t.Errorf("round-tripped hostname = %q", decoded.Hostname)
	}

	// The address must still be reported where it belongs, as the loopback
	// interface's own address. Repairing the hostname field must not have
	// removed or relocated it.
	var loopbackCIDR bool
	for _, i := range decoded.Interfaces {
		for _, a := range i.Addresses {
			if a == "127.0.0.1/8" {
				loopbackCIDR = true
			}
		}
	}
	if !loopbackCIDR {
		t.Error("the loopback interface no longer reports 127.0.0.1/8; " +
			"the hostname fix must not have moved or dropped an address")
	}
}

// TestDiscoverRendersHostnameUnderItsOwnLabel guards the sibling renderer.
//
// `thn discover` printed the same field under a "Loopback:" label, which was
// only correct while the value was a loopback address. Repairing the value
// without repairing the label would have produced "Loopback: test-gateway".
func TestDiscoverRendersHostnameUnderItsOwnLabel(t *testing.T) {
	d := deviceWithPorts(2)

	out := RenderDiscovery(d, false)

	if !strings.Contains(out, "test-gateway") {
		t.Errorf("discovery report does not render the hostname:\n%s", out)
	}
	if strings.Contains(out, "Loopback:") {
		t.Errorf("discovery report still labels the hostname as a loopback:\n%s", out)
	}
}

// ------------------------------------------------------------------- helpers

// hasBlockingCode reports whether the verdict carries a blocking finding with
// the given code.
func hasBlockingCode(r host.Readiness, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code && f.Severity == host.SeverityBlocking {
			return true
		}
	}
	return false
}

// renderFindings renders a verdict's findings for a failure message.
func renderFindings(r host.Readiness) string {
	var b strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s] %s: %s\n", f.Severity, f.Code, f.Message)
	}
	return b.String()
}
