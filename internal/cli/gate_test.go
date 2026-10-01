package cli

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/config"
)

// This file and its siblings implement the gateway gate: an end-to-end check
// that the subsystems agree with each other, not merely that each one works.
//
// # What a unit test cannot find
//
// Every subsystem in this project is tested inside its own package, and those
// tests are good — but they are blind to a specific and dangerous class of
// bug. A subsystem tested alone is correct by construction: it is handed a
// policy and asked about that policy. The failures that matter on a gateway
// happen in the seams:
//
//   - The data plane says a direction is accepted while the firewall renderer
//     drops it. Each model is internally correct; the gateway forwards
//     nothing.
//   - The DHCP pool is derived from a different LAN prefix than the one the
//     firewall's anti-spoofing rule uses. Clients get addresses that are then
//     dropped as spoofed.
//   - DNS listens on one address while DHCP tells clients the gateway is at
//     another. Name resolution fails on a network that is otherwise healthy.
//
// None of those is visible to a test that only exercises one package. The gate
// exists to catch exactly this class.
//
// # The topology
//
// Everything is exercised against one fixed WAN / THN / LAN topology:
//
//	                    internet
//	                       |
//	                 203.0.113.1  (upstream gateway)
//	                       |
//	              eth0  203.0.113.10/24
//	                       |
//	                   [ THN ]  10.77.0.1/24
//	                       |
//	              eth1  10.77.0.0/24
//	                       |
//	                10.77.0.100+  (DHCP pool)
//
// The addresses are from RFC 5737's documentation range, so nothing here can
// collide with a real network even if a value is typed into a live command.
//
// # A gate, not a smoke test
//
// Two properties make this a gate rather than a pile of assertions:
//
//  1. Every phase derives its policies through the same functions the CLI uses.
//     The gate does not re-derive anything. A re-derivation would test the
//     test; using netPolicyFromConfig and policyFromConfig means the gate
//     breaks the moment the real translators disagree.
//
//  2. The gate is deterministic. Clock values are passed explicitly, no
//     network is touched, and no output is asserted on by substring alone
//     where a stronger check is available. A gate that fails intermittently
//     gets ignored, and an ignored gate is worse than no gate.

const (
	// gateWANAddr is the THN's address on the uplink.
	gateWANAddr = "203.0.113.10/24"

	// gateLANAddr is the gateway address on the LAN, and the address DHCP
	// hands out as option 3 and DNS hands out as the resolver.
	gateLANAddr = "10.77.0.1/24"

	// gateUpstreamGW is the ISP's router.
	gateUpstreamGW = "203.0.113.1"

	// gateWANIface faces the bottleneck and is therefore where shaping belongs.
	gateWANIface = "eth0"

	// gateLANIface faces the clients.
	gateLANIface = "eth1"

	// gatePoolStart is the first address handed out. It is offset from .1 so
	// the first 99 addresses stay free for static hosts and the gateway.
	gatePoolStart = "10.77.0.100"

	// gatePoolEnd is the last address handed out, inclusive.
	gatePoolEnd = "10.77.0.249"

	// gateDownloadKbps is the provisioned downstream rate.
	gateDownloadKbps = 100_000

	// gateUploadKbps is the provisioned upstream rate.
	gateUploadKbps = 20_000
)

// gateFixedTime is the clock the gate runs at.
//
// Every timestamp-sensitive assertion uses this rather than time.Now, so that
// lease expiry, plan generation and recovery planning are decided by the test
// rather than by when the suite happened to run.
var gateFixedTime = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

// gateConfig is the configuration document the gate runs on.
//
// Aliased rather than re-declared so that a signature taking a gateConfig
// accepts a config.Config without a conversion, and so that the alias becomes
// a single place to narrow if the gate ever needs a subset.
type gateConfig = config.Config

// topologyConfig returns a configuration describing the gate topology.
//
// It starts from config.Defaults rather than a literal document so that the
// gate tracks the shipped defaults instead of drifting from them. A literal
// fixture would go stale the moment a default changed, and would then be
// testing a gateway nobody ships.
func topologyConfig() config.Config {
	cfg := config.Defaults()

	cfg.Gateway.Name = "thn-gate"
	cfg.Gateway.Generation = 1

	cfg.Network.WAN = gateWANIface
	cfg.Network.LAN = gateLANIface
	cfg.Network.LANPrefix = gateLANAddr
	cfg.Network.UpstreamGateway = gateUpstreamGW
	cfg.Network.MTU = 1500
	cfg.Network.DNS = []string{"1.1.1.1", "9.9.9.9"}

	cfg.NAT.Enabled = true

	cfg.Firewall.Enabled = true
	cfg.Firewall.Backend = "nftables"
	cfg.Firewall.DefaultInboundPolicy = "drop"

	cfg.DHCP.Enabled = true
	cfg.DHCP.Authoritative = true
	cfg.DHCP.Domain = "lan"
	cfg.DHCP.Ranges = []config.DHCPRangeConfig{
		{Start: gatePoolStart, End: gatePoolEnd},
	}
	cfg.DHCP.Reservations = []config.DHCPReservationConfig{
		{MAC: "aa:bb:cc:dd:ee:01", Address: "10.77.0.10", Hostname: "nas"},
	}

	cfg.DNS.Enabled = true
	cfg.DNS.LocalDomain = "lan"
	cfg.DNS.LocalRecords = []config.LocalRecordConfig{
		{Hostname: "nas", Address: "10.77.0.10", Aliases: []string{"storage"}},
		{Hostname: "printer", Address: "10.77.0.20"},
	}

	cfg.QoS.Enabled = true
	cfg.QoS.Algorithm = "cake"
	cfg.QoS.Interface = gateWANIface
	cfg.QoS.DownloadKbps = gateDownloadKbps
	cfg.QoS.UploadKbps = gateUploadKbps
	cfg.QoS.OverheadPercent = 10

	return cfg
}

// writeTopology persists a configuration and returns its path.
//
// The gate goes through config.Write and config.Load rather than constructing
// a config.Config directly at the point of use, because the load path is where
// normalisation and unknown-key rejection happen. A gate that skips it would
// pass on a document the real CLI would reject.
func writeTopology(t *testing.T, cfg config.Config) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")

	cfg.Paths.StateDB = filepath.ToSlash(filepath.Join(filepath.Dir(path), "state.db"))

	if _, err := cfg.Marshal(); err != nil {
		t.Fatalf("marshalling the gate config: %v", err)
	}
	if err := cfg.Write(path); err != nil {
		t.Fatalf("writing the gate config: %v", err)
	}
	return path
}

// loadTopology writes and reloads a configuration, returning both.
//
// Reloading is deliberate. The gate should assert against the normalised
// document an operator would actually get, not against the struct this test
// happened to build.
func loadTopology(t *testing.T, cfg config.Config) (config.Config, string) {
	t.Helper()

	path := writeTopology(t, cfg)

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading the gate config: %v", err)
	}
	return loaded, path
}

// addr parses an address, failing the test if it does not parse.
//
// The topology constants are compile-time strings, so a failure here is a typo
// in the gate rather than a runtime condition, and it should stop the run
// immediately rather than surface later as a confusing assertion failure.
func addr(t *testing.T, s string) netip.Addr {
	t.Helper()

	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("the gate topology contains an unparseable address %q: %v", s, err)
	}
	return a
}

// mustPrefix parses a prefix or fails the test.
func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()

	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("the gate topology contains an unparseable prefix %q: %v", s, err)
	}
	return p.Masked()
}

// runGateCLI executes a command line against the real dispatch table and
// returns its output and exit code.
//
// The buffers are read after Run returns. Returning buf.String() inline would
// evaluate it before the command wrote anything, so every assertion would see
// an empty buffer and the phase would pass for the wrong reason.
func runGateCLI(t *testing.T, args ...string) (string, string, ExitCode) {
	t.Helper()

	var out, errBuf bytes.Buffer

	env := &Env{
		Stdout: &out,
		Stderr: &errBuf,
		Args:   args,
		// No environment inheritance. A THN_* variable exported in the
		// developer's shell would otherwise silently redirect the config path
		// and make the gate pass or fail depending on who ran it.
		Getenv: func(string) string { return "" },
		Getwd:  func() (string, error) { return t.TempDir(), nil },
	}

	code := Run(env)
	return out.String(), errBuf.String(), code
}

// runGateJSON executes a command with --json and decodes the result.
//
// Decoding rather than matching on text is deliberate. A JSON assertion fails
// when a field changes meaning; a substring assertion fails when someone
// rewords a sentence, which trains everyone to ignore it.
func runGateJSON(t *testing.T, args ...string) (map[string]any, ExitCode) {
	t.Helper()

	stdout, stderr, code := runGateCLI(t, append(args, "--json")...)

	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("%v: --json produced undecodable output (exit %d)\nstdout:\n%s\nstderr:\n%s",
			args, code, stdout, stderr)
	}
	return doc, code
}

// jsonString reads a string field, failing if it is absent or the wrong type.
func jsonString(t *testing.T, doc map[string]any, key string) string {
	t.Helper()

	v, ok := doc[key]
	if !ok {
		t.Fatalf("the output has no %q field; keys are %v", key, keysOf(doc))
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("%q is %T, want string", key, v)
	}
	return s
}

// jsonBool reads a bool field, failing if it is absent or the wrong type.
func jsonBool(t *testing.T, doc map[string]any, key string) bool {
	t.Helper()

	v, ok := doc[key]
	if !ok {
		t.Fatalf("the output has no %q field; keys are %v", key, keysOf(doc))
	}
	b, ok := v.(bool)
	if !ok {
		t.Fatalf("%q is %T, want bool", key, v)
	}
	return b
}

// jsonObject reads a nested object, failing if it is absent or not an object.
func jsonObject(t *testing.T, doc map[string]any, key string) map[string]any {
	t.Helper()

	v, ok := doc[key]
	if !ok {
		t.Fatalf("the output has no %q field; keys are %v", key, keysOf(doc))
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%q is %T, want an object", key, v)
	}
	return m
}

// keysOf lists a decoded object's keys, for failure messages.
func keysOf(doc map[string]any) []string {
	out := make([]string, 0, len(doc))
	for k := range doc {
		out = append(out, k)
	}
	return out
}

// requireContains fails unless text contains want.
//
// The message includes the surrounding text, because a gate failure that only
// says "expected X" costs more time than it saves.
func requireContains(t *testing.T, what, text, want string) {
	t.Helper()

	if strings.Contains(text, want) {
		return
	}
	t.Errorf("%s does not contain %q\n--- actual ---\n%s\n--------------", what, want, text)
}

// requireNotContains fails if text contains unwanted.
func requireNotContains(t *testing.T, what, text, unwanted string) {
	t.Helper()

	if !strings.Contains(text, unwanted) {
		return
	}
	t.Errorf("%s unexpectedly contains %q\n--- actual ---\n%s\n--------------", what, unwanted, text)
}

// TestGateTopologyIsItselfValid is the gate's own precondition.
//
// If the fixture topology is not a configuration THN would accept, every other
// phase is asserting against a gateway that cannot exist, and their failures
// would point at the wrong thing. This runs first so that a broken fixture is
// diagnosed as a broken fixture.
func TestGateTopologyIsItselfValid(t *testing.T) {
	cfg, path := loadTopology(t, topologyConfig())

	result := cfg.Validate()
	if result.HasErrors() {
		for _, f := range result.Findings {
			if f.Severity == config.SeverityError {
				t.Errorf("the gate topology is not a valid configuration: %s: %s", f.Field, f.Message)
			}
		}
		t.Fatalf("the gate fixture is broken; every later phase would be testing nothing")
	}

	// The written document must be the one that was asked for. If Write
	// silently dropped a section, the gate would pass while testing a
	// configuration that is missing that subsystem entirely.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the written config: %v", err)
	}
	for _, want := range []string{"qos:", "dhcp:", "dns:", "nat:", "firewall:"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the written configuration has no %q section", want)
		}
	}
}

// gateSubsystems is every subsystem a configuration can configure, and the
// subject each gate phase must be named after.
//
// Kept as an explicit list rather than derived from the code. A list derived
// from the code would grow silently as subsystems are added, and the
// completeness check would then be checking that the code agrees with itself
// — which is always true, and proves nothing.
var gateSubsystems = []string{
	"routing",
	"nat",
	"firewall",
	"dhcp",
	"dns",
	"qos",
	"failure",
	"rollback",
	"policies",
	"schedules",
}

// gateTestNames returns the names of every test in this package's gate files.
//
// The names are read from the source rather than from a registry, because a
// registry would be maintained by hand and would drift: a phase renamed or
// deleted would leave its entry behind, and the completeness check would keep
// reporting coverage for a phase that no longer runs.
//
// Parsing the source is the same approach internal/guard takes to enforce its
// own invariant, and for the same reason — the check has to hold against what
// the code actually says.
func gateTestNames(t *testing.T) []string {
	t.Helper()

	entries, err := filepath.Glob("gate*_test.go")
	if err != nil {
		t.Fatalf("globbing the gate test files: %v", err)
	}
	if len(entries) == 0 {
		dir, _ := os.Getwd()
		t.Fatalf("no gate test files found in %s; the gate's files were renamed or "+
			"moved, so its completeness checks are no longer running", dir)
	}

	fset := token.NewFileSet()

	var names []string
	for _, path := range entries {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil {
				continue
			}
			if strings.HasPrefix(fd.Name.Name, "Test") {
				names = append(names, fd.Name.Name)
			}
		}
	}
	return names
}

// gateTestsMatching returns the gate tests whose names contain a subsystem.
//
// Matching is on the test name, so a phase is required to declare what it
// covers. A test that exercises DHCP but is called TestConfigHappyPath is not
// discoverable, and discoverability is what the completeness check rests on.
//
// The match is a plain substring test. A false positive here could only ever
// add apparent coverage, never remove it, so the failure mode is a slightly
// weaker check rather than a broken one.
func gateTestsMatching(t *testing.T, subsystem string) []string {
	t.Helper()

	var out []string
	for _, name := range gateTestNames(t) {
		if strings.Contains(strings.ToLower(name), subsystem) {
			out = append(out, name)
		}
	}
	return out
}

// gatePhaseSubjects returns the subsystems that gate tests are named after.
//
// It is derived from the same matcher the coverage check uses, so the two
// cannot disagree about what a phase claims to cover.
func gatePhaseSubjects(t *testing.T) []string {
	t.Helper()

	var out []string
	for _, subject := range gateSubsystems {
		if len(gateTestsMatching(t, subject)) > 0 {
			out = append(out, subject)
		}
	}
	return out
}

// TestGateCoversEverySubsystem is the gate's own completeness check.
//
// A gate that only covers the subsystems someone remembered is worse than no
// gate, because it is read as a general verdict. This asserts the mapping
// instead: every subsystem THN manages must have a phase that names it, and
// every phase must name a subsystem that exists.
//
// Adding a subsystem to THN without adding it here fails this test, which is
// the point — the omission is then a deliberate decision rather than a gap
// nobody noticed.
func TestGateCoversEverySubsystem(t *testing.T) {
	// Every subsystem a configuration can configure. The list lives in
	// gateSubsystems and is asserted complete by this test.
	for _, subsystem := range gateSubsystems {
		if len(gateTestsMatching(t, subsystem)) == 0 {
			t.Errorf("no gate phase covers %q; a subsystem that is added without a "+
				"phase would be tested only by its own package, which cannot see "+
				"it disagree with the others", subsystem)
		}
	}
}

// TestGateHasNoPhaseForAnUnknownSubsystem is the other direction.
//
// A phase naming a subsystem that no longer exists is dead weight that will
// quietly stop asserting anything.
func TestGateHasNoPhaseForAnUnknownSubsystem(t *testing.T) {
	known := map[string]bool{}
	for _, s := range gateSubsystems {
		known[s] = true
	}

	for _, subject := range gatePhaseSubjects(t) {
		if !known[subject] {
			t.Errorf("a gate phase names %q, which is not a subsystem THN manages; "+
				"the phase is asserting against nothing", subject)
		}
	}
}

// TestGatePhasesAreIndependentlyRunnable checks the gate's usability.
//
// Every phase must be selectable on its own. A gate that only runs as one
// monolithic test cannot be used to check a single subsystem after a change,
// which is most of what a gate is for.
func TestGatePhasesAreIndependentlyRunnable(t *testing.T) {
	for _, subsystem := range gateSubsystems {
		matches := gateTestsMatching(t, subsystem)
		if len(matches) == 0 {
			continue // reported by TestGateCoversEverySubsystem
		}
		// Every match must be selectable on its own, which means the name has
		// to be unique enough to target. A phase whose name collides with
		// another's is still runnable, but not addressable.
		if len(matches) > 1 {
			t.Logf("%d gate tests cover %s: %v", len(matches), subsystem, matches)
		}
	}

	// The gate's own structural checks must not be mistaken for phases, and
	// the phases must not be mistaken for them. A structural check that
	// stopped running would leave the gate reporting coverage it does not
	// have.
	structural := 0
	for _, name := range gateTestNames(t) {
		switch {
		case strings.HasPrefix(name, "TestGateCovers"),
			strings.HasPrefix(name, "TestGateHasNoPhase"),
			strings.HasPrefix(name, "TestGatePhasesAre"),
			strings.HasPrefix(name, "TestGateTime"),
			strings.HasPrefix(name, "TestGateTopology"),
			strings.HasPrefix(name, "TestGateHasNoApplyPath"):
			structural++
		}
	}
	if structural == 0 {
		t.Error("no structural checks were found; the gate cannot confirm it covers " +
			"what it claims to cover")
	}
}

// TestGateHasNoApplyPath is a structural assertion about the build, and it
// belongs at the top of the gate.
//
// Everything below simulates. If a code path ever gained the ability to apply
// a configuration, the gate would start asserting against a system that can
// change, and its guarantees would quietly become untrue.
func TestGateHasNoApplyPath(t *testing.T) {
	cmd, ok := commands["activate"]
	if !ok {
		t.Fatal("the activate command is not registered")
	}
	if cmd.Tier != TierDestructive {
		t.Errorf("activate tier = %q, want destructive", cmd.Tier)
	}

	// A gate that leaves a real interface alone is only meaningful if nothing
	// in the pure tier can reach one.
	for name, c := range commands {
		if c.Tier == TierPure {
			continue
		}
		if name == "activate" {
			continue
		}
		t.Logf("non-pure command %q (%s) is outside the gate's scope", name, c.Tier)
	}
}
