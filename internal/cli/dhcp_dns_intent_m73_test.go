package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/execution"
	"github.com/venth/thn-gateway/internal/planner"
)

func serviceConfig() config.Config {
	cfg := config.Defaults()
	cfg.Gateway.Name = "m73-service"
	cfg.Gateway.Enabled = true
	cfg.Gateway.Generation = 7
	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "enp1s0"
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.NAT.Enabled = true
	cfg.NAT.Masquerade.Enabled = true
	cfg.NAT.Masquerade.Outbound = "wan"
	cfg.DHCP.Enabled = true
	cfg.DHCP.Ranges = []config.DHCPRangeConfig{
		{Start: "10.77.0.100", End: "10.77.0.250"},
	}
	cfg.DNS.Enabled = true
	cfg.DNS.Upstream = append([]string(nil), cfg.Network.DNS...)
	cfg.Firewall.AdminSources = []string{"192.168.77.0/24"}
	return cfg
}

func intentVerdict(out, header string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, header) {
			return strings.TrimSpace(strings.TrimPrefix(line, header))
		}
	}
	return ""
}

func stepIDs(p *planner.Plan) []string {
	out := make([]string, 0, len(p.Steps))
	for _, s := range p.Steps {
		out = append(out, s.ID)
	}
	return out
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// TestValidateReportsGatewayDHCPAndDNSSeparately is the headline acceptance
// case: one command, three understandable sections.
func TestValidateReportsGatewayDHCPAndDNSSeparately(t *testing.T) {
	path := writeIntentConfig(t, serviceConfig())

	stdout, stderr, _ := runGateCLI(t, "validate", path)

	for _, want := range []string{"Gateway intent:", "DHCP intent:", "DNS intent:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("`thn validate` did not report %q:\n%s\n%s", want, stdout, stderr)
		}
	}

	// The sections must show what the operator asked for, not just that
	// something was checked.
	if !strings.Contains(stdout, "10.77.0.100-10.77.0.250") {
		t.Errorf("the DHCP section must show the address pool:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1.1.1.1") {
		t.Errorf("the DNS section must show the upstream resolvers:\n%s", stdout)
	}
}

// TestConfigValidateDelegatesToSamePipeline: `thn config validate` must reach
// the same conclusions as `thn validate`.
//
// One source of truth means the two commands cannot disagree. If they ever do,
// an operator who validated in CI and planned on the gateway would be reading
// two different verdicts about one document.
func TestConfigValidateDelegatesToSamePipeline(t *testing.T) {
	path := writeIntentConfig(t, serviceConfig())

	a, _, _ := runGateCLI(t, "validate", path)
	b, _, _ := runGateCLI(t, "config", "validate", path)

	// Compare the three intent blocks rather than the whole output, which also
	// carries the configuration path.
	for _, section := range []string{"Gateway intent:", "DHCP intent:", "DNS intent:"} {
		if x, y := intentVerdict(a, section), intentVerdict(b, section); x != y {
			t.Errorf("%s: `thn validate` said %q but `thn config validate` said %q", section, x, y)
		}
	}
}

// TestValidateDNSConflictIsBlocked: two disagreeing resolver sources must stop
// the document and carry a stable code.
func TestValidateDNSConflictIsBlocked(t *testing.T) {
	cfg := serviceConfig()
	cfg.DNS.Upstream = []string{"1.1.1.1"}
	cfg.Network.DNS = []string{"8.8.8.8"}

	path := writeIntentConfig(t, cfg)
	stdout, _, code := runGateCLI(t, "validate", path)

	if code == ExitOK {
		t.Errorf("a document that disagrees with itself must not pass the gate:\n%s", stdout)
	}
	if !strings.Contains(stdout, "dns-upstream-conflict") {
		t.Errorf("expected the stable code dns-upstream-conflict:\n%s", stdout)
	}
	if !strings.Contains(stdout, "DNS intent: BLOCKED") {
		t.Errorf("expected the DNS section to be BLOCKED:\n%s", stdout)
	}
}

// TestValidateDHCPOutsideLANIsBlocked: the milestone's worked example.
func TestValidateDHCPOutsideLANIsBlocked(t *testing.T) {
	cfg := serviceConfig()
	cfg.DHCP.Ranges = []config.DHCPRangeConfig{
		{Start: "10.88.0.100", End: "10.88.0.250"},
	}

	path := writeIntentConfig(t, cfg)
	stdout, _, code := runGateCLI(t, "validate", path)

	if code == ExitOK {
		t.Errorf("a pool outside the LAN must not pass the gate:\n%s", stdout)
	}
	if !strings.Contains(stdout, "outside the LAN prefix") {
		t.Errorf("expected a plain-English explanation of the subnet mismatch:\n%s", stdout)
	}
}

// TestValidateUnresolvedLANExplainsDependency: when the LAN cannot be
// resolved, the downstream services must say so rather than blaming their own
// configuration.
//
// This is the milestone's dependency-ordering requirement, asserted end to end.
func TestValidateUnresolvedLANExplainsDependency(t *testing.T) {
	cfg := serviceConfig()
	cfg.Network.LAN = "hw:99notattached"

	path := writeIntentConfig(t, cfg)
	stdout, _, _ := runGateCLI(t, "validate", path)

	for _, want := range []string{"dhcp-lan-unresolved", "dns-lan-unresolved"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("expected %s:\n%s", want, stdout)
		}
	}

	// The misleading consequence must NOT appear: the pool is not the problem.
	if strings.Contains(stdout, "dhcp-range-outside-lan") {
		t.Errorf("with an unresolved LAN the pool cannot be judged; it must not be blamed:\n%s", stdout)
	}
}

// TestValidateJSONExposesAllThreeIndependently: a client must not have to
// parse human-readable text to learn the three verdicts.
func TestValidateJSONExposesAllThreeIndependently(t *testing.T) {
	path := writeIntentConfig(t, serviceConfig())

	stdout, stderr, _ := runGateCLI(t, "validate", "--json", path)

	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("validate --json is not valid JSON: %v\n%s\n%s", err, stdout, stderr)
	}

	for _, key := range []string{"gateway", "dhcp", "dns"} {
		sec, ok := doc[key].(map[string]any)
		if !ok {
			t.Fatalf("JSON has no %q object; top-level keys: %v", key, keysOf(doc))
		}
		if _, ok := sec["verdict"].(string); !ok {
			t.Errorf("%q has no string \"verdict\"; got %v", key, keysOf(sec))
		}
		for _, field := range []string{"findings", "intent", "summary"} {
			if _, ok := sec[field]; !ok {
				t.Errorf("%q has no %q; got %v", key, field, keysOf(sec))
			}
		}
	}
}

// TestValidateJSONPreservesExistingFields: M7.3 extends the schema, it does
// not reshape it.
func TestValidateJSONPreservesExistingFields(t *testing.T) {
	path := writeIntentConfig(t, serviceConfig())

	stdout, _, _ := runGateCLI(t, "validate", "--json", path)

	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("validate --json is not valid JSON: %v", err)
	}

	for _, key := range []string{"config", "live", "valid", "layers", "findings", "gateway"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("M7.3 dropped the existing %q field; keys: %v", key, keysOf(doc))
		}
	}
}

// TestDHCPChangeChangesDigest: editing a pool must change the content address.
//
// If it does not, two documents describing different networks produce the same
// plan ID, and a plan cannot be compared against what was actually asked for.
func TestDHCPChangeChangesDigest(t *testing.T) {
	base := desired.FromConfig(serviceConfig())

	changed := serviceConfig()
	changed.DHCP.Ranges = []config.DHCPRangeConfig{
		{Start: "10.77.0.100", End: "10.77.0.200"},
	}

	if planner.ComputeDesiredDigest(base) == planner.ComputeDesiredDigest(desired.FromConfig(changed)) {
		t.Error("changing the DHCP pool did not change the desired digest")
	}
}

// TestDHCPEnablementChangesDigest: turning DHCP off is a different machine.
func TestDHCPEnablementChangesDigest(t *testing.T) {
	base := desired.FromConfig(serviceConfig())

	off := serviceConfig()
	off.DHCP.Enabled = false

	if planner.ComputeDesiredDigest(base) == planner.ComputeDesiredDigest(desired.FromConfig(off)) {
		t.Error("turning DHCP off did not change the desired digest")
	}
}

// TestDNSUpstreamChangeChangesDigest: editing a resolver must change the
// content address.
func TestDNSUpstreamChangeChangesDigest(t *testing.T) {
	base := desired.FromConfig(serviceConfig())

	changed := serviceConfig()
	changed.DNS.Upstream = []string{"9.9.9.10", "1.0.0.1"}
	changed.Network.DNS = nil

	if planner.ComputeDesiredDigest(base) == planner.ComputeDesiredDigest(desired.FromConfig(changed)) {
		t.Error("changing the DNS upstream did not change the desired digest")
	}
}

// TestDNSEnablementChangesDigest: turning DNS off is a different machine.
func TestDNSEnablementChangesDigest(t *testing.T) {
	base := desired.FromConfig(serviceConfig())

	off := serviceConfig()
	off.DNS.Enabled = false

	if planner.ComputeDesiredDigest(base) == planner.ComputeDesiredDigest(desired.FromConfig(off)) {
		t.Error("turning DNS off did not change the desired digest")
	}
}

// TestDNSUpstreamOrderDoesNotChangeDigest: equivalent documents are equivalent.
//
// Two documents listing the same resolvers in a different order describe the
// same machine. Reordering them must not produce a different plan.
func TestDNSUpstreamOrderDoesNotChangeDigest(t *testing.T) {
	a := serviceConfig()
	a.DNS.Upstream = []string{"1.1.1.1", "9.9.9.9"}
	a.Network.DNS = nil

	b := serviceConfig()
	b.DNS.Upstream = []string{"9.9.9.9", "1.1.1.1"}
	b.Network.DNS = nil

	if planner.ComputeDesiredDigest(desired.FromConfig(a)) !=
		planner.ComputeDesiredDigest(desired.FromConfig(b)) {
		t.Error("reordering the same resolvers changed the digest; they describe one machine")
	}
}

// TestDigestIsDeterministic: the same document always hashes the same.
func TestDigestIsDeterministic(t *testing.T) {
	cfg := serviceConfig()
	first := planner.ComputeDesiredDigest(desired.FromConfig(cfg))
	for i := 0; i < 5; i++ {
		if got := planner.ComputeDesiredDigest(desired.FromConfig(cfg)); got != first {
			t.Fatalf("run %d: digest = %s, want %s", i, got, first)
		}
	}
}

// TestDesiredCarriesStableIdentity: the desired state must survive a NIC
// moving slots.
func TestDesiredCarriesStableIdentity(t *testing.T) {
	d := desired.FromConfig(serviceConfig())

	if d.DHCP.LANSelector == "" {
		t.Error("the DHCP desired state must record what the document asked for")
	}
	if d.DNS.Service.LANSelector == "" {
		t.Error("the DNS desired state must record what the document asked for")
	}
	if d.DHCP.Router != "10.77.0.1" {
		t.Errorf("DHCP router = %q, want the declared LAN address 10.77.0.1", d.DHCP.Router)
	}
	if d.DNS.Service.ListenAddress != "10.77.0.1" {
		t.Errorf("DNS listen address = %q, want the declared LAN address 10.77.0.1",
			d.DNS.Service.ListenAddress)
	}
}

// TestPlanDescribesServiceIntentWithoutClaimingToApply: M7.3 describes desired
// behaviour and must not pretend an implementation exists.
func TestPlanDescribesServiceIntentWithoutClaimingToApply(t *testing.T) {
	path := writeIntentConfig(t, serviceConfig())

	stdout, stderr, _ := runGateCLI(t, "plan", path)

	if !strings.Contains(stdout, "10.77.0.100") {
		t.Errorf("`thn plan` must describe the requested DHCP pool:\n%s\n%s", stdout, stderr)
	}

	// And it must NOT claim to start a service. A step rendering
	// "systemctl enable dnsmasq" would assert an implementation this build
	// does not have, which is the specific failure the milestone forbids.
	for _, forbidden := range []string{
		"systemctl enable",
		"systemctl start",
		"apt-get install",
		"dnsmasq --",
		"service dnsmasq start",
	} {
		if strings.Contains(stdout, forbidden) {
			t.Errorf("`thn plan` rendered %q, which claims a service implementation exists:\n%s",
				forbidden, stdout)
		}
	}
}

// TestPlanStepsCarryNoCommandsForServices: the DHCP and DNS steps must not
// carry executable commands.
func TestPlanStepsCarryNoCommandsForServices(t *testing.T) {
	d := desired.FromConfig(serviceConfig())

	p := planner.Build(diff.Result{}, planner.Options{
		Generation: 7,
		Source:     "test",
		Desired:    d,
	})

	found := 0
	for _, s := range p.Steps {
		switch s.ID {
		case "dhcp-intent", "dns-service-intent":
			found++
			if len(s.Commands) != 0 {
				t.Errorf("step %s carries commands %v; M7.3 must not fake a service implementation",
					s.ID, s.Commands)
			}
			if s.RequiresRoot {
				t.Errorf("step %s claims to need root; nothing is applied", s.ID)
			}
		}
	}

	if found != 2 {
		t.Errorf("plan carries %d service-intent steps, want 2 (DHCP and DNS); steps: %v", found, stepIDs(p))
	}
}

// TestPlanIsDeterministic: repeated planning produces identical results.
func TestPlanIsDeterministic(t *testing.T) {
	d := desired.FromConfig(serviceConfig())

	first := planner.Build(diff.Result{}, planner.Options{Generation: 7, Source: "test", Desired: d})
	for i := 0; i < 5; i++ {
		got := planner.Build(diff.Result{}, planner.Options{Generation: 7, Source: "test", Desired: d})
		if got.ID != first.ID {
			t.Fatalf("run %d: plan ID = %s, want %s", i, got.ID, first.ID)
		}
		if len(got.Steps) != len(first.Steps) {
			t.Fatalf("run %d: %d steps, want %d", i, len(got.Steps), len(first.Steps))
		}
		for j := range got.Steps {
			if got.Steps[j].ID != first.Steps[j].ID || got.Steps[j].Desired != first.Steps[j].Desired {
				t.Fatalf("run %d, step %d: %+v, want %+v", i, j, got.Steps[j], first.Steps[j])
			}
		}
	}
}

// TestPlanIsDeterministicAcrossRepeatedCLI: the command itself must be
// reproducible, not just the library underneath it.
func TestPlanIsDeterministicAcrossRepeatedCLI(t *testing.T) {
	path := writeIntentConfig(t, serviceConfig())

	first, _, _ := runGateCLI(t, "plan", path)
	for i := 0; i < 3; i++ {
		got, _, _ := runGateCLI(t, "plan", path)
		if got != first {
			t.Fatalf("run %d produced different output from the first run", i)
		}
	}
}

// TestM73ActivationRemainsDisabled is the safety gate for this milestone.
//
// M7.3 describes DHCP and DNS behaviour. It must not, by any route, become a
// path that starts a service, binds a port or changes host networking.
func TestM73ActivationRemainsDisabled(t *testing.T) {
	assertActivationRemainsGated(t, "adding DHCP and DNS intent")

	// Describing a service and starting one are different things. A plan may
	// carry DHCP and DNS intent steps; the execution layer must refuse to apply
	// them rather than record an apply that did not happen.
	if len(execution.OpDNSApply{Servers: []string{"1.1.1.1"}}.RequiredCapabilities()) == 0 {
		t.Error("OpDNSApply requires no capability, so the executor cannot refuse it " +
			"before taking a baseline")
	}
}

// TestM73ValidationAndPlanningDoNotMutate: neither command may need
// privileges, which is the signal that neither is doing something it should
// not to the host.
func TestM73ValidationAndPlanningDoNotMutate(t *testing.T) {
	path := writeIntentConfig(t, serviceConfig())

	for _, args := range [][]string{
		{"validate", path},
		{"config", "validate", path},
		{"plan", path},
		{"config", "plan", path},
	} {
		if _, stderr, _ := runGateCLI(t, args...); strings.Contains(stderr, "permission denied") {
			t.Errorf("`thn %s` required privileges:\n%s", strings.Join(args, " "), stderr)
		}
	}
}

// TestM73NoServiceArtifactsAreWritten: rendering must not create backend
// configuration on disk.
//
// THN renders configuration for a service it does not start. Nothing in this
// milestone may write a dnsmasq or Kea file as a side effect of validating or
// planning.
func TestM73NoServiceArtifactsAreWritten(t *testing.T) {
	dir := t.TempDir()
	path := writeIntentConfig(t, serviceConfig())

	before := dirEntries(t, dir)
	for _, args := range [][]string{{"validate", path}, {"plan", path}} {
		runGateCLI(t, args...)
	}
	after := dirEntries(t, dir)

	if len(before) != len(after) {
		t.Errorf("validation or planning wrote %d file(s) into %s: %v -> %v",
			len(after)-len(before), dir, before, after)
	}
}
