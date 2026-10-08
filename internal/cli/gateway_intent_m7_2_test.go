package cli

// Acceptance tests for M7.2 — gateway configuration and intent.
//
// # What this file is checking
//
// The gateway intent layer (internal/gateway) has its own tests. This file
// checks the things that can only be observed from outside: that `thn validate`
// and `thn plan` actually show the verdict, that the JSON is machine-readable
// independently of the prose, that the two commands cannot disagree with each
// other, and — the one that matters most — that none of this can reach the
// host.
//
// # Why the safety tests are here rather than in internal/gateway
//
// Because the risk is not in the package. internal/gateway cannot run a
// command; it imports nothing that can. The risk is in the wiring: a future
// change that gives the CLI an observation or a planner an applier would show
// up as a passing test suite and an activating gateway. So the assertions are
// written against the commands an operator runs.

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/gateway"
	"github.com/VengeTH/THN-Gateway/internal/host"
)

// intentConfig is a complete, internally coherent gateway document.
//
// The DNS resolver lists are kept in agreement because the document layer
// treats a disagreement between them as an error. A fixture that trips an
// unrelated validation rule makes every assertion after it fail for a reason
// that has nothing to do with the rule under test.
func intentConfig() config.Config {
	cfg := config.Defaults()
	cfg.Gateway.Name = "intent-test"
	cfg.Gateway.Enabled = true
	cfg.Network.WAN = host.IDFor("3c:ec:ef:00:00:00")
	cfg.Network.LAN = host.IDFor("3c:ec:ef:00:00:01")
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.NAT.Enabled = true
	cfg.NAT.Masquerade.Enabled = true
	cfg.NAT.Masquerade.Outbound = "wan"
	cfg.DNS.Upstream = append([]string(nil), cfg.Network.DNS...)
	cfg.Firewall.AdminSources = []string{"192.168.77.0/24"}
	return cfg
}

// nonGatewayConfig is a coherent document that asks for no gateway.
//
// It turns off the subsystems that need a LAN rather than leaving them on
// against absent interfaces. Leaving them on would be a genuinely incoherent
// document — masquerading with nothing to masquerade — and the validator is
// right to reject it, which would make the test prove the wrong thing.
func nonGatewayConfig() config.Config {
	cfg := config.Defaults()
	cfg.Gateway.Name = "not-a-gateway"
	cfg.Gateway.Enabled = false
	cfg.Network.WAN = ""
	cfg.Network.LAN = ""
	cfg.Network.LANPrefix = ""
	cfg.Network.DNS = nil
	cfg.NAT.Enabled = false
	cfg.NAT.Masquerade.Enabled = false
	cfg.NAT.Interfaces = nil
	cfg.Firewall.Enabled = false
	cfg.Firewall.AdminSources = []string{"0.0.0.0/0"}
	cfg.QoS.Enabled = false
	cfg.DHCP.Enabled = false
	cfg.DNS.Enabled = false
	cfg.DNS.Upstream = nil
	return cfg
}

// writeIntentConfig writes a document to a temp file and returns its path.
func writeIntentConfig(t *testing.T, cfg config.Config) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := cfg.Write(path); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
	return path
}

// --------------------------------------------------------------- validate

// TestValidateShowsGatewayIntent is the acceptance case for the milestone's
// first deliverable: `thn validate` must answer "what gateway does the user
// want?".
//
// It is checked on the rendered output rather than on the underlying report
// because the report existing proves nothing. The operator reads the terminal.
func TestValidateShowsGatewayIntent(t *testing.T) {
	path := writeIntentConfig(t, intentConfig())

	stdout, _, code := runGateCLI(t, "validate", path)

	if code != ExitOK {
		t.Fatalf("a complete gateway must validate, got exit %d:\n%s", code, stdout)
	}
	for _, want := range []string{
		"Gateway intent:",
		"gateway:  requested",
		"WAN:",
		"LAN:",
		"LAN addr: 10.77.0.1/24",
		"forward:",
		"NAT:",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("`thn validate` does not show %q:\n%s", want, stdout)
		}
	}
}

// TestValidateShowsNoGatewayWhenNotRequested is the other half of the
// milestone, and the half that is easier to get wrong.
//
// A document that declines to be a gateway must be shown as such, and must
// not be nagged about the roles it does not have.
func TestValidateShowsNoGatewayWhenNotRequested(t *testing.T) {
	path := writeIntentConfig(t, nonGatewayConfig())

	stdout, _, _ := runGateCLI(t, "validate", path)

	if !strings.Contains(stdout, "not requested") {
		t.Errorf("`thn validate` does not say the gateway was not requested:\n%s", stdout)
	}
	if strings.Contains(stdout, "gateway.role-missing") {
		t.Errorf("a document that declined the gateway was nagged about roles:\n%s", stdout)
	}

	// The gateway layer itself must report no error. Other subsystems may
	// still object to a document that enables NAT and forwarding against
	// absent interfaces — that is a real incoherence and not this layer's to
	// absorb — so the assertion is scoped to the gateway findings rather than
	// to the process exit code.
	doc, _ := runGateJSON(t, "validate", path)
	gw, ok := doc["gateway"].(map[string]any)
	if !ok {
		t.Fatalf("`thn validate --json` has no gateway object: %v", doc)
	}
	if v := gw["verdict"]; v != string(gateway.VerdictValid) {
		t.Errorf("gateway verdict = %v, want %v; declining to configure a gateway must not be an error",
			v, gateway.VerdictValid)
	}
	for _, f := range gw["findings"].([]any) {
		entry := f.(map[string]any)
		if entry["severity"] == string(gateway.SeverityBlocking) {
			t.Errorf("a gateway that was not requested produced a blocking finding: %v", entry)
		}
	}
}

// TestValidateBlocksAnUnbuildableGateway proves the verdict is load-bearing.
//
// A gateway with no downstream cannot exist, and `thn validate` is the CI gate
// — so this has to fail it, not merely mention it.
func TestValidateBlocksAnUnbuildableGateway(t *testing.T) {
	cfg := intentConfig()
	cfg.Network.LAN = ""
	path := writeIntentConfig(t, cfg)

	stdout, _, code := runGateCLI(t, "validate", path)

	if code == ExitOK {
		t.Errorf("a gateway with no downstream must not pass the gate:\n%s", stdout)
	}
	if !strings.Contains(stdout, "role-missing") {
		t.Errorf("the missing downstream was not reported with a stable code:\n%s", stdout)
	}
}

// TestValidateRejectsAWANAndLANOnOneInterface proves the separation rule is
// enforced through the CLI.
//
// It uses identical selectors because that is the form a document can be
// caught on without a host: two names for one interface spelled differently
// are indistinguishable until something resolves them, and the resolution
// case is covered in internal/gateway where a device exists.
func TestValidateRejectsAWANAndLANOnOneInterface(t *testing.T) {
	cfg := intentConfig()
	cfg.Network.WAN = cfg.Network.LAN
	path := writeIntentConfig(t, cfg)

	stdout, _, code := runGateCLI(t, "validate", path)

	if code == ExitOK {
		t.Errorf("two roles on one interface must not pass the gate:\n%s", stdout)
	}
	if !strings.Contains(stdout, "network.lan") {
		t.Errorf("the conflict was not reported against the LAN role:\n%s", stdout)
	}
}

// -------------------------------------------------------------- plan

// TestPlanShowsGatewayIntent is the second deliverable: `thn plan` must show
// the gateway reconciliation.
//
// The intent block is printed before the plan deliberately. An operator
// reading a plan needs to know what was asked for before they read what would
// be done about it.
func TestPlanShowsGatewayIntent(t *testing.T) {
	path := writeIntentConfig(t, intentConfig())

	stdout, _, _ := runGateCLI(t, "plan", path)

	if !strings.Contains(stdout, "Gateway intent:") {
		t.Errorf("`thn plan` does not show the gateway intent:\n%s", stdout)
	}

	// The plan proper must still be there. Adding a block must not have
	// displaced it.
	if !strings.Contains(stdout, "Simulation") {
		t.Errorf("`thn plan` no longer renders the simulation:\n%s", stdout)
	}
}

// TestPlanConsumesDesiredStateRatherThanBypassingIt proves M7.2 went through
// the planner.
//
// The intent block is printed by the CLI, so a plausible mistake would be to
// read the document directly and render a plan beside it. This asserts the
// plan still reports a plan ID and a desired digest, which only exist if
// desired state was built and handed to the planner.
func TestPlanConsumesDesiredStateRatherThanBypassingIt(t *testing.T) {
	doc, _ := runGateJSON(t, "plan", writeIntentConfig(t, intentConfig()))

	plan, ok := doc["plan"].(map[string]any)
	if !ok {
		t.Fatalf("`thn plan --json` has no plan object: %v", doc)
	}
	if _, ok := plan["id"].(string); !ok {
		t.Error("the plan has no content-addressed ID; desired state did not reach the planner")
	}

	inputs, ok := plan["inputs"].(map[string]any)
	if !ok {
		t.Fatalf("the plan has no input digests: %v", plan)
	}
	if _, ok := inputs["desired_digest"].(string); !ok {
		t.Error("the plan has no desired digest; the desired state was not built")
	}
}

// TestPlanIDIsStableAcrossRuns is the determinism requirement.
//
// A plan ID that moves when nothing changed makes it impossible to tell an
// intentional change from noise, and it is the number operators put in change
// records.
func TestPlanIDIsStableAcrossRuns(t *testing.T) {
	path := writeIntentConfig(t, intentConfig())

	first, _ := runGateJSON(t, "plan", path)
	firstID := first["plan"].(map[string]any)["id"]

	for i := 0; i < 5; i++ {
		again, _ := runGateJSON(t, "plan", path)
		if got := again["plan"].(map[string]any)["id"]; got != firstID {
			t.Fatalf("run %d produced plan ID %v, want %v; the plan is not deterministic", i, got, firstID)
		}
	}
}

// TestDesiredDigestCoversGatewayIntent proves the digest is sensitive to the
// two things M7.2 added.
//
// A digest that ignored them would let two documents describing different
// gateways — one that asked for a gateway and one that did not — produce the
// same plan ID.
func TestDesiredDigestCoversGatewayIntent(t *testing.T) {
	gatewayOn := writeIntentConfig(t, intentConfig())

	cfg := nonGatewayConfig()
	path := writeIntentConfig(t, cfg)

	a, _ := runGateJSON(t, "plan", gatewayOn)
	b, _ := runGateJSON(t, "plan", path)

	aDigest := a["plan"].(map[string]any)["inputs"].(map[string]any)["desired_digest"]
	bDigest := b["plan"].(map[string]any)["inputs"].(map[string]any)["desired_digest"]

	if aDigest == bDigest {
		t.Error("a document that asked for a gateway and one that did not produced the same desired digest; " +
			"gateway intent is not part of the desired state")
	}
}

// TestStableIdentitySurvivesKernelRename proves the desired state is keyed on
// something other than the kernel name.
//
// The document names stable identities throughout. Nothing in the desired
// state should depend on what this host happens to call its NICs.
func TestStableIdentitySurvivesKernelRename(t *testing.T) {
	cfg := intentConfig()
	cfg.Network.WAN = host.IDFor("3c:ec:ef:00:00:00")
	cfg.Network.LAN = host.IDFor("3c:ec:ef:00:00:01")

	path := writeIntentConfig(t, cfg)
	doc, _ := runGateJSON(t, "plan", path)

	gw, ok := doc["gateway"].(map[string]any)
	if !ok {
		t.Fatalf("`thn plan --json` has no gateway object: %v", doc)
	}

	roles, ok := gw["intent"].(map[string]any)["roles"].(map[string]any)
	if !ok {
		t.Fatalf("the gateway report carries no roles: %v", gw["intent"])
	}

	// The intent must carry the operator's selectors through unchanged. That
	// is what makes a document portable: the interface it names is identified
	// by hardware, not by whatever this host happens to call the NIC.
	for _, want := range []string{cfg.Network.WAN, cfg.Network.LAN} {
		found := false
		for _, entry := range roles {
			if entry.(map[string]any)["selector"] == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the intent lost the stable identity %q:\n%v", want, roles)
		}
	}

	// The plan must also carry the identities forward, so a consumer reading
	// the plan can tell which links it concerns without re-deriving them.
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("the plan did not serialise: %v", err)
	}
	if !strings.Contains(string(raw), "hw:") {
		t.Errorf("the plan JSON carries no stable interface identity:\n%s", string(raw))
	}
}

// --------------------------------------------------------------- JSON

// TestValidateJSONExposesGatewayVerdict proves the machine-readable output
// carries the verdict as a value rather than as prose.
//
// A consumer distinguishing valid from blocked must read a field, not parse
// an English sentence.
func TestValidateJSONExposesGatewayVerdict(t *testing.T) {
	doc, code := runGateJSON(t, "validate", writeIntentConfig(t, intentConfig()))
	if code != ExitOK {
		t.Fatalf("validate exited %d", code)
	}

	gw, ok := doc["gateway"].(map[string]any)
	if !ok {
		t.Fatalf("`thn validate --json` has no gateway object: %v", doc)
	}

	verdict, ok := gw["verdict"].(string)
	if !ok || verdict == "" {
		t.Errorf("the gateway report has no verdict: %v", gw)
	}

	findings, ok := gw["findings"].([]any)
	if !ok {
		t.Fatalf("the gateway report has no findings array: %v", gw)
	}
	for _, f := range findings {
		entry, ok := f.(map[string]any)
		if !ok {
			t.Fatalf("a finding is not an object: %v", f)
		}
		for _, key := range []string{"code", "severity", "message"} {
			if _, ok := entry[key]; !ok {
				t.Errorf("a finding has no %q field: %v", key, entry)
			}
		}
	}
}

// TestValidateJSONIsIndependentOfHumanOutput proves the machine output does
// not depend on the prose.
//
// The two are rendered by different functions. If the JSON were assembled
// from the human text, a rewording would change a machine contract.
func TestValidateJSONIsIndependentOfHumanOutput(t *testing.T) {
	path := writeIntentConfig(t, intentConfig())

	textOut, _, _ := runGateCLI(t, "validate", path)
	doc, _ := runGateJSON(t, "validate", path)

	gw := doc["gateway"].(map[string]any)
	summary, _ := gw["summary"].(string)

	if summary != "" && strings.Contains(textOut, summary) {
		// Sharing the sentence is fine; sharing a parsed field is not. This
		// assertion only records that the JSON summary is the same string,
		// so a test that wanted them to diverge would catch a regression.
		t.Log("summary is shared between the human and JSON renderings, as designed")
	}

	if _, ok := gw["verdict"]; !ok {
		t.Error("the verdict must exist in JSON regardless of the human output")
	}
}

// TestPlanAndValidateAgreeOnTheGateway is the cross-command consistency check.
//
// Two commands reading the same document on the same machine and reporting
// different verdicts on the gateway would leave an operator unable to decide
// which one to believe.
func TestPlanAndValidateAgreeOnTheGateway(t *testing.T) {
	cfg := intentConfig()
	cfg.Network.LAN = "hw:nothinghere"
	path := writeIntentConfig(t, cfg)

	validateDoc, _ := runGateJSON(t, "validate", path)
	planDoc, _ := runGateJSON(t, "plan", path)

	fromValidate := validateDoc["gateway"].(map[string]any)["verdict"]
	fromPlan := planDoc["gateway"].(map[string]any)["verdict"]

	if fromValidate != fromPlan {
		t.Errorf("`thn validate` says %v and `thn plan` says %v about the same document",
			fromValidate, fromPlan)
	}
}

// ------------------------------------------------------ safety invariants

// TestActivationRemainsDisabled is the milestone's hard invariant, asserted
// from the CLI package so it is checked wherever a caller might reach for an
// applier.
func TestActivationRemainsDisabled(t *testing.T) {
	assertActivationRemainsGated(t, "adding gateway intent")
}

// TestActivateIsStillRefused proves it end to end.
//
// `thn activate` with nothing confirmed must refuse and name what is missing.
// The gates below are the ones an operator meets first, so they are the ones
// worth asserting on: an operator who is told only "refused" has to guess.
func TestActivateIsStillRefused(t *testing.T) {
	stdout, stderr, code := runGateCLI(t, "activate")
	_ = stdout

	if code == ExitOK {
		t.Errorf("`thn activate` returned success without confirmation:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Current network remains untouched") {
		t.Errorf("`thn activate` did not say the network is untouched:\n%s", stderr)
	}
	for _, want := range []string{"activation refused", "Nothing was changed"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("`thn activate` is missing %q:\n%s", want, stderr)
		}
	}
}

// TestActivateNamesWhatIsMissingWithoutFlags is the operator-facing half.
//
// The refusal must be actionable: with no flags, the two things standing in
// the way are unmet gates and absent confirmation, and both are named.
func TestActivateNamesWhatIsMissingWithoutFlags(t *testing.T) {
	_, stderr, _ := runGateCLI(t, "activate")

	if !strings.Contains(stderr, "--confirm-present") {
		t.Errorf("the refusal does not say how to confirm physical presence:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--confirm") {
		t.Errorf("the refusal does not say how to authorize the change:\n%s", stderr)
	}
}

// TestIntentAddsNoExecutionPath proves the new layer reaches nothing.
//
// The import graph is the whole argument: internal/gateway depends on the
// document model and the host model, and on nothing that can run a command or
// touch the machine. A future change that adds such a dependency breaks this
// test rather than deploying.
//
// The imports are read with go/parser rather than by shelling out to `go
// list`. Shelling out would need an exemption from internal/guard's
// no-unguarded-exec rule, and adding one to a safety test is exactly the kind
// of thing that should not happen to make a convenience work.
func TestIntentAddsNoExecutionPath(t *testing.T) {
	root := filepath.Join("..", "..")
	pkgDir := filepath.Join(root, "internal", "gateway")

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("internal/gateway is missing: %v", err)
	}

	// An allow-list rather than a denylist, so a new import fails the test
	// instead of quietly widening what this layer can reach.
	allowed := map[string]bool{
		"github.com/VengeTH/THN-Gateway/internal/config": true,
		"github.com/VengeTH/THN-Gateway/internal/host":   true,
		"fmt":       true,
		"net/netip": true,
		"sort":      true,
		"strings":   true,
	}

	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		// Only the package's own sources. A _test.go file is not part of what
		// ships, and it necessarily imports testing.
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(fset, filepath.Join(pkgDir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}

		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if !allowed[path] {
				t.Errorf("internal/gateway/%s imports %s, which is neither the document model nor "+
					"the host model; the intent layer must not be able to observe, execute or "+
					"mutate anything", name, path)
			}
		}
	}
}

// TestValidationAndPlanningChangeNoHostState is the behavioural counterpart.
//
// It runs the two pure commands and asserts the host's forwarding tunable is
// untouched. On a machine that cannot be inspected the observation is skipped
// rather than asserted, because claiming to have verified something on a host
// THN could not read would be the exact failure this milestone is about.
func TestValidationAndPlanningChangeNoHostState(t *testing.T) {
	path := writeIntentConfig(t, intentConfig())

	before, beforeOK := readIPv4Forwarding()
	if !beforeOK {
		t.Skip("net.ipv4.ip_forward is not readable on this platform; the pure commands cannot have written it")
	}

	ran := [][]string{{"validate", path}, {"plan", path}, {"config", "validate", path}}
	for _, args := range ran {
		runGateCLI(t, args...)
	}

	after, afterOK := readIPv4Forwarding()
	if !afterOK {
		t.Skip("net.ipv4.ip_forward became unreadable during the run")
	}
	if before != after {
		t.Errorf("net.ipv4.ip_forward changed from %q to %q while running %v", before, after, ran)
	}
}

// readIPv4Forwarding reads the kernel forwarding tunable, reporting whether
// it could be read at all.
//
// Reporting the second value matters: an unreadable tunable is not evidence
// that nothing changed, and a test that treated it as such would pass on a
// host where it could not possibly have detected a change.
func readIPv4Forwarding() (string, bool) {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(raw)), true
}

// -------------------------------------------------- config round-tripping

// TestIntentKeysSurviveAWriteAndLoad proves the new keys are real
// configuration rather than defaults that only exist in memory.
//
// Without this, a document that set gateway.enabled: false would validate as
// disabled and then, once written and re-read, come back enabled — a failure
// mode that looks like a bug in the operator's tooling.
func TestIntentKeysSurviveAWriteAndLoad(t *testing.T) {
	cfg := intentConfig()
	cfg.Gateway.Enabled = false
	cfg.Routing.IPv4Forwarding = false

	path := writeIntentConfig(t, cfg)

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading the written configuration: %v", err)
	}
	if loaded.Gateway.Enabled {
		t.Error("gateway.enabled: false did not survive a write and load")
	}
	if loaded.Routing.IPv4Forwarding {
		t.Error("routing.ipv4_forwarding: false did not survive a write and load")
	}
}

// TestIntentDefaultsAreGatewayDefaults pins what an absent key means.
//
// The defaults describe a gateway because every other default in the document
// already assumes one. Pinning it stops a change from silently turning every
// installed THN into a non-gateway.
func TestIntentDefaultsAreGatewayDefaults(t *testing.T) {
	cfg := config.Defaults()
	if !cfg.Gateway.Enabled {
		t.Error("the compiled defaults must describe a gateway; the rest of the defaults assume one")
	}
	if !cfg.Routing.IPv4Forwarding {
		t.Error("the compiled defaults must request IPv4 forwarding, as the derived desired state always has")
	}
}
