package cli

// Diagnostic tests for the host command's debug channel.
//
// # The invariant these protect
//
// `--debug` changes what goes to stderr and nothing else. stdout is the
// report, and under --json it is a document a machine parses, so a diagnostic
// line printed there would corrupt the output for every consumer that is not
// a person reading a terminal.
//
// That is worth a test rather than a convention because the failure is silent
// in the worst way: the document still parses as JSON in a human's editor, so
// the corruption is discovered downstream by a script that trusted it.
//
// # What is checked
//
//   - stdout is byte-identical with and without the flag
//   - stdout remains valid JSON with both --debug and --json
//   - stderr actually receives something when the flag is on, and nothing when
//     it is off
//   - the diagnostics name the failing stage rather than emitting a bare
//     "unknown"

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

// diagDevice builds a host carrying one of every interesting diagnostic state:
// a failed probe, an unrun probe, and a successful probe that found nothing.
func diagDevice() *host.Device {
	d := analysisDevice()

	d.NFTables = network.NFTablesState{
		Checked: true, Available: true,
		// A parse failure: nft RAN and exited cleanly, and THN could not read
		// what it said. ExitStatus is therefore 0, which is the whole evidence
		// that this is a THN-side problem rather than an nft problem.
		Probe: network.Probe{
			Subsystem: "nftables", Operation: "list-tables",
			Stage: network.StageParse, Outcome: network.ProbeParseFailed,
			Tool: "nft", Args: []string{"-j", "list", "tables"}, ExitStatus: 0,
			Detail: "nft ran and produced output THN could not parse",
			Reason: "unexpected token 'Error'",
		},
	}
	d.TrafficControl = network.TCState{
		Checked: true, Available: true, QuerySucceeded: true,
		// An execution failure, so the record exercises the other exit path.
		Probe: network.Probe{
			Subsystem: "traffic-control", Operation: "qdisc-show",
			Stage: network.StageExecute, Outcome: network.ProbeExecutionFailed,
			Tool: "tc", Args: []string{"-j", "qdisc", "show"}, ExitStatus: 1,
			Detail: "the tool ran but did not succeed",
			Reason: "tc: exit 1: RTNETLINK answers: Operation not permitted",
		},
	}
	d.Probes = []network.Probe{
		d.NFTables.Probe,
		d.TrafficControl.Probe,
		network.NotChecked("wireless", "nl80211-modes"),
	}
	return d
}

// TestDebugWritesNothingToStdout is the core guarantee.
//
// Byte-identical, not merely equivalent: an operator diffing two reports
// should not see a spurious difference, and a consumer comparing two documents
// should not either.
func TestDebugWritesNothingToStdout(t *testing.T) {
	plain, _ := runHostDiag(t, diagDevice(), false, false)
	debug, _ := runHostDiag(t, diagDevice(), true, false)

	if plain != debug {
		t.Errorf("stdout differed with --debug:\n--- plain ---\n%s\n--- debug ---\n%s", plain, debug)
	}
}

// TestDebugEmitsNothingWithoutTheFlag keeps normal output clean.
//
// A diagnostic printed unconditionally would put probe records into every
// report, every test fixture and every CI log.
func TestDebugEmitsNothingWithoutTheFlag(t *testing.T) {
	_, stderr := runHostDiag(t, diagDevice(), false, false)

	if strings.Contains(stderr, "THN host diagnostics") {
		t.Errorf("diagnostics appeared without --debug:\n%s", stderr)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Errorf("something was written to stderr without --debug:\n%s", stderr)
	}
}

// TestDebugEmitsDiagnosticsWhenAsked is the positive half: the flag does
// something.
func TestDebugEmitsDiagnosticsWhenAsked(t *testing.T) {
	_, stderr := runHostDiag(t, diagDevice(), true, false)

	if !strings.Contains(stderr, "THN host diagnostics") {
		t.Fatalf("--debug produced no diagnostics:\n%s", stderr)
	}
	// A failing probe must name its stage and outcome, not just "failed".
	for _, want := range []string{
		"nftables/list-tables",
		"stage=parse",
		"outcome=parse_failed",
		"nft",
		"unexpected token",
		// The parse failure exited 0, and that zero is the evidence it was a
		// THN-side problem rather than an nft one.
		"exit=0",
		// And an execution failure carries its non-zero status.
		"traffic-control/qdisc-show",
		"stage=execute",
		"outcome=execution_failed",
		"exit=1",
		"Operation not permitted",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the diagnostics are missing %q:\n%s", want, stderr)
		}
	}
	// A probe that never ran must be visible as its own category, because it
	// is invisible everywhere else.
	if !strings.Contains(stderr, "outcome=not_checked") {
		t.Errorf("an unrun probe is not shown; it is the case with no other trace:\n%s", stderr)
	}
}

// TestJSONStaysValidWithDebugEnabled is case 9 of the requirement.
//
// Both flags together is the combination that breaks if diagnostics leak.
func TestJSONStaysValidWithDebugEnabled(t *testing.T) {
	stdout, stderr := runHostDiag(t, diagDevice(), true, true)

	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON with --debug --json: %v\n---\n%s", err, stdout)
	}
	if doc["readiness"] == nil {
		t.Error("the document is missing its readiness section; it parsed but is not the report")
	}
	// The diagnostics did happen â€” they just did not go here.
	if !strings.Contains(stderr, "THN host diagnostics") {
		t.Error("--debug --json produced no diagnostics at all")
	}
}

// TestJSONIsIdenticalWithAndWithoutDebug is the stronger form.
//
// Not "still parses" â€” identical. The document describes the host, not the
// command that produced it, so a consumer cannot tell which flags the operator
// passed.
func TestJSONIsIdenticalWithAndWithoutDebug(t *testing.T) {
	plain, _ := runHostDiag(t, diagDevice(), false, true)
	debug, _ := runHostDiag(t, diagDevice(), true, true)

	// observed_at is a timestamp, so the documents are compared with it
	// removed rather than being expected to match byte for byte.
	if stripObserved(plain) != stripObserved(debug) {
		t.Errorf("the JSON document changed with --debug:\n%s\nvs\n%s", plain, debug)
	}
}

// stripObserved removes the observation timestamp from a JSON document.
func stripObserved(doc string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		return doc
	}
	delete(m, "observed_at")
	out, err := json.Marshal(m)
	if err != nil {
		return doc
	}
	return string(out)
}

// TestUnknownsAreMachineReadable covers the M7.1 half of the requirement.
//
// An unknown an automation cannot explain is an unknown it cannot act on, so
// the cause has to be a structured field rather than a prose note.
func TestUnknownsAreMachineReadable(t *testing.T) {
	d := diagDevice()
	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})

	out := hostJSON(d, false, ready, 2, host.AnalyzeHardware(d), true)
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("the report did not serialise: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the report did not deserialise: %v", err)
	}

	hardware := doc["hardware"].(map[string]any)
	unknowns, ok := hardware["unknowns"].([]any)
	if !ok {
		t.Fatal("the hardware block has no unknowns list; an automation consumer cannot explain an unknown without it")
	}

	// The analysis device has a spare port with no speed, so there must be at
	// least one unknown and it must carry a probe.
	found := false
	for _, u := range unknowns {
		m := u.(map[string]any)
		if m["question"] != "link-speed" {
			continue
		}
		found = true
		probe, ok := m["probe"].(map[string]any)
		if !ok {
			t.Errorf("the unknown %v carries no probe record", m)
			continue
		}
		// A probe with an unset stage and outcome would be an unrecorded
		// probe wearing a probe's clothes.
		if probe["stage"] == "" || probe["outcome"] == "" {
			t.Errorf("the unknown's probe does not name its stage and outcome: %v", probe)
		}
		if m["detail"] == "" {
			t.Errorf("the unknown carries no explanation: %v", m)
		}
	}
	if !found {
		t.Errorf("the spare port's unknown speed was not reported; got %v", unknowns)
	}
}

// runHostDiag renders a host report with the debug and JSON options set,
// capturing each stream separately.
//
// It drives writeHostDiagnostics and RenderHost directly rather than the whole
// command, because these tests are about which stream each of them writes to
// and the command body would only obscure that.
func runHostDiag(t *testing.T, d *host.Device, debug, asJSON bool) (stdout, stderr string) {
	t.Helper()

	env, out, errOut := newTestEnv("host")
	env.IsJSON = asJSON

	intel := host.AnalyzeHardware(d)
	if debug {
		writeHostDiagnostics(env, d, intel, true)
	}

	ready := host.EvaluateReadiness(d, host.ReadinessRequest{RequiredInterfaces: 2})
	if asJSON {
		doc := hostJSON(d, false, ready, 2, intel, true)
		env.printf("%s", mustJSON(t, doc))
	} else {
		env.printf("%s", RenderHost(d, false, ready, intel, true))
	}
	return out.String(), errOut.String()
}
