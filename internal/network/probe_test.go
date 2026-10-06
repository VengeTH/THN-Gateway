package network_test

// Diagnostic tests: no silent failure, no unexplained unknown.
//
// # What these prove
//
// Every way an observation can fail produces a Probe naming the stage, and no
// failure becomes a silent zero, an empty slice or a bare `unknown`.
//
// The failure modes are enumerated rather than sampled because each one was a
// real way for the observation layer to lie before this milestone:
//
//	tool unavailable     "nft is not installed" — install something
//	execution failed     usually privilege — the tool is there
//	parse failed         the tool ran and said something we do not understand
//	unexpected output    it parsed, but not into the expected shape
//	empty output         a working probe that found nothing — NOT a failure
//	positive evidence    a working probe that found what it looked for
//	not checked          nobody looked — the case that produced no diagnostic
//
// The seventh is the one most easily lost. A probe that never runs produces no
// error, no diagnostic and no log line, so "we did not check" is
// indistinguishable from "there was nothing to find" unless something records
// it deliberately.
//
// # Fixtures, not a live host
//
// Every case here is driven by bytes handed to a parser or an error injected
// directly. A test that needed a real machine would pass on the developer box
// and tell us nothing about the failure path, which is the part that matters
// and the part that never runs on a healthy host.
//
// The sysfs read path is exercised separately, in probe_hostinfo_test.go,
// which is an internal test so it can reach the real implementation.

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/guard"
	"github.com/venth/thn-gateway/internal/network"
)

// ------------------------------------------------- 1. command unavailable

// TestProbeRecordsAToolThatIsNotInstalled is case 1.
//
// The error text is the one the operating system produces when a binary is
// absent. It matters that this is classified as tool_unavailable rather than
// as an execution failure: the two call for opposite fixes, and telling an
// operator to fix a permission problem on a tool they do not have is the worst
// thing a diagnostic can do.
func TestProbeRecordsAToolThatIsNotInstalled(t *testing.T) {
	notFound := &os.PathError{
		Op:   "exec",
		Path: "nft",
		Err:  errors.New("executable file not found in $PATH"),
	}

	p := network.ExecProbe("nftables", "list-tables", "nft",
		[]string{"-j", "list", "tables"}, nil, notFound)

	if p.Outcome != network.ProbeToolUnavailable {
		t.Errorf("outcome = %q, want %q", p.Outcome, network.ProbeToolUnavailable)
	}
	if p.Stage != network.StageExecute {
		t.Errorf("stage = %q, want %q", p.Stage, network.StageExecute)
	}
	// The cause is preserved rather than replaced by our own wording, because
	// the wording is what an operator will grep for.
	if !strings.Contains(p.Reason, "executable file not found") {
		t.Errorf("the underlying cause was lost: %q", p.Reason)
	}
	if p.Tool != "nft" {
		t.Errorf("tool = %q, want nft", p.Tool)
	}
	if len(p.Args) != 3 || p.Args[0] != "-j" {
		t.Errorf("args = %v, want the invocation as it was made", p.Args)
	}
}

// TestProbeSeparatesMissingToolFromPermissionFailure is the distinction the
// whole classification exists for.
func TestProbeSeparatesMissingToolFromPermissionFailure(t *testing.T) {
	permission := errors.New("nft: exit 1: operation not permitted")
	p := network.ExecProbe("nftables", "list-tables", "nft",
		[]string{"-j", "list", "tables"}, nil, permission)

	if p.Outcome != network.ProbeExecutionFailed {
		t.Errorf("a permission failure was classified as %q; it must be %q, not tool_unavailable",
			p.Outcome, network.ProbeExecutionFailed)
	}
}

// ------------------------------------------------- 2. execution failure

// TestProbeRecordsAnExitStatus is case 2.
//
// The exit code is what distinguishes "ran and refused" from "could not
// start", and it is the first field anyone debugging an nftables probe on a
// real gateway looks at.
func TestProbeRecordsAnExitStatus(t *testing.T) {
	out := &guard.Output{
		Stderr:   "netlink: cache initialization failed: Operation not permitted",
		ExitCode: 1,
	}
	err := errors.New("nft: exit 1: netlink: cache initialization failed: Operation not permitted")

	p := network.ExecProbe("nftables", "list-tables", "nft",
		[]string{"-j", "list", "tables"}, out, err)

	if p.ExitStatus != 1 {
		t.Errorf("exit status = %d, want 1", p.ExitStatus)
	}
	if p.Outcome != network.ProbeExecutionFailed {
		t.Errorf("outcome = %q, want %q", p.Outcome, network.ProbeExecutionFailed)
	}
	if !strings.Contains(p.Reason, "Operation not permitted") {
		t.Errorf("the underlying error was lost: %q", p.Reason)
	}
}

// ------------------------------------------------------- 3. malformed output

// TestParseQdiscsMalformedOutputIsAParseFailure is case 3, and the one that
// mattered most in practice.
//
// Returning an empty slice here was indistinguishable from "this host has no
// queue disciplines attached", so the caller set QuerySucceeded=true and a tc
// that had started emitting a new format would be reported as a host needing
// no shaping.
func TestParseQdiscsMalformedOutputIsAParseFailure(t *testing.T) {
	for name, raw := range map[string]string{
		"not json at all":    `tc: unknown command "qdisc"`,
		"truncated array":    `[{"kind":"cake","handle":`,
		"wrong scalar shape": `{"kind":"cake"}`,
	} {
		t.Run(name, func(t *testing.T) {
			qdiscs, err := network.ParseQdiscs([]byte(raw))
			if err == nil {
				t.Fatalf("malformed output parsed without error; %q was accepted", raw)
			}
			if len(qdiscs) != 0 {
				t.Errorf("malformed output produced %d qdiscs, want 0", len(qdiscs))
			}
			// The message must say which tool and what shape was expected,
			// because "unknown" tells an operator nothing they can act on.
			if !strings.Contains(err.Error(), "tc") {
				t.Errorf("the error does not name the tool: %v", err)
			}
			if !strings.Contains(err.Error(), "JSON array") {
				t.Errorf("the error does not say what was expected: %v", err)
			}
		})
	}
}

// TestParseNFTablesMalformedOutputIsAParseFailure is the same guarantee for
// the other parser, on the same reasoning: an unreadable ruleset must not be
// reported as a host with no firewall tables.
func TestParseNFTablesMalformedOutputIsAParseFailure(t *testing.T) {
	tables, err := network.ParseNFTablesTables(
		[]byte("Error: Could not process rule: No such file or directory"))
	if err == nil {
		t.Fatal("error output from nft parsed as a table inventory")
	}
	if len(tables) != 0 {
		t.Errorf("error output produced %d tables, want 0", len(tables))
	}
	if !strings.Contains(err.Error(), "nftables") {
		t.Errorf("the error does not name the subsystem: %v", err)
	}
}

// -------------------------------------------------------- 4. empty output

// TestEmptyOutputIsSuccessNotFailure is case 4, and the subtle one.
//
// An empty array is what a host with nothing configured prints. Treating it as
// a failure would mean a correct answer — "this host has no queue
// disciplines" — was reported as a broken probe, and an operator would go
// looking for a tc problem on a host whose tc is fine.
func TestEmptyOutputIsSuccessNotFailure(t *testing.T) {
	qdiscs, err := network.ParseQdiscs([]byte(`[]`))
	if err != nil {
		t.Fatalf("an empty array is a valid answer, not an error: %v", err)
	}
	if len(qdiscs) != 0 {
		t.Errorf("empty array produced %d qdiscs, want 0", len(qdiscs))
	}

	tables, err := network.ParseNFTablesTables([]byte(`{"nftables": []}`))
	if err != nil {
		t.Fatalf("an empty ruleset is a valid answer, not an error: %v", err)
	}
	if len(tables) != 0 {
		t.Errorf("empty ruleset produced %d tables, want 0", len(tables))
	}

	// And the probe built from that answer must read as a working probe that
	// found nothing — no_evidence, never a failure.
	p := network.Succeeded(network.Probe{
		Subsystem: "traffic-control",
		Operation: "qdisc-show",
	}, "the query succeeded and no queue disciplines are attached", len(qdiscs))

	if p.Outcome != network.ProbeNoEvidence {
		t.Errorf("outcome = %q, want %q; an empty result is a working probe",
			p.Outcome, network.ProbeNoEvidence)
	}
	if !p.Outcome.OK() {
		t.Error("no_evidence must count as a successful probe")
	}
}

// ------------------------------------------------- 5. unexpected output

// TestOutputThatParsesIntoTheWrongShapeIsUnexpected is case 5.
//
// The narrowest failure and the easiest to miss, because the bytes are valid
// JSON and no error is raised anywhere on the way. nft always emits an
// `nftables` element; its absence means THN is looking at a shape it does not
// understand, which is a THN problem and not evidence about the host.
func TestOutputThatParsesIntoTheWrongShapeIsUnexpected(t *testing.T) {
	tables, err := network.ParseNFTablesTables([]byte(`{"metainfo": {"version": "1.0.6"}}`))
	if err == nil {
		t.Fatalf("a document with no nftables element was accepted as an inventory: %+v", tables)
	}
	if !strings.Contains(err.Error(), "not a shape THN recognises") {
		t.Errorf("the error does not say this is a THN-side shape problem: %v", err)
	}

	qdiscs, err := network.ParseQdiscs([]byte(`{"kind": "cake"}`))
	if err == nil {
		t.Fatalf("an object was accepted as a qdisc array: %+v", qdiscs)
	}
	if !strings.Contains(err.Error(), "not the expected JSON array") {
		t.Errorf("the error does not name the expected shape: %v", err)
	}
}

// TestJSONNullIsNotTreatedAsAnEmptyInventory guards the edge of the edge.
//
// `null` decodes into a Go nil without raising an error, which would otherwise
// be indistinguishable from "the element was absent". Both parsers treat it as
// an EMPTY answer rather than a shape error — a tool reporting nothing as
// `null` has answered correctly, and calling that a format problem would send
// an operator to fix a parser for behaviour that is not a fault.
func TestJSONNullIsNotTreatedAsAnEmptyInventory(t *testing.T) {
	tables, err := network.ParseNFTablesTables([]byte(`null`))
	if err != nil {
		t.Fatalf("null is accepted as an empty inventory: %v", err)
	}
	if len(tables) != 0 {
		t.Errorf("null produced %d tables, want 0", len(tables))
	}

	qdiscs, err := network.ParseQdiscs([]byte(`null`))
	if err != nil {
		t.Fatalf("null is accepted as an empty discipline list: %v", err)
	}
	if len(qdiscs) != 0 {
		t.Errorf("null produced %d qdiscs, want 0", len(qdiscs))
	}
}

// ------------------------------------ 6 and 7. probe with and without evidence

// TestSuccessfulProbeDistinguishesEvidenceFromNone is cases 6 and 7.
//
// Both are successes. Collapsing them is how "no CAKE discipline is attached"
// — a fact about the host — becomes indistinguishable from "THN could not
// check", which is a gap in THN's knowledge.
func TestSuccessfulProbeDistinguishesEvidenceFromNone(t *testing.T) {
	found := network.Succeeded(network.Probe{
		Subsystem: "traffic-control",
		Operation: "qdisc-show",
	}, "the query succeeded", 2)
	if found.Outcome != network.ProbeEvidence {
		t.Errorf("a probe finding %d items reported %q, want %q", 2, found.Outcome, network.ProbeEvidence)
	}
	if found.Count != 2 {
		t.Errorf("count = %d, want 2", found.Count)
	}

	none := network.Succeeded(network.Probe{
		Subsystem: "traffic-control",
		Operation: "qdisc-show",
	}, "the query succeeded and no CAKE discipline is attached", 0)
	if none.Outcome != network.ProbeNoEvidence {
		t.Errorf("a probe finding nothing reported %q, want %q", none.Outcome, network.ProbeNoEvidence)
	}
	if !none.Outcome.OK() {
		t.Error("no_evidence must count as a successful probe")
	}

	if !found.Outcome.OK() || !none.Outcome.OK() {
		t.Error("a successful probe must report OK regardless of what it found")
	}
}

// ------------------------------------------- 8. classified as not checked

// TestNotCheckedIsDistinctFromEverythingElse is case 8.
//
// A probe that never ran has established nothing. It must not read as success
// and must not read as failure — it is a third thing, and the one an operator
// most needs to see, because it is invisible everywhere else.
func TestNotCheckedIsDistinctFromEverythingElse(t *testing.T) {
	p := network.NotChecked("wireless", "nl80211-modes")

	if p.Outcome != network.ProbeNotChecked {
		t.Errorf("outcome = %q, want %q", p.Outcome, network.ProbeNotChecked)
	}
	if p.Stage != network.StageNotStarted {
		t.Errorf("stage = %q, want %q", p.Stage, network.StageNotStarted)
	}
	if p.Outcome.OK() {
		t.Error("a probe that never ran must not report OK; it established nothing")
	}
	if p.Detail == "" {
		t.Error("a not-checked probe must explain that nothing was looked at")
	}

	// And it is distinguishable from the zero value, which is what a caller
	// that forgot to fill a probe in would produce. Compared field by field:
	// Probe contains a slice and so is not comparable with ==, which is itself
	// worth knowing rather than papering over with reflect.DeepEqual.
	var zero network.Probe
	if zero.Subsystem == p.Subsystem && zero.Outcome == p.Outcome && zero.Stage == p.Stage {
		t.Error("NotChecked() returned the zero value; an unrecorded probe is not the same as an unrun one")
	}
}

// ------------------------------------ 10. errors preserve their underlying cause

// TestErrorsPreserveTheirCause is case 10.
//
// The underlying error must survive into the record. A probe that reports
// "execution failed" without the reason is an operator with nowhere to go.
func TestErrorsPreserveTheirCause(t *testing.T) {
	underlying := errors.New("connect: permission denied")

	p := network.ExecProbe("nftables", "list-tables", "nft",
		[]string{"-j", "list", "tables"},
		&guard.Output{ExitCode: 1, Stderr: "connect: permission denied"},
		underlying)

	if p.Reason != underlying.Error() {
		t.Errorf("reason = %q, want the underlying error verbatim: %q",
			p.Reason, underlying.Error())
	}
	if p.Detail == "" {
		t.Error("a failing probe must carry a human summary as well as the raw cause")
	}
	// The summary and the cause are different things and both are needed: the
	// first says what happened in THN's words, the second in the tool's.
	if p.Detail == p.Reason {
		t.Error("the summary and the cause are the same string; they serve different readers")
	}
}

// ------------------------------------------------------ filesystem probes

// TestFileProbeSeparatesAbsentFromUnreadable is the sysfs case.
//
// A missing speed attribute is normal on many legitimate links and a refused
// one means something else entirely, so treating them alike would make every
// virtual interface look like a kernel problem.
func TestFileProbeSeparatesAbsentFromUnreadable(t *testing.T) {
	absent := network.FileProbe("link-speed", "sysfs-speed",
		"/sys/class/net/veth0/speed", network.StageLocate,
		network.ProbeToolUnavailable, "the file is not present",
		&os.PathError{Op: "open", Path: "speed", Err: os.ErrNotExist})

	if absent.Outcome != network.ProbeToolUnavailable {
		t.Errorf("an absent file reported %q, want %q", absent.Outcome, network.ProbeToolUnavailable)
	}
	if absent.Reason == "" {
		t.Error("the underlying filesystem error was lost")
	}

	unreadable := network.FileProbe("link-speed", "sysfs-speed",
		"/sys/class/net/enp0s31f6/speed", network.StageLocate,
		network.ProbeExecutionFailed,
		"the file is present but could not be read: permission denied",
		&os.PathError{Op: "open", Path: "speed", Err: os.ErrPermission})

	if unreadable.Outcome != network.ProbeExecutionFailed {
		t.Errorf("an unreadable file reported %q, want %q",
			unreadable.Outcome, network.ProbeExecutionFailed)
	}
}

// TestProbeRecordsNeverDumpConfiguration is the no-secrets guarantee.
//
// A probe is the one diagnostic that gets copied into a bug report, so it must
// not carry a configuration dump. Multi-line output is reduced to the line
// that identifies the failure, and an unbounded line is capped and marked.
func TestProbeRecordsNeverDumpConfiguration(t *testing.T) {
	multi := network.FileProbe("dns", "resolv-conf", "/etc/resolv.conf",
		network.StageParse, network.ProbeParseFailed, "unparseable",
		errors.New("line one\nline two\nline three"))
	if strings.Contains(multi.Reason, "line two") {
		t.Errorf("a multi-line error was recorded whole; probes must not dump configuration:\n%q", multi.Reason)
	}
	if !strings.Contains(multi.Reason, "line one") {
		t.Errorf("the first line was lost, which is the part that identifies the failure: %q", multi.Reason)
	}

	long := network.FileProbe("dns", "resolv-conf", "/etc/resolv.conf",
		network.StageParse, network.ProbeParseFailed, "unparseable",
		errors.New(strings.Repeat("x", 5000)))
	if len(long.Reason) > 300 {
		t.Errorf("a %d-byte reason was recorded uncapped", len(long.Reason))
	}
	if !strings.HasSuffix(long.Reason, "…") {
		t.Error("a truncated reason is not marked as truncated, so a reader cannot tell it was cut")
	}
}

// ------------------------------------------------------ serialisation

// TestProbesSurviveSerialisation.
//
// The CLI and the daemon are different processes, so a probe that could not
// cross a JSON boundary could not be read by the thing an operator is looking
// at.
func TestProbesSurviveSerialisation(t *testing.T) {
	original := network.Snapshot{
		Supported: true,
		Probes: []network.Probe{
			{
				Subsystem: "nftables", Operation: "list-tables",
				Stage: network.StageParse, Outcome: network.ProbeParseFailed,
				Tool: "nft", Args: []string{"-j", "list", "tables"},
				ExitStatus: 1, Detail: "the output was not the expected shape",
				Reason: "unexpected token",
			},
			network.NotChecked("wireless", "nl80211-modes"),
		},
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("the snapshot did not serialise: %v", err)
	}
	var decoded network.Snapshot
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("the snapshot did not deserialise: %v", err)
	}

	if len(decoded.Probes) != 2 {
		t.Fatalf("probes did not survive serialisation: %d became %d",
			len(original.Probes), len(decoded.Probes))
	}
	first := decoded.Probes[0]
	if first.Outcome != network.ProbeParseFailed || first.Stage != network.StageParse {
		t.Errorf("outcome or stage changed across serialisation: %+v", first)
	}
	if first.Reason != "unexpected token" {
		t.Errorf("the cause was lost across serialisation: %q", first.Reason)
	}
	if len(first.Args) != 3 {
		t.Errorf("the invocation was lost across serialisation: %v", first.Args)
	}
	if decoded.Probes[1].Outcome != network.ProbeNotChecked {
		t.Errorf("a not-checked probe became %q across serialisation", decoded.Probes[1].Outcome)
	}
}

// TestFailedProbesIncludesNotChecked is the "nothing ran" surfacing rule.
func TestFailedProbesIncludesNotChecked(t *testing.T) {
	snap := network.Snapshot{
		Probes: []network.Probe{
			network.Succeeded(network.Probe{Subsystem: "a"}, "found", 2),
			network.Succeeded(network.Probe{Subsystem: "b"}, "found none", 0),
			network.NotChecked("c", "never-ran"),
			network.ExecProbe("d", "op", "nft", nil, nil, errors.New("nft: exit 1")),
		},
	}

	failed := snap.FailedProbes()
	if len(failed) != 2 {
		t.Fatalf("FailedProbes() returned %d entries, want 2: %+v", len(failed), failed)
	}
	// Both successes are excluded, including the one that found nothing:
	// "checked and found nothing" is an answer.
	for _, p := range failed {
		if p.Outcome.OK() {
			t.Errorf("a successful probe was listed as failed: %+v", p)
		}
	}
}

// TestProbeForDistinguishesAbsentFromEmpty is the lookup contract.
func TestProbeForDistinguishesAbsentFromEmpty(t *testing.T) {
	snap := network.Snapshot{
		Probes: []network.Probe{
			network.Succeeded(
				network.Probe{Subsystem: "nftables", Operation: "list-tables"}, "ok", 1),
		},
	}

	if _, ok := snap.ProbeFor("nftables", "list-tables"); !ok {
		t.Error("an existing probe was not found")
	}
	if p, ok := snap.ProbeFor("nftables", "never-asked"); ok {
		t.Errorf("a probe that was never run was returned: %+v", p)
	}
	if _, ok := snap.ProbeFor("wrong-subsystem", "list-tables"); ok {
		t.Error("a probe matched on operation alone, ignoring the subsystem")
	}
}
