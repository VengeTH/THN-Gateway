package network_test

// M7.1.1 regression: a tool that RAN must never be scored as absent.
//
// # The bug this pins
//
// guard.Exec formats a non-zero exit as "%s: exit %d: %s", where the last %s
// is the command's own stderr. So the error string contains whatever the tool
// printed, and the previous isMissingTool substring-matched that combined
// string for "no such file or directory", "cannot find" and "executable file
// not found".
//
// The failure is not cosmetic and it points the wrong way:
//
//	ip -j addr show   prints "Cannot find device \"eth0\"" when an interface
//	                  disappears between the link and address reads
//	nft               prints "No such file or directory" for any rule it
//	                  cannot resolve
//
// Either would have been classified as "the binary is not installed", leaving
// Available=false. And a confirmed absence is scored ConfidenceObserved —
// "we were in a position to find that out".
//
// So THN would have reported "nftables: unavailable / observed" for a host
// where nft is installed and working, and the confidence column — the one that
// gates activation — would have been confidently wrong. That is the exact
// failure this product exists to prevent, and it was reachable from a routine
// message on stderr.
//
// # The fix
//
// guard.Exec returns a non-nil Output whenever a process was created and run.
// That is a structural fact requiring no reading of the tool's output, and it
// is the only sound discriminator.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/guard"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

// TestARanCommandIsNeverScoredAsAbsent is the core assertion.
func TestARanCommandIsNeverScoredAsAbsent(t *testing.T) {
	// Every one of these is a message a networking tool realistically prints
	// to stderr, and every one previously flipped the classification to
	// "not installed".
	runtime := []struct {
		name   string
		stderr string
	}{
		{"vanished interface", `Cannot find device "eth0"`},
		{"missing rule target", `Error: Could not process rule: No such file or directory`},
		{"netlink cache", "netlink receive: cache initialization failed: Operation not permitted"},
		{"permission", "RTNETLINK answers: Operation not permitted"},
		{"no ruleset", `Error: No such file or directory`},
	}

	for _, tc := range runtime {
		t.Run(tc.name, func(t *testing.T) {
			out := &guard.Output{ExitCode: 1, Stderr: tc.stderr}
			err := fmt.Errorf("nft: exit 1: %s", tc.stderr)

			st := observeNFTablesWith(t, out, err)

			if !st.Available {
				t.Errorf("nft was scored as ABSENT because its stderr said %q; "+
					"the process ran, so the binary is present. reason: %q",
					tc.stderr, st.Reason)
			}
			if st.QuerySucceeded {
				t.Error("a command that exited 1 was scored as a successful query")
			}
			// The probe must record an execution failure, not an absence.
			if st.Probe.Outcome != network.ProbeExecutionFailed {
				t.Errorf("probe outcome = %q, want %q", st.Probe.Outcome, network.ProbeExecutionFailed)
			}
			if st.Probe.ExitStatus != 1 {
				t.Errorf("probe exit status = %d, want 1; the exit code is the evidence "+
					"that the tool ran and refused", st.Probe.ExitStatus)
			}
		})
	}
}

// TestAGenuinelyMissingBinaryIsStillAbsent is the other direction.
//
// The fix must not turn "not installed" into "installed but broken", or a
// minimal host would report a firewall it cannot possibly have.
func TestAGenuinelyMissingBinaryIsStillAbsent(t *testing.T) {
	// guard.Exec returns a nil Output when no process could be created.
	notFound := &os.PathError{
		Op: "exec", Path: "nft",
		Err: errors.New("executable file not found in $PATH"),
	}

	st := observeNFTablesWith(t, nil, notFound)

	if st.Available {
		t.Error("a binary that could not be executed was scored as available")
	}
	if st.Probe.Outcome != network.ProbeToolUnavailable {
		t.Errorf("probe outcome = %q, want %q", st.Probe.Outcome, network.ProbeToolUnavailable)
	}
	if !strings.Contains(st.Reason, "not installed") {
		t.Errorf("the reason does not say the tool is absent: %q", st.Reason)
	}
}

// TestAMissingBinaryIsAConfirmedAbsence is the consequence the capability
// layer depends on.
//
// A tool confirmed absent has been ESTABLISHED as absent. That is a finding,
// and it must not be softened into "unknown" — which would make a minimal host
// indistinguishable from one nobody examined.
func TestAMissingBinaryIsAConfirmedAbsence(t *testing.T) {
	notFound := &os.PathError{
		Op: "exec", Path: "nft",
		Err: errors.New("executable file not found in $PATH"),
	}
	st := observeNFTablesWith(t, nil, notFound)

	if st.Probe.Outcome.OK() {
		t.Error("a missing tool was recorded as a successful probe")
	}
	if st.Probe.Outcome.BlocksClaim() {
		t.Error("a confirmed absence was recorded as blocking a capability claim; " +
			"absence is evidence, not a gap")
	}
}

// TestTheSameMessageMeansDifferentThingsDependingOnWhetherTheProcessRan is
// the distinction in one test.
//
// "no such file or directory" appears in both a missing-binary error and a
// runtime message from a tool that exists. Only the structural signal — did a
// process get created — separates them, and getting it wrong in either
// direction is a bug.
func TestTheSameMessageMeansDifferentThingsDependingOnWhetherTheProcessRan(t *testing.T) {
	// "no such file or directory" (ENOENT) is what a missing binary reports,
	// and it is also what `nft` prints on stderr for a rule it cannot
	// resolve. Only the structural signal separates the two, and getting it
	// wrong in either direction is a bug:
	//
	//	ran      → execution_failed   the tool exists and refused
	//	absent   → tool_unavailable   the tool does not exist
	//
	// Confusing the second for the first reports a working nft as absent,
	// which a confirmed absence scores as OBSERVED.
	const msg = "no such file or directory"

	ran := observeNFTablesWith(t,
		&guard.Output{ExitCode: 1, Stderr: "Error: Could not process rule: " + msg},
		fmt.Errorf("nft: exit 1: Error: Could not process rule: %s", msg))
	never := observeNFTablesWith(t,
		nil,
		&os.PathError{Op: "fork/exec", Path: "nft", Err: os.ErrNotExist})

	if !ran.Available {
		t.Error("the command that ran was scored absent")
	}
	if never.Available {
		t.Error("the command that never started was scored present")
	}
	if ran.Probe.Outcome == never.Probe.Outcome {
		t.Errorf("both cases produced outcome %q; the same ENOENT text in a "+
			"different structural situation must classify differently",
			ran.Probe.Outcome)
	}
	if ran.Probe.Outcome != network.ProbeExecutionFailed {
		t.Errorf("a ran-but-failed command = %q, want %q", ran.Probe.Outcome, network.ProbeExecutionFailed)
	}
	if never.Probe.Outcome != network.ProbeToolUnavailable {
		t.Errorf("a never-started command = %q, want %q", never.Probe.Outcome, network.ProbeToolUnavailable)
	}
}

// observeNFTablesWith drives the real ObserveNFTables against an injected
// exec result.
//
// The subsystem observers call guard.Exec directly, so this test uses the
// package's own seam rather than a copy of the logic. What it asserts is that
// the real function classifies correctly — not that a reimplementation of it
// would.
func observeNFTablesWith(t *testing.T, out *guard.Output, err error) network.NFTablesState {
	t.Helper()
	return network.ObserveNFTablesWithRunner(t.Context(),
		func(context.Context, string, ...string) (*guard.Output, error) {
			return out, err
		})
}
