package network

import (
	"strings"

	"github.com/venth/thn-gateway/internal/guard"
)

// Structured records of what THN asked the host, and what came back.
//
// # The problem this file exists to solve
//
// Before it, every observation failure collapsed into a boolean or a bare
// string. `ParseQdiscs` returned nil on malformed output and said nothing, so
// "tc reported no queue disciplines" and "tc's output was not JSON we
// understand" were the same answer with the same evidence. An operator
// debugging that on a live gateway had nothing to go on but a guess.
//
// Worse, the collapse was silent in the direction that lies. See
// ObserveTrafficControl: a parse failure produced a TCState reporting
// QuerySucceeded=true over zero disciplines, which is precisely the shape a
// successful "this host has no shaping configured" would take. A tool that
// cannot tell those apart is not diagnosing anything.
//
// # Every probe answers the same six questions
//
//	What was probed?      Subsystem and Operation
//	What was used?        Tool, and the arguments as invoked
//	Did it execute?       Outcome, and the exit status when it did
//	What did it return?   Bytes, or a count — never the whole dump
//	Did parsing succeed?  Stage
//	Why this result?      Reason, and the underlying error preserved
//
// A question with no answer is itself an answer worth recording: ProbeNotChecked
// means nobody looked, which is different from looking and finding nothing.
//
// # Collapsed states, and why they stay separate
//
// The five outcomes below are not a severity scale. Each is a different
// operator action:
//
//	NotChecked        a THN problem: the probe was never wired up
//	ToolUnavailable   install the package
//	ExecutionFailed   usually privilege — the tool is there, THN is not root
//	ParseFailed       the tool ran and said something THN does not understand
//	NoEvidence        success. The probe worked and found nothing.
//	Evidence          success
//
// NoEvidence and Evidence are both success, which is the pair most often
// collapsed: "the probe did not find a CAKE discipline" is a working probe
// reporting a fact about the host, not a failure. Keeping them apart is what
// lets a reader tell "CAKE is not attached" from "THN could not check".
//
// # What is deliberately not recorded
//
// Full command output. An nftables ruleset or a resolv.conf is operator
// configuration, and a debug log that dumps it by default is a log that ends
// up in a bug report. Probes record counts, outcomes and truncated reasons —
// enough to locate a stage, not enough to leak a host's configuration.
// Redaction is enforced in redacted() rather than left to each caller, because
// every caller would get it wrong eventually.

// ProbeStage is where in a probe the work stopped.
//
// It is separate from Outcome because "the tool ran and printed something we
// could not parse" and "the tool could not be found" fail at different lines,
// and an operator debugging on a live host reads the stage first.
type ProbeStage string

const (
	// StageNotStarted means the probe did not run.
	StageNotStarted ProbeStage = "not-started"

	// StageLocate means finding the tool or file. A failure here is almost
	// always "not installed", which is an operator action.
	StageLocate ProbeStage = "locate"

	// StageExecute means running it. A failure here is usually privilege.
	StageExecute ProbeStage = "execute"

	// StageParse means reading its output. A failure here means the tool
	// worked and THN does not understand what it said — a THN problem, and
	// the one that is hardest to diagnose from the outside.
	StageParse ProbeStage = "parse"

	// StageClassify means turning parsed data into a verdict.
	StageClassify ProbeStage = "classify"
)

// ProbeOutcome is what a probe concluded.
//
// NotChecked is the important one. Every other outcome is a statement about
// the host; NotChecked is a statement about THN, and reporting it as "the host
// has nothing" is how a tool that never ran ends up confident.
type ProbeOutcome string

const (
	// ProbeNotChecked means nobody looked. The zero value, and the honest
	// answer for a subsystem nothing has been asked about.
	ProbeNotChecked ProbeOutcome = "not_checked"

	// ProbeToolUnavailable means the tool or file was not found.
	ProbeToolUnavailable ProbeOutcome = "tool_unavailable"

	// ProbeExecutionFailed means it was found and running it failed. On a
	// gateway this is usually insufficient privilege, and it is the single
	// most common cause of a subsystem that "cannot be queried".
	ProbeExecutionFailed ProbeOutcome = "execution_failed"

	// ProbeParseFailed means it ran and produced output THN could not read.
	//
	// Distinct from ToolUnavailable because the two call for opposite fixes:
	// one means install something, the other means THN is out of date
	// against a tool that changed its output format.
	ProbeParseFailed ProbeOutcome = "parse_failed"

	// ProbeUnexpectedOutput means it parsed, but not into the shape expected.
	//
	// The narrowest of the failure states and the most diagnostic: the bytes
	// were JSON, the JSON was an object, and it was not the object expected.
	ProbeUnexpectedOutput ProbeOutcome = "unexpected_output"

	// ProbeNoEvidence means the probe succeeded and found nothing.
	//
	// A working probe and a fact, not a failure. "No CAKE discipline is
	// attached" arrives here, and it is the only honest way that fact can be
	// reported.
	ProbeNoEvidence ProbeOutcome = "no_evidence"

	// ProbeEvidence means the probe succeeded and found what it looked for.
	ProbeEvidence ProbeOutcome = "evidence"
)

// OK reports whether the probe reached a conclusion about the host.
//
// True for both success outcomes. False for everything else INCLUDING
// NotChecked, which is the point: a probe that never ran has not established
// that the host lacks anything.
func (o ProbeOutcome) OK() bool {
	return o == ProbeEvidence || o == ProbeNoEvidence
}

// Describe renders the outcome as the phrase an operator reads.
func (o ProbeOutcome) Describe() string {
	switch o {
	case ProbeNotChecked:
		return "not checked"
	case ProbeToolUnavailable:
		return "tool unavailable"
	case ProbeExecutionFailed:
		return "execution failed"
	case ProbeParseFailed:
		return "could not parse the output"
	case ProbeUnexpectedOutput:
		return "output was not the expected shape"
	case ProbeNoEvidence:
		return "checked; no evidence found"
	case ProbeEvidence:
		return "checked; evidence found"
	default:
		return string(o)
	}
}

// Probe is a structured record of one external observation.
//
// It is a plain value with no handle, no executor and no closure, which is
// what lets it ride on the same snapshot the observations do and survive a
// JSON round trip. That is deliberate: a diagnostic that cannot be serialised
// cannot cross the IPC boundary, and the CLI and the daemon are exactly where
// a reader most wants the detail.
type Probe struct {
	// Subsystem is the thing being asked about: "nftables", "traffic-control",
	// "wireless", "link-speed", "platform".
	Subsystem string `json:"subsystem"`

	// Operation is the specific question: "list-tables", "qdisc-show",
	// "nl80211-modes", "sysfs-speed".
	Operation string `json:"operation"`

	// Stage is where the work stopped.
	Stage ProbeStage `json:"stage"`

	// Outcome is what was concluded.
	Outcome ProbeOutcome `json:"outcome"`

	// Tool is the binary or file that was consulted, empty when the probe was
	// pure computation.
	Tool string `json:"tool,omitempty"`

	// Args are the arguments as invoked, for an exec probe.
	Args []string `json:"args,omitempty"`

	// Path is the file consulted, for a filesystem probe.
	Path string `json:"path,omitempty"`

	// ExitStatus is the process exit code. Zero when no process ran, which is
	// why Outcome is checked before this is trusted.
	ExitStatus int `json:"exit_status,omitempty"`

	// Detail is the short operator-facing statement of the result.
	Detail string `json:"detail,omitempty"`

	// Reason is the underlying cause, preserved verbatim.
	//
	// Never rewritten into something tidier. "exit status 1: permission
	// denied" is what the kernel said, and paraphrasing it is how a
	// permission problem turns into a mysterious unknown.
	Reason string `json:"reason,omitempty"`

	// Count is how many items a successful probe found. It exists so that
	// "found nothing" and "found three" are distinguishable from a report
	// that simply omits the field.
	Count int `json:"count,omitempty"`
}

// NotChecked returns the record for a probe nothing was run for.
//
// Exported as a constructor rather than left to callers to write the zero
// value, because a literal `Probe{}` has an empty subsystem and an operation,
// and two blank probes are indistinguishable from two different blank probes.
func NotChecked(subsystem, operation string) Probe {
	return Probe{
		Subsystem: subsystem,
		Operation: operation,
		Stage:     StageNotStarted,
		Outcome:   ProbeNotChecked,
		Detail:    "this probe was never run, so nothing is known about " + subsystem,
	}
}

// failed builds a failure record, preserving the cause.
//
// Every failure path in the observation layer goes through here, which is what
// makes the "no silent failure" rule mechanical rather than a habit: there is
// one place to forget, and it is a constructor call.
//
// The cause is redacted on the way in. That is not a small detail — it is the
// only place every recorded error passes through, so redaction here is
// enforced rather than remembered, and every call site gets it for free.
func failed(p Probe, stage ProbeStage, outcome ProbeOutcome, detail string, err error) Probe {
	p.Stage = stage
	p.Outcome = outcome
	p.Detail = redacted(detail)
	if err != nil {
		p.Reason = redacted(err.Error())
	}
	return p
}

// Succeeded builds a success record.
//
// count is the number of items found, and is what distinguishes "the probe
// worked and there is nothing here" from "the probe did not run".
func Succeeded(p Probe, detail string, count int) Probe {
	p.Stage = StageClassify
	p.Count = count
	p.Detail = redacted(detail)
	if count > 0 {
		p.Outcome = ProbeEvidence
	} else {
		p.Outcome = ProbeNoEvidence
	}
	return p
}

// classifyExecError maps an execution error onto an outcome.
//
// The tool-present question comes first because it is the one that decides
// which of two opposite fixes applies. An error mentioning "not found" from a
// shell is not the same thing as a command that ran and exited non-zero, and
// treating them alike produces the "install a package you already have"
// outcome that is the worst thing a diagnostic tool can say.
func classifyExecError(err error) (ProbeOutcome, string) {
	if err == nil {
		return ProbeEvidence, ""
	}
	if isMissingTool(err) {
		return ProbeToolUnavailable, "the tool is not installed or not on PATH"
	}
	return ProbeExecutionFailed, "the tool ran but did not succeed"
}

// ExecProbe records a command that was run through the guard.
//
// exitStatus and stderr come from guard.Output when a process was created at
// all. Both are zero when none was — the command was denied by policy, or
// could not be located — and Outcome is what distinguishes those cases.
func ExecProbe(subsystem, operation, tool string, args []string, out *guard.Output, err error) Probe {
	p := Probe{
		Subsystem: subsystem,
		Operation: operation,
		Tool:      tool,
		Args:      append([]string(nil), args...),
	}
	if out != nil {
		p.ExitStatus = out.ExitCode
	}

	outcome, detail := classifyExecError(err)
	if err != nil {
		return failed(p, StageExecute, outcome, detail, err)
	}
	return Succeeded(p, "the command succeeded", 0)
}

// FileProbe records a file that was read from the host's filesystem.
//
// Distinguishes "the file is not there" from "the file is there and THN could
// not read it" from "the file is there and did not parse", because a sysfs
// attribute that is absent and one that is unreadable lead to completely
// different conclusions about the kernel.
func FileProbe(subsystem, operation, path string, stage ProbeStage, outcome ProbeOutcome, detail string, err error) Probe {
	p := Probe{Subsystem: subsystem, Operation: operation, Path: path}
	return failed(p, stage, outcome, detail, err)
}

// redacted shortens command output to something safe to record.
//
// Probes never carry full output: an nftables ruleset or a resolv.conf is
// operator configuration, and a debug log that dumps it by default is a debug
// log that ends up pasted into a bug report. What survives is a length, a
// count, and the first line of a message that has already been chosen for
// being an error — none of which is the configuration itself.
//
// Single-line and length-capped because an error message can be arbitrarily
// long and arbitrarily shaped.
func redacted(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	const cap = 200
	if len(s) > cap {
		return s[:cap] + "…"
	}
	return s
}
