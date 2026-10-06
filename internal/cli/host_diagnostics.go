package cli

// Structured diagnostics for "thn host --debug".
//
// # Why this is not ad-hoc printing
//
// The requirement this file serves is "no silent failure, no unexplained
// unknown". Writing that with fmt.Println scattered through the observation
// code would put diagnostics into the normal output of every command and every
// test, and would mean the JSON consumer had to filter noise out of a document
// it is entitled to parse.
//
// So the diagnostics are a projection of data the observation layer already
// records, printed only when asked for and only to stderr. Two consequences
// worth stating:
//
//   - JSON output is byte-identical with and without the debug flag. A
//     consumer cannot tell which flags the operator passed, which is the
//     point: the document describes the host, not the command that made it.
//
//   - A diagnostic can never be the only source of a fact. Everything printed
//     here already exists in the Device, the Snapshot and the M7.1 analysis.
//     Deleting this file would lose presentation, not information.
//
// # What is deliberately absent
//
// Full command output. An nftables ruleset, a resolv.conf, a routing table:
// these are operator configuration, and a debug log that dumps them by default
// is a debug log that ends up pasted into a bug report. Probes carry counts,
// outcomes and truncated reasons, which is enough to locate a stage and not
// enough to leak the host.
//
// Nothing here reaches the network, executes anything, or writes to the
// filesystem. Debugging an observation layer must not become a way to mutate
// the machine being observed.

import (
	"fmt"
	"strings"

	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/network"
)

// writeHostDiagnostics prints the diagnostic record for the host command in
// debug mode.
//
// Everything goes to stderr. Stdout belongs to the report and, under JSON
// output, to a machine consumer.
func writeHostDiagnostics(env *Env, d *host.Device, intel host.HardwareIntelligence, analyze bool) {
	w := func(format string, args ...any) {
		fmt.Fprintf(env.Stderr, format+"\n", args...)
	}

	w("# THN host diagnostics")
	w("# This is the human rendering of the structured probe record.")
	w("# stdout is untouched, so JSON output remains valid.")

	if d == nil {
		w("host         none; no device was observed")
		return
	}

	w("platform     %s", orNone(d.System.Describe()))
	w("supported    %t", d.Supported)
	w("interfaces   %d (%d physical, %d virtual)",
		len(d.Interfaces), len(d.PhysicalInterfaces()), len(d.Interfaces)-len(d.PhysicalInterfaces()))

	// Forwarding is the one sysctl a gateway cannot work without, and it has
	// three possible answers rather than two. It is printed explicitly because
	// "unreadable" and "disabled" need opposite responses.
	if !d.ForwardingKnown {
		w("forwarding   unknown (could not be read)")
	} else {
		w("forwarding   %t", d.ForwardingEnabled)
	}

	if len(d.Diagnostics) > 0 {
		w("")
		w("observations")
		// Device.Diagnostics is []string rather than the structured form: the
		// snapshot's diagnostics reach the host model already flattened into
		// one sentence each, and re-deriving a severity here would invent a
		// classification the observation layer never made.
		for _, diag := range d.Diagnostics {
			w("  %s", diag)
		}
	}

	if len(d.Probes) > 0 {
		w("")
		w("probes       %d run, %d did not reach a conclusion",
			len(d.Probes), len(d.FailedProbes()))
		for _, p := range d.Probes {
			w("%s", renderProbe(p))
		}
	}

	if !analyze {
		return
	}

	if len(intel.Unknowns) > 0 {
		w("")
		w("unknowns     %d, each with its cause", len(intel.Unknowns))
		for _, u := range intel.Unknowns {
			w("  %-16s %-16s %s", u.Subject, u.Question, u.Detail)
			w("%s", indent(renderProbe(u.Probe), "      "))
		}
	}
}

// renderProbe renders one probe as a structured line.
//
// key=value throughout rather than prose, because the whole point is that a
// reader can scan it for the field they care about.
//
// The marker separates the three shapes a reader must not confuse: a probe
// that ran and succeeded, one that never ran, and one that failed. In a long
// output they look alike, and only the first says anything about the host.
func renderProbe(p network.Probe) string {
	mark := "ok"
	switch {
	case p.Outcome.OK():
	case p.Outcome == network.ProbeNotChecked:
		mark = "---"
	default:
		mark = "!!"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "  [%s] %s/%s", mark, orNone(p.Subsystem), orNone(p.Operation))
	// Stage and Outcome are typed strings rather than plain ones, so they are
	// printed through their own formatter. Printing a typed string with %s
	// works, but naming the empty case explicitly is what keeps a zero Probe
	// from rendering as "stage= outcome=" and looking like a real record.
	fmt.Fprintf(&b, " stage=%s outcome=%s", probeStage(p.Stage), probeOutcome(p.Outcome))

	if p.Tool != "" {
		fmt.Fprintf(&b, " tool=%s", p.Tool)
	}
	if len(p.Args) > 0 {
		fmt.Fprintf(&b, " args=%q", strings.Join(p.Args, " "))
	}
	if p.Path != "" {
		fmt.Fprintf(&b, " path=%s", p.Path)
	}
	// Exit status is printed whenever a process actually ran, which includes
	// a parse failure — the command succeeded there and THN could not read
	// what it said, and the zero exit is exactly the evidence that it did
	// run. Printing it only for execute-stage failures would hide that.
	//
	// It is suppressed for a tool that was never located, where a zero would
	// read as a clean exit of something that never started.
	if p.Tool != "" && p.Stage != network.StageLocate && p.Stage != network.StageNotStarted {
		fmt.Fprintf(&b, " exit=%d", p.ExitStatus)
	}
	if p.Count > 0 {
		fmt.Fprintf(&b, " count=%d", p.Count)
	}
	if p.Detail != "" {
		fmt.Fprintf(&b, "\n       %s", p.Detail)
	}
	if p.Reason != "" {
		fmt.Fprintf(&b, "\n       cause: %s", p.Reason)
	}
	return b.String()
}

// probeStage renders a stage, naming the zero value explicitly.
//
// A bare empty string for "no stage" would be indistinguishable from a stage
// that failed to record one, which is exactly the confusion this rendering
// exists to remove.
func probeStage(s network.ProbeStage) string {
	if s == "" {
		return "unset"
	}
	return string(s)
}

// probeOutcome renders an outcome, naming the zero value explicitly.
func probeOutcome(o network.ProbeOutcome) string {
	if o == "" {
		return "unset"
	}
	return string(o)
}

// indent prefixes every line of s.
func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
