package execution

// Baseline capture for traffic control, and the foreign-state refusal built
// on top of it.
//
// # Why this file exists
//
// Before M7.6, two capture paths existed — LinuxDriver.CaptureState and
// ProductionDriver.CaptureState — and NEITHER of them read a qdisc. Both
// constructed a StateSnapshot whose QDiscs map stayed empty. StateSnapshot
// then carried a QDiscs map and MatchesBaseline looped over it comparing
// nothing to nothing, and every comparison passed.
//
// The result was a rollback that reported VERIFIED while restoring no traffic
// control at all. That is the worst shape a safety mechanism can take: it is
// not absent, it is present and lying. A missing check fails loudly; a check
// that compares two empty sets succeeds and certifies a host nobody can
// recover.
//
// So qdisc capture is here, once, and both drivers call it.
//
// # What a "baseline" is
//
// Not an algorithm name. A usable baseline is the tc specification that would
// recreate what is there: device, handle, parent, kind and every parameter.
//
//	qdisc cake 1: root refcnt 2 bandwidth 100Mbit diffserv4  ->  restorable
//	cake                                                          ->  not
//
// The second form is what M7.4 stored (PreviousAlgorithm) and it cannot
// restore a handle, a rate, a parent or a parameter set. Restoring it replaces
// an operator's shaping with a differently-parameterised one and calls that
// success.
//
// # Foreign state is refused, not adopted
//
// An interface carrying a root qdisc THN did not put there is FOREIGN. THN
// does not take it over: replacing it destroys configuration whose purpose it
// cannot know, and the plan that would do so was built from a document that
// never mentioned it.
//
// So ClassifyRootQdisc distinguishes THN's own disciplines from foreign ones,
// and AdoptableRootQdisc refuses the second. A kernel-installed default is the
// exception — noqueue, pfifo_fast, pfifo — because it is the kernel's own
// choice rather than anyone's configuration: an interface showing no explicit
// root discipline, or showing a kernel default, has nothing to destroy.
//
// # The kernel default is a fact, not an assumption
//
// "There was no qdisc here" and "THN did not look" must not share a value.
// tcSpecs.Captured carries which of the two applies, and a rollback that has
// no captured baseline refuses rather than guessing — see
// OpQDiscApply.RollbackOp.

import (
	"context"
	"fmt"
	"strings"
)

// TcBaseline is what THN found on one interface before touching it.
type TcBaseline struct {
	// Device is the interface the baseline was read from.
	Device string `json:"device"`

	// Root is the root discipline's tc specification, empty when the
	// interface carried the kernel default.
	Root string `json:"root,omitempty"`

	// Classes and Filters are the supporting hierarchy, captured as
	// specifications that `tc class replace` and `tc filter replace` accept.
	//
	// A root discipline is rarely the whole picture: an HTB tree or a
	// CAKE-with-overrides setup has children whose loss is as disruptive as
	// losing the root. Capturing only the root restores a working discipline
	// with none of its policy.
	Classes []string `json:"classes,omitempty"`

	// Filters is the same for filters, which carry the classification that
	// decides which traffic reaches which class.
	Filters []string `json:"filters,omitempty"`

	// Captured reports whether a read actually happened.
	//
	// Separate from Root being empty on purpose. An interface genuinely
	// carrying the default has Root == "" and Captured == true; an interface
	// THN never managed to read has Root == "" and Captured == false, and
	// those two must not be treated alike by anything deciding whether it is
	// safe to destroy a qdisc.
	Captured bool `json:"captured"`

	// Reason explains an unsuccessful capture, so a refused activation can say
	// why rather than only that it failed.
	Reason string `json:"reason,omitempty"`
}

// Foreign reports whether the baseline holds a discipline THN did not create.
//
// A kernel-installed default is not foreign: it is nobody's configuration, and
// replacing it destroys nothing.
func (b TcBaseline) Foreign() bool {
	if !b.Captured || b.Root == "" {
		return false
	}
	return !isKernelDefaultQdisc(rootQdiscKind(b.Root))
}

// isKernelDefaultQdisc reports whether a discipline is one the kernel installs
// for itself rather than one an operator or another tool asked for.
//
// The set is deliberately more than one name.
//
// pfifo_fast is the long-standing default on a physical NIC. noqueue is what a
// veth, a tun device or a dummy carries: it is not a queue at all, it is the
// kernel stating that the device has none. pfifo is the plain FIFO the kernel
// falls back to. They are the same fact about three kinds of device.
//
// Enumerating only pfifo_fast made a freshly created veth look like it carried
// an operator's hand-tuned tree. `tc qdisc show dev <veth>` prints
// `qdisc noqueue 0: root refcnt 2`; the capture recorded that faithfully, and
// AdoptableRootQdisc then refused every QoS activation on a virtual interface,
// naming a qdisc nobody had configured. The refusal was the safety property
// working correctly on a wrong classification, which is why it presented as a
// claim about provenance rather than as a defect.
//
// This is the same set internal/signals treats as "present but not shaping",
// so the two no longer disagree about what the kernel default is.
func isKernelDefaultQdisc(kind string) bool {
	switch kind {
	case "noqueue", "pfifo_fast", "pfifo":
		return true
	default:
		return false
	}
}

// Restorable reports whether rollback can recreate this baseline.
func (b TcBaseline) Restorable() bool {
	return b.Captured
}

// Empty reports whether the baseline holds no configuration at all.
func (b TcBaseline) Empty() bool {
	return b.Root == "" && len(b.Classes) == 0 && len(b.Filters) == 0
}

// rootQdiscKind extracts the discipline kind from a tc specification.
//
// It reads the token after `root`, and falls back to the token before `root`
// for the `replace`/`add` forms, because the two wordings appear in different
// places: `tc qdisc show` emits `<kind> <handle>: root ...`, while a captured
// command line is `qdisc replace dev X root <kind> ...`.
func rootQdiscKind(spec string) string {
	fields := splitFields(spec)
	for i, f := range fields {
		if f == "root" && i+1 < len(fields) {
			// `qdisc ... root <kind> ...`
			return trimHandle(fields[i+1])
		}
		if f == "root" && i > 0 {
			// `<kind> <handle>: root ...` — the handle token may carry a
			// trailing colon.
			return trimHandle(fields[i-1])
		}
	}
	// `qdisc replace dev X root cake` with nothing after root is malformed, but
	// the token before it is still the kind.
	for i, f := range fields {
		if f == "root" && i > 0 {
			return trimHandle(fields[i-1])
		}
	}
	return ""
}

// trimHandle strips a trailing colon from a tc handle.
func trimHandle(s string) string { return strings.TrimSuffix(s, ":") }

// splitFields splits on whitespace, rejecting nothing.
//
// tc output is whitespace-separated and THN builds these strings itself, so
// there is no shell or quoting concern here. It is NOT the path by which a
// captured specification reaches exec: that goes through splitTCSpec, which
// does validate.
func splitFields(s string) []string { return strings.Fields(s) }

// splitTCSpec parses a captured tc specification into an argv.
//
// It refuses anything that is not a `qdisc`/`class`/`filter` operation with a
// device, because these strings originate from `tc ... show` output on a host
// and are later handed to exec. A capture buffer that somehow contained
// something else must not become a command.
//
// The validation is structural, not an allowlist of the whole tc grammar,
// because the whole point of a baseline is to reproduce something THN did not
// author and therefore cannot enumerate.
func splitTCSpec(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty tc specification")
	}
	fields := splitFields(spec)
	if len(fields) < 4 {
		return nil, fmt.Errorf("tc specification is too short to be a command: %q", spec)
	}

	// The object word leads when the spec came from a command line
	// (`qdisc replace ...`); otherwise it is the kind token that leads
	// (`cake 1: root ...`).
	obj := fields[0]
	switch obj {
	case "qdisc", "class", "filter":
		// A command-line form: tc <obj> <verb> dev <iface> ...
	default:
		obj = "qdisc"
	}

	// Find the device. A show-form spec has no `dev`, because the device was
	// the argument to show; a command-form spec does.
	dev := ""
	hasRoot := false
	for _, f := range fields {
		if f == "root" {
			hasRoot = true
		}
	}
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			dev = fields[i+1]
			break
		}
	}

	if dev == "" {
		return nil, fmt.Errorf("tc specification names no device: %q", spec)
	}
	if !ifaceRegex.MatchString(dev) {
		return nil, fmt.Errorf("tc specification names an invalid device %q", dev)
	}
	if !hasRoot && obj == "qdisc" {
		return nil, fmt.Errorf("tc qdisc specification has no root or parent: %q", spec)
	}

	return fields, nil
}

// tcSpecFields is the parse used by OpQDiscReplace.Validate. It exists so a
// validation error names the specification rather than the parser.
func tcSpecFields(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("no tc arguments")
	}
	return args[0], nil
}

// AdoptableRootQdisc reports whether THN may replace a root discipline with
// its own.
//
// # The rule
//
//	no baseline captured            -> refuse. THN does not know what is there.
//	baseline is the kernel default    -> adopt. Nothing is destroyed.
//	baseline is THN's own discipline  -> adopt. Replacing one's own work is normal reconciliation.
//	baseline is anything else         -> refuse. Foreign configuration is not THN's to destroy.
//
// # Why refusing is right even though it blocks activation
//
// An operator with a hand-tuned HTB tree and a THN document asking for CAKE
// has a real conflict. Two defensible resolutions exist — the operator
// removes theirs, or THN is told about it explicitly — and silently picking
// one destroys work in the case where it matters most.
//
// The refusal is reported with the observed kind and the interface so it can
// be acted on, rather than as a generic refusal.
func AdoptableRootQdisc(b TcBaseline) error {
	if !b.Captured {
		return fmt.Errorf("the traffic-control state of %s was not observed, so THN cannot "+
			"establish whether replacing it would destroy existing configuration; "+
			"activation requires observed state, not inferred state", b.Device)
	}
	if b.Foreign() {
		return fmt.Errorf("%s carries a %q queue discipline that THN did not create; "+
			"THN does not take over foreign traffic-control configuration, and replacing it "+
			"would destroy a hierarchy whose purpose it cannot know. Remove it deliberately, "+
			"or leave qos disabled", b.Device, rootQdiscKind(b.Root))
	}
	return nil
}

// RestoreOp returns the operation that reinstates a baseline.
//
// The three outcomes are deliberately distinct:
//
//	not captured        -> nil. No rollback. Refusing is the safe answer.
//	captured, empty     -> OpQDiscDelete. Restores the kernel default.
//	captured, populated -> OpQDiscReplace. Restores the recorded discipline.
func (b TcBaseline) RestoreOp() Operation {
	if !b.Captured {
		return nil
	}
	if b.Empty() {
		if !ifaceRegex.MatchString(b.Device) {
			return nil
		}
		return OpQDiscDelete{Interface: b.Device}
	}
	return OpQDiscReplace{Spec: b.Root}
}

// TcReader is the read-only view of tc a capture needs.
//
// An interface rather than a concrete runner, so the capture logic is testable
// without a kernel and so it cannot grow the ability to mutate anything: every
// method here returns text.
type TcReader interface {
	// RunTCOutput runs a read-only tc query and returns stdout.
	RunTCOutput(ctx context.Context, args ...string) (string, error)
}

// CaptureTcBaseline reads the traffic-control state of one interface.
//
// # Every failure mode records WHY
//
// A capture that could not be read returns Captured=false with a Reason, not a
// zero value. The distinction is the whole point: an interface genuinely
// carrying the kernel default and an interface nobody managed to inspect must
// never look the same to a decision about destroying a qdisc.
//
// # What is read
//
// Root discipline, classes and filters. A root alone is frequently not the
// whole configuration — an HTB tree or an operator's overrides live in the
// children — and restoring only the root would produce a working discipline
// with none of its policy.
//
// Reading is done per device so each line carries the interface name, which is
// what makes the captured text re-runnable as a command.
func CaptureTcBaseline(ctx context.Context, r TcReader, device string) TcBaseline {
	b := TcBaseline{Device: device}

	if device == "" {
		b.Reason = "no interface was named, so there was nothing to read"
		return b
	}
	if !ifaceRegex.MatchString(device) {
		b.Reason = fmt.Sprintf("interface %q is not a valid device name", device)
		return b
	}

	// A missing device is a fact about this interface, not a failure to read
	// it: "there is no qdisc here" and "I could not look" coincide only when
	// the device genuinely is absent, and tc says so specifically.
	out, err := r.RunTCOutput(ctx, "qdisc", "show", "dev", device)
	if err != nil {
		if strings.Contains(err.Error(), "Cannot find device") ||
			strings.Contains(err.Error(), "No such device") {
			b.Captured = true
			b.Reason = "the interface does not exist on this host, so it carries no qdisc"
			return b
		}
		b.Reason = fmt.Sprintf("tc qdisc show failed: %v", err)
		return b
	}

	b.Captured = true

	// tc prints one line per discipline. The root line is the one carrying
	// `root`; the rest are recorded too, because losing an operator's child
	// qdiscs is as disruptive as losing the root.
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "qdisc ") {
			continue
		}
		spec := buildRestoreSpec(device, line)
		if isRootQdiscLine(line) {
			b.Root = spec
			continue
		}
		b.Classes = append(b.Classes, spec)
	}
	sortStrings(b.Classes)

	if classOut, err := r.RunTCOutput(ctx, "class", "show", "dev", device); err == nil {
		for _, line := range strings.Split(classOut, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "class ") {
				continue
			}
			b.Classes = append(b.Classes, buildClassRestoreSpec(device, line))
		}
		sortStrings(b.Classes)
	}

	if filterOut, err := r.RunTCOutput(ctx, "filter", "show", "dev", device); err == nil {
		for _, line := range strings.Split(filterOut, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			b.Filters = append(b.Filters, buildFilterRestoreSpec(device, line))
		}
		sortStrings(b.Filters)
	}

	return b
}

// isRootQdiscLine reports whether a `tc qdisc show` line describes the root.
func isRootQdiscLine(line string) bool {
	fields := splitFields(line)
	for i, f := range fields {
		if f == "root" && i >= 2 {
			return true
		}
	}
	return false
}

// buildRestoreSpec turns a `tc qdisc show` line into a re-runnable command.
//
// The show form is `<kind> <handle>: root refcnt 2 <params>`, which is not a
// command. `qdisc replace dev <if> root <kind> <params>` is, and preserves
// everything the capture recorded — the handle, the parent, every parameter —
// which is precisely what a bare algorithm name lost.
func buildRestoreSpec(device, line string) string {
	fields := splitFields(line)

	kind := ""
	params := []string{}
	for i, f := range fields {
		if i == 0 {
			continue // the literal "qdisc"
		}
		if f == "root" {
			params = fields[i+1:]
			break
		}
	}
	if len(fields) >= 2 {
		kind = strings.TrimSuffix(fields[1], ":")
	}

	args := []string{"qdisc", "replace", "dev", device, "root", kind}
	return JoinTCArgs(append(args, stripCounters(params)...))
}

// buildClassRestoreSpec turns a `tc class show` line into a class command.
//
// The show form is `class <kind> <classid> ...`. The parent is not always
// printed by tc, so this preserves the observed class id and parameters and
// leaves parent reconstruction to the future class-operation layer rather
// than inventing a hierarchy during rollback.
func buildClassRestoreSpec(device, line string) string {
	fields := splitFields(line)
	if len(fields) < 3 {
		return ""
	}
	args := []string{"class", "replace", "dev", device, "classid", fields[2], fields[1]}
	return JoinTCArgs(append(args, stripCounters(fields[3:])...))
}

// buildFilterRestoreSpec turns a `tc filter show` line into a re-runnable
// command.
func buildFilterRestoreSpec(device, line string) string {
	args := []string{"filter", "replace", "dev", device}
	return JoinTCArgs(append(args, stripCounters(splitFields(line))...))
}

// stripCounters removes the volatile fields tc includes in show output.
//
// refcnt changes as other references are taken and dropped; a capture that
// includes it would never restore cleanly and would report a mismatch on every
// rollback. A baseline must contain only what is configuration.
func stripCounters(fields []string) []string {
	var out []string
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "refcnt":
			i++ // and its value
			continue
		case "Sent", "backlog", "requeues", "memory", "capacity",
			"min/max", "average", "thresh", "target", "interval",
			"pk_delay", "av_delay", "sp_delay", "pkts", "bytes",
			"way_inds", "way_miss", "way_cols", "drops", "marks",
			"ack_drop", "sp_flows", "bk_flows", "un_flows",
			"max_len", "quantum", "rate", "peakdelay", "undertime":
			// These are statistics in show output, not configuration.
			// Skipping to the next token that looks like a statistic is
			// deliberately conservative: a keyword with a following numeric
			// or size token is dropped, everything else is kept.
			for i+1 < len(fields) && isStatValue(fields[i+1]) {
				i++
			}
			continue
		}
		out = append(out, fields[i])
	}
	return out
}

// isStatValue reports whether a token looks like a statistic value rather than
// a configuration keyword.
func isStatValue(s string) bool {
	if s == "" {
		return false
	}
	// A configuration keyword is a bare word. A value carries a digit, a
	// unit suffix, or a trailing colon.
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	if strings.HasSuffix(s, ":") {
		return true
	}
	// Things like "0b", "12p", "1.5ms", "100Mbit".
	if strings.ContainsAny(s, "bpsKMGm") && strings.ContainsFunc(s, func(r rune) bool {
		return r >= '0' && r <= '9'
	}) {
		return true
	}
	return false
}

// JoinTCArgs renders an argument vector as space-joined text.
func JoinTCArgs(args []string) string { return strings.Join(args, " ") }

// sortStrings sorts in place, for deterministic baselines.
//
// Two reads of identical state must produce identical baselines, or a
// rollback's comparison is a coin flip and a real mismatch is indistinguishable
// from a spurious one.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// RestoreTcBaseline applies a captured qdisc/class/filter baseline through the
// structured command runner. It never uses a shell and stops at the first
// failed restore so the executor can report rollback as degraded.
func RestoreTcBaseline(ctx context.Context, runner CommandRunner, baseline TcBaseline) error {
	if !baseline.Captured {
		return fmt.Errorf("traffic-control baseline for %s was not captured", baseline.Device)
	}

	if baseline.Root == "" {
		if _, _, err := runner.Run(ctx, "tc", "qdisc", "del", "dev", baseline.Device, "root"); err != nil {
			return fmt.Errorf("restoring kernel-default qdisc on %s: %w", baseline.Device, err)
		}
	} else {
		args, err := splitTCSpec(baseline.Root)
		if err != nil {
			return fmt.Errorf("parsing captured root qdisc on %s: %w", baseline.Device, err)
		}
		if _, _, err := runner.Run(ctx, "tc", args...); err != nil {
			return fmt.Errorf("restoring root qdisc on %s: %w", baseline.Device, err)
		}
	}

	for _, spec := range append(append([]string{}, baseline.Classes...), baseline.Filters...) {
		args, err := splitTCSpec(spec)
		if err != nil {
			return fmt.Errorf("parsing captured child on %s: %w", baseline.Device, err)
		}
		if _, _, err := runner.Run(ctx, "tc", args...); err != nil {
			return fmt.Errorf("restoring captured child on %s: %w", baseline.Device, err)
		}
	}
	return nil
}
