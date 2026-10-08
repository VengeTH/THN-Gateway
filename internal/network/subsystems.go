package network

// Which networking facilities this host actually exposes.
//
// # Why this exists
//
// `ip -j link show` tells you what interfaces there are. It says nothing about
// whether nftables is installed, whether traffic control is available, or how
// this particular distribution manages DNS — and M7.0 must answer all three,
// because "can this host be a gateway" depends on them.
//
// The awkward part is that "available" and "present" are not the same claim.
//
//	tc exists                the binary is on PATH
//	tc qdisc show works      the kernel accepted the query
//	CAKE is available        the kernel has sch_cake
//
// These are three separate facts, and a gateway that conflates them will one
// day offer to shape a link with an algorithm the kernel does not have. Each
// is observed separately here and each is reported at the confidence it was
// actually established at.
//
// # Nothing here modifies anything
//
// nft is invoked with `list`, tc with `show`, and DNS is read from files. The
// nft and tc calls pass through internal/guard, whose allowlist contains no
// mutating verb for either binary — there is no "nft add" or "tc replace" entry
// to reach, so a mistake here is denied by the chokepoint before a process is
// created rather than by review.
//
// # Parsers are separated from execution
//
// Every function that parses output takes a string. The functions that execute
// commands are thin. This is the same split as ParseLinks, and for the same
// reason: a parser welded to exec can only be tested on the machine that has
// the tool installed, which is never the machine running the tests.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/guard"
)

// THNTableFamily and THNTableName identify the nftables table THN would own.
//
// They are recorded here rather than invented at each call site because the
// question "does THN already have a table on this host" has exactly one right
// answer, and two call sites guessing differently would produce two different
// answers to it.
const (
	THNTableFamily = "inet"
	THNTableName   = "thn"
)

// NFTablesState is an observation of nftables, made without changing it.
//
// The distinction the type exists to preserve is between "nftables is
// installed", "nftables answered a query", and "THN has a table here". A host
// can be in any combination of those states, and they mean different things.
type NFTablesState struct {
	// Checked reports whether nftables was actually probed.
	//
	// This field exists because the zero value of this struct must mean
	// "nobody looked", not "looked, and there is nothing there". Without it,
	// a snapshot built by a test — or by any future caller that assembles
	// one by hand — would assert as an OBSERVED FACT that nftables is not
	// installed, which is a conclusion nobody drew.
	//
	// Every confidence calculation downstream keys off this field, so an
	// unchecked state produces unknown rather than a confident negative.
	Checked bool `json:"checked"`

	// Available reports whether `nft` could be executed at all.
	//
	// False means the binary is absent or not executable. It does NOT mean
	// the host is unprotected, and it does not mean the kernel lacks nft.
	Available bool `json:"available"`

	// QuerySucceeded reports whether a ruleset query completed.
	//
	// Available && !QuerySucceeded means the binary exists but could not be
	// talked to — usually insufficient privilege. That is a different
	// diagnostic from "nft is not installed", and conflating them would tell
	// an operator to install a package they already have.
	//
	// It is also false when the output could not be parsed, which the Probe
	// below distinguishes. Reporting a parse failure as a successful empty
	// inventory would be a claim about somebody else's firewall.
	QuerySucceeded bool `json:"query_succeeded"`

	// Probe records how this state was determined, structurally.
	//
	// Reason is the human sentence; Probe is the field that names the failing
	// stage. "nft is installed but the ruleset could not be read" covers three
	// unrelated problems — not installed, no privilege, unreadable output —
	// and only Probe separates them.
	Probe Probe `json:"probe"`

	// Tables are the nftables tables observed on this host, whatever created
	// them.
	//
	// A table THN did not create is not an error and is not a cleanup target.
	// It is recorded so that a future plan can see it exists, so that
	// discovery never has to decide what to do about someone else's rules.
	Tables []NftTable `json:"tables,omitempty"`

	// THNTablePresent reports whether THN's own table exists.
	THNTablePresent bool `json:"thn_table_present"`

	// Managed reports whether every observed table is THN's own.
	//
	// false means this host carries infrastructure THN does not own. That is
	// the normal condition on a machine running Docker, Tailscale or any
	// host firewall, and it is information rather than a problem.
	Managed bool `json:"managed"`

	// Reason explains an unavailable or unqueryable state.
	Reason string `json:"reason,omitempty"`
}

// NftTable is one observed nftables table.
type NftTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	// Chains are the chain names observed in this table.
	Chains []string `json:"chains,omitempty"`
}

// IsTHNTable reports whether this table is the one THN would own.
func (t NftTable) IsTHNTable() bool {
	return t.Family == THNTableFamily && t.Name == THNTableName
}

// nftTablesJSON is the subset of `nft -j list tables` output THN reads.
//
// `nft -j list tables` is preferred over `list ruleset` for a capability
// question. It reports the same table inventory in a fraction of the output,
// needs no rule interpretation, and on a busy host the ruleset form can be
// megabytes of JSON to answer a question that only wanted a list of names.
type nftTablesJSON struct {
	Nftables []struct {
		Table *struct {
			Family string `json:"family"`
			Name   string `json:"name"`
			Handle int    `json:"handle"`
		} `json:"table"`
		Chain *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Hook   string `json:"hook"`
		} `json:"chain"`
	} `json:"nftables"`
}

// ParseNFTablesTables parses `nft -j list tables` output into an inventory.
//
// Tables and chains arrive as a flat stream — a table object, then the chain
// objects that belong to it — so chains are attached as they are met. A chain
// naming a table that was never declared is dropped rather than guessed at:
// attributing a chain to the wrong table is worse than not reporting it, and
// an unrecognised output shape should be visible as a missing chain rather
// than as a wrong one.
//
// # Why this returns an error
//
// It used to return nil and say nothing. That made "nft printed JSON THN
// cannot read" and "nft printed an empty ruleset" the same value, and the
// caller set QuerySucceeded=true either way — so a parse failure was reported
// to the operator as a host with no nftables tables, which is a confident
// wrong answer about somebody else's firewall.
//
// The two are now separable: an empty inventory is a successful parse of an
// empty document, and a parse failure is an error naming the stage.
func ParseNFTablesTables(raw []byte) ([]NftTable, error) {
	if jsonIsNull(raw) {
		return []NftTable{}, nil
	}

	var doc nftTablesJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf(
			"nftables table inventory: the output was not the expected JSON shape: %w", err)
	}

	// A document that parsed but carried no nftables key is almost certainly a
	// shape THN does not recognise yet, rather than a host with no ruleset —
	// `nft` always emits the key. Reporting it as an empty inventory would
	// repeat the exact confusion this function's error return exists to
	// prevent, one layer up.
	if doc.Nftables == nil {
		return nil, fmt.Errorf(
			"nftables table inventory: the output parsed but carried no %q element; "+
				"this is not a shape THN recognises", "nftables")
	}

	type key struct{ family, name string }
	tables := map[key]*NftTable{}

	for _, item := range doc.Nftables {
		switch {
		case item.Table != nil:
			k := key{item.Table.Family, item.Table.Name}
			if _, seen := tables[k]; !seen {
				tables[k] = &NftTable{Family: k.family, Name: k.name}
			}
		case item.Chain != nil:
			t, ok := tables[key{item.Chain.Family, item.Chain.Table}]
			if !ok {
				continue
			}
			t.Chains = append(t.Chains, item.Chain.Name)
		}
	}

	out := make([]NftTable, 0, len(tables))
	for _, t := range tables {
		sort.Strings(t.Chains)
		out = append(out, *t)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Family != out[b].Family {
			return out[a].Family < out[b].Family
		}
		return out[a].Name < out[b].Name
	})

	return out, nil
}

// ObserveNFTables reports what nftables this host exposes, without touching it.
//
// Three outcomes are distinguished and they are not interchangeable:
//
//	Available=false              nft is not installed
//	Available=true, query failed  nft exists but could not be asked
//	QuerySucceeded=true          the ruleset was read successfully
//
// Collapsing the second into the first is the mistake this function exists to
// prevent: an operator told "nftables unavailable" who then installs a package
// they already had has been actively misled by the tool.
func ObserveNFTables(ctx context.Context) NFTablesState {
	return ObserveNFTablesWithRunner(ctx, guard.Exec)
}

// ObserveNFTablesWithRunner is ObserveNFTables with the command runner
// supplied.
//
// # Why the seam exists
//
// Without it, every failure path in this file — tool absent, command refused,
// output unparseable, output the wrong shape — was reachable only by running
// on a machine with the right tools installed and the wrong privileges. Those
// are exactly the states a developer's laptop does not have, which is why the
// classification bug this seam now catches survived as long as it did.
//
// The runner is guard.Runner rather than a bespoke type, so a test cannot
// accidentally supply something that is not a guard-validated exec. The policy
// check lives inside guard.Exec, which the default uses; a test that injects
// its own runner opts out of it deliberately and is testing the
// CLASSIFICATION, not the allowlist — and TestRepoContainsNoUnguardedExec
// still covers the allowlist.
func ObserveNFTablesWithRunner(ctx context.Context, run guard.Runner) NFTablesState {
	st := NFTablesState{
		Checked: true,
		Probe:   NotChecked("nftables", "list-tables"),
	}
	if run == nil {
		run = guard.Exec
	}

	args := []string{"-j", "list", "tables"}
	out, err := run(ctx, "nft", args...)
	st.Probe = ExecProbe("nftables", "list-tables", "nft", args, out, err)
	if err != nil {
		if toolMissing(out, err) {
			st.Reason = "the nft binary is not installed on this host"
			return st
		}
		// The binary is present but unusable — almost always privilege. Say
		// so rather than reporting nftables as absent.
		st.Available = true
		st.Reason = fmt.Sprintf("nft is installed but the ruleset could not be read: %v", err)
		return st
	}

	st.Available = true

	tables, perr := ParseNFTablesTables([]byte(out.Stdout))
	if perr != nil {
		// Same reasoning as traffic control: the tool is present and the
		// answer is unreadable. Recording that as an empty inventory would
		// tell an operator their firewall has no tables, which is a
		// statement about somebody else's security that THN has no basis for.
		st.Probe = failed(st.Probe, StageParse, ProbeParseFailed,
			"nft ran and produced output THN could not parse", perr)
		st.Reason = fmt.Sprintf("nft is installed but its output could not be parsed: %v", perr)
		return st
	}

	st.QuerySucceeded = true
	st.Tables = tables
	st.Managed = true

	for _, t := range st.Tables {
		if t.IsTHNTable() {
			st.THNTablePresent = true
		}
		if !t.IsTHNTable() {
			st.Managed = false
		}
	}

	// An empty table list is a working probe and a fact about the host, so it
	// is recorded as no-evidence rather than as a failure. That distinction
	// is what lets a reader tell "this host has no nftables tables" from "we
	// could not find out".
	detail := "the query succeeded"
	if len(st.Tables) == 0 {
		detail = "the query succeeded and no nftables tables are present"
	}
	st.Probe = Succeeded(st.Probe, detail, len(st.Tables))
	return st
}

// toolMissing reports whether a command could not be started at all.
//
// # Why the output is the discriminator, not the error text
//
// guard.Exec formats a non-zero exit as "%s: exit %d: %s" — the last %s is
// the command's own STDERR. So the returned error string contains whatever the
// tool printed, and the previous implementation substring-matched that string
// for "no such file or directory", "cannot find" and "executable file not
// found".
//
// That is a false-confidence bug in the worst direction. `ip -j addr show`
// prints "Cannot find device \"eth0\"" when an interface disappears
// mid-read, and `nft` prints "No such file or directory" for any rule it
// cannot resolve. Either would have been classified as "the binary is not
// installed", leaving Available=false — and nftConfidence turns a confirmed
// absence into ConfidenceObserved on the grounds that "we were in a position
// to find that out".
//
// So THN would have reported "nftables: unavailable / observed" for a host
// where nft is installed and working, and the confidence column — the one that
// gates activation — would have been confidently wrong.
//
// A non-nil Output means a process was created and ran. That is a structural
// fact, available without reading a single byte of the tool's output, and it
// is the only sound discriminator. The string tests remain for the case where
// no process was created, because that is the only case where the text is
// about the binary rather than about the work.
func toolMissing(out *guard.Output, err error) bool {
	if err == nil {
		return false
	}
	if out != nil {
		// A process existed and was run. Whatever it printed, the tool is
		// present; this is an execution failure or a non-zero exit, not a
		// missing binary.
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "cannot find") || strings.Contains(msg, "no such file")
}

// TCState is an observation of traffic control.
type TCState struct {
	// Checked reports whether traffic control was actually probed.
	//
	// As with NFTablesState.Checked, the zero value must mean "nobody
	// looked". Without it, an unprobed state would assert that tc is absent,
	// which is a conclusion rather than an observation.
	Checked bool `json:"checked"`

	// Available reports whether `tc` could be executed.
	Available bool `json:"available"`

	// QuerySucceeded reports whether a qdisc query completed.
	//
	// It is false when the parse failed, which is what makes this field
	// trustworthy: previously a malformed `tc` output produced
	// QuerySucceeded=true over an empty discipline list, and that is
	// indistinguishable from a host with no shaping configured.
	QuerySucceeded bool `json:"query_succeeded"`

	// Probe records how this state was determined.
	//
	// Reason is a human sentence; Probe is the structured form, and it is the
	// one that answers "which stage failed and why" — tool unavailable,
	// execution failed, or output could not be parsed are three different
	// operator problems that Reason alone blurred together.
	Probe Probe `json:"probe"`

	// Qdiscs are the root queue disciplines observed, in the order tc reports
	// them.
	Qdiscs []Qdisc `json:"qdiscs,omitempty"`

	// CakeObserved reports whether a CAKE discipline is currently attached.
	//
	// This is the ONLY evidence that turns CAKE from unknown into observed.
	// The binary being on PATH is not evidence — sch_cake is a kernel module
	// and `tc` does not consult it until it is asked to install one.
	CakeObserved bool `json:"cake_observed"`

	// Reason explains an unavailable or unqueryable state.
	Reason string `json:"reason,omitempty"`
}

// Qdisc is one observed queue discipline.
type Qdisc struct {
	Device string `json:"device,omitempty"`
	Kind   string `json:"kind"`
	Handle string `json:"handle,omitempty"`
	Root   bool   `json:"root,omitempty"`
}

// ParseQdiscs parses `tc -j qdisc show` output.
//
// The JSON form is used rather than the text form because the text form is
// human-shaped prose — "qdisc cake 8001: root refcnt 2 bandwidth 100Mbit" — and
// parsing prose to answer a capability question is how a parser ends up
// disagreeing with the tool it is standing in for. Where a field is absent the
// entry is still reported with an empty handle: an unrecognised discipline is
// still a discipline, and dropping it would under-report.
//
// # Why this returns an error
//
// The failure this prevents is specific and was live. Returning nil on
// malformed JSON meant the caller could not distinguish it from a host with
// no queue disciplines attached, and set QuerySucceeded=true over either. That
// is the shape of "this host has no shaping configured" — so a tc that had
// started emitting a format THN could not read would be reported, with
// confidence, as a host that needs no shaping.
func ParseQdiscs(raw []byte) ([]Qdisc, error) {
	// A literal null is an empty answer, matching ParseNFTablesTables. It is
	// the one value that decodes into a Go nil without error, and treating it
	// as a format fault would report a tool's correct "nothing here" as a
	// parser problem.
	if jsonIsNull(raw) {
		return []Qdisc{}, nil
	}

	var parsed []struct {
		Kind   string `json:"kind"`
		Handle string `json:"handle"`
		Root   bool   `json:"root"`
		Dev    string `json:"dev"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf(
			"traffic control: `tc -j qdisc show` output was not the expected JSON array: %w", err)
	}

	out := make([]Qdisc, 0, len(parsed))
	for _, q := range parsed {
		if q.Kind == "" {
			continue
		}
		out = append(out, Qdisc{
			Device: q.Dev,
			Kind:   q.Kind,
			Handle: normaliseQdiscHandle(q.Handle),
			Root:   q.Root,
		})
	}
	return out, nil
}

// ObserveTrafficControl reports what traffic control this host exposes.
//
// It establishes that tc is present and answerable. It deliberately does not
// establish that any particular algorithm is available: that would require
// asking the kernel to install one, which is mutation, and M7.0 does not
// mutate. The distinction is carried through to the capability model, where
// CAKE on a host with no CAKE qdisc stays unknown rather than becoming
// available.
func ObserveTrafficControl(ctx context.Context) TCState {
	return ObserveTrafficControlWithRunner(ctx, guard.Exec)
}

// ObserveTrafficControlWithRunner is ObserveTrafficControl with the command
// runner supplied.
//
// The same seam and the same reasoning as ObserveNFTablesWithRunner: the
// traffic-control observer's failure classification is the one most likely to
// be wrong and the least likely to be exercised, because every reachable
// failure needs a machine whose tc is installed and whose privileges are
// wrong.
func ObserveTrafficControlWithRunner(ctx context.Context, run guard.Runner) TCState {
	st := TCState{
		Checked: true,
		Probe:   NotChecked("traffic-control", "qdisc-show"),
	}
	if run == nil {
		run = guard.Exec
	}

	args := []string{"-j", "qdisc", "show"}
	out, err := run(ctx, "tc", args...)
	st.Probe = ExecProbe("traffic-control", "qdisc-show", "tc", args, out, err)
	if err != nil {
		if toolMissing(out, err) {
			st.Reason = "the tc binary is not installed on this host"
			return st
		}
		st.Available = true
		st.Reason = fmt.Sprintf("tc is installed but queue disciplines could not be read: %v", err)
		return st
	}

	st.Available = true

	qdiscs, perr := ParseQdiscs([]byte(out.Stdout))
	if perr != nil {
		// Available is true and QuerySucceeded is false, which is the honest
		// combination: the tool is there, and THN could not read it. The
		// previous code set QuerySucceeded here regardless, which reported a
		// format change as an absence of shaping.
		st.Probe = failed(st.Probe, StageParse, ProbeParseFailed,
			"tc ran and produced output THN could not parse", perr)
		st.Reason = fmt.Sprintf("tc is installed but its output could not be parsed: %v", perr)
		return st
	}

	st.QuerySucceeded = true
	st.Qdiscs = qdiscs

	for _, q := range st.Qdiscs {
		if strings.EqualFold(q.Kind, "cake") {
			st.CakeObserved = true
		}
	}

	// Cake is the capability most likely to be wrong on a real host, so the
	// probe records which of the two "not available" reasons applies: a
	// working probe that found none, versus a probe that never ran.
	detail := "the query succeeded"
	if !st.CakeObserved {
		detail = "the query succeeded and no CAKE discipline is attached; " +
			"sch_cake is a kernel module and cannot be established without mutation"
	}
	st.Probe = Succeeded(st.Probe, detail, len(qdiscs))
	if !st.CakeObserved {
		st.Probe.Operation = "qdisc-show/cake"
	}
	return st
}

// normaliseQdiscHandle reduces a tc handle to its printable form.
//
// `tc -j` emits handles as "8001:" with a trailing colon. The colon is tc's
// own punctuation, carries no information, and would otherwise be repeated in
// every rendered report.
func normaliseQdiscHandle(h string) string { return strings.TrimSuffix(h, ":") }

// DNSState is an observation of how this host resolves names.
type DNSState struct {
	// Mechanism is how DNS is configured here, as far as THN could tell.
	//
	// Recognised values are "resolv.conf" (the file is authoritative),
	// "systemd-resolved" (the file is a stub pointing at a local resolver)
	// and "unknown" (THN could not determine it).
	Mechanism string `json:"mechanism"`

	// Nameservers are the upstream resolvers, in file order.
	Nameservers []string `json:"nameservers,omitempty"`

	// Search are the search domains.
	Search []string `json:"search,omitempty"`

	// Options are resolver options, e.g. "ndots:2".
	Options []string `json:"options,omitempty"`

	// Authoritative reports whether the resolv.conf THN read is the host's
	// real DNS configuration.
	//
	// False on a systemd-resolved system, where /etc/resolv.conf is a stub
	// whose contents are rewritten at runtime. An operator reading a
	// nameserver list from such a file is reading a placeholder, and THN
	// says so rather than presenting it as the truth.
	Authoritative bool `json:"authoritative"`

	// Reason explains why the mechanism could not be determined.
	Reason string `json:"reason,omitempty"`

	// Probe records how the mechanism was determined.
	//
	// DNS is the subsystem most likely to be read from a file that is not
	// what it appears to be — a systemd-resolved stub rewritten at runtime,
	// a container's bind-mount, a symlink to nowhere — so the record names
	// which file was read and whether the answer came from it or from a
	// fallback.
	Probe Probe `json:"probe"`
}

// DNS mechanisms.
const (
	DNSMechanismResolvConf      = "resolv.conf"
	DNSMechanismSystemdResolved = "systemd-resolved"
	DNSMechanismUnknown         = "unknown"
)

// resolvConfPath is the file read for resolver configuration. It is read
// rather than executed, and never written.
const resolvConfPath = "/etc/resolv.conf"

// ParseResolvConf parses a resolv.conf file.
//
// Comments, blank lines and the `search`/`domain` distinction are handled
// because all of them appear in real files. A nameserver entry that does not
// parse as an IP is dropped rather than passed through: this function's output
// is rendered as "the upstream resolvers", and putting a malformed address in
// that list would be a claim THN cannot support.
func ParseResolvConf(content string) DNSState {
	st := DNSState{Mechanism: DNSMechanismResolvConf}

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			// A resolver address must be a literal IP. Anything else is not a
			// nameserver, however confidently the file claims otherwise.
			if isLiteralIP(fields[1]) {
				st.Nameservers = append(st.Nameservers, fields[1])
			}
		case "search":
			st.Search = append(st.Search, fields[1:]...)
		case "domain":
			// The deprecated single-domain form is exactly one domain.
			if len(fields) > 1 {
				st.Search = append(st.Search, fields[1])
			}
		case "options":
			st.Options = append(st.Options, fields[1:]...)
		}
	}

	sort.Strings(st.Search)
	st.Authoritative = true
	return st
}

// ObserveDNS reads the host's resolver configuration.
//
// It does not stop at reading the file, because on a systemd-resolved host the
// file is not the configuration. A stub pointing at 127.0.0.53 is a strong
// signal that a local resolver owns DNS, and reporting its contents as "the
// nameservers" would be reporting the placeholder rather than the truth.
//
// Nothing is modified, and no resolver is queried. THN observes how DNS is
// CONFIGURED here; whether it works is a different question that needs a
// network, and answering it would take a network action.
func ObserveDNS() DNSState {
	b, err := os.ReadFile(resolvConfPath)
	if err != nil {
		st, alt := observeDNSAlternate(err)
		st.Probe = alt
		return st
	}

	st := ParseResolvConf(string(b))

	// Detect a systemd-resolved stub. Both the symlink and the file's own
	// banner are checked: the symlink is the reliable signal, and the banner
	// is what a copied or bind-mounted resolv.conf leaves behind.
	detail := "the resolver configuration was read from the authoritative file"
	if isSystemdResolvedStub(resolvConfPath, string(b)) {
		st.Mechanism = DNSMechanismSystemdResolved
		st.Authoritative = false
		st.Reason = "/etc/resolv.conf is a systemd-resolved stub; " +
			"the local resolver owns DNS on this host and this file's " +
			"contents are rewritten at runtime"
		detail = "the file was read and is a systemd-resolved stub, so it is not the authoritative configuration"
	}

	// The read succeeded, so this is a working probe with a positive result
	// even when the answer is "this file is not the real configuration" —
	// which is itself a fact THN established rather than a failure.
	st.Probe = Succeeded(Probe{
		Subsystem: "dns",
		Operation: "resolv-conf",
		Path:      resolvConfPath,
	}, detail, len(st.Nameservers))
	if st.Mechanism == DNSMechanismSystemdResolved {
		// No nameserver count, because the file's nameservers are not the
		// host's nameservers and reporting a count would invite exactly the
		// reading the Reason forbids.
		st.Probe.Count = 0
		st.Probe.Operation = "resolv-conf/systemd-resolved"
	}
	return st
}

// isSystemdResolvedStub reports whether a resolv.conf is a systemd-resolved stub.
func isSystemdResolvedStub(path, content string) bool {
	if target, err := os.Readlink(path); err == nil {
		if strings.Contains(target, "systemd/resolve") {
			return true
		}
	}
	return strings.Contains(content, "/run/systemd/resolve/")
}

// jsonIsNull reports whether the payload is a literal JSON null.
//
// Checked before unmarshalling because `null` is the one value that decodes
// into a Go nil without raising an error, which makes it indistinguishable
// from "the element was absent" once it has been unmarshalled.
//
// It is treated as an EMPTY answer rather than as a shape error, and both
// parsers here agree on that deliberately: a tool that reports nothing as
// `null` has answered correctly, and calling that a format problem would send
// an operator to fix a parser for behaviour that is not a fault.
func jsonIsNull(raw []byte) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// net.ParseIP rather than a regex or a hand-rolled check: it is the standard
// library's definition of what an address is, and inventing a second one
// creates a place for the two to disagree.
func isLiteralIP(s string) bool { return net.ParseIP(s) != nil }

// resolvConfAlternates are consulted when /etc/resolv.conf cannot be read.
//
// A container image, or a host whose /etc/resolv.conf was removed by tooling
// that manages it elsewhere, can still have a perfectly good resolver
// configuration at the well-known systemd-resolved path. Reading it is still
// read-only, and still better than reporting "unknown" for a host that plainly
// has DNS configured.
var resolvConfAlternates = []string{
	filepath.Join("/run/systemd/resolve", "resolv.conf"),
}

// observeDNSAlternate is used by ObserveDNS when the primary file is missing.
//
// The primary read's error is carried through so the fallback's own record
// can say what happened rather than only that an alternative was used. Before
// this, a host whose resolver configuration could not be read produced a
// "Reason" naming the alternate path and nothing about why the original read
// failed — so the most interesting question went unasked.
func observeDNSAlternate(primaryErr error) (DNSState, Probe) {
	primary := FileProbe("dns", "resolv-conf", resolvConfPath, StageLocate,
		classifyFileErrorOutcome(primaryErr),
		fmt.Sprintf("the resolver configuration could not be read from the primary path: %v", primaryErr),
		primaryErr)

	for _, path := range resolvConfAlternates {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		st := ParseResolvConf(string(b))
		st.Reason = fmt.Sprintf("%s was read because %s is absent", path, resolvConfPath)
		// The fallback succeeded, and saying so plainly is what distinguishes
		// "this host has a resolver, read from a less usual path" from
		// "THN could not find one".
		return st, Succeeded(primary,
			fmt.Sprintf("the primary path was unreadable, so the well-known alternate %s was read instead", path),
			len(st.Nameservers))
	}

	// Every path failed. The last error is retained because it is the one an
	// operator would act on.
	st := DNSState{
		Mechanism: DNSMechanismUnknown,
		Reason:    fmt.Sprintf("%s is not present and no alternative was found", resolvConfPath),
	}
	primary.Operation = "resolv-conf-and-alternates"
	primary.Outcome = ProbeToolUnavailable
	primary.Detail = "no resolver configuration could be read from any known path"
	primary.Reason = strings.TrimSpace(primary.Reason + "; " + fmt.Sprintf(
		"no alternative under %s was readable either", filepath.Dir(resolvConfAlternates[0])))
	return st, primary
}

// classifyFileErrorOutcome reduces a file error to a probe outcome.
func classifyFileErrorOutcome(err error) ProbeOutcome {
	outcome, _ := classifyFileError(err)
	return outcome
}
