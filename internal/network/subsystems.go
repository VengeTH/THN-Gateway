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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/venth/thn-gateway/internal/guard"
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
	QuerySucceeded bool `json:"query_succeeded"`

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
func ParseNFTablesTables(raw []byte) []NftTable {
	var doc nftTablesJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
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
	return out
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
	st := NFTablesState{Checked: true}

	out, err := guard.Exec(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		if isMissingTool(err) {
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
	st.QuerySucceeded = true
	st.Tables = ParseNFTablesTables([]byte(out.Stdout))
	st.Managed = true

	for _, t := range st.Tables {
		if t.IsTHNTable() {
			st.THNTablePresent = true
		}
		if !t.IsTHNTable() {
			st.Managed = false
		}
	}
	return st
}

// isMissingTool reports whether an exec error means the binary is absent.
//
// exec.ErrNotFound is the unambiguous case. The string test covers the case
// where the lookup succeeded but execution failed for want of the interpreter
// or a missing shared library, which is still "the tool is not usable here" and
// not a permission problem.
func isMissingTool(err error) bool {
	if err == nil {
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "cannot find")
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
	QuerySucceeded bool `json:"query_succeeded"`

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
func ParseQdiscs(raw []byte) []Qdisc {
	var parsed []struct {
		Kind   string `json:"kind"`
		Handle string `json:"handle"`
		Root   bool   `json:"root"`
		Dev    string `json:"dev"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
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
	return out
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
	st := TCState{Checked: true}

	out, err := guard.Exec(ctx, "tc", "-j", "qdisc", "show")
	if err != nil {
		if isMissingTool(err) {
			st.Reason = "the tc binary is not installed on this host"
			return st
		}
		st.Available = true
		st.Reason = fmt.Sprintf("tc is installed but queue disciplines could not be read: %v", err)
		return st
	}

	st.Available = true
	st.QuerySucceeded = true
	st.Qdiscs = ParseQdiscs([]byte(out.Stdout))

	for _, q := range st.Qdiscs {
		if strings.EqualFold(q.Kind, "cake") {
			st.CakeObserved = true
		}
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
		return observeDNSAlternate()
	}

	st := ParseResolvConf(string(b))

	// Detect a systemd-resolved stub. Both the symlink and the file's own
	// banner are checked: the symlink is the reliable signal, and the banner
	// is what a copied or bind-mounted resolv.conf leaves behind.
	if isSystemdResolvedStub(resolvConfPath, string(b)) {
		st.Mechanism = DNSMechanismSystemdResolved
		st.Authoritative = false
		st.Reason = "/etc/resolv.conf is a systemd-resolved stub; " +
			"the local resolver owns DNS on this host and this file's " +
			"contents are rewritten at runtime"
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

// isLiteralIP reports whether s parses as an IPv4 or IPv6 address.
//
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
func observeDNSAlternate() DNSState {
	for _, path := range resolvConfAlternates {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		st := ParseResolvConf(string(b))
		st.Reason = fmt.Sprintf("%s was read because %s is absent", path, resolvConfPath)
		return st
	}
	return DNSState{
		Mechanism: DNSMechanismUnknown,
		Reason:    fmt.Sprintf("%s is not present and no alternative was found", resolvConfPath),
	}
}
