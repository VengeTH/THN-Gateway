package network_test

// M7.0 host observation: the parsers that turn a real Linux host's output
// into the model the rest of THN reasons about.
//
// # What is being protected here
//
// Every parser below turns an external tool's output into a fact THN will
// report to an operator as if it were true about their machine. Each one has a
// specific way of failing quietly, and each test below is aimed at that way:
//
//   - ParseOSRelease silently reporting an empty distribution (quoting styles)
//   - ParseResolvConf reporting a systemd stub's placeholder as a nameserver
//   - ParseNFTablesTables attributing a chain to the wrong table
//   - ParseQdiscs dropping a discipline because a field shape was unfamiliar
//   - ParseLinks calling a tunnel a NIC because it has a MAC
//
// A parser that returns empty without error is the failure that matters most:
// an empty interface list looks exactly like a host with no network card, and
// both look like a healthy machine with nothing to report.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/network"
)

// hostFixture reads a checked-in host capture from testdata/hosts.
func hostFixture(t *testing.T, name string) []byte {
	t.Helper()
	return fixture(t, filepath.Join("hosts", name))
}

// hostTextFixture reads a checked-in host capture as text.
func hostTextFixture(t *testing.T, name string) string {
	t.Helper()
	return string(hostFixture(t, name))
}

// ------------------------------------------------------------- platform

// TestParseOSReleaseReadsUbuntu proves a standard os-release is understood.
func TestParseOSReleaseReadsUbuntu(t *testing.T) {
	p := network.ParseOSRelease(hostTextFixture(t, "os_release_ubuntu"))

	if p.Distribution != "ubuntu" {
		t.Errorf("Distribution = %q, want ubuntu", p.Distribution)
	}
	if p.Version != "24.04" {
		t.Errorf("Version = %q, want 24.04", p.Version)
	}
	if p.Codename != "noble" {
		t.Errorf("Codename = %q, want noble", p.Codename)
	}
	if p.Describe() != "Ubuntu 24.04.1 LTS" {
		t.Errorf("Describe() = %q, want the distribution's own PRETTY_NAME", p.Describe())
	}
}

// TestParseOSReleaseHandlesSingleQuoting is the case that motivates the
// unquoting logic.
//
// Alpine writes its os-release with single quotes and no PRETTY_NAME. A
// parser written against Ubuntu's output reports an empty distribution on
// every Alpine host — silently, and with no diagnostic to explain why.
func TestParseOSReleaseHandlesSingleQuoting(t *testing.T) {
	p := network.ParseOSRelease(hostTextFixture(t, "os_release_alpine"))

	if p.Distribution != "alpine" {
		t.Errorf("Distribution = %q, want alpine", p.Distribution)
	}
	if p.Name != "Alpine Linux" {
		t.Errorf("Name = %q; single-quoted values must be unquoted", p.Name)
	}
	if p.Version != "3.20.1" {
		t.Errorf("Version = %q, want 3.20.1", p.Version)
	}
}

// TestParseOSReleaseSurvivesGarbage proves a malformed file does not lose the
// facts that were readable.
//
// One bad line must cost one field, not the whole parse: refusing to describe
// a host because of a stray line would make THN useless exactly where the
// distribution is unusual and the operator needs help most.
func TestParseOSReleaseSurvivesGarbage(t *testing.T) {
	p := network.ParseOSRelease(`
# a comment
this line has no equals sign
ID=plan9
=novalue
PRETTY_NAME="Weird Linux"
`)

	if p.Distribution != "plan9" {
		t.Errorf("Distribution = %q, want plan9; unparseable lines must be skipped", p.Distribution)
	}
	if p.Describe() != "Weird Linux" {
		t.Errorf("Describe() = %q, want Weird Linux", p.Describe())
	}
}

// TestParseOSReleaseEmptyIsUnknown proves absence is reported as absence.
//
// An empty os-release must not produce a distribution name that looks like a
// finding. It produces nothing, and the caller reports "not established".
func TestParseOSReleaseEmptyIsUnknown(t *testing.T) {
	p := network.ParseOSRelease("")

	if p.Distribution != "" || p.Name != "" || p.PrettyName != "" {
		t.Errorf("empty os-release produced %+v; want every field empty", p)
	}
}

// TestSystemDescribeFallsBack proves Describe always says something.
//
// The fallback chain exists so a report never has an empty "platform" line.
// Each step down is less specific but still true, which is what a summary
// needs to be.
func TestSystemDescribeFallsBack(t *testing.T) {
	cases := []struct {
		name string
		in   network.System
		want string
	}{
		{"pretty name wins", network.System{PrettyName: "Ubuntu 24.04.1 LTS", Name: "Ubuntu"}, "Ubuntu 24.04.1 LTS"},
		{"name and version", network.System{Name: "Debian GNU/Linux", Version: "12"}, "Debian GNU/Linux 12"},
		{"name only", network.System{Name: "Void Linux"}, "Void Linux"},
		{"distribution only", network.System{Distribution: "arch"}, "arch"},
		{"os only", network.System{OS: "linux"}, "linux"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Describe(); got != tc.want {
				t.Errorf("Describe() = %q, want %q", got, tc.want)
			}
		})
	}
}

// --------------------------------------------------------------- nftables

// TestParseNFTablesTablesReadsUnmanagedTables is Fixture C's nft half.
//
// The host carries four tables and none of them are THN's. Every one must be
// visible, because the whole point of discovery is that an operator can see
// what is already on the machine.
func TestParseNFTablesTablesReadsUnmanagedTables(t *testing.T) {
	tables, err := network.ParseNFTablesTables(hostFixture(t, "infrastructure_nft.json"))
	if err != nil {
		t.Fatalf("ParseNFTablesTables: %v", err)
	}

	if len(tables) != 4 {
		t.Fatalf("parsed %d tables, want 4 (ip/filter, ip/nat, inet/filter, ip/docker-forward): %+v",
			len(tables), tables)
	}

	if findTable(tables, "ip", "filter") == nil {
		t.Error("ip/filter was not reported")
	}
	docker := findTable(tables, "ip", "docker-forward")
	if docker == nil {
		t.Fatal("Docker's own table was not reported; unmanaged resources must stay visible")
	}
	// Chains must be attached to the table they actually belong to. A chain
	// attributed to the wrong table is worse than a missing one.
	if len(docker.Chains) != 2 {
		t.Errorf("docker-forward chains = %v, want the two DOCKER chains", docker.Chains)
	}
	for _, c := range docker.Chains {
		if c != "DOCKER-FORWARD" && c != "DOCKER-ISOLATION-STAGE-1" {
			t.Errorf("docker-forward carries unexpected chain %q; chains must not migrate between tables", c)
		}
	}

	// No table in this fixture is THN's, and IsTHNTable must say so.
	for _, tb := range tables {
		if tb.IsTHNTable() {
			t.Errorf("table %s %s was claimed as THN's", tb.Family, tb.Name)
		}
	}
}

// TestIsTHNTableMatchesOnlyTheOwnTable proves the ownership test is exact.
//
// Family matters as much as name: `ip filter` is not `inet thn`, and a host
// with both must not be reported as THN-owned.
func TestIsTHNTableMatchesOnlyTheOwnTable(t *testing.T) {
	if !(network.NftTable{Family: "inet", Name: "thn"}).IsTHNTable() {
		t.Error("inet/thn was not recognised as THN's own table")
	}
	for _, tb := range []network.NftTable{
		{Family: "ip", Name: "thn"},
		{Family: "inet", Name: "filter"},
		{Family: "ip6", Name: "thn"},
	} {
		if tb.IsTHNTable() {
			t.Errorf("%s %s was wrongly claimed as THN's table", tb.Family, tb.Name)
		}
	}
}

// TestParseNFTablesTablesEmptyIsEmptyNotBroken proves an empty ruleset parses
// to no tables without error.
//
// A host with nft installed and no rules is a normal host. It must not be
// reported as an error, and must not be reported as having tables.
func TestParseNFTablesTablesEmptyIsEmptyNotBroken(t *testing.T) {
	tables, err := network.ParseNFTablesTables([]byte(`{"nftables": []}`))
	if err != nil {
		t.Fatalf("an empty ruleset must not be an error: %v", err)
	}
	if len(tables) != 0 {
		t.Errorf("empty ruleset produced %d tables, want 0", len(tables))
	}
}

// ---------------------------------------------------------------------- tc

// TestParseQdiscsReadsRootDisciplines proves disciplines are read with their
// kind, handle and device.
func TestParseQdiscsReadsRootDisciplines(t *testing.T) {
	qdiscs, err := network.ParseQdiscs(hostFixture(t, "tc_cake.json"))
	if err != nil {
		t.Fatalf("ParseQdiscs: %v", err)
	}

	if len(qdiscs) != 2 {
		t.Fatalf("parsed %d qdiscs, want 2: %+v", len(qdiscs), qdiscs)
	}
	cake := qdiscs[1]
	if cake.Kind != "cake" {
		t.Errorf("second qdisc kind = %q, want cake", cake.Kind)
	}
	if cake.Handle != "8001" {
		t.Errorf("handle = %q; the trailing tc colon is punctuation and must be trimmed", cake.Handle)
	}
	if cake.Device != "wan0" {
		t.Errorf("device = %q, want wan0", cake.Device)
	}
	if !cake.Root {
		t.Error("the attached discipline should be reported as root")
	}
}

// TestParseQdiscsKeepsUnknownDisciplines proves an unfamiliar algorithm is
// still reported.
//
// A future or vendor qdisc must appear as itself. Dropping it would under-
// report the host's shaping configuration, and the operator would see a host
// that appears unshaped when it is not.
func TestParseQdiscsKeepsUnknownDisciplines(t *testing.T) {
	qdiscs, err := network.ParseQdiscs([]byte(`[{"kind":"ethtool","handle":"8002:","root":false,"dev":"lan0"}]`))
	if err != nil {
		t.Fatalf("ParseQdiscs: %v", err)
	}

	if len(qdiscs) != 1 {
		t.Fatalf("parsed %d qdiscs, want 1", len(qdiscs))
	}
	if qdiscs[0].Kind != "ethtool" {
		t.Errorf("kind = %q, want ethtool; an unfamiliar discipline must still be reported", qdiscs[0].Kind)
	}
}

// TestParseQdiscsRejectsGarbage proves unparseable output yields an ERROR,
// not a partial, wrong answer.
//
// This is the behaviour the error return was added for. Returning an empty
// slice was indistinguishable from "this host has no queue disciplines
// attached", so ObserveTrafficControl set QuerySucceeded=true over garbage
// output and reported a format change as an absence of shaping.
func TestParseQdiscsRejectsGarbage(t *testing.T) {
	qdiscs, err := network.ParseQdiscs([]byte("not json"))
	if err == nil {
		t.Fatal("malformed tc output parsed without error; a format change would be reported as an empty host")
	}
	if len(qdiscs) != 0 {
		t.Errorf("garbage input produced %d qdiscs, want 0", len(qdiscs))
	}
	if !strings.Contains(err.Error(), "not the expected JSON array") {
		t.Errorf("error does not say what failed: %v", err)
	}
}

// --------------------------------------------------------------------- DNS

// TestParseResolvConfReadsNameservers proves a plain resolv.conf is read.
func TestParseResolvConfReadsNameservers(t *testing.T) {
	st := network.ParseResolvConf(hostTextFixture(t, "resolv_plain.conf"))

	if len(st.Nameservers) != 2 {
		t.Fatalf("nameservers = %v, want two", st.Nameservers)
	}
	if st.Nameservers[0] != "192.168.2.1" {
		t.Errorf("first nameserver = %q, want 192.168.2.1", st.Nameservers[0])
	}
	if len(st.Search) != 1 || st.Search[0] != "example.lan" {
		t.Errorf("search = %v, want [example.lan]", st.Search)
	}
	if len(st.Options) != 2 {
		t.Errorf("options = %v, want two", st.Options)
	}
	if st.Mechanism != network.DNSMechanismResolvConf {
		t.Errorf("mechanism = %q, want resolv.conf", st.Mechanism)
	}
	if !st.Authoritative {
		t.Error("a plain resolv.conf is authoritative and must be reported as such")
	}
}

// TestParseResolvConfDropsNonAddresses proves a bogus nameserver is not
// reported as a nameserver.
//
// The output of this function is rendered to an operator as "the upstream
// resolvers". A hostname there is not a resolver, and printing it as one is a
// claim THN cannot support.
func TestParseResolvConfDropsNonAddresses(t *testing.T) {
	st := network.ParseResolvConf("nameserver not-an-ip\nnameserver 1.1.1.1\n")

	if len(st.Nameservers) != 1 || st.Nameservers[0] != "1.1.1.1" {
		t.Errorf("nameservers = %v, want only the literal address", st.Nameservers)
	}
}

// TestParseResolvConfAcceptsIPv6 proves v6 resolvers are read.
func TestParseResolvConfAcceptsIPv6(t *testing.T) {
	st := network.ParseResolvConf("nameserver 2606:4700:4700::1111\n")

	if len(st.Nameservers) != 1 || st.Nameservers[0] != "2606:4700:4700::1111" {
		t.Errorf("nameservers = %v, want the IPv6 resolver", st.Nameservers)
	}
}

// TestParseResolvConfHandlesDomainDirective proves the deprecated single-domain
// form is read as a search domain.
func TestParseResolvConfHandlesDomainDirective(t *testing.T) {
	st := network.ParseResolvConf("domain corp.example\nnameserver 10.0.0.1\n")

	if len(st.Search) != 1 || st.Search[0] != "corp.example" {
		t.Errorf("search = %v, want [corp.example]", st.Search)
	}
}

// ---------------------------------------------------------------- fixtures

// TestFixtureBSingleInterfaceIsFullyParsed is Fixture B at the parser level.
//
// The host must be fully described even though it cannot be a two-port
// gateway. "Not a gateway" is a verdict; "cannot be observed" would be a bug.
func TestFixtureBSingleInterfaceIsFullyParsed(t *testing.T) {
	ifaces, err := network.ParseLinks(hostFixture(t, "single_interface_link.json"))
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}
	if len(ifaces) != 2 {
		t.Fatalf("parsed %d interfaces, want lo + eth0", len(ifaces))
	}

	eth := find(ifaces, "eth0")
	if eth == nil {
		t.Fatal("eth0 was not parsed")
	}
	if !eth.Physical {
		t.Error("eth0 should be classified physical")
	}
	if eth.SpeedMbps != 1000 {
		t.Errorf("eth0 speed = %d, want 1000", eth.SpeedMbps)
	}
}

// TestFixtureCInfrastructureIsNotMistakenForHardware is the classification
// property the whole interface model rests on.
//
// Docker's bridge, a container veth and a Tailscale tunnel all appear here,
// and all three report an Ethernet-ish address. Classifying any of them as
// physical would offer it to an operator as a gateway port — the specific
// failure the Physical field exists to prevent.
func TestFixtureCInfrastructureIsNotMistakenForHardware(t *testing.T) {
	ifaces, err := network.ParseLinks(hostFixture(t, "infrastructure_link.json"))
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}

	// Exactly two real NICs, and they are the two "enp" ports.
	physical := 0
	for _, i := range ifaces {
		if i.Physical {
			physical++
		}
	}
	if physical != 2 {
		t.Errorf("%d physical interfaces, want 2; Docker/veth/tailscale must not count as hardware: %v",
			physical, names(ifaces))
	}

	for _, name := range []string{"docker0", "veth9f2a1c", "tailscale0", "lo"} {
		ifc := find(ifaces, name)
		if ifc == nil {
			t.Errorf("%s was not parsed at all", name)
			continue
		}
		if ifc.Physical {
			t.Errorf("%s was classified physical; it is %s infrastructure, not a port", name, ifc.Kind)
		}
	}
}

// TestFixtureCInfrastructureKeepsItsKinds proves the kinds survive.
func TestFixtureCInfrastructureKeepsItsKinds(t *testing.T) {
	ifaces, err := network.ParseLinks(hostFixture(t, "infrastructure_link.json"))
	if err != nil {
		t.Fatalf("ParseLinks: %v", err)
	}

	for name, want := range map[string]string{
		"docker0":    "bridge",
		"veth9f2a1c": "veth",
		"tailscale0": "tun",
		"lo":         "loopback",
	} {
		ifc := find(ifaces, name)
		if ifc == nil {
			t.Errorf("%s missing", name)
			continue
		}
		if ifc.Kind != want {
			t.Errorf("%s kind = %q, want %q", name, ifc.Kind, want)
		}
	}
}

// TestFixtureCRoutesAreObservedNotJudged proves existing routes are reported
// verbatim.
//
// The host's default route is an observation. THN does not claim it as a WAN,
// does not treat it as authoritative, and must not drop it either.
func TestFixtureCRoutesAreObservedNotJudged(t *testing.T) {
	var doc struct {
		Routes []struct {
			Dst      string `json:"dst"`
			Gateway  string `json:"gateway"`
			Dev      string `json:"dev"`
			Protocol string `json:"protocol"`
		} `json:"routes"`
	}
	raw := hostFixture(t, "infrastructure_routes.json")
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}

	// Route through the real parser by re-emitting it as `ip -j route show`.
	encoded, err := json.Marshal(doc.Routes)
	if err != nil {
		t.Fatalf("re-encoding fixture: %v", err)
	}
	routes, err := network.ParseRoutes(encoded)
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}

	if len(routes) != 4 {
		t.Fatalf("parsed %d routes, want 4", len(routes))
	}
	def := routes[0]
	if !def.Default || def.Destination != "default" {
		t.Errorf("first route = %+v; the default route must sort first", def)
	}
	if def.Gateway != "192.168.2.1" || def.Interface != "enp1s0" {
		t.Errorf("default route = %+v, want via 192.168.2.1 dev enp1s0", def)
	}

	// Every route survives. Discovery does not curate.
	seen := map[string]bool{}
	for _, r := range routes {
		seen[r.Destination] = true
	}
	for _, want := range []string{"172.17.0.0/16", "192.168.2.0/24", "100.64.0.0/10"} {
		if !seen[want] {
			t.Errorf("route %s was not observed; unmanaged routes must stay visible", want)
		}
	}
}

// findTable returns the table with the given family and name, or nil.
func findTable(tables []network.NftTable, family, name string) *network.NftTable {
	for i := range tables {
		if tables[i].Family == family && tables[i].Name == name {
			return &tables[i]
		}
	}
	return nil
}
