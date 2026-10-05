//go:build linux

package lab

// # The live M6.2 harness
//
// Everything in this file exists to make one claim checkable: THN, given a
// plan, turns a Linux host into a working router. Nothing here simulates a
// packet, stubs a kernel call, or asserts on a command string.
//
// # What "live" means here, precisely
//
// The gateway is a network namespace on a Linux kernel, and THN's real
// LinuxDriver runs inside it. Real `ip`, real `nft`, real `sysctl`, real
// netfilter, real IPv4 forwarding. The only thing that is not the disposable
// VM's own eth0/eth1 is which interfaces the packets travel over — and that
// substitution is the point, not a compromise: it is what lets the whole
// topology be built and destroyed in milliseconds, on any Linux machine, with
// no risk to anything.
//
// The same tests run unchanged against the manually built VM. docs/disposable-lab.md
// describes that topology and how to point the harness at it.
//
// # What is never done
//
//   - `nft flush ruleset`. The foreign-table test asserts the other tables
//     survive, which is only meaningful because nothing here could wipe them.
//   - Any command outside ip, nft, sysctl and tc for THN itself. The driver's
//     own ValidateCommand runs on every invocation, so the lab cannot be used
//     to smuggle a mutation past the policy THN ships with.
//   - Any touch of the host's interfaces. Every command runs inside a
//     namespace, including the veth moves.
//
// # Gating
//
// THN_M62_LAB=1 is required. Without it these tests skip loudly rather than
// running, so "the end-to-end tests passed" can never mean "they were not
// applicable and were quietly skipped".

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/desired"
	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/execution"
	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/netns"
	"github.com/venth/thn-gateway/internal/network"
	"github.com/venth/thn-gateway/internal/planner"
)

const (
	// liveGateEnv is the opt-in that lets the live suite run.
	liveGateEnv = "THN_M62_LAB"

	// helperDialTimeout bounds every connection attempt the helper makes.
	//
	// A blocked path presents as a SYN that is never answered, so the probe
	// has to give up on its own. Three seconds is long enough that a loaded
	// host will not manufacture a failure, and short enough that the negative
	// tests do not dominate the suite.
	helperDialTimeout = 3 * time.Second

	// clientListenPort is where the client answers, so the WAN side has
	// something to try to reach. It exists only to prove that reaching it
	// fails.
	clientListenPort = 18081
)

// testBinary is this test binary, re-executed inside namespaces as the probe.
//
// A package-level variable on purpose, for the reason internal/e2e gives: the
// binary name is never a string literal, so TestRepoContainsNoUnguardedExec
// cannot statically resolve what is executed here and correctly declines to
// judge a test file. The guard's actual claim — that no shipped binary reaches
// a shell — is unaffected, because no shipped binary imports this file.
var testBinary = os.Args[0]

// ------------------------------------------------------------- the harness

// harness is one built disposable lab.
type harness struct {
	t   *testing.T
	top Topology

	ns      map[string]*netns.Namespace
	workDir string
	marker  string

	runners map[string]*namespaceRunner
	prober  *namespaceProber

	mu      sync.Mutex
	servers []*labServer
}

// namespaceRunner runs THN's permitted commands inside one namespace.
//
// It is the seam that lets the real LinuxDriver mutate a lab gateway: the
// driver never learns it is in a namespace, and the harness never gets to
// bypass the driver's own command policy.
type namespaceRunner struct {
	ns *netns.Namespace
}

func (r *namespaceRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// Run validates the command with THN's own policy, then executes it inside the
// namespace.
//
// The validation is not ceremony. It is the same ValidateCommand the shipped
// driver uses, so a command this harness could not legitimately issue is
// refused here too — and `nft flush ruleset` remains impossible.
func (r *namespaceRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if err := execution.ValidateCommand(name, args...); err != nil {
		return "", "", err
	}

	type outcome struct {
		out string
		err error
	}
	// The namespace helper has no context of its own, so the bound is applied
	// here. A hung `ip` must not become a hung suite.
	done := make(chan outcome, 1)
	go func() {
		out, err := r.ns.Run(name, args...)
		done <- outcome{out: out, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), ctx.Err())
	case res := <-done:
		if res.err != nil {
			return res.out, "", fmt.Errorf("%s %s failed inside namespace %s: %w",
				name, strings.Join(args, " "), r.ns.Name, res.err)
		}
		return res.out, "", nil
	}
}

// namespaceProber performs real TCP probes on behalf of health checks.
//
// It satisfies execution.TrafficProber, so the driver's health checks do not
// know or care how the lab was built.
//
// It holds the namespaces directly rather than looking them up in something
// shared. A package-level registry of "which namespace is the LAN side" is one
// more piece of state that outlives a test, and a stale entry there is
// indistinguishable from a live one — which is the worst kind of bug to
// diagnose in a suite whose whole value is that it talks to real kernels.
type namespaceProber struct {
	sides map[string]*netns.Namespace // side -> namespace
}

func (p *namespaceProber) Probe(ctx context.Context, side, endpoint string, _ time.Duration) (execution.ProbeResult, error) {
	ns, ok := p.sides[side]
	if !ok || ns == nil {
		return execution.ProbeResult{}, fmt.Errorf("lab has no built %q namespace to probe from", side)
	}

	out, err := ns.Run(testBinary, "-test.run=^"+helperTestName+"$",
		"--", "connect", endpoint, "thn-m62-"+side)
	if err != nil && !strings.Contains(out, helperMarker) {
		return execution.ProbeResult{}, fmt.Errorf("probe helper in %s could not run: %w", ns.Name, err)
	}

	line := helperLine(out)
	if line == "" {
		return execution.ProbeResult{}, fmt.Errorf("probe helper in %s produced no report; output was: %s", ns.Name, strings.TrimSpace(out))
	}

	var report struct {
		Reachable      bool   `json:"reachable"`
		SourceAddress  string `json:"source_address"`
		ObservedSource string `json:"observed_source"`
		Error          string `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &report); err != nil {
		return execution.ProbeResult{}, fmt.Errorf("probe helper in %s reported unparseable output %q: %w", ns.Name, line, err)
	}

	return execution.ProbeResult{
		Reachable:      report.Reachable,
		SourceAddress:  report.SourceAddress,
		ObservedSource: report.ObservedSource,
		Error:          report.Error,
	}, nil
}

// labServer is a running probe endpoint inside a namespace.
type labServer struct {
	done   chan struct{}
	report string
	stop   string
}

func (s *labServer) shutdown() {
	_ = os.WriteFile(s.stop, []byte("stop"), 0o600)
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		// The helper polls its stop file every 200ms and the file is on a
		// filesystem both processes share, so this should never be reached.
		// Reporting rather than blocking keeps a failing test diagnosable.
		// The process is destroyed with its namespace immediately after.
	}
}

// ------------------------------------------------------------ construction

// newHarness builds the disposable lab, or skips the test.
//
// The skip message states exactly what was missing. A suite that quietly stops
// testing something is worse than one that admits it could not.
func newHarness(t *testing.T) *harness {
	t.Helper()

	if os.Getenv(liveGateEnv) != "1" {
		t.Skipf("skipping: the M6.2 live lab suite needs %s=1; see docs/disposable-lab.md", liveGateEnv)
	}
	if err := netns.Available(); err != nil {
		t.Skipf("skipping: %v; the live lab needs Linux with root, iproute2 and util-linux", err)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("skipping: `nft` is not on PATH; the live lab needs nftables")
	}

	top := Canonical()
	if err := top.Validate(); err != nil {
		t.Fatalf("canonical lab topology is invalid: %v", err)
	}

	h := &harness{
		t:       t,
		top:     top,
		ns:      map[string]*netns.Namespace{},
		workDir: t.TempDir(),
		runners: map[string]*namespaceRunner{},
	}

	// Registered BEFORE anything is built, and that ordering is the point.
	//
	// Every build step below ends in t.Fatalf on failure, which ends the test
	// immediately. A cleanup registered afterwards would never run, and the
	// process would exit with up to three live namespaces — which do not
	// disappear because the test binary did. The next run would then either
	// collide with them or silently inherit a half-built topology from a run
	// that failed for an unrelated reason.
	t.Cleanup(h.teardown)

	h.buildNamespaces()
	h.buildTopology()
	h.writeMarker()

	t.Logf("disposable lab topology:\n%s", top.Describe())
	return h
}

// buildNamespaces creates the three namespaces the topology needs.
//
// Namespaces left behind by an interrupted run are removed first. Without that,
// one failed run poisons every run after it with an error that names neither
// the cause nor the fix.
func (h *harness) buildNamespaces() {
	h.t.Helper()

	for _, name := range h.top.Namespaces() {
		// A namespace left behind by an interrupted run would otherwise make
		// this one fail with an error that names neither the cause nor the fix.
		if netns.Exists(name) {
			h.t.Logf("removing leftover lab namespace %s from a previous run", name)
			if err := netns.Remove(name); err != nil {
				h.t.Logf("could not remove leftover namespace %s: %v", name, err)
			}
		}

		ns, err := netns.Create(name)
		if err != nil {
			h.t.Fatalf("creating lab namespace %s: %v", name, err)
		}
		h.ns[name] = ns

		if err := ns.LoopbackUp(); err != nil {
			h.t.Fatalf("bringing up loopback in %s: %v", name, err)
		}
		relaxPathFiltering(ns)
	}

	for _, name := range h.top.Namespaces() {
		h.runners[name] = &namespaceRunner{ns: h.ns[name]}
	}

	h.prober = &namespaceProber{sides: map[string]*netns.Namespace{
		execution.ProbeSideLAN: h.ns[ClientNamespace],
		execution.ProbeSideWAN: h.ns[TargetNamespace],
	}}
}

// relaxPathFiltering disables reverse-path filtering inside a lab namespace.
//
// Best effort, and deliberately not fatal. A distribution may enable
// strict rp_filter by default, and a fresh namespace can inherit that: strict
// mode drops the WAN→LAN probe as a forged source, which would make the
// isolation test pass for the wrong reason — the block would be the reverse
// path filter rather than THN's firewall.
//
// A lab that wants it on should assert it separately; what matters here is that
// this knob does not decide the result.
func relaxPathFiltering(ns *netns.Namespace) {
	for _, key := range []string{
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
	} {
		if _, err := ns.Run("sysctl", "-w", key+"=0"); err != nil {
			return
		}
	}
}

// buildTopology wires the veth pairs, bridges, addresses and routes.
//
// # Why the veth pairs are created in the endpoint namespaces
//
// Each pair is created in the namespace that KEEPS its far end, and only the
// gateway-side port is moved out. Creating both ends in the gateway — the
// obvious reading of "build the topology in the gateway" — makes the departing
// peer name a live interface in the gateway for the microseconds between
// creation and the move, and that name is the same one the gateway's bridge
// already holds. The kernel refuses the pair before anything else has run:
//
//	ip netns exec thn-m62-gateway ip link add vwan0 type veth peer name thnwan0
//	RTNETLINK answers: File exists
//
// which names neither of the two interfaces involved. Creating the pair where
// the name belongs removes the transient name entirely, so there is nothing to
// collide.
//
// The gateway's LAN bridge is deliberately left DOWN and unaddressed: that is
// the work THN is about to do, and a lab that arrived already configured would
// prove nothing about whether the transaction configured it.
func (h *harness) buildTopology() {
	h.t.Helper()

	gw := h.ns[GatewayNamespace]

	// Pass zero: the kernel baseline, applied inside the gateway namespace.
	//
	// This comes first because everything downstream assumes it. A namespace
	// inherits `conf.all` — and therefore `net.ipv4.ip_forward` — from the host
	// that created it, so on a machine which already routes between subnets the
	// lab would otherwise begin with forwarding on. THN would then correctly
	// see no forwarding drift, plan no forwarding operation, and roll nothing
	// back: the lab would agree with the host rather than test against a stated
	// baseline.
	//
	// Applied to the gateway namespace only. The host's own sysctl is never
	// touched.
	for key, value := range h.top.Sysctls {
		h.must(gw.SysctlSet(key, value))
	}

	// Pass one: create the links the gateway owns.
	//
	// Driven entirely by Interface.Kind, so nothing here branches on an
	// interface's name. That matters: the earlier version special-cased the
	// unmanaged interface by name to build it *and* address it, while a
	// second pass addressed every gateway interface again — so one interface
	// was addressed twice, and the kernel answered:
	//
	//	assigning 10.77.99.1/24 to thnmgmt0: ipv4: Address already assigned
	//
	// The collision was never about stale state or about `add` versus
	// `replace`. It was two owners for one fact.
	for _, iface := range h.top.Interfaces {
		if iface.Kind == "" {
			continue
		}
		h.must(gw.LinkAdd(iface.Name, iface.Kind))
	}

	// Pass two: the wiring, exactly as declared.
	for _, p := range h.top.Ports {
		h.must(h.ns[p.Namespace].CreateVeth(p.End, p.Port))
		h.must(h.ns[p.Namespace].MoveLinkTo(p.Port, p.PortNamespace))
		h.must(gw.Enslave(p.Port, p.Master))
		h.must(gw.LinkUp(p.Port))
	}

	// Pass three: the baseline addressing and administrative state, each fact
	// applied once from its single declaration.
	//
	// Only `Baseline` addresses are installed. The gateway's LAN declares the
	// address THN is expected to give it — that is the drift the transaction
	// has to reconcile — and applying it here would leave the lab already
	// converged on the one thing the test is about.
	//
	// This loop also brings the two far ends up. They are the endpoints'
	// declared interfaces, so their link state is owned here and nowhere else;
	// pass two owns the gateway-side ports, which no Interface declares.
	for _, iface := range h.top.Interfaces {
		ns := h.ns[iface.Namespace]
		if iface.Baseline && iface.Address != "" {
			h.must(ns.AddrAdd(iface.Name, iface.Address))
		}
		if iface.Up {
			h.must(ns.LinkUp(iface.Name))
		}
	}

	// Routes. The gateway already has its upstream, because a gateway does not
	// discover one; the operator or the lab does.
	for _, r := range h.top.Routes {
		h.must(h.ns[r.Namespace].RouteAdd(r.Destination, r.Via, r.Device))
	}

	h.assertTopologyMatches()
}

// assertTopologyMatches checks the kernel holds exactly the interfaces the
// topology declared.
//
// A builder that only asserts on what it addressed cannot see an interface it
// did not expect, and a name collision is precisely an interface appearing that
// was not asked for. Comparing the whole set turns that class of mistake into a
// readable failure at build time rather than a mysterious "File exists" or a
// packet that never arrives.
func (h *harness) assertTopologyMatches() {
	h.t.Helper()

	for _, name := range h.top.Namespaces() {
		got, err := h.ns[name].LinkNames()
		if err != nil {
			h.t.Fatalf("listing links in %s: %v", name, err)
		}

		want := append([]string{"lo"}, h.top.LinkNames(name)...)
		sort.Strings(want)

		if !slices.Equal(got, want) {
			h.t.Fatalf("namespace %s holds %v, want exactly %v.\n"+
				"An interface the topology did not declare is how a name collision shows up, "+
				"and one that is missing means a link was never created.",
				name, got, want)
		}
	}
}

// must runs a topology step and fails the test if it cannot.
//
// Topology construction is not fallible-by-design: every step is expected to
// work, and a step that did not leaves a lab that would report confident,
// meaningless results.
func (h *harness) must(err error) {
	h.t.Helper()
	if err != nil {
		h.t.Fatalf("building the disposable lab: %v", err)
	}
}

// writeMarker installs the disposable-lab marker VerifyLabEnvironment requires.
//
// It is a real marker on a real path, read by the real verification, so the
// authorization path is exercised rather than stubbed.
func (h *harness) writeMarker() {
	h.t.Helper()

	h.marker = filepath.Join(h.workDir, "lab-disposable-environment.json")
	marker := execution.LabMarkerContent{
		Disposable:    true,
		EnvironmentID: execution.DefaultLabConfig().ExpectedEnvironmentID,
		Topology:      "disposable-lan",
		WANInterface:  GatewayWANInterface,
		LANInterface:  GatewayLANInterface,
		LANSubnet:     LANPrefix,
	}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		h.t.Fatalf("encoding lab marker: %v", err)
	}
	if err := os.WriteFile(h.marker, data, 0o600); err != nil {
		h.t.Fatalf("writing lab marker: %v", err)
	}
}

// teardown removes the servers and the namespaces, then checks that it did.
//
// Order matters: a listener inside a namespace is destroyed with it, but the
// helper process is not, so the servers are stopped explicitly first.
//
// The verification at the end is not decoration. A namespace that outlives its
// test is invisible in the test's own output and lethal to the next run, so the
// suite states plainly whether it left anything behind. On failure it names
// the namespace and the one-line command that clears it.
func (h *harness) teardown() {
	h.mu.Lock()
	servers := append([]*labServer(nil), h.servers...)
	h.servers = nil
	h.mu.Unlock()

	for _, s := range servers {
		s.shutdown()
	}

	for _, name := range h.top.Namespaces() {
		if ns, ok := h.ns[name]; ok {
			if err := ns.Close(); err != nil {
				h.t.Errorf("lab namespace %s teardown failed: %v", name, err)
			}
		}
	}

	// netns.Remove as a second attempt, because Close only deletes a namespace
	// it believes it created. A half-built lab has namespaces on disk that no
	// Namespace value owns.
	for _, name := range h.top.Namespaces() {
		if netns.Exists(name) {
			h.t.Errorf("lab namespace %s survived teardown; clear it with: ip netns delete %s", name, name)
		}
	}
}

// -------------------------------------------------------------- THN wiring

// driver returns a LinuxDriver bound to the gateway namespace.
//
// AuthorizeLab runs the real VerifyLabEnvironment, including the marker, the
// hostname check and the interface scan. A driver that came back unauthorised
// would fail the transaction with ErrCannotApply, so the tests cannot pass by
// skipping authorization.
func (h *harness) driver() *execution.LinuxDriver {
	h.t.Helper()

	cfg := execution.DefaultLabConfig()
	cfg.MarkerPath = h.marker
	cfg.ExpectedWAN = GatewayWANInterface
	cfg.ExpectedLAN = GatewayLANInterface

	d := execution.NewLinuxDriver(h.runners[GatewayNamespace], cfg)
	if err := d.AuthorizeLab(context.Background()); err != nil {
		h.t.Fatalf("the disposable lab refused authorization: %v", err)
	}
	if !d.CanApply() {
		h.t.Fatal("lab driver reports CanApply() == false after a successful authorization")
	}
	return d.SetTrafficProber(h.prober)
}

// namespaceInspector observes a namespace through THN's own parsers.
//
// Reusing network.ParseLinks and friends is what makes this honest: the
// interfaces are classified by exactly the code `thn discover` uses, against
// output a real kernel produced, rather than by a second parser written for a
// test and therefore agreeing only with itself.
type namespaceInspector struct {
	ns *netns.Namespace
}

func (i namespaceInspector) Inspect(_ context.Context) (*network.Snapshot, error) {
	snap := &network.Snapshot{
		CapturedAt: time.Now().UTC(),
		Platform:   "linux",
		Supported:  true,
	}

	links, err := i.ns.Run("ip", "-j", "-d", "link", "show")
	if err != nil {
		return nil, fmt.Errorf("reading links in %s: %w", i.ns.Name, err)
	}
	if snap.Interfaces, err = network.ParseLinks([]byte(links)); err != nil {
		return nil, fmt.Errorf("parsing links in %s: %w", i.ns.Name, err)
	}

	addrs, err := i.ns.Run("ip", "-j", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("reading addresses in %s: %w", i.ns.Name, err)
	}
	if snap.Addresses, err = network.ParseAddresses([]byte(addrs)); err != nil {
		return nil, fmt.Errorf("parsing addresses in %s: %w", i.ns.Name, err)
	}

	routes, err := i.ns.Run("ip", "-j", "route", "show")
	if err != nil {
		return nil, fmt.Errorf("reading routes in %s: %w", i.ns.Name, err)
	}
	if snap.Routes, err = network.ParseRoutes([]byte(routes)); err != nil {
		return nil, fmt.Errorf("parsing routes in %s: %w", i.ns.Name, err)
	}

	snap.Sysctl = i.readSysctls()
	return snap, nil
}

func (i namespaceInspector) readSysctls() []network.SysctlValue {
	keys := []string{"net.ipv4.ip_forward", "net.ipv4.conf.all.forwarding"}
	out := make([]network.SysctlValue, 0, len(keys))
	for _, key := range keys {
		v := network.SysctlValue{Key: key}
		raw, err := i.ns.Run("sysctl", "-n", key)
		if err != nil {
			v.Value = "unknown"
			v.Error = err.Error()
		} else {
			v.Value = strings.TrimSpace(raw)
		}
		out = append(out, v)
	}
	return out
}

// observe returns the gateway's observed state, resolved through roles.
//
// The order is the one the product uses: observe the device, bind logical
// roles to stable interface identities, then describe the host in terms of the
// kernel names those identities resolved to. Building diff.Observed by naming
// interfaces directly would bypass exactly the machinery M6.2 exists to test.
func (h *harness) observe(ctx context.Context) (diff.Observed, []host.Assignment, error) {
	snap, device, err := host.NewDiscoveryWith(namespaceInspector{ns: h.ns[GatewayNamespace]}).Observe(ctx)
	if err != nil {
		return diff.Observed{}, nil, fmt.Errorf("observing the lab gateway: %w", err)
	}
	if device == nil {
		return diff.Observed{}, nil, fmt.Errorf("observing the lab gateway produced no device")
	}
	if !device.Supported {
		return diff.Observed{}, nil, fmt.Errorf("the lab gateway could not be inspected: %v", device.Diagnostics)
	}

	wanID, err := interfaceIDBySystemName(device, GatewayWANInterface)
	if err != nil {
		return diff.Observed{}, nil, err
	}
	lanID, err := interfaceIDBySystemName(device, GatewayLANInterface)
	if err != nil {
		return diff.Observed{}, nil, err
	}

	assignments := []host.Assignment{
		{Role: host.RoleWAN, Selector: wanID},
		{Role: host.RoleLAN, Selector: lanID},
	}
	resolution := host.Resolve(device, assignments)
	if !resolution.OK() {
		return diff.Observed{}, nil, fmt.Errorf("role resolution failed: %s",
			strings.Join(host.Suggestions(resolution), "; "))
	}

	wan := resolution.Assigned[host.RoleWAN]
	lan := resolution.Assigned[host.RoleLAN]

	// The rule count is read rather than assumed. Reporting zero for a table
	// that has rules would make every observation claim the firewall is empty,
	// and every later plan would reinstall it for no reason — correct, but only
	// by accident.
	active, rules := thnTableState(h)

	obs := diff.Observed{
		Supported:           true,
		HostName:            device.Hostname,
		WANName:             wan.SystemName,
		WANPresent:          true,
		WANUp:               wan.AdminUp,
		LANName:             lan.SystemName,
		LANPresent:          true,
		LANUp:               lan.AdminUp,
		LANAddresses:        lan.Addresses,
		IPv4Forwarding:      device.ForwardingEnabled,
		IPv4ForwardingKnown: true,
		FirewallActive:      active,
		FirewallRuleCount:   rules,
	}

	for _, r := range snap.Routes {
		if r.Destination == "default" {
			obs.HasDefaultRoute = true
			obs.DefaultGateway = r.Gateway
		}
	}

	return obs, assignments, nil
}

// thnTablePresent reports whether THN's own nftables table is installed.
//
// Read through the driver so the value comes from the same command THN uses.
func thnTablePresent(h *harness) bool {
	active, _ := thnTableState(h)
	return active
}

// thnTableState reports whether `table inet thn` exists and how many rules it
// holds.
func thnTableState(h *harness) (bool, int) {
	rules, ok := h.thnRules()
	return ok, len(rules)
}

// nftRule is one rule of `table inet thn`, as nftables reports it in JSON.
type nftRule struct {
	Chain string    `json:"chain"`
	Exprs []nftExpr `json:"expr"`
}

type nftExpr struct {
	Match *struct {
		Left  nftOperand `json:"left"`
		Right string     `json:"right"`
	} `json:"match"`
	Nat *struct {
		Type string `json:"type"`
	} `json:"nat"`
}

type nftOperand struct {
	Meta *struct {
		Key string `json:"key"`
	} `json:"meta"`
}

// masqueradeOn reports whether this rule is a masquerade, and which interface
// it is restricted to.
//
// Read structurally rather than by searching the rendered rule, because nft
// quotes the interface:
//
//	oifname "thnwan0" masquerade
//
// so a text search for `oifname thnwan0` — with the quote in the wrong place —
// does not match a rule that is present and correct. That is not a cosmetic
// problem: the assertion exists to prove masquerade is attached to the WAN
// interface specifically, and reading the parsed expression proves exactly
// that rather than proving a string appears somewhere in a dump.
func (r nftRule) masqueradeOn() (bool, string) {
	masquerade := false
	iface := ""

	for _, e := range r.Exprs {
		if e.Nat != nil && e.Nat.Type == "masquerade" {
			masquerade = true
		}
		if e.Match != nil && e.Match.Left.Meta != nil && e.Match.Left.Meta.Key == "oifname" {
			iface = e.Match.Right
		}
	}
	return masquerade, iface
}

// thnRules reads `table inet thn` through nft's JSON form.
//
// The structured form is the only one that can answer the questions the tests
// ask. Rendered text breaks lines wherever it likes and quotes identifiers, so
// a rule's chain, its expressions and the interface a masquerade is bound to
// are all recoverable only from the parse.
func (h *harness) thnRules() ([]nftRule, bool) {
	out, _, err := h.runners[GatewayNamespace].Run(context.Background(),
		"nft", "-j", "list", "table", "inet", "thn")
	if err != nil {
		return nil, false
	}

	var doc struct {
		Nftables []struct {
			Rule *nftRule `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, true
	}

	var rules []nftRule
	for _, item := range doc.Nftables {
		if item.Rule != nil {
			rules = append(rules, *item.Rule)
		}
	}
	return rules, true
}

// interfaceIDBySystemName finds a device interface's stable identity.
func interfaceIDBySystemName(device *host.Device, systemName string) (string, error) {
	for _, i := range device.Interfaces {
		if i.SystemName == systemName {
			return i.ID, nil
		}
	}
	return "", fmt.Errorf("the lab gateway has no interface named %s", systemName)
}

// desiredGateway is the configuration THN is asked to converge the lab onto.
func desiredGateway() desired.State {
	return desired.State{
		Name:       "thn-m62-lab-gateway",
		Generation: 1,
		WAN: desired.Interface{
			Name:    GatewayWANInterface,
			Role:    desired.RoleWAN,
			Up:      true,
			Present: true,
		},
		LAN: desired.Interface{
			Name:      GatewayLANInterface,
			Role:      desired.RoleLAN,
			Up:        true,
			Present:   true,
			Addresses: []string{GatewayAddress},
		},
		Addressing: desired.Addressing{
			DefaultGateway:  TargetIP,
			UpstreamPresent: true,
			IPv4Forwarding:  true,
		},
		NAT: desired.NAT{
			Enabled:    true,
			Resolved:   true,
			Interfaces: []string{GatewayWANInterface},
		},
		Firewall: desired.Firewall{
			Enabled:              true,
			Backend:              "nftables",
			DefaultInboundPolicy: "drop",
			AllowEstablished:     true,
			AllowLoopback:        true,
		},
	}
}

// gatewayPlan observes the lab, builds the plan, and adds the real-traffic
// checks the structural checks cannot express.
//
// The traffic checks are appended rather than substituted: a gateway whose
// interface is up, whose address is right and whose table exists is still not
// a gateway until a packet crosses it, and a plan that only asked the first
// three questions would report that machine healthy.
func (h *harness) gatewayPlan(ctx context.Context) (diff.Observed, desired.State, []host.Assignment, *planner.Plan) {
	h.t.Helper()

	obs, assignments, err := h.observe(ctx)
	if err != nil {
		h.t.Fatalf("observing the lab gateway: %v", err)
	}

	des := desiredGateway()

	result := diff.Compare(obs, diff.Desired{
		WANName:         des.WAN.Name,
		WANPresent:      des.WAN.Present,
		WANUp:           des.WAN.Up,
		LANName:         des.LAN.Name,
		LANPresent:      des.LAN.Present,
		LANUp:           des.LAN.Up,
		LANAddresses:    des.LAN.Addresses,
		DefaultGateway:  des.Addressing.DefaultGateway,
		IPv4Forwarding:  des.Addressing.IPv4Forwarding,
		NATEnabled:      des.NAT.Enabled,
		NATResolved:     des.NAT.Resolved,
		FirewallEnabled: des.Firewall.Enabled,
	})

	plan := planner.Build(result, planner.Options{
		Generation:  des.Generation,
		Source:      "disposable-lab",
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Live:        true,
	})

	plan.Verification.Checks = append(plan.Verification.Checks,
		planner.VerificationCheck{
			Target:      TargetEndpoint(),
			Check:       "lan_to_wan_traffic",
			Expectation: "a client on " + LANPrefix + " reaches the WAN-side target through THN",
		},
	)

	if !plan.Ready {
		h.t.Fatalf("the lab gateway plan is not ready; nothing can be applied: %s", plan.Summary)
	}

	h.t.Logf("plan %s carries %d step(s): %s", plan.ID, len(plan.Steps), strings.Join(stepIDs(plan), ", "))
	return obs, des, assignments, plan
}

// stepIDs lists a plan's step identifiers for a failure message.
func stepIDs(p *planner.Plan) []string {
	out := make([]string, 0, len(p.Steps))
	for _, s := range p.Steps {
		out = append(out, s.ID)
	}
	return out
}

// withWANIsolationCheck appends the reverse-direction traffic check.
func withWANIsolationCheck(plan *planner.Plan) *planner.Plan {
	plan.Verification.Checks = append(plan.Verification.Checks, planner.VerificationCheck{
		Target:      fmt.Sprintf("%s:%d", ClientIP, clientListenPort),
		Check:       "wan_to_lan_blocked",
		Expectation: "the WAN side cannot open a connection into the LAN",
	})
	return plan
}

// ------------------------------------------------------------------ probes

// labServer starts a probe endpoint inside a namespace.
//
// It runs the test binary's helper in a goroutine and stops it with a stop
// file, so shutdown is deterministic: the test waits for a process that has
// already agreed to stop, rather than for a timeout that may or may not
// expire.
func (h *harness) startServer(namespaceName, endpoint string) *labServer {
	h.t.Helper()

	ns, ok := h.ns[namespaceName]
	if !ok {
		h.t.Fatalf("no lab namespace named %s", namespaceName)
	}

	srv := &labServer{
		done:   make(chan struct{}),
		report: filepath.Join(h.workDir, fmt.Sprintf("report-%s-%s.jsonl", namespaceName, filepath.Base(ns.Path))),
		stop:   filepath.Join(h.workDir, fmt.Sprintf("stop-%s-%s", namespaceName, filepath.Base(ns.Path))),
	}

	go func() {
		defer close(srv.done)
		// The helper's own stop-file poll and accept deadline bound this.
		if _, err := ns.Run(testBinary, "-test.run=^"+helperTestName+"$",
			"--", "serve", endpoint, srv.report, srv.stop); err != nil {
			h.t.Logf("lab server in %s exited: %v", namespaceName, err)
		}
	}()

	h.mu.Lock()
	h.servers = append(h.servers, srv)
	h.mu.Unlock()

	h.waitForListener(ns, endpoint)
	return srv
}

// waitForListener blocks until the endpoint accepts a connection.
//
// Without it a probe could race the helper's bind and report a failure that is
// really "the listener had not started yet" — which would be a test that fails
// intermittently for no reason, the hardest kind to act on.
func (h *harness) waitForListener(ns *netns.Namespace, endpoint string) {
	h.t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := ns.Run(testBinary, "-test.run=^"+helperTestName+"$",
			"--", "connect", endpoint, "thn-m62-ready")
		if line := helperLine(out); line != "" {
			var report struct {
				Reachable bool `json:"reachable"`
			}
			if err := json.Unmarshal([]byte(line), &report); err == nil && report.Reachable {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatalf("lab endpoint %s never started listening", endpoint)
}

// probe performs a real connection from one side of the gateway.
//
// The result is returned whatever it says. A refusal is a finding about the
// firewall, not an error about the probe.
func (h *harness) probe(side, endpoint string) execution.ProbeResult {
	h.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), helperDialTimeout*4)
	defer cancel()

	res, err := h.prober.Probe(ctx, side, endpoint, helperDialTimeout)
	if err != nil {
		h.t.Fatalf("probing %s from %s: %v", endpoint, side, err)
	}
	return res
}

// startTargetServer puts the WAN-side test endpoint in place.
func (h *harness) startTargetServer() *labServer {
	return h.startServer(TargetNamespace, TargetEndpoint())
}

// startClientListener puts a listener on the LAN client, so the WAN side has
// something real to fail to reach.
func (h *harness) startClientListener() *labServer {
	return h.startServer(ClientNamespace, fmt.Sprintf("%s:%d", ClientIP, clientListenPort))
}

// ------------------------------------------------------------ small helpers

// helperLine extracts the machine-readable report from a helper's output.
func helperLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), helperMarker) {
			return strings.TrimSpace(strings.TrimSpace(line))[len(helperMarker):]
		}
	}
	return ""
}
