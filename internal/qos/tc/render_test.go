package tc

// Tests for the rendered shaping script.
//
// # Why these assert on option membership rather than on literal strings
//
// The M7.4 versions of these tests asserted strings.Contains(cmd, "uplink
// 22000kbit"), then "target 5ms", "interval 100ms" and "quantum 1514". Every
// one of those tokens looks like a plausible tc option to a reader and to a
// test, and none of them is one CAKE accepts. The tests passed; the kernel
// rejected the command.
//
// So the assertions here are written against OptionCake, transcribed from
// iproute2's cake_parse_opt, plus behavioural properties: which rate, which
// interface, which fairness mode. A test written that way cannot pass by
// asserting something that merely looks right. args_test.go applies the same
// allowlist to the argument vector itself.

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/qos"
)

// The two interfaces a gateway shapes. The WAN egress carries the clients'
// upload; the LAN egress carries their download.
const (
	wanName = "wan0"
	lanName = "lan0"
)

// renderPolicy returns a CAKE policy that renders cleanly.
func renderPolicy() qos.Policy {
	p := qos.Default()
	p.Enabled = true
	p.Interface = wanName
	p.Algorithm = qos.AlgorithmCake
	p.MTU = 1500
	p.Limits = qos.DefaultLimits()
	return p.WithBandwidth(100_000, 20_000)
}

// renderSelection is the selection for a kernel that has CAKE.
func renderSelection() qos.Selection {
	return qos.Selection{Algorithm: qos.AlgorithmCake, Requested: qos.AlgorithmCake, Available: true}
}

// degradedSelection is the selection for a kernel without CAKE.
func degradedSelection() qos.Selection {
	return qos.Selection{
		Algorithm: qos.AlgorithmFqCodel,
		Requested: qos.AlgorithmCake,
		Available: false,
		Degraded:  true,
		Reason:    "cake is not available on this kernel; fell back to fq_codel",
	}
}

// commandLines returns the non-comment, non-blank lines of a script.
func commandLines(script string) []string {
	var out []string
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// commandsFor returns the rendered commands targeting one interface.
func commandsFor(t *testing.T, script, iface string) []string {
	t.Helper()
	prefix := "tc qdisc replace dev " + iface + " root "
	var out []string
	for _, line := range commandLines(script) {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

// soleCommandFor returns the single command targeting one interface, failing
// if there is not exactly one.
func soleCommandFor(t *testing.T, script, iface string) string {
	t.Helper()
	cmds := commandsFor(t, script, iface)
	if len(cmds) != 1 {
		t.Fatalf("expected exactly one command for %s, got %d: %v", iface, len(cmds), cmds)
	}
	return cmds[0]
}

// TestRenderShapesBothDirections is the Section 5 property stated as a test.
//
// A qdisc shapes egress. On a gateway the WAN's egress is the clients' upload
// and the LAN's egress is their download, so a correct script needs two
// disciplines on two interfaces. The M7.4 script had one, on the WAN, which
// could only ever have enforced the upload rate while the download ran
// unshaped — the exact assumption Section 5 of the product spec says not to
// make.
func TestRenderShapesBothDirections(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)

	if cmd := soleCommandFor(t, script, wanName); !strings.Contains(cmd, "root cake") {
		t.Errorf("WAN command = %q; want a cake discipline", cmd)
	}
	if cmd := soleCommandFor(t, script, lanName); !strings.Contains(cmd, "root cake") {
		t.Errorf("LAN command = %q; want a cake discipline", cmd)
	}
}

// TestRenderPutsEachDirectionRateOnItsOwnInterface is the trap a single
// discipline makes impossible to avoid: putting the download rate on the WAN
// would cap the uplink at the downstream rate.
func TestRenderPutsEachDirectionRateOnItsOwnInterface(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)

	wan := soleCommandFor(t, script, wanName)
	lan := soleCommandFor(t, script, lanName)

	if !strings.Contains(wan, "bandwidth 22Mbit") {
		t.Errorf("WAN command = %q; want the upload rate 22Mbit (20000 plus 10%% overhead)", wan)
	}
	if !strings.Contains(lan, "bandwidth 110Mbit") {
		t.Errorf("LAN command = %q; want the download rate 110Mbit (100000 plus 10%% overhead)", lan)
	}
	if strings.Contains(wan, "110Mbit") {
		t.Error("the WAN (upload) discipline carries the download rate")
	}
	if strings.Contains(lan, "22Mbit") {
		t.Error("the LAN (download) discipline carries the upload rate")
	}
}

// TestRenderedCommandsUseOnlyRealTcOptions is the assertion that would have
// caught the M7.4 defect, applied to the whole script.
func TestRenderedCommandsUseOnlyRealTcOptions(t *testing.T) {
	cases := map[string]string{
		"cake":        Render(renderPolicy(), renderSelection(), wanName, lanName),
		"degraded":    Render(renderPolicy(), degradedSelection(), wanName, lanName),
		"wan only":    Render(renderPolicy(), renderSelection(), wanName, ""),
		"no iface":    Render(withoutInterface(), renderSelection(), "", ""),
		"algorithm 0": Render(renderPolicy(), qos.Selection{Algorithm: qos.AlgorithmNone}, wanName, lanName),
	}
	for name, script := range cases {
		for _, cmd := range commandLines(script) {
			assertRealOptions(t, name, cmd)
		}
	}
}

// assertRealOptions checks one command line against the option set for its
// discipline.
func assertRealOptions(t *testing.T, name, cmd string) {
	t.Helper()
	set := OptionCake
	if strings.Contains(cmd, "root fq_codel") {
		set = OptionFqCodel
	}
	fields := strings.Fields(cmd)
	// tc qdisc replace dev <iface> root <algo> [options...]
	if len(fields) < 8 {
		t.Errorf("%s: command is too short to be valid: %q", name, cmd)
		return
	}
	algo := fields[6]
	opts := fields[7:]
	for i := 0; i < len(opts); i++ {
		if !isOption(set, opts[i]) {
			t.Errorf("%s: %q is not an option tc accepts for %q\ncommand: %s",
				name, opts[i], algo, cmd)
			continue
		}
		if valueOptions[opts[i]] || fqCodelValueOptions[opts[i]] {
			i++
		}
	}
}

// TestRenderCakeCarriesTheRate is the central assertion: a CAKE command that
// omits bandwidth attaches a shaper with nothing to shape toward, and it looks
// correct in the generated file.
func TestRenderCakeCarriesTheRate(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)

	for _, iface := range []string{wanName, lanName} {
		cmd := soleCommandFor(t, script, iface)
		if !strings.Contains(cmd, "bandwidth ") {
			t.Errorf("%s command = %q; CAKE has nothing to shape toward without a rate", iface, cmd)
		}
	}
}

// TestRenderCakeAppliesOverhead: the wire rate must exceed the payload rate,
// or the link is permanently under-utilised by about a tenth.
func TestRenderCakeAppliesOverhead(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)

	wan := soleCommandFor(t, script, wanName)
	if strings.Contains(wan, "bandwidth 20Mbit") {
		t.Error("the upload rate is the raw payload rate; overhead was not applied")
	}
	if strings.Contains(wan, "bandwidth 20000") {
		t.Error("a bare number is read by tc as bytes per second")
	}

	// The rate is raised by 10%, so the number in the command will not match
	// the number in the configuration. An unexplained discrepancy reads as a
	// bug, so the script has to account for it.
	if !strings.Contains(script, "10% framing overhead") {
		t.Error("the script must state that the rate includes overhead, or the number looks wrong")
	}
	if !strings.Contains(script, "the configured 100000kbit/s down") {
		t.Error("the script must restate the configured payload rate, so the wire rate reconciles")
	}
}

// TestRenderCakeTunesAqmWithRtt: CAKE exposes one AQM knob, `rtt`, and derives
// target as rtt/20. The M7.4 renderer emitted `interval` and `target` as if
// they were separate inputs; neither is accepted.
func TestRenderCakeTunesAqmWithRtt(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)
	cmd := soleCommandFor(t, script, wanName)

	if !strings.Contains(cmd, "rtt 100ms") {
		t.Errorf("command = %q; want rtt 100ms (CAKE derives target = rtt/20 = 5ms)", cmd)
	}
	for _, rejected := range []string{"target ", "interval ", "quantum ", "uplink "} {
		if strings.Contains(cmd+" ", " "+rejected) {
			t.Errorf("command = %q; contains %q, which tc's CAKE parser rejects", cmd, rejected)
		}
	}
}

// TestRenderCakeEnablesHostFairnessPerDirection: fairness must group by the
// address that varies. Egress sees many source addresses; the downlink's
// egress sees many destination addresses.
func TestRenderCakeEnablesHostFairnessPerDirection(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)

	if cmd := soleCommandFor(t, script, wanName); !strings.Contains(cmd, "dual-srchost") {
		t.Errorf("WAN command = %q; want dual-srchost so one client cannot win with many flows", cmd)
	}
	if cmd := soleCommandFor(t, script, lanName); !strings.Contains(cmd, "dual-dsthost") {
		t.Errorf("LAN command = %q; want dual-dsthost", cmd)
	}
}

// TestRenderCakeLooksThroughNat: THN masquerades everything leaving the WAN,
// so without `nat` CAKE sees a single source address and host-level fairness
// applies to one host — which is the gateway, so it is inert.
func TestRenderCakeLooksThroughNat(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)
	for _, iface := range []string{wanName, lanName} {
		if cmd := soleCommandFor(t, script, iface); !strings.Contains(cmd+" ", " nat ") {
			t.Errorf("%s command = %q; want nat, or host fairness is inert behind THN's masquerade", iface, cmd)
		}
	}
}

// TestRenderCakeKeepsPriorityTins: diffserv4 gives four DSCP-driven priority
// tins. besteffort collapses them to one, which would make "priority" mean
// nothing in the product spec.
func TestRenderCakeKeepsPriorityTins(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)
	cmd := soleCommandFor(t, script, wanName)

	if !strings.Contains(cmd, "diffserv4") {
		t.Errorf("command = %q; want diffserv4 so priority tiers have somewhere to land", cmd)
	}
	if strings.Contains(cmd, "besteffort") {
		t.Errorf("command = %q; besteffort disables priority queuing entirely", cmd)
	}
}

// TestRenderCakeIngressOnlyOnDownlink: `ingress` tunes the AQM for a
// discipline fed by traffic that already crossed the link. Upload egress is
// not.
func TestRenderCakeIngressOnlyOnDownlink(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)

	if cmd := soleCommandFor(t, script, wanName); strings.Contains(cmd+" ", " ingress ") {
		t.Errorf("WAN command = %q; upload egress is not fed by post-link traffic", cmd)
	}
	if cmd := soleCommandFor(t, script, lanName); !strings.Contains(cmd+" ", " ingress ") {
		t.Errorf("LAN command = %q; want ingress on the downlink discipline", cmd)
	}
}

// TestRenderFqCodelHasNoRateParameters: fq_codel cannot enforce a bandwidth,
// and rendering one would misrepresent the fallback as a fulfilment.
func TestRenderFqCodelHasNoRateParameters(t *testing.T) {
	p := renderPolicy()
	p.Algorithm = qos.AlgorithmFqCodel
	p.Limits = qos.FqCodelLimits(1500)

	script := Render(p, qos.Selection{
		Algorithm: qos.AlgorithmFqCodel, Requested: qos.AlgorithmFqCodel, Available: true,
	}, wanName, lanName)

	cmd := soleCommandFor(t, script, wanName)
	if !strings.HasPrefix(cmd, "tc qdisc replace dev "+wanName+" root fq_codel") {
		t.Errorf("command = %q", cmd)
	}
	for _, forbidden := range []string{"bandwidth", "uplink", "maxrate"} {
		if strings.Contains(cmd, forbidden) {
			t.Errorf("command = %q; fq_codel takes no %s parameter", cmd, forbidden)
		}
	}
	if !strings.Contains(cmd, "quantum 1500") {
		t.Errorf("command = %q; the quantum should be the interface MTU", cmd)
	}
}

// TestRenderFqCodelStatesTheLimitation: the whole point of the fallback design
// is that the loss is visible, so the file itself must say what was lost.
func TestRenderFqCodelStatesTheLimitation(t *testing.T) {
	script := Render(renderPolicy(), degradedSelection(), wanName, lanName)

	for _, want := range []string{
		"cannot enforce a bandwidth",
		"NOT applied",
		"DEGRADED",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script does not say %q; the loss must be stated in the file", want)
		}
	}
}

// TestRenderDegradedCarriesTheBanner: a fallback that renders silently is
// worse than one that fails, because the operator believes the problem is
// solved.
func TestRenderDegradedCarriesTheBanner(t *testing.T) {
	script := Render(renderPolicy(), degradedSelection(), wanName, lanName)

	if !strings.Contains(script, "DEGRADED") {
		t.Error("a degraded render must be banner-marked")
	}
	if !strings.Contains(script, "modprobe sch_cake") {
		t.Error("the banner must tell the operator how to get the intended behaviour")
	}
	if !strings.Contains(script, "will not reduce bufferbloat") {
		t.Error("the banner must say what the fallback does not achieve")
	}
}

// TestRenderNotDegradedOmitsTheBanner: marking a normal render as degraded
// trains operators to ignore the warning, so the absence case matters too.
func TestRenderNotDegradedOmitsTheBanner(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, lanName)
	if strings.Contains(script, "DEGRADED") {
		t.Error("a non-degraded render must not carry the degradation banner")
	}
}

// TestRenderUsesTheSelectedAlgorithmNotTheRequestedOne: the render must
// reflect what will actually be applied, or an operator reviewing the file
// would be reviewing the wrong thing.
func TestRenderUsesTheSelectedAlgorithmNotTheRequestedOne(t *testing.T) {
	script := Render(renderPolicy(), degradedSelection(), wanName, lanName)

	cmds := commandLines(script)
	if len(cmds) == 0 {
		t.Fatal("the degraded render produced no commands at all")
	}
	for _, cmd := range cmds {
		if strings.Contains(cmd, "cake") {
			t.Errorf("command = %q; the selection was fq_codel", cmd)
		}
	}
}

// TestRenderWithoutBothInterfacesEmitsNoCommand: a policy that cannot resolve
// both links cannot produce a correct pair of disciplines, so it produces
// none rather than half of one.
func TestRenderWithoutBothInterfacesEmitsNoCommand(t *testing.T) {
	cases := map[string]string{
		"neither": Render(renderPolicy(), renderSelection(), "", ""),
		"no lan":  Render(renderPolicy(), renderSelection(), wanName, ""),
		"no wan":  Render(renderPolicy(), renderSelection(), "", lanName),
	}
	for name, script := range cases {
		if cmds := commandLines(script); len(cmds) != 0 {
			t.Errorf("%s: expected no commands without both interfaces, got %v", name, cmds)
		}
	}
}

// TestRenderExplainsTheMissingInterface: silence is not an explanation.
func TestRenderExplainsTheMissingInterface(t *testing.T) {
	script := Render(renderPolicy(), renderSelection(), wanName, "")

	if !strings.Contains(script, "WAN and a LAN interface are required") {
		t.Errorf("the script must say why there is no command:\n%s", script)
	}
	if !strings.Contains(script, "(unresolved)") {
		t.Error("the script must name which role is unresolved")
	}
}

// TestRenderWithAlgorithmNoneEmitsNoCommand.
func TestRenderWithAlgorithmNoneEmitsNoCommand(t *testing.T) {
	script := Render(renderPolicy(), qos.Selection{
		Algorithm: qos.AlgorithmNone, Requested: qos.AlgorithmNone, Available: true,
	}, wanName, lanName)

	if cmds := commandLines(script); len(cmds) != 0 {
		t.Errorf("expected no commands for algorithm none, got %v", cmds)
	}
}

// TestRenderIsValidShell: the output is offered as a script, so a malformed
// command line would break it at the worst moment.
//
// Only command lines are checked. Comments are prose and legitimately contain
// apostrophes; counting quotes across the whole file would flag "device's
// queue" as an unbalanced quote, which it is not.
func TestRenderIsValidShell(t *testing.T) {
	cases := map[string]string{
		"cake":        Render(renderPolicy(), renderSelection(), wanName, lanName),
		"degraded":    Render(renderPolicy(), degradedSelection(), wanName, lanName),
		"no iface":    Render(withoutInterface(), renderSelection(), "", ""),
		"no lan":      Render(renderPolicy(), renderSelection(), wanName, ""),
		"algorithm 0": Render(renderPolicy(), qos.Selection{Algorithm: qos.AlgorithmNone}, wanName, lanName),
	}
	for name, script := range cases {
		for _, line := range strings.Split(script, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Count(trimmed, "'")%2 != 0 {
				t.Errorf("%s: unbalanced single quote in %q", name, trimmed)
			}
			if strings.Count(trimmed, "\"")%2 != 0 {
				t.Errorf("%s: unbalanced double quote in %q", name, trimmed)
			}
			if !strings.HasPrefix(trimmed, "tc qdisc replace dev ") {
				t.Errorf("%s: unexpected command line %q", name, trimmed)
			}
		}
	}
}

// withoutInterface returns a policy with nowhere to apply.
func withoutInterface() qos.Policy {
	p := renderPolicy()
	p.Interface = ""
	return p
}
