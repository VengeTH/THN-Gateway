package tc

import (
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/qos"
)

// renderPolicy returns a CAKE policy that renders cleanly.
func renderPolicy() qos.Policy {
	p := qos.Default()
	p.Enabled = true
	p.Interface = "eth0"
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

// soleCommand returns the single command a script contains, failing if there
// is not exactly one. A render that emits two commands would apply one and
// leave the other, which is worse than emitting neither.
func soleCommand(t *testing.T, script string) string {
	t.Helper()

	cmds := commandLines(script)
	if len(cmds) != 1 {
		t.Fatalf("expected exactly one command, got %d: %v", len(cmds), cmds)
	}
	return cmds[0]
}

// TestRenderCakeCarriesTheRate is the central assertion: a CAKE command that
// omits bandwidth would attach a shaper with nothing to shape toward, and it
// would look correct in the generated file.
func TestRenderCakeCarriesTheRate(t *testing.T) {
	cmd := soleCommand(t, Render(renderPolicy(), renderSelection()))

	if !strings.HasPrefix(cmd, "tc qdisc replace dev eth0 root cake") {
		t.Errorf("command = %q; it must target the configured interface with cake", cmd)
	}
	if !strings.Contains(cmd, "bandwidth 110000kbit") {
		t.Errorf("command = %q; want bandwidth 110000kbit (100000 plus 10%% overhead)", cmd)
	}
	if !strings.Contains(cmd, "uplink 22000kbit") {
		t.Errorf("command = %q; want uplink 22000kbit (20000 plus 10%% overhead)", cmd)
	}
}

// TestRenderCakeAppliesOverhead: the wire rate must exceed the payload rate,
// or the link is permanently under-utilised by about a tenth.
func TestRenderCakeAppliesOverhead(t *testing.T) {
	cmd := soleCommand(t, Render(renderPolicy(), renderSelection()))

	if strings.Contains(cmd, "bandwidth 100000kbit") {
		t.Error("the rendered bandwidth is the raw payload rate; overhead was not applied")
	}
	if !strings.Contains(cmd, "10% framing overhead") {
		t.Error("the script must state that the rate includes overhead, or the number looks wrong")
	}
}

// TestRenderCakeCarriesTheQueueLimits: without target and interval CAKE uses
// its own defaults, which are usually right, but an operator who tuned them
// must see them honoured.
func TestRenderCakeCarriesTheQueueLimits(t *testing.T) {
	cmd := soleCommand(t, Render(renderPolicy(), renderSelection()))

	for _, want := range []string{"target 5ms", "interval 100ms", "quantum 1514"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command = %q; missing %q", cmd, want)
		}
	}
}

// TestRenderCakeUsesFlowScheduling: besteffort and diffserv4 are what separate
// CAKE's use here from a plain rate limiter, and without them a bulk transfer
// starves interactive traffic.
func TestRenderCakeUsesFlowScheduling(t *testing.T) {
	cmd := soleCommand(t, Render(renderPolicy(), renderSelection()))

	if !strings.Contains(cmd, "besteffort") {
		t.Errorf("command = %q; missing besteffort", cmd)
	}
	if !strings.Contains(cmd, "diffserv4") {
		t.Errorf("command = %q; missing diffserv4", cmd)
	}
}

// TestRenderFqCodelHasNoRateParameters: fq_codel cannot enforce a bandwidth,
// and rendering one would produce a command tc rejects.
func TestRenderFqCodelHasNoRateParameters(t *testing.T) {
	p := renderPolicy()
	p.Algorithm = qos.AlgorithmFqCodel
	p.Limits = qos.FqCodelLimits(1500)

	cmd := soleCommand(t, Render(p, qos.Selection{
		Algorithm: qos.AlgorithmFqCodel, Requested: qos.AlgorithmFqCodel, Available: true,
	}))

	if !strings.HasPrefix(cmd, "tc qdisc replace dev eth0 root fq_codel") {
		t.Errorf("command = %q", cmd)
	}
	for _, forbidden := range []string{"bandwidth", "uplink"} {
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
	script := Render(renderPolicy(), degradedSelection())

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
	script := Render(renderPolicy(), degradedSelection())

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
	script := Render(renderPolicy(), renderSelection())

	if strings.Contains(script, "DEGRADED") {
		t.Error("a non-degraded render must not carry the degradation banner")
	}
}

// TestRenderUsesTheSelectedAlgorithmNotTheRequestedOne: the render must
// reflect what will actually be applied, or an operator reviewing the file
// would be reviewing the wrong thing.
func TestRenderUsesTheSelectedAlgorithmNotTheRequestedOne(t *testing.T) {
	script := Render(renderPolicy(), degradedSelection())

	cmds := commandLines(script)
	if len(cmds) != 1 {
		t.Fatalf("expected one command, got %v", cmds)
	}
	if strings.Contains(cmds[0], "cake") {
		t.Errorf("command = %q; the selection was fq_codel", cmds[0])
	}
}

// TestRenderWithoutAnInterfaceEmitsNoCommand: a policy with nowhere to apply
// must not produce a command aimed at a guessed device.
func TestRenderWithoutAnInterfaceEmitsNoCommand(t *testing.T) {
	p := renderPolicy()
	p.Interface = ""

	script := Render(p, renderSelection())

	if cmds := commandLines(script); len(cmds) != 0 {
		t.Errorf("expected no commands for an unset interface, got %v", cmds)
	}
	if !strings.Contains(script, "no interface is configured") {
		t.Error("the script must say why there is no command")
	}
}

// TestRenderWithAlgorithmNoneEmitsNoCommand.
func TestRenderWithAlgorithmNoneEmitsNoCommand(t *testing.T) {
	script := Render(renderPolicy(), qos.Selection{
		Algorithm: qos.AlgorithmNone, Requested: qos.AlgorithmNone, Available: true,
	})

	if cmds := commandLines(script); len(cmds) != 0 {
		t.Errorf("expected no commands for algorithm none, got %v", cmds)
	}
}

// TestRenderIsValidShell: the output is offered as a script, so an unbalanced
// quote or a stray backslash would break it at the worst moment.
func TestRenderIsValidShell(t *testing.T) {
	for name, script := range map[string]string{
		"cake":     Render(renderPolicy(), renderSelection()),
		"degraded": Render(renderPolicy(), degradedSelection()),
		"noiface":  Render(func() qos.Policy { p := renderPolicy(); p.Interface = ""; return p }(), renderSelection()),
	} {
		if strings.Count(script, "'")%2 != 0 {
			t.Errorf("%s: odd number of single quotes", name)
		}
		if strings.Count(script, "\"")%2 != 0 {
			t.Errorf("%s: odd number of double quotes", name)
		}
		// Every non-comment line must be a complete shell statement.
		for _, line := range strings.Split(script, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !strings.HasPrefix(trimmed, "tc ") {
				t.Errorf("%s: unexpected command line %q", name, trimmed)
			}
		}
	}
}

// TestRenderStartsWithAShebang: the file is meant to be run with sh, and a
// file without one will be executed by whatever the operator's shell is.
func TestRenderStartsWithAShebang(t *testing.T) {
	if !strings.HasPrefix(Render(renderPolicy(), renderSelection()), "#!/bin/sh") {
		t.Error("the script must start with a shebang")
	}
}

// TestRenderIncludesTeardown: leaving a shaper attached after testing it is
// how an experiment becomes an outage.
func TestRenderIncludesTeardown(t *testing.T) {
	script := Render(renderPolicy(), renderSelection())

	if !strings.Contains(script, "tc qdisc replace dev eth0 root pfifo_fast") {
		t.Error("the script must include the removal command, commented out")
	}
}

// TestRenderWarnsAboutRemoteApplication: the project's whole premise is that
// it is run against an unattended device, and applying from a remote session
// is the risky case.
func TestRenderWarnsAboutRemoteApplication(t *testing.T) {
	script := Render(renderPolicy(), renderSelection())

	for _, want := range []string{
		"Changes host networking",
		"Capture the current state first",
		"Nothing has been applied",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script is missing the warning %q", want)
		}
	}
}

// TestRenderNotesAMissingRate: an invalid policy rendered with --no-validate
// must still say that the command it produced is meaningless.
func TestRenderNotesAMissingRate(t *testing.T) {
	p := renderPolicy()
	p.Bandwidth = qos.Bandwidth{OverheadPercent: 10}

	script := Render(p, renderSelection())

	if !strings.Contains(script, "no bandwidth is configured") {
		t.Error("a rate-less render must say the result is meaningless")
	}
	if strings.Contains(commandLines(script)[0], "bandwidth") {
		t.Error("a rate-less policy must not emit a bandwidth parameter")
	}
}

// TestRenderOmitsZeroUplink: leaving one direction unshaped is legitimate, so
// the parameter is omitted rather than emitted as zero, which tc would reject.
func TestRenderOmitsZeroUplink(t *testing.T) {
	p := renderPolicy().WithBandwidth(100_000, 0)

	cmd := soleCommand(t, Render(p, renderSelection()))

	if !strings.Contains(cmd, "bandwidth 110000kbit") {
		t.Errorf("command = %q; the configured direction must still be shaped", cmd)
	}
	if strings.Contains(cmd, "uplink") {
		t.Errorf("command = %q; an unset direction must be omitted, not sent as 0", cmd)
	}
}

// TestRenderIsDeterministic: two renders of one policy must be byte-identical,
// or a diff of generated files shows noise.
func TestRenderIsDeterministic(t *testing.T) {
	p := renderPolicy()

	first := Render(p, renderSelection())
	for i := 0; i < 20; i++ {
		if got := Render(p, renderSelection()); got != first {
			t.Fatal("render is not deterministic")
		}
	}
}

// TestRenderDoesNotMutateThePolicy: Render takes a policy by value but the
// caller must not see its algorithm changed as a side effect of a degraded
// render.
func TestRenderDoesNotMutateThePolicy(t *testing.T) {
	p := renderPolicy()

	_ = Render(p, degradedSelection())

	if p.Algorithm != qos.AlgorithmCake {
		t.Errorf("policy algorithm = %q after render, want cake; Render mutated the caller's copy",
			p.Algorithm)
	}
}

// TestRenderEveryAlgorithmProducesSomething is a smoke test over the whole
// switch, so a new algorithm cannot be added without the render following.
func TestRenderEveryAlgorithmProducesSomething(t *testing.T) {
	selections := []qos.Selection{
		{Algorithm: qos.AlgorithmCake, Requested: qos.AlgorithmCake, Available: true},
		{Algorithm: qos.AlgorithmFqCodel, Requested: qos.AlgorithmFqCodel, Available: true},
		{Algorithm: qos.AlgorithmFqCodel, Requested: qos.AlgorithmCake, Degraded: true},
		{Algorithm: qos.AlgorithmNone, Requested: qos.AlgorithmCake},
	}

	for _, sel := range selections {
		script := Render(renderPolicy(), sel)
		if !strings.HasPrefix(script, "#!/bin/sh") {
			t.Errorf("selection %+v produced no script", sel)
		}
		if !strings.Contains(script, "# --- apply") {
			t.Errorf("selection %+v produced no apply section", sel)
		}
	}
}
