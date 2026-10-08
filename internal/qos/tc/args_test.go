package tc

// Tests for the shared argument builder.
//
// # Why this file is mostly allowlist assertions
//
// The defect this file exists to prevent is a command that tc rejects. That
// failure mode is invisible in a text-diff review — `uplink 22000kbit` looks
// like a rate, and so does `bandwidth 100000kbit upload 10000kbit`. Only the
// kernel's option table can tell them apart from something real.
//
// So rather than asserting on expected strings (which is how M7.4's renderer
// came to be wrong in the first place: the test asserted `target 5ms` and the
// kernel had no such option), these tests assert membership in OptionCake,
// which is transcribed from iproute2's cake_parse_opt. A token that is not in
// that set fails here whether or not it looks plausible.

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/qos"
)

// cakePolicy returns a policy with both directions configured.
func cakePolicy() qos.Policy {
	p := qos.Default()
	p.Enabled = true
	p.Interface = "eth0"
	p.Algorithm = qos.AlgorithmCake
	p.MTU = 1500
	p.Limits = qos.DefaultLimits()
	return p.WithBandwidth(100_000, 20_000)
}

// TestCakeArgsUseOnlyRealTcOptions is the load-bearing test. Every option
// token emitted must be one tc's CAKE parser accepts.
func TestCakeArgsUseOnlyRealTcOptions(t *testing.T) {
	for _, dir := range []Direction{DirectionUpload, DirectionDownload} {
		args, err := CakeArgs(cakePolicy(), dir, 1500)
		if err != nil {
			t.Fatalf("CakeArgs(%s): %v", dir, err)
		}

		for i := 0; i < len(args); i++ {
			tok := args[i]
			if !isOption(OptionCake, tok) {
				t.Errorf("CakeArgs(%s) emitted %q, which tc's CAKE parser does not accept.\n"+
					"args: %s", dir, tok, Join(args))
				continue
			}
			// Skip the option's value so a rate or a duration is not itself
			// checked against the option names.
			if cakeOptionTakesValue(tok) && i+1 < len(args) {
				i++
			}
		}
	}
}

// TestCakeArgsNeverEmitRemovedOptions pins the four tokens M7.4 emitted and
// modern tc rejects.
//
// Each has a specific reason for being gone, so each is called out rather
// than lumped together: an option removed from CAKE is not the same as an
// option that never existed, and the difference decides whether a kernel
// errors out or silently ignores it.
func TestCakeArgsNeverEmitRemovedOptions(t *testing.T) {
	removed := map[string]string{
		"uplink":   "removed from CAKE; upload is shaped by the LAN egress discipline, not a second rate on this one",
		"target":   "not settable; CAKE derives target as rtt/20",
		"interval": "this is rtt under its old name; settable only as `rtt`",
		"quantum":  "derived per tin from the MTU and reported in tc -s qdisc show; not an input",
		"upload":   "never a CAKE option at all; the direction does not exist on one discipline",
		"flows":    "a flow-isolation MODE keyword here, not a count; passing a count is a different command",
	}

	for _, dir := range []Direction{DirectionUpload, DirectionDownload} {
		args, err := CakeArgs(cakePolicy(), dir, 1500)
		if err != nil {
			t.Fatalf("CakeArgs(%s): %v", dir, err)
		}
		line := " " + Join(args) + " "

		for opt, why := range removed {
			// flows is legitimate as the isolation MODE, so it only counts as
			// a violation when it appears as `flows <number>`.
			if opt == "flows" && !strings.Contains(line, " flows ") {
				continue
			}
			if strings.Contains(line, " "+opt+" ") {
				t.Errorf("CakeArgs(%s) emitted %q: %s\nargs: %s", dir, opt, why, Join(args))
			}
		}
	}
}

// TestCakeArgsCarryTheWireRate checks the rate actually reaches CAKE.
//
// The number must be the wire rate, not the payload rate: shaping at exactly
// the provisioned payload figure leaves the link about a tenth under-utilised,
// which presents as "the shaping is broken" rather than as an off-by-ten-percent.
func TestCakeArgsCarryTheWireRate(t *testing.T) {
	p := cakePolicy() // 100000 down / 20000 up, overhead 10%

	up, err := CakeArgs(p, DirectionUpload, p.MTU)
	if err != nil {
		t.Fatalf("CakeArgs(upload): %v", err)
	}
	if !containsPair(up, "bandwidth", "22Mbit") {
		t.Errorf("upload args = %q; want bandwidth 22Mbit (20000 kbit + 10%% overhead)", Join(up))
	}

	down, err := CakeArgs(p, DirectionDownload, p.MTU)
	if err != nil {
		t.Fatalf("CakeArgs(download): %v", err)
	}
	if !containsPair(down, "bandwidth", "110Mbit") {
		t.Errorf("download args = %q; want bandwidth 110Mbit (100000 kbit + 10%% overhead)", Join(down))
	}
}

// TestCakeArgsUseSuffixedRates guards the unit trap.
//
// A bare number after `bandwidth` is BYTES PER SECOND in tc. "bandwidth 110000"
// is not 110 Mbit/s — it is 110 kbyte/s, a factor of eight low and wrong in a
// way that still produces a working shaper.
func TestCakeArgsUseSuffixedRates(t *testing.T) {
	for _, dir := range []Direction{DirectionUpload, DirectionDownload} {
		args, err := CakeArgs(cakePolicy(), dir, 1500)
		if err != nil {
			t.Fatalf("CakeArgs(%s): %v", dir, err)
		}
		for i, tok := range args {
			if tok != "bandwidth" {
				continue
			}
			if i+1 >= len(args) {
				t.Fatalf("bandwidth has no value: %s", Join(args))
			}
			v := args[i+1]
			if !strings.HasSuffix(v, "bit") {
				t.Errorf("rate %q has no unit suffix; tc reads a bare number as bytes/s", v)
			}
			return
		}
		t.Fatalf("no bandwidth option in %s", Join(args))
	}
}

// TestCakeArgsDirectionSelectsTheRightRate is the Section 5 trap stated as a
// test: the two disciplines must not be interchangeable.
//
// Putting the download rate on the upload direction would cap the uplink at
// the downstream rate — a gateway that works perfectly in testing and is
// unusable for anyone who uploads.
func TestCakeArgsDirectionSelectsTheRightRate(t *testing.T) {
	p := cakePolicy()

	up, _ := CakeArgs(p, DirectionUpload, p.MTU)
	down, _ := CakeArgs(p, DirectionDownload, p.MTU)

	if containsPair(up, "bandwidth", "110Mbit") {
		t.Error("the upload discipline was given the DOWNLOAD rate")
	}
	if containsPair(down, "bandwidth", "22Mbit") {
		t.Error("the download discipline was given the UPLOAD rate")
	}
}

// TestCakeArgsHostFairnessFollowsDirection.
//
// The isolation mode must match which end of the connection varies. Upload
// egress has many distinct source addresses; download egress has many distinct
// destination addresses. Getting it backwards leaves per-flow fairness, so a
// single client with many flows wins — the exact failure Section 12 names.
func TestCakeArgsHostFairnessFollowsDirection(t *testing.T) {
	p := cakePolicy()

	up, _ := CakeArgs(p, DirectionUpload, p.MTU)
	if !containsOpt(up, "dual-srchost") {
		t.Errorf("upload args = %q; want dual-srchost so fairness groups by source host", Join(up))
	}
	if containsOpt(up, "dual-dsthost") {
		t.Errorf("upload args = %q; dual-dsthost groups by destination, which all share one on egress", Join(up))
	}

	down, _ := CakeArgs(p, DirectionDownload, p.MTU)
	if !containsOpt(down, "dual-dsthost") {
		t.Errorf("download args = %q; want dual-dsthost so fairness groups by destination host", Join(down))
	}
}

// TestCakeArgsNatIsAlwaysPresent guards the interaction between THN's NAT and
// CAKE's host fairness.
//
// THN masquerades everything leaving the WAN. Without `nat`, CAKE sees a single
// source address on egress and its host-level fairness applies to one host —
// which is the gateway, so it is inert. The option is not a tuning knob; with
// NAT on and `nat` off, the fairness the spec asks for does not happen.
func TestCakeArgsNatIsAlwaysPresent(t *testing.T) {
	for _, dir := range []Direction{DirectionUpload, DirectionDownload} {
		args, err := CakeArgs(cakePolicy(), dir, 1500)
		if err != nil {
			t.Fatalf("CakeArgs(%s): %v", dir, err)
		}
		if !containsOpt(args, "nat") {
			t.Errorf("CakeArgs(%s) = %q; want nat, or host fairness is inert behind THN's masquerade", dir, Join(args))
		}
	}
}

// TestCakeArgsIngressOnlyOnDownload: `ingress` changes the AQM to account for
// packets that already crossed the link. Upload leaves the box at this
// discipline, so marking it ingress would tune it for traffic it never sees.
func TestCakeArgsIngressOnlyOnDownload(t *testing.T) {
	p := cakePolicy()

	up, _ := CakeArgs(p, DirectionUpload, p.MTU)
	if containsOpt(up, "ingress") {
		t.Errorf("upload args = %q; upload egress is not fed by traffic that already crossed the link", Join(up))
	}

	down, _ := CakeArgs(p, DirectionDownload, p.MTU)
	if !containsOpt(down, "ingress") {
		t.Errorf("download args = %q; want ingress for the downlink discipline", Join(down))
	}
}

// TestCakeArgsMapDefaultsToRtt100ms documents the target/interval -> rtt
// mapping rather than leaving it implicit.
//
// The default Limits (target 5ms, interval 100ms) correspond exactly to
// rtt 100ms, because CAKE sets target = rtt/20. So the translation preserves
// the operator's intent rather than approximating it, and this test fails if
// either default moves.
func TestCakeArgsMapDefaultsToRtt100ms(t *testing.T) {
	if got := qos.DefaultLimits(); got.TargetMS != 5 || got.IntervalMS != 100 {
		t.Fatalf("qos.DefaultLimits() = %+v; the rtt mapping below assumes 5ms/100ms", got)
	}

	args, err := CakeArgs(cakePolicy(), DirectionUpload, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPair(args, "rtt", "100ms") {
		t.Errorf("args = %q; want rtt 100ms (CAKE derives target = rtt/20 = 5ms)", Join(args))
	}
}

// TestCakeArgsRefuseUnshapedPolicies: a discipline with no rate is worse than
// none, because it looks like shaping is active.
//
// This is the shape M7.4's operation compiler produced — `tc qdisc replace
// dev X root cake` with the rates silently dropped — so it gets a test.
func TestCakeArgsRefuseUnshapedPolicies(t *testing.T) {
	p := qos.Default()
	p.Enabled = true
	p.Interface = "eth0"
	p.Algorithm = qos.AlgorithmCake

	if _, err := CakeArgs(p, DirectionUpload, 1500); err == nil {
		t.Error("a policy with no upload rate must not produce a CAKE command")
	}
	if _, err := CakeArgs(p, DirectionDownload, 1500); err == nil {
		t.Error("a policy with no download rate must not produce a CAKE command")
	}
}

// TestCakeArgsRefuseMissingInterface: no interface means nowhere to attach.
func TestCakeArgsRefuseMissingInterface(t *testing.T) {
	p := cakePolicy()
	p.Interface = ""
	if _, err := CakeArgs(p, DirectionUpload, 1500); err == nil {
		t.Error("CAKE args were built with no interface to attach to")
	}
}

// TestQDiscReplaceArgsRefuseUnshapedDiscipline guards the second door to the
// same bug.
func TestQDiscReplaceArgsRefuseUnshapedDiscipline(t *testing.T) {
	if _, err := QDiscReplaceArgs("eth0", "cake"); err == nil {
		t.Error("an optionless cake replace must be refused; it would install an unshaped discipline")
	}
	if _, err := QDiscReplaceArgs("eth0", "htb"); err == nil {
		t.Error("an unknown algorithm must be refused")
	}
	if _, err := QDiscReplaceArgs("", "cake", "bandwidth", "1Mbit"); err == nil {
		t.Error("an empty interface must be refused")
	}
}

// TestQDiscReplaceArgsAreWellFormed pins the grammar, since the drivers exec
// this vector directly.
func TestQDiscReplaceArgsAreWellFormed(t *testing.T) {
	args, err := QDiscReplaceArgs("eth0", "cake", "bandwidth", "100Mbit")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"qdisc", "replace", "dev", "eth0", "root", "cake", "bandwidth", "100Mbit"}
	if len(args) != len(want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args = %v, want %v", args, want)
		}
	}
}

// TestFqCodelArgsUseOnlyRealTcOptions: the same allowlist discipline for the
// fallback. fq_codel's option set genuinely differs from CAKE's.
func TestFqCodelArgsUseOnlyRealTcOptions(t *testing.T) {
	args, err := FqCodelArgs(cakePolicy(), 1500)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if !isOption(OptionFqCodel, tok) {
			t.Errorf("fq_codel args emitted %q, which is in neither option set. args: %s", tok, Join(args))
			continue
		}
		if fqCodelValueOptions[tok] && i+1 < len(args) {
			i++
		}
	}
	if !containsPair(args, "quantum", "1500") {
		t.Errorf("args = %q; want quantum matching the MTU", Join(args))
	}
}

// TestFqCodelArgsHaveNoRate: fq_codel cannot enforce a bandwidth, and a
// command that appears to would misrepresent what the fallback does.
func TestFqCodelArgsHaveNoRate(t *testing.T) {
	args, err := FqCodelArgs(cakePolicy(), 1500)
	if err != nil {
		t.Fatal(err)
	}
	if containsOpt(args, "bandwidth") || containsOpt(args, "maxrate") {
		t.Errorf("fq_codel args = %q; it has no rate option and must not be given one", Join(args))
	}
}

// TestDirectionInterfaceFor pins which interface each discipline belongs on.
func TestDirectionInterfaceFor(t *testing.T) {
	if got, err := DirectionUpload.InterfaceFor("wan0", "lan0"); err != nil || got != "wan0" {
		t.Errorf("upload interface = %q, %v; want wan0", got, err)
	}
	if got, err := DirectionDownload.InterfaceFor("wan0", "lan0"); err != nil || got != "lan0" {
		t.Errorf("download interface = %q, %v; want lan0", got, err)
	}
	if _, err := DirectionUpload.InterfaceFor("", "lan0"); err == nil {
		t.Error("upload shaping with no WAN must be refused, not pointed at the LAN")
	}
	if _, err := DirectionDownload.InterfaceFor("wan0", ""); err == nil {
		t.Error("download shaping with no LAN must be refused, not pointed at the WAN")
	}
	if _, err := Direction("sideways").InterfaceFor("wan0", "lan0"); err == nil {
		t.Error("an unknown direction must be refused")
	}
}

// isOption reports membership in an option set.
func isOption(set []string, tok string) bool {
	for _, o := range set {
		if o == tok {
			return true
		}
	}
	return false
}

// valueOptions are the CAKE options that consume the following token.
//
// Transcribed from cake_parse_opt: an option whose handler calls NEXT_ARG().
// The keyword-form options (diffserv4, nat, dual-srchost, …) take none.
var valueOptions = map[string]bool{
	"bandwidth": true,
	"rtt":       true,
	"memlimit":  true,
	"fwmark":    true,
	"overhead":  true,
	"mpu":       true,
}

// cakeOptionTakesValue reports whether an option consumes the next token.
func cakeOptionTakesValue(opt string) bool { return valueOptions[opt] }

// fqCodelValueOptions are the fq_codel options that consume the next token.
//
// Transcribed from q_fq_codel.c's parser. Kept separate from
// valueOptions because fq_codel's grammar genuinely differs: it takes
// target, interval and quantum, and has no bandwidth.
var fqCodelValueOptions = map[string]bool{
	"limit":          true,
	"flows":          true,
	"quantum":        true,
	"target":         true,
	"interval":       true,
	"memory_limit":   true,
	"maxrate":        true,
	"ce_threshold":   true,
	"ecn":            true,
	"ecn_cap":        true,
	"ecn_proportion": true,
}

// containsOpt reports whether a bare option token is present.
func containsOpt(args []string, tok string) bool {
	return isOption(args, tok)
}

// containsPair reports whether token tok is immediately followed by value.
func containsPair(args []string, tok, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == tok && args[i+1] == value {
			return true
		}
	}
	return false
}
