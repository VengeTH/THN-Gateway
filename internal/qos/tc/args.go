package tc

// Verified tc argument construction.
//
// # Why this file exists
//
// M7.4 shipped two independent builders for the same command:
//
//	internal/qos/tc/render.go      the review script `thn qos render` prints
//	internal/execution/*_driver.go the arguments the production driver runs
//
// They disagreed, and both were wrong. The driver emitted `bandwidth <d>kbit
// upload <u>kbit`; CAKE has no `upload` option. The renderer emitted `uplink`,
// `target`, `interval` and `quantum`; CAKE has none of those either. tc
// rejects an unknown option with `What is "X"?` and a non-zero exit, so a
// successful tc call was the exception rather than the rule.
//
// Two builders for one command is the defect, not the duplication. So this
// file is the single place an argument vector is built, and both the renderer
// and the drivers call it. A future option change touches one function and
// cannot drift.
//
// # Where the accepted option set came from
//
// Not from memory, and not from the man page alone. It was read out of
// iproute2's tc/q_cake.c, the function cake_parse_opt, which is the code that
// decides what tc accepts, cross-checked against tc-cake(8). The full set is
// recorded in OptionCake so a reviewer can check a change against the source
// rather than against a comment.
//
// CAKE's grammar as of iproute2 7.x / kernel sch_cake v5:
//
//	bandwidth RATE | unlimited | autorate-ingress
//	rtt TIME | datacentre|lan|metro|regional|internet|oceanic|satellite|...
//	besteffort | diffserv8 | diffserv4 | diffserv3 | precedence
//	flowblind|srchost|dsthost|hosts|flows|dual-srchost|dual-dsthost
//	         |triple-isolate
//	nat | nonat
//	wash | nowash
//	split-gso | no-split-gso
//	no-ack-filter | ack-filter | ack-filter-aggressive
//	memlimit LIMIT
//	fwmark MASK
//	ptm | atm | noatm
//	raw | conservative | ethernet | ether-vlan | docsis | overhead N | mpu N
//	ingress | egress
//
// What is NOT there, and what M7.4 used to emit:
//
//	uplink     removed from CAKE. Upload direction is handled by shaping the
//	           egress of the LAN toward each client, not by a second rate on
//	           the WAN discipline. See DirectionNote.
//	target     derived: rtt/20, and not settable
//	interval   this IS rtt under its old name; settable only as `rtt`
//	quantum    reported in `tc -s qdisc show` per tin; derived, not settable
//
// # DirectionNote, and why upload is not on this qdisc
//
// A root qdisc shapes EGRESS. On a gateway the WAN's egress is the clients'
// upload, and the LAN's egress is the clients' download. So:
//
//	WAN  root cake bandwidth <upload>          shapes upload
//	LAN  root cake bandwidth <download>        shapes download
//
// A single root qdisc on the WAN therefore shapes upload, and cannot shape
// download — the download path enters the WAN and never egresses it. This is
// the trap Section 5 of the product spec calls out, and it is why the
// existing code's habit of putting both rates on one discipline cannot be
// repaired by renaming a keyword. It needs two disciplines on two interfaces,
// which is Phase 2. Until then this file builds ONE discipline for ONE
// direction, and takes that direction as an explicit parameter rather than
// guessing it from which rate is larger.
//
// # No overflow, no zero, no empty
//
// Every builder here is total: any policy that cannot produce a valid
// argument vector returns an error rather than a partial command. A partially
// built tc line is worse than none, because it is a line that looks applied.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/qos"
)

// Direction is the traffic a discipline shapes.
//
// Egress, always: a qdisc shapes packets leaving the device it is attached to.
// The two values name which interface the discipline belongs on, not which
// way the packets move.
type Direction string

const (
	// DirectionUpload shapes the WAN's egress: LAN clients sending to the
	// internet. Attach to the WAN interface.
	DirectionUpload Direction = "upload"

	// DirectionDownload shapes the LAN's egress: the internet sending to LAN
	// clients. Attach to the LAN interface.
	DirectionDownload Direction = "download"
)

// String renders the direction.
func (d Direction) String() string { return string(d) }

// bandwidthDirection maps a shaping direction onto qos.Direction.
//
// The two vocabularies exist because they answer different questions — one is
// "which link is the bottleneck", the other is "which number in the document".
// Converting in one place keeps the confusion from spreading into the
// arithmetic, where an unconverted value would silently shape the wrong rate.
func (d Direction) bandwidthDirection() (qos.Direction, error) {
	switch d {
	case DirectionDownload:
		return qos.Download, nil
	case DirectionUpload:
		return qos.Upload, nil
	default:
		return "", fmt.Errorf("unknown shaping direction %q", d)
	}
}

// InterfaceFor reports which interface carries a direction.
//
// This mapping is the whole reason two disciplines are needed, so it is one
// function rather than a decision repeated at each call site.
func (d Direction) InterfaceFor(wan, lan string) (string, error) {
	switch d {
	case DirectionUpload:
		if wan == "" {
			return "", fmt.Errorf("shaping upload requires a resolved WAN interface")
		}
		return wan, nil
	case DirectionDownload:
		if lan == "" {
			return "", fmt.Errorf("shaping download requires a resolved LAN interface")
		}
		return lan, nil
	default:
		return "", fmt.Errorf("unknown shaping direction %q", d)
	}
}

// OptionCake is the complete set of options tc's CAKE parser accepts.
//
// It is exported so the option set is checkable against iproute2's
// cake_parse_opt in review, rather than trusted because a function happens to
// build a string today. A test asserts every token this package emits is in
// this set.
var OptionCake = []string{
	"bandwidth", "unlimited", "autorate-ingress",
	"rtt",
	"datacentre", "lan", "metro", "regional", "internet", "oceanic", "satellite", "interplanetary",
	"besteffort", "diffserv8", "diffserv4", "diffserv3", "precedence",
	"flowblind", "srchost", "dsthost", "hosts", "flows",
	"dual-srchost", "dual-dsthost", "triple-isolate",
	"nat", "nonat", "wash", "nowash",
	"split-gso", "no-split-gso",
	"no-ack-filter", "ack-filter", "ack-filter-aggressive",
	"memlimit", "fwmark",
	"ptm", "atm", "noatm",
	"raw", "conservative", "ethernet", "ether-vlan", "docsis", "overhead", "mpu",
	"ingress", "egress",
}

// OptionFqCodel is the complete set of options tc's fq_codel parser accepts.
var OptionFqCodel = []string{
	"limit", "flows", "quantum", "target", "interval",
	"memory_limit", "maxrate", "ce_threshold", "ecn",
}

// Rate is a shaped rate in kilobits per second.
type Rate int

// validate rejects a rate that would produce a meaningless or harmful
// command.
//
// The upper bound is not arbitrary caution: it is the point past which the
// number in the command is certainly wrong. A configured rate above 400 Gbit/s
// means the figure did not survive some unit conversion, and CAKE's 64-bit
// rate field is not the constraint.
const maxRateKbps = 400_000_000

// rateArg renders a rate as a tc RATE token ("100Mbit"), which is what CAKE's
// bandwidth option takes.
//
// The suffixed form rather than a bare number because a bare number is read by
// tc as BYTES PER SECOND. "bandwidth 100000" is 100 kbyte/s, not 100 Mbit/s —
// a factor of eight and a unit class of error that looks like a plausible
// number in a log.
func rateArg(kbps int) (string, error) {
	if kbps <= 0 {
		return "", fmt.Errorf("shaping rate must be positive, got %d kbit/s", kbps)
	}
	if kbps > maxRateKbps {
		return "", fmt.Errorf("shaping rate %d kbit/s is implausible", kbps)
	}
	switch {
	case kbps%1_000_000 == 0:
		return strconv.Itoa(kbps/1_000_000) + "Gbit", nil
	case kbps%1_000 == 0:
		return strconv.Itoa(kbps/1_000) + "Mbit", nil
	default:
		return strconv.Itoa(kbps) + "Kbit", nil
	}
}

// CakeArgs builds the CAKE argument vector for one direction.
//
// dir selects which configured rate is used; the other direction's rate is
// deliberately not consulted, because a discipline shapes one direction and
// putting the other one here would be exactly the silent-degradation the
// product spec forbids.
//
// Overhead is expressed the way CAKE expresses it. qos.Policy carries a
// PERCENT because that is what an operator can reason about from a speed test,
// and CAKE's `overhead` is in BYTES PER PACKET. THN does not pass the percent
// through as though the units matched. It raises the shaped rate instead, so
// the link carries the operator's payload rate over the air — the wire-rate
// derate. This is why the rate reaching CAKE is larger than the configured
// figure, and it is the single most confusing thing about shaping a link, so
// it is stated at every call site rather than left in the arithmetic.
func CakeArgs(p qos.Policy, dir Direction, mtu int) ([]string, error) {
	if p.Interface == "" {
		return nil, fmt.Errorf("no interface is configured, so no qdisc can be built")
	}

	dirBandwidth, err := dir.bandwidthDirection()
	if err != nil {
		return nil, err
	}
	kbps := p.Bandwidth.DownloadKbps
	if dir == DirectionUpload {
		kbps = p.Bandwidth.UploadKbps
	}
	if kbps <= 0 {
		return nil, fmt.Errorf("no %s rate is configured; CAKE has nothing to shape toward", dir)
	}

	// CAKE shapes toward the wire rate, so the payload figure is raised by
	// the configured framing allowance. See the package comment.
	wire := p.Bandwidth.Effective(dirBandwidth)

	bandwidth, err := rateArg(wire)
	if err != nil {
		return nil, fmt.Errorf("shaping %s: %w", dir, err)
	}

	args := []string{"bandwidth", bandwidth}

	// rtt tunes CAKE's AQM. The operator-facing model is queue-delay
	// target plus measurement window (qos.Policy.Limits); CAKE exposes one
	// knob, its assumed RTT, and derives target as rtt/20.
	//
	// THN passes IntervalMS as `rtt`. The defaults (target 5ms, interval
	// 100ms) are exactly rtt 100ms, because 100ms/20 = 5ms. So the mapping
	// is faithful for the default case rather than approximate.
	//
	// M7.4 emitted `interval 100ms target 5ms`, which reads as if CAKE took
	// them separately. It does not: `interval` is `rtt` under its old name
	// and `target` is not accepted at all.
	if p.Limits.IntervalMS > 0 {
		args = append(args, "rtt", strconv.Itoa(p.Limits.IntervalMS)+"ms")
	}

	// diffserv4 gives CAKE four priority tins (Bulk / Best Effort / Video /
	// Voice) driven by the DSCP field. It is the only way THN currently has
	// of expressing priority at all, so it is on by default rather than
	// besteffort — which would collapse everything into one tin and make the
	// word "priority" mean nothing.
	//
	// The tins are only useful once something marks traffic into them. Until
	// THN ships DSCP marking, every packet is unmarked and lands in Best
	// Effort, which behaves identically to besteffort. The option is kept
	// because it is a strict superset: it costs nothing unmarked and starts
	// working the moment marking lands.
	args = append(args, "diffserv4")

	// dual-srchost on upload, dual-dsthost on download.
	//
	// Both give host-level fairness FIRST and per-flow fairness second, which
	// is what stops one client opening fifty flows and monopolising the link
	// (Section 12). The direction matters: egress sees distinct source
	// addresses, ingress sees distinct destination addresses. Using the
	// wrong one silently degrades fairness to plain per-flow.
	switch dir {
	case DirectionUpload:
		args = append(args, "dual-srchost")
	case DirectionDownload:
		args = append(args, "dual-dsthost")
	default:
		return nil, fmt.Errorf("unknown shaping direction %q", dir)
	}

	// nat makes CAKE look through the NAT to find the real client address.
	//
	// THN masquerades every WAN-bound flow (OpNFTApplyTHNTable), so without
	// this CAKE sees one source address — the gateway's — and its host-level
	// fairness degenerates to "one host", which is everyone. This is not an
	// optional tuning: with NAT on and `nat` off, host fairness is inert.
	args = append(args, "nat")

	// ingress tunes the AQM for a discipline fed by traffic that already
	// crossed the link. Only download is that; upload leaves the box here,
	// so marking it ingress would be wrong rather than merely redundant.
	if dir == DirectionDownload {
		args = append(args, "ingress")
	}

	// `quantum` was removed because it is not settable. CAKE computes a
	// per-tin quantum from the MTU and reports it in `tc -s qdisc show`; it
	// is an output, not an input. mtu is therefore accepted and deliberately
	// unused here rather than silently shaping a command around it.
	_ = mtu

	return args, nil
}

// FqCodelArgs builds the fq_codel argument vector.
//
// fq_codel genuinely does accept target, interval and quantum — unlike CAKE —
// so they are emitted. It has no rate option at all, which is why the caller
// must treat it as a degradation rather than a substitute: it smooths bursts
// and bounds the queue, but it cannot keep a link under its provisioned rate.
func FqCodelArgs(p qos.Policy, mtu int) ([]string, error) {
	if p.Interface == "" {
		return nil, fmt.Errorf("no interface is configured, so no qdisc can be built")
	}
	if mtu <= 0 {
		mtu = 1500
	}

	args := []string{
		"limit", "10240",
		"flows", "1024",
		"quantum", strconv.Itoa(mtu),
	}
	if p.Limits.TargetMS > 0 {
		args = append(args, "target", strconv.Itoa(p.Limits.TargetMS)+"ms")
	}
	if p.Limits.IntervalMS > 0 {
		args = append(args, "interval", strconv.Itoa(p.Limits.IntervalMS)+"ms")
	}
	return args, nil
}

// QDiscReplaceArgs builds a complete `tc qdisc replace` argument vector.
//
// `replace` rather than `add` so the command is idempotent: applying a plan
// twice is a no-op rather than an error. It is still destructive of whatever
// root discipline is there, which is why the caller must have established
// ownership and a restorable baseline before reaching this function.
func QDiscReplaceArgs(iface, algorithm string, extra ...string) ([]string, error) {
	if iface == "" {
		return nil, fmt.Errorf("no interface given")
	}
	switch algorithm {
	case "cake", "fq_codel":
	default:
		return nil, fmt.Errorf("unsupported qdisc algorithm %q", algorithm)
	}
	if len(extra) == 0 {
		return nil, fmt.Errorf("qdisc %q would be installed with no options; "+
			"refusing to emit an unshaped discipline", algorithm)
	}
	args := append([]string{"qdisc", "replace", "dev", iface, "root", algorithm}, extra...)
	return args, nil
}

// Join renders an argument vector as a reviewable command line.
//
// For display only. Nothing executes the result of this call; the drivers pass
// the slice to exec directly and never through a shell.
func Join(args []string) string { return strings.Join(args, " ") }
