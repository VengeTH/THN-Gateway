package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/guard"
	"github.com/venth/thn-gateway/internal/netns"
	"github.com/venth/thn-gateway/internal/qos"
	qostc "github.com/venth/thn-gateway/internal/qos/tc"
)

// qosPolicyFromConfig derives a shaping policy from configuration.
//
// The configured rate is taken verbatim from the file. It is never inferred
// from the link speed, because a negotiated speed is not a provisioned one:
// shaping a 500Mbit/s provisioned circuit toward its 1Gbit/s physical capacity
// would do nothing at all, and doing so silently would be worse than not
// shaping.
func qosPolicyFromConfig(cfg config.Config) qos.Policy {
	p := qos.Default()

	if !cfg.QoS.Enabled {
		p.Enabled = false
		p.Algorithm = qos.AlgorithmNone
		return p
	}

	p.Enabled = true
	p.Interface = cfg.QoS.Interface
	p.Algorithm = qos.Algorithm(cfg.QoS.Algorithm)
	p.Bandwidth.DownloadKbps = cfg.QoS.DownloadKbps
	p.Bandwidth.UploadKbps = cfg.QoS.UploadKbps
	p.MTU = cfg.Network.MTU
	p.FallbackToFqCodel = true

	// CAKE's defaults are correct for CAKE. fq_codel's quantum is the
	// interface MTU instead, and leaving CAKE's value in place there costs
	// measurable throughput, so the two get different limits.
	if p.Algorithm == qos.AlgorithmFqCodel {
		p.Limits = qos.FqCodelLimits(cfg.Network.MTU)
	} else {
		p.Limits = qos.DefaultLimits()
	}

	p.Comments = append(p.Comments,
		"Rendering this does not change host networking.",
	)

	return p
}

// runQoS implements the `thn qos` group.
func runQoS(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		env.errorf("thn qos: expected a subcommand\n\n")
		env.errorf("  render     print the tc commands, without running them\n")
		env.errorf("  validate   check the policy and report what would be applied\n")
		env.errorf("  stats      read queue counters from the live interface\n")
		env.errorf("  available  report what this kernel supports\n")
		return ExitUsage
	}

	switch args[0] {
	case "render":
		return runQoSRender(env, args[1:])
	case "validate":
		return runQoSValidate(env, args[1:])
	case "stats":
		return runQoSStats(env, args[1:])
	case "available":
		return runQoSAvailable(env, args[1:])
	default:
		return env.fatalf("thn qos: unknown subcommand %q; expected render, validate, stats or available\n", args[0])
	}
}

// qosPolicy loads configuration and derives the shaping policy.
func qosPolicy(env *Env, configPath string) (qos.Policy, string, ExitCode) {
	path := env.resolveConfigPath(configPath)

	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn qos: %v\n", err)
		return qos.Policy{}, path, ExitProblems
	}

	return qosPolicyFromConfig(cfg), path, ExitOK
}

// assumedQoSAvailability builds an availability set from flags.
//
// Without a kernel probe, validation is told what to assume. The flags make
// that explicit rather than defaulting to "cake is available", which would
// hide the fallback case entirely — and the fallback case is the one that
// needs reporting.
func assumedQoSAvailability(cake, fqCodel bool) qos.Availability {
	avail := qos.Availability{
		Algorithms: map[qos.Algorithm]bool{},
		Source:     "assumed",
		CheckedAt:  time.Now(),
	}
	if cake {
		avail.Algorithms[qos.AlgorithmCake] = true
	}
	if fqCodel {
		avail.Algorithms[qos.AlgorithmFqCodel] = true
	}
	if len(avail.Algorithms) == 0 {
		// Neither assumed. The default is the case a kernel without CAKE
		// actually presents, so the resulting fallback is visible rather than
		// hidden. An operator who wants the other case says so.
		avail.Algorithms[qos.AlgorithmFqCodel] = true
		avail.Error = "no kernel probe was run; assuming only fq_codel is present"
	}
	return avail
}

// runQoSValidate implements `thn qos validate`.
func runQoSValidate(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	cake := fs.Bool("assume-cake", false)
	fqCodel := fs.Bool("assume-fq-codel", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn qos validate: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	p, path, code := qosPolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	avail := assumedQoSAvailability(*cake, *fqCodel)
	result := qos.Validate(p, avail)

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config":       path,
			"policy":       p,
			"availability": avail,
			"valid":        result.Valid,
			"selection":    result.Selection,
			"findings":     result.Findings,
		}); err != nil {
			env.errorf("thn qos validate: %v\n", err)
			return ExitProblems
		}
	} else {
		printQoSValidation(env, path, p, avail, result)
	}

	if !result.Valid {
		return ExitProblems
	}
	// A degraded policy still renders, but exits non-zero. CI should notice
	// that the kernel cannot do what was asked, and an exit code is the only
	// way to make that hard to miss.
	if result.Selection.Degraded {
		return ExitProblems
	}
	return ExitOK
}

// printQoSValidation renders a validation result.
func printQoSValidation(env *Env, path string, p qos.Policy, avail qos.Availability, r qos.Result) {
	env.printf("Traffic shaping (from %s)\n", path)
	env.printf("-----------------------\n")
	env.printf("%s\n", p)
	env.printf("\n")
	env.printf("Interface:    %s\n", orNone(p.Interface))
	env.printf("MTU:          %d\n", p.MTU)
	env.printf("Available:    %s\n", avail.Summary())
	env.printf("Selected:     %s\n", qosSelectionLabel(r.Selection))
	env.printf("Result:       %s (%d error, %d warning, %d info)\n",
		passFail(r.Valid), r.ErrorCount, r.WarningCount, r.InfoCount)

	if r.Selection.Degraded {
		env.printf("\n")
		env.printf("  DEGRADED\n")
		env.printf("  %s\n", r.Selection.Reason)
		env.printf("\n")
		env.printf("  Latency will not improve as configured. This is a limit of the\n")
		env.printf("  running kernel, not something the configuration can fix.\n")
	}

	if len(r.Findings) == 0 {
		env.printf("\nNo findings.\n")
		return
	}

	printFindings(env, qosFindings(r.Findings))
}

// qosSelectionLabel renders the selection outcome.
func qosSelectionLabel(s qos.Selection) string {
	if s.Available {
		return s.Algorithm.String() + " (as requested)"
	}
	if s.Degraded {
		return s.Requested.String() + " -> " + s.Algorithm.String() + " (DEGRADED)"
	}
	return s.Algorithm.String() + " (unavailable)"
}

// runQoSRender implements `thn qos render`.
//
// Render prints commands. It does not run them, and this package has no path
// to running them: tc appears only inside guard's allowlist, where every verb
// that changes a queue is absent.
func runQoSRender(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	rootPath := fs.String("root", "")
	out := fs.String("out", "")
	force := fs.Bool("force", false)
	skipValidate := fs.Bool("no-validate", false)
	cake := fs.Bool("assume-cake", false)
	fqCodel := fs.Bool("assume-fq-codel", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn qos render: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	p, path, code := qosPolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	avail := assumedQoSAvailability(*cake, *fqCodel)
	result := qos.Validate(p, avail)

	if !*skipValidate && !result.Valid {
		env.errorf("thn qos render: the policy is not valid; not rendering.\n\n")
		printQoSValidation(env, path, p, avail, result)
		env.errorf("\nFix the findings above, or pass --no-validate to render anyway.\n")
		return ExitProblems
	}

	script := qostc.Render(p, result.Selection)

	if *out == "" {
		if env.IsJSON {
			if err := env.printJSON(map[string]any{
				"config":    path,
				"policy":    p,
				"selection": result.Selection,
				"script":    script,
				"written":   false,
			}); err != nil {
				env.errorf("thn qos render: %v\n", err)
				return ExitProblems
			}
			return ExitOK
		}
		env.printf("%s", script)
		if result.Selection.Degraded {
			return ExitProblems
		}
		return ExitOK
	}

	root := resolveServiceRoot(env, *rootPath)
	if root.Exists(*out) && !*force {
		env.errorf("thn qos render: %s already exists; pass --force to overwrite it.\n", *out)
		env.errorf("The file is THN-generated, so replacing it is safe, but the check\n")
		env.errorf("exists so a render cannot discard a hand-corrected file silently.\n")
		return ExitProblems
	}

	if err := root.WriteFile(*out, script, 0o644); err != nil {
		env.errorf("thn qos render: %v\n", err)
		return ExitProblems
	}

	if !env.IsJSON {
		env.errorf("Wrote %d bytes to %s\n", len(script), root.Resolve(*out))
		env.errorf("\n")
		env.errorf("Nothing has been applied. No qdisc has been changed.\n")
		env.errorf("To check and apply:\n")
		env.errorf("  sh -n %s      # syntax check only\n", root.Resolve(*out))
		env.errorf("  sh %s          # apply\n", root.Resolve(*out))
	}

	if result.Selection.Degraded {
		return ExitProblems
	}
	return ExitOK
}

// runQoSAvailable implements `thn qos available`.
//
// It reports what the running kernel can actually do. Probing requires a
// namespace, because attaching a qdisc to a real interface would change it —
// which is the one thing this project must not do. Without privileges it says
// so rather than guessing.
func runQoSAvailable(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn qos available: %v\n", err)
	}

	avail := probeQoSAvailability()

	if env.IsJSON {
		if err := env.printJSON(avail); err != nil {
			env.errorf("thn qos available: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Shaping support on this host\n")
	env.printf("-----------------------\n")

	if avail.Source == "unavailable" || avail.Source == "failed" {
		env.printf("Available:  unknown\n")
		env.printf("Reason:     %s\n", avail.Error)
		env.printf("\n")
		env.printf("The probe attaches each qdisc to a throwaway interface inside a\n")
		env.printf("network namespace, so it never touches a real one. Without root it\n")
		env.printf("cannot run, and this reports that rather than assuming an answer.\n")
		env.printf("\n")
		env.printf("To check by hand on a host you are not worried about:\n")
		env.printf("  modprobe sch_cake\n")
		env.printf("  tc qdisc add dev eth0 root cake bandwidth 100Mbit\n")
		env.printf("  tc qdisc del dev eth0 root\n")
		return ExitProblems
	}

	env.printf("Source:     %s\n", avail.Source)
	env.printf("Available:  %s\n", avail.Summary())
	env.printf("\n")

	for _, alg := range []qos.Algorithm{qos.AlgorithmCake, qos.AlgorithmFqCodel} {
		mark := "no"
		if avail.Supports(alg) {
			mark = "yes"
		}
		env.printf("  %-10s %s\n", alg, mark)
	}

	env.printf("\n")
	env.printf("The probe ran inside a temporary network namespace, which was\n")
	env.printf("destroyed afterwards. No interface on this host was modified.\n")
	return ExitOK
}

// probeQoSAvailability determines what the kernel supports.
//
// The probe attaches each qdisc to a dummy interface inside a namespace and
// removes it again. Attaching is the only reliable test: a module may be
// available but unloaded, and the attempt is what loads it.
func probeQoSAvailability() qos.Availability {
	avail := qos.Availability{
		Algorithms: map[qos.Algorithm]bool{},
		Source:     "none",
		CheckedAt:  time.Now(),
	}

	if err := netns.Available(); err != nil {
		avail.Source = "unavailable"
		avail.Error = err.Error()
		return avail
	}

	name := fmt.Sprintf("thn-qos-%d", os.Getpid())
	ns, err := netns.Create(name)
	if err != nil {
		avail.Source = "failed"
		avail.Error = err.Error()
		return avail
	}
	defer func() { _ = ns.Close() }()

	const iface = "thnq0"
	if err := ns.Setup(iface); err != nil {
		avail.Source = "failed"
		avail.Error = err.Error()
		return avail
	}
	defer ns.Teardown(iface)

	avail.Source = "probe"
	avail.Algorithms[qos.AlgorithmCake] = ns.HasCake(iface)
	avail.Algorithms[qos.AlgorithmFqCodel] = ns.HasFqCodel(iface)

	return avail
}

// runQoSStats implements `thn qos stats`.
//
// Reading queue counters is permitted: `tc qdisc show` is inspection and is on
// guard's allowlist. This command therefore runs against the live host and
// cannot change it.
func runQoSStats(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	iface := fs.String("interface", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn qos stats: %v\n", err)
	}
	if len(rest) > 0 {
		*iface = rest[0]
	}

	if *iface == "" {
		env.errorf("thn qos stats: --interface is required.\n")
		env.errorf("\n")
		env.errorf("  thn qos stats --interface enp0s31f6\n")
		return ExitUsage
	}

	out, err := guard.Exec(context.Background(), "tc", "-j", "-s", "qdisc", "show", "dev", *iface)
	if err != nil {
		env.errorf("thn qos stats: could not read the queue on %s: %v\n", *iface, err)
		if isMissingBinary(err) {
			env.errorf("\niproute2 is not installed on this host, so queue state cannot be read.\n")
		}
		return ExitProblems
	}

	snap, err := qostc.ParseStats(*iface, out.Stdout)
	if err != nil {
		env.errorf("thn qos stats: %v\n", err)
		return ExitProblems
	}
	snap.ReadAtUnix = time.Now().Unix()

	if env.IsJSON {
		if err := env.printJSON(snap); err != nil {
			env.errorf("thn qos stats: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	printQoSStats(env, snap)
	return ExitOK
}

// isMissingBinary reports whether an error means the tool is not installed.
func isMissingBinary(err error) bool {
	m := err.Error()
	return strings.Contains(m, "executable file not found") || strings.Contains(m, "cannot find")
}

// printQoSStats renders queue statistics.
func printQoSStats(env *Env, snap qostc.Snapshot) {
	env.printf("Queue state for %s\n", orNone(snap.Interface))
	env.printf("-----------------------\n")

	if !snap.Present {
		env.printf("\n")
		env.printf("No root queue discipline is attached to this interface.\n")
		env.printf("Traffic is using the kernel default queue, which does not shape and\n")
		env.printf("does not control delay. If shaping is expected here, it is not running.\n")
		return
	}

	r := snap.Root

	env.printf("\n")
	env.printf("Algorithm:   %s\n", orNone(r.Algorithm))
	if r.Handle != "" {
		env.printf("Handle:      %s\n", r.Handle)
	}
	if r.BandwidthMbps > 0 {
		env.printf("Bandwidth:   %d Mbps\n", r.BandwidthMbps)
	}
	env.printf("\n")
	env.printf("Traffic\n")
	env.printf("  Bytes:     %s\n", formatBytes(r.Bytes))
	env.printf("  Packets:   %d\n", r.Packets)
	env.printf("\n")
	env.printf("Queue\n")
	env.printf("  Backlog:   %d bytes, %d packets\n", r.BacklogBytes, r.BacklogPackets)
	env.printf("  Depth:     %d packets\n", r.QueueLength)
	env.printf("\n")
	env.printf("Loss\n")
	env.printf("  Dropped:     %d (%s)\n", r.Dropped, formatRatio(r.DropRatio()))
	env.printf("  Overlimits:  %d (%s)\n", r.Overlimits, formatRatio(r.OverlimitRatio()))
	env.printf("  Requeues:    %d\n", r.Requeues)
	env.printf("\n")
	env.printf("Health:     %s\n", r.Assess())
	env.printf("           %s\n", r.Explain())

	if len(r.Errors) > 0 {
		env.printf("\nParse problems\n")
		for _, e := range r.Errors {
			env.printf("  %s\n", e)
		}
	}

	if len(snap.Children) > 0 {
		env.printf("\nChild qdiscs\n")
		children := make([]qostc.Stats, len(snap.Children))
		copy(children, snap.Children)
		sort.SliceStable(children, func(i, j int) bool {
			if children[i].Algorithm != children[j].Algorithm {
				return children[i].Algorithm < children[j].Algorithm
			}
			return children[i].Handle < children[j].Handle
		})
		for _, c := range children {
			env.printf("  %-10s %-8s %s, %d packets, %s dropped\n",
				c.Algorithm, c.Handle, formatBytes(c.Bytes), c.Packets, formatRatio(c.DropRatio()))
		}
	}
}

// formatBytes renders a byte count in human units.
func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// formatRatio renders a ratio as a percentage.
func formatRatio(r float64) string {
	return strconv.FormatFloat(r*100, 'f', 2, 64) + "%"
}

// qosFindings projects QoS findings into the shared rendering view.
func qosFindings(in []qos.Finding) []findingView {
	out := make([]findingView, 0, len(in))
	for _, f := range in {
		out = append(out, findingView{
			severity: string(f.Severity),
			field:    f.Field,
			message:  f.Message,
			hint:     f.Hint,
		})
	}
	return out
}
