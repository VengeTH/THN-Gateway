package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/correlation"
	"github.com/VengeTH/THN-Gateway/internal/incidents"
	"github.com/VengeTH/THN-Gateway/internal/rules"
	"github.com/VengeTH/THN-Gateway/internal/ruleset"
	"github.com/VengeTH/THN-Gateway/internal/signals"
)

// This file implements `thn rules` and `thn incidents`.
//
// Both are pure. Neither reads the host, neither needs the daemon, and
// neither can change anything. The rules are the shipped set and the
// incidents are whatever the caller supplies, which is what makes them safe to
// run on a laptop pointed at a production gateway â€” and testable in CI, which
// is where most of their value is during development.
//
// # Why `thn rules test` exists
//
// A rule set that has never been exercised is a rule set nobody knows works.
// `thn rules test` evaluates the shipped rules against observations supplied
// on the command line and prints what each one concluded, including what it
// could not conclude. That makes the three-valued logic inspectable from a
// shell, which is the only way to answer "what would this rule do about that
// gateway" without writing a test.

// runRules implements the `thn rules` group.
func runRules(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn rules: expected a subcommand\n\n")
		// env.fatalf already returns; this is unreachable but keeps the
		// control flow obvious to a reader.
	}

	switch args[0] {
	case "list":
		return runRulesList(env, args[1:])
	case "test":
		return runRulesTest(env, args[1:])
	default:
		return env.fatalf("thn rules: unknown subcommand %q; expected list or test\n", args[0])
	}
}

// runRulesList prints the shipped rules.
//
// The whole point is that a rule is readable. An operator deciding whether
// THN's judgements are reasonable has to be able to see them without reading
// Go, and the reasoning behind each threshold lives in the rule's own text.
func runRulesList(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	severity := fs.String("severity", "")
	verbose := fs.Bool("long", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn rules list: %v\n", err)
	}

	all := ruleset.All()

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"rules":       listed(all),
			"inhibitions": listed(ruleset.Inhibitions()),
			"count":       len(all),
		}); err != nil {
			env.errorf("thn rules list: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	var shown []rules.Rule
	for _, r := range all {
		if *severity != "" && string(r.Severity) != *severity {
			continue
		}
		shown = append(shown, r)
	}

	if len(shown) == 0 {
		env.errorf("No rules with severity %q.\n", *severity)
		return ExitOK
	}

	env.printf("Traffic shaping and gateway rules (%d of %d)\n", len(shown), len(all))
	env.printf("â”€â”€â”€â”€â”€â”€â”€\n\n")

	for _, r := range shown {
		env.printf("  %-26s %-8s %s\n", r.Name, r.Severity, r.Title)
		env.printf("  %-26s %-8s when %s\n", "", durationOr(r.For),
			r.Condition.Describe())

		if *verbose {
			env.printf("\n")
			for _, line := range strings.Split(r.Remedy, "\n") {
				env.printf("      %s\n", line)
			}
			for _, c := range r.Comments {
				for _, line := range strings.Split(c, "\n") {
					env.printf("      %s\n", line)
				}
			}
			env.printf("\n")
		}
	}

	env.printf("\n")
	env.printf("Every rule above is renderable only. THN evaluates them and records\n")
	env.printf("what it finds; it does not act on any of them.\n")

	if *verbose {
		env.printf("\n")
		env.printf("Suppressions\n")
		env.printf("â”€â”€â”€â”€â”€â”€â”€\n")
		env.printf("These say which conditions are consequences of which, so that one\n")
		env.printf("fault is reported once rather than as several:\n\n")
		for _, in := range ruleset.Inhibitions() {
			env.printf("  %s suppresses %s\n", in.Source, in.Target)
			env.printf("      %s\n", in.Reason)
		}
	}

	return ExitOK
}

// observation is one --observe flag.
type observation struct {
	name  string
	value string
}

// runRulesTest evaluates the shipped rules against supplied observations.
//
// This is the command that makes the three-valued logic inspectable. It
// prints what each rule concluded and, for anything it could not conclude,
// why. The second half is the part that matters: "the rule did not fire" is
// ambiguous between "the condition is fine" and "THN could not tell", and an
// operator debugging a silent rule needs to know which.
func runRulesTest(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	_ = fs.String("at", "")
	_ = fs.Bool("long", false)
	// --observe is registered so the parser accepts it, and its occurrences
	// are collected from the raw arguments below. The flag set keeps only the
	// last value for a repeated flag, and every rule evaluation needs all of
	// them, so the collection cannot go through it.
	_ = fs.String("observe", "")

	raw, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn rules test: %v\n", err)
	}
	_ = raw

	obs := collectObservations(args)
	if len(obs) == 0 {
		env.errorf("thn rules test: no observations given.\n")
		env.errorf("\n")
		env.errorf("Supply at least one --observe name=value. The value may be:\n")
		env.errorf("  true / false    a known boolean\n")
		env.errorf("  a number        a known figure\n")
		env.errorf("  ?               the signal could not be read\n")
		env.errorf("\n")
		env.errorf("For example, an uplink that is present but down:\n")
		env.errorf("  thn rules test \\\n")
		env.errorf("    --observe %s=true --observe %s=false\n",
			signals.NetWANPresent, signals.NetWANUp)
		env.errorf("\n")
		env.errorf("A rule fires only after its condition has held for its duration,\n")
		env.errorf("so a single test shows which rules are PENDING, not firing.\n")
		return ExitUsage
	}

	// The parsed rest is unused: --observe is the only positional this
	// command takes and it is read from the raw arguments.
	_ = raw

	// The timestamp is re-read from the parsed flags, which is the only place
	// it is decoded.
	when := time.Now().UTC()
	if v := fsValue(fs, "at"); v != "" {
		parsed, perr := time.Parse(time.RFC3339, v)
		if perr != nil {
			return env.fatalf("thn rules test: --at %q is not an RFC 3339 timestamp\n", v)
		}
		when = parsed.UTC()
	}

	set := buildObservationSet(obs, when)
	ev := rules.NewEvaluator(func() time.Time { return when })

	// Evaluated twice at the same instant: the first starts any duration
	// threshold and the second is past none of them. What this shows is which
	// rules are pending, which is the state an operator sees before a
	// threshold elapses.
	ev.Evaluate(ruleset.All(), set)
	firing, _ := ev.Evaluate(ruleset.All(), set)

	pending := ev.Pending()
	undecidable := ev.Undecidable()

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"at":           when,
			"observations": listed(set.All()),
			"firing":       listed(firing),
			"pending":      listed(pending),
			"undecidable":  listed(undecidable),
		}); err != nil {
			env.errorf("thn rules test: %v\n", err)
			return ExitProblems
		}
		// An undecidable rule is a problem the caller needs to see, but it is
		// not a failure of this command: it succeeded in reporting that it
		// could not conclude.
		return ExitOK
	}

	env.printf("Rule evaluation at %s\n", when.Format(time.RFC3339))
	env.printf("â”€â”€â”€â”€â”€â”€â”€\n\n")

	env.printf("Observations\n")
	for _, s := range set.All() {
		mark := "known"
		if !s.Value.Known {
			mark = "UNREAD"
		}
		env.printf("  %-32s %-22s %s\n", s.Name, s.Value.String(), mark)
	}

	env.printf("\nConclusions\n")
	all := ev.All()
	if len(all) == 0 {
		env.printf("  No rule could be evaluated: the observations do not reach any " +
			"of them.\n")
	}

	byName := map[string]rules.Rule{}
	for _, r := range ruleset.All() {
		byName[r.Name] = r
	}

	sort.SliceStable(all, func(i, j int) bool { return all[i].Rule < all[j].Rule })

	verbose := fs.Seen("long")
	for _, inst := range all {
		rule := byName[inst.Rule]
		verdict := inst.State.String()

		env.printf("  %-26s %-10s %s\n", inst.Rule, verdict, rule.Condition.Describe())
		if verbose {
			env.printf("  %-26s %-10s severity: %s", "", "", rule.Severity)
			if inst.State == rules.StatePending {
				env.printf("; needs %s more", remaining(inst, rule.For))
			}
			env.printf("\n")
		}
		for _, reason := range inst.Conditions {
			env.printf("  %-26s %-10s could not determine: %s\n", "", "", reason)
		}
	}

	env.printf("\n")
	env.printf("%d firing, %d pending, %d undecidable of %d rules\n",
		len(firing), len(pending), len(undecidable), len(ruleset.All()))

	if len(undecidable) > 0 {
		env.printf("\n")
		env.printf("%d rule(s) could not be evaluated. They have not fired, and they\n", len(undecidable))
		env.printf("have not cleared either: THN is not reporting them as fine, it is\n")
		env.printf("reporting that it could not see. Supply the missing observations.\n")
	}

	return ExitOK
}

// collectObservations pulls --observe name=value pairs out of the arguments.
func collectObservations(args []string) []observation {
	var out []observation
	for i := 0; i < len(args); i++ {
		a := strings.TrimLeft(args[i], "-")
		if a != "observe" {
			continue
		}
		// Both "--observe=x" and "--observe x" are accepted.
		value := ""
		if eq := strings.Index(a, "="); eq >= 0 {
			value = a[eq+1:]
		} else if i+1 < len(args) {
			value = args[i+1]
			i++
		}
		eq := strings.Index(value, "=")
		if eq < 0 {
			continue
		}
		out = append(out, observation{name: value[:eq], value: value[eq+1:]})
	}
	return out
}

// buildObservationSet turns flag values into a signal set.
//
// "?" is the interesting case: it is how an operator expresses "this could not
// be read", which is a third state rather than a false, and the whole point of
// the design is that it stays distinguishable.
//
// Each signal is labelled with its subsystem, because that label is what
// correlation groups on. Without it every supplied observation would share an
// empty grouping key, and a test against two subsystems would produce one
// incident covering both — which would be a true statement about the grouping
// and a false one about the gateway.
func buildObservationSet(obs []observation, at time.Time) *signals.Set {
	sigs := make([]signals.Signal, 0, len(obs))
	for _, o := range obs {
		source := signals.SourceOf(o.name)
		sigs = append(sigs, signals.Signal{
			Name:   o.name,
			Source: source,
			Value:  parseObservedValue(o.value),
			At:     at,
			Detail: "supplied with `thn rules test`",
			Labels: map[string]string{signals.LabelSource: source},
		})
	}
	return signals.NewSet(at, sigs...)
}

// parseObservedValue interprets a supplied value.
func parseObservedValue(v string) signals.Value {
	switch v {
	case "?":
		// The kind is unknown here, which is honest: the caller has said the
		// value could not be read without saying what it would have been.
		return signals.Unknown(signals.KindBool)
	case "true":
		return signals.Bool(true)
	case "false":
		return signals.Bool(false)
	}
	if f, err := parseFloat(v); err == nil {
		return signals.Number(f)
	}
	return signals.String(v)
}

// parseFloat parses a number, or returns an error.
func parseFloat(s string) (float64, error) {
	var f float64
	var neg bool
	i := 0
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		neg = s[i] == '-'
		i++
	}
	if i >= len(s) {
		return 0, fmt.Errorf("not a number")
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("not a number")
		}
		f = f*10 + float64(s[i]-'0')
	}
	if neg {
		f = -f
	}
	return f, nil
}

// runIncidents implements the `thn incidents` group.
func runIncidents(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn incidents: expected a subcommand\n\n")
	}

	switch args[0] {
	case "list":
		return runIncidentsList(env, args[1:])
	default:
		return env.fatalf("thn incidents: unknown subcommand %q; expected list\n", args[0])
	}
}

// runIncidentsList shows what the current observations imply.
//
// There is no daemon in this build, so there is no incident history to read.
// What this command can do is the part that is genuinely useful from a
// laptop: evaluate the rules against a supplied observation and show what
// would be reported. It says so plainly rather than presenting a synthetic
// history as though it were recorded fact.
func runIncidentsList(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	_ = fs.Bool("all", false)
	_ = fs.String("observe", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn incidents list: %v\n", err)
	}
	_ = rest

	obs := collectObservations(args)
	if len(obs) == 0 {
		env.errorf("thn incidents list: no observations given.\n")
		env.errorf("\n")
		env.errorf("This build has no daemon, so there is no recorded incident history.\n")
		env.errorf("What this command can do is evaluate the rules against an\n")
		env.errorf("observation you supply and show what would be reported.\n")
		env.errorf("\n")
		env.errorf("  thn incidents list --observe %s=false --observe %s=true \\\n",
			signals.NetWANUp, signals.NetWANPresent)
		env.errorf("\n")
		env.errorf("Use `thn rules test` to see per-rule conclusions instead.\n")
		return ExitUsage
	}

	now := time.Now().UTC()
	set := buildObservationSet(obs, now)

	ev := rules.NewEvaluator(func() time.Time { return now })
	cor, err := correlation.New(ruleset.CorrelationConfig())
	if err != nil {
		env.errorf("thn incidents list: %v\n", err)
		return ExitProblems
	}
	mgr := incidents.NewManager(func() time.Time { return now })

	// Advance far enough for every grace period, so what is shown is what
	// would be reported rather than what is merely pending.
	clock := &advancingClock{now: now}
	ev = rules.NewEvaluator(clock.Now)

	var groups []correlation.Group
	for i := 0; i < 20; i++ {
		clock.advance(30 * time.Second)
		firing, _ := ev.Evaluate(ruleset.All(), set)
		groups = append(groups, cor.Process(firing, clock.now)...)
	}

	mgr.Apply(groups)
	all := mgr.All()

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"source":    "evaluated from supplied observations",
			"recorded":  false,
			"incidents": listed(all),
			"summary":   mgr.Summarise(),
		}); err != nil {
			env.errorf("thn incidents list: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Incidents implied by the supplied observations\n")
	env.printf("â”€â”€â”€â”€â”€â”€â”€\n")
	env.printf("Evaluated at %s. This is not a recorded history: this build has no\n", now.Format(time.RFC3339))
	env.printf("daemon, so nothing has been retained between runs.\n\n")

	if len(all) == 0 {
		env.printf("No incidents.\n")
		env.printf("\n")
		env.printf("If you expected one, the rules may be pending rather than clear â€”\n")
		env.printf("every rule has a duration threshold. Run `thn rules test` with the\n")
		env.printf("same observations to see which are pending and which could not be\n")
		env.printf("determined at all.\n")
		return ExitOK
	}

	for _, inc := range all {
		env.printf("  %s\n", inc.String())
		env.printf("    opened:     %s\n", inc.OpenedAt.Format(time.RFC3339))
		env.printf("    key:        %s\n", inc.Key)
		env.printf("    fingerprint: %s\n", inc.Fingerprint)

		if len(inc.Causes) > 0 {
			env.printf("    causes:\n")
			for _, c := range inc.Causes {
				env.printf("      %-26s %s\n", c.Rule, c.Title)
			}
		}
		if len(inc.Consequences) > 0 {
			env.printf("    suppressed as consequences:\n")
			for _, c := range inc.Consequences {
				env.printf("      %-26s suppressed by %s\n", c.Rule, c.SuppressedBy)
			}
		}
		env.printf("\n")
	}

	counts := mgr.Summarise()
	env.printf("%d incident(s): %d active, %d resolved, %d critical, %d warning\n",
		len(all), counts.Active, counts.Resolved, counts.Critical, counts.Warning)

	return ExitOK
}

// advancingClock is a clock that moves on demand.
type advancingClock struct{ now time.Time }

func (c *advancingClock) advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func (c *advancingClock) Now() time.Time { return c.now }

// fsValue reads a registered string flag's value.
//
// The flag set keeps its values in a map of pointers, and this reads through
// it rather than through a captured pointer so that a caller which registers
// a flag it does not otherwise use does not have to keep the pointer alive.
func fsValue(fs *flagSet, name string) string {
	if p, ok := fs.strings[name]; ok {
		return *p
	}
	return ""
}

// remaining reports how much longer a pending rule must hold.
func remaining(inst rules.Instance, threshold time.Duration) time.Duration {
	held := time.Since(inst.Since)
	if held >= threshold {
		return 0
	}
	return threshold - held
}

// durationOr renders a rule's threshold for display.
func durationOr(d time.Duration) string {
	if d == 0 {
		return "immediate"
	}
	return "for " + d.String()
}
