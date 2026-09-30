package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/assistant"
	"github.com/venth/thn-gateway/internal/correlation"
	"github.com/venth/thn-gateway/internal/rules"
	"github.com/venth/thn-gateway/internal/ruleset"
	"github.com/venth/thn-gateway/internal/signals"
)

// This file implements `thn explain`, `thn ask` and `thn suggest`.
//
// # What these commands are
//
// A translation layer over the deterministic pipeline. They take what the rule
// engine, the correlator and the incident manager already concluded and arrange
// it into prose. They do not observe anything the other commands do not
// observe, decide anything the rule set does not decide, or change anything at
// all.
//
// # Why they exist
//
// `thn rules test` prints one line per rule. That is the right shape for a
// person who already knows which rule they are looking at, and the wrong shape
// for somebody woken at three in the morning who has been told the uplink is
// down and wants to know what to do about it.
//
// The difference between the two is entirely presentational, and that is the
// point: the work was already being done correctly by code with tests, and
// this file makes its output usable without changing what it says.
//
// # The AI question
//
// No model is configured by these commands. `assistant.NoModel` is what they
// install, so `thn explain` is fully deterministic, needs no network, runs
// identically on a laptop and on the gateway, and is what CI tests.
//
// A model can be plugged in behind the same interface. When one is, it writes
// prose and nothing else: it cannot select which facts are used, it cannot add
// one, and every sentence it produces is checked against the bundle before it
// is shown. A sentence that cites nothing is dropped. The deterministic answer
// is always produced as well, and is always shown.

// resolveWhen reads --at, or uses the current time.
//
// Shared by the three commands so that a timestamp means the same thing in all
// of them and there is one place where a malformed one is reported.
func resolveWhen(env *Env, fs *flagSet, command string) (time.Time, ExitCode) {
	v := fsValue(fs, "at")
	if v == "" {
		return time.Now().UTC(), ExitOK
	}
	parsed, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, env.fatalf("%s: --at %q is not an RFC 3339 timestamp\n", command, v)
	}
	return parsed.UTC(), ExitOK
}

// runExplain implements `thn explain`.
func runExplain(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("local", false)
	fs.Bool("remedies", false)
	fs.String("at", "")
	fs.String("kind", string(assistant.QueryStatus))
	fs.String("subject", "")
	fs.String("limit", "")
	fs.String("audit", "")
	_ = fs.String("observe", "")

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn explain: %v\n", err)
	}

	when, wcode := resolveWhen(env, fs, "thn explain")
	if wcode != ExitOK {
		return wcode
	}

	scene, code := buildScene(env, args, when, *fs.bools["local"])
	if code != ExitOK {
		return code
	}

	q := assistant.Query{
		Kind:            assistant.QueryKind(fsValue(fs, "kind")),
		Subject:         fsValue(fs, "subject"),
		IncludeRemedies: *fs.bools["remedies"],
	}
	if v := fsValue(fs, "limit"); v != "" {
		n, err := parsePositiveInt(v)
		if err != nil {
			return env.fatalf("thn explain: --limit %q is not a number\n", v)
		}
		q.Limit = n
	}

	if err := q.Validate(); err != nil {
		return env.fatalf("thn explain: %v\n", err)
	}

	answer, err := assistant.Explain(scene.bundle, q, "")
	if err != nil {
		return env.fatalf("thn explain: %v\n", err)
	}

	if log := openAudit(env, fsValue(fs, "audit"), scene.when); log != nil {
		defer log.Close()
		entry := assistant.Audit(scene.when, assistant.EventAsked, "", answer, nil)
		entry.FactsAvailable = len(scene.bundle.Facts)
		if aerr := log.Append(entry); aerr != nil {
			env.errorf("thn explain: audit: %v\n", aerr)
		}
	}

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"at":        scene.when,
			"bundle":    scene.bundle.Describe(),
			"digest":    scene.bundle.Digest,
			"query":     answer.Query.String(),
			"claims":    listed(answer.Claims),
			"dropped":   listed(answer.Dropped),
			"facts":     scene.bundle.Facts,
			"model":     "none (deterministic)",
			"instances": listed(scene.instances),
			"groups":    listed(scene.groups),
		}); err != nil {
			env.errorf("thn explain: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	printAnswer(env, scene, answer)
	return ExitOK
}

// runAsk implements `thn ask`.
func runAsk(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("local", false)
	fs.String("at", "")
	fs.String("audit", "")
	_ = fs.String("observe", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn ask: %v\n", err)
	}

	question := strings.TrimSpace(strings.Join(rest, " "))
	if question == "" {
		env.errorf("thn ask: expected a question.\n")
		env.errorf("\n")
		env.errorf("For example:\n")
		env.errorf("  thn ask \"why is the uplink down\"\n")
		env.errorf("  thn ask \"what should I do\" --local\n")
		env.errorf("  thn ask \"what can't you see\"\n")
		return ExitUsage
	}

	when, wcode := resolveWhen(env, fs, "thn ask")
	if wcode != ExitOK {
		return wcode
	}

	scene, code := buildScene(env, args, when, *fs.bools["local"])
	if code != ExitOK {
		return code
	}

	// No model and no translator: the deterministic parser is the whole of the
	// natural-language handling in this build. Both interfaces are passed as
	// nil so the fallback path is the one exercised, which is the path that
	// must not break.
	answer, err := assistant.Ask(context.Background(), scene.bundle, question, assistant.NoModel{}, nil)
	if err != nil {
		if log := openAudit(env, fsValue(fs, "audit"), scene.when); log != nil {
			defer log.Close()
			// The question is hashed, never written. See assistant/audit.go.
			_ = log.Append(assistant.Audit(scene.when, assistant.EventRefused, question,
				assistant.Answer{}, err))
		}
		return env.fatalf("thn ask: %v\n", err)
	}

	if log := openAudit(env, fsValue(fs, "audit"), scene.when); log != nil {
		defer log.Close()
		entry := assistant.Audit(scene.when, assistant.EventAsked, question, answer, nil)
		entry.FactsAvailable = len(scene.bundle.Facts)
		if aerr := log.Append(entry); aerr != nil {
			env.errorf("thn ask: audit: %v\n", aerr)
		}
	}

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"at":       scene.when,
			"question": question,
			"digest":   answer.Digest,
			"query":    answer.Query.String(),
			"claims":   listed(answer.Claims),
			"dropped":  listed(answer.Dropped),
			"facts":    answer.Facts,
			"model":    "none (deterministic)",
		}); err != nil {
			env.errorf("thn ask: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	printAnswer(env, scene, answer)
	return ExitOK
}

// runSuggest implements `thn suggest`.
func runSuggest(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("local", false)
	fs.String("at", "")
	fs.String("audit", "")
	_ = fs.String("observe", "")

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn suggest: %v\n", err)
	}

	when, wcode := resolveWhen(env, fs, "thn suggest")
	if wcode != ExitOK {
		return wcode
	}

	scene, code := buildScene(env, args, when, *fs.bools["local"])
	if code != ExitOK {
		return code
	}

	defs := make(map[string]rules.Rule)
	for _, r := range ruleset.All() {
		defs[r.Name] = r
	}

	suggestions := assistant.SuggestCorrelations(
		scene.groups, defs, ruleset.Inhibitions(), scene.when)

	if log := openAudit(env, fsValue(fs, "audit"), scene.when); log != nil {
		defer log.Close()
		if aerr := log.Append(assistant.AuditSuggestion(scene.when, len(suggestions))); aerr != nil {
			env.errorf("thn suggest: audit: %v\n", aerr)
		}
	}

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"at":          scene.when,
			"suggestions": listed(suggestions),
			"groups":      listed(scene.groups),
			"applied":     false,
			"note":        "suggestions are printed for review; nothing here changes the configuration",
		}); err != nil {
			env.errorf("thn suggest: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Correlation suggestions\n")
	env.printf("%s\n\n", strings.Repeat("─", 72))
	env.printf("%s", assistant.RenderSuggestions(suggestions))
	return ExitOK
}

// ---------------------------------------------------------------- the scene

// assistantScene is everything one assistant invocation is built from.
type assistantScene struct {
	when      time.Time
	bundle    assistant.Bundle
	instances []rules.Instance
	groups    []correlation.Group
}

// buildScene assembles observations, evaluates the rules, correlates them and
// builds the fact bundle.
//
// The order matters and is the same as the pipeline's: observe, evaluate,
// correlate, then explain. Nothing here re-derives a conclusion that an earlier
// stage already reached; it only passes the results along.
//
// `when` and `local` arrive already parsed. This function used to build its own
// flag set and re-read them, which meant two flag sets had to agree about which
// flags existed - and when they did not, the disagreement was a nil map lookup
// and a panic rather than a message. One parse, in the caller.
func buildScene(env *Env, args []string, when time.Time, local bool) (assistantScene, ExitCode) {
	obs := collectObservations(args)

	// Hoisted: the two sources of observations assign to the same set, and
	// declaring it inside each case would scope it to that case.
	var set *signals.Set

	switch {
	case local && len(obs) > 0:
		return assistantScene{}, env.fatalf(
			"thn: --local reads this host and --observe supplies observations. Use one or the other.\n")

	case local:
		path := env.resolveConfigPath("")
		cfg, err := loadConfig(env, path)
		if err != nil {
			return assistantScene{}, ExitProblems
		}
		observed, _, _ := observeHost(cfg)
		set := signals.Derive(observed, when)
		if set == nil {
			return assistantScene{}, env.fatalf(
				"thn: the host could not be inspected, so there is nothing to explain.\n")
		}

	case len(obs) > 0:
		set = buildObservationSet(obs, when)

	default:
		env.errorf("thn: no observations given.\n")
		env.errorf("\n")
		env.errorf("There is no daemon in this build, so these commands explain what\n")
		env.errorf("you tell them, or what they can read from this host.\n")
		env.errorf("\n")
		env.errorf("  --local           read this host (the gateway itself, normally)\n")
		env.errorf("  --observe n=v     supply an observation; ? means it could not be read\n")
		env.errorf("\n")
		env.errorf("For example, an uplink that is present but down:\n")
		env.errorf("  thn explain --observe %s=true --observe %s=false\n",
			signals.NetWANPresent, signals.NetWANUp)
		return assistantScene{}, ExitUsage
	}

	// Evaluated twice at the same instant, for the same reason `thn rules
	// test` does it: the first pass starts a duration threshold and the second
	// passes none of them, so the result shows what is pending rather than what
	// would eventually fire.
	ev := rules.NewEvaluator(func() time.Time { return when })
	ev.Evaluate(ruleset.All(), set)
	firing, _ := ev.Evaluate(ruleset.All(), set)

	pending := ev.Pending()
	undecidable := ev.Undecidable()

	instances := make([]rules.Instance, 0, len(firing)+len(pending)+len(undecidable))
	instances = append(instances, firing...)
	instances = append(instances, pending...)
	instances = append(instances, undecidable...)

	cor, cerr := correlation.New(ruleset.CorrelationConfig())
	if cerr != nil {
		return assistantScene{}, env.fatalf("thn: correlation configuration is invalid: %v\n", cerr)
	}
	groups := cor.Process(firing, when)

	defs := make(map[string]rules.Rule, len(ruleset.All()))
	for _, r := range ruleset.All() {
		defs[r.Name] = r
	}

	// The limitation is stated rather than left as an absence. A bundle built
	// from observations the caller supplied describes those observations and
	// nothing else, and a reader who does not know that will read it as a
	// description of the gateway.
	var degradable []string
	if !local {
		degradable = []string{
			"the gateway itself",
		}
	}

	bundle := assistant.Build(assistant.Input{
		At:           when,
		Instances:    instances,
		Definitions:  defs,
		Observations: set.All(),
		Groups:       groups,
		Degradable:   degradable,
	})

	return assistantScene{
		when:      when,
		bundle:    bundle,
		instances: instances,
		groups:    groups,
	}, ExitOK
}

// ------------------------------------------------------------------ output

// printAnswer renders an answer for a terminal.
func printAnswer(env *Env, scene assistantScene, answer assistant.Answer) {
	env.printf("%s\n", scene.bundle.Describe())
	env.printf("%s\n\n", strings.Repeat("─", 72))

	for _, c := range answer.Claims {
		env.printf("%s\n", c.Text)
		if c.Remedy != "" {
			env.printf("  → %s\n", c.Remedy)
		}
		if len(c.FactIDs) > 0 {
			env.printf("  [%s]\n", strings.Join(c.FactIDs, " "))
		}
		env.printf("\n")
	}

	if len(answer.Claims) == 0 {
		env.printf("No conclusion matched this question.\n\n")
	}

	if len(answer.Dropped) > 0 {
		env.printf("Filtered out %d sentence(s) that cited no observation:\n", len(answer.Dropped))
		for _, d := range answer.Dropped {
			env.printf("  %s\n", truncateRunes(d.Text, 90))
			env.printf("      %s\n", d.Reason)
		}
		env.printf("\n")
	}

	env.printf("%s\n", strings.Repeat("─", 72))
	env.printf("Deterministic answer: no language model was involved.\n")
	env.printf("Every sentence above is a restatement of a rule evaluation, not advice.\n")
	env.printf("Actions shown come from the rule set's own remedy text.\n")
	env.printf("Bundle %s, observed at %s.\n", scene.bundle.Digest, scene.when.Format(time.RFC3339))
}

// openAudit opens an append-only audit log if one was requested.
//
// Audit logging is opt-in and off by default. A gateway that is unattended
// should not accumulate files nobody asked for, and the read-only commands
// must work when there is nowhere to write.
func openAudit(env *Env, path string, when time.Time) *auditFile {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		env.errorf("thn: audit log: %v\n", err)
		return nil
	}
	return &auditFile{
		JSONL: assistant.JSONL{W: f, Now: func() time.Time { return when }},
		f:     f,
	}
}

// auditFile couples the JSONL writer to the file it writes, so that closing
// the audit trail is one call and cannot be forgotten.
type auditFile struct {
	assistant.JSONL
	f *os.File
}

// Close closes the underlying file.
func (a *auditFile) Close() error {
	if a == nil || a.f == nil {
		return nil
	}
	return a.f.Close()
}

func parsePositiveInt(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("negative")
	}
	return n, nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
