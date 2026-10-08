package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/signals"
)

// This file holds the condition vocabulary. Conditions are built from a small
// set of combinators rather than parsed from an expression language.
//
// # Why no expression language
//
// A string expression would be more flexible and would need a parser, a
// grammar, an evaluator and a documentation page explaining the difference
// between "no data" and "false" in that syntax. In exchange it would let
// someone write a rule THN cannot check at compile time, cannot describe
// exactly when it will fire, and cannot explain in an incident.
//
// THN's rules are a fixed, reviewed set that ships with the binary. A
// combinator vocabulary gives the same expressiveness with none of those
// costs, and every condition can say precisely which signals it reads and
// when it cannot be determined.

// GroupLabel is the label a rule uses to fan out over instances.
//
// A rule carrying this label is evaluated once per distinct value of the
// named signal label, which is how "every interface" becomes one rule rather
// than one rule per interface.
const GroupLabel = "thn_group"

// Always is a condition that always holds.
func Always() Condition { return alwaysCond{} }

type alwaysCond struct{}

func (alwaysCond) Test(*signals.Set) Truth          { return TruthTrue }
func (alwaysCond) Describe() string                 { return "always" }
func (alwaysCond) Signals() []string                { return nil }
func (alwaysCond) Conditions(*signals.Set) []string { return nil }

// Never is a condition that never holds.
//
// It exists so a rule can be disabled by making its condition false, rather
// than by deleting it. A disabled rule that still appears in the list is
// visible; a deleted one leaves a gap nobody notices.
func Never() Condition { return neverCond{} }

type neverCond struct{}

func (neverCond) Test(*signals.Set) Truth          { return TruthFalse }
func (neverCond) Describe() string                 { return "never" }
func (neverCond) Signals() []string                { return nil }
func (neverCond) Conditions(*signals.Set) []string { return nil }

// IsTrue holds when a signal reads true.
func IsTrue(name string) Condition {
	return signalCond{name: name, want: truthWant{known: true, val: true}}
}

// IsFalse holds when a signal reads false.
func IsFalse(name string) Condition {
	return signalCond{name: name, want: truthWant{known: true, val: false}}
}

// IsUnknown holds when a signal could not be read.
//
// It is the inverse of the usual assumption, and it is how a rule watches for
// the case that matters most on an unattended device: THN itself losing the
// ability to see the gateway.
func IsUnknown(name string) Condition { return signalCond{name: name, want: truthWant{unknown: true}} }

// Below holds when a numeric signal is less than a threshold.
//
// The comparison is strict, so Below(x) and AtOrAbove(x) partition the
// numbers exactly. A rule pair that overlapped at the boundary would fire
// both of its rules at once, and correlation would then have to merge two
// incidents that are the same incident.
func Below(name string, threshold float64) Condition {
	return numericCond{name: name, cmp: cmpLess, threshold: threshold}
}

// AtOrAbove holds when a numeric signal is at least a threshold.
func AtOrAbove(name string, threshold float64) Condition {
	return numericCond{name: name, cmp: cmpGreaterEqual, threshold: threshold}
}

// Between holds when a numeric signal falls within an inclusive range.
//
// It is the one condition that is false in the middle rather than at the
// edges, and it exists for the rules where the interesting case is a value
// that is too high: a drop ratio above 10% is a problem, and one below 1% is
// not. Written as two rules that would fire on mutually exclusive inputs and
// correlate into nothing useful.
func Between(name string, low, high float64) Condition {
	return numericCond{name: name, cmp: cmpBetween, low: low, high: high}
}

// Equals holds when a string signal matches exactly.
func Equals(name, want string) Condition {
	return stringCond{name: name, want: want}
}

// NotIn holds when a string signal is anything other than a listed value.
func NotIn(name string, unwanted ...string) Condition {
	return notInCond{name: name, unwanted: unwanted}
}

// All holds when every condition holds.
//
// An unknown from any operand makes the whole thing unknown, not false. That
// propagates deliberately: a conjunction whose parts were not all observed has
// not been established, and reporting it as false would be a claim nobody
// made.
func All(conds ...Condition) Condition { return allCond{conds: conds} }

// Any holds when at least one condition holds.
//
// The unknown case is the interesting one. If one operand is unknown and
// another is true, the answer is true — something was established. If one is
// unknown and the rest are false, the answer is unknown: the unknown operand
// might have been the one that held.
//
// Collapsing that to false would silently discard the one observation that
// could not be made, which is the failure this whole package is built to
// avoid.
func Any(conds ...Condition) Condition { return anyCond{conds: conds} }

// Not inverts a condition.
//
// Unknown inverts to unknown, not to true. "The link is not down" is not
// established when THN could not read the link, and inverting to true would
// assert the exact opposite of what is known.
func Not(c Condition) Condition { return notCond{inner: c} }

// truthWant describes what a signal must read for a condition to hold.
type truthWant struct {
	known   bool
	val     bool
	unknown bool
}

// satisfiedBy reports whether a value meets the want.
//
// A type mismatch is unknown rather than false. The signal was read and it is
// simply not the thing this rule expected, which is a bug in the rule; calling
// that "the condition did not hold" would make the bug invisible, because a
// mis-typed rule that silently never fires looks exactly like a healthy
// gateway.
func (w truthWant) satisfiedBy(v signals.Value) Truth {
	switch {
	case !v.Known:
		if w.unknown {
			return TruthTrue
		}
		return TruthUnknown
	case v.Kind != signals.KindBool:
		return TruthUnknown
	case w.known && v.Bool == w.val:
		return TruthTrue
	default:
		return TruthFalse
	}
}

// describe renders the want.
func (w truthWant) describe(name string) string {
	switch {
	case w.unknown:
		return name + " could not be read"
	case w.val:
		return name + " is true"
	default:
		return name + " is false"
	}
}

// signalCond tests a boolean signal.
type signalCond struct {
	name string
	want truthWant
}

func (c signalCond) Test(set *signals.Set) Truth {
	return c.want.satisfiedBy(set.Value(c.name))
}
func (c signalCond) Describe() string  { return c.want.describe(c.name) }
func (c signalCond) Signals() []string { return []string{c.name} }
func (c signalCond) Conditions(set *signals.Set) []string {
	v := set.Value(c.name)
	switch {
	case v.Known && v.Kind != signals.KindBool:
		return []string{fmt.Sprintf("%s is a %s, but %q compares it as a boolean",
			c.name, v.TypeName(), c.Describe())}
	case v.Known:
		return nil
	default:
		return []string{fmt.Sprintf("%s could not be read, so %q could not be determined", c.name, c.Describe())}
	}
}

// comparison operators for numeric conditions.
type comparison int

const (
	cmpLess comparison = iota
	cmpGreaterEqual
	cmpBetween
)

// numericCond tests a numeric signal against a threshold.
type numericCond struct {
	name      string
	cmp       comparison
	threshold float64
	low       float64
	high      float64
}

func (c numericCond) Test(set *signals.Set) Truth {
	v := set.Value(c.name)
	if !v.Known {
		return TruthUnknown
	}
	if v.Kind != signals.KindNumber {
		// A type mismatch is unknown rather than false. The signal exists and
		// was read; it is simply not the thing this rule expected, which is a
		// bug worth surfacing rather than a condition that silently fails.
		return TruthUnknown
	}

	switch c.cmp {
	case cmpLess:
		return boolTruth(v.Number < c.threshold)
	case cmpGreaterEqual:
		return boolTruth(v.Number >= c.threshold)
	case cmpBetween:
		return boolTruth(v.Number >= c.low && v.Number <= c.high)
	}
	return TruthUnknown
}

func (c numericCond) Describe() string {
	switch c.cmp {
	case cmpLess:
		return fmt.Sprintf("%s is below %g", c.name, c.threshold)
	case cmpGreaterEqual:
		return fmt.Sprintf("%s is at least %g", c.name, c.threshold)
	case cmpBetween:
		return fmt.Sprintf("%s is between %g and %g inclusive", c.name, c.low, c.high)
	}
	return c.name + " is unconstrained"
}

func (c numericCond) Signals() []string { return []string{c.name} }

func (c numericCond) Conditions(set *signals.Set) []string {
	v := set.Value(c.name)
	switch {
	case !v.Known:
		return []string{fmt.Sprintf("%s could not be read", c.name)}
	case v.Kind != signals.KindNumber:
		return []string{fmt.Sprintf("%s is a %s, but %q compares it as a number", c.name, v.TypeName(), c.Describe())}
	}
	return nil
}

// stringCond tests a string signal for equality.
type stringCond struct {
	name string
	want string
}

func (c stringCond) Test(set *signals.Set) Truth {
	v := set.Value(c.name)
	if !v.Known {
		return TruthUnknown
	}
	if v.Kind != signals.KindString {
		return TruthUnknown
	}
	return boolTruth(v.Str == c.want)
}

func (c stringCond) Describe() string {
	return fmt.Sprintf("%s is %q", c.name, c.want)
}
func (c stringCond) Signals() []string { return []string{c.name} }

func (c stringCond) Conditions(set *signals.Set) []string {
	v := set.Value(c.name)
	switch {
	case !v.Known:
		return []string{fmt.Sprintf("%s could not be read", c.name)}
	case v.Kind != signals.KindString:
		return []string{fmt.Sprintf("%s is a %s, but %q compares it as text", c.name, v.TypeName(), c.Describe())}
	}
	return nil
}

// notInCond holds when a string signal is anything but a listed value.
type notInCond struct {
	name     string
	unwanted []string
}

func (c notInCond) Test(set *signals.Set) Truth {
	v := set.Value(c.name)
	if !v.Known || v.Kind != signals.KindString {
		return TruthUnknown
	}
	for _, u := range c.unwanted {
		if v.Str == u {
			return TruthFalse
		}
	}
	return TruthTrue
}

func (c notInCond) Describe() string {
	return fmt.Sprintf("%s is none of %s", c.name, strings.Join(quoteAll(c.unwanted), ", "))
}
func (c notInCond) Signals() []string { return []string{c.name} }

func (c notInCond) Conditions(set *signals.Set) []string {
	if !set.Value(c.name).Known {
		return []string{fmt.Sprintf("%s could not be read", c.name)}
	}
	return nil
}

// allCond is a conjunction.
type allCond struct{ conds []Condition }

func (c allCond) Test(set *signals.Set) Truth {
	unknown := []string{}

	for _, inner := range c.conds {
		switch inner.Test(set) {
		case TruthFalse:
			// A false part settles it immediately, even if a later part is
			// unknown: the conjunction is false regardless.
			return TruthFalse
		case TruthUnknown:
			unknown = append(unknown, inner.Describe())
		}
	}

	if len(unknown) > 0 {
		return TruthUnknown
	}
	return TruthTrue
}

func (c allCond) Describe() string  { return joinClauses(describeAll(c.conds), " and ") }
func (c allCond) Signals() []string { return unionSignals(c.conds) }

func (c allCond) Conditions(set *signals.Set) []string { return collectConditions(c.conds, set) }

// anyCond is a disjunction.
type anyCond struct{ conds []Condition }

func (c anyCond) Test(set *signals.Set) Truth {
	unknown := false

	for _, inner := range c.conds {
		switch inner.Test(set) {
		case TruthTrue:
			// Something was established. An unknown alongside a true does not
			// weaken it: the disjunction is true either way.
			return TruthTrue
		case TruthUnknown:
			unknown = true
		}
	}

	if unknown {
		return TruthUnknown
	}
	return TruthFalse
}

func (c anyCond) Describe() string  { return joinClauses(describeAll(c.conds), " or ") }
func (c anyCond) Signals() []string { return unionSignals(c.conds) }

func (c anyCond) Conditions(set *signals.Set) []string { return collectConditions(c.conds, set) }

// notCond inverts a condition, preserving unknown.
type notCond struct{ inner Condition }

func (c notCond) Test(set *signals.Set) Truth {
	switch c.inner.Test(set) {
	case TruthTrue:
		return TruthFalse
	case TruthFalse:
		return TruthTrue
	default:
		return TruthUnknown
	}
}

func (c notCond) Describe() string  { return "not (" + c.inner.Describe() + ")" }
func (c notCond) Signals() []string { return c.inner.Signals() }

func (c notCond) Conditions(set *signals.Set) []string { return c.inner.Conditions(set) }

// boolTruth converts a bool to a Truth.
func boolTruth(b bool) Truth {
	if b {
		return TruthTrue
	}
	return TruthFalse
}

// describeAll renders a list of condition descriptions.
func describeAll(conds []Condition) []string {
	out := make([]string, 0, len(conds))
	for _, c := range conds {
		out = append(out, c.Describe())
	}
	return out
}

// unionSignals returns the distinct signal names a set of conditions reads.
func unionSignals(conds []Condition) []string {
	seen := map[string]bool{}
	var out []string

	for _, c := range conds {
		for _, n := range c.Signals() {
			if seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// collectConditions gathers the reasons a set of conditions could not be
// determined.
//
// The reasons are gathered rather than only the first one, because a rule
// reading four signals where two are unreadable should say which two. A
// single generic "insufficient data" is not actionable.
func collectConditions(conds []Condition, set *signals.Set) []string {
	var out []string
	seen := map[string]bool{}

	for _, c := range conds {
		for _, reason := range c.Conditions(set) {
			if seen[reason] {
				continue
			}
			seen[reason] = true
			out = append(out, reason)
		}
	}
	sort.Strings(out)
	return out
}

// joinClauses renders a list with a separator, parenthesising where needed.
func joinClauses(parts []string, sep string) string {
	if len(parts) == 0 {
		return "nothing"
	}
	if len(parts) == 1 {
		return parts[0]
	}

	// A nested clause is parenthesised so that "a and (b or c)" does not
	// render as "a and b or c", which reads as a different condition.
	out := make([]string, 0, len(parts))
	for i, p := range parts {
		if i > 0 {
			out = append(out, strings.TrimSpace(sep))
		}
		if strings.Contains(p, " and ") || strings.Contains(p, " or ") {
			p = "(" + p + ")"
		}
		out = append(out, p)
	}
	return strings.Join(out, " ")
}

// quoteAll quotes a list of strings.
func quoteAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, fmt.Sprintf("%q", s))
	}
	return out
}
