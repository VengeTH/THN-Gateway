// Package signals declares the observations THN can make about a gateway, in a
// form that rules can be evaluated against.
//
// # Why a signal layer exists
//
// Every subsystem already reports its own state in its own vocabulary:
// network.Snapshot carries interface links, dhcp.Summary carries pool
// utilisation, qos/tc carries queue counters, diff.Observed carries a
// flattened comparison projection. A rule that wanted to say "the uplink is
// down" would otherwise have to reach into four packages and reconcile four
// shapes, and every new subsystem would mean every rule author learning a new
// API.
//
// The signal layer is the single vocabulary those observations are projected
// into. It is deliberately thin: a name, a typed value, a timestamp, and an
// explanation. It adds no new information and makes no judgements. Its only
// job is to make "what did THN see" a thing rules can ask about.
//
// # Unknown is not false
//
// This is the property the whole package exists to get right.
//
// A gateway that THN cannot inspect fully — because a read failed, because the
// platform is unsupported, because the tool it needs is not installed — has
// not reported that everything is fine, and it has not reported that anything
// is broken. It has reported nothing. Conflating that with false is the single
// most damaging thing an alerting system can do, because it produces confident
// conclusions from absent data.
//
// So every Value carries a Known flag, and Value.False is only ever what a
// successful read actually said. A rule that tests a signal it could not read
// gets TruthUnknown and does not fire. An operator looking at an incident can
// then trust that the incident means something was observed, not merely that
// something failed to be.
//
// # Every signal explains itself
//
// Detail is not decoration. THN is developed against an unattended device, so
// the person reading an incident cannot go and look. "wan.link.up = false" is
// a claim; "wan.link.up = false: eth0 is present but the carrier reports it
// down" is something an operator can act on from the other side of the world.
//
// # Nothing here reads the host
//
// Derivation happens at the boundary, from types the caller already has. This
// package imports no os/exec and no guard, so the repository-wide test that
// forbids unguarded process spawning passes without needing an exemption.
package signals

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Kind is the type of a signal's value.
type Kind string

const (
	// KindBool is a true/false observation.
	KindBool Kind = "bool"

	// KindNumber is a numeric observation, such as a ratio or a count.
	KindNumber Kind = "number"

	// KindString is a textual observation, such as an algorithm name.
	KindString Kind = "string"
)

// Value is a typed observation, with an explicit statement of whether it was
// actually read.
//
// The three typed fields are mutually exclusive. Construct one through Bool,
// Number, String or Unknown rather than by filling the struct directly: the
// constructors are what keep a value from carrying, say, a string in the
// numeric field, which would compare unpredictably.
//
// The json tags are explicit because this struct is serialised into every
// `--json` response that carries observations or evidence. Untagged, Go emits
// `Kind`, `Known`, `Number`, `Bool` and `Str` — capitals, amid a document whose
// other fields are lower-case — and every consumer then needs to know that this
// one struct is the odd one out.
type Value struct {
	// Kind is the value's type.
	Kind Kind `json:"kind"`

	// Known reports whether the value was actually read.
	//
	// This is the field that carries the whole design. A false value and an
	// unreadable value look identical without it, and every rule built on
	// top would have to rediscover that difference.
	Known bool `json:"known"`

	// Number, Bool and Str hold the value, per Kind.
	Number float64 `json:"number"`
	Bool   bool    `json:"bool"`
	Str    string  `json:"str"`
}

// Bool returns a known boolean value.
func Bool(b bool) Value { return Value{Kind: KindBool, Known: true, Bool: b} }

// Number returns a known numeric value.
func Number(f float64) Value { return Value{Kind: KindNumber, Known: true, Number: f} }

// String returns a known textual value.
func String(s string) Value { return Value{Kind: KindString, Known: true, Str: s} }

// Unknown returns a value of the given kind that was not read.
//
// The kind still matters: a rule comparing a number needs to know it was
// expecting a number, so it can report a type mismatch rather than a silent
// miss.
func Unknown(k Kind) Value { return Value{Kind: k, Known: false} }

// String renders the value for display.
func (v Value) String() string {
	if !v.Known {
		return "unknown"
	}
	switch v.Kind {
	case KindBool:
		return strconv.FormatBool(v.Bool)
	case KindNumber:
		return strconv.FormatFloat(v.Number, 'f', -1, 64)
	case KindString:
		return v.Str
	}
	return "?"
}

// TypeName reports the value's type, for error messages.
func (v Value) TypeName() string {
	if !v.Known {
		return "unknown"
	}
	return string(v.Kind)
}

// Signal is one observation, at one moment, about one thing.
type Signal struct {
	// Name identifies the signal, as "subsystem.subject.metric".
	//
	// Names are part of the contract: they appear in incident output, in
	// suppression rules and in tests, so renaming one is a breaking change to
	// everything downstream of it.
	Name string `json:"name"`

	// Source names the subsystem that produced the signal, e.g. "network".
	// It is a first-class field rather than parsed out of Name because
	// grouping by source is one of the most common correlation needs.
	Source string `json:"source"`

	// Value is what was observed.
	Value Value `json:"value"`

	// At is when the observation was taken.
	//
	// Every signal carries its own timestamp rather than sharing one from an
	// enclosing snapshot, because the sources are not read at the same instant
	// and pretending otherwise would make a rate computed across them wrong.
	At time.Time `json:"at"`

	// Labels are additional dimensions, such as an interface name.
	Labels map[string]string `json:"labels,omitempty"`

	// Detail explains what was observed, in terms an operator can act on from
	// a device they cannot reach.
	Detail string `json:"detail,omitempty"`
}

// Label returns a label value, or "" when it is absent.
func (s Signal) Label(key string) string {
	if s.Labels == nil {
		return ""
	}
	return s.Labels[key]
}

// LabelKeys returns the label names in sorted order.
//
// Sorted so that two signals with the same labels render identically, which is
// what makes an incident's contributor list diffable between runs.
func (s Signal) LabelKeys() []string {
	out := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LabelFingerprint renders the labels as a stable string.
//
// The keys are sorted and the values escaped, so two different label sets
// cannot produce the same fingerprint by containing the same characters in a
// different order. A collision here would merge two unrelated groups into one
// incident, which is the failure this function exists to make impossible.
func (s Signal) LabelFingerprint() string {
	if len(s.Labels) == 0 {
		return ""
	}

	parts := make([]string, 0, len(s.Labels))
	for _, k := range s.LabelKeys() {
		parts = append(parts, k+"="+escapeLabel(s.Labels[k]))
	}
	return strings.Join(parts, ",")
}

// escapeLabel makes a label value safe to join with commas.
//
// Labels arrive from configuration, interface names and hostnames, any of
// which may contain a comma or an equals sign. Without escaping, a hostname
// containing a comma would forge a label boundary and let one device's labels
// impersonate another's.
func escapeLabel(v string) string {
	return strings.NewReplacer(
		`\`, `\\`,
		`,`, `\,`,
		`=`, `\=`,
	).Replace(v)
}

// Set is the collection of signals observed at one moment.
//
// It is immutable once built. Rules read it concurrently and a collector may
// be writing the next one, so a mutable set would be a data race rather than
// merely awkward.
type Set struct {
	// At is when the set was assembled.
	At time.Time `json:"at"`

	byName map[string]Signal
	order  []string
}

// NewSet builds a set from signals, indexed by name.
//
// The order is the order given, not sorted, because the order reflects the
// sequence the collector read them in and that sequence is worth preserving
// for display. Lookups are by name and are order-independent.
func NewSet(at time.Time, sigs ...Signal) *Set {
	s := &Set{
		At:     at,
		byName: make(map[string]Signal, len(sigs)),
		order:  make([]string, 0, len(sigs)),
	}

	for _, sig := range sigs {
		if sig.Name == "" {
			continue
		}
		if _, dup := s.byName[sig.Name]; dup {
			// A duplicate name is a collector bug, and silently keeping the
			// last one would make the result depend on read order. Keeping the
			// first and recording nothing is worse than ignoring the second,
			// because a collector that emits a name twice has bigger problems
			// than the one this hides.
			continue
		}
		s.byName[sig.Name] = sig
		s.order = append(s.order, sig.Name)
	}
	return s
}

// Get returns a signal by name.
func (s *Set) Get(name string) (Signal, bool) {
	if s == nil {
		return Signal{}, false
	}
	sig, ok := s.byName[name]
	return sig, ok
}

// Value returns a signal's value by name, or an unknown value when the name is
// absent.
//
// An absent signal is unknown, not false. A rule asking about a signal that
// was never emitted is asking a question the collector could not answer.
func (s *Set) Value(name string) Value {
	sig, ok := s.Get(name)
	if !ok {
		return Unknown(KindBool)
	}
	return sig.Value
}

// All returns the signals in insertion order.
func (s *Set) All() []Signal {
	if s == nil {
		return nil
	}
	out := make([]Signal, 0, len(s.order))
	for _, name := range s.order {
		out = append(out, s.byName[name])
	}
	return out
}

// Names returns the signal names in insertion order.
func (s *Set) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// Len returns the number of signals.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.order)
}

// BySource returns the signals from one source, in insertion order.
func (s *Set) BySource(source string) []Signal {
	if s == nil {
		return nil
	}
	var out []Signal
	for _, name := range s.order {
		if sig := s.byName[name]; sig.Source == source {
			out = append(out, sig)
		}
	}
	return out
}

// Unknown returns the signals whose value could not be read.
//
// This is the diagnostic an operator actually wants from a degraded gateway:
// not just "something is wrong" but "here is everything I could not see". On a
// device that cannot be reached, it is usually the whole story.
func (s *Set) Unknown() []Signal {
	if s == nil {
		return nil
	}
	var out []Signal
	for _, name := range s.order {
		if sig := s.byName[name]; !sig.Value.Known {
			out = append(out, sig)
		}
	}
	return out
}

// ByName returns a signal's name split into its dotted parts.
//
// "wan.link.up" becomes ["wan", "link", "up"]. A name that is not dotted is
// returned as a single part, because a rule naming a top-level signal is
// legitimate and should not be an error.
func ByName(name string) []string {
	return strings.Split(name, ".")
}

// SourceOf returns the source part of a signal name.
//
// For "wan.link.up" it returns "wan", which is the subsystem. The value is
// also available as Signal.Source, which is authoritative; this is for the
// cases where only a name is to hand, such as a rule referring to a signal it
// never received.
func SourceOf(name string) string {
	parts := ByName(name)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
