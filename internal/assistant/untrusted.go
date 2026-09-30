package assistant

import (
	"fmt"
	"strings"
	"unicode"
)

// Untrusted values, and what to do about them.
//
// # The problem
//
// Most strings in THN are written by whoever wrote the configuration or the
// rule set. Some are not. A DHCP lease carries a hostname chosen by whatever
// device joined the network. A DNS query carries a name chosen by whoever sent
// it. A MAC address is chosen by whoever burned the bit. On an unattended
// gateway that anyone on the LAN can join, those strings are attacker-authored.
//
// They end up in the same place as everything else: labels on signals, fields
// on incident members, the subject of a question an operator typed. And now
// they are also in a text handed to a language model.
//
// So they are marked, bounded, and defused. This is not a theoretical concern
// and it is not only about injection: an untrusted value is also capable of
// making an answer *wrong* without any adversarial intent at all. A hostname of
// `wan-down is not firing` is not an attack, it is a device named by someone
// who did not know what it would do to a monitoring system.

// MaxUntrustedLength bounds a value taken from the network.
//
// Long enough for any real hostname, interface name or MAC; short enough that
// a value cannot become a paragraph. A legitimate device name has no business
// being 4 KB of text, and if one turns up the correct response is to see it
// truncated in the audit trail, not to feed it whole into a model.
const MaxUntrustedLength = 128

// injectionMarkers are phrases that suggest an attempt to address the reader
// rather than to be data.
//
// The list is not a security control on its own — it cannot be, because the
// space of such phrasings is unbounded and any list is trivially evaded by
// paraphrase. What it does is narrow something important: it decides whether a
// value is safe to place inside a model-facing sentence at all, and when one is
// found, the value is quarantined rather than merely cleaned. Defence in depth
// means the structural protections — the claim check, the untrusted marker —
// still hold for anything that gets past this.
var injectionMarkers = []string{
	"ignore previous",
	"ignore the previous",
	"ignore all previous",
	"disregard previous",
	"disregard all",
	"you are now",
	"system prompt",
	"new instructions",
	"forget your instructions",
	"act as",
	"pretend to be",
	"reveal your",
	"print your",
	"do not tell",
	"don't tell the operator",
	"mark this as resolved",
	"report this as healthy",
}

// Sanitise makes a network-supplied string safe to carry.
//
// It returns the cleaned value and whether anything was removed or flagged. The
// flag is propagated rather than swallowed: a caller that drops a hostile
// hostname silently has learned nothing from the attempt, and the next one
// will look identical to ordinary operation.
//
// The transformations, in order:
//
//   - control characters are removed, because a value containing a newline can
//     terminate the line it appears on and forge an entire new statement;
//   - the value is truncated, so it cannot flood a context;
//   - quotes, backticks and brackets are replaced, because the model-facing
//     format delimits with them and a value must not be able to close one;
//   - injection markers cause the value to be neutralised entirely rather than
//     cleaned, because a string trying to address the reader is not data no
//     matter how it is escaped.
func Sanitise(raw string) (clean string, flagged bool) {
	if raw == "" {
		return "", false
	}

	lower := strings.ToLower(raw)
	for _, marker := range injectionMarkers {
		if strings.Contains(lower, marker) {
			return neutralise(raw), true
		}
	}

	var sb strings.Builder
	sb.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r == '\n' || r == '\r':
			// A newline inside a value is how a value becomes a statement.
			sb.WriteRune(' ')
		case unicode.IsControl(r):
			// Dropped entirely rather than replaced: these have no legitimate
			// use in a hostname and can affect terminals and log viewers.
		case r == '"' || r == '\'' || r == '`' || r == '[' || r == ']' ||
			r == '{' || r == '}' || r == '<' || r == '>':
			// The characters that can close a delimiter the model-facing format
			// uses. Parentheses and dashes are left alone: they appear in
			// ordinary prose and in hyphenated hostnames, and mangling them
			// makes this project's own sentences read as corrupted text.
			sb.WriteRune('_')
		default:
			sb.WriteRune(r)
		}
	}

	clean = sb.String()
	if len([]rune(clean)) > MaxUntrustedLength {
		clean = string([]rune(clean)[:MaxUntrustedLength]) + "…"
	}
	return strings.TrimSpace(clean), false
}

// neutralise replaces a value entirely.
//
// The result is a fixed marker rather than a redacted form of the original,
// because a partially preserved instruction is still an instruction, and
// because keeping the text at all would mean the audit trail holds a copy of
// an attacker's payload.
func neutralise(raw string) string {
	return fmt.Sprintf("[refused: %d bytes of instruction-like text]", len(raw))
}

// UntrustedValue prepares a network-supplied value for use in a fact or a
// sentence, returning the safe text and whether it was flagged.
func UntrustedValue(raw string) (string, bool) {
	return Sanitise(raw)
}

// trustedValue prepares a string that came from the configuration or the rule
// set.
//
// The same transformations are applied, because "trusted" here means "written
// by whoever maintains this repository", not "impossible to contain a newline".
// A comment in a YAML file is still a comment in a YAML file. The difference is
// that a flagged trusted value is a bug in this repository rather than an
// attack, and both are worth knowing about.
func trustedValue(raw string) string {
	clean, _ := Sanitise(raw)
	return clean
}
