//go:build linux

package management

import "testing"

// The ARP Flags column is hexadecimal with an "0x" prefix. Parsing it as
// decimal is a silent failure: every entry is skipped and a reachable gateway
// reports as unreachable, with a result that is indistinguishable from a
// genuine "no".
//
// This class of bug is invisible in review because the failure mode is a
// plausible answer rather than a crash, so the parse is pinned directly.

func TestParseArpFlagsReadsHexWithPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"0x2", 2, true},          // REACHABLE — the ordinary case
		{"0x0", 0, true},          // FAILED, valid syntax
		{"0x1", 1, true},          // incomplete
		{"0x22", 0x22, true},      // REACHABLE | PERMANENT
		{"0x2 ", 2, true},         // trailing space tolerated
		{"", 0, false},            // empty
		{"0x", 0, false},          // prefix with no digits
		{"nonsense", 0, false},    // not a number at all
		{"zz", 0, false},          // not hex
	}

	for _, tc := range cases {
		got, ok := parseArpFlags(tc.in)
		if ok != tc.ok {
			t.Errorf("parseArpFlags(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("parseArpFlags(%q) = %#x, want %#x", tc.in, got, tc.want)
		}
	}
}

// TestParseArpFlagsRejectsDecimalMisreading pins the specific regression.
//
// "0x2" read as base 10 is not 2 — it is an error. If a future change drops
// the base-16 argument, this fails rather than quietly reporting every host
// as unreachable.
func TestParseArpFlagsRejectsDecimalMisreading(t *testing.T) {
	if _, ok := parseArpFlags("0x2"); !ok {
		t.Fatal("a well-formed kernel flags word was rejected; it must parse as hexadecimal")
	}

	// The literal "2" is what a decimal reader would see if the prefix were
	// stripped first. It must still be read as hex, i.e. 0x2 == 2, and the
	// caller's FAILED check (flags == 0) must not fire on it.
	got, ok := parseArpFlags("2")
	if !ok || got != 2 {
		t.Fatalf(`parseArpFlags("2") = %#x, %v; want 0x2, true`, got, ok)
	}
}