package signals_test

import (
	"net/netip"
	"testing"
	"time"

	qostc "github.com/VengeTH/THN-Gateway/internal/qos/tc"
	"github.com/VengeTH/THN-Gateway/internal/signals"
	"github.com/VengeTH/THN-Gateway/internal/validation"
)

// Helpers shared by the signals tests. They live in a separate file so the
// test body stays about assertions rather than construction.

// detailContains reports whether a named signal's explanation mentions want.
//
// The assertions in this package frequently need to check that a signal says
// something specific, because the explanation is the only thing an operator
// reading from a distance has. Writing that as a one-liner per assertion would
// bury the assertion.
func detailContains(t *testing.T, set *signals.Set, name, want string) bool {
	t.Helper()

	s, ok := set.Get(name)
	if !ok {
		t.Fatalf("the set has no %q signal; names are %v", name, set.Names())
	}
	return contains(s.Detail, want)
}

// contains is a substring test, named so the call sites read as prose.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// mustAddr parses an address or fails the test.
func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()

	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("the test fixture contains an unparseable address %q: %v", s, err)
	}
	return a
}

// validationResult builds a validation result with the given counts.
func validationResult(errs, warns, infos int) validation.Result {
	r := validation.Result{
		Valid:        errs == 0,
		ErrorCount:   errs,
		WarningCount: warns,
		InfoCount:    infos,
		Layers:       []validation.Layer{validation.LayerStatic, validation.LayerLive},
	}
	for i := 0; i < errs; i++ {
		r.Findings = append(r.Findings, validation.Finding{
			Field: "test", Severity: validation.SeverityError, Message: "an error",
		})
	}
	for i := 0; i < warns; i++ {
		r.Findings = append(r.Findings, validation.Finding{
			Field: "test", Severity: validation.SeverityWarning, Message: "a warning",
		})
	}
	for i := 0; i < infos; i++ {
		r.Findings = append(r.Findings, validation.Finding{
			Field: "test", Severity: validation.SeverityInfo, Message: "an info",
		})
	}
	return r
}

// qostcAbsent is what a kernel reports when no qdisc is attached.
func qostcAbsent() qostc.Snapshot {
	return qostc.Snapshot{Interface: "eth0", Present: false}
}

// qostcDefaultQueue is what a kernel reports when the default queue is in
// place: a qdisc that exists and does not shape.
func qostcDefaultQueue() qostc.Snapshot {
	return qostc.Snapshot{
		Interface: "eth0",
		Present:   true,
		Root: qostc.Stats{
			Algorithm: "pfifo_fast",
			Handle:    "0:",
			Root:      true,
			Bytes:     2048,
			Packets:   16,
		},
	}
}

// qostcCake is a working shaper.
func qostcCake() qostc.Snapshot {
	return qostc.Snapshot{
		Interface: "eth0",
		Present:   true,
		Root: qostc.Stats{
			Algorithm:     "cake",
			Handle:        "8001:",
			Root:          true,
			Bytes:         1 << 30,
			Packets:       1_000_000,
			Dropped:       10_000,
			Overlimits:    500_000,
			BandwidthMbps: 110,
		},
	}
}

// ensure the time import is used by the helpers above.
var _ = time.Second
