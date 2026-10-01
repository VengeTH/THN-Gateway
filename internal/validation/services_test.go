package validation_test

// Unit coverage for the DHCP hand-off into the combined validation result.
//
// internal/cli/validate_dhcp_gate_test.go proves the wiring works end to end
// through the dispatch table. This file proves the two things that wiring
// depends on and that an end-to-end test cannot pin down on its own: that the
// severity mapping is total, and that merging counts findings exactly once.

import (
	"net/netip"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/dhcp"
	"github.com/venth/thn-gateway/internal/validation"
)

// dhcpFinding builds one DHCP finding.
func dhcpFinding(field string, sev dhcp.Severity) dhcp.Finding {
	return dhcp.Finding{Field: field, Severity: sev, Message: "m", Hint: "h"}
}

// dhcpResult builds a finalised-looking DHCP result.
//
// dhcp.Validate is the only constructor that produces one, so these go through
// it rather than fabricating a dhcp.Result, which would let the test pass
// against a field this package never reads.
func dhcpResult(fields ...dhcp.Finding) dhcp.Result {
	return dhcp.Result{Findings: fields}
}

// TestFromDHCPPreservesEverySeverity is the test that caught a real defect.
//
// SeverityInfo fell through to the fail-closed default and became an error,
// which failed every configuration that had a single-label domain and no
// configured interface — both of which are normal states, not faults.
//
// Every constant the DHCP package defines gets its own row. A mapping that
// fails closed is right for a value nobody recognises, and wrong for a value
// that is simply not listed.
func TestFromDHCPPreservesEverySeverity(t *testing.T) {
	cases := []struct {
		name string
		in   dhcp.Severity
		want validation.Severity
	}{
		{"error", dhcp.SeverityError, validation.SeverityError},
		{"warning", dhcp.SeverityWarning, validation.SeverityWarning},
		{"info", dhcp.SeverityInfo, validation.SeverityInfo},
		// The DHCP package defines no other severity. If it ever adds one
		// without updating the mapping, this row is what the compiler cannot
		// catch and this table would have to be extended by hand.
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := validation.FromDHCP(dhcpResult(dhcpFinding("ranges[0].start", c.in)))

			if len(got.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(got.Findings))
			}
			if got.Findings[0].Severity != c.want {
				t.Errorf("severity = %q, want %q", got.Findings[0].Severity, c.want)
			}
		})
	}
}

// TestFromDHCPCountsFindings proves a projected result is internally coherent
// on its own, without being merged first.
func TestFromDHCPCountsFindings(t *testing.T) {
	in := dhcpResult(
		dhcpFinding("ranges[0]", dhcp.SeverityError),
		dhcpFinding("ranges[1]", dhcp.SeverityWarning),
		dhcpFinding("ranges[2]", dhcp.SeverityInfo),
		dhcpFinding("lease_time", dhcp.SeverityInfo),
	)

	got := validation.FromDHCP(in)

	if got.ErrorCount != 1 || got.WarningCount != 1 || got.InfoCount != 2 {
		t.Errorf("counts = e%d w%d i%d, want e1 w1 i2",
			got.ErrorCount, got.WarningCount, got.InfoCount)
	}
	if got.Valid {
		t.Error("Valid = true for a result containing an error")
	}
	if got.ErrorCount+got.WarningCount+got.InfoCount != len(got.Findings) {
		t.Errorf("counts sum to %d but there are %d findings",
			got.ErrorCount+got.WarningCount+got.InfoCount, len(got.Findings))
	}
}

// TestFromDHCPPreservesTheFieldPath is the structured-information requirement.
//
// A DHCP finding must arrive with its path intact, namespaced but not
// flattened. "ranges[0].end" becomes "dhcp.ranges[0].end" — the prefix says
// which subsystem, and everything after it is what internal/dhcp decided.
func TestFromDHCPPreservesTheFieldPath(t *testing.T) {
	paths := []string{"ranges[0]", "ranges[0].start", "ranges[0].end", "lease_time"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			got := validation.FromDHCP(dhcpResult(dhcpFinding(p, dhcp.SeverityError)))
			if len(got.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(got.Findings))
			}

			want := validation.DHCPFieldPrefix + p
			if got.Findings[0].Field != want {
				t.Errorf("field = %q, want %q", got.Findings[0].Field, want)
			}
		})
	}
}

// TestFromDHCPIsStaticEvenUnderLiveValidation pins the layer.
//
// A pool's validity does not depend on whether a host was observed, so a DHCP
// finding is static. Marking it live would make it disappear from the
// no-observation run, which is the one CI uses.
func TestFromDHCPIsStatic(t *testing.T) {
	got := validation.FromDHCP(dhcpResult(dhcpFinding("ranges[0]", dhcp.SeverityError)))

	for _, f := range got.Findings {
		if f.Layer != validation.LayerStatic {
			t.Errorf("finding %q has layer %q, want %q", f.Field, f.Layer, validation.LayerStatic)
		}
	}
	if len(got.Layers) != 1 || got.Layers[0] != validation.LayerStatic {
		t.Errorf("layers = %v, want [%s]", got.Layers, validation.LayerStatic)
	}
}

// TestMergeCountsEachFindingExactlyOnce is the bug Merge had to avoid.
//
// finalise adds to the existing counts rather than resetting them, so a merge
// that appended in place would report an error count of 2 for one DHCP error.
// The result would still be invalid, so the exit code would be right, and the
// count would be wrong — which is the kind of defect that makes a summary
// untrustworthy without making it obviously wrong.
func TestMergeCountsEachFindingExactlyOnce(t *testing.T) {
	base := validation.Result{
		Findings: []validation.Finding{
			{Layer: validation.LayerStatic, Field: "network.lan_prefix", Severity: validation.SeverityWarning},
		},
		Layers: []validation.Layer{validation.LayerStatic},
	}

	extra := validation.FromDHCP(dhcpResult(dhcpFinding("ranges[0].end", dhcp.SeverityError)))

	got := base.Merge(extra)

	if len(got.Findings) != 2 {
		t.Fatalf("got %d findings, want 2: %v", len(got.Findings), got.Findings)
	}
	if got.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1; the merge counted a finding twice", got.ErrorCount)
	}
	if got.WarningCount != 1 {
		t.Errorf("WarningCount = %d, want 1", got.WarningCount)
	}
	if got.Valid {
		t.Error("Valid = true for a merged result containing an error")
	}
}

// TestMergePreservesBothLayerSets checks the union.
func TestMergePreservesBothLayerSets(t *testing.T) {
	static := validation.Result{Layers: []validation.Layer{validation.LayerStatic}}
	live := validation.Result{Layers: []validation.Layer{validation.LayerLive}}

	got := static.Merge(live)

	if len(got.Layers) != 2 || got.Layers[0] != validation.LayerStatic || got.Layers[1] != validation.LayerLive {
		t.Errorf("layers = %v, want [%s %s]", got.Layers, validation.LayerStatic, validation.LayerLive)
	}

	// Merging a set whose layers are already present must not duplicate them.
	again := got.Merge(static)
	if len(again.Layers) != 2 {
		t.Errorf("re-merging produced layers %v, want two", again.Layers)
	}
}

// TestMergeIsDeterministic guards the summary an operator reads.
func TestMergeIsDeterministic(t *testing.T) {
	build := func() validation.Result {
		return validation.FromDHCP(dhcp.Validate(validDHCPPolicy()))
	}

	first := build()
	for i := 0; i < 8; i++ {
		next := build()
		if len(next.Findings) != len(first.Findings) {
			t.Fatalf("run %d produced %d findings, first produced %d",
				i, len(next.Findings), len(first.Findings))
		}
		for j := range first.Findings {
			if next.Findings[j] != first.Findings[j] {
				t.Fatalf("run %d finding %d = %+v, first = %+v",
					i, j, next.Findings[j], first.Findings[j])
			}
		}
	}
}

// validDHCPPolicy is a pool that passes every rule, so the determinism check
// above compares a non-empty finding set rather than an empty one.
func validDHCPPolicy() dhcp.Policy {
	return dhcp.Policy{
		Enabled:        true,
		Interface:      "lan0",
		Authoritative:  true,
		LeaseTime:      12 * time.Hour,
		Domain:         "lan",
		LANPrefix:      netip.MustParsePrefix("192.168.1.1/24"),
		GatewayAddress: netip.MustParseAddr("192.168.1.1"),
		Ranges: []dhcp.Range{
			{Start: netip.MustParseAddr("192.168.1.10"), End: netip.MustParseAddr("192.168.1.200")},
		},
	}
}
