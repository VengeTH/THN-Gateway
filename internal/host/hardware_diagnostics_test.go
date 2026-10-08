package host

// Diagnostic tests for the M7.1 analyzer's unknowns.
//
// # Why an analyzer needs diagnostics at all
//
// M7.1 reports things as "unknown" that are not capability probes: a link
// speed the driver never reported, a wireless mode the host did not state.
// Those arrive at the analyzer as a zero and an empty string, and a zero and
// an empty string say nothing about why.
//
// So an operator reading "spare0: speed unknown" had no way to tell a NIC
// whose driver has no speed attribute — entirely normal on a USB adapter — from
// a sysfs read that was refused, or from an observation that never happened.
// All three printed the same word.
//
// # What these assert
//
// Every unknown the analysis reaches names a probe, and that probe names a
// stage. An unknown with no cause is the failure this file exists to prevent.

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/network"
)

// unknownProbeDevice builds a host whose spare port has no speed attribute,
// with the observation layer's own probe attached — which is what a real
// snapshot carries, and what makes the explanation possible.
func unknownProbeDevice() *Device {
	d := FromSnapshot(&network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "uplink0", Index: 2, MAC: "3c:ec:ef:cc:00:01", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true,
				State: network.LinkUp, SpeedMbps: 1000},
			{Name: "spare0", Index: 3, MAC: "3c:ec:ef:cc:00:02", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true,
				State: network.LinkDown},
		},
		Addresses: []network.Address{
			{Family: "inet", CIDR: "203.0.113.20/24", Interface: "uplink0"},
		},
		Routes: []network.Route{
			{Destination: "default", Gateway: "203.0.113.1",
				Interface: "uplink0", Default: true},
		},
	})

	// What internal/network's sysfs source would have recorded for the read
	// that came back empty.
	d.Probes = []network.Probe{
		{
			Subsystem: "link-speed", Operation: "sysfs-speed",
			Stage: network.StageLocate, Outcome: network.ProbeToolUnavailable,
			Path:   "/sys/class/net/spare0/speed",
			Detail: "the file is not present",
			Reason: "open /sys/class/net/spare0/speed: no such file or directory",
		},
	}
	return d
}

// TestAnUnknownSpeedNamesItsCause is the central case.
//
// The point is not that the analysis says "speed unknown" — it already did —
// but that it now says WHY, in a form that points at the machine.
func TestAnUnknownSpeedNamesItsCause(t *testing.T) {
	intel := AnalyzeHardware(unknownProbeDevice())

	var found bool
	for _, u := range intel.Unknowns {
		if u.Question != "link-speed" || u.Subject != "spare0" {
			continue
		}
		found = true

		if u.Detail == "" {
			t.Error("the unknown carries no explanation")
		}
		// The probe is the part that answers "which stage stopped".
		if u.Probe.Subsystem != "link-speed" {
			t.Errorf("probe subsystem = %q, want link-speed; the cause was not attached",
				u.Probe.Subsystem)
		}
		if u.Probe.Stage == "" || u.Probe.Outcome == "" {
			t.Errorf("the probe names no stage and no outcome: %+v", u.Probe)
		}
		if u.Probe.Reason == "" {
			t.Error("the probe carries no underlying reason; an unknown with no cause is the failure being fixed")
		}
		if !strings.Contains(u.Probe.Reason, "no such file") {
			t.Errorf("the kernel's own error was not preserved: %q", u.Probe.Reason)
		}
	}
	if !found {
		t.Fatalf("the spare port's unknown speed was not reported as an unknown: %+v", intel.Unknowns)
	}
}

// TestAnUncausedUnknownSaysSoRatherThanBeingSilent is the fallback case.
//
// When the observation carried no probe for the read, the analysis must still
// emit an unknown that admits it is unexplained. Returning nothing would make
// the absence invisible, and that is the original bug.
func TestAnUncausedUnknownSaysSoRatherThanBeingSilent(t *testing.T) {
	// A device with no probes at all, as a hand-built fixture has.
	d := FromSnapshot(&network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "spare0", Index: 2, MAC: "3c:ec:ef:dd:00:01", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkDown},
		},
	})

	intel := AnalyzeHardware(d)

	for _, u := range intel.Unknowns {
		if u.Question != "link-speed" {
			continue
		}
		if u.Probe.Subsystem == "" || u.Probe.Outcome == "" {
			t.Errorf("an unknown was emitted with no probe record at all: %+v", u)
		}
		if !strings.Contains(u.Probe.Detail, "unexplained") &&
			!strings.Contains(u.Probe.Detail, "no probe") {
			t.Errorf("an uncaused unknown does not admit that it is uncaused: %+v", u.Probe)
		}
	}
}

// TestAnUninspectableHostExplainsItself covers the whole-host unknown.
func TestAnUninspectableHostExplainsItself(t *testing.T) {
	for name, d := range map[string]*Device{
		"nil device":  nil,
		"unsupported": {Supported: false},
	} {
		t.Run(name, func(t *testing.T) {
			intel := AnalyzeHardware(d)

			if len(intel.Unknowns) == 0 {
				t.Fatal("an uninspectable host produced no unknown explaining why")
			}
			u := intel.Unknowns[0]
			if u.Question != "host-inspection" {
				t.Errorf("question = %q, want host-inspection", u.Question)
			}
			if u.Probe.Outcome != network.ProbeNotChecked {
				t.Errorf("outcome = %q, want not_checked", u.Probe.Outcome)
			}
			if u.Detail == "" {
				t.Error("the unknown carries no explanation")
			}
		})
	}
}

// TestAWirelessInterfaceWithNoModeExplainsWhyAPIsNotInferred is the case the
// M7.1 brief calls out by name.
//
// "Do not infer wireless AP capability unless it is actually observed" is a
// rule about restraint, and a restraint with no explanation reads as an
// oversight. The unknown has to say that the mode was not reported.
func TestAWirelessInterfaceWithNoModeExplainsWhyAPIsNotInferred(t *testing.T) {
	d := FromSnapshot(&network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			// A mode-less radio, as `ip` reports it when the wireless object
			// carries no mode field. The link kind is still wlan — the parser
			// decides that from the presence of the wireless object, not from
			// the mode — so this is the exact shape the rule exists for: real
			// hardware, known to be a radio, mode unstated.
			{Name: "radio0", Index: 2, MAC: "3c:ec:ef:ee:00:01", Kind: "wlan",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkUp,
				WirelessMode: ""},
		},
	})

	intel := AnalyzeHardware(d)

	var found bool
	for _, u := range intel.Unknowns {
		if u.Question != "wireless-mode" {
			continue
		}
		found = true
		if !strings.Contains(u.Detail, "access-point") {
			t.Errorf("the unknown does not say what was deliberately not inferred: %q", u.Detail)
		}
		if u.Probe.Outcome == "" {
			t.Error("the unknown carries no probe record")
		}
	}
	if !found {
		t.Error("a radio with no reported mode produced no unknown; the analysis is silent about it")
	}
}

// TestAnInterfaceThatDoesReportAModeRaisesNoUnknown is the other half.
//
// The rule is about an unobserved mode. A radio whose mode WAS reported must
// not produce an unknown, or the diagnostic becomes noise and stops being read.
func TestAnInterfaceThatDoesReportAModeRaisesNoUnknown(t *testing.T) {
	d := FromSnapshot(&network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "radio0", Index: 2, MAC: "3c:ec:ef:ee:00:02", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkUp,
				WirelessMode: WirelessModeClient, SpeedMbps: 300},
		},
	})

	intel := AnalyzeHardware(d)

	for _, u := range intel.Unknowns {
		if u.Question == "wireless-mode" {
			t.Errorf("an observed mode produced an unknown: %+v", u)
		}
	}
}

// TestAnalysisIsUnchangedByTheAdditionOfDiagnostics guards the M7.1
// guarantee that adding a diagnostic does not change a verdict.
//
// A diagnostic that altered a classification would be worse than no
// diagnostic, because it would make the unknowns load-bearing.
func TestAnalysisIsUnchangedByTheAdditionOfDiagnostics(t *testing.T) {
	withProbes := AnalyzeHardware(unknownProbeDevice())

	// The same host, with the probes removed.
	stripped := unknownProbeDevice()
	stripped.Probes = nil
	withoutProbes := AnalyzeHardware(stripped)

	if len(withProbes.Interfaces) != len(withoutProbes.Interfaces) {
		t.Fatal("the probe records changed the interface count")
	}
	for _, in := range withProbes.Interfaces {
		other, ok := bySystemName(withoutProbes.Interfaces, in.SystemName)
		if !ok {
			t.Fatalf("%s disappeared", in.SystemName)
		}
		for _, role := range IntelligenceRoles() {
			if in.SuitabilityFor(role).Suitability != other.SuitabilityFor(role).Suitability {
				t.Errorf("%s %s suitability changed when probes were removed: %q became %q",
					in.SystemName, role,
					in.SuitabilityFor(role).Suitability,
					other.SuitabilityFor(role).Suitability)
			}
		}
	}
}

// TestForwardingProbeDistinguishesTheThreeAnswers is the sysctl case.
//
// Forwarding is the one setting a gateway cannot work without, and it has
// three answers rather than two: on, off, and unreadable. The third is a THN
// problem and the second is a host problem, and an operator who has been told
// only "forwarding is unavailable" cannot tell which they are looking at.
func TestForwardingProbeDistinguishesTheThreeAnswers(t *testing.T) {
	base := func(value string, errMsg string) *network.SysctlValue {
		return &network.SysctlValue{
			Key: "net.ipv4.ip_forward", Value: value, Error: errMsg,
		}
	}

	cases := []struct {
		name        string
		sysctl      *network.SysctlValue
		wantOutcome network.ProbeOutcome
		wantStage   network.ProbeStage
	}{
		{"enabled", base("1", ""), network.ProbeEvidence, network.StageClassify},
		{"disabled", base("0", ""), network.ProbeNoEvidence, network.StageClassify},
		{"unreadable", base("", "permission denied"), network.ProbeExecutionFailed, network.StageExecute},
		{"no value", base("unknown", ""), network.ProbeParseFailed, network.StageParse},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := FromSnapshot(&network.Snapshot{
				Platform:  "linux",
				Supported: true,
				Sysctl:    []network.SysctlValue{*tc.sysctl},
			})

			var got network.Probe
			for _, p := range d.Probes {
				if p.Subsystem == "forwarding" {
					got = p
				}
			}
			if got.Subsystem == "" {
				t.Fatalf("no forwarding probe was recorded: %+v", d.Probes)
			}
			if got.Outcome != tc.wantOutcome {
				t.Errorf("outcome = %q, want %q", got.Outcome, tc.wantOutcome)
			}
			if got.Stage != tc.wantStage {
				t.Errorf("stage = %q, want %q", got.Stage, tc.wantStage)
			}
			// The kernel's own error must survive, or "unreadable" is just
			// another unexplained word.
			if tc.name == "unreadable" && got.Reason != "permission denied" {
				t.Errorf("reason = %q, want the underlying error verbatim", got.Reason)
			}
		})
	}
}

// TestAnAbsentForwardingKeyIsNotChecked is the "nobody looked" case.
//
// A missing key is not the same as forwarding being off, and it is not the
// same as a failed read. It is THN having nothing to report.
func TestAnAbsentForwardingKeyIsNotChecked(t *testing.T) {
	d := FromSnapshot(&network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Sysctl:    []network.SysctlValue{{Key: "net.ipv4.conf.all.rp_filter", Value: "0"}},
	})

	for _, p := range d.Probes {
		if p.Subsystem != "forwarding" {
			continue
		}
		if p.Outcome != network.ProbeNotChecked {
			t.Errorf("outcome = %q, want not_checked; an absent key is not a value of zero",
				p.Outcome)
		}
		if p.Stage != network.StageNotStarted {
			t.Errorf("stage = %q, want not-started", p.Stage)
		}
	}
}
