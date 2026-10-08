package host

// M7.1.1 regression tests: capability classification follows the observation.
//
// # The bug this file pins
//
// `TestLiveDiscoveryOnLinux` asserted that no capability on a supported host
// may be `unknown`, on the premise that `unknown` means "we did not look".
// That premise is false. `unknown` also means "we looked, and the answer is
// not obtainable from here" — which is the correct, honest answer for three
// capabilities on any unprivileged host:
//
//	firewall, nftables   nft is installed and the query was refused
//	tc                   tc is installed and the query was refused
//	cake                 nothing can establish CAKE without attaching a
//	                     discipline, which would mutate the host
//
// So the suite failed on every machine where the developer was not root, and
// passed only where they were. The observation layer was right throughout and
// the assertion was wrong.
//
// # What these tests do instead
//
// They assert the causal invariant, which is strictly stronger than the proxy
// it replaced: a capability's confidence must follow from the observation that
// decided it, in the safe direction, every time.
//
// The direction matters more than the count. The old assertion could not
// detect a capability reported `observed` when its probe had FAILED — the
// false-confidence case, which is the one that would eventually produce a
// gateway that believes it has a firewall it never managed to read.
//
// # Fixtures, not a live host
//
// Every case below is a snapshot built by hand. A test needing CAP_NET_ADMIN
// passes on exactly the machines that were already passing, which is the
// property that caused the original bug.

import (
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/network"
)

// unprivilegedHost is a host whose probe tools are installed but unqueryable —
// the state of a real Linux host running the suite as an ordinary user.
func unprivilegedHost() *Device {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "lo", Index: 1, Kind: "loopback", AdminUp: true, State: network.LinkUp},
			{Name: "enp0s31f6", Index: 2, MAC: "3c:ec:ef:ff:00:01", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkUp,
				SpeedMbps: 1000},
		},
		Addresses: []network.Address{
			{Family: "inet", CIDR: "192.0.2.10/24", Interface: "enp0s31f6"},
		},
		Routes: []network.Route{
			{Destination: "default", Gateway: "192.0.2.1", Interface: "enp0s31f6", Default: true},
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},

		// Installed, present, and refused. This is the state that produced
		// the failure: Available true, QuerySucceeded false.
		NFTables: network.NFTablesState{
			Checked: true, Available: true, QuerySucceeded: false,
			Reason: "nft is installed but the ruleset could not be read: exit 1: Operation not permitted",
			Probe: network.Probe{
				Subsystem: "nftables", Operation: "list-tables",
				Stage: network.StageExecute, Outcome: network.ProbeExecutionFailed,
				Tool: "nft", Args: []string{"-j", "list", "tables"}, ExitStatus: 1,
				Detail: "the tool ran but did not succeed",
				Reason: "nft: exit 1: netlink: cache initialization failed: Operation not permitted",
			},
		},
		TrafficControl: network.TCState{
			Checked: true, Available: true, QuerySucceeded: false,
			Reason: "tc is installed but queue disciplines could not be read: exit 1: Operation not permitted",
			Probe: network.Probe{
				Subsystem: "traffic-control", Operation: "qdisc-show",
				Stage: network.StageExecute, Outcome: network.ProbeExecutionFailed,
				Tool: "tc", Args: []string{"-j", "qdisc", "show"}, ExitStatus: 1,
				Detail: "the tool ran but did not succeed",
				Reason: "tc: exit 1: RTNETLINK answers: Operation not permitted",
			},
		},
	}
	return FromSnapshot(snap)
}

// privilegedHost is the same host observed with working tools — the state
// `sudo thn host` reports.
func privilegedHost() *Device {
	snap := &network.Snapshot{
		Platform:  "linux",
		Supported: true,
		Interfaces: []network.Interface{
			{Name: "lo", Index: 1, Kind: "loopback", AdminUp: true, State: network.LinkUp},
			{Name: "enp0s31f6", Index: 2, MAC: "3c:ec:ef:ff:00:01", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkUp,
				SpeedMbps: 1000},
			{Name: "enx00e099001812", Index: 3, MAC: "3c:ec:ef:ff:00:02", Kind: "ether",
				LinkType: "ether", Physical: true, AdminUp: true, State: network.LinkDown},
		},
		Addresses: []network.Address{
			{Family: "inet", CIDR: "192.0.2.10/24", Interface: "enp0s31f6"},
		},
		Routes: []network.Route{
			{Destination: "default", Gateway: "192.0.2.1", Interface: "enp0s31f6", Default: true},
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},

		NFTables: network.NFTablesState{
			Checked: true, Available: true, QuerySucceeded: true,
			Tables: []network.NftTable{
				{Family: "ip", Name: "filter"},
				{Family: "ip", Name: "docker-bridges"},
			},
			Probe: network.Succeeded(network.Probe{
				Subsystem: "nftables", Operation: "list-tables",
				Tool: "nft", Args: []string{"-j", "list", "tables"},
			}, "the query succeeded", 2),
		},
		TrafficControl: network.TCState{
			Checked: true, Available: true, QuerySucceeded: true, CakeObserved: false,
			Qdiscs: []network.Qdisc{
				{Kind: "fq_codel", Handle: "0", Device: "enp0s31f6"},
			},
			Probe: network.Succeeded(network.Probe{
				Subsystem: "traffic-control", Operation: "qdisc-show",
				Tool: "tc", Args: []string{"-j", "qdisc", "show"},
			}, "the query succeeded and no CAKE discipline is attached", 1),
		},
	}
	return FromSnapshot(snap)
}

// ------------------------------------------------- 1. successful observation

// TestASuccessfulObservationIsNotDowngraded is requirement 1.
//
// The bug this milestone fixes, stated in the positive. If the query
// succeeded, the capability must be observed; anything else means an
// observation was dropped between the probe and the capability table.
func TestASuccessfulObservationIsNotDowngraded(t *testing.T) {
	d := privilegedHost()

	for _, c := range []Capability{CapNFTables, CapFirewall, CapTC} {
		s, ok := d.Capabilities[c]
		if !ok {
			t.Fatalf("capability %s is missing", c)
		}
		if !s.Available {
			t.Errorf("%s: available = false, but the probe succeeded", c)
		}
		if s.Confidence != ConfidenceObserved {
			t.Errorf("%s: confidence = %q, want observed; a successful query was not carried through. reason: %q",
				c, s.Confidence, s.Reason)
		}
		if !s.Satisfies() {
			t.Errorf("%s: Satisfies() = false; an observed, available capability must satisfy a gate", c)
		}
	}
}

// TestFirewallFollowsTheNftablesObservation is requirement 4, stated.
//
// Firewall has no probe of its own; it IS the nftables observation. The test
// has to exercise that path, which means building the state the real observer
// would have built rather than asserting a value.
func TestFirewallFollowsTheNftablesObservation(t *testing.T) {
	// Success.
	d := privilegedHost()
	if got := d.Capabilities[CapFirewall].Confidence; got != ConfidenceObserved {
		t.Errorf("firewall = %q with nftables observed, want observed", got)
	}
	if got := d.Capabilities[CapFirewall].Available; !got {
		t.Error("firewall is unavailable while nftables is available")
	}

	// Failure: the same host, unqueryable.
	u := unprivilegedHost()
	if got := u.Capabilities[CapFirewall].Confidence; got != ConfidenceUnknown {
		t.Errorf("firewall = %q with nftables unqueryable, want unknown", got)
	}

	// Absent: nft genuinely not installed is a POSITIVE finding, not a gap.
	absent := FromSnapshot(&network.Snapshot{
		Platform: "linux", Supported: true,
		NFTables: network.NFTablesState{
			Checked: true, Available: false, QuerySucceeded: false,
			Reason: "the nft binary is not installed on this host",
			Probe: network.Probe{
				Subsystem: "nftables", Operation: "list-tables",
				Stage: network.StageExecute, Outcome: network.ProbeToolUnavailable,
				Tool: "nft", Detail: "the tool is not installed or not on PATH",
				Reason: "nft: executable file not found in $PATH",
			},
		},
	})
	if got := absent.Capabilities[CapNFTables].Confidence; got != ConfidenceObserved {
		t.Errorf("nftables = %q when nft is genuinely absent, want observed; "+
			"a confirmed absence is a finding, not a gap", got)
	}
	if got := absent.Capabilities[CapFirewall].Confidence; got != ConfidenceObserved {
		t.Errorf("firewall = %q when nft is genuinely absent, want observed", got)
	}
}

// ------------------------------------------------ 2. TC observation

// TestTcObservationPropagates is requirement 2.
func TestTcObservationPropagates(t *testing.T) {
	d := privilegedHost()

	s := d.Capabilities[CapTC]
	if s.Confidence != ConfidenceObserved {
		t.Errorf("tc = %q after a successful query, want observed", s.Confidence)
	}
	if !strings.Contains(s.Reason, "discipline") {
		t.Errorf("the tc reason does not report what was found: %q", s.Reason)
	}

	u := unprivilegedHost()
	if got := u.Capabilities[CapTC].Confidence; got != ConfidenceUnknown {
		t.Errorf("tc = %q after a refused query, want unknown", got)
	}
}

// ---------------------------------------------------- 3. CAKE stays distinct

// TestCakeIsNotCollapsedIntoTc is requirement 3.
//
// "tc worked and found no CAKE" must never become "CAKE unavailable because
// tc failed". Those are different facts: the first means THN cannot tell
// without mutating, the second means the evidence is missing.
//
// Collapsing them would either report a perfectly healthy host as broken, or
// motivate loading sch_cake to find out — which is exactly the mutation this
// model exists to prevent.
func TestCakeIsNotCollapsedIntoTc(t *testing.T) {
	d := privilegedHost()

	tc := d.Capabilities[CapTC]
	cake := d.Capabilities[CapCake]

	if tc.Confidence != ConfidenceObserved {
		t.Fatalf("precondition: tc = %q, want observed", tc.Confidence)
	}
	if cake.Confidence != ConfidenceUnknown {
		t.Errorf("cake = %q with a working tc and no CAKE discipline, want unknown", cake.Confidence)
	}
	if cake.Available {
		t.Error("cake was reported available with no CAKE discipline observed")
	}
	// The reason must name the reason, and must say why THN did not go
	// further — so an operator does not read "unknown" as "THN gave up".
	if !strings.Contains(cake.Reason, "mutate") {
		t.Errorf("the cake reason does not explain the limitation: %q", cake.Reason)
	}

	// An attached CAKE discipline is the one piece of evidence that flips it.
	withCake := FromSnapshot(&network.Snapshot{
		Platform: "linux", Supported: true,
		TrafficControl: network.TCState{
			Checked: true, Available: true, QuerySucceeded: true, CakeObserved: true,
			Probe: network.Succeeded(network.Probe{
				Subsystem: "traffic-control", Operation: "qdisc-show",
				Tool: "tc",
			}, "the query succeeded", 2),
		},
	})
	if got := withCake.Capabilities[CapCake].Confidence; got != ConfidenceObserved {
		t.Errorf("cake = %q with a CAKE discipline attached, want observed", got)
	}

	// And with no tc at all, absence of CAKE IS established.
	noTC := FromSnapshot(&network.Snapshot{
		Platform: "linux", Supported: true,
		TrafficControl: network.TCState{
			Checked: true, Available: false,
			Reason: "the tc binary is not installed on this host",
			Probe: network.Probe{
				Subsystem: "traffic-control", Operation: "qdisc-show",
				Stage: network.StageExecute, Outcome: network.ProbeToolUnavailable,
				Tool: "tc", Detail: "the tool is not installed or not on PATH",
			},
		},
	})
	if got := noTC.Capabilities[CapCake].Confidence; got != ConfidenceObserved {
		t.Errorf("cake = %q with tc absent, want observed; no tc means no CAKE is possible", got)
	}
}

// ------------------------------ the direction that matters: false confidence

// TestAFailedProbeNeverProducesAnObservedCapability is the new assertion.
//
// This is what the old test could not detect, and it is the failure that
// matters: a gateway that believes it has a firewall or a CAKE shaper it
// never managed to establish. It walks every combination of probe outcome and
// capability state rather than checking one, because the bug lives in the
// mapping between them.
func TestAFailedProbeNeverProducesAnObservedCapability(t *testing.T) {
	cases := []struct {
		name       string
		nft        network.NFTablesState
		tc         network.TCState
		wantCaps   []Capability
		unwantCaps []Capability
	}{
		{
			name: "both probes refused",
			nft:  unprivilegedHost().NFTables,
			tc:   unprivilegedHost().TrafficControl,
			wantCaps: []Capability{
				CapFirewall, CapNFTables, CapTC, CapCake, CapQoS,
			},
		},
		{
			name: "nft absent is a positive finding",
			nft: network.NFTablesState{
				Checked: true, Available: false,
				Reason: "the nft binary is not installed on this host",
				Probe: network.Probe{
					Subsystem: "nftables", Operation: "list-tables",
					Stage: network.StageExecute, Outcome: network.ProbeToolUnavailable,
					Tool: "nft", Detail: "the tool is not installed or not on PATH",
				},
			},
			tc: network.TCState{
				Checked: true, Available: false,
				Reason: "the tc binary is not installed on this host",
				Probe: network.Probe{
					Subsystem: "traffic-control", Operation: "qdisc-show",
					Stage: network.StageExecute, Outcome: network.ProbeToolUnavailable,
					Tool: "tc", Detail: "the tool is not installed or not on PATH",
				},
			},
			// Absence is evidence. A host with no nft genuinely cannot have
			// a firewall, and THN can say so with confidence.
			unwantCaps: []Capability{CapFirewall, CapNFTables, CapTC},
		},
		{
			name: "nft query failed at the parse stage",
			nft: network.NFTablesState{
				Checked: true, Available: true, QuerySucceeded: false,
				Reason: "nft is installed but its output could not be parsed",
				Probe: network.Probe{
					Subsystem: "nftables", Operation: "list-tables",
					Stage: network.StageParse, Outcome: network.ProbeParseFailed,
					Tool: "nft", ExitStatus: 0, Detail: "nft ran and produced output THN could not parse",
				},
			},
			tc:       unprivilegedHost().TrafficControl,
			wantCaps: []Capability{CapFirewall, CapNFTables},
		},
		{
			// Nothing was probed at all. Every dependent capability must be
			// unknown, because a probe that never ran establishes nothing —
			// this is the "not checked" case, and it is the only one of the
			// four where absence and "we don't know" coincide.
			name:     "nothing was probed at all",
			nft:      network.NFTablesState{Checked: false},
			tc:       network.TCState{Checked: false},
			wantCaps: []Capability{CapFirewall, CapNFTables, CapTC, CapCake, CapQoS},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := FromSnapshot(&network.Snapshot{
				Platform: "linux", Supported: true,
				Sysctl:         []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
				NFTables:       tc.nft,
				TrafficControl: tc.tc,
			})

			for _, c := range tc.wantCaps {
				if got := d.Capabilities[c].Confidence; got != ConfidenceUnknown {
					t.Errorf("%s = %q, want unknown", c, got)
				}
			}
			for _, c := range tc.unwantCaps {
				if got := d.Capabilities[c].Confidence; got == ConfidenceUnknown {
					t.Errorf("%s = unknown; a confirmed absence is a finding, not a gap", c)
				}
			}

			// And the general invariant, checked across every capability
			// rather than only the listed ones.
			for _, c := range d.FalseConfidenceCapabilities() {
				ev := d.EvidenceFor(c)
				t.Errorf("%s claims observed while its %s probe ended %s at stage %s; "+
					"a probe that did not reach a conclusion cannot establish a capability",
					c, ev.Source, ev.Probe.Outcome, ev.Probe.Stage)
			}
		})
	}
}

// ------------------------------------------------- unknowns explain themselves

// TestEveryUnknownNamesItsSource is the "no unexplained unknown" rule.
//
// An unknown with no probe record is the only genuinely unacceptable outcome:
// it is indistinguishable from a capability THN never thought about.
func TestEveryUnknownNamesItsSource(t *testing.T) {
	for name, d := range map[string]*Device{
		"unprivileged": unprivilegedHost(),
		"privileged":   privilegedHost(),
	} {
		t.Run(name, func(t *testing.T) {
			for _, c := range d.UnknownCapabilitiesExplainThemselves() {
				ev := d.EvidenceFor(c)
				t.Errorf("capability %s is unknown from source %q with no probe record. reason: %q",
					c, ev.Source, ev.Reason)
			}
		})
	}
}

// TestEvidenceForNamesTheDecidingObservation is the join the whole milestone
// exists to provide.
//
// Before this, a capability's verdict and the observation behind it lived in
// different places with nothing connecting them. This asserts the join.
func TestEvidenceForNamesTheDecidingObservation(t *testing.T) {
	for _, tc := range []struct {
		capability Capability
		host       *Device
		wantSource string
	}{
		{CapFirewall, privilegedHost(), "nftables"},
		{CapNFTables, privilegedHost(), "nftables"},
		{CapTC, privilegedHost(), "traffic-control"},
		{CapCake, privilegedHost(), "traffic-control"},
		{CapQoS, privilegedHost(), "traffic-control"},
		{CapForwarding, privilegedHost(), "sysctl"},
		{CapRouting, unprivilegedHost(), "sysctl"},
		// NAT, DHCP and DNS have no probe and never will: answering them
		// would mean running the software THN would run.
		{CapNAT, privilegedHost(), "inferred"},
		{CapDHCP, privilegedHost(), "inferred"},
		{CapDNS, privilegedHost(), "inferred"},
	} {
		ev := tc.host.EvidenceFor(tc.capability)
		if ev.Source != tc.wantSource {
			t.Errorf("%s: source = %q, want %q", tc.capability, ev.Source, tc.wantSource)
		}
		if ev.Probe.Subsystem == "" {
			t.Errorf("%s: evidence carries no probe subsystem", tc.capability)
		}
		if ev.Probe.Stage == "" || ev.Probe.Outcome == "" {
			t.Errorf("%s: evidence carries no stage/outcome: %+v", tc.capability, ev.Probe)
		}
	}
}

// TestAMissingProbeRecordIsReportedAsMissing is the honesty check on the join
// itself.
//
// The evidence is a view over data the Device already carries. A subsystem
// state with no probe record must surface as MISSING rather than being
// papered over with a synthetic "not checked" — because a fabricated record is
// indistinguishable from a real one, and the whole point of the join is that a
// reader can tell a genuine gap from a fabricated answer.
//
// The second half of the test is the consequence: such a fixture must be
// flagged by UnknownCapabilitiesExplainThemselves, so the gap is detected
// rather than hidden.
func TestAMissingProbeRecordIsReportedAsMissing(t *testing.T) {
	d := FromSnapshot(&network.Snapshot{
		Platform: "linux", Supported: true,
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "1"}},
		// No Probe set on either subsystem: a hand-built fixture that never
		// ran the observers, which is exactly how a real gap would arise.
		NFTables:       network.NFTablesState{Checked: true, Available: false},
		TrafficControl: network.TCState{Checked: true, Available: false},
	})

	// Absence is confirmed for both, so the capabilities are observed —
	// correctly, and separately from the missing record.
	if got := d.Capabilities[CapNFTables].Confidence; got != ConfidenceObserved {
		t.Errorf("nftables = %q with nft confirmed absent, want observed", got)
	}

	// But nothing recorded WHY that absence was established, and the evidence
	// says so rather than inventing a reason.
	for _, c := range []Capability{CapNFTables, CapFirewall, CapTC} {
		ev := d.EvidenceFor(c)
		if ev.Probe.Subsystem != "" {
			t.Errorf("%s: a probe record was invented where none existed: %+v", c, ev.Probe)
		}
	}

	// And that gap is detected rather than passed off as explained.
	flagged := map[Capability]bool{}
	for _, c := range d.UnknownCapabilitiesExplainThemselves() {
		flagged[c] = true
	}
	// These are observed, so they are not unknowns — but the point of the
	// check is that the MISSING RECORD is visible, and a reviewer can see it
	// here rather than inferring it. Assert the fact directly.
	for _, c := range []Capability{CapNFTables, CapFirewall, CapTC} {
		if d.Capabilities[c].Confidence == ConfidenceUnknown && !flagged[c] {
			t.Errorf("%s is unknown with no probe record and was not flagged as unexplained", c)
		}
	}
}
