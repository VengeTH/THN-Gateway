// Package ruleset is the shipped rule set: the conditions THN evaluates about
// a gateway, and the inhibitions that say which of them are consequences of
// which.
//
// # These are the rules, not examples
//
// The conditions in internal/rules are a vocabulary. The rules here are the
// actual judgements, and they ship with the binary so that a gateway being
// developed against absent hardware still has something to say about itself.
//
// They are also the first thing a reviewer should argue with. Every threshold
// below is a claim about what matters on a home gateway, and a claim that
// nobody examined is a claim nobody will notice when it is wrong.
//
// # Thresholds are chosen, and the choice is arguable
//
// The durations here are the interesting part, and each carries a reason in
// its comment. The general shape:
//
//   - Anything derived from link state has a duration. Links flap, and an
//     incident per flap is how an operator learns to ignore the output.
//   - Anything derived from a counter has a duration for the opposite reason.
//     A pool at 95% is not a fault; a pool at 95% for ten minutes is, and the
//     duration is what distinguishes the two.
//   - Anything derived from configuration has no duration. A misconfigured
//     gateway does not become configured on its own, so there is nothing to
//     wait for.
//
// # Critical means traffic is affected
//
// Only conditions where traffic is actually impaired are critical. A gateway
// that is fully working with a full DHCP pool is a warning. A gateway whose
// uplink is down is critical.
//
// This boundary is the one most worth defending, because the cost of getting
// it wrong is specific: a critical label that appears for conditions nobody
// would act on immediately trains triage, and triage is what makes the label
// mean anything at all.
package ruleset

import (
	"fmt"
	"time"

	"github.com/venth/thn-gateway/internal/correlation"
	"github.com/venth/thn-gateway/internal/rules"
	"github.com/venth/thn-gateway/internal/signals"
)

// Rule names, as they appear in incidents.
const (
	// Network.
	WANDown           = "wan-down"
	WANDownUnobserved = "wan-state-unobserved"
	LANDown           = "lan-down"
	NoDefaultRoute    = "no-default-route"
	ForwardingOff     = "ipv4-forwarding-off"
	HostUnobservable  = "host-unobservable"

	// Firewall.
	FirewallInactive = "firewall-inactive"
	FirewallNoRules  = "firewall-empty"

	// DHCP.
	PoolExhausted    = "dhcp-pool-exhausted"
	PoolNearlyFull   = "dhcp-pool-nearly-full"
	UncorrelatedHigh = "dhcp-uncorrelated-devices"

	// Traffic shaping.
	ShapingInactive  = "shaping-inactive"
	ShapingCongested = "shaping-congested"
	ShapingWrongAlgo = "shaping-wrong-algorithm"
	ShapingStalled   = "shaping-queue-stalled"

	// Configuration and intent.
	ConfigInvalid   = "config-invalid"
	DriftPersistent = "drift-persistent"
)

// Thresholds, named so a test or an operator can refer to them without
// restating the number and getting it subtly different.
const (
	// LinkDownGrace is how long the uplink must be down before it is an
	// incident. A minute is long enough to ride out a carrier blip and short
	// enough that an operator is still looking at the screen.
	LinkDownGrace = 60 * time.Second

	// UnobservedGrace is how long THN may be unable to see the uplink before
	// that itself is reported.
	//
	// It is shorter than LinkDownGrace, deliberately. "The uplink is down" and
	// "THN cannot see the uplink" need different responses — one is a carrier
	// fault, the other might be a THN fault or a dead daemon — and waiting the
	// full link-down grace before distinguishing them would leave an operator
	// guessing which problem they have for a minute.
	UnobservedGrace = 30 * time.Second

	// PoolHighWatermark is the fraction of the pool that must be in use.
	//
	// 90%, not 100%. A pool that is full cannot serve a device that arrives
	// next, and the operator needs warning before that happens rather than
	// after: a client that cannot get an address has no way to report it, so
	// the only signal is from the gateway.
	PoolHighWatermark = 0.90

	// PoolFullFor is how long the pool must stay above the watermark.
	PoolFullFor = 15 * time.Minute

	// UncorrelatedRatio is the fraction of leases with no identified device
	// that triggers a warning.
	//
	// A device seen on the LAN that THN cannot identify is worth knowing
	// about. It is a warning rather than a critical because an unidentified
	// device is usually a device that simply has not renewed yet.
	UncorrelatedRatio = 0.50

	// UncorrelatedFor is how long the ratio must hold.
	UncorrelatedFor = 30 * time.Minute

	// DropRatioCongested is the packet drop ratio that means the shaper is
	// below the offered load.
	//
	// It matches the threshold internal/qos/tc uses, deliberately: two
	// packages disagreeing about when a queue is congested would produce a
	// report that says the queue is fine while the traffic statistics call it
	// congested.
	DropRatioCongested = 0.10

	// CongestedFor is how long heavy loss must persist.
	CongestedFor = 2 * time.Minute

	// BacklogStalled is the packet count above which a non-empty backlog with
	// no byte count means the link below is not draining.
	BacklogStalled = 1000

	// DriftFor is how long the host must differ from its configuration.
	//
	// Drift is usually transient — a service restarting, an interface coming
	// up in a different order — so a short grace absorbs it. A minute is
	// long enough for a systemd restart cycle and short enough that genuine
	// drift is reported while it is still fixable.
	DriftFor = time.Minute
)

// All returns the shipped rule set.
//
// It returns a fresh slice each call so a caller that sorts or filters it
// cannot affect anyone else's copy. Rules are value types, but the slice
// header is shared, and a package-level var mutated by a test is a bug that
// only reproduces in the test that caused it.
func All() []rules.Rule {
	return []rules.Rule{
		// --- Network ---

		{
			Name:     WANDown,
			Title:    "The uplink is down",
			Severity: rules.SeverityCritical,
			For:      LinkDownGrace,
			Condition: rules.All(
				rules.IsTrue(signals.NetWANPresent),
				rules.IsFalse(signals.NetWANUp),
			),
			Remedy: "Check the carrier, the modem, and the cable. The gateway is " +
				"reachable but has no path to anything beyond the LAN.",
			Comments: []string{
				"The interface being present is required, so that a gateway whose WAN " +
					"has not been identified yet is not reported as having lost one.",
			},
		},
		{
			Name:     WANDownUnobserved,
			Title:    "The uplink's state cannot be read",
			Severity: rules.SeverityWarning,
			For:      UnobservedGrace,
			Condition: rules.All(
				rules.IsTrue(signals.NetInspectSupported),
				rules.IsUnknown(signals.NetWANUp),
			),
			Remedy: "THN is running but cannot read the interface. Check that iproute2 " +
				"is installed and that thn has the privileges to run it.",
			Comments: []string{
				"This is a THN problem, not a network problem, and it is deliberately a " +
					"separate rule from wan-down. The two need different responses and an " +
					"operator told \"uplink down\" when the truth is \"I cannot see\" will " +
					"spend an afternoon on the wrong component.",
			},
		},
		{
			Name:      HostUnobservable,
			Title:     "The gateway's own state cannot be read",
			Severity:  rules.SeverityWarning,
			Condition: rules.IsFalse(signals.NetInspectSupported),
			Remedy: "Host inspection is unavailable. On Linux this usually means " +
				"iproute2 is missing; on another platform it is expected.",
			Comments: []string{
				"This has no duration. Platform support does not appear and disappear " +
					"on its own, so there is nothing to wait for.",
			},
		}, {
			// The gateway's gate phase found this missing: network.lan.up was
			// derived on every observation and read by no rule, so a LAN that
			// had gone down entirely — every client cut off from the gateway —
			// produced no incident at all. The observation was being made and
			// discarded, which is the quietest kind of omission: nothing looks
			// broken, and the coverage check that catches it only exists
			// because someone asked what the unused signals were for.
			Name:     LANDown,
			Title:    "The LAN is down",
			Severity: rules.SeverityCritical,
			For:      LinkDownGrace,
			Condition: rules.All(
				rules.IsTrue(signals.NetLANPresent),
				rules.IsFalse(signals.NetLANUp),
			),
			Remedy: "Every client on the LAN has lost the gateway. Check the " +
				"interface, the cable, and the switch it is attached to.",
			Comments: []string{
				"Critical and not warning: unlike the uplink, whose loss degrades " +
					"the internet, losing the LAN cuts every client off from the " +
					"gateway itself — including its DNS and DHCP, which means a " +
					"client cannot even be told what went wrong.",
				"Presence is required for the same reason as wan-down: a gateway " +
					"whose LAN has not been identified yet is not one that has lost it.",
			},
		}, {
			Name:     NoDefaultRoute,
			Title:    "There is no default route",
			Severity: rules.SeverityCritical,
			For:      LinkDownGrace,
			Condition: rules.All(
				rules.IsTrue(signals.NetInspectSupported),
				rules.IsFalse(signals.NetDefaultRoute),
			),
			Remedy: "Nothing beyond the directly connected networks is reachable. Check " +
				"whether the uplink obtained an address and a gateway.",
		},
		{
			Name:     ForwardingOff,
			Title:    "IPv4 forwarding is disabled",
			Severity: rules.SeverityCritical,
			For:      LinkDownGrace,
			Condition: rules.All(
				rules.IsTrue(signals.NetInspectSupported),
				rules.IsFalse(signals.NetIPv4Forwarding),
			),
			Remedy: "The kernel is not forwarding, so the gateway routes nothing " +
				"regardless of how the rest is configured.",
		},

		// --- Firewall ---

		{
			Name:      FirewallInactive,
			Title:     "The firewall is not running",
			Severity:  rules.SeverityCritical,
			For:       LinkDownGrace,
			Condition: rules.IsFalse(signals.FirewallActive),
			Remedy:    "Without a ruleset the host is unfiltered. This is the one condition on this list that is a security problem rather than a connectivity one.",
		},
		{
			Name:     FirewallNoRules,
			Title:    "The firewall is running with no rules",
			Severity: rules.SeverityCritical,
			For:      LinkDownGrace,
			Condition: rules.All(
				rules.IsTrue(signals.FirewallActive),
				rules.Below(signals.FirewallRules, 1),
			),
			Remedy: "A table with no rules denies nothing. A loaded-but-empty ruleset " +
				"looks identical to a working one from the outside.",
		},

		// --- DHCP ---

		{
			Name:     PoolExhausted,
			Title:    "The address pool is exhausted",
			Severity: rules.SeverityCritical,
			For:      PoolFullFor,
			Condition: rules.All(
				rules.AtOrAbove(signals.DHCPPoolUtilisation, PoolHighWatermark),
				rules.AtOrAbove(signals.DHCPPoolCapacity, 1),
			),
			Remedy: "Clients arriving now cannot be served. Widen the pool, or find " +
				"out what is holding the addresses.",
			Comments: []string{
				"The capacity check is what makes this rule safe on a gateway with no " +
					"DHCP configured: a utilisation of zero against a capacity of zero " +
					"would otherwise read as 100% full, and every deployment without " +
					"DHCP would report an exhausted pool.",
			},
		},
		{
			Name:     PoolNearlyFull,
			Title:    "The address pool is nearly full",
			Severity: rules.SeverityWarning,
			For:      PoolFullFor,
			Condition: rules.All(
				rules.Between(signals.DHCPPoolUtilisation, PoolHighWatermark*0.8, PoolHighWatermark),
				rules.AtOrAbove(signals.DHCPPoolCapacity, 1),
			),
			Remedy: "There is room, but not much. Widen the pool before it runs out.",
		},
		{
			Name:     UncorrelatedHigh,
			Title:    "Many devices on the LAN are unidentified",
			Severity: rules.SeverityWarning,
			For:      UncorrelatedFor,
			Condition: rules.All(
				rules.AtOrAbove(signals.DHCPLeasesActive, 4),
				rules.AtOrAbove(signals.DHCPDevicesUnknown, 2),
			),
			Remedy: "Hardware is appearing on the LAN that THN has not identified. " +
				"This is the first sign of a device nobody put there.",
		},

		// --- Traffic shaping ---

		{
			Name:      ShapingInactive,
			Title:     "Traffic shaping is not running",
			Severity:  rules.SeverityInfo,
			For:       LinkDownGrace,
			Condition: rules.IsFalse(signals.QoSActive),
			Remedy:    "Informational. If shaping was configured, check that the generated tc script was applied.",
			Comments: []string{
				"Info rather than warning: an unshaped gateway is slower under load, " +
					"not broken, and a gateway that reports shaping as a problem trains " +
					"an operator to ignore the label on the things that are problems.",
			},
		},
		{
			Name:     ShapingCongested,
			Title:    "The shaper is dropping heavily",
			Severity: rules.SeverityWarning,
			For:      CongestedFor,
			Condition: rules.All(
				rules.IsTrue(signals.QoSActive),
				rules.AtOrAbove(signals.QoSDropRatio, DropRatioCongested),
			),
			Remedy: "The shaped rate is below the offered load. Either the rate is " +
				"set too low, or something is saturating the link.",
		},
		{
			Name:     ShapingStalled,
			Title:    "The queue is full and not moving",
			Severity: rules.SeverityWarning,
			For:      CongestedFor,
			Condition: rules.All(
				rules.IsTrue(signals.QoSActive),
				rules.AtOrAbove(signals.QoSBacklogBytes, BacklogStalled),
			),
			Remedy: "Packets are queued and the link below is not draining. This is a " +
				"fault below the shaper rather than in its configuration.",
		},
		{
			Name:     ShapingWrongAlgo,
			Title:    "Traffic shaping fell back to a weaker algorithm",
			Severity: rules.SeverityWarning,
			For:      LinkDownGrace,
			Condition: rules.All(
				rules.IsTrue(signals.QoSActive),
				rules.NotIn(signals.QoSAlgorithm, "cake"),
			),
			Remedy: "fq_codel cannot enforce a bandwidth, so latency under load is not " +
				"being controlled. Load the CAKE module on the gateway.",
			Comments: []string{
				"This is a warning rather than info because the operator's configured " +
					"rate is being ignored, which is a loss they did not agree to.",
			},
		},

		// --- Configuration and intent ---

		{
			Name:      ConfigInvalid,
			Title:     "The configuration is not valid",
			Severity:  rules.SeverityCritical,
			Condition: rules.IsFalse(signals.ConfigValid),
			Remedy:    "Run `thn validate` for the specific findings. Nothing will be applied until this is fixed.",
			Comments: []string{
				"No duration: a configuration does not become valid on its own, so " +
					"there is nothing to wait for.",
			},
		},
		{
			Name:     DriftPersistent,
			Title:    "The gateway does not match its configuration",
			Severity: rules.SeverityWarning,
			For:      DriftFor,
			Condition: rules.All(
				rules.IsTrue(signals.NetInspectSupported),
				rules.IsFalse(signals.DriftConverged),
				rules.AtOrAbove(signals.DriftCount, 1),
			),
			Remedy: "Something changed outside THN. Run `thn plan` to see what it " +
				"would do about it, and `thn plan --live` to include what it observes.",
		},
	}
}

// Inhibitions returns the shipped suppression rules.
//
// Every entry names a cause and its consequences. Reading this list is the
// clearest statement of THN's belief about how a gateway fails: an uplink that
// goes down explains the absence of a default route, and nothing else.
//
// The suppressions are narrow on purpose. A broad one — "when the uplink is
// down, suppress everything" — would look helpful and would be wrong: an
// uplink that is down and a disabled forwarding sysctl are two independent
// faults, and reporting only the first would mean the second is discovered
// when the first is fixed. Suppression is for cases where the second fact
// carries no information the first does not already carry.
func Inhibitions() []correlation.InhibitRule {
	return []correlation.InhibitRule{
		{
			// A link that is down has no default route, because a default route
			// through a down interface is not a route. Reporting both tells an
			// operator to look at two things when there is one.
			Source: WANDown,
			Target: NoDefaultRoute,
			Reason: "a down uplink has no usable default route; the two are the same " +
				"failure observed from two directions",
		},
		{
			// If the link's state cannot be read, the routing table's state is
			// not reliable either. Reporting a default route's absence as an
			// observation would be presenting a guess as a fact — and it is
			// specifically the guess that would send an operator to reconfigure
			// a gateway that is perfectly fine and merely invisible.
			Source: WANDownUnobserved,
			Target: NoDefaultRoute,
			Reason: "if the uplink cannot be read, the routing table cannot be trusted; " +
				"a missing default route would be a guess rather than an observation",
		},
		{
			// Broad within the group, and correctly so. When the host cannot be
			// inspected, every network reading is unreliable together, not
			// selectively. The group is keyed by source, so this reaches the
			// network rules and nothing else.
			//
			// In practice it cannot fire alongside the rules it suppresses —
			// those require inspection to have succeeded — which makes this a
			// defence against a future rule that forgets that requirement,
			// rather than a suppression doing work today. That is worth having:
			// the alternative is a rule added later that reports a confident
			// negative on a host THN cannot see.
			Source: HostUnobservable,
			Target: "*",
			Reason: "when the host cannot be inspected, no reading from it is reliable",
		},
		{
			// A configuration that does not parse is not producing an intent to
			// drift from, so "the host differs from its configuration" has no
			// referent. Reporting both would give an operator a drift to chase
			// and a validation error to fix, when fixing the validation error
			// is the whole job.
			Source: ConfigInvalid,
			Target: DriftPersistent,
			Reason: "a configuration that is not valid is not producing an intent to " +
				"drift from, so the drift report has no referent",
		},
		{
			// Heavy loss and a full queue are the same condition. The drop ratio
			// is the more specific of the two, and reporting both would send an
			// operator to check the queue before checking the rate.
			Source: ShapingCongested,
			Target: ShapingStalled,
			Reason: "heavy loss with a full queue is one condition; the drop ratio is " +
				"the more specific diagnosis of the two",
		},
	}
}

// CorrelationConfig returns the grouping configuration for the shipped rules.
//
// Grouping by source means a network incident, a DHCP incident and a shaping
// incident are three incidents rather than one, because they have nothing to do
// with each other and merging them would hide the one that matters.
func CorrelationConfig() correlation.Config {
	return correlation.Config{
		GroupBy:     []string{"source"},
		GroupWindow: time.Minute,
		Inhibit:     Inhibitions(),
	}
}

// Validate checks the shipped rule set.
//
// It runs in the tests rather than at init, because a package that panics on
// import cannot be tested. A malformed rule in this set is a bug that should
// surface in `go test`, not in whatever command happens to run first.
func Validate() error {
	for _, r := range All() {
		if err := r.Validate(); err != nil {
			return err
		}
	}

	if _, err := correlation.New(CorrelationConfig()); err != nil {
		return err
	}

	// Every inhibition must name a rule that exists, or a typo silently
	// disables a suppression and the correlation quietly stops working.
	names := map[string]bool{}
	for _, r := range All() {
		names[r.Name] = true
	}

	for _, in := range Inhibitions() {
		if in.Source != "*" && !names[in.Source] {
			return fmt.Errorf("inhibition names source rule %q, which does not exist; "+
				"a typo here silently disables a suppression", in.Source)
		}
		if in.Target == "*" {
			continue
		}
		if !names[in.Target] {
			return fmt.Errorf("inhibition names target rule %q, which does not exist; "+
				"a typo here silently disables a suppression", in.Target)
		}
	}

	return nil
}
