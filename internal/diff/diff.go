// Package diff compares observed host state against desired state and
// classifies the differences.
//
// # The three-way distinction
//
// A diff does not answer "is this different?" It answers "what kind of
// difference is this?", because the three kinds demand different responses:
//
//	Pending     the desired state is not yet determined, or could not be
//	            observed, so no change can be proposed.
//	Drift       the host is configured differently from the intent.
//	Blocked     the host cannot be reconciled as configured.
//
// Collapsing Pending into Drift is the most common mistake in this kind of
// tool: it produces a plan that tries to configure an interface which does not
// exist. Here, an unidentified LAN is always Pending.
//
// # Fail closed on an unobservable host
//
// When host inspection is unavailable, Compare reports everything as Pending
// rather than reporting drift. Reporting drift would assert knowledge the diff
// does not have: nothing was observed, so nothing was compared. A tool that
// says "nothing to do" when it simply could not look is worse than useless on
// a remote device.
//
// # Risk
//
// Each change carries a risk classification, so that `thn plan` can lead with
// the dangerous items: an operator scanning for "what could go wrong" should
// see the firewall change before the DNS change.
package diff

import (
	"fmt"
	"sort"
	"strings"
)

// Kind classifies a difference.
type Kind string

const (
	// KindPending means the desired state is undetermined, or the host state
	// could not be observed. Nothing to do yet.
	KindPending Kind = "pending"
	// KindDrift means the host differs from the intent.
	KindDrift Kind = "drift"
	// KindBlocked means the difference cannot be reconciled as configured.
	KindBlocked Kind = "blocked"
)

// Risk classifies how consequential a change would be.
type Risk string

const (
	// RiskNone is a read-only or already-correct observation.
	RiskNone Risk = "none"
	// RiskLow is a change with no connectivity impact, such as adding an
	// address alongside existing ones.
	RiskLow Risk = "low"
	// RiskMedium changes behaviour but not reachability, such as forwarding.
	RiskMedium Risk = "medium"
	// RiskHigh can interrupt traffic, such as replacing an address.
	RiskHigh Risk = "high"
	// RiskCritical can render the host unreachable, such as a firewall.
	RiskCritical Risk = "critical"
)

// Change is a single difference between observed and desired state.
type Change struct {
	// ID is a stable identifier for this change.
	ID string `json:"id"`
	// Kind classifies the difference.
	Kind Kind `json:"kind"`
	// Risk classifies how consequential applying it would be.
	Risk Risk `json:"risk"`
	// Subsystem is "address", "route", "link", "nftables", "qdisc", "sysctl"
	// or "resolver".
	Subsystem string `json:"subsystem"`
	// Field is the dotted path of the affected setting.
	Field string `json:"field"`
	// Current is the observed value, or a marker when unobserved.
	Current string `json:"current,omitempty"`
	// Desired is the value the host should have.
	Desired string `json:"desired,omitempty"`
	// Reason explains the difference in plain language.
	Reason string `json:"reason"`
}

// String renders a change for terminal output.
func (c Change) String() string {
	return fmt.Sprintf("[%s/%s] %s: %s", c.Kind, c.Risk, c.Field, c.Reason)
}

// Result is the complete outcome of a comparison.
type Result struct {
	// Changes are all detected differences.
	Changes []Change `json:"changes"`
	// Converged reports that observed already matches desired, or that no
	// difference was detected at all. Pending items do not prevent
	// convergence, because pending means "not yet asked", not "wrong".
	Converged bool `json:"converged"`
	// DriftCount counts changes of kind Drift.
	DriftCount int `json:"drift_count"`
	// PendingCount counts changes of kind Pending.
	PendingCount int `json:"pending_count"`
	// BlockedCount counts changes of kind Blocked.
	BlockedCount int `json:"blocked_count"`
	// HighestRisk is the greatest risk among all changes.
	HighestRisk Risk `json:"highest_risk"`
}

// Observed is the subset of host state the diff compares against.
//
// It is declared here rather than imported from internal/network so that the
// diff can be tested exhaustively without a live host, and so that the
// comparison contract is explicit at every call site.
type Observed struct {
	// HostName is the host the observation came from.
	HostName string
	// Supported reports whether host inspection was available at all. When
	// false, Compare reports everything as Pending rather than guessing.
	Supported bool

	// WANName is the observed uplink interface.
	WANName string
	// WANPresent reports whether it exists.
	WANPresent bool
	// WANUp reports its link state.
	WANUp bool

	// LANName is the observed downstream interface.
	LANName string
	// LANPresent reports whether it exists.
	LANPresent bool
	// LANUp reports its link state.
	LANUp bool
	// LANAddresses are its observed addresses.
	LANAddresses []string

	// DefaultGateway is the observed default route gateway.
	DefaultGateway string
	// HasDefaultRoute reports whether a default route exists.
	HasDefaultRoute bool

	// IPv4Forwarding is the observed forwarding state.
	IPv4Forwarding bool
	// IPv4ForwardingKnown reports whether it was read successfully.
	IPv4ForwardingKnown bool

	// FirewallActive reports whether a ruleset was observed.
	FirewallActive bool
	// FirewallRuleCount is the number of observed rules.
	FirewallRuleCount int

	// QoSActive reports whether a queue discipline was observed.
	QoSActive bool
	// QoSAlgorithm is the detected algorithm.
	QoSAlgorithm string

	// Resolvers are the observed resolvers, when THN could read them.
	Resolvers []string
	// ResolversKnown reports whether the resolver set was observed.
	ResolversKnown bool
}

// Desired is the subset of desired state the diff needs. Declaring it
// structurally keeps this package free of a dependency on internal/desired.
type Desired struct {
	// WANName is the intended uplink interface name.
	WANName string
	// WANPresent reports whether it has been identified.
	WANPresent bool
	// WANUp requests the link up.
	WANUp bool

	// LANName is the intended downstream interface name.
	LANName string
	// LANPresent reports whether it has been identified.
	LANPresent bool
	// LANUp requests the link up.
	LANUp bool
	// LANAddresses are the intended addresses. A nil slice means THN does not
	// manage this interface's addressing, so no comparison is made.
	LANAddresses []string

	// DefaultGateway is the intended default route next hop.
	DefaultGateway string
	// UpstreamPresent reports whether one was configured.
	UpstreamPresent bool

	// IPv4Forwarding requests IPv4 forwarding.
	IPv4Forwarding bool

	// NATEnabled reports whether masquerading is wanted.
	NATEnabled bool
	// NATResolved reports whether the masquerade interfaces are known.
	NATResolved bool

	// FirewallEnabled reports whether filtering is wanted.
	FirewallEnabled bool
	// FirewallBackend is the filtering implementation.
	FirewallBackend string
	// FirewallPolicy is the default inbound policy.
	FirewallPolicy string

	// QoSEnabled reports whether shaping is wanted.
	QoSEnabled bool
	// QoSResolved reports whether the shaping target is known.
	QoSResolved bool
	// QoSAlgorithm is the shaping algorithm.
	QoSAlgorithm string
	// QoSInterface is the device to shape.
	QoSInterface string
	// QoSDownloadKbps is the shaped download rate.
	QoSDownloadKbps int
	// QoSUploadKbps is the shaped upload rate.
	QoSUploadKbps int

	// DNSPresent reports whether a resolver set was configured.
	DNSPresent bool
	// DNSServers is the intended resolver set.
	DNSServers []string
}

// unobservableReason explains a pending item produced by an unobservable host.
const unobservableReason = "host inspection is unavailable on this platform, so this subsystem could not be compared"

// Compare produces the diff between observed host state and desired state.
//
// The function never fails. Host inspection that did not happen, or hardware
// that is not attached, produces Pending entries rather than an error, because
// "not yet" is the normal condition while THN is developed remotely.
func Compare(obs Observed, want Desired) Result {
	d := differ{obs: obs, want: want}

	// Fail closed: without an observation there is nothing to compare, and
	// claiming drift would assert knowledge the diff does not have.
	if !obs.Supported {
		d.compareUnobservable()
		return d.result()
	}

	d.compareInterfaces()
	d.compareAddressing()
	d.compareForwarding()
	d.compareNAT()
	d.compareFirewall()
	d.compareQoS()
	d.compareResolvers()

	return d.result()
}

// differ accumulates changes during a comparison.
type differ struct {
	obs     Observed
	want    Desired
	changes []Change
}

// add appends a change.
func (d *differ) add(c Change) { d.changes = append(d.changes, c) }

// pending appends a Pending change with no risk, which is how every
// outstanding item is represented.
func (d *differ) pending(id, subsystem, field, desired, reason string) {
	d.add(Change{
		ID:        id,
		Kind:      KindPending,
		Risk:      RiskNone,
		Subsystem: subsystem,
		Field:     field,
		Desired:   desired,
		Reason:    reason,
	})
}

// compareUnobservable reports every configured subsystem as pending.
func (d *differ) compareUnobservable() {
	d.pending("host-unobservable", "host", "host.inspection", "", unobservableReason)

	if d.want.WANPresent {
		d.pending("wan-unobservable", "link", "wan.interface", d.want.WANName, unobservableReason)
	}
	if d.want.LANPresent {
		d.pending("lan-unobservable", "link", "lan.interface", d.want.LANName, unobservableReason)
	}
	if d.want.FirewallEnabled {
		d.pending("firewall-unobservable", "nftables", "firewall.enabled", "", unobservableReason)
	}
	if d.want.QoSEnabled {
		d.pending("qos-unobservable", "qdisc", "qos.enabled", "", unobservableReason)
	}
	if d.want.DNSPresent {
		d.pending("resolvers-unobservable", "resolver", "network.dns", "", unobservableReason)
	}
}

// compareInterfaces diffs the WAN and LAN interfaces.
func (d *differ) compareInterfaces() {
	// The WAN's addressing is not managed by THN, so nil is passed for both
	// address slices to suppress the address comparison entirely. The uplink
	// is observed but never rewritten.
	d.compareInterface("wan", d.want.WANPresent, d.want.WANName,
		d.obs.WANPresent, d.obs.WANName, d.want.WANUp, d.obs.WANUp, nil, nil)

	d.compareInterface("lan", d.want.LANPresent, d.want.LANName,
		d.obs.LANPresent, d.obs.LANName, d.want.LANUp, d.obs.LANUp,
		d.want.LANAddresses, d.obs.LANAddresses)
}

// compareInterface diffs a single interface.
//
// A nil wantAddrs means THN does not manage this interface's addressing.
func (d *differ) compareInterface(role string, wantPresent bool, wantName string,
	obsPresent bool, obsName string, wantUp, obsUp bool,
	wantAddrs, obsAddrs []string) {

	field := role + ".interface"
	label := strings.ToUpper(role)

	// The desired interface has not been identified yet.
	if !wantPresent {
		d.pending(role+"-unidentified", "link", field, "",
			fmt.Sprintf("the %s interface has not been identified in the configuration", label))
		return
	}

	// The desired interface exists but is not attached to this host.
	if !obsPresent {
		d.pending(role+"-not-attached", "link", field, wantName,
			fmt.Sprintf("interface %s is not attached to this host; %s configuration is pending",
				wantName, label))
		return
	}

	// The interfaces have different names: this host is not the intended
	// device, or the configuration points elsewhere. Flagged distinctly and
	// stopped at, because reconciling it would reconfigure the wrong NIC.
	if obsName != wantName {
		d.add(Change{
			ID:        role + "-name-mismatch",
			Kind:      KindBlocked,
			Risk:      RiskCritical,
			Subsystem: "link",
			Field:     field,
			Current:   obsName,
			Desired:   wantName,
			Reason: fmt.Sprintf("the configured %s interface is %s but this host has %s; check that the configuration matches this device",
				label, wantName, obsName),
		})
		return
	}

	// Link state.
	if wantUp != obsUp {
		state := "bring it up"
		if !wantUp {
			state = "bring it down"
		}
		d.add(Change{
			ID:        role + "-link-state",
			Kind:      KindDrift,
			Risk:      RiskMedium,
			Subsystem: "link",
			Field:     role + ".link",
			Current:   linkLabel(obsUp),
			Desired:   linkLabel(wantUp),
			Reason:    fmt.Sprintf("%s is %s; the configuration would %s", wantName, linkLabel(obsUp), state),
		})
	}

	if wantAddrs == nil {
		return
	}
	d.compareAddresses(role, wantName, wantAddrs, obsAddrs)
}

// compareAddresses diffs the address set of one interface.
func (d *differ) compareAddresses(role, iface string, want, obs []string) {
	wantSet := toSet(want)
	obsSet := toSet(obs)

	var missing, extra []string
	for _, a := range want {
		if !obsSet[a] {
			missing = append(missing, a)
		}
	}
	for _, a := range obs {
		if !wantSet[a] {
			extra = append(extra, a)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		// Adding an address alongside existing ones is low risk: the
		// interface keeps working throughout.
		d.add(Change{
			ID:        role + "-address-add",
			Kind:      KindDrift,
			Risk:      RiskLow,
			Subsystem: "address",
			Field:     role + ".address",
			Current:   joinOr(obs, "(none)"),
			Desired:   joinOr(want, "(none)"),
			Reason:    fmt.Sprintf("%s is missing the address %s", iface, strings.Join(missing, ", ")),
		})
	}

	if len(extra) > 0 {
		// Removing an address severs whatever was using it, which is what
		// makes this high rather than low risk.
		d.add(Change{
			ID:        role + "-address-remove",
			Kind:      KindDrift,
			Risk:      RiskHigh,
			Subsystem: "address",
			Field:     role + ".address",
			Current:   joinOr(obs, "(none)"),
			Desired:   joinOr(want, "(none)"),
			Reason: fmt.Sprintf("%s carries the address %s, which the configuration does not list; removing it would interrupt traffic on that segment",
				iface, strings.Join(extra, ", ")),
		})
	}
}

// compareAddressing diffs the default route.
func (d *differ) compareAddressing() {
	if !d.want.UpstreamPresent {
		return
	}

	if !d.obs.HasDefaultRoute {
		d.add(Change{
			ID:        "default-route-add",
			Kind:      KindDrift,
			Risk:      RiskMedium,
			Subsystem: "route",
			Field:     "addressing.default_gateway",
			Current:   "(no default route)",
			Desired:   d.want.DefaultGateway,
			Reason:    fmt.Sprintf("this host has no default route; the configuration specifies one via %s", d.want.DefaultGateway),
		})
		return
	}

	if d.obs.DefaultGateway != d.want.DefaultGateway {
		d.add(Change{
			ID:        "default-route-gateway",
			Kind:      KindDrift,
			Risk:      RiskHigh,
			Subsystem: "route",
			Field:     "addressing.default_gateway",
			Current:   d.obs.DefaultGateway,
			Desired:   d.want.DefaultGateway,
			Reason:    fmt.Sprintf("the default route points at %s but the configuration specifies %s", d.obs.DefaultGateway, d.want.DefaultGateway),
		})
	}
}

// compareForwarding diffs the IPv4 forwarding tunable.
func (d *differ) compareForwarding() {
	if !d.obs.IPv4ForwardingKnown {
		d.pending("ip-forwarding-unknown", "sysctl", "addressing.ipv4_forwarding", "",
			"net.ipv4.ip_forward could not be read on this host")
		return
	}

	if d.want.IPv4Forwarding != d.obs.IPv4Forwarding {
		d.add(Change{
			ID:        "ip-forwarding",
			Kind:      KindDrift,
			Risk:      RiskMedium,
			Subsystem: "sysctl",
			Field:     "addressing.ipv4_forwarding",
			Current:   boolLabel(d.obs.IPv4Forwarding),
			Desired:   boolLabel(d.want.IPv4Forwarding),
			Reason: fmt.Sprintf("IPv4 forwarding is %s; the configuration requires it to be %s",
				boolLabel(d.obs.IPv4Forwarding), boolLabel(d.want.IPv4Forwarding)),
		})
	}
}

// compareNAT reports masquerading state.
//
// Whether NAT rules are present cannot be read back reliably from an nftables
// rule count, so this reports only the unambiguous case: NAT wanted but the
// masquerade interface not yet determined.
func (d *differ) compareNAT() {
	if d.want.NATEnabled && !d.want.NATResolved {
		d.pending("nat-pending", "nftables", "nat.interfaces", "(unresolved)",
			"NAT is enabled but no masquerade interface has been determined")
	}
}

// compareFirewall diffs filtering.
func (d *differ) compareFirewall() {
	if !d.want.FirewallEnabled {
		return
	}

	if !d.obs.FirewallActive {
		d.add(Change{
			ID:        "firewall-absent",
			Kind:      KindDrift,
			Risk:      RiskCritical,
			Subsystem: "nftables",
			Field:     "firewall.enabled",
			Current:   "no ruleset present",
			Desired:   fmt.Sprintf("%s with default %s", d.want.FirewallBackend, d.want.FirewallPolicy),
			Reason:    "the configuration requires a firewall but this host has no ruleset",
		})
		return
	}

	if d.obs.FirewallRuleCount == 0 {
		d.add(Change{
			ID:        "firewall-empty",
			Kind:      KindDrift,
			Risk:      RiskCritical,
			Subsystem: "nftables",
			Field:     "firewall.enabled",
			Current:   "ruleset present with no rules",
			Desired:   fmt.Sprintf("%s with default %s", d.want.FirewallBackend, d.want.FirewallPolicy),
			Reason:    "a firewall table exists but contains no rules, so all traffic would be handled by the base policy alone",
		})
	}
}

// compareQoS diffs traffic shaping.
func (d *differ) compareQoS() {
	if !d.want.QoSEnabled {
		return
	}

	if !d.want.QoSResolved {
		d.pending("qos-pending", "qdisc", "qos.interface", "(unresolved)",
			"QoS is enabled but the interface or rates are incomplete")
		return
	}

	if !d.obs.QoSActive {
		d.add(Change{
			ID:        "qos-absent",
			Kind:      KindDrift,
			Risk:      RiskMedium,
			Subsystem: "qdisc",
			Field:     "qos.enabled",
			Current:   "no queue discipline",
			Desired:   d.qosDesired(),
			Reason:    "the configuration requires traffic shaping but this host has no queue discipline configured",
		})
		return
	}

	if d.obs.QoSAlgorithm != d.want.QoSAlgorithm {
		d.add(Change{
			ID:        "qos-algorithm",
			Kind:      KindDrift,
			Risk:      RiskMedium,
			Subsystem: "qdisc",
			Field:     "qos.algorithm",
			Current:   d.obs.QoSAlgorithm,
			Desired:   d.qosDesired(),
			Reason:    fmt.Sprintf("this host uses %s for shaping but the configuration specifies %s", d.obs.QoSAlgorithm, d.want.QoSAlgorithm),
		})
	}
}

// qosDesired renders the intended shaping target as a structured string.
//
// The form is "algorithm on device down=N up=N". It is a string so that the
// change carries everything a renderer needs in one field, and so that a plan
// step never has to reach back into the desired state to draw a command.
func (d *differ) qosDesired() string {
	return fmt.Sprintf("%s on %s down=%d up=%d",
		d.want.QoSAlgorithm, d.want.QoSInterface, d.want.QoSDownloadKbps, d.want.QoSUploadKbps)
}

// compareResolvers diffs the resolver set.
func (d *differ) compareResolvers() {
	if !d.want.DNSPresent {
		return
	}

	if !d.obs.ResolversKnown {
		d.pending("resolvers-unknown", "resolver", "network.dns",
			strings.Join(d.want.DNSServers, ", "),
			"THN does not yet observe the host resolver configuration, so the current value is unknown")
		return
	}

	if !sameSet(d.want.DNSServers, d.obs.Resolvers) {
		d.add(Change{
			ID:        "resolvers",
			Kind:      KindDrift,
			Risk:      RiskLow,
			Subsystem: "resolver",
			Field:     "network.dns",
			Current:   strings.Join(d.obs.Resolvers, ", "),
			Desired:   strings.Join(d.want.DNSServers, ", "),
			Reason: fmt.Sprintf("this host uses resolvers %s but the configuration specifies %s",
				strings.Join(d.obs.Resolvers, ", "), strings.Join(d.want.DNSServers, ", ")),
		})
	}
}

// result finalises the accumulated changes.
func (d *differ) result() Result {
	r := Result{
		Changes:     d.changes,
		HighestRisk: RiskNone,
	}

	for _, c := range d.changes {
		switch c.Kind {
		case KindDrift:
			r.DriftCount++
		case KindPending:
			r.PendingCount++
		case KindBlocked:
			r.BlockedCount++
		}
		if riskRank(c.Risk) > riskRank(r.HighestRisk) {
			r.HighestRisk = c.Risk
		}
	}

	// Pending work does not prevent convergence: pending means "not yet
	// asked" or "could not be seen", not "wrong".
	r.Converged = r.DriftCount == 0 && r.BlockedCount == 0

	sort.SliceStable(r.Changes, func(i, j int) bool {
		a, b := r.Changes[i], r.Changes[j]
		if a.Kind != b.Kind {
			return kindRank(a.Kind) < kindRank(b.Kind)
		}
		if a.Risk != b.Risk {
			return riskRank(a.Risk) > riskRank(b.Risk)
		}
		return a.Field < b.Field
	})

	return r
}

// kindRank orders kinds for display: blocked first, then drift, then pending.
func kindRank(k Kind) int {
	switch k {
	case KindBlocked:
		return 0
	case KindDrift:
		return 1
	default:
		return 2
	}
}

// riskRank orders risks from none to critical.
func riskRank(r Risk) int {
	switch r {
	case RiskNone:
		return 0
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	default:
		return 0
	}
}

// ByKind returns the changes of one kind.
func (r Result) ByKind(k Kind) []Change {
	var out []Change
	for _, c := range r.Changes {
		if c.Kind == k {
			out = append(out, c)
		}
	}
	return out
}

// Riskiest returns the highest-risk change, or nil when there are none.
func (r Result) Riskiest() *Change {
	if len(r.Changes) == 0 {
		return nil
	}
	best := r.Changes[0]
	for _, c := range r.Changes[1:] {
		if riskRank(c.Risk) > riskRank(best.Risk) {
			best = c
		}
	}
	return &best
}

// Summary renders a one-line description of the comparison.
func (r Result) Summary() string {
	switch {
	case len(r.Changes) == 0:
		return "observed state matches the configured intent"
	case r.Converged && r.PendingCount > 0:
		return fmt.Sprintf("no drift; %d subsystem(s) pending", r.PendingCount)
	case r.Converged:
		return "no drift"
	default:
		return fmt.Sprintf("%d change(s) to make, %d pending, %d blocked, highest risk %s",
			r.DriftCount, r.PendingCount, r.BlockedCount, r.HighestRisk)
	}
}

// linkLabel renders a link state.
func linkLabel(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

// boolLabel renders a boolean for diff display.
func boolLabel(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// toSet converts a slice into a lookup set.
func toSet(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, v := range in {
		out[v] = true
	}
	return out
}

// sameSet reports whether two slices contain the same elements, ignoring
// order.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := toSet(a), toSet(b)
	for k := range as {
		if !bs[k] {
			return false
		}
	}
	return true
}

// joinOr joins values, or returns fallback when empty.
func joinOr(in []string, fallback string) string {
	if len(in) == 0 {
		return fallback
	}
	return strings.Join(in, ", ")
}
