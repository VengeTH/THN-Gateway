package signals

import (
	"fmt"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/dhcp"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/identity"
	"github.com/VengeTH/THN-Gateway/internal/network"
	qostc "github.com/VengeTH/THN-Gateway/internal/qos/tc"
	"github.com/VengeTH/THN-Gateway/internal/validation"
)

// This file projects the observation types THN already has into the signal
// vocabulary. It is the only place that knows how those types spell things.
//
// Two reasons it lives here rather than in each subsystem. A rule author then
// needs to know one vocabulary instead of five APIs, and a change to a
// subsystem's shape becomes a change to one file rather than to every rule
// that touched it.
//
// Every derivation here is a projection. None of it makes a judgement, and
// none of it reads the host: the caller supplies types it has already read.
//
// # Unreadable is not healthy
//
// The most important line in this file is the handling of unsupported
// observations. When THN cannot inspect a host, every signal derived from that
// inspection is unknown — not false, and not zero. A gateway whose WAN is
// genuinely down and a gateway THN cannot see both produce a set of unknowns,
// and the difference is visible in the signals, which is the point.

// Sources, as they appear in Signal.Source and in signal names.
const (
	SourceNetwork   = "network"
	SourceFirewall  = "firewall"
	SourceDHCP      = "dhcp"
	SourceQoS       = "qos"
	SourceConfig    = "config"
	SourceDrift     = "drift"
	SourceDevice    = "device"
	SourceHeartbeat = "thn"
)

// Signal names. These are part of the package's contract: they appear in
// suppression rules, in incident output and in tests.
const (
	// Network.
	NetInspectSupported = "network.inspect.supported"
	NetWANPresent       = "network.wan.present"
	NetWANUp            = "network.wan.up"
	NetLANPresent       = "network.lan.present"
	NetLANUp            = "network.lan.up"
	NetDefaultRoute     = "network.route.default"
	NetIPv4Forwarding   = "network.forwarding.ipv4"

	// Firewall.
	FirewallActive = "firewall.active"
	FirewallRules  = "firewall.rules"

	// DHCP.
	DHCPPoolCapacity     = "dhcp.pool.capacity"
	DHCPPoolUsed         = "dhcp.pool.used"
	DHCPPoolUtilisation  = "dhcp.pool.utilisation"
	DHCPLeasesActive     = "dhcp.leases.active"
	DHCPDevicesUnknown   = "dhcp.devices.uncorrelated"
	DHCPLastCollectedAge = "dhcp.last-collected.age"

	// Traffic shaping.
	QoSActive        = "qos.active"
	QoSAlgorithm     = "qos.algorithm"
	QoSDropRatio     = "qos.drop.ratio"
	QoSOverlimitRate = "qos.overlimit.ratio"
	QoSBacklogBytes  = "qos.backlog.bytes"

	// Configuration and intent.
	ConfigValid      = "config.valid"
	ConfigErrCount   = "config.findings.error"
	ConfigWarnCount  = "config.findings.warning"
	DriftCount       = "drift.count"
	DriftConverged   = "drift.converged"
	DriftHighestRisk = "drift.highest-risk"

	// Device inventory.
	DevicesTotal       = "device.total"
	DevicesWeakID      = "device.weak-identity"
	DevicesStaleAfter  = "device.stale.count"
	HeartbeatAge       = "thn.heartbeat.age"
	HeartbeatAvailable = "thn.heartbeat.available"
)

// Label keys used by signals. The interface label is the one correlation
// groups by, so it is named here rather than spelled inline.
const (
	LabelInterface = "interface"
	LabelReason    = "reason"

	// LabelSource names the subsystem a signal came from. Correlation groups
	// on it, so it is set on every derived signal rather than only on the ones
	// a caller happens to remember.
	//
	// It duplicates Signal.Source deliberately: Source is a field and this is
	// a label, and correlation groups on labels because that is what survives
	// being carried through an instance and back out again.
	LabelSource = "source"
)

// Derive projects an observed host into signals.
//
// obs carries only what diff.Compare consumes, which is a flattened
// projection with no error channel: findings from network.Snapshot are
// dropped on the way in. Where that matters, TakeSnapshot is used instead and
// its diagnostics are projected as signals in their own right.
func Derive(obs diff.Observed, at time.Time) *Set {
	if at.IsZero() {
		at = time.Now().UTC()
	}

	var sigs []Signal

	add := func(name, source string, v Value, detail string) {
		sigs = append(sigs, Signal{
			Name:   name,
			Source: source,
			Value:  v,
			At:     at,
			Detail: detail,
		})
	}

	// An unobservable host reports unknown for everything, rather than
	// reporting absence. `diff.Observed.Supported` is the only field that
	// distinguishes "I looked and it is down" from "I did not look".
	supported := obs.Supported

	boolOf := func(observed bool) Value {
		if !supported {
			return Unknown(KindBool)
		}
		return Bool(observed)
	}
	numOf := func(n int) Value {
		if !supported {
			return Unknown(KindNumber)
		}
		return Number(float64(n))
	}

	// network.inspect.supported is the one signal that is always known, even
	// on a host that could not be inspected.
	//
	// It records the failure itself. Routing it through boolOf would make the
	// record of the failure unknown whenever there was one, which is precisely
	// backwards: it is the signal that tells a rule, and an operator, that
	// everything else is unreadable.
	add(NetInspectSupported, SourceNetwork, Bool(supported), inspectDetail(supported))

	add(NetWANPresent, SourceNetwork, boolOf(obs.WANPresent),
		fmt.Sprintf("the configured WAN interface %q was %s", orNone(obs.WANName), presentLabel(obs.WANPresent)))
	add(NetWANUp, SourceNetwork, boolOf(obs.WANUp),
		fmt.Sprintf("%s is %s", orNone(obs.WANName), upLabel(obs.WANUp)))
	add(NetLANPresent, SourceNetwork, boolOf(obs.LANPresent),
		fmt.Sprintf("the configured LAN interface %q was %s", orNone(obs.LANName), presentLabel(obs.LANPresent)))
	add(NetLANUp, SourceNetwork, boolOf(obs.LANUp),
		fmt.Sprintf("%s is %s", orNone(obs.LANName), upLabel(obs.LANUp)))
	add(NetDefaultRoute, SourceNetwork, boolOf(obs.HasDefaultRoute),
		defaultRouteDetail(obs))
	add(NetIPv4Forwarding, SourceNetwork, forwardingValue(obs),
		forwardingDetail(obs))

	// diff.Observed carries no firewall or shaping observation of its own, so
	// these stay unknown unless the caller filled them in. Guessing would be
	// worse than not knowing: an absent observation is not a disabled
	// firewall.
	add(FirewallActive, SourceFirewall, Unknown(KindBool),
		"the firewall state was not part of this observation")
	add(FirewallRules, SourceFirewall, Unknown(KindNumber),
		"the firewall rule count was not part of this observation")

	add(QoSActive, SourceQoS, Unknown(KindBool),
		"the shaping state was not part of this observation")
	add(QoSAlgorithm, SourceQoS, Unknown(KindString),
		"the shaping algorithm was not part of this observation")

	_ = numOf // reserved: numeric observations join as the fields arrive
	_ = obs.QoSActive

	return NewSet(at, sigs...)
}

// TakeSnapshot projects a full network snapshot.
//
// This is the richer derivation, and it exists because network.Snapshot
// carries diagnostics that diff.Observed drops. Those diagnostics are the
// difference between "the WAN is down" and "THN could not read the WAN's
// state", and on an unattended device that difference is usually the whole
// answer.
func TakeSnapshot(snap *network.Snapshot, at time.Time) *Set {
	if snap == nil {
		return NewSet(at,
			Signal{
				Name: NetInspectSupported, Source: SourceNetwork,
				Value:  Bool(false),
				At:     at,
				Detail: "no host inspection was supplied",
			},
		)
	}

	if at.IsZero() {
		at = snap.CapturedAt
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	var sigs []Signal

	add := func(name, source string, v Value, detail string) {
		sigs = append(sigs, Signal{
			Name: name, Source: source, Value: v, At: at, Detail: detail,
			Labels: map[string]string{LabelSource: source},
		})
	}

	ifaceSig := func(name, iface string, state network.LinkState, present bool) {
		v := Unknown(KindBool)
		detail := fmt.Sprintf("interface %q was not found", orNone(iface))

		switch {
		case !snap.Supported:
			detail = "host inspection is not supported on this platform"
		case !present:
			// Known false. The interface was looked for and not found, which
			// is a real observation.
			v = Bool(false)
			detail = fmt.Sprintf("interface %q was not found on this host", orNone(iface))
		case state == network.LinkUp:
			v = Bool(true)
			detail = fmt.Sprintf("interface %q is up", iface)
		case state == network.LinkDown:
			v = Bool(false)
			detail = fmt.Sprintf("interface %q is present but down", iface)
		default:
			// Present but in a state THN does not classify. Reporting false
			// here would claim a link-down that was not observed.
			detail = fmt.Sprintf("interface %q is in state %q, which THN does not classify",
				iface, state)
		}

		sigs = append(sigs, Signal{
			Name:   name,
			Source: SourceNetwork,
			Value:  v,
			At:     at,
			Detail: detail,
			Labels: map[string]string{LabelInterface: iface},
		})
	}

	add(NetInspectSupported, SourceNetwork, Bool(snap.Supported), inspectDetail(snap.Supported))

	wan := snap.Interface(wanNameOf(snap))
	if wan != nil {
		ifaceSig(NetWANPresent, wan.Name, wan.State, true)
		ifaceSig(NetWANUp, wan.Name, wan.State, true)
	} else {
		ifaceSig(NetWANPresent, "", network.LinkUnknown, false)
		ifaceSig(NetWANUp, "", network.LinkUnknown, false)
	}

	lan := snap.Interface(lanNameOf(snap))
	if lan != nil {
		ifaceSig(NetLANPresent, lan.Name, lan.State, true)
		ifaceSig(NetLANUp, lan.Name, lan.State, true)
	} else {
		ifaceSig(NetLANPresent, "", network.LinkUnknown, false)
		ifaceSig(NetLANUp, "", network.LinkUnknown, false)
	}

	// A default route is either present or not; that is a real observation
	// whenever inspection worked at all.
	hasDefault := snap.DefaultRoute() != nil
	if snap.Supported {
		add(NetDefaultRoute, SourceNetwork, Bool(hasDefault),
			defaultRouteFromSnapshot(snap))
	} else {
		add(NetDefaultRoute, SourceNetwork, Unknown(KindBool),
			"host inspection is not supported on this platform")
	}

	// The forwarding sysctl is read directly rather than through
	// Snapshot.IPForwardingEnabled, which returns a bare bool and therefore
	// cannot distinguish "the kernel says 0" from "the key was not readable".
	// That distinction is the whole point of this package, so it is not taken
	// through a helper that has already thrown it away.
	if raw, ok := snap.SysctlValue("net.ipv4.ip_forward"); ok && snap.Supported {
		fw := raw == "1"
		add(NetIPv4Forwarding, SourceNetwork, Bool(fw),
			fmt.Sprintf("the kernel reports net.ipv4.ip_forward = %s", orNone(raw)))
	} else {
		detail := "the forwarding sysctl could not be read"
		if !snap.Supported {
			detail = "host inspection is not supported on this platform"
		}
		add(NetIPv4Forwarding, SourceNetwork, Unknown(KindBool), detail)
	}

	// The diagnostics network.Snapshot collected are projected as signals in
	// their own right, so that a tool which could not read something says so
	// in the same vocabulary as the things it did read.
	for _, d := range snap.Diagnostics {
		sigs = append(sigs, Signal{
			Name:   "network.diagnostic." + SourceOf(d.Subject),
			Source: SourceNetwork,
			Value:  Bool(false),
			At:     at,
			Detail: fmt.Sprintf("[%s] %s: %s", d.Severity, d.Subject, d.Message),
			Labels: map[string]string{
				LabelInterface: d.Subject,
				LabelReason:    d.Severity,
			},
		})
	}

	return NewSet(at, sigs...)
}

// DeriveDHCP projects a lease-pool summary.
//
// poolCapacity of zero is a real observation — an empty pool is a
// configuration state, not a missing reading — so the utilisation is reported
// as zero rather than unknown, and the capacity signal carries the reason.
func DeriveDHCP(sum dhcp.Summary, collectedAt, now time.Time) []Signal {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if collectedAt.IsZero() {
		collectedAt = now
	}

	capacity := float64(sum.PoolCapacity)
	utilisation := 0.0
	if capacity > 0 {
		utilisation = sum.PoolUtilisation
	}

	age := now.Sub(collectedAt)
	// A negative age means the collection is stamped in the future, which is
	// a clock problem rather than a fresh collection. It is clamped to zero:
	// the detail explains the clock, but a rule that reads this value would
	// otherwise compute a negative rate from it, and a rule that fires on
	// "rate is negative" would fire on every badly-clocked host.
	stale := age < 0
	if stale {
		age = 0
	}

	return []Signal{
		{
			Name: DHCPPoolCapacity, Source: SourceDHCP,
			Value:  Number(capacity),
			At:     collectedAt,
			Detail: fmt.Sprintf("the pool holds %d addresses", sum.PoolCapacity),
		},
		{
			Name: DHCPPoolUsed, Source: SourceDHCP,
			Value:  Number(float64(sum.AddressesInUse)),
			At:     collectedAt,
			Detail: fmt.Sprintf("%d of %d pool addresses are held", sum.AddressesInUse, sum.PoolCapacity),
		},
		{
			Name: DHCPPoolUtilisation, Source: SourceDHCP,
			Value:  Number(utilisation),
			At:     collectedAt,
			Detail: fmt.Sprintf("%.1f%% of %d addresses are held", utilisation*100, sum.PoolCapacity),
		},
		{
			Name: DHCPLeasesActive, Source: SourceDHCP,
			Value: Number(float64(sum.Active)),
			At:    collectedAt,
			Detail: fmt.Sprintf("%d active, %d expired, %d reserved of %d leases",
				sum.Active, sum.Expired, sum.Reserved, sum.Total),
		},
		{
			Name: DHCPDevicesUnknown, Source: SourceDHCP,
			Value:  Number(float64(sum.Uncorrelated)),
			At:     collectedAt,
			Detail: fmt.Sprintf("%d leases have no identified device behind them", sum.Uncorrelated),
		},
		{
			Name: DHCPLastCollectedAge, Source: SourceDHCP,
			Value:  Number(age.Seconds()),
			At:     now,
			Detail: collectionAgeDetail(age, stale),
		},
	}
}

// DeriveDevices projects a device registry.
//
// The three counts answer three different questions an operator asks: how many
// devices are there, how many are we not sure about, and how many have gone
// quiet. Collapsing them into one "device count" would answer none of them.
func DeriveDevices(reg *identity.Registry, now time.Time, staleAfter time.Duration) []Signal {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if reg == nil {
		return []Signal{
			{Name: DevicesTotal, Source: SourceDevice, Value: Unknown(KindNumber), At: now,
				Detail: "no device registry was supplied"},
			{Name: DevicesWeakID, Source: SourceDevice, Value: Unknown(KindNumber), At: now,
				Detail: "no device registry was supplied"},
			{Name: DevicesStaleAfter, Source: SourceDevice, Value: Unknown(KindNumber), At: now,
				Detail: "no device registry was supplied"},
		}
	}

	all := reg.All()

	var weak, stale int
	for _, d := range all {
		if d.Confidence == identity.ConfidenceWeak || d.Confidence == identity.ConfidenceUnknown {
			weak++
		}
		if staleAfter > 0 && d.Age(now) > staleAfter {
			stale++
		}
	}

	return []Signal{
		{
			Name: DevicesTotal, Source: SourceDevice,
			Value:  Number(float64(len(all))),
			At:     now,
			Detail: fmt.Sprintf("%d devices have been seen", len(all)),
		},
		{
			Name: DevicesWeakID, Source: SourceDevice,
			Value:  Number(float64(weak)),
			At:     now,
			Detail: fmt.Sprintf("%d devices are identified only by hostname or not at all", weak),
		},
		{
			Name: DevicesStaleAfter, Source: SourceDevice,
			Value:  Number(float64(stale)),
			At:     now,
			Detail: fmt.Sprintf("%d devices have not been seen for over %s", stale, staleAfter),
		},
	}
}

// DeriveQoS projects queue counters.
//
// An absent qdisc is a real observation — the kernel's default queue is in
// place and it is not shaping — so it is reported as known. Only a failed read
// is unknown.
func DeriveQoS(snap qostc.Snapshot, at time.Time) []Signal {
	if at.IsZero() {
		at = time.Now().UTC()
	}

	labels := map[string]string{LabelInterface: snap.Interface}

	if !snap.Present {
		return []Signal{
			{
				Name: QoSActive, Source: SourceQoS, Value: Bool(false), At: at,
				Detail: "no root queue discipline is attached; the kernel default queue is in use",
				Labels: labels,
			},
			{
				Name: QoSAlgorithm, Source: SourceQoS, Value: String("none"), At: at,
				Detail: "no shaping algorithm is in use",
				Labels: labels,
			},
			{Name: QoSDropRatio, Source: SourceQoS, Value: Number(0), At: at,
				Detail: "the default queue reports no drop ratio", Labels: labels},
			{Name: QoSOverlimitRate, Source: SourceQoS, Value: Number(0), At: at,
				Detail: "the default queue reports no overlimits", Labels: labels},
			{Name: QoSBacklogBytes, Source: SourceQoS, Value: Number(0), At: at,
				Detail: "the default queue holds no backlog", Labels: labels},
		}
	}

	root := snap.Root

	active := Bool(true)
	detail := fmt.Sprintf("the root queue on %s is %s", orNone(snap.Interface), orNone(root.Algorithm))

	if root.Algorithm == "pfifo_fast" || root.Algorithm == "pfifo" {
		// Present, but not shaping. A qdisc existing is not a gateway
		// shaping, and conflating them would report a default queue as
		// working traffic management.
		active = Bool(false)
		detail = fmt.Sprintf("the root queue on %s is the kernel default (%s), which does not shape",
			orNone(snap.Interface), root.Algorithm)
	}

	return []Signal{
		{Name: QoSActive, Source: SourceQoS, Value: active, At: at, Detail: detail, Labels: labels},
		{Name: QoSAlgorithm, Source: SourceQoS, Value: String(root.Algorithm), At: at,
			Detail: fmt.Sprintf("the shaping algorithm is %s", orNone(root.Algorithm)), Labels: labels},
		{Name: QoSDropRatio, Source: SourceQoS, Value: Number(root.DropRatio()), At: at,
			Detail: root.Explain(), Labels: labels},
		{Name: QoSOverlimitRate, Source: SourceQoS, Value: Number(root.OverlimitRatio()), At: at,
			Detail: fmt.Sprintf("%d of %d packets hit the shaper limit",
				root.Overlimits, root.Packets), Labels: labels},
		{Name: QoSBacklogBytes, Source: SourceQoS, Value: Number(float64(root.BacklogBytes)), At: at,
			Detail: fmt.Sprintf("%d bytes are queued across %d packets",
				root.BacklogBytes, root.BacklogPackets), Labels: labels},
	}
}

// DeriveValidation projects a validation result.
//
// Severity is mapped rather than copied: validation's three levels and the
// ones rules use are the same concept, and translating them here keeps the
// rest of the pipeline free of a dependency on validation's vocabulary.
func DeriveValidation(r validation.Result, at time.Time) []Signal {
	if at.IsZero() {
		at = time.Now().UTC()
	}

	return []Signal{
		{
			Name: ConfigValid, Source: SourceConfig, Value: Bool(r.Valid), At: at,
			Detail: validDetail(r),
		},
		{
			Name: ConfigErrCount, Source: SourceConfig, Value: Number(float64(r.ErrorCount)), At: at,
			Detail: fmt.Sprintf("%d configuration errors across layers %v", r.ErrorCount, r.Layers),
		},
		{
			Name: ConfigWarnCount, Source: SourceConfig, Value: Number(float64(r.WarningCount)), At: at,
			Detail: fmt.Sprintf("%d configuration warnings across layers %v", r.WarningCount, r.Layers),
		},
	}
}

// DeriveDrift projects a comparison result.
func DeriveDrift(r diff.Result, at time.Time) []Signal {
	if at.IsZero() {
		at = time.Now().UTC()
	}

	convergedDetail := "the host matches the intended configuration"
	switch {
	case !r.Converged:
		convergedDetail = fmt.Sprintf("%d pending, %d drifted, %d blocked changes",
			r.PendingCount, r.DriftCount, r.BlockedCount)
	case r.PendingCount > 0:
		// Converged with work still pending means "nothing to do", not
		// "verified correct". diff reports it that way because an
		// unobservable host produces exactly this state, and there is
		// genuinely nothing for THN to do about it.
		//
		// The detail has to say so. The value alone reads as "everything is
		// fine", and an operator who read only the value would conclude a
		// gateway that THN has never successfully inspected was verified.
		convergedDetail = fmt.Sprintf(
			"%d changes are pending because the host could not be observed; "+
				"nothing is known to be wrong, and nothing has been verified either", r.PendingCount)
	}

	return []Signal{
		{
			Name: DriftCount, Source: SourceDrift, Value: Number(float64(r.DriftCount)), At: at,
			Detail: fmt.Sprintf("%d fields differ from the intended configuration", r.DriftCount),
		},
		{
			Name: DriftConverged, Source: SourceDrift, Value: Bool(r.Converged), At: at,
			Detail: convergedDetail,
		},
		{
			Name: DriftHighestRisk, Source: SourceDrift, Value: String(string(r.HighestRisk)), At: at,
			Detail: fmt.Sprintf("the highest risk among the differences is %s", r.HighestRisk),
		},
	}
}

// DeriveHeartbeat projects how long ago THN itself last ran.
//
// A gateway that stops reporting is indistinguishable from a gateway that has
// failed, and the difference matters more than any individual subsystem check:
// without a heartbeat, silence is ambiguous. This makes it explicit.
func DeriveHeartbeat(lastSeen, now time.Time) Signal {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if lastSeen.IsZero() {
		return Signal{
			Name: HeartbeatAvailable, Source: SourceHeartbeat, Value: Bool(false), At: now,
			Detail: "no previous run has been recorded",
		}
	}

	age := now.Sub(lastSeen)
	return Signal{
		Name: HeartbeatAge, Source: SourceHeartbeat,
		Value:  Number(age.Seconds()),
		At:     now,
		Detail: fmt.Sprintf("the last recorded run was %s ago", age),
	}
}

// forwardValue maps diff's forwarding observation, honouring whether it was
// actually read.
//
// IPv4ForwardingKnown is the whole point: without it, an unread sysctl and a
// disabled one are the same false, and a rule guarding the firewall would
// stay silent on a host THN simply could not check.
func forwardingValue(obs diff.Observed) Value {
	if !obs.Supported || !obs.IPv4ForwardingKnown {
		return Unknown(KindBool)
	}
	return Bool(obs.IPv4Forwarding)
}

func forwardingDetail(obs diff.Observed) string {
	switch {
	case !obs.Supported:
		return "host inspection is not supported on this platform"
	case !obs.IPv4ForwardingKnown:
		return "the forwarding sysctl could not be read"
	case obs.IPv4Forwarding:
		return "the kernel is forwarding IPv4"
	default:
		return "the kernel is not forwarding IPv4; a gateway that does not forward routes nothing"
	}
}

func defaultRouteDetail(obs diff.Observed) string {
	if !obs.Supported {
		return "host inspection is not supported on this platform"
	}
	if !obs.HasDefaultRoute {
		return "the host has no default route, so it cannot reach anything beyond its own networks"
	}
	return fmt.Sprintf("the default route is via %s", orNone(obs.DefaultGateway))
}

func defaultRouteFromSnapshot(snap *network.Snapshot) string {
	r := snap.DefaultRoute()
	if r == nil {
		return "the host has no default route, so it cannot reach anything beyond its own networks"
	}
	gw := r.Gateway
	if gw == "" {
		gw = "on-link"
	}
	return fmt.Sprintf("the default route is via %s on %s", gw, r.Interface)
}

func inspectDetail(supported bool) string {
	if supported {
		return "this host was inspected successfully"
	}
	return "this host could not be inspected; every observation from it is unknown"
}

func presentLabel(present bool) string {
	if present {
		return "found on this host"
	}
	return "not found on this host"
}

func upLabel(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func validDetail(r validation.Result) string {
	if r.Valid {
		return "the configuration passed validation"
	}
	return fmt.Sprintf("the configuration has %d errors and %d warnings",
		r.ErrorCount, r.WarningCount)
}

func collectionAgeDetail(age time.Duration, stale bool) string {
	switch {
	case stale:
		return "the last lease collection is stamped in the future; the host clock is wrong " +
			"or unsynchronised, and lease ages cannot be trusted"
	case age < 0:
		return "the last lease collection has a negative age"
	default:
		return fmt.Sprintf("leases were last collected %s ago", age.Round(time.Second))
	}
}

// wanNameOf returns the snapshot's WAN interface name, or "".
func wanNameOf(snap *network.Snapshot) string {
	for _, i := range snap.Interfaces {
		if i.Role == network.RoleWAN {
			return i.Name
		}
	}
	return ""
}

// lanNameOf returns the snapshot's LAN interface name, or "".
func lanNameOf(snap *network.Snapshot) string {
	for _, i := range snap.Interfaces {
		if i.Role == network.RoleLAN {
			return i.Name
		}
	}
	return ""
}

// orNone renders an empty string as a placeholder.
func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}
