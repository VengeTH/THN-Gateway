package host

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/network"
)

// Discovery produces an observed Device.
//
// Everything that knows how to read a host implements this, and nothing else in
// THN does. The rest of the codebase consumes a Device and has no way to ask
// what platform it came from, which is the point: a planner written against
// /sys or netlink is a planner that cannot be tested on a laptop.
//
// A Discovery is read-only by construction. It is given the Snapshot that
// internal/network already produced rather than being handed a command runner,
// so adding an implementation cannot introduce a path that executes anything.
type Discovery interface {
	// Discover returns the observed host.
	Discover() (*Device, error)

	// Describe names the implementation, for `thn discover`.
	Describe() string
}

// FromSnapshot adapts an already-collected network observation into a Device.
//
// It is the whole of the Linux edge. internal/network owns every /sys, ip,
// nft and tc call; this turns the result into a model that does not care where
// it came from.
func FromSnapshot(snap *network.Snapshot) *Device {
	d := &Device{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		ObservedAt: time.Now().UTC(),
		Hostname:   hostnameOf(snap),
	}

	if snap == nil || !snap.Supported {
		// Not supported is reported as unsupported, not as an empty host with
		// every capability missing. The difference matters: the first says
		// "we did not look", the second says "we looked and it cannot".
		d.Supported = false
		d.Diagnostics = append(d.Diagnostics,
			fmt.Sprintf("host inspection is unavailable on %s/%s; "+
				"no interfaces and no capabilities were observed",
				runtime.GOOS, runtime.GOARCH))
		d.Probes = probeRecords(snap, d)
		if len(d.Probes) == 0 {
			d.Probes = []network.Probe{
				network.NotChecked("host-inspection", "observe-host"),
			}
		}
		d.Capabilities = capabilitiesFor(d, nil)
		return d
	}

	d.Supported = true
	d.Interfaces = interfacesFrom(snap.Interfaces, snap.Addresses)
	sort.Slice(d.Interfaces, func(a, b int) bool {
		return d.Interfaces[a].SystemName < d.Interfaces[b].SystemName
	})

	for _, diag := range snap.Diagnostics {
		if diag.Severity == "error" {
			d.Diagnostics = append(d.Diagnostics, diag.Subject+": "+diag.Message)
		}
	}

	// The subsystem observations are carried through verbatim. They are
	// observations of somebody else's configuration — a Docker bridge, a
	// Tailscale table, a distribution's DNS stub — and copying them across
	// unchanged is what keeps "what THN saw" and "what THN thinks" from
	// drifting apart.
	d.System = snap.System
	d.NFTables = snap.NFTables
	d.TrafficControl = snap.TrafficControl
	d.DNS = snap.DNS
	d.Routes = snap.Routes

	d.ForwardingEnabled, d.ForwardingKnown = forwardingFrom(snap)
	d.Probes = probeRecords(snap, d)
	d.Capabilities = capabilitiesFor(d, snap)
	return d
}

// probeRecords collects every probe a snapshot made.
//
// Assembled here rather than copied field by field because a probe that is
// forgotten when a new subsystem is added is precisely the kind of silent gap
// this collection exists to prevent: the subsystem would report an unknown with
// no record of having been asked.
//
// Ordered so that the same host always produces the same list. The per-link
// probes come from a map in the snapshot's source, so they are sorted by
// interface name rather than left in whatever order iteration produced.
func probeRecords(snap *network.Snapshot, d *Device) []network.Probe {
	if snap == nil {
		return []network.Probe{network.NotChecked("host-inspection", "observe-host")}
	}

	out := make([]network.Probe, 0, len(snap.Probes)+len(snap.Diagnostics))
	out = append(out, snap.Probes...)

	// The three subsystem states each carry their own probe, and they are
	// appended unconditionally so that "the probe is missing" is itself
	// visible: a state with a zero Probe means the observer never recorded one.
	if snap.NFTables.Probe.Subsystem != "" {
		out = append(out, snap.NFTables.Probe)
	}
	if snap.TrafficControl.Probe.Subsystem != "" {
		out = append(out, snap.TrafficControl.Probe)
	}
	if snap.DNS.Probe.Subsystem != "" {
		out = append(out, snap.DNS.Probe)
	}

	// Forwarding gets a record too, because it is the one sysctl a gateway
	// cannot work without and it has three possible answers: enabled,
	// disabled, and unreadable. The third is a THN problem and produces no
	// diagnostic on its own.
	out = append(out, forwardingProbe(snap))

	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Subsystem != out[b].Subsystem {
			return out[a].Subsystem < out[b].Subsystem
		}
		if out[a].Operation != out[b].Operation {
			return out[a].Operation < out[b].Operation
		}
		if out[a].Path != out[b].Path {
			return out[a].Path < out[b].Path
		}
		return out[a].Detail < out[b].Detail
	})
	return out
}

// NotCheckedProbe returns the record for a probe nothing was run for.
//
// Wrapped here rather than using network.NotChecked directly at every call
// site, so that "nothing was asked" always carries a stage and an outcome. A
// bare zero Probe would render as empty fields, which is indistinguishable
// from a probe that was never filled in.
func NotCheckedProbe(subsystem, operation string) network.Probe {
	return network.NotChecked(subsystem, operation)
}

// findForwardingProbe locates the forwarding record among a device's probes.
func findForwardingProbe(probes []network.Probe) (network.Probe, bool) {
	for _, p := range probes {
		if p.Subsystem == "forwarding" {
			return p, true
		}
	}
	return network.Probe{}, false
}

// firstProbeFor returns the first probe recorded for any of the named
// subsystems.
//
// Used where a capability rests on a source with many records — every radio on
// the host produces one — and any single one of them is representative of
// whether the source was consulted at all.
func firstProbeFor(probes []network.Probe, subsystems ...string) network.Probe {
	for _, want := range subsystems {
		for _, p := range probes {
			if p.Subsystem == want && p.Subsystem != "" {
				return p
			}
		}
	}
	return NotCheckedProbe("observation", "unrecorded")
}

// forwardingProbe records how the IPv4 forwarding setting was determined.
func forwardingProbe(snap *network.Snapshot) network.Probe {
	p := network.Probe{Subsystem: "forwarding", Operation: "sysctl-ipv4-forward"}

	for _, s := range snap.Sysctl {
		if s.Key != "net.ipv4.ip_forward" {
			continue
		}
		if s.Error != "" {
			// The reason is preserved verbatim. "could not read it" and "it is
			// off" are opposite diagnoses, and an operator who has been told
			// only that forwarding is unavailable cannot tell which they have.
			p.Stage = network.StageExecute
			p.Outcome = network.ProbeExecutionFailed
			p.Detail = "the setting exists but could not be read"
			p.Reason = s.Error
			return p
		}
		if s.Value == "unknown" {
			p.Stage = network.StageParse
			p.Outcome = network.ProbeParseFailed
			p.Detail = "sysctl returned no usable value for the setting"
			p.Reason = "sysctl -n net.ipv4.ip_forward returned the literal \"unknown\""
			return p
		}
		if s.Value == "1" {
			p = network.Succeeded(p, "the setting was read and IPv4 forwarding is enabled", 1)
			return p
		}
		// A successful read that found forwarding off.
		//
		// Count is zero on purpose. The probe asked "is forwarding on?" and the
		// answer was no, which is no_evidence — the same classification a host
		// with no CAKE discipline gets. Reporting it as positive evidence
		// would make "checked and found off" indistinguishable from "checked
		// and found on", which is the distinction the operator needs.
		p = network.Succeeded(p, "the setting was read and IPv4 forwarding is disabled", 0)
		return p
	}

	// The key was not observed at all, which is different from it being off
	// and different from a failed read.
	p = network.NotChecked("forwarding", "sysctl-ipv4-forward")
	p.Detail = "net.ipv4.ip_forward was not present in the collected sysctl values"
	return p
}

// interfacesFrom converts observed interfaces, assigning no roles.
//
// Addresses come from the snapshot's FLAT list rather than from the copies
// internal/network hangs on each interface. The inspector populates both, but
// a snapshot built by anything else populates only one, and silently producing
// a device with no addresses is a far worse failure than the extra loop.
func interfacesFrom(in []network.Interface, flat []network.Address) []Interface {
	byName := make(map[string][]string, len(in))
	for _, a := range flat {
		byName[a.Interface] = append(byName[a.Interface], a.CIDR)
	}

	out := make([]Interface, 0, len(in))

	for _, i := range in {
		// The nested copies win when present; the flat list is the fallback.
		addrs := make([]string, 0, len(i.Addresses))
		for _, a := range i.Addresses {
			addrs = append(addrs, a.CIDR)
		}
		if len(addrs) == 0 {
			addrs = byName[i.Name]
		}

		linkKind := NormaliseKind(i.Kind)
		id, kind := InterfaceID(linkKind, i.MAC, i.Index)
		out = append(out, Interface{
			ID:           id,
			IDKind:       kind,
			SystemName:   i.Name,
			Index:        i.Index,
			Kind:         linkKind,
			RawKind:      i.Kind,
			Physical:     i.Physical,
			Virtual:      !i.Physical,
			AdminUp:      i.AdminUp,
			LinkUp:       i.State == network.LinkUp,
			Master:       i.Master,
			WirelessMode: i.WirelessMode,
			MAC:          i.MAC,
			State:        i.State,
			MTU:          i.MTU,
			SpeedMbps:    i.SpeedMbps,
			Addresses:    addrs,
			// Roles are assigned by configuration. Nothing here infers one.
			Role:       RoleUnassigned,
			Assignable: assignable(linkKind),
		})
	}
	return out
}

// assignable reports whether an interface could reasonably hold a role.
//
// # The exclusions, and why each one
//
// This used to exclude loopback and nothing else. Two more kinds are now
// excluded, and neither exclusion is about the link being "not a real port" —
// it is about the link not outliving a decision.
//
//	veth    A container's endpoint. It exists while a container runs and
//	        disappears when it stops. Binding a gateway's LAN to one would
//	        work perfectly until the container was restarted, and then fail
//	        in a way nobody would connect to the original configuration.
//	dummy   Exists to be a placeholder. It has no peer and never will.
//
// Deliberately NOT excluded: bridges, bonds, VLANs and tunnels. An operator
// may legitimately want the LAN on a bridge, and THN is in no position to
// decide that a bridge is a lesser citizen. Those are judged by what the
// operator assigns, and by profile evaluation — not by a hard-coded list.
//
// An interface that is currently DOWN is still assignable. Plugging the cable
// in after configuring is the normal order of operations.
func assignable(kind string) bool {
	switch kind {
	case KindLoopback, KindVeth, KindDummy:
		return false
	default:
		return true
	}
}

// # The kernel's vocabulary is not THN's
//
// `ip -j -d link show` reports info_kind "ether" for a wired NIC and "wlan"
// for a wireless one. THN's renderer says "Ethernet", and its wireless
// capability check asks for "wireless".
//
// That mismatch was invisible: every test fixture was written in THN's
// vocabulary, because the fixtures were built from the model rather than
// captured from a host. On a real machine `thn discover` printed "Ether" and
// reported wireless-ap NOT AVAILABLE with a Wi-Fi card fitted and working.
//
// The correction happens HERE, at the edge, in one function. Everywhere above
// this line THN speaks one vocabulary, and the kernel's is preserved in
// RawKind for the case where the distinction matters.
func NormaliseKind(raw string) string {
	switch raw {
	case "":
		return ""
	case "ether", "ethernet":
		return KindEthernet
	case "loopback":
		return KindLoopback
	case "wlan", "wireless":
		return KindWireless
	case "bridge":
		return KindBridge
	case "vlan":
		return KindVLAN
	case "bond", "team":
		return KindBond
	case "tun", "tap", "tunnel":
		return KindTunnel
	case "dummy":
		return KindDummy
	default:
		return raw
	}
}

// forwardingFrom reads the kernel's forwarding setting out of the snapshot.
//
// It is an observation of the sysctl the observer already collected, not a
// separate probe.
//
// The second return is whether the value was actually READ, and it is the more
// important of the two. Without it, "forwarding is off" and "THN could not
// read the forwarding setting" produce an identical model, and a host THN
// failed to inspect reports identically to a correctly-configured host with
// forwarding genuinely disabled. Only the second of those is a gateway
// problem, and conflating them sends an operator to debug a setting that was
// never wrong.
func forwardingFrom(snap *network.Snapshot) (enabled, known bool) {
	if snap == nil {
		return false, false
	}
	for _, s := range snap.Sysctl {
		if s.Key == "net.ipv4.ip_forward" {
			// A value that could not be read is recorded as the literal
			// string "unknown" by the observer, and carries an Error.
			if s.Error != "" || s.Value == "unknown" {
				return false, false
			}
			return s.Value == "1", true
		}
	}
	return false, false
}

// hostnameOf returns the observed system hostname.
//
// It reads the hostname the platform observer recorded, which is the machine's
// own name. It deliberately does not synthesise one from an interface address:
// an earlier version returned the loopback CIDR, which rendered as
// "hostname 127.0.0.1/8" — an address presented under a hostname label,
// identical on every Linux host and therefore carrying no information.
//
// The observation layer owns reading the host, so this is a copy of a fact
// already gathered rather than a second, divergent way to establish one. An
// empty result means the platform could not report a hostname, never that the
// machine has none.
func hostnameOf(snap *network.Snapshot) string {
	if snap == nil {
		return ""
	}
	return snap.System.Hostname
}

// capabilitiesFor derives what the host can do.
//
// The rule throughout: a capability is AVAILABLE only when something was
// observed that establishes it. Where THN has to reason from the platform
// rather than a probe, it says "inferred" rather than "observed", so a caller
// that must not guess can refuse to accept an inferred answer.
func capabilitiesFor(d *Device, snap *network.Snapshot) map[Capability]CapabilityState {
	caps := make(map[Capability]CapabilityState, len(AllCapabilities()))

	set := func(c Capability, available bool, confidence Confidence, reason string) {
		caps[c] = CapabilityState{Available: available, Confidence: confidence, Reason: reason}
	}

	if !d.Supported {
		for _, c := range AllCapabilities() {
			set(c, false, ConfidenceUnknown,
				"host inspection is unavailable, so this capability was not determined")
		}
		return caps
	}

	// Routing and forwarding depend on the kernel's own setting, which the
	// observer already read. That is an observation, not an inference.
	//
	// Forwarding carries its own uncertainty: if the sysctl could not be
	// read at all, the verdict is unknown rather than "off". A gateway that
	// cannot read the one setting it most needs is a gateway THN should
	// describe honestly rather than report as correctly-configured-but-off.
	if d.ForwardingKnown {
		set(CapRouting, true, ConfidenceObserved, "the kernel routes; THN observed net.ipv4.ip_forward")
		set(CapForwarding, d.ForwardingEnabled, ConfidenceObserved,
			fmt.Sprintf("observed net.ipv4.ip_forward=%v", d.ForwardingEnabled))
	} else {
		set(CapRouting, false, ConfidenceUnknown,
			"net.ipv4.ip_forward could not be read, so routing was not determined")
		set(CapForwarding, false, ConfidenceUnknown,
			"net.ipv4.ip_forward could not be read, so forwarding was not determined")
	}

	// NAT is conntrack plus masquerade. THN reads the nft tables it would
	// plan against but does not probe module availability, so this is
	// inferred from the platform and labelled as such.
	set(CapNAT, true, ConfidenceInferred, "inferred from the Linux platform; conntrack availability was not probed")

	// DHCP and DNS are served by software THN would run, not by the kernel.
	// Availability here means "not blocked by what was observed", which is a
	// weaker claim and is labelled weaker.
	set(CapDHCP, true, ConfidenceInferred, "inferred: DHCP is served in userspace, not provided by the kernel")
	set(CapDNS, true, ConfidenceInferred, "inferred: DNS is served in userspace, not provided by the kernel")

	// Firewall: nftables is the only supported backend. Whether nftables is
	// installed and answerable is now OBSERVED rather than inferred, because
	// M7.0 actually asks the host. This is the clearest example in the
	// codebase of a capability moving from inference to observation, and it
	// moved only because a probe was written — not because the answer was
	// assumed to be yes.
	set(CapFirewall, d.NFTables.QuerySucceeded, d.nftConfidence(),
		d.nftReason())

	// nftables itself, separately from the firewall built on it.
	set(CapNFTables, d.NFTables.QuerySucceeded, d.nftConfidence(), d.nftReason())

	// Traffic control. Observed, because M7.0 queries it.
	set(CapTC, d.TrafficControl.QuerySucceeded, tcConfidence(d.TrafficControl),
		tcReason(d.TrafficControl))

	// CAKE, the strictest capability in the model.
	//
	// `tc` being installed proves nothing: sch_cake is a kernel module and
	// tc does not consult it until asked to install one. Asking would be
	// mutation. So the ONLY non-mutating evidence that CAKE works is a CAKE
	// discipline already attached — and absent that, this is UNKNOWN.
	//
	// Note what is NOT done here: a CAKE-less host is not reported as
	// lacking CAKE. It is reported as unknown, because that is the truth.
	set(CapCake, d.TrafficControl.CakeObserved, cakeConfidence(d.TrafficControl),
		cakeReason(d.TrafficControl))

	// QoS: shaping needs an egress interface, and a configured rate.
	//
	// The availability signal stays weak on purpose. Knowing that some
	// interface exists does not mean a shaped rate is knowable: the correct
	// rate depends on the provisioned uplink, which the negotiated link speed
	// is not. Reporting availability here says "THN could shape here", not
	// "THN knows how fast this link is".
	set(CapQoS, d.TrafficControl.Available, tcConfidence(d.TrafficControl),
		"shaping needs tc and an interface to shape on; the correct rate "+
			"depends on the provisioned uplink, which is not observable ("+
			tcReason(d.TrafficControl)+")")

	// Multiple Ethernet ports: the canonical two-port gateway topology needs
	// two. Counted from observed physical Ethernet interfaces, never from
	// interface order and never from names.
	set(CapMultipleEthernet, d.CountKind(KindEthernet) >= 2, ConfidenceObserved,
		fmt.Sprintf("observed %d physical Ethernet interfaces; the canonical "+
			"two-port gateway topology needs 2", d.CountKind(KindEthernet)))

	// VLAN and bridging: derived from what kinds of interface were observed.
	//
	// A bridge present on a developer laptop because Docker created it is
	// still an observed bridge, and the reason says exactly that — so an
	// operator can tell "this machine bridges" from "this machine has a NIC
	// I could bridge on" without either being asserted in place of the other.
	set(CapVLAN, hasKind(d, KindVLAN), ConfidenceObserved, kindReason(d, KindVLAN, "no VLAN interface was observed"))
	set(CapBridge, hasKind(d, KindBridge), ConfidenceObserved, kindReason(d, KindBridge, "no bridge interface was observed"))

	// veth and network namespaces.
	//
	// Both are observed from existing instances rather than by creating one,
	// which would be mutation. That makes the negative case genuinely
	// uncertain rather than false: a host with no veth pair today may well
	// support creating one, and reporting that as established either way
	// would overclaim. Presence is observed; absence is inferred from the
	// weaker signal that nothing was seen.
	set(CapVeth, hasKind(d, KindVeth), presenceConfidence(hasKind(d, KindVeth)),
		presenceReason(d, KindVeth, "no veth interface was observed, so veth "+
			"support was not established (it was not tested: creating one would mutate the host)"))
	set(CapNetns, hasKind(d, KindVeth) || hasKind(d, KindBridge), presenceConfidence(hasNetnsEvidence(d)),
		presenceReason(d, KindNetnsLabel(), "no namespace-resident interface was observed, so "+
			"network namespace support was not established (it was not tested: creating one would mutate the host)"))

	// Wireless CLIENT and ACCESS POINT are separate capabilities on the same
	// hardware, and the observed mode is what tells them apart.
	//
	// Reporting both from mere presence would be the overclaim this package
	// exists to avoid: a laptop's Wi-Fi in managed mode is a client, and
	// claiming it can be an access point because a radio is fitted would be
	// reporting what the hardware could theoretically do rather than what was
	// observed.
	wlanClients, wlanAPs := wirelessByMode(d)
	wProbe := firstProbeFor(d.Probes, "wireless")

	set(CapWirelessClient, len(wlanClients) > 0, wirelessConfidence(wProbe, len(wlanClients) > 0),
		wirelessReason("client", wlanClients, wProbe,
			"no wireless interface was observed operating as a client (mode managed/station)"))
	set(CapWirelessAP, len(wlanAPs) > 0, wirelessConfidence(wProbe, len(wlanAPs) > 0),
		wirelessReason("access-point", wlanAPs, wProbe,
			"no wireless interface was observed operating as an access point (mode AP)"))
	return caps
}

func wirelessConfidence(p network.Probe, present bool) Confidence {
	if present {
		return ConfidenceObserved
	}
	if p.Outcome.BlocksClaim() {
		return ConfidenceUnknown
	}
	return ConfidenceObserved
}

// nftConfidence reports how firmly nftables availability was established.
//
// The distinction it preserves is the one that matters operationally: a host
// where nft is not installed is known to lack it, while a host where nft
// exists but could not be queried has not been determined. Both are
// unavailable, but only the second is uncertain, and an operator debugging
// "why does THN think nft is unavailable" needs to be told which they have.
//
// An UNCHECKED state is always unknown. That case means nobody probed nft
// at all — the zero value of the struct, from a hand-built snapshot or a
// platform where inspection is unavailable — and reporting "nftables is not
// installed" from it would be asserting a finding nobody made.
func (d *Device) nftConfidence() Confidence {
	switch {
	case !d.NFTables.Checked:
		return ConfidenceUnknown
	case d.NFTables.QuerySucceeded:
		return ConfidenceObserved
	case d.NFTables.Available:
		// The binary is there; the query did not complete. Undetermined.
		return ConfidenceUnknown
	default:
		// The binary is absent, and we were in a position to find that out.
		// That is a positive finding, not a gap.
		return ConfidenceObserved
	}
}

// nftReason always explains the nftables verdict.
//
// Every capability in this model carries a reason — that invariant predates
// M7.0 and is worth more than brevity. A nil Reason here would render as a
// blank cell in the capability table, which is the least informative thing a
// report can say.
func (d *Device) nftReason() string {
	switch {
	case !d.NFTables.Checked:
		return "nftables was not probed on this host, so its availability was not determined"
	case d.NFTables.Reason != "":
		return d.NFTables.Reason
	case d.NFTables.QuerySucceeded:
		return fmt.Sprintf("observed: nft answered a ruleset query and reported %d table(s)",
			len(d.NFTables.Tables))
	default:
		return "nft is installed and answered a ruleset query"
	}
}

// tcConfidence mirrors nftConfidence for traffic control.
func tcConfidence(st network.TCState) Confidence {
	switch {
	case !st.Checked:
		return ConfidenceUnknown
	case st.QuerySucceeded:
		return ConfidenceObserved
	case st.Available:
		return ConfidenceUnknown
	default:
		return ConfidenceObserved
	}
}

// tcReason always explains the traffic control verdict.
func tcReason(st network.TCState) string {
	switch {
	case !st.Checked:
		return "traffic control was not probed on this host, so its availability was not determined"
	case st.Reason != "":
		return st.Reason
	case st.QuerySucceeded:
		return fmt.Sprintf("observed: tc answered a qdisc query and reported %d discipline(s)",
			len(st.Qdiscs))
	default:
		return "tc is installed and answered a qdisc query"
	}
}

// cakeConfidence decides how firmly CAKE availability is established.
//
// This is the function the "fail closed" requirement is really about, and it
// is asymmetric on purpose:
//
//	CakeObserved=true    OBSERVED — a CAKE discipline is attached and working
//	tc unavailable        OBSERVED — no CAKE, and no tc to have one
//	tc present, no cake   UNKNOWN  — THN cannot tell whether the kernel could
//	                                 load sch_cake without loading it
//
// The middle case is the whole point. `tc` being installed is not evidence
// about CAKE, so it is not treated as evidence. Reporting it as either
// available or unavailable would be a guess, and a guess here becomes a plan
// that shapes a link with an algorithm the kernel does not have.
func cakeConfidence(st network.TCState) Confidence {
	switch {
	case !st.Checked:
		return ConfidenceUnknown
	case st.CakeObserved:
		return ConfidenceObserved
	case !st.Available:
		return ConfidenceObserved
	default:
		return ConfidenceUnknown
	}
}

// cakeReason explains the CAKE verdict in every case.
func cakeReason(st network.TCState) string {
	switch {
	case !st.Checked:
		return "traffic control was not probed, so CAKE availability was not determined"
	case st.CakeObserved:
		return "observed: a CAKE queue discipline is attached on this host, so CAKE works here"
	case !st.Available:
		return "observed: tc is not installed on this host, so no CAKE discipline can be attached"
	default:
		return "tc is installed but whether this kernel provides the CAKE " +
			"scheduler is not established; THN cannot test it without " +
			"attaching a discipline, which would mutate the host"
	}
}

// presenceConfidence reports the confidence of a capability established purely
// by the presence of a resource.
//
// Presence is genuine evidence and is labelled observed. Absence is not
// evidence of impossibility — THN did not try to create the resource, and
// deliberately did not, because creating one would mutate a production host —
// so it is labelled inferred.
func presenceConfidence(present bool) Confidence {
	if present {
		return ConfidenceObserved
	}
	return ConfidenceInferred
}

// hasNetnsEvidence reports whether anything observed implies namespaces work.
//
// A veth pair or a bridge on a production host is nearly always a namespace
// resident link: that is where bridges and veths come from. It is suggestive
// rather than conclusive, which is exactly what an inferred confidence is for.
func hasNetnsEvidence(d *Device) bool {
	return hasKind(d, KindVeth) || hasKind(d, KindBridge)
}

// KindNetnsLabel names the evidence used for the netns capability.
//
// It is a label rather than a Kind because network namespaces are not a link
// kind — they are where links live. Naming it as a kind would invite a caller
// to look for an interface of kind "network-namespace", which cannot exist.
func KindNetnsLabel() string { return "network namespace resident link" }

// presenceReason explains a presence-based capability verdict.
func presenceReason(d *Device, kind, absent string) string {
	if hasKind(d, kind) {
		return kindReason(d, kind, absent)
	}
	return absent
}

// wirelessByMode separates observed wireless interfaces by operating mode.
//
// # Why the mode is required rather than assumed
//
// The first version counted ANY wireless interface as a client, because a
// wireless interface is a client by default. On a real gateway that produced
// the opposite error: a managed-mode adapter was reported as neither, and an
// adapter in AP mode would have been reported as both.
//
// A radio can be a station, an access point, a monitor, or a mesh point. They
// are different capabilities on identical hardware, and only the observed
// mode distinguishes them. So:
//
//	managed / station    → client
//	AP / master          → access point
//	monitor              → neither
//	mesh, adhoc          → neither
//	unknown / unreported → NEITHER
//
// An unreported mode is not a client. Claiming it would be exactly the
// "report a capability because the hardware could do it" the capability
// model exists to prevent, and it would satisfy a hard gate on a guess.
func wirelessByMode(d *Device) (clients, aps []string) {
	for _, i := range d.Interfaces {
		if i.Kind != KindWireless {
			continue
		}
		switch i.WirelessMode {
		case network.WirelessModeClient:
			clients = append(clients, i.SystemName)
		case network.WirelessModeAP:
			aps = append(aps, i.SystemName)
		}
	}
	sort.Strings(clients)
	sort.Strings(aps)
	return clients, aps
}

func wirelessReason(mode string, names []string, p network.Probe, absent string) string {
	if len(names) > 0 {
		return fmt.Sprintf("observed in %s mode on: %s", mode, strings.Join(names, ", "))
	}
	if p.Outcome.BlocksClaim() {
		return fmt.Sprintf("wireless %s could not be determined: probe ended %s (%s)", mode, p.Outcome, p.Detail)
	}
	return absent
}

func hasKind(d *Device, kind string) bool {
	for _, i := range d.Interfaces {
		if i.Kind == kind {
			return true
		}
	}
	return false
}

func kindReason(d *Device, kind, reason string) string {
	if hasKind(d, kind) {
		return fmt.Sprintf("a %s interface was observed", kind)
	}
	return reason
}
