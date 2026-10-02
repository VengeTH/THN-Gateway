package host

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/network"
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

	d.ForwardingEnabled = forwardingFrom(snap)
	d.Capabilities = capabilitiesFor(d, snap)
	return d
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
func forwardingFrom(snap *network.Snapshot) bool {
	if snap == nil {
		return false
	}
	for _, s := range snap.Sysctl {
		if s.Key == "net.ipv4.ip_forward" {
			return s.Value == "1"
		}
	}
	return false
}

// hostnameOf finds the loopback hostname, which is the one the observer saw.
func hostnameOf(snap *network.Snapshot) string {
	if snap == nil {
		return ""
	}
	for _, i := range snap.Interfaces {
		if i.Kind == "loopback" || i.Name == "lo" {
			for _, a := range i.Addresses {
				if strings.HasPrefix(a.CIDR, "127.") {
					return a.CIDR
				}
			}
		}
	}
	return ""
}

// capabilitiesFor derives what the host can do.
//
// The rule throughout: a capability is AVAILABLE only when something was
// observed that establishes it. Where THN has to reason from the platform
// rather than a probe, it says "inferred" rather than "observed", so a caller
// that must not guess can refuse to accept an inferred answer.
func capabilitiesFor(d *Device, snap *network.Snapshot) map[Capability]CapabilityState {
	caps := make(map[Capability]CapabilityState, len(AllCapabilities()))

	set := func(c Capability, available bool, confidence, reason string) {
		caps[c] = CapabilityState{Available: available, Confidence: confidence, Reason: reason}
	}

	if !d.Supported {
		for _, c := range AllCapabilities() {
			set(c, false, "unknown",
				"host inspection is unavailable, so this capability was not determined")
		}
		return caps
	}

	// Routing and forwarding depend on the kernel's own setting, which the
	// observer already read. That is an observation, not an inference.
	set(CapRouting, true, "observed", "the kernel routes; THN observed net.ipv4.ip_forward")
	set(CapForwarding, snap.IPForwardingEnabled(), "observed",
		fmt.Sprintf("observed net.ipv4.ip_forward=%v", snap.IPForwardingEnabled()))

	// NAT is conntrack plus masquerade. THN reads the nft tables it would
	// plan against but does not probe module availability, so this is
	// inferred from the platform and labelled as such.
	set(CapNAT, true, "inferred", "inferred from the Linux platform; conntrack availability was not probed")

	// DHCP and DNS are served by software THN would run, not by the kernel.
	// Availability here means "not blocked by what was observed", which is a
	// weaker claim and is labelled weaker.
	set(CapDHCP, true, "inferred", "inferred: DHCP is served in userspace, not provided by the kernel")
	set(CapDNS, true, "inferred", "inferred: DNS is served in userspace, not provided by the kernel")

	// Firewall: nftables is the only supported backend, but whether the
	// kernel would accept a table has NOT been probed by this package, so
	// this is an inference from the platform and is labelled one. Claiming it
	// were observed would be exactly the "report a capability because Linux
	// theoretically supports it" the design rules out.
	set(CapFirewall, true, "inferred",
		"inferred from the Linux platform; nftables availability was not probed")

	// QoS: shaping needs an egress interface, and a configured rate.
	//
	// The availability signal stays weak on purpose. Knowing that some
	// interface exists does not mean a shaped rate is knowable: the correct
	// rate depends on the provisioned uplink, which the negotiated link speed
	// is not. Reporting availability here says "THN could shape here", not
	// "THN knows how fast this link is".
	set(CapQoS, len(d.Interfaces) > 0, "inferred",
		"inferred: shaping needs an interface to shape on; the correct rate "+
			"depends on the provisioned uplink, which is not observable")

	// VLAN and bridging: derived from what kinds of interface were observed.
	//
	// A bridge present on a developer laptop because Docker created it is
	// still an observed bridge, and the reason says exactly that — so an
	// operator can tell "this machine bridges" from "this machine has a NIC
	// I could bridge on" without either being asserted in place of the other.
	set(CapVLAN, hasKind(d, KindVLAN), "observed", kindReason(d, KindVLAN, "no VLAN interface was observed"))
	set(CapBridge, hasKind(d, KindBridge), "observed", kindReason(d, KindBridge, "no bridge interface was observed"))

	// Wireless CLIENT and ACCESS POINT are separate capabilities on the same
	// hardware, and the observed mode is what tells them apart.
	//
	// Reporting both from mere presence would be the overclaim this package
	// exists to avoid: a laptop's Wi-Fi in managed mode is a client, and
	// claiming it can be an access point because a radio is fitted would be
	// reporting what the hardware could theoretically do rather than what was
	// observed.
	wlanClients, wlanAPs := wirelessByMode(d)

	set(CapWirelessClient, len(wlanClients) > 0, "observed",
		wirelessReason("client", wlanClients, "no wireless interface was observed in client mode"))
	set(CapWirelessAP, len(wlanAPs) > 0, "observed",
		wirelessReason("access-point", wlanAPs, "no wireless interface was observed in access-point mode"))
	return caps
}

// wirelessByMode separates observed wireless interfaces by operating mode.
//
// The rule is conservative in the direction that matters. An interface whose
// mode the kernel did not report is counted as a CLIENT, because that is what
// a wireless interface is by default and because a client that is merely
// unconfirmed must not be promoted into an access point.
func wirelessByMode(d *Device) (clients, aps []string) {
	for _, i := range d.Interfaces {
		if i.Kind != KindWireless {
			continue
		}
		switch i.WirelessMode {
		case "ap", "master", "__ap":
			aps = append(aps, i.SystemName)
		default:
			clients = append(clients, i.SystemName)
		}
	}
	sort.Strings(clients)
	sort.Strings(aps)
	return clients, aps
}

func wirelessReason(mode string, names []string, absent string) string {
	if len(names) == 0 {
		return absent
	}
	return fmt.Sprintf("observed in %s mode on: %s", mode, strings.Join(names, ", "))
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
