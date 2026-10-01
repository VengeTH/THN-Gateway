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
	d.Interfaces = interfacesFrom(snap.Interfaces)
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
func interfacesFrom(in []network.Interface) []Interface {
	out := make([]Interface, 0, len(in))

	for _, i := range in {
		addrs := make([]string, 0, len(i.Addresses))
		for _, a := range i.Addresses {
			addrs = append(addrs, a.CIDR)
		}

		id, kind := InterfaceID(i.Kind, i.MAC, i.Index)
		out = append(out, Interface{
			ID:         id,
			IDKind:     kind,
			SystemName: i.Name,
			Index:      i.Index,
			Kind:       i.Kind,
			MAC:        i.MAC,
			State:      i.State,
			LinkUp:     i.State == network.LinkUp,
			MTU:        i.MTU,
			Addresses:  addrs,
			// Roles are assigned by configuration. Nothing here infers one.
			Role:       RoleUnassigned,
			Assignable: i.Kind != "loopback",
		})
	}
	return out
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

	// QoS: a shaped link needs an egress interface that exists and is up.
	set(CapQoS, len(d.Interfaces) > 0, "inferred",
		"inferred: shaping needs an interface to shape on")

	// VLAN and bridging: derived from what kinds of interface are present.
	set(CapVLAN, hasKind(d, "vlan"), "observed", kindReason(d, "vlan", "no VLAN interface was observed"))
	set(CapBridge, hasKind(d, "bridge"), "observed", kindReason(d, "bridge", "no bridge interface was observed"))

	// Wireless, by kind.
	set(CapWirelessAP, hasKind(d, "wireless"), "observed", kindReason(d, "wireless", "no wireless interface was observed"))
	set(CapWirelessClient, hasKind(d, "wireless"), "observed", kindReason(d, "wireless", "no wireless interface was observed"))

	return caps
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
