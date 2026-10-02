// Package host models the machine THN runs on: its identity, its observed
// network interfaces, the logical roles those interfaces are asked to fill,
// and what the host can actually do.
//
// # Why this exists
//
// Until now a THN configuration named kernel interfaces directly:
//
//	network:
//	  wan: enp0s31f6
//	  lan: enp1s0
//
// That works on exactly one machine. The names came from a Dell, and every
// other host — a different NIC, a VM, a renamed interface — either fails
// validation or, worse, configures the wrong link and looks correct doing so.
//
// The fix is not to guess better. It is to separate three things that were
// collapsed into one string:
//
//	physical interface   what the hardware is           enp0s31f6, 00:1a:...
//	observed interface   what the kernel currently calls it   enp0s31f6
//	logical role         what the operator wants it to be        wan
//
// An operator says "the internet uplink"; THN finds an interface that can be
// one. Which interface that turns out to be is decided at discovery time and
// is visible in the plan, not baked into the configuration.
//
// # Identity is not the system name
//
// SystemName is an OBSERVATION. It is not an identity. Kernel interface names
// change — a NIC moves from an onboard slot to a USB adapter and becomes
// enx001122334455; predictable naming can be turned off and it becomes eth1.
//
// ID is derived from the hardware address where one exists, because the
// hardware address survives the rename that the name does not. Where there is
// no hardware address — loopback, bridges, tunnels — there is no stable
// identity to be had, and this package says so rather than inventing one.
//
// # Roles are assigned, never inferred from order
//
// "First NIC is WAN, second is LAN" is a guess, and on a laptop with a
// virtual bridge it is a wrong one. Nothing in this package, or in anything
// built on it, reads Interfaces[0] and calls it an uplink.
//
// # Capabilities are observed, not assumed
//
// CanRoute and CanNAT are properties of a kernel and a set of loaded modules,
// not of a product description. This package derives them from what was
// actually observed and reports what it could not determine, rather than
// reporting what Linux could theoretically do.

package host

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/network"
)

// Role is a logical purpose an interface is asked to serve.
//
// The set is open: adding a role is a constant and a label, not a schema
// change. Multi-LAN, DMZ and guest networks are all expressible as additional
// roles without any structural change to this package.
type Role string

const (
	// RoleWAN is the internet uplink.
	RoleWAN Role = "wan"
	// RoleLAN is the primary downstream network.
	RoleLAN Role = "lan"
	// RoleMGMT is an administrative path. Distinct from LAN so management
	// access can be restricted without exposing the whole LAN.
	RoleMGMT Role = "mgmt"
	// RoleGuest is an untrusted downstream network.
	RoleGuest Role = "guest"
	// RoleDMZ is a semi-exposed downstream network.
	RoleDMZ Role = "dmz"
	// RoleUnassigned means no role has been chosen for this interface.
	RoleUnassigned Role = "unassigned"
)

// KnownRoles returns every role an operator may assign, excluding unassigned.
//
// It exists so validation and the CLI can offer the full set without each
// keeping its own copy, and so a new role cannot be added in one place and
// forgotten in another.
func KnownRoles() []Role {
	return []Role{RoleWAN, RoleLAN, RoleMGMT, RoleGuest, RoleDMZ}
}

// ParseRole parses a role name, accepting an empty string as unassigned.
func ParseRole(s string) (Role, error) {
	r := Role(strings.ToLower(strings.TrimSpace(s)))
	if r == "" {
		return RoleUnassigned, nil
	}
	for _, k := range KnownRoles() {
		if r == k {
			return r, nil
		}
	}
	names := make([]string, 0, len(KnownRoles()))
	for _, k := range KnownRoles() {
		names = append(names, string(k))
	}
	return RoleUnassigned, fmt.Errorf("unknown role %q; known roles are %s", s, strings.Join(names, ", "))
}

// Capability is something the host can do.
//
// These are observed, never assumed. A host with no nftables loaded does not
// have CapFirewall, however capable Linux is in general.
type Capability string

const (
	CapRouting        Capability = "routing"
	CapForwarding     Capability = "forwarding"
	CapNAT            Capability = "nat"
	CapDHCP           Capability = "dhcp"
	CapDNS            Capability = "dns"
	CapFirewall       Capability = "firewall"
	CapQoS            Capability = "qos"
	CapVLAN           Capability = "vlan"
	CapBridge         Capability = "bridge"
	CapWirelessAP     Capability = "wireless-ap"
	CapWirelessClient Capability = "wireless-client"
)

// AllCapabilities is every capability this package can report, for the CLI to
// render a complete table rather than only the ones that happen to be present.
func AllCapabilities() []Capability {
	return []Capability{
		CapRouting, CapForwarding, CapNAT, CapDHCP, CapDNS, CapFirewall,
		CapQoS, CapVLAN, CapBridge, CapWirelessAP, CapWirelessClient,
	}
}

// IdentityKind explains where an interface's ID came from.
//
// It is carried rather than implied so that an operator — and a test — can
// tell a confidently-identified physical interface from one that could only be
// labelled by position.
type IdentityKind string

const (
	// IdentityHardware means the ID derives from a hardware address.
	IdentityHardware IdentityKind = "hardware"
	// IdentityEphemeral means no hardware address exists, so the ID is derived
	// from what else was observed and will NOT survive a rename.
	IdentityEphemeral IdentityKind = "ephemeral"
)

// Kind constants are THN's own link-kind vocabulary.
//
// They are not the kernel's. The kernel says "ether" and "wlan"; these say
// "ethernet" and "wireless". NormaliseKind bridges the two at the discovery
// edge so that nothing above it has to know what `ip` calls things.
const (
	KindEthernet = "ethernet"
	KindLoopback = "loopback"
	KindWireless = "wireless"
	KindBridge   = "bridge"
	KindVLAN     = "vlan"
	KindBond     = "bond"
	KindTunnel   = "tunnel"
	KindDummy    = "dummy"
	KindVeth     = "veth"
)

// Interface is one observed network interface.
type Interface struct {
	// ID is the stable identity this package refers to an interface by.
	//
	// It is derived from the hardware address where one exists. It is NOT the
	// kernel name: see the package comment on identity.
	ID string `json:"id"`

	// IDKind records how ID was derived.
	IDKind IdentityKind `json:"id_kind"`

	// SystemName is the kernel interface name as observed. This is an
	// observation and is allowed to change between runs.
	SystemName string `json:"system_name"`

	// Index is the kernel interface index.
	Index int `json:"index"`

	// Kind classifies the interface, e.g. "ethernet", "loopback", "vlan".
	// It is THN's vocabulary, not the kernel's: see the Kind constants above.
	Kind string `json:"kind,omitempty"`

	// RawKind is the kernel's own linkinfo.info_kind, preserved verbatim.
	//
	// It exists so that the normalisation is auditable and reversible, not
	// because anything needs it. An operator reading a diagnostic that says
	// "wlan" and an interface that reports "wireless" should be able to see
	// that they are the same thing rather than wondering which is wrong.
	RawKind string `json:"raw_kind,omitempty"`

	// Physical reports whether this link is real hardware.
	//
	// It is an OBSERVATION, decided at the discovery edge from what the
	// kernel states about the link — never from the name. It is the field
	// that stops a Docker bridge, a Tailscale tunnel, a WireGuard link or a
	// container veth from being offered to an operator as a gateway port,
	// which is the mistake that matters: a gateway that decides its uplink is
	// `docker0` looks correct while routing nothing.
	Physical bool `json:"physical"`

	// Virtual is the complement of Physical, named because it is what an
	// operator reads. It is not stored separately in the observation layer;
	// here it is explicit because the two are used in opposite directions.
	Virtual bool `json:"virtual"`

	// AdminUp reports the administrative state: whether the link has been
	// brought up. Distinct from LinkUp, which also reflects carrier, and a
	// link can be administratively up with no cable plugged into it.
	AdminUp bool `json:"admin_up"`

	// Master names the bond or bridge this interface is enslaved to, empty
	// when it is not enslaved.
	//
	// A NIC inside a bond is still physical. Recording the relationship
	// separately is what lets the model say "this is real hardware, and it
	// currently belongs to something else" without conflating the two.
	Master string `json:"master,omitempty"`

	// WirelessMode is the wireless operating mode as observed: "managed" for
	// a client, "ap" for an access point, "monitor" for a capture interface.
	//
	// Empty on every non-wireless interface. It is the difference between a
	// wireless NIC that can act as a CLIENT and one acting as an ACCESS
	// POINT — two different capabilities on identical hardware, and the only
	// way to tell them apart without asking the operator.
	WirelessMode string `json:"wireless_mode,omitempty"`

	// MAC is the hardware address. Sensitive: the CLI does not print it
	// unless asked.
	MAC string `json:"mac,omitempty"`

	// State is the observed link state.
	State network.LinkState `json:"state"`

	// LinkUp reports whether a carrier is present. A wireless interface in
	// client mode reports down until it associates.
	LinkUp bool `json:"link_up"`

	// SpeedMbps is the negotiated link speed, 0 when unknown.
	//
	// Zero means "not reported", not "zero". A NIC whose driver does not
	// report a speed is not a slow NIC, and reporting 0 as a number would
	// invite a planner to treat it as unusable.
	SpeedMbps int `json:"speed_mbps,omitempty"`

	// MTU is the interface MTU.
	MTU int `json:"mtu"`

	// Addresses are the addresses assigned to this interface, in CIDR form.
	Addresses []string `json:"addresses,omitempty"`

	// Role is the logical role this interface has been ASSIGNED.
	//
	// It is empty until an assignment names it. Nothing in this package
	// infers a role from position, from the kernel name, or from the fact
	// that an interface is up.
	Role Role `json:"role,omitempty"`

	// Assignable reports whether this interface could be given a role at all.
	//
	// Loopback is never assignable. Everything else is, including interfaces
	// that are currently down: an operator may legitimately want the uplink
	// on a cable they have not plugged in yet.
	Assignable bool `json:"assignable"`
}

// Device is the observed host.
type Device struct {
	// Hostname is the machine's hostname, when one was readable.
	Hostname string `json:"hostname,omitempty"`

	// OS and Arch are the runtime platform.
	OS   string `json:"os"`
	Arch string `json:"arch"`

	// Supported reports whether host inspection is available here at all.
	//
	// False on a non-Linux development host. When false, Interfaces is empty
	// and Capabilities is empty, and both are honestly empty rather than
	// optimistically populated.
	Supported bool `json:"supported"`

	// Interfaces are the observed interfaces, ordered by system name for a
	// stable rendering. Ordering is for readability only; no consumer may
	// infer meaning from position.
	Interfaces []Interface `json:"interfaces"`

	// Capabilities is what the host can do.
	Capabilities map[Capability]CapabilityState `json:"capabilities,omitempty"`

	// ForwardingEnabled reports the kernel's IPv4 forwarding setting.
	// Recorded as an observation; THN never writes it.
	ForwardingEnabled bool `json:"forwarding_enabled"`

	// ObservedAt is when the observation was taken.
	ObservedAt time.Time `json:"observed_at"`

	// Diagnostics records what could not be determined and why.
	Diagnostics []string `json:"diagnostics,omitempty"`
}

// CapabilityState is one capability and how it was determined.
type CapabilityState struct {
	// Available reports whether the host can perform it.
	Available bool `json:"available"`

	// Confidence is "observed", "inferred" or "unknown".
	//
	// "inferred" means THN concluded it from the platform rather than from a
	// probe. A caller that must not guess should require "observed".
	Confidence string `json:"confidence"`

	// Reason explains the verdict, especially when unavailable.
	Reason string `json:"reason,omitempty"`
}

// IsAvailable is a convenience accessor.
//
// It is a method rather than a field read because the field is exported for
// serialisation and a caller reaching for `.Available` should be deliberate.
func (s CapabilityState) IsAvailable() bool { return s.Available }

// Can reports whether the host has a capability, and how confidently.
func (d *Device) Can(c Capability) (CapabilityState, bool) {
	s, ok := d.Capabilities[c]
	return s, ok
}

// Has reports whether a capability is available at all, regardless of
// confidence.
func (d *Device) Has(c Capability) bool {
	s, ok := d.Capabilities[c]
	return ok && s.Available
}

// InterfaceByID returns an interface by its stable ID.
func (d *Device) InterfaceByID(id string) (Interface, bool) {
	for _, i := range d.Interfaces {
		if i.ID == id {
			return i, true
		}
	}
	return Interface{}, false
}

// InterfaceForRole returns the interface assigned to a role.
func (d *Device) InterfaceForRole(r Role) (Interface, bool) {
	for _, i := range d.Interfaces {
		if i.Role == r {
			return i, true
		}
	}
	return Interface{}, false
}

// SystemNames returns the observed kernel names, for diagnostics and for the
// the error model that has to name what was actually seen.
func (d *Device) SystemNames() []string {
	out := make([]string, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		out = append(out, i.SystemName)
	}
	sort.Strings(out)
	return out
}

// IPv4 returns the IPv4 addresses assigned to this interface.
//
// It is computed rather than stored so that the observation and this view
// cannot disagree. An address counts as IPv4 only if it parses as one; text
// that does not parse is reported as belonging to neither family, rather than
// being guessed into one.
func (i Interface) IPv4() []string { return i.addressesOf(true) }

// IPv6 returns the IPv6 addresses assigned to this interface.
func (i Interface) IPv6() []string { return i.addressesOf(false) }

func (i Interface) addressesOf(wantV4 bool) []string {
	var out []string
	for _, c := range i.Addresses {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if prefix.Addr().Is4() == wantV4 {
			out = append(out, c)
		}
	}
	return out
}

// RoleCandidates returns the interfaces that could hold a role.
//
// It answers the question an operator actually has — "which of these can I
// choose from?" — without answering the question they did not ask, which is
// "which one should I choose". The distinction is the whole point: the
// candidate list is offered, the choice is made.
//
// Interfaces that are currently down are included. An operator plugging in an
// uplink after configuring is the normal sequence, and excluding down links
// would make the list wrong exactly when it is most needed.
func (d *Device) RoleCandidates() []Interface {
	out := make([]Interface, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		if i.Assignable {
			out = append(out, i)
		}
	}
	return out
}

// RoleCandidatesFor returns the assignable interfaces of a given kind.
//
// It exists so the error model can offer a useful next step — "assign one of
// these two Ethernet ports" — rather than every link on the machine.
func (d *Device) RoleCandidatesFor(kinds ...string) []Interface {
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	var out []Interface
	for _, i := range d.RoleCandidates() {
		if want[i.Kind] {
			out = append(out, i)
		}
	}
	return out
}

// RoleAssignments returns the assignments an operator would write down to
// reproduce the roles currently on this device.
//
// It is the inverse of Resolve: it turns an observed device back into the
// selectors that would reproduce it. `thn discover --assignments` prints it,
// so an operator does not have to transcribe kernel names by hand and get
// them subtly wrong.
//
// Selectors are emitted in a stable form. Where a stable identity exists it is
// preferred, because a name stops working when a NIC moves slots.
func (d *Device) RoleAssignments() []Assignment {
	out := make([]Assignment, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		if i.Role == RoleUnassigned || i.Role == "" {
			continue
		}
		sel := i.SystemName
		if i.IDKind == IdentityHardware {
			sel = i.ID
		}
		out = append(out, Assignment{Role: i.Role, Selector: sel})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Role < out[b].Role })
	return out
}

// InterfaceID derives a stable identifier for an observed interface.
//
// The hardware address is preferred because it survives the rename that the
// kernel name does not. Where there is none the result is explicitly
// ephemeral, and callers that must not survive a rename should refuse to act
// rather than treat the ephemeral ID as if it were stable.
//
// # Why the link kind is part of the digest
//
// A MAC address identifies a DEVICE, not an interface. On a machine with a
// bond, `bond0` and its port `enp2s0` report the SAME hardware address — the
// bond takes its active port's address.
//
// The first version of this function digested the address alone, so those two
// distinct links received the same identity. Everything downstream then had an
// ambiguity it could not see: a role assigned by identity would match whichever
// of the two Resolve happened to reach first, and `InterfaceByID` could
// return a bond when asked for a NIC.
//
// Including the kind separates them, and costs nothing that matters: a rename
// changes the name, not the kind, so the identity is exactly as rename-stable
// as it was before.
//
// # The hardware address is hashed, not embedded
//
// An earlier version returned "mac:" + the address. That was stable and it
// worked, and it leaked: the ID is printed in every command that mentions an
// interface, so putting the address in it put a half-network-identifier on
// every screen. A test asserting that MACs are hidden by default caught it.
//
// So the ID is a truncated digest. It remains stable across renames, it is
// still comparable between two observations of the same machine, and it does
// not disclose the address. The cost is that it is not human-recognisable: an
// operator cannot tell "the Intel NIC" from "the USB NIC" by reading it. That
// cost is real and is why the renderer prints the system name alongside it —
// and, when the operator asks, the address behind --mac.
func InterfaceID(kind, mac string, index int) (string, IdentityKind) {
	if mac = usableHardwareAddress(mac); mac != "" {
		sum := sha256.Sum256([]byte(NormaliseKind(kind) + "\x00" + strings.ToLower(mac)))
		return "hw:" + hex.EncodeToString(sum[:])[:16], IdentityHardware
	}
	// No usable hardware address: loopback, bridges, tunnels, some virtual
	// links. There is genuinely nothing stable here. Saying so is the point.
	return fmt.Sprintf("ephemeral:%s:%d", orUnknown(NormaliseKind(kind)), index), IdentityEphemeral
}

// usableHardwareAddress rejects addresses that identify nothing.
//
// The all-zero address is what the kernel reports for loopback and for a
// great many virtual links. Treating it as a hardware identity would give
// every one of them the SAME stable ID — so a configuration naming it would
// match whichever happened to be encountered first. It is the absence of an
// address, not an address.
func usableHardwareAddress(mac string) string {
	trimmed := strings.TrimSpace(strings.ToLower(mac))
	if trimmed == "" {
		return ""
	}
	if strings.Trim(trimmed, "0:") == "" {
		return ""
	}
	return trimmed
}

// IDFor returns the stable identifier for a wired interface with this hardware
// address.
//
// It is the same computation InterfaceID performs, exposed so that a caller
// can BUILD the selector a configuration will contain without duplicating the
// digest. A test or a UI that guessed the format would break the moment the
// digest changed.
//
// It assumes an ethernet interface, which is the overwhelmingly common case
// and the one every existing document uses. For any other kind, use
// IDForKind — guessing the kind would produce a selector that silently never
// matches.
func IDFor(mac string) string {
	id, _ := InterfaceID(KindEthernet, mac, 0)
	return id
}

// IDForKind returns the stable identifier for an interface of a given kind.
func IDForKind(kind, mac string) string {
	id, _ := InterfaceID(kind, mac, 0)
	return id
}
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
