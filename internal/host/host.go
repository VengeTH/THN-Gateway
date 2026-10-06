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

	// The capabilities below were added in M7.0, when observation widened
	// from "what interfaces exist" to "what this host can actually do".
	// Each names a specific, separately-observable fact, because each can
	// fail independently and a gateway that reports one verdict for all of
	// them cannot tell an operator which one to go and fix.

	// CapNFTables reports whether nftables is installed and answerable.
	// Distinct from CapFirewall: the firewall needs nftables, but so does
	// anything else that touches netfilter, and a host can have one without
	// the other.
	CapNFTables Capability = "nftables"

	// CapTC reports whether traffic control is installed and answerable.
	// Distinct from CapQoS, which is about shaping policy rather than the
	// presence of the tc tooling itself.
	CapTC Capability = "tc"

	// CapCake reports whether the CAKE shaper can be used.
	//
	// This is the capability most likely to be wrong on a real host, and it
	// is deliberately the strictest in the model. sch_cake is a kernel
	// module; `tc` being installed says nothing about whether it is loaded,
	// and the only non-mutating evidence that it works is a CAKE discipline
	// already attached somewhere. Absent that, this stays unknown — see
	// CapTC for why a binary is not a capability.
	CapCake Capability = "cake"

	// CapMultipleEthernet reports whether the host has at least two physical
	// Ethernet interfaces — enough for the canonical two-port gateway.
	CapMultipleEthernet Capability = "multiple-ethernet"

	// CapVeth reports whether veth pairs can be created.
	//
	// Observed from existing veth interfaces rather than by creating one,
	// which would be mutation. Its absence therefore means "not observed",
	// not "impossible" — see the confidence attached to it.
	CapVeth Capability = "veth"

	// CapNetns reports whether network namespaces are in use.
	//
	// This is what the M6.x lab uses, so a host that cannot do it cannot run
	// THN's own tests — which makes it a real requirement for the project
	// even though a production gateway does not need it.
	CapNetns Capability = "network-namespace"
)

// AllCapabilities is every capability this package can report, for the CLI to
// render a complete table rather than only the ones that happen to be present.
func AllCapabilities() []Capability {
	return []Capability{
		CapRouting, CapForwarding, CapNAT, CapDHCP, CapDNS, CapFirewall,
		CapQoS, CapVLAN, CapBridge, CapWirelessAP, CapWirelessClient,
		CapNFTables, CapTC, CapCake, CapMultipleEthernet, CapVeth, CapNetns,
	}
}

// Confidence is how firmly a capability verdict was established.
//
// # The three states are not interchangeable
//
// This is the most important type in the package, because collapsing any two
// of its values produces a gateway that lies in a way it looks correct doing so.
//
//	ConfidenceObserved   THN asked the host and the host answered
//	ConfidenceInferred   THN concluded it from the platform
//	ConfidenceUnknown    THN could not tell, and says so
//
// A host running Linux does not have nftables. "Linux has nftables" is a
// statement about a great many kernels, and a gateway that reports firewall
// support on the strength of it will cheerfully plan rules for a machine whose
// nft binary is not installed.
//
// # Unknown is not false
//
// An unknown capability is not unavailable. They are different, and treating
// them as the same produces two opposite mistakes: a host THN failed to probe
// gets reported as incapable, and a host it never asked gets reported as
// capable. The first wastes an operator's afternoon. The second is worse.
type Confidence string

const (
	// ConfidenceObserved means THN queried the host and got an answer.
	ConfidenceObserved Confidence = "observed"

	// ConfidenceInferred means THN concluded the verdict from the platform
	// rather than from a probe.
	//
	// A gate that must not guess rejects this. See CapabilityState.Satisfies.
	ConfidenceInferred Confidence = "inferred"

	// ConfidenceUnknown means THN could not determine the answer.
	//
	// It fails closed: an unknown capability never satisfies a hard gate and
	// never reports available.
	ConfidenceUnknown Confidence = "unknown"
)

// ParseConfidence normalises a confidence string, defaulting to unknown.
//
// The default matters more than it looks. A capability state whose confidence
// is blank, misspelled, or set by a caller that did not think about it must
// land on the safe answer rather than on whichever constant happened to sort
// first.
func ParseConfidence(s string) Confidence {
	switch Confidence(strings.ToLower(strings.TrimSpace(s))) {
	case ConfidenceObserved:
		return ConfidenceObserved
	case ConfidenceInferred:
		return ConfidenceInferred
	default:
		return ConfidenceUnknown
	}
}

// rank orders confidences from weakest to strongest.
//
// Used only for ordering display. It is never used to decide whether a gate
// passes — Satisfies does that, by exact comparison.
func (c Confidence) rank() int {
	switch c {
	case ConfidenceObserved:
		return 3
	case ConfidenceInferred:
		return 2
	case ConfidenceUnknown:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether c is at least as strong as other.
func (c Confidence) AtLeast(other Confidence) bool { return c.rank() >= other.rank() }

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

	// ForwardingKnown reports whether the forwarding setting was actually
	// read, as opposed to defaulting to false because the read failed.
	//
	// Without this the two cases are indistinguishable on the model, and a
	// host where THN could not read the sysctl reports identically to a host
	// with forwarding genuinely off. Only the second is a gateway problem.
	ForwardingKnown bool `json:"forwarding_known"`

	// System identifies the running system: distribution, version, kernel.
	System network.System `json:"system"`

	// NFTables is what nftables this host exposes. Observed, never modified.
	NFTables network.NFTablesState `json:"nftables"`

	// TrafficControl is what traffic control this host exposes.
	TrafficControl network.TCState `json:"traffic_control"`

	// DNS is how this host resolves names.
	DNS network.DNSState `json:"dns"`

	// Routes are the observed routing table entries.
	//
	// Recorded whole rather than distilled into "is there a default route",
	// because the other entries matter too: an operator needs to see that
	// this machine already carries routes for a Docker bridge and a VPN
	// before deciding what to do with its own.
	Routes []network.Route `json:"routes,omitempty"`

	// ObservedAt is when the observation was taken.
	ObservedAt time.Time `json:"observed_at"`

	// Diagnostics records what could not be determined and why.
	Diagnostics []string `json:"diagnostics,omitempty"`

	// Probes records how each observation was made, and what it concluded.
	//
	// Diagnostics is for what is wrong. Probes is for how each question was
	// answered — including when the answer is "not checked", which produces no
	// diagnostic at all and is precisely the case an operator cannot otherwise
	// explain.
	//
	// Carried whole rather than distilled, so that a capability reporting
	// `unknown` can name the stage that failed instead of leaving the reader
	// to guess between "nobody looked", "the tool is missing", and "the tool
	// ran and said something we do not understand".
	Probes []network.Probe `json:"probes,omitempty"`
}

// FailedProbes returns the probes that did not reach a conclusion.
//
// ProbeNotChecked is included deliberately. A probe that never ran has
// established nothing about the host, so it belongs in the list of things a
// reader must know about — and it is the entry that would otherwise be
// invisible, because a probe that never ran produces no diagnostic.
func (d *Device) FailedProbes() []network.Probe {
	out := make([]network.Probe, 0, len(d.Probes))
	for _, p := range d.Probes {
		if !p.Outcome.OK() {
			out = append(out, p)
		}
	}
	return out
}

// DefaultRoute returns the observed default route, or nil.
//
// Nil is a real answer: a host with no default route has one, and reporting
// that plainly is more useful than omitting the field.
func (d *Device) DefaultRoute() (network.Route, bool) {
	for _, r := range d.Routes {
		if r.Default {
			return r, true
		}
	}
	return network.Route{}, false
}

// UnmanagedResources counts the observed resources THN does not own.
//
// It is a count, not a verdict. Docker bridges, Tailscale tunnels and
// someone else's nftables tables are all normal on a real gateway, and M7.0
// records them without judging them: discovery exists to describe a host, not
// to tidy one.
func (d *Device) UnmanagedResources() int {
	n := 0
	for _, i := range d.Interfaces {
		if i.Virtual {
			n++
		}
	}
	for _, t := range d.NFTables.Tables {
		if !t.IsTHNTable() {
			n++
		}
	}
	return n
}

// CapabilityState is one capability and how it was determined.
type CapabilityState struct {
	// Available reports whether the host can perform it.
	Available bool `json:"available"`

	// Confidence is how the verdict was established: observed, inferred or
	// unknown. See the Confidence type for why the three are not
	// interchangeable.
	Confidence Confidence `json:"confidence"`

	// Reason explains the verdict, especially when unavailable.
	Reason string `json:"reason,omitempty"`
}

// IsAvailable is a convenience accessor.
//
// It is a method rather than a field read because the field is exported for
// serialisation and a caller reaching for `.Available` should be deliberate.
//
// It deliberately ignores confidence. IsAvailable answers "did THN conclude
// the host has this?" — a reporting question. Satisfies answers "may this
// satisfy a hard gate?", which is a different question with a stricter answer,
// and a caller that wants the strict one must ask for it explicitly.
func (s CapabilityState) IsAvailable() bool { return s.Available }

// Satisfies reports whether this state may satisfy a hard gate.
//
// The rule is exact and deliberately unforgiving: a gate is satisfied only by
// an AVAILABLE capability that was OBSERVED. Inferred does not pass, and
// unknown does not pass.
//
// This is the entire point of modelling confidence. If an inference could
// satisfy a gate, then a host whose nft binary is missing would report
// firewall support on the strength of running Linux, and the gate meant to
// catch exactly that would wave it through.
func (s CapabilityState) Satisfies() bool {
	return s.Available && s.Confidence == ConfidenceObserved
}

// Can reports whether the host has a capability, and how confidently.
func (d *Device) Can(c Capability) (CapabilityState, bool) {
	s, ok := d.Capabilities[c]
	return s, ok
}

// CapabilityEvidence is the complete derivation of one capability's verdict.
//
// # Why this exists
//
// A capability whose confidence is `unknown` used to be a dead end: the
// operator saw a word and no way to get behind it. The capability table knows
// the verdict; the observation knows why; and nothing joined them.
//
// That join is this type. It answers, for any capability: which observation
// decided it, what that observation concluded, at which stage it stopped, and
// what the underlying error was — which is the difference between "firewall
// is unknown" and "firewall is unknown because `nft` ran, exited 1, and said
// 'Operation not permitted'".
//
// It is a view over data the Device already carries. Nothing is recomputed, so
// it cannot disagree with the verdict it is explaining.
type CapabilityEvidence struct {
	// Capability is the capability this explains.
	Capability Capability `json:"capability"`

	// Available and Confidence are the verdict itself.
	Available  bool       `json:"available"`
	Confidence Confidence `json:"confidence"`

	// Reason is the verdict's own explanation.
	Reason string `json:"reason,omitempty"`

	// Source names the observation that decided it: "nftables",
	// "traffic-control", "sysctl", "interfaces", or "" where no external
	// observation was involved.
	Source string `json:"source,omitempty"`

	// Probe is that observation's structured record.
	//
	// The zero value means the capability was decided by reasoning about
	// THN's own architecture rather than by asking the host — NAT, DHCP and
	// DNS are the three, and they are inferred for exactly that reason.
	Probe network.Probe `json:"probe"`
}

// EvidenceFor returns the full derivation of one capability's verdict.
//
// It never fails and never invents. A capability with no external source
// returns its verdict with an empty Source, which is itself informative:
// "this was not asked".
func (d *Device) EvidenceFor(c Capability) CapabilityEvidence {
	s := d.Capabilities[c]
	ev := CapabilityEvidence{
		Capability: c,
		Available:  s.Available,
		Confidence: s.Confidence,
		Reason:     s.Reason,
	}

	switch c {
	case CapFirewall, CapNFTables:
		ev.Source, ev.Probe = "nftables", d.NFTables.Probe
	case CapTC, CapCake, CapQoS:
		ev.Source, ev.Probe = "traffic-control", d.TrafficControl.Probe
	case CapRouting, CapForwarding:
		ev.Source = "sysctl"
		if p, ok := findForwardingProbe(d.Probes); ok {
			ev.Probe = p
		} else {
			ev.Probe = NotCheckedProbe("forwarding", "sysctl-ipv4-forward")
		}
	case CapWirelessAP, CapWirelessClient, CapVeth, CapNetns:
		ev.Source = "interfaces"
		ev.Probe = firstProbeFor(d.Probes, "wireless", "host-info", "interfaces")
	case CapMultipleEthernet, CapVLAN, CapBridge:
		ev.Source = "interfaces"
		ev.Probe = firstProbeFor(d.Probes, "interfaces", "host-info")
	default:
		// NAT, DHCP and DNS are structural: no probe will ever exist for
		// them, because answering them would mean running the software.
		ev.Source = "inferred"
		ev.Probe = NotCheckedProbe(string(c), "structural-inference")
	}
	return ev
}

// UnknownCapabilitiesExplainThemselves reports whether every unknown
// capability carries a probe that reached a conclusion.
//
// It is the assertion behind "no unexplained unknown", and it is checked
// rather than assumed: a capability can be `unknown` for a legitimate reason
// (a probe failed) or an illegitimate one (nobody recorded why), and only one
// of those is acceptable.
func (d *Device) UnknownCapabilitiesExplainThemselves() []Capability {
	var out []Capability
	for _, c := range AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok || s.Confidence != ConfidenceUnknown {
			continue
		}
		ev := d.EvidenceFor(c)
		// An unknown derived from a structural inference is not an
		// unexplained unknown: THN will never probe it, and the reason
		// string says so. Only an unknown that claims an external source and
		// then has no record of asking is a gap.
		if ev.Source == "" || ev.Source == "inferred" {
			continue
		}
		if ev.Probe.Subsystem == "" || ev.Probe.Detail == "" {
			out = append(out, c)
		}
	}
	return out
}

// FalseConfidenceCapabilities returns the capabilities that claim `observed`
// while the probe behind them produced nothing usable.
//
// This is the failure that matters. A gateway reporting "firewall: available,
// observed" because a query it never completed was scored as a successful
// absence would plan rules against a firewall it has never read — and the
// confidence column exists precisely so that such a claim cannot pass a gate.
//
// It is checked rather than assumed because the mapping from probe outcome to
// confidence is exactly where a future change would introduce one, and the
// symptom would appear as a confidently wrong plan on a host nobody was
// watching.
func (d *Device) FalseConfidenceCapabilities() []Capability {
	var out []Capability
	for _, c := range AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok || s.Confidence != ConfidenceObserved {
			continue
		}
		ev := d.EvidenceFor(c)
		if ev.Probe.Outcome.BlocksClaim() {
			out = append(out, c)
		}
	}
	return out
}

// Has reports whether a capability is available at all, regardless of
// confidence.
func (d *Device) Has(c Capability) bool {
	s, ok := d.Capabilities[c]
	return ok && s.Available
}

// Satisfies reports whether a capability is available AND was observed.
//
// This is the method a gate uses. Has is the reporting accessor and ignores
// confidence on purpose; Satisfies is the enforcing one and does not.
func (d *Device) Satisfies(c Capability) bool {
	s, ok := d.Capabilities[c]
	return ok && s.Satisfies()
}

// UncertainCapabilities returns the capabilities whose confidence is not
// observed, sorted by name.
//
// Readiness reports these as warnings rather than failures. The distinction
// is deliberate: "this host cannot route" and "THN could not determine
// whether this host can route" call for different responses from an operator,
// and merging them into one block of red text loses that.
func (d *Device) UncertainCapabilities() []Capability {
	var out []Capability
	for _, c := range AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			continue
		}
		if s.Confidence != ConfidenceObserved {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// PhysicalInterfaces returns the observed physical interfaces, sorted by
// system name for a stable rendering.
func (d *Device) PhysicalInterfaces() []Interface {
	out := make([]Interface, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		if i.Physical {
			out = append(out, i)
		}
	}
	return out
}

// CountKind returns how many interfaces of a given kind were observed.
func (d *Device) CountKind(kind string) int {
	n := 0
	for _, i := range d.Interfaces {
		if i.Kind == kind {
			n++
		}
	}
	return n
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
