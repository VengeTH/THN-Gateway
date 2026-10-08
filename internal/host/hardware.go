package host

// Hardware & capability intelligence (M7.1).
//
// # The state machine this file sits inside
//
//	OBSERVED  →  SUITABLE  →  ASSIGNED  →  ACTIVATED
//	 (M7.0)      (M7.1)       (later)       (later)
//
// M7.0 answered "what exists on this host". M7.1 answers the next question —
// "given what exists, what could this host reasonably be used for as a THN
// gateway?" — and it answers it in the second state only.
//
// The distinction is the whole point of this file, and collapsing any two of
// those four states produces a failure that looks correct while it happens:
//
//   - A gateway that decides enp0s31f6 IS the WAN because it carries the
//     default route has skipped ASSIGNMENT. It guessed an operator's decision
//     from an observation.
//   - A gateway that reports "WAN: strong candidate" for a virtual Docker
//     bridge carrying a default route has collapsed SUITABLE into OBSERVED.
//
// Everything below therefore keeps three things apart, and none of them
// implies the next:
//
//	current usage     what the host is doing with this link right now
//	suitability       what this link could reasonably be used for
//	assignment        what an operator has explicitly configured (not here)
//
// # This file is pure
//
// AnalyzeHardware is a total function from an observed Device to an
// explanation. It executes nothing, reads nothing, and writes nothing. That is
// what makes it testable from a fixture, deterministic run to run, and safe to
// call from anywhere — including a future UI, a remote agent, or a
// configuration assistant.
//
// Observation already gathered every fact used here. Adding a probe to make
// suitability "smarter" would be the mistake this milestone exists to prevent:
// a second observation path is a second chance to mutate a live gateway.
//
// # Suitability is not a score
//
// There is no "WAN score: 87" here. A number invites an operator to compare
// interfaces without reading why, and the why is the part that matters. Every
// classification carries the observations it rests on, and an interface THN
// cannot classify says so rather than being given a middling number.
//
// # Nothing here is inferred that was not observed
//
// A NIC whose driver reports no link speed has an UNKNOWN speed. THN does not
// guess 1000, and it does not treat zero as a real measurement. An interface
// observed as a wireless client is never reported as access-point capable,
// because "this radio could host an AP" is a claim about a kernel module, not
// an observation of this host. The Confidence values used here are the same
// three the capability model already uses, and none is ever silently upgraded.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/network"
)

// Wireless operating modes, taken from the observation layer's vocabulary.
//
// Aliased rather than restated. These were previously written out as string
// literals here, which meant two copies of the same vocabulary that could
// drift apart and leave this analysis quietly failing to recognise the mode it
// was written for. Aliasing them makes that impossible by construction.
const (
	// WirelessModeAP is an observed access point.
	WirelessModeAP = network.WirelessModeAP
	// WirelessModeClient is an observed station joining a network.
	WirelessModeClient = network.WirelessModeClient
	// WirelessModeMonitor is an observed capture interface.
	WirelessModeMonitor = network.WirelessModeMonitor
	// WirelessModeMesh is an observed mesh interface.
	WirelessModeMesh = network.WirelessModeMesh
	// WirelessModeAdhoc is an observed ad-hoc interface.
	WirelessModeAdhoc = network.WirelessModeAdhoc
)

// Suitability is how well an interface could serve a logical role.
//
// The scale is ordered but not continuous: there is no arithmetic on it, and
// two interfaces at the same classification are not equivalent — they differ
// in the Evidence attached to each, which is why the evidence is part of the
// verdict rather than a decoration on it.
type Suitability string

const (
	// SuitabilityStrongCandidate means the observed evidence is the shape a
	// gateway role is normally expected to have: real hardware, of the right
	// kind, currently carrying the traffic that role carries.
	//
	// It says the interface LOOKS like that role. It does not say the role
	// has been given to it.
	SuitabilityStrongCandidate Suitability = "strong_candidate"

	// SuitabilityCandidate means the interface is plausible for the role with
	// nothing observed arguing against it, but without the full set of
	// signals a strong candidate would have.
	SuitabilityCandidate Suitability = "candidate"

	// SuitabilityLimitedCandidate means the interface is the right KIND of
	// hardware, but something observed restricts it: no carrier, an existing
	// bridge relationship, or a link type that cannot carry the role in the
	// conventional way.
	//
	// A disconnected Ethernet port is a limited candidate, not an unsuitable
	// one. Plugging the cable in is the normal order of operations, and
	// refusing to offer the port until it is plugged in would make THN
	// useless for exactly the setup it exists for.
	SuitabilityLimitedCandidate Suitability = "limited_candidate"

	// SuitabilityUnsuitable means something observed rules the interface out
	// as a gateway port: it is virtual infrastructure, it is loopback, it is
	// enslaved to something else, or its observed mode cannot carry the role.
	SuitabilityUnsuitable Suitability = "unsuitable"

	// SuitabilityUnknown means THN could not classify it.
	//
	// It is the honest answer when the host could not be inspected at all.
	// Unknown is never rounded to unsuitable, which would report a host THN
	// failed to look at as a host it judged.
	SuitabilityUnknown Suitability = "unknown"
)

// rank orders classifications for comparison. Strongest first.
//
// Used for choosing which interface to name as the best candidate for a
// profile, never for deciding whether a gate passes.
func (s Suitability) rank() int {
	switch s {
	case SuitabilityStrongCandidate:
		return 4
	case SuitabilityCandidate:
		return 3
	case SuitabilityLimitedCandidate:
		return 2
	case SuitabilityUnknown:
		return 1
	case SuitabilityUnsuitable:
		return 0
	default:
		return -1
	}
}

// AtLeast reports whether s is at least as strong as other.
func (s Suitability) AtLeast(other Suitability) bool { return s.rank() >= other.rank() }

// Describe renders the classification as the phrase an operator reads.
func (s Suitability) Describe() string {
	switch s {
	case SuitabilityStrongCandidate:
		return "strong candidate"
	case SuitabilityCandidate:
		return "candidate"
	case SuitabilityLimitedCandidate:
		return "limited candidate"
	case SuitabilityUnsuitable:
		return "unsuitable"
	case SuitabilityUnknown:
		return "unknown"
	default:
		return string(s)
	}
}

// UsageState is what the host is currently doing with an interface.
//
// It is deliberately a separate type from Suitability.
//
// `occupied` is a usage state and NOT a suitability class. An interface
// carrying the default route is very often the strongest WAN candidate on the
// host, and folding "in use" into the suitability scale would mean reporting
// the best uplink on a real gateway as a poor one — which is precisely how a
// tool talks an operator out of the correct configuration.
type UsageState string

const (
	// UsageIdle means nothing observed is currently using this interface.
	UsageIdle UsageState = "idle"

	// UsageOccupied means the interface is carrying observed connectivity:
	// a routable address, or a route, or the default route.
	UsageOccupied UsageState = "occupied"

	// UsageEnslaved means the interface belongs to a bridge or bond.
	//
	// It is its own state rather than a flavour of occupied because the
	// remedy is different. An occupied interface is busy; an enslaved one has
	// had its layer-2 identity delegated, and an operator has to decide what
	// to do about that relationship.
	UsageEnslaved UsageState = "enslaved"

	// UsageInfrastructure means the interface is virtual infrastructure:
	// a container endpoint, a bridge, a tunnel, a VLAN.
	UsageInfrastructure UsageState = "infrastructure"
)

// Describe renders the usage state as the phrase an operator reads.
func (u UsageState) Describe() string {
	switch u {
	case UsageIdle:
		return "idle"
	case UsageOccupied:
		return "in use"
	case UsageEnslaved:
		return "enslaved to an existing bridge or bond"
	case UsageInfrastructure:
		return "virtual infrastructure"
	default:
		return string(u)
	}
}

// LinkClass is what kind of hardware, or lack of it, a link is.
//
// It is coarser than Interface.Kind on purpose. Kind records the link type the
// kernel reported; Class records whether that link type is a port an operator
// could plug a cable into. That distinction is what stops a Docker bridge or a
// Tailscale tunnel from being offered as a gateway port.
type LinkClass string

const (
	// LinkPhysicalWired is a real Ethernet port.
	LinkPhysicalWired LinkClass = "physical-wired"

	// LinkPhysicalWireless is a real radio.
	//
	// It is hardware, and it is not a wired port. Those are separate facts
	// and the analysis keeps them separate.
	LinkPhysicalWireless LinkClass = "physical-wireless"

	// LinkPhysicalOther is real hardware whose kind was observed but is not
	// one this analysis has a specific opinion about.
	LinkPhysicalOther LinkClass = "physical-other"

	// LinkInfrastructure is a virtual link: loopback, bridge, bond, VLAN,
	// tunnel, veth or dummy.
	//
	// None of these is a physical gateway port, and none is described in
	// terms of one.
	LinkInfrastructure LinkClass = "infrastructure"
)

// Describe renders the class as the phrase an operator reads.
func (c LinkClass) Describe() string {
	switch c {
	case LinkPhysicalWired:
		return "physical Ethernet"
	case LinkPhysicalWireless:
		return "physical wireless"
	case LinkPhysicalOther:
		return "physical (other kind)"
	case LinkInfrastructure:
		return "virtual infrastructure"
	default:
		return string(c)
	}
}

// Evidence is one observed fact a classification rests on.
//
// Evidence carries its own Confidence rather than inheriting the verdict's,
// because they are not the same question. A verdict can be firmly observed
// while one of the facts behind it was unavailable — "this is a strong WAN
// candidate" is well established even on a NIC whose speed the driver never
// reported. Losing the per-fact distinction would mean either reporting the
// whole verdict as unknown, or hiding which specific fact is missing.
type Evidence struct {
	// Code is a stable machine-readable identifier.
	//
	//	physical-link       the host reports this as real hardware
	//	ethernet            the link kind is Ethernet
	//	wireless            the link kind is wireless
	//	carrier-present     a carrier is present
	//	no-carrier          no carrier is present
	//	link-speed          a negotiated speed was reported
	//	link-speed-unknown  the host reported no speed
	//	ipv4-address        an IPv4 address is assigned
	//	ipv6-address        a non-link-local IPv6 address is assigned
	//	no-address          no routable address is assigned
	//	default-route       an observed default route uses this interface
	//	no-default-route    no observed default route uses this interface
	//	enslaved            the link belongs to a bridge or bond
	//	assigned-role       an operator has recorded a role for this link
	//	stable-identity     the link has a rename-stable identity
	//	wireless-mode       the observed wireless operating mode
	//	virtual-link        the link is virtual infrastructure
	Code string `json:"code"`

	// Detail is the human sentence explaining what was observed.
	Detail string `json:"detail"`

	// Confidence is how firmly this fact was established.
	Confidence Confidence `json:"confidence"`
}

// observedEvidence builds one evidence entry at observed confidence.
//
// Nearly every fact here comes from a query THN made against the host, so
// nearly every entry is observed. The field exists because the alternative —
// one confidence for the whole verdict — is a strictly worse answer, and
// because it is the type a future probe-backed fact would use.
func observedEvidence(code, detail string) Evidence {
	return Evidence{Code: code, Detail: detail, Confidence: ConfidenceObserved}
}

// CurrentUsage is what the host is doing with an interface right now.
//
// This is evidence, never configuration. Every field describes something that
// was observed to be true; none of them is something THN decided, and none of
// them is changed by this analysis.
type CurrentUsage struct {
	// Carrier reports whether a carrier is present.
	Carrier bool `json:"carrier"`

	// AdminUp reports the administrative state.
	AdminUp bool `json:"admin_up"`

	// Addressed reports whether a routable address is assigned.
	//
	// "Routable" is doing real work here. Every IPv6-capable host
	// auto-assigns fe80::/10 on every interface, so counting a link-local
	// address as occupancy would mark every NIC on the planet as in use and
	// make the field useless.
	Addressed bool `json:"addressed"`

	// IPv4 and IPv6 report the address families observed, using the same
	// link-local exclusion as Addressed.
	IPv4 bool `json:"ipv4"`
	IPv6 bool `json:"ipv6"`

	// DefaultRoute reports whether an observed default route uses this
	// interface.
	DefaultRoute bool `json:"default_route"`

	// RouteCount is how many observed routes use this interface.
	RouteCount int `json:"route_count"`

	// Master names the bridge or bond this link is enslaved to.
	Master string `json:"master,omitempty"`

	// AssignedRole is the role an operator has recorded for this link, or
	// empty. Observation never sets it, and neither does this analysis.
	AssignedRole Role `json:"assigned_role,omitempty"`

	// State is the usage state all of the above adds up to.
	State UsageState `json:"state"`
}

// RoleSuitability is one interface judged against one logical role.
type RoleSuitability struct {
	// Role is the logical role being judged.
	Role Role `json:"role"`

	// Suitability is the classification.
	//
	// It describes what this interface COULD be. It is never a record of
	// what it IS; that lives in CurrentUsage.AssignedRole, which only
	// configuration writes.
	Suitability Suitability `json:"suitability"`

	// Confidence is how firmly the classification was reached.
	//
	// A classification built entirely from queried facts is observed. A
	// classification reached with nothing observed is unknown. Inferred does
	// not appear here at all — see the file comment.
	Confidence Confidence `json:"confidence"`

	// Evidence is everything the classification rests on, in a fixed order.
	Evidence []Evidence `json:"evidence"`

	// Blockers are reasons the interface cannot serve this role at all.
	Blockers []string `json:"blockers,omitempty"`

	// Limitations are caveats on an otherwise live candidate.
	//
	// They are separate from blockers because they call for different
	// responses: a blocker needs the host or the hardware changed, a
	// limitation needs the operator to know something before configuring.
	Limitations []string `json:"limitations,omitempty"`
}

// Candidate reports whether this interface is offered for the role at all.
//
// offered is anything above unsuitable or unknown. It answers "can this be
// chosen" — not "should it be". Only an operator answers the second.
func (s RoleSuitability) Candidate() bool {
	return s.Suitability.rank() >= SuitabilityLimitedCandidate.rank()
}

// InterfaceIntelligence is everything M7.1 concludes about one interface.
type InterfaceIntelligence struct {
	// ID and IDKind are the existing stable identity, carried unchanged.
	//
	// Reusing it is the point: an analysis keyed on the kernel name would
	// report a different gateway every time a NIC moved slots.
	ID string `json:"id"`

	IDKind IdentityKind `json:"id_kind"`

	// SystemName is the observed kernel name.
	SystemName string `json:"system_name"`

	// Kind is the observed link kind, in THN's vocabulary.
	Kind string `json:"kind,omitempty"`

	// Physical and Class record what the link is.
	Physical bool      `json:"physical"`
	Class    LinkClass `json:"class"`

	// SpeedMbps is the observed speed, and SpeedKnown says whether it was
	// observed at all.
	//
	// Both are reported because SpeedMbps alone is the mistake this pair
	// exists to prevent: a zero speed that reads as a measurement rather than
	// an absence of one. JSON omits SpeedMbps entirely when it is unknown.
	SpeedMbps  int  `json:"speed_mbps,omitempty"`
	SpeedKnown bool `json:"speed_known"`

	// Usage is what the host is currently doing with this link.
	Usage CurrentUsage `json:"current"`

	// Suitability is keyed by logical role: WAN, LAN and MGMT.
	//
	// It is a map because the role set is open — guest and DMZ are roles
	// this package already defines — and a slice would have to be rewritten
	// every time a role was added. Consumers iterate IntelligenceRoles for a
	// stable order.
	Suitability map[Role]RoleSuitability `json:"suitability"`
}

// SuitabilityFor returns the judgement for one role.
func (i InterfaceIntelligence) SuitabilityFor(r Role) RoleSuitability {
	s, ok := i.Suitability[r]
	if !ok {
		return RoleSuitability{Role: r, Suitability: SuitabilityUnknown, Confidence: ConfidenceUnknown}
	}
	return s
}

// ProfileID names a gateway shape.
type ProfileID string

const (
	// ProfileSingleInterface is a host with one physical port.
	ProfileSingleInterface ProfileID = "single-interface"

	// ProfileTwoPortWired is the canonical gateway: two physical Ethernet
	// ports, one uplink and one downstream.
	ProfileTwoPortWired ProfileID = "two-port-wired"

	// ProfileMultiInterface is three or more physical ports, enough for an
	// uplink, a downstream network and a management path.
	ProfileMultiInterface ProfileID = "multi-interface"
)

// ProfileVerdict is whether an observed host could take a profile's shape.
//
// It is POSSIBLE or NOT POSSIBLE, never READY. The distinction is not
// cosmetic: a hardware shape being present says nothing about whether the
// services on it work, and a verdict of READY here would be a claim about
// capabilities this analysis has no standing to make.
type ProfileVerdict string

const (
	// ProfilePossible means the observed hardware could take this shape.
	ProfilePossible ProfileVerdict = "POSSIBLE"

	// ProfileNotPossible means the observed hardware cannot take this shape.
	ProfileNotPossible ProfileVerdict = "NOT POSSIBLE"
)

// GatewayProfile is one gateway shape judged against one observed host.
type GatewayProfile struct {
	// ID and Title name the shape.
	ID    ProfileID `json:"id"`
	Title string    `json:"title"`

	// Verdict is POSSIBLE or NOT POSSIBLE.
	Verdict ProfileVerdict `json:"verdict"`

	// Evidence is why, in the same form as interface evidence.
	Evidence []Evidence `json:"evidence"`

	// Candidates names the best-suited interface per role.
	//
	// This is SUITABILITY, not ASSIGNMENT. It says "of the interfaces you
	// could use for this, this one has the strongest observed evidence". It
	// writes nothing, resolves nothing, and appears in no Assignment. An
	// operator who configures the WAN to the name in this field is making a
	// decision THN did not make for them — and is free to make a different
	// one.
	//
	// A role is omitted when no observed interface could serve it.
	Candidates map[Role]string `json:"candidates,omitempty"`

	// Constraints are the things an operator must know before configuring
	// this shape on this host.
	Constraints []string `json:"constraints,omitempty"`
}

// Possible reports whether the profile's shape was found.
func (p GatewayProfile) Possible() bool { return p.Verdict == ProfilePossible }

// HardwareIntelligence is the complete M7.1 result.
type HardwareIntelligence struct {
	// Supported reports whether the host could be inspected at all.
	//
	// When false every classification is SuitabilityUnknown. THN did not
	// judge this host; it could not look at it, and the difference is the
	// whole value of the field.
	Supported bool `json:"supported"`

	// Interfaces is the per-interface analysis, deterministically ordered.
	Interfaces []InterfaceIntelligence `json:"interfaces"`

	// Profiles is the gateway-shape analysis, in a fixed order.
	Profiles []GatewayProfile `json:"profiles"`

	// PhysicalPorts counts every observed physical interface.
	PhysicalPorts int `json:"physical_ports"`

	// PhysicalEthernet counts physical Ethernet interfaces, which is the
	// figure a two-port wired gateway actually needs. A wireless radio is
	// hardware, and it is not a wired port.
	PhysicalEthernet int `json:"physical_ethernet"`

	// PhysicalWireless counts physical wireless interfaces.
	PhysicalWireless int `json:"physical_wireless"`

	// DefaultRouteCount and DefaultRouteInterfaces describe the observed
	// routing topology.
	//
	// More than one default route is reported as a FACT, not as a fault. A
	// host with both a wired and a wireless default route is an ordinary
	// laptop, and a report that called it broken would be teaching the
	// operator to distrust every warning.
	DefaultRouteCount      int      `json:"default_route_count"`
	DefaultRouteInterfaces []string `json:"default_route_interfaces,omitempty"`

	// Infrastructure lists the virtual links THN observed and does not own.
	Infrastructure []string `json:"infrastructure,omitempty"`

	// Notes are observations that qualify the analysis as a whole.
	Notes []string `json:"notes,omitempty"`

	// Unknowns explains every `unknown` the analysis reached.
	//
	// An unknown with no reason is the thing this milestone's diagnostics
	// requirement exists to eliminate. "the host reported no link speed" is
	// true and useless: it does not distinguish a driver that never reports
	// one from a sysfs read that was refused, and those are different
	// problems on different machines.
	Unknowns []Unknown `json:"unknowns,omitempty"`

	// AssignmentMade is always false.
	//
	// It exists so a machine consumer reading this document is told so in a
	// field and not only in prose. Analysis cannot produce an assignment —
	// see TestM71AnalysisAssignsNothing.
	AssignmentMade bool `json:"assignment_made"`
}

// IntelligenceRoles returns the roles M7.1 analyses, in rendering order.
//
// A closed list rather than everything in KnownRoles, because suitability for
// guest or DMZ is not what this milestone answers, and offering one would
// imply the others had been considered and found equivalent.
func IntelligenceRoles() []Role { return []Role{RoleWAN, RoleLAN, RoleMGMT} }

// Unknown is one thing the analysis could not determine, and why.
//
// It exists because "unknown" without a cause is the single least useful
// thing a diagnostic tool can report. Every entry answers the question an
// operator actually has — why does THN not know this? — and names the stage
// that stopped, so the answer points at the fix rather than at THN.
//
// Subject is the interface or role; Probe is the underlying record, so a
// reader can trace it back to the command or file that produced it.
type Unknown struct {
	// Subject is what could not be determined: an interface name, or
	// "host" for something with no single owner.
	Subject string `json:"subject"`

	// Question is the specific thing that is unknown, as a stable code.
	//
	//	link-speed      the negotiated link speed
	//	wireless-mode   the wireless operating mode
	//	physicality     whether the link is real hardware
	//	host-inspection whether anything at all could be observed
	Question string `json:"question"`

	// Detail is the human sentence.
	Detail string `json:"detail"`

	// Probe is the structured cause.
	//
	// A zero Probe here means THN established the unknown by reasoning about
	// what it could see, with no external read behind it — which is itself
	// recorded rather than left blank, because "nothing was asked" is the
	// answer to a question an operator may need to ask differently.
	Probe network.Probe `json:"probe"`
}

// unknown builds an Unknown whose cause is a probe.
func unknown(subject, question, detail string, p network.Probe) Unknown {
	return Unknown{Subject: subject, Question: question, Detail: detail, Probe: p}
}

// unknownFrom builds an Unknown whose cause is already known to be an
// absence rather than a failure.
func unknownFrom(subject, question, detail string) Unknown {
	return unknown(subject, question, detail, network.NotChecked("analysis", question))
}

// analyzeInterface adds the entries this interface contributed.
//
// The two questions worth asking about are the ones the analyzer cannot
// answer from the observation alone, because the observation carries the
// answer's ABSENCE and not its cause. Link speed and wireless mode are both
// `(value, bool)` pairs where false means "unknown", and both originate in a
// read that either failed or found nothing — and the analyzer cannot tell
// which, because that record lives on the Device's probes.
//
// Linking back to it is what turns "speed unknown" into "the kernel's speed
// attribute is absent for this interface", which is an answer.
func analyzeInterface(d *Device, in InterfaceIntelligence, out *[]Unknown) {
	if !in.SpeedKnown {
		*out = append(*out, unknown(
			in.SystemName, "link-speed",
			"the link speed was not reported, so throughput is unknown and is not estimated",
			speedProbeFor(d, in.SystemName)))
	}

	// A wireless interface with no observed mode is the case the brief singles
	// out: THN must not infer AP capability, and saying why it did not is
	// what makes that restraint legible rather than looking like an omission.
	// A wireless radio whose mode the host did not state. Keyed on the
	// LINK CLASS rather than on Interface.Kind, because the class is what
	// survives the kernel's own reclassification: `ip` reports a Wi-Fi NIC's
	// link_type as "ether" and relies on the wireless object to mark it, and
	// the class is computed from the already-normalised kind.
	if in.Class == LinkPhysicalWireless && wirelessModeOf(d, in.SystemName) == "" {
		*out = append(*out, unknown(
			in.SystemName, "wireless-mode",
			"the host reported no wireless mode, so access-point capability is not inferred",
			wirelessProbeFor(d, in.SystemName)))
	}
}

// speedProbeFor finds the probe that explains an absent link speed.
//
// Falls back to a not-checked record rather than an empty one, so an unknown
// always carries a record that says something — even if all it says is that
// THN did not ask.
func speedProbeFor(d *Device, iface string) network.Probe {
	if p, ok := findProbe(d, "link-speed", iface); ok {
		return p
	}
	p := network.NotChecked("link-speed", "sysfs-speed/"+iface)
	p.Detail = "no probe for this interface's link speed is recorded on the device; " +
		"the absence of a speed is unexplained by the observation itself"
	return p
}

// wirelessProbeFor finds the probe that explains an unobserved wireless mode.
func wirelessProbeFor(d *Device, iface string) network.Probe {
	for _, op := range []string{"sysfs-wireless-status/" + iface, "sysfs-wireless-mode/" + iface} {
		if p, ok := findProbe(d, "wireless", iface); ok {
			// The operation is refined to name the interface because a host
			// with several radios produces one record per radio, and a reader
			// needs to know which one this is.
			p.Operation = op
			return p
		}
	}
	if p, ok := findProbe(d, "wireless", "nl80211-modes/"+iface); ok {
		return p
	}
	p := network.NotChecked("wireless", "wireless-mode/"+iface)
	p.Detail = "no probe for this interface's wireless mode is recorded on the device; " +
		"the absence of a mode is unexplained by the observation itself"
	return p
}

// findProbe locates a probe by subsystem and by an interface named anywhere
// in its operation or path.
//
// Matching on the interface name across both fields rather than expecting one
// exact spelling is deliberate: the probe that explains a speed comes from
// sysfs and names the interface in its Path, while the one that explains a
// wireless mode names it in its Operation. Requiring one of them would make
// half the unknowns fall back to the "unexplained" record.
//
// The path is matched by SEGMENT rather than by joining with the platform's
// separator. A path built with the other platform's separator is still a path
// that names the interface, and a check that silently stopped matching on one
// operating system would turn every speed unknown on that host into an
// unexplained one — the exact bug this is fixing, reproduced in a new place.
func findProbe(d *Device, subsystem, iface string) (network.Probe, bool) {
	if iface == "" {
		return network.Probe{}, false
	}
	for _, p := range d.Probes {
		if p.Subsystem != subsystem {
			continue
		}
		if p.Operation == iface || strings.HasSuffix(p.Operation, "/"+iface) {
			return p, true
		}
		if pathNamesSegment(p.Path, iface) {
			return p, true
		}
	}
	return network.Probe{}, false
}

// pathNamesSegment reports whether any path segment equals name.
//
// Both separators are accepted regardless of the platform, because a recorded
// path is data rather than something this package built, and a diagnostic that
// only resolves on the platform that produced the path is not a diagnostic.
func pathNamesSegment(path, name string) bool {
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if seg == name {
			return true
		}
	}
	return false
}

// wirelessModeOf reads the observed mode for an interface, empty when none.
func wirelessModeOf(d *Device, iface string) string {
	for _, i := range d.Interfaces {
		if i.SystemName == iface {
			return i.WirelessMode
		}
	}
	return ""
}

// AnalyzeHardware judges an observed host for gateway suitability.
//
// Pure and total. It never returns an error, never mutates the Device it is
// given, and has no parameter through which an Assignment could be returned.
func AnalyzeHardware(d *Device) HardwareIntelligence {
	out := HardwareIntelligence{
		Interfaces:     []InterfaceIntelligence{},
		Profiles:       []GatewayProfile{},
		Notes:          []string{},
		Infrastructure: []string{},
		Unknowns:       []Unknown{},
	}

	if d == nil || !d.Supported {
		out.Unknowns = append(out.Unknowns, unknownFrom("host", "host-inspection",
			"host inspection is not available on this machine, so no interface could be assessed"))
		out.Notes = append(out.Notes,
			"host inspection is not available on this machine, so no interface could be assessed; "+
				"every classification is unknown rather than unsuitable")
		return out
	}
	out.Supported = true

	var routes []network.Route
	if d != nil {
		routes = d.Routes
	}
	idx := indexRoutes(routes)
	out.DefaultRouteCount = idx.defaultTotal
	out.DefaultRouteInterfaces = idx.defaultIfaces

	intel := make([]InterfaceIntelligence, 0, len(d.Interfaces))
	for _, i := range sortedInterfaces(d.Interfaces) {
		in := assessInterface(i, idx)
		intel = append(intel, in)
		analyzeInterface(d, in, &out.Unknowns)

		if !in.Physical {
			out.Infrastructure = append(out.Infrastructure, i.SystemName)
			continue
		}
		out.PhysicalPorts++
		switch in.Class {
		case LinkPhysicalWired:
			out.PhysicalEthernet++
		case LinkPhysicalWireless:
			out.PhysicalWireless++
		}
	}
	out.Interfaces = intel

	out.Profiles = profilesFor(intel, idx)
	out.Notes = append(out.Notes, wholeHostNotes(out, idx)...)
	return out
}

// sortedInterfaces returns a deterministically ordered copy.
//
// Two runs over the same host must produce byte-identical output, and a caller
// that assembled a Device by hand rather than through FromSnapshot would
// otherwise get output in whatever order it happened to populate the slice.
// System name leads because that is what the rest of THN renders, and the
// stable ID breaks the tie so two links can never be ordered inconsistently
// between runs.
func sortedInterfaces(in []Interface) []Interface {
	out := make([]Interface, len(in))
	copy(out, in)
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].SystemName != out[b].SystemName {
			return out[a].SystemName < out[b].SystemName
		}
		return out[a].ID < out[b].ID
	})
	return out
}

// ------------------------------------------------------------ routing index

// routeFacts is what the observed routing table says about one interface.
type routeFacts struct {
	total int

	// defaults counts how many observed default routes use this interface.
	defaults int
}

// routeIndex is the whole routing table, keyed by interface name.
//
// Keyed by NAME because that is how the kernel reports routes, and because a
// route pointing at an interface this host no longer has is still a fact worth
// reporting — that is how a stale route would show up.
type routeIndex struct {
	byInterface   map[string]routeFacts
	defaultTotal  int
	defaultIfaces []string
}

// indexRoutes builds the per-interface routing summary.
func indexRoutes(routes []network.Route) routeIndex {
	idx := routeIndex{byInterface: map[string]routeFacts{}}

	for _, r := range routes {
		if r.Interface == "" {
			continue
		}
		f := idx.byInterface[r.Interface]
		f.total++
		if r.Default {
			f.defaults++
			idx.defaultTotal++
			idx.defaultIfaces = append(idx.defaultIfaces, r.Interface)
		}
		idx.byInterface[r.Interface] = f
	}

	// Sorted and de-duplicated: two default routes out of one Ethernet link
	// are one interface carrying a default route, and reporting it twice
	// would suggest the host has two uplinks when it has one.
	idx.defaultIfaces = distinctSorted(idx.defaultIfaces)
	return idx
}

func (r routeIndex) factsFor(name string) routeFacts { return r.byInterface[name] }

// ------------------------------------------------------ per-interface work

// assessInterface produces the complete judgement for one interface.
func assessInterface(i Interface, idx routeIndex) InterfaceIntelligence {
	class := classifyLink(i)
	usage := usageOf(i, idx.factsFor(i.SystemName))

	in := InterfaceIntelligence{
		ID:          i.ID,
		IDKind:      i.IDKind,
		SystemName:  i.SystemName,
		Kind:        i.Kind,
		Physical:    i.Physical,
		Class:       class,
		SpeedMbps:   i.SpeedMbps,
		SpeedKnown:  i.SpeedMbps > 0,
		Usage:       usage,
		Suitability: map[Role]RoleSuitability{},
	}

	for _, role := range IntelligenceRoles() {
		in.Suitability[role] = assessRole(i, class, usage, role)
	}
	return in
}

// classifyLink decides whether a link is a port an operator could plug a
// cable into.
//
// Decided entirely from observed properties. Not from the name — "eth0",
// "enp0s31f6" and "br-abc123" are all names, and the two ends of that list are
// opposite ends of the question. Not from the address either: a Docker bridge
// holding 172.18.0.1/16 and a NIC holding 192.168.1.5/24 both carry private
// addresses, and neither fact says anything about what the link is.
func classifyLink(i Interface) LinkClass {
	switch {
	case !i.Physical:
		return LinkInfrastructure
	case i.Kind == KindEthernet:
		return LinkPhysicalWired
	case i.Kind == KindWireless:
		return LinkPhysicalWireless
	default:
		return LinkPhysicalOther
	}
}

// usageOf summarises what the host is currently doing with an interface.
func usageOf(i Interface, f routeFacts) CurrentUsage {
	v4, v6 := routableAddresses(i)

	u := CurrentUsage{
		Carrier:      i.LinkUp,
		AdminUp:      i.AdminUp,
		IPv4:         v4,
		IPv6:         v6,
		Addressed:    v4 || v6,
		DefaultRoute: f.defaults > 0,
		RouteCount:   f.total,
		Master:       i.Master,
		AssignedRole: assignedRoleOf(i),
	}

	switch {
	case !i.Physical:
		u.State = UsageInfrastructure
	case i.Master != "":
		u.State = UsageEnslaved
	case u.DefaultRoute || u.Addressed:
		u.State = UsageOccupied
	default:
		u.State = UsageIdle
	}
	return u
}

// assignedRoleOf returns a recorded assignment, or empty.
//
// Empty rather than RoleUnassigned, because on an observed device "unassigned"
// and "not yet recorded" are the same thing, and rendering the constant would
// imply a decision had been made.
func assignedRoleOf(i Interface) Role {
	if i.Role == "" || i.Role == RoleUnassigned {
		return ""
	}
	return i.Role
}

// routableAddresses reports whether a link holds an address that means
// somebody configured it.
//
// Two exclusions, both of which are the difference between a field that
// carries information and one that is always true.
//
// Link-local: Linux assigns an fe80::/64 to every IPv6-capable interface
// automatically. Counting it would mark every NIC on every host as carrying an
// address, and the whole "is anything using this link" question would answer
// yes everywhere and mean nothing.
//
// Loopback: 127.0.0.1 and ::1 are addresses of the loopback device and of no
// other link, and a host carrying one on some interface has not configured
// that interface at all.
func routableAddresses(i Interface) (v4, v6 bool) {
	for _, c := range i.IPv4() {
		a, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if addr := a.Addr(); !addr.IsUnspecified() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
			v4 = true
		}
	}
	for _, c := range i.IPv6() {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		a := p.Addr()
		if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsLoopback() || a.IsUnspecified() {
			continue
		}
		v6 = true
	}
	return v4, v6
}

// assessRole judges one interface against one role.
func assessRole(i Interface, class LinkClass, u CurrentUsage, role Role) RoleSuitability {
	s := RoleSuitability{Role: role, Confidence: ConfidenceObserved}

	if class == LinkInfrastructure {
		s.Suitability = SuitabilityUnsuitable
		s.Evidence = infrastructureEvidence(i, u)
		s.Blockers = []string{infrastructureBlocker(i)}
		return s
	}

	s.Evidence = physicalEvidence(i, class, u)
	s.Suitability = SuitabilityUnknown
	s.Blockers = []string{}
	s.Limitations = []string{}

	if !i.Assignable {
		s.Suitability = SuitabilityUnsuitable
		s.Blockers = append(s.Blockers,
			"THN will not offer this interface for any role, independent of its hardware")
		return s
	}

	switch class {
	case LinkPhysicalWireless:
		wirelessVerdict(i, u, &s)
	default:
		wiredVerdict(i, u, &s)
	}

	// Constraints that apply to every physical link, whatever the role.
	if i.SpeedMbps <= 0 {
		s.Limitations = append(s.Limitations,
			"the host reported no link speed, so throughput is unknown and is not estimated")
	}
	if u.AssignedRole != "" {
		s.Blockers = append(s.Blockers, fmt.Sprintf(
			"role %s is already recorded against this interface; suitability is not a decision to change that",
			u.AssignedRole))
	}
	if u.State == UsageEnslaved {
		// A bridge relationship is a compatibility constraint, not a
		// classification of busy-ness, so it does reduce the verdict.
		s.Suitability = SuitabilityLimitedCandidate
		s.Blockers = append(s.Blockers, fmt.Sprintf(
			"this interface is enslaved to %s; that relationship is existing configuration and "+
				"cannot be repurposed without resolving it", u.Master))
	}
	return s
}

// wiredVerdict judges a physical Ethernet or other wired port.
//
// Occupancy is recorded as a limitation and never subtracted from the
// classification. The interface carrying the default route is the best
// evidence on the host that it is the uplink; reporting it as a poor
// candidate because it is already working would be the single most misleading
// thing this analysis could do.
func wiredVerdict(i Interface, u CurrentUsage, s *RoleSuitability) {
	switch s.Role {
	case RoleWAN:
		switch {
		case u.DefaultRoute && u.Carrier:
			s.Suitability = SuitabilityStrongCandidate
			s.Evidence = append(s.Evidence, observedEvidence("uplink-shape",
				"this is the shape an uplink normally has: real hardware, connected, and carrying the observed default route"))
		case u.Carrier:
			s.Suitability = SuitabilityCandidate
		default:
			s.Suitability = SuitabilityLimitedCandidate
			s.Limitations = append(s.Limitations,
				"no carrier is present, so the link is not currently connected")
		}

	case RoleLAN:
		if u.DefaultRoute {
			// Not unsuitable, and not a candidate either. The link is real
			// hardware doing exactly the thing this role does not want done.
			s.Suitability = SuitabilityLimitedCandidate
			s.Limitations = append(s.Limitations,
				"an observed default route currently uses this interface; "+
					"using it for a downstream network would change the host's current path to the internet")
		} else {
			s.Suitability = SuitabilityCandidate
			if !u.Carrier {
				s.Limitations = append(s.Limitations,
					"no carrier is present, so the link is not currently connected")
			}
		}

	case RoleMGMT:
		s.Suitability = SuitabilityCandidate
		if u.DefaultRoute {
			s.Limitations = append(s.Limitations,
				"an observed default route currently uses this interface")
		}
		if !u.Carrier {
			s.Limitations = append(s.Limitations,
				"no carrier is present, so the link is not currently connected")
		}
	}

	if u.State == UsageOccupied {
		s.Limitations = append(s.Limitations,
			"currently in use: the interface carries observed addresses or routes")
	}
}

// wirelessVerdict judges a physical radio.
//
// Three separate decisions, kept separate on purpose:
//
//   - A radio is hardware, and it is not a wired port.
//   - A wireless CLIENT is a plausible uplink and a poor LAN. That asymmetry
//     is about what the medium is, not about the interface being second-class.
//   - Access-point capability is OBSERVED or absent. THN never infers it from
//     the presence of a radio, because "this chip could host an AP" is a claim
//     about a driver and a regulatory domain, not about this host.
func wirelessVerdict(i Interface, u CurrentUsage, s *RoleSuitability) {
	mode := i.WirelessMode
	s.Evidence = append(s.Evidence, observedEvidence("wireless-mode", wirelessModeDetail(mode)))

	switch mode {
	case WirelessModeAP:
		// Observed as an access point. Serving downstream is exactly what
		// this interface is doing, so LAN is a reasonable shape for it.
		if s.Role == RoleWAN {
			s.Suitability = SuitabilityUnsuitable
			s.Blockers = append(s.Blockers,
				"this radio is observed in access-point mode; an access point serves downstream "+
					"clients and is not an uplink")
			return
		}
		s.Suitability = SuitabilityCandidate
		s.Limitations = append(s.Limitations,
			"observed in access-point mode; reported because the host stated it, not inferred from the hardware")
		return

	case WirelessModeMonitor, WirelessModeMesh, WirelessModeAdhoc:
		s.Suitability = SuitabilityUnsuitable
		s.Blockers = append(s.Blockers, fmt.Sprintf(
			"this radio is observed in %s mode, which carries no gateway traffic", mode))
		return
	}

	// Client, or a mode the host did not report. Neither case gets AP
	// capability inferred, and the unreported case says so explicitly.
	if mode == "" {
		s.Limitations = append(s.Limitations,
			"the host reported no wireless mode, so THN does not assume access-point capability")
	}

	if s.Role == RoleLAN {
		s.Suitability = SuitabilityLimitedCandidate
		s.Limitations = append(s.Limitations,
			"a wireless client interface is not equivalent to a wired LAN port")
		if !u.Carrier {
			s.Limitations = append(s.Limitations,
				"the radio has not associated with an access point")
		}
		return
	}

	if s.Role == RoleMGMT {
		s.Suitability = SuitabilityLimitedCandidate
		s.Limitations = append(s.Limitations,
			"management over wireless is subject to the same association as any other wireless link")
		if !u.Carrier {
			s.Limitations = append(s.Limitations,
				"the radio has not associated with an access point")
		}
		return
	}

	// WAN.
	switch {
	case u.DefaultRoute && u.Carrier:
		s.Suitability = SuitabilityStrongCandidate
	case u.Carrier && u.Addressed:
		s.Suitability = SuitabilityCandidate
	case u.Carrier:
		s.Suitability = SuitabilityLimitedCandidate
	default:
		s.Suitability = SuitabilityLimitedCandidate
		s.Limitations = append(s.Limitations,
			"the radio has not associated with an access point")
	}
	s.Limitations = append(s.Limitations,
		"a wireless uplink is plausible but is not interchangeable with a wired port, and "+
			"its link characteristics are not assessed by this analysis")
}

// wirelessModeDetail renders an observed mode, saying plainly when there is
// none.
func wirelessModeDetail(mode string) string {
	if mode == "" {
		return "no wireless mode was reported by the host"
	}
	return "wireless mode: " + mode
}

// physicalEvidence is the shared evidence every hardware port carries.
func physicalEvidence(i Interface, class LinkClass, u CurrentUsage) []Evidence {
	ev := []Evidence{observedEvidence("physical-link", "the host reports this as real hardware")}

	switch class {
	case LinkPhysicalWired:
		ev = append(ev, observedEvidence("ethernet", "Ethernet link kind"))
	case LinkPhysicalWireless:
		ev = append(ev, observedEvidence("wireless", "wireless link kind"))
	default:
		ev = append(ev, observedEvidence("link-kind",
			"link kind "+orUnknown(i.Kind)+"; THN has no specific assessment for this kind"))
	}

	if u.Carrier {
		ev = append(ev, observedEvidence("carrier-present", "a carrier is present"))
	} else {
		ev = append(ev, observedEvidence("no-carrier", "no carrier is present"))
	}
	if u.AdminUp {
		ev = append(ev, observedEvidence("admin-up", "the link is administratively up"))
	} else {
		ev = append(ev, observedEvidence("admin-down", "the link is administratively down"))
	}

	if i.SpeedMbps > 0 {
		ev = append(ev, observedEvidence("link-speed", fmt.Sprintf("%d Mbps observed", i.SpeedMbps)))
	} else {
		ev = append(ev, observedEvidence("link-speed-unknown",
			"the host reported no link speed; zero would be a measurement and this is not one"))
	}

	if u.IPv4 {
		ev = append(ev, observedEvidence("ipv4-address", "an IPv4 address is assigned"))
	}
	if u.IPv6 {
		ev = append(ev, observedEvidence("ipv6-address", "a non-link-local IPv6 address is assigned"))
	}
	if !u.IPv4 && !u.IPv6 {
		ev = append(ev, observedEvidence("no-address", "no routable address is assigned"))
	}

	if u.DefaultRoute {
		ev = append(ev, observedEvidence("default-route", "an observed default route uses this interface"))
	} else {
		ev = append(ev, observedEvidence("no-default-route", "no observed default route uses this interface"))
	}
	if u.RouteCount > 0 {
		ev = append(ev, observedEvidence("routes-present",
			fmt.Sprintf("%d observed route(s) use this interface", u.RouteCount)))
	}

	if u.Master != "" {
		ev = append(ev, observedEvidence("enslaved",
			"enslaved to "+u.Master+"; the link's layer-2 identity belongs to that device"))
	}
	if u.AssignedRole != "" {
		ev = append(ev, observedEvidence("assigned-role",
			"role "+string(u.AssignedRole)+" is recorded against this interface"))
	}
	if i.IDKind == IdentityHardware {
		ev = append(ev, observedEvidence("stable-identity", "this interface has a rename-stable identity"))
	} else {
		ev = append(ev, observedEvidence("ephemeral-identity",
			"this interface has no hardware address, so its identity does not survive a rename"))
	}

	return ev
}

// infrastructureEvidence describes a virtual link.
//
// The wording names the concrete thing rather than the general one. "virtual
// interface" tells an operator nothing they did not already assume; "container
// endpoint attached to a bridge" tells them why it must not be bound to a role.
func infrastructureEvidence(i Interface, u CurrentUsage) []Evidence {
	ev := []Evidence{
		observedEvidence("virtual-link", "the host reports this as a virtual link, not hardware"),
	}

	switch i.Kind {
	case KindLoopback:
		ev = append(ev, observedEvidence("loopback", "loopback interface"))
	case KindBridge:
		ev = append(ev, observedEvidence("bridge", "bridge interface"))
	case KindBond:
		ev = append(ev, observedEvidence("bond", "bond interface; its member ports are the physical hardware"))
	case KindVLAN:
		ev = append(ev, observedEvidence("vlan", "VLAN interface"))
	case KindTunnel:
		ev = append(ev, observedEvidence("tunnel", "tunnel interface"))
	case KindVeth:
		ev = append(ev, observedEvidence("veth",
			"veth interface; a container endpoint that does not outlive its container"))
	case KindDummy:
		ev = append(ev, observedEvidence("dummy", "dummy interface; a placeholder with no peer"))
	default:
		ev = append(ev, observedEvidence("link-kind", "link kind "+orUnknown(i.Kind)))
	}

	if u.Master != "" {
		ev = append(ev, observedEvidence("enslaved", "attached to "+u.Master))
	}
	if u.DefaultRoute {
		ev = append(ev, observedEvidence("default-route", "an observed default route uses this interface"))
	}
	return ev
}

// infrastructureBlocker is the sentence that rules a virtual link out.
func infrastructureBlocker(i Interface) string {
	switch i.Kind {
	case KindLoopback:
		return "loopback is not a gateway port"
	case KindBridge:
		return "a bridge is virtual infrastructure, not a physical port"
	case KindBond:
		return "a bond is virtual infrastructure; its physical member ports are the things to assess"
	case KindVLAN:
		return "a VLAN interface is virtual infrastructure, not a physical port"
	case KindTunnel:
		return "a tunnel is virtual infrastructure, not a physical port"
	case KindVeth:
		if i.Master != "" {
			return fmt.Sprintf(
				"a container endpoint attached to %s is virtual infrastructure and does not outlive its container",
				i.Master)
		}
		return "a container endpoint is virtual infrastructure and does not outlive its container"
	case KindDummy:
		return "a dummy interface is a placeholder with no peer"
	default:
		return "this is a virtual interface and not a physical gateway port"
	}
}

// -------------------------------------------------------- gateway profiles

// profilesFor judges the three gateway shapes against one observed host.
//
// Every profile is always reported. A host with two ports is not simply "not
// multi-interface" with nothing said: an operator choosing a shape needs to
// know that three ports would be possible here and what is missing, and an
// absent section is indistinguishable from a section nobody wrote.
func profilesFor(ifaces []InterfaceIntelligence, idx routeIndex) []GatewayProfile {
	return []GatewayProfile{
		singleInterfaceProfile(ifaces, idx),
		twoPortWiredProfile(ifaces, idx),
		multiInterfaceProfile(ifaces, idx),
	}
}

// singleInterfaceProfile judges the one-port shape.
func singleInterfaceProfile(ifaces []InterfaceIntelligence, idx routeIndex) GatewayProfile {
	physical := countPhysical(ifaces)
	p := GatewayProfile{ID: ProfileSingleInterface, Title: "Single-interface host"}

	if physical != 1 {
		return impossibleProfile(p, fmt.Sprintf(
			"%d physical interface(s) observed, so this host is not a single-interface host", physical))
	}

	p.Verdict = ProfilePossible
	p.Evidence = []Evidence{observedEvidence("physical-port-count", "1 physical interface observed")}
	p.Constraints = []string{
		"one physical port cannot carry a separate uplink and a downstream network over separate hardware",
	}
	addConstraints(&p, ifaces, idx)
	return p
}

// twoPortWiredProfile judges the canonical shape.
//
// It counts physical ETHERNET specifically rather than all physical
// interfaces. A wired port and a Wi-Fi radio are two pieces of hardware, and
// only one of them is the port a cable goes into; counting the radio would let
// this host report a two-port wired gateway on the strength of a wireless
// adapter.
func twoPortWiredProfile(ifaces []InterfaceIntelligence, idx routeIndex) GatewayProfile {
	ethernet := countClass(ifaces, LinkPhysicalWired)
	p := GatewayProfile{ID: ProfileTwoPortWired, Title: "Two-port wired gateway"}

	if ethernet < 2 {
		return impossibleProfile(p, fmt.Sprintf(
			"%d physical Ethernet interface(s) observed, but this shape needs 2; "+
				"this says nothing about what else the host is able to do", ethernet))
	}

	p.Verdict = ProfilePossible
	p.Evidence = []Evidence{observedEvidence("physical-ethernet-count",
		fmt.Sprintf("%d physical Ethernet interfaces observed", ethernet))}

	pickBest(ifaces, &p, IntelligenceRoles())
	addConstraints(&p, ifaces, idx)
	return p
}

// multiInterfaceProfile judges the three-or-more-ports shape.
func multiInterfaceProfile(ifaces []InterfaceIntelligence, idx routeIndex) GatewayProfile {
	physical := countPhysical(ifaces)
	p := GatewayProfile{ID: ProfileMultiInterface, Title: "Multi-interface gateway"}

	if physical < 3 {
		return impossibleProfile(p, fmt.Sprintf(
			"%d physical interface(s) observed, but this shape needs 3 or more", physical))
	}

	p.Verdict = ProfilePossible
	p.Evidence = []Evidence{observedEvidence("physical-port-count",
		fmt.Sprintf("%d physical interface(s) observed", physical))}

	pickBest(ifaces, &p, IntelligenceRoles())
	addConstraints(&p, ifaces, idx)
	return p
}

// impossibleProfile builds the NOT POSSIBLE form, with a reason that never
// generalises.
//
// "0 physical Ethernet interfaces" is a statement about wired ports. Turning
// that into "this host is unsuitable" would be wrong — the same host may have
// a working wireless uplink and be perfectly usable as an access point — and
// it is the generalisation an operator would quote back at THN when it is
// wrong about a machine they can see.
//
// The reason appears once, as evidence. It is not repeated as a constraint:
// the same sentence twice under one heading reads as two findings, and an
// operator counting problems is now counting one problem twice.
func impossibleProfile(p GatewayProfile, reason string) GatewayProfile {
	p.Verdict = ProfileNotPossible
	p.Evidence = []Evidence{observedEvidence("port-count-shortfall", reason)}
	return p
}

// pickBest names the best-suited interface for each requested role.
//
// Selection is by observed evidence, never by position. Reading Interfaces[0]
// would mean a virtual bridge that happens to sort first becomes the uplink —
// the exact failure the identity and physicality work in M7.0 was built to
// prevent, reintroduced through a different door.
//
// Two interfaces cannot be picked for one profile, so a role already chosen is
// excluded from the remaining picks.
func pickBest(ifaces []InterfaceIntelligence, p *GatewayProfile, roles []Role) {
	taken := map[string]bool{}
	for _, name := range p.Candidates {
		taken[name] = true
	}

	for _, role := range roles {
		best := ""
		bestScore := 0
		bestWired := false
		bestCarriesDefault := false

		for _, in := range ifaces {
			if !in.Physical || taken[in.SystemName] {
				continue
			}
			s := in.SuitabilityFor(role)
			if !s.Candidate() {
				continue
			}

			// Strictly-greater comparisons only, so a tie keeps the earlier
			// interface. ifaces is already sorted, which means the winner does
			// not depend on map iteration order or on the order a caller
			// happened to populate the Device.
			if best == "" || betterPick(
				s.Suitability.rank(), in.Class == LinkPhysicalWired, in.Usage.DefaultRoute,
				bestScore, bestWired, bestCarriesDefault) {
				best = in.SystemName
				bestScore = s.Suitability.rank()
				bestWired = in.Class == LinkPhysicalWired
				bestCarriesDefault = in.Usage.DefaultRoute
			}
		}

		if best == "" {
			continue
		}
		if p.Candidates == nil {
			p.Candidates = map[Role]string{}
		}
		p.Candidates[role] = best
		taken[best] = true
	}
}

// betterPick reports whether a candidate outranks the incumbent.
//
// Ordered deliberately: strength first, then wired over wireless, then an
// interface already carrying the default route. Ties fall through to the
// deterministic ordering of the input slice.
func betterPick(score int, wired, carriesDefault bool, bestScore int, bestWired, bestCarriesDefault bool) bool {
	if score != bestScore {
		return score > bestScore
	}
	if wired != bestWired {
		return wired
	}
	return carriesDefault && !bestCarriesDefault
}

// addConstraints records what an operator must know before configuring this
// shape on this host.
//
// The three groups — what the chosen ports are doing now, what virtual
// infrastructure exists, and what the routing topology looks like — are each
// real but easy to miss, and an operator reading only the profile section
// would otherwise have to correlate it against three other sections by hand.
func addConstraints(p *GatewayProfile, ifaces []InterfaceIntelligence, idx routeIndex) {
	p.Constraints = append(p.Constraints, roleConstraints(p, ifaces)...)

	for _, in := range ifaces {
		if in.Physical {
			if in.Usage.State == UsageEnslaved {
				p.Constraints = append(p.Constraints, fmt.Sprintf(
					"physical interface %s is enslaved to %s; that relationship is existing configuration, not a suggestion",
					in.SystemName, in.Usage.Master))
			}
			continue
		}
		p.Constraints = append(p.Constraints, fmt.Sprintf(
			"this host carries virtual interface %s (%s), which THN records and does not modify",
			in.SystemName, orUnknown(in.Kind)))
	}

	switch {
	case idx.defaultTotal > 1:
		p.Constraints = append(p.Constraints, fmt.Sprintf(
			"multiple default-route paths observed (%d routes across %s); recorded as an observation, not an error",
			idx.defaultTotal, strings.Join(idx.defaultIfaces, ", ")))
	case idx.defaultTotal == 1:
		p.Constraints = append(p.Constraints, fmt.Sprintf(
			"an observed default route uses %s", idx.defaultIfaces[0]))
	}
}

// roleConstraints describes what each chosen port is currently doing.
//
// A role with no candidate gets its own wording rather than the generic one,
// because the two failures look identical on the model and mean different
// things to an operator. "No interface could serve as mgmt" is a statement
// about the hardware; "every candidate has already been taken by another role
// in this profile" is a statement about this profile, and the operator's next
// move is different in each case.
func roleConstraints(p *GatewayProfile, ifaces []InterfaceIntelligence) []string {
	var out []string
	for _, role := range IntelligenceRoles() {
		name, ok := p.Candidates[role]
		if !ok {
			out = append(out, fmt.Sprintf(
				"no further observed interface is available for %s in this profile; "+
					"every candidate already named has been taken by another role", role))
			continue
		}
		in, found := bySystemName(ifaces, name)
		if !found {
			continue
		}
		switch in.Usage.State {
		case UsageOccupied:
			out = append(out, fmt.Sprintf("the %s candidate %s is currently in use", role, name))
		case UsageEnslaved:
			out = append(out, fmt.Sprintf("the %s candidate %s is enslaved to %s", role, name, in.Usage.Master))
		case UsageIdle:
			out = append(out, fmt.Sprintf("the %s candidate %s is idle and has no carrier", role, name))
		}
		if in.Usage.DefaultRoute {
			out = append(out, fmt.Sprintf("the %s candidate %s currently carries an observed default route", role, name))
		}
	}
	return out
}

func countPhysical(ifaces []InterfaceIntelligence) int {
	n := 0
	for _, in := range ifaces {
		if in.Physical {
			n++
		}
	}
	return n
}

func countClass(ifaces []InterfaceIntelligence, c LinkClass) int {
	n := 0
	for _, in := range ifaces {
		if in.Class == c {
			n++
		}
	}
	return n
}

func bySystemName(ifaces []InterfaceIntelligence, name string) (InterfaceIntelligence, bool) {
	for _, in := range ifaces {
		if in.SystemName == name {
			return in, true
		}
	}
	return InterfaceIntelligence{}, false
}

// wholeHostNotes records the observations that qualify the analysis itself.
func wholeHostNotes(out HardwareIntelligence, idx routeIndex) []string {
	var notes []string

	if len(out.Infrastructure) > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d virtual interface(s) were observed; they are recorded as infrastructure and left untouched",
			len(out.Infrastructure)))
	}
	if idx.defaultTotal > 1 {
		notes = append(notes, fmt.Sprintf(
			"multiple default-route paths observed (%d routes across %s); "+
				"this is a fact about the host, not a fault",
			idx.defaultTotal, strings.Join(idx.defaultIfaces, ", ")))
	}

	// The non-negotiable caveats, stated in the data and not only in prose.
	notes = append(notes,
		"suitability is hardware evidence only; it does not confirm DHCP, DNS, VLAN, "+
			"access-point, firewall, shaping or multi-WAN capability, and it is not a readiness verdict")
	notes = append(notes,
		"no interface was assigned a role and no configuration was changed by this analysis")
	return notes
}

// distinctSorted returns the sorted, de-duplicated members of a list.
func distinctSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
