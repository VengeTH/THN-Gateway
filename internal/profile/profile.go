package profile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/host"
)

// Profile is an intended use of this machine.
//
// The set is open in the same way host.Role is: adding one is a constant and a
// definition, not a schema change.
type Profile string

const (
	// ProfileGateway routes between an uplink and one or more downstream
	// networks, masquerades outbound traffic, and serves DHCP and DNS.
	// This is the product's first target.
	ProfileGateway Profile = "gateway"

	// ProfileRouter routes and masquerades but serves no DHCP or DNS. The
	// difference from a gateway is who answers addresses on the LAN.
	ProfileRouter Profile = "router"

	// ProfileFirewall filters traffic and terminates nothing else.
	ProfileFirewall Profile = "firewall"

	// ProfileDNSOnly answers name queries and does not route.
	ProfileDNSOnly Profile = "dns-server"

	// ProfileDHCPServer hands out addresses and does not route.
	ProfileDHCPServer Profile = "dhcp-server"

	// ProfileAccessPoint bridges wireless clients onto a downstream network.
	ProfileAccessPoint Profile = "access-point"

	// ProfileBridge extends an existing L2 segment without routing.
	ProfileBridge Profile = "bridge"

	// ProfileManagedDevice is the "I want to run THN on this machine and be
	// told what is possible" answer. It requires no particular topology.
	ProfileManagedDevice Profile = "managed-device"
)

// Requirement is one thing a profile needs from the host.
type Requirement struct {
	// Role is the logical role that must be filled, if any.
	//
	// Empty means the requirement is about a capability rather than an
	// interface.
	Role host.Role

	// Required distinguishes "must have" from "nice to have".
	//
	// It exists because a strict profile would refuse a perfectly usable
	// machine over a nicety. An operator with a one-NIC gateway should be
	// told what is missing, not refused outright.
	Required bool

	// Capability is the host capability this requirement is about, when the
	// requirement is not about a specific role.
	Capability host.Capability
}

// Definition is a profile: what it is for and what it therefore needs.
//
// It contains no interface names, no counts and no addresses. Every field is
// either an intent or a statement about what that intent requires.
type Definition struct {
	// Name is the profile identifier used in configuration.
	Name Profile

	// Title is the operator-facing name.
	Title string

	// Description is one sentence an operator can read and recognise.
	Description string

	// Requirements are what must hold on this host.
	Requirements []Requirement

	// Capabilities are the host capabilities this profile makes sense with.
	//
	// This is a statement about the profile, not about the host. Whether the
	// host HAS them is a separate question answered by evaluation.
	Capabilities []host.Capability
}

// gateway is the definition most operators will pick first.
var gateway = Definition{
	Name:  ProfileGateway,
	Title: "Home / office router",
	Description: "Routes between an internet uplink and one or more networks " +
		"behind it, masquerades outbound traffic, and serves DHCP and DNS.",
	Requirements: []Requirement{
		{Role: host.RoleWAN, Required: true, Capability: host.CapRouting},
		{Role: host.RoleLAN, Required: true, Capability: host.CapNAT},
	},
	Capabilities: []host.Capability{
		host.CapRouting, host.CapForwarding, host.CapNAT,
		host.CapDHCP, host.CapDNS, host.CapFirewall,
	},
}

// router is a gateway without the DHCP and DNS server.
var router = Definition{
	Name:  ProfileRouter,
	Title: "Router",
	Description: "Routes and masquerades traffic. Does not serve DHCP or DNS — " +
		"something else on the network already does.",
	Requirements: []Requirement{
		{Role: host.RoleWAN, Required: true, Capability: host.CapRouting},
		{Role: host.RoleLAN, Required: true, Capability: host.CapNAT},
	},
	Capabilities: []host.Capability{
		host.CapRouting, host.CapForwarding, host.CapNAT, host.CapFirewall,
	},
}

// firewall filters and terminates nothing else.
var firewall = Definition{
	Name:  ProfileFirewall,
	Title: "Firewall",
	Description: "Filters traffic between networks. Serves no addresses and " +
		"resolves no names.",
	Requirements: []Requirement{
		{Role: host.RoleWAN, Required: true, Capability: host.CapFirewall},
		{Role: host.RoleLAN, Required: true, Capability: host.CapForwarding},
	},
	Capabilities: []host.Capability{
		host.CapRouting, host.CapForwarding, host.CapNAT, host.CapFirewall, host.CapQoS,
	},
}

// dnsOnly answers queries from one downstream network.
var dnsOnly = Definition{
	Name:  ProfileDNSOnly,
	Title: "DNS server",
	Description: "Answers name queries for one network. Does not route, " +
		"masquerade or hand out addresses.",
	Requirements: []Requirement{
		{Role: host.RoleLAN, Required: true, Capability: host.CapDNS},
	},
	Capabilities: []host.Capability{},
}

// dhcpServer hands out addresses on one downstream network.
var dhcpServer = Definition{
	Name:  ProfileDHCPServer,
	Title: "DHCP server",
	Description: "Hands out addresses on one network. Does not route or " +
		"masquerade traffic.",
	Requirements: []Requirement{
		{Role: host.RoleLAN, Required: true, Capability: host.CapDHCP},
	},
	Capabilities: []host.Capability{
		host.CapDHCP, host.CapDNS,
	},
}

// accessPoint bridges wireless clients onto a downstream network.
var accessPoint = Definition{
	Name:  ProfileAccessPoint,
	Title: "Access point",
	Description: "Bridges wireless clients onto an existing network. " +
		"Requires a wireless adapter and does not route.",
	Requirements: []Requirement{
		{Role: host.RoleLAN, Required: true, Capability: host.CapWirelessAP},
	},
	Capabilities: []host.Capability{
		host.CapWirelessAP, host.CapBridge,
	},
}

// bridge extends an existing segment without routing.
var bridge = Definition{
	Name:  ProfileBridge,
	Title: "Bridge",
	Description: "Extends an existing layer-2 network. Requires two wired " +
		"interfaces on this host and no routing at all.",
	Requirements: []Requirement{
		{Role: host.RoleLAN, Required: true, Capability: host.CapBridge},
	},
	Capabilities: []host.Capability{},
}

// managedDevice asks nothing of the host.
var managedDevice = Definition{
	Name:  ProfileManagedDevice,
	Title: "Managed network device",
	Description: "Runs THN here and reports what this machine can do. " +
		"Assumes no particular topology.",
	Requirements: nil,
	Capabilities: []host.Capability{
		host.CapRouting, host.CapFirewall, host.CapDHCP, host.CapDNS, host.CapQoS,
	},
}

// registry is every profile this build knows.
//
// It is a registry rather than a switch so that adding a profile cannot
// silently change the behaviour of an unrelated one.
var registry = []Definition{
	gateway, router, firewall, dnsOnly, dhcpServer, accessPoint, bridge, managedDevice,
}

// All returns every known profile, in a stable order.
func All() []Profile {
	out := make([]Profile, 0, len(registry))
	for _, d := range registry {
		out = append(out, d.Name)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Lookup returns a profile definition by name.
//
// An unknown name is an error rather than a silent fallback to the gateway.
// Falling back would give an operator asking for a bridge a router's
// requirements, which is the kind of quiet substitution that is discovered
// after it has been applied.
func Lookup(name string) (Definition, error) {
	want := Profile(strings.ToLower(strings.TrimSpace(name)))
	names := make([]string, 0, len(registry))
	for _, d := range registry {
		names = append(names, string(d.Name))
		if d.Name == want {
			return d, nil
		}
	}
	sort.Strings(names)
	return Definition{}, fmt.Errorf("unknown profile %q; known profiles are %s",
		name, strings.Join(names, ", "))
}

// Finding is one structured way a host falls short of a profile.
//
// It is a value with a code, not a sentence, for the same reason
// host.Problem is: the CLI renders one sentence from it, a future UI renders
// a checklist, and an automated check reads the code. Three consumers, one
// set of facts.
type Finding struct {
	// Code is a stable machine-readable reason.
	//
	//	role-unassigned   no interface fills a role the profile needs
	//	capability-absent the host does not have a capability the profile needs
	//	not-inspected     the host could not be observed at all
	Code string `json:"code"`

	// Message is the human sentence.
	Message string `json:"message"`

	// Role is the role involved, when the finding is about one.
	Role host.Role `json:"role,omitempty"`

	// Capability is the capability involved, when the finding is about one.
	Capability host.Capability `json:"capability,omitempty"`

	// Required distinguishes a blocker from a note.
	Required bool `json:"required"`
}

// Report is the outcome of evaluating a profile against a host.
type Report struct {
	// Profile is the profile that was evaluated.
	Profile Profile `json:"profile"`

	// Satisfied reports whether every required requirement holds.
	Satisfied bool `json:"satisfied"`

	// Findings are every shortfall, required and optional alike.
	//
	// Optional ones are included because an operator deciding between a
	// bridge and a router needs to see what else the machine could do.
	Findings []Finding `json:"findings,omitempty"`
}

// Blocked lists only the required shortfalls.
func (r Report) Blocked() []Finding {
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Required {
			out = append(out, f)
		}
	}
	return out
}

// Suggestions lists only the optional shortfalls.
func (r Report) Suggestions() []Finding {
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if !f.Required {
			out = append(out, f)
		}
	}
	return out
}

// Evaluate checks a profile against an observed host and a role resolution.
//
// It reports; it never decides and never applies. The distinction is why the
// caller must pass BOTH the device and the resolution: the device says what
// hardware exists, and the resolution says what the operator already asked it
// to do. Evaluating a profile against hardware alone would report the same
// missing uplink twice — once because it is absent, and once because nobody
// assigned it.
func Evaluate(d *host.Device, res host.Resolution, p Definition) Report {
	rep := Report{Profile: p.Name, Satisfied: true}

	if d == nil || !d.Supported {
		rep.Satisfied = false
		rep.Findings = append(rep.Findings, Finding{
			Code:     "not-inspected",
			Required: true,
			Message: fmt.Sprintf(
				"this host could not be inspected, so it is unknown whether the %s profile can run here",
				p.Name),
		})
		return rep
	}

	for _, req := range p.Requirements {
		if req.Role != host.RoleUnassigned && req.Role != "" {
			if _, filled := res.Assigned[req.Role]; !filled {
				rep.Findings = append(rep.Findings, Finding{
					Code:     "role-unassigned",
					Role:     req.Role,
					Required: req.Required,
					Message: fmt.Sprintf(
						"the %s profile needs an interface in role %s; observed interfaces are %s",
						p.Name, req.Role, strings.Join(d.SystemNames(), ", ")),
				})
				if req.Required {
					rep.Satisfied = false
				}
			}
		}

		if req.Capability != "" {
			if st, known := d.Capabilities[req.Capability]; !known || !st.Available {
				reason := "it was not determined"
				if known {
					reason = st.Reason
				}
				rep.Findings = append(rep.Findings, Finding{
					Code:       "capability-absent",
					Capability: req.Capability,
					Required:   req.Required,
					Message: fmt.Sprintf(
						"the %s profile needs %s, which this host does not have (%s)",
						p.Name, req.Capability, reason),
				})
				if req.Required {
					rep.Satisfied = false
				}
			}
		}
	}

	// Deterministic order, so two runs produce the same report and an operator
	// can diff them.
	sort.Slice(rep.Findings, func(i, j int) bool {
		if rep.Findings[i].Required != rep.Findings[j].Required {
			return rep.Findings[i].Required
		}
		if rep.Findings[i].Role != rep.Findings[j].Role {
			return rep.Findings[i].Role < rep.Findings[j].Role
		}
		return rep.Findings[i].Code < rep.Findings[j].Code
	})

	return rep
}
