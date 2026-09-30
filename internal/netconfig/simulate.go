package netconfig

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Packet is a hypothetical packet offered to the simulation.
type Packet struct {
	// Source is the originating address.
	Source netip.Addr `json:"source"`

	// Destination is the address being sent to.
	Destination netip.Addr `json:"destination"`

	// Protocol is "tcp", "udp", "icmp" or "icmpv6".
	Protocol string `json:"protocol"`

	// SourcePort is set for TCP and UDP.
	SourcePort int `json:"source_port,omitempty"`

	// DestinationPort is set for TCP and UDP.
	DestinationPort int `json:"destination_port,omitempty"`

	// Ingress is the interface the packet arrives on. Empty means the policy
	// decides from the source address alone, which is what a packet from an
	// unidentified segment looks like.
	Ingress string `json:"ingress,omitempty"`

	// Label is an operator-supplied name for the simulation, used in output.
	Label string `json:"label,omitempty"`
}

// Stage names a point in the packet's path.
type Stage string

const (
	// StageIngress is arrival at the host.
	StageIngress Stage = "ingress"
	// StageForwarding is the forward-chain decision.
	StageForwarding Stage = "forwarding"
	// StageRouting is the route lookup.
	StageRouting Stage = "routing"
	// StageNAT is source translation.
	StageNAT Stage = "nat"
	// StageEgress is departure from the host.
	StageEgress Stage = "egress"
)

// Outcome is what a stage decided.
type Outcome string

const (
	// OutcomePass means the packet continues.
	OutcomePass Outcome = "pass"
	// OutcomeDrop means the packet is discarded here.
	OutcomeDrop Outcome = "drop"
	// OutcomeNoMatch means no rule applied, so the stage default applies.
	OutcomeNoMatch Outcome = "no-match"
	// OutcomeUndetermined means the simulation cannot decide, usually because
	// an interface is unidentified.
	OutcomeUndetermined Outcome = "undetermined"
)

// Step is one stage of the packet path.
type Step struct {
	// Stage names the point in the path.
	Stage Stage `json:"stage"`
	// Outcome is what this stage decided.
	Outcome Outcome `json:"outcome"`
	// Rule names the rule that decided, when one did.
	Rule string `json:"rule,omitempty"`
	// Detail explains the decision.
	Detail string `json:"detail"`
}

// Verdict is the overall simulation result.
type Verdict string

const (
	// VerdictForwarded means the packet would be routed and sent on.
	VerdictForwarded Verdict = "forwarded"
	// VerdictAccepted means the packet would be accepted for local delivery.
	VerdictAccepted Verdict = "accepted"
	// VerdictDropped means the packet would be discarded.
	VerdictDropped Verdict = "dropped"
	// VerdictUndetermined means the simulation could not decide.
	VerdictUndetermined Verdict = "undetermined"
)

// Simulation is the result of walking one packet through the policy.
type Simulation struct {
	// Packet is the packet that was simulated.
	Packet Packet `json:"packet"`
	// Steps are the stages in order.
	Steps []Step `json:"steps"`
	// Verdict is the overall outcome.
	Verdict Verdict `json:"verdict"`
	// Summary is a one-line explanation.
	Summary string `json:"summary"`
	// EgressInterface is the interface the packet would leave through.
	EgressInterface string `json:"egress_interface,omitempty"`
	// NextHop is the gateway the packet would be sent to.
	NextHop netip.Addr `json:"next_hop,omitempty"`
	// Translated reports whether the source address would be rewritten.
	Translated bool `json:"translated"`
	// TranslatedSource is the source address after translation.
	TranslatedSource netip.Addr `json:"translated_source,omitempty"`
}

// addStep appends a stage result.
func (s *Simulation) addStep(stage Stage, outcome Outcome, rule, detail string) {
	s.Steps = append(s.Steps, Step{Stage: stage, Outcome: outcome, Rule: rule, Detail: detail})
}

// Simulate walks a packet through the policy and reports what would happen.
//
// The simulation is intentionally conservative: where the policy is
// incomplete it reports undetermined rather than guessing. A simulation that
// confidently says "forwarded" for a policy with no LAN configured would be
// worse than useless, because the operator would act on it.
//
// The stages mirror kernel processing order: ingress, then the forward chain,
// then the route lookup, then NAT, then egress.
func Simulate(p Policy, pkt Packet) Simulation {
	p = p.Clone()
	p.Normalize()

	s := &Simulation{Packet: pkt}

	s.simulateIngress(&p, pkt)

	// Routing is resolved before the forward chain is evaluated, because the
	// forwarding decision depends on the direction of travel: lan-to-wan and
	// wan-to-lan are different rules. A simulation that picked the direction
	// before knowing where the packet was going would report "the  rule",
	// which is exactly the kind of confident nonsense that erodes trust in a
	// tool people rely on remotely.
	routed := s.simulateRouting(&p, pkt)
	if !routed {
		s.finish(VerdictDropped)
		return *s
	}

	if dropped := s.simulateForwarding(&p, pkt); dropped {
		s.finish(VerdictDropped)
		return *s
	}

	s.simulateNAT(&p, pkt)
	s.simulateEgress(&p, pkt)
	s.finish(VerdictForwarded)

	return *s
}

// simulateIngress resolves which role the packet arrived under.
func (s *Simulation) simulateIngress(p *Policy, pkt Packet) {
	// Determine the ingress role. An explicit interface is authoritative; a
	// packet with only a source address is attributed by looking the address
	// up in the policy's own routes.
	role := RoleUnknown
	ingress := pkt.Ingress

	if ingress != "" {
		role = p.Interfaces.RoleOf(ingress)
	} else {
		// Attribute by source: an address inside a LAN-attached network is
		// coming from the LAN.
		for _, route := range p.Routing.Routes {
			if route.Interface == p.Interfaces.LAN && route.Destination.Contains(pkt.Source) {
				role = RoleLAN
				ingress = route.Interface
				break
			}
		}
	}

	s.Packet.Ingress = ingress

	switch role {
	case RoleLAN:
		s.addStep(StageIngress, OutcomePass, "",
			fmt.Sprintf("packet arrives on the LAN interface %s with source %s", ingress, pkt.Source))
	case RoleWAN:
		s.addStep(StageIngress, OutcomePass, "",
			fmt.Sprintf("packet arrives on the WAN interface %s with source %s", ingress, pkt.Source))
	case RoleLoopback:
		s.addStep(StageIngress, OutcomePass, "",
			fmt.Sprintf("packet is locally generated on %s", ingress))
	default:
		s.addStep(StageIngress, OutcomeUndetermined, "",
			fmt.Sprintf("the ingress interface of a packet from %s could not be determined: "+
				"no ingress interface was given and the source address matches no configured network",
				pkt.Source))
	}
}

// simulateForwarding walks the forwarding rules. It reports whether the packet
// was dropped.
func (s *Simulation) simulateForwarding(p *Policy, pkt Packet) bool {
	f := p.Forwarding

	// Packet forwarding must be enabled in the kernel, or none of the rules
	// below matter. This is the check most often missed: enabling the rules
	// without enabling forwarding produces a gateway that carries nothing.
	isV4 := pkt.Source.Is4() || pkt.Source.Is4In6()
	if isV4 && !f.IPv4Enabled {
		s.addStep(StageForwarding, OutcomeDrop, "ipv4-forwarding-disabled",
			"IPv4 forwarding is disabled in the kernel, so every forwarded IPv4 packet is dropped regardless of the rules")
		return true
	}
	if !isV4 && !f.IPv6Enabled {
		s.addStep(StageForwarding, OutcomeDrop, "ipv6-forwarding-disabled",
			"IPv6 forwarding is disabled in the kernel, so every forwarded IPv6 packet is dropped")
		return true
	}

	// The direction of travel, now that routing has resolved the egress.
	ingressRole := s.Packet.Ingress
	role := p.Interfaces.RoleOf(ingressRole)
	egressRole := p.Interfaces.RoleOf(s.EgressInterface)
	direction := directionBetween(role, egressRole)

	if direction == "" {
		s.addStep(StageForwarding, OutcomeUndetermined, "",
			fmt.Sprintf("the path from %s to %s is not a forwarding direction this policy governs",
				orNone(ingressRole), orNone(s.EgressInterface)))
		return false
	}

	// The rule is selected by direction first, then refined by source and
	// destination within that direction.
	//
	// Selecting on source and destination alone would be a serious bug: the
	// lan-to-wan rule would match inbound traffic too, and an operator
	// simulating an attack would be told their drop rule accepts it.
	rule, ok := ruleForDirection(*p, direction, pkt)
	if !ok {
		s.addStep(StageForwarding, OutcomeDrop, "default-drop",
			fmt.Sprintf("no %s rule is defined; the forward chain's default policy drops it",
				direction))
		return true
	}

	if role == RoleLoopback {
		s.addStep(StageForwarding, OutcomePass, "loopback",
			"locally generated traffic is not subject to the forwarding rules")
		return false
	}

	if rule.Action != "accept" {
		s.addStep(StageForwarding, OutcomeDrop, ruleName(direction, rule.Action),
			fmt.Sprintf("the %s rule is %s", direction, rule.Action))
		return true
	}

	s.addStep(StageForwarding, OutcomePass, ruleName(direction, rule.Action),
		fmt.Sprintf("the %s rule accepts this packet%s", direction, restrictionNote(rule)))
	return false
}

// egressGuess determines which interface a packet would leave through,
// without performing the full route lookup. It is used only to select a
// forwarding direction.
func (s *Simulation) egressGuess(p *Policy, pkt Packet) string {
	if m, ok := LookupRoute(*p, pkt.Destination); ok {
		return m.Route.Interface
	}
	return ""
}

// simulateRouting performs the route lookup. It reports whether routing
// succeeded.
func (s *Simulation) simulateRouting(p *Policy, pkt Packet) bool {
	m, ok := LookupRoute(*p, pkt.Destination)
	if !ok {
		s.addStep(StageRouting, OutcomeDrop, "no-route",
			fmt.Sprintf("no route matches %s in the configured table, so the packet has nowhere to go", pkt.Destination))
		return false
	}

	s.EgressInterface = m.Route.Interface
	s.NextHop = m.Route.NextHop

	detail := fmt.Sprintf("%s matches %s", pkt.Destination, m.Route.Destination)
	if m.Route.NextHop.IsValid() {
		detail += fmt.Sprintf(" via %s", m.Route.NextHop)
	}
	if m.Route.Interface != "" {
		detail += fmt.Sprintf(" out %s", m.Route.Interface)
	}
	if m.Route.Source.IsValid() {
		detail += fmt.Sprintf(" (prefsrc %s)", m.Route.Source)
	}
	detail += fmt.Sprintf(" [prefix /%d, metric %d, %s]",
		m.Route.Destination.Bits(), m.Route.Metric, m.Reason)

	s.addStep(StageRouting, OutcomePass, m.Route.Destination.String(), detail)
	return true
}

// simulateNAT applies source translation.
func (s *Simulation) simulateNAT(p *Policy, pkt Packet) {
	n := p.NAT

	if !n.Enabled {
		s.addStep(StageNAT, OutcomePass, "nat-disabled",
			"NAT is disabled; the source address is unchanged")
		return
	}

	// NAT only applies to traffic leaving the host.
	if n.OutInterface != "" && n.OutInterface != s.EgressInterface {
		s.addStep(StageNAT, OutcomeUndetermined, "",
			fmt.Sprintf("NAT is scoped to %s but the packet would leave via %s, so no translation rule matches",
				n.OutInterface, s.EgressInterface))
		return
	}

	// Never translate traffic that is leaving through the LAN: that would
	// rewrite the addresses of clients on the downstream segment and break
	// the LAN entirely.
	if n.OutInterface != "" && n.OutInterface == p.Interfaces.LAN {
		s.addStep(StageNAT, OutcomeDrop, "nat-scoped-to-lan",
			fmt.Sprintf("NAT is scoped to the LAN interface (%s); translating traffic leaving it would break the downstream segment",
				n.OutInterface))
		return
	}

	switch n.Mode {
	case NATMasquerade:
		s.Translated = true
		// Masquerade substitutes the egress interface's address, which is
		// not knowable from the policy alone. TranslatedSource is left unset
		// rather than faked: reporting the original address back as the
		// "translated" one would be worse than reporting nothing, because a
		// reader could reasonably take it as the value the uplink would see.
		s.addStep(StageNAT, OutcomePass, "masquerade",
			fmt.Sprintf("the source address %s would be rewritten to the address assigned to %s; "+
				"that address is not known from the policy because it is assigned to the uplink at activation",
				pkt.Source, orNone(n.OutInterface)))
	case NATSNAT:
		s.Translated = true
		s.TranslatedSource = n.SNATAddress
		s.addStep(StageNAT, OutcomePass, "snat",
			fmt.Sprintf("the source address %s would be rewritten to %s", pkt.Source, n.SNATAddress))
	case NATNone, "":
		s.addStep(StageNAT, OutcomePass, "nat-mode-none",
			"NAT is enabled but the mode translates nothing, so the source address is unchanged")
	default:
		s.addStep(StageNAT, OutcomeUndetermined, "",
			fmt.Sprintf("unknown NAT mode %q", n.Mode))
	}
}

// simulateEgress records the final interface.
func (s *Simulation) simulateEgress(p *Policy, pkt Packet) {
	role := p.Interfaces.RoleOf(s.EgressInterface)

	source := pkt.Source.String()
	if s.Translated && s.TranslatedSource.IsValid() && s.TranslatedSource != pkt.Source {
		source = s.TranslatedSource.String()
	}

	switch role {
	case RoleWAN:
		s.addStep(StageEgress, OutcomePass, "",
			fmt.Sprintf("the packet would leave through %s to %s with source %s",
				s.EgressInterface, orNone(nextHopLabel(s.NextHop)), source))
	case RoleLAN:
		s.addStep(StageEgress, OutcomePass, "",
			fmt.Sprintf("the packet would leave through the LAN interface %s", s.EgressInterface))
	default:
		s.addStep(StageEgress, OutcomeUndetermined, "",
			fmt.Sprintf("the egress interface %q is neither the WAN nor the LAN, so the packet's fate is undetermined",
				orNone(s.EgressInterface)))
	}
}

// finish computes the verdict and summary.
func (s *Simulation) finish(v Verdict) {
	s.Verdict = v

	// The verdict reflects the earliest decisive stage, not the last one to
	// run, so a packet dropped at forwarding is reported as dropped even
	// though routing and NAT are never consulted.
	for _, step := range s.Steps {
		if step.Outcome == OutcomeDrop {
			s.Verdict = VerdictDropped
			s.Summary = fmt.Sprintf("dropped at %s: %s", step.Stage, step.Detail)
			return
		}
	}

	undetermined := false
	for _, step := range s.Steps {
		if step.Outcome == OutcomeUndetermined {
			undetermined = true
		}
	}

	if v == VerdictForwarded && undetermined {
		s.Verdict = VerdictUndetermined
		s.Summary = "would be forwarded, but at least one stage could not be determined from the policy"
		return
	}

	if v == VerdictForwarded {
		s.Summary = fmt.Sprintf("would be forwarded out of %s", orNone(s.EgressInterface))
		return
	}

	s.Summary = "accepted for local delivery"
}

// RouteMatch is the result of a route lookup.
type RouteMatch struct {
	// Route is the matching route.
	Route Route `json:"route"`
	// Reason explains why this route was chosen over the others.
	Reason string `json:"reason"`
}

// LookupRoute performs a longest-prefix match against the policy's routes.
//
// This is the same algorithm the kernel uses: the most specific matching
// prefix wins, and among equally specific prefixes the lowest metric wins. It
// is implemented here rather than assumed, because a simulation that used a
// different rule than the kernel would produce confident and wrong answers.
func LookupRoute(p Policy, dst netip.Addr) (RouteMatch, bool) {
	// Reject an invalid or unspecified destination: there is no route to it.
	if !dst.IsValid() || dst.IsUnspecified() {
		return RouteMatch{}, false
	}

	// Routing disabled means there are no routes at all. Without this a
	// disabled subsystem would still resolve via the default route, and a
	// simulation would report traffic as forwarded by a device that routes
	// nothing.
	if !p.Routing.Enabled {
		return RouteMatch{}, false
	}

	type candidate struct {
		route  Route
		bits   int
		metric int
		isDflt bool
	}

	var candidates []candidate

	for _, r := range p.Routing.Routes {
		// A route in the other address family can never match.
		if !sameFamily(r.Destination.Addr(), dst) {
			continue
		}
		// A route with no egress interface cannot carry traffic.
		if r.Interface == "" {
			continue
		}
		if !r.Destination.Contains(dst) {
			continue
		}
		candidates = append(candidates, candidate{
			route:  r,
			bits:   r.Destination.Bits(),
			metric: r.Metric,
			isDflt: r.Destination.Bits() == 0,
		})
	}

	// The default route. It is modelled whenever an egress interface is
	// known, with or without a gateway address, because an uplink that
	// obtains its address over DHCP supplies the gateway at activation time.
	//
	// Requiring both would be wrong: it would make a DHCP-attached gateway
	// simulate as having no route at all, and every packet would appear
	// unroutable when in fact the uplink provides one.
	if egress := defaultEgress(p); egress != "" {
		if sameFamily(defaultAddr(dst), dst) {
			candidates = append(candidates, candidate{
				route: Route{
					Destination: prefixForFamily(dst),
					NextHop:     p.Routing.DefaultGateway,
					Interface:   egress,
					Metric:      p.Routing.DefaultMetric,
					Protocol:    "dhcp",
					Scope:       "global",
				},
				bits:   0,
				metric: p.Routing.DefaultMetric,
				isDflt: true,
			})
		}
	}

	if len(candidates) == 0 {
		return RouteMatch{}, false
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		// Most specific prefix first.
		if a.bits != b.bits {
			return a.bits > b.bits
		}
		// Then lowest metric.
		if a.metric != b.metric {
			return a.metric < b.metric
		}
		return a.route.Interface < b.route.Interface
	})

	best := candidates[0]
	reason := "most specific matching prefix"

	if best.isDflt {
		reason = "default route"
	} else if len(candidates) > 1 {
		second := candidates[1]
		if second.bits == best.bits && second.metric == best.metric {
			reason = fmt.Sprintf("most specific prefix, tied with %s on the same metric",
				second.route.Destination)
		} else if second.bits == best.bits {
			reason = fmt.Sprintf("most specific prefix, preferred over metric %d on the same prefix",
				second.metric)
		}
	}

	return RouteMatch{Route: best.route, Reason: reason}, true
}

// sameFamily reports whether two addresses belong to the same address family.
func sameFamily(a, b netip.Addr) bool {
	return a.Is4() == b.Is4() && a.Is6() == b.Is6()
}

// defaultEgress returns the interface the default route leaves through.
//
// It falls back to the WAN because that is where a default route goes on a
// gateway. Returning "" means the policy has no default route at all.
func defaultEgress(p Policy) string {
	if p.Routing.DefaultGatewayInterface != "" {
		return p.Routing.DefaultGatewayInterface
	}
	return p.Interfaces.WAN
}

// defaultAddr returns an address of the same family as the given one.
func defaultAddr(addr netip.Addr) netip.Addr {
	if addr.Is4() {
		return netip.AddrFrom4([4]byte{0, 0, 0, 0})
	}
	return netip.IPv6Unspecified()
}

// prefixForFamily returns the default prefix for an address's family.
func prefixForFamily(addr netip.Addr) netip.Prefix {
	if addr.Is4() {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
}

// sameFamilyFamily reports whether an address can host a route for dst.
func sameFamilyFamily(placeholder, dst netip.Addr) bool { return placeholder.IsValid() }

// ruleForDirection selects the rule governing a direction.
//
// Rules are filtered to the direction first, then the most specific
// source/destination match within that direction wins. Without the direction
// filter a lan-to-wan accept would be applied to inbound traffic, which is the
// opposite of what the operator wrote.
func ruleForDirection(p Policy, direction ForwardDirection, pkt Packet) (ForwardRule, bool) {
	var candidates []ForwardRule

	for _, r := range p.Forwarding.Rules {
		if r.Direction != direction {
			continue
		}

		// A rule with no source restriction matches any source.
		if len(r.Source) > 0 && !anyContains(r.Source, pkt.Source) {
			continue
		}
		// A rule with no destination restriction matches any destination.
		if len(r.Destination) > 0 && !anyContains(r.Destination, pkt.Destination) {
			continue
		}

		candidates = append(candidates, r)
	}

	if len(candidates) == 0 {
		return ForwardRule{}, false
	}

	// The most specific match wins: more restrictions means more specific.
	// Ties keep declaration order, which Normalize preserves.
	best := candidates[0]
	bestScore := len(best.Source) + len(best.Destination)

	for _, r := range candidates[1:] {
		score := len(r.Source) + len(r.Destination)
		if score > bestScore {
			best, bestScore = r, score
		}
	}

	return best, true
}

// directionBetween returns the forwarding direction for a path between roles.
func directionBetween(from, to Role) ForwardDirection {
	switch {
	case from == RoleLAN && to == RoleWAN:
		return LANToWAN
	case from == RoleWAN && to == RoleLAN:
		return WANToLAN
	case from == RoleLAN && to == RoleLAN:
		return LANToLAN
	case from == RoleWAN && to == RoleWAN:
		return WANToWAN
	default:
		return ""
	}
}

// ruleName renders a rule identifier for output.
func ruleName(d ForwardDirection, action string) string {
	if d == "" {
		return action
	}
	return string(d) + "/" + action
}

// restrictionNote describes a rule's source or destination restrictions.
func restrictionNote(r ForwardRule) string {
	var parts []string
	if len(r.Source) > 0 {
		parts = append(parts, "source "+PrefixList(r.Source))
	}
	if len(r.Destination) > 0 {
		parts = append(parts, "destination "+PrefixList(r.Destination))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// nextHopLabel renders a next hop for display.
func nextHopLabel(h netip.Addr) string {
	if !h.IsValid() {
		return "the next hop"
	}
	return h.String()
}

// SimulateMany runs several packets and returns their simulations.
func SimulateMany(p Policy, packets []Packet) []Simulation {
	out := make([]Simulation, 0, len(packets))
	for _, pkt := range packets {
		out = append(out, Simulate(p, pkt))
	}
	return out
}
