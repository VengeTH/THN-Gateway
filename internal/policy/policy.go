// Package policy holds named settings that can be selected per subject and per
// time.
//
// # Why this is a layer and not four more policies
//
// THN already has a bandwidth policy, a DNS policy and a firewall policy. They
// are host-global: one shaped rate, one resolver, one ruleset, applying to
// everything on the LAN.
//
// That is sufficient for a single household using the internet the same way at
// three in the morning as at eight, and insufficient the moment it is not. A
// guest network needs a lower ceiling. A child's console needs a different
// one. A device that has been compromised needs a different one again, and the
// owner needs that to change at eleven at night without editing a config file
// on a machine they cannot reach.
//
// So this package adds the two things the existing policies lack: *profiles*
// and *selection*.
//
// # Profiles, not replacements
//
// A BandwidthProfile carries a qos.Bandwidth, not a copy of the fields in one.
// A DNSProfile carries upstreams in the shape dns.Policy uses. Reuse rather
// than a parallel model is the same rule the gateway gate exists to enforce
// across the rest of the codebase: two models of one concept is how a gateway
// ends up configuring two different things and reporting both.
//
// The host-global policy remains the default, and a profile is an override. A
// device with no profile gets exactly what it got before this layer existed.
//
// # Selection is reported, never silent
//
// A device's effective settings are the result of matching several bindings
// against a clock. That is four places to get it wrong, and the wrong answer
// looks entirely normal: a guest quietly getting the full link, or a limit
// applying to the whole house because one device matched.
//
// So every resolution carries a reason per profile, and a binding that loses a
// contest says so rather than vanishing. `thn policy resolve` prints them.
// An operator who cannot see why a limit applied cannot predict their own
// configuration, and a configuration they cannot predict is one they will
// stop trusting.
package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/dhcp"
	"github.com/venth/thn-gateway/internal/identity"
	"github.com/venth/thn-gateway/internal/qos"
	"github.com/venth/thn-gateway/internal/schedule"
)

// Kind names a class of policy. It is what a binding refers to, so that one
// document can hold profiles of all four kinds and selection can be asked for
// any of them.
type Kind string

const (
	// KindDevice is a device's own settings: which other profiles it uses.
	KindDevice Kind = "device"

	// KindBandwidth is a shaped rate.
	KindBandwidth Kind = "bandwidth"

	// KindDNS is a resolver configuration.
	KindDNS Kind = "dns"

	// KindFirewall is per-device access control.
	KindFirewall Kind = "firewall"
)

// AllKinds is the set of policy classes, in a stable order.
var AllKinds = []Kind{KindDevice, KindBandwidth, KindDNS, KindFirewall}

// Valid reports whether the kind is one of the defined values.
func (k Kind) Valid() bool {
	for _, known := range AllKinds {
		if k == known {
			return true
		}
	}
	return false
}

// String renders the kind.
func (k Kind) String() string { return string(k) }

// Subject is what a policy applies to.
//
// A subject is identified rather than a pointer, because a policy document is
// written before any device has been seen. A device is matched by its hardware
// address, which identity.Registry owns; nothing here reaches into the registry
// to decide what a profile means.
type Subject struct {
	// Kind is what sort of thing this is.
	//
	// Only a device is addressable by this layer. A host-wide setting belongs
	// in the existing policy packages, and duplicating it here would create
	// two places to set the same thing.
	Kind string `json:"kind" yaml:"kind"`

	// MAC is the subject's hardware address, for a device subject.
	MAC string `json:"mac,omitempty" yaml:"mac,omitempty"`

	// DeviceID is the subject's stable identifier, when the subject is known by
	// identity rather than by address.
	//
	// Both are accepted and either may be empty, because an operator who has
	// only read a lease file has a MAC and no device ID, and an operator who
	// has a registry has both. Requiring the identifier would exclude the
	// common case.
	DeviceID string `json:"device_id,omitempty" yaml:"device_id,omitempty"`

	// Hostname matches a subject by name, as a last resort.
	//
	// It is deliberately the weakest form. A hostname is a claim a device
	// makes about itself, and two devices can make it. It exists because a
	// guest network is often described that way and refusing to match would
	// leave an operator with a policy that silently does nothing.
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
}

// SubjectKind values.
const (
	SubjectDevice = "device"
	SubjectHost   = "host"
)

// NewDeviceSubject builds a subject matching a hardware address.
func NewDeviceSubject(mac string) Subject {
	return Subject{Kind: SubjectDevice, MAC: dhcp.NormalisedMAC(mac)}
}

// String renders the subject.
func (s Subject) String() string {
	switch {
	case s.MAC != "":
		return s.MAC
	case s.DeviceID != "":
		return s.DeviceID
	case s.Hostname != "":
		return s.Hostname
	default:
		return "(any device)"
	}
}

// specificity ranks how precisely a subject names its target.
//
// It exists because two bindings can match the same device, and the tie has to
// be broken by something the operator can see. A hardware address names one
// device; a hostname may name several; an empty subject names all of them.
func (s Subject) specificity() int {
	switch {
	case s.MAC != "":
		return 3
	case s.DeviceID != "":
		return 2
	case s.Hostname != "":
		return 1
	default:
		return 0
	}
}

// matches reports whether a device is this subject.
func (s Subject) matches(d identity.Device) bool {
	switch {
	case s.MAC != "":
		return d.MAC == s.MAC
	case s.DeviceID != "":
		return d.ID == s.DeviceID
	case s.Hostname != "":
		for _, h := range d.Hostnames {
			if strings.EqualFold(h, s.Hostname) {
				return true
			}
		}
		return false
	default:
		// A subject naming nothing matches every device. It is how a
		// house-wide default is expressed, and it is the lowest specificity so
		// any specific binding overrides it.
		return true
	}
}

// BandwidthProfile is a shaped rate a device or the whole LAN can use.
type BandwidthProfile struct {
	// Name identifies the profile.
	Name string `json:"name" yaml:"name"`

	// Rate is the shaped rate, reused from the qos package rather than
	// re-stated.
	Rate qos.Bandwidth `json:"rate" yaml:"rate"`

	// Limits are the scheduler parameters.
	Limits qos.Limits `json:"limits" yaml:"limits"`

	// Shaped reports whether this profile shapes at all.
	//
	// A profile with no rate is the house default, and saying so explicitly is
	// better than a rate of zero: zero would be a claim that the link is
	// infinitely slow, and an unconfigured profile is not a claim at all.
	Shaped bool `json:"shaped,omitempty" yaml:"shaped,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty" yaml:"comments,omitempty"`
}

// String renders the profile.
func (p BandwidthProfile) String() string {
	if !p.Shaped {
		return fmt.Sprintf("%s: unconstrained", p.Name)
	}
	return fmt.Sprintf("%s: %d/%d kbit/s (overhead %d%%)",
		p.Name, p.Rate.DownloadKbps, p.Rate.UploadKbps, p.Rate.OverheadPercent)
}

// DNSProfile is a resolver configuration for a device or a group of devices.
type DNSProfile struct {
	// Name identifies the profile.
	Name string `json:"name" yaml:"name"`

	// Upstreams are the resolvers to forward to.
	//
	// Empty means "the host default", which is the global resolver list. It
	// does not mean "no forwarding": a profile that overrode the resolver list
	// with an empty one would leave the device with no name resolution at all,
	// which is a different and much more alarming configuration.
	Upstreams []netip.Addr `json:"upstreams,omitempty" yaml:"upstreams,omitempty"`

	// Blocked are hostname patterns this subject may not resolve.
	//
	// A block here is a statement that the operator has decided this device
	// should not reach a category of name. It is enforced by refusing to
	// forward, not by returning a wrong answer, because returning a wrong
	// answer would make a blocked name look broken rather than refused.
	Blocked []string `json:"blocked,omitempty" yaml:"blocked,omitempty"`

	// LogQueries forces query logging for this subject on, regardless of the
	// global setting. It is per-subject because the reason to log a child's
	// console is different from the reason to log a guest's phone.
	LogQueries *bool `json:"log_queries,omitempty" yaml:"log_queries,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty" yaml:"comments,omitempty"`
}

// String renders the profile.
func (p DNSProfile) String() string {
	var b strings.Builder
	b.WriteString(p.Name + ": ")

	if len(p.Upstreams) == 0 {
		b.WriteString("host default resolvers")
	} else {
		parts := make([]string, 0, len(p.Upstreams))
		for _, u := range p.Upstreams {
			parts = append(parts, u.String())
		}
		b.WriteString("via " + strings.Join(parts, ", "))
	}

	if len(p.Blocked) > 0 {
		b.WriteString(fmt.Sprintf(", blocking %d name(s)", len(p.Blocked)))
	}
	if p.LogQueries != nil && *p.LogQueries {
		b.WriteString(", logging queries")
	}
	return b.String()
}

// FirewallAction is what a firewall profile permits or denies.
type FirewallAction string

const (
	// Allow permits traffic that would otherwise be denied.
	Allow FirewallAction = "allow"

	// Deny drops it.
	Deny FirewallAction = "deny"
)

// AccessRule is one per-device access decision.
type AccessRule struct {
	// Action is allow or deny.
	Action FirewallAction `json:"action" yaml:"action"`

	// To is the destination network this rule covers. Empty means anywhere.
	To netip.Prefix `json:"to,omitempty" yaml:"to,omitempty"`

	// Ports is the destination port set, as "80", "443", "8000-8100".
	//
	// It is a string rather than a parsed range because the set syntax is
	// dnsmasq-like and an operator writes it that way. Parsing happens at
	// render time, and a rule that cannot be parsed is reported rather than
	// silently matching nothing.
	Ports string `json:"ports,omitempty" yaml:"ports,omitempty"`

	// Protocol is tcp, udp, icmp, or empty for any.
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`

	// Comment explains the rule, and is carried into rendered output.
	Comment string `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// String renders the rule.
func (r AccessRule) String() string {
	var b strings.Builder
	b.WriteString(string(r.Action))
	if r.Protocol != "" {
		b.WriteString(" " + r.Protocol)
	}
	if r.Ports != "" {
		b.WriteString(" to port " + r.Ports)
	}
	if r.To.IsValid() {
		b.WriteString(" from " + r.To.String())
	}
	return b.String()
}

// FirewallProfile is per-device access control, layered on the host ruleset.
//
// It is an additional layer and not a replacement. The host firewall decides
// what the gateway itself permits; this decides what one device is permitted
// to reach. A rule here cannot widen the host policy — that is a property the
// resolver enforces, and it is the property worth enforcing, because a
// per-device "allow" that could out-vote the host drop policy would be a way
// for a compromised device to make itself reachable.
type FirewallProfile struct {
	// Name identifies the profile.
	Name string `json:"name" yaml:"name"`

	// Default is what to do with traffic no rule covers: allow or deny.
	//
	// Deny is the more useful default and is stated explicitly rather than
	// implied by an empty rule list, because "an empty profile" is ambiguous
	// between "allow everything" and "deny everything" and the two are
	// opposites.
	Default FirewallAction `json:"default" yaml:"default"`

	// Rules are evaluated in order; the first match decides.
	Rules []AccessRule `json:"rules,omitempty" yaml:"rules,omitempty"`

	// Isolate cuts the device off from the gateway and from the other devices
	// on the LAN.
	//
	// It is a single flag rather than a set of rules because it is the
	// setting people reach for, and expressing it as rules would let an
	// operator write a rule that accidentally undoes it.
	Isolate bool `json:"isolate,omitempty" yaml:"isolate,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty" yaml:"comments,omitempty"`
}

// String renders the profile.
func (p FirewallProfile) String() string {
	out := fmt.Sprintf("%s: default %s", p.Name, p.Default)
	if p.Isolate {
		out += ", isolated"
	}
	if len(p.Rules) > 0 {
		out += fmt.Sprintf(", %d rule(s)", len(p.Rules))
	}
	return out
}

// DeviceProfile is a device's own settings.
type DeviceProfile struct {
	// Name identifies the profile.
	Name string `json:"name" yaml:"name"`

	// Bandwidth names the bandwidth profile this device uses.
	Bandwidth string `json:"bandwidth,omitempty" yaml:"bandwidth,omitempty"`

	// DNS names the DNS profile this device uses.
	DNS string `json:"dns,omitempty" yaml:"dns,omitempty"`

	// Firewall names the firewall profile this device uses.
	Firewall string `json:"firewall,omitempty" yaml:"firewall,omitempty"`

	// Pool names the DHCP range this device is served from.
	//
	// It is a dhcp.Range, reused rather than restated, so that a device
	// profile cannot serve an address from outside a configured pool.
	Pool *dhcp.Range `json:"pool,omitempty" yaml:"pool,omitempty"`

	// FixedAddress pins an address regardless of the pool, for a device whose
	// address other things are configured against.
	FixedAddress *netip.Addr `json:"fixed_address,omitempty" yaml:"fixed_address,omitempty"`

	// ExpectStrongIdentity requires this device to be identified by hardware
	// address alone.
	//
	// It exists for the "tell me if something unidentified appears" case. A
	// device matching the profile is expected, and a device that is not
	// strongly identified while claiming to be is worth reporting.
	ExpectStrongIdentity bool `json:"expect_strong_identity,omitempty" yaml:"expect_strong_identity,omitempty"`

	// Tags are free-form labels, for grouping subjects that share settings
	// without a shared profile.
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty" yaml:"comments,omitempty"`
}

// String renders the profile.
func (p DeviceProfile) String() string {
	var parts []string
	for _, ref := range []struct {
		kind Kind
		name string
	}{
		{KindBandwidth, p.Bandwidth},
		{KindDNS, p.DNS},
		{KindFirewall, p.Firewall},
	} {
		if ref.name != "" {
			parts = append(parts, fmt.Sprintf("%s=%s", ref.kind, ref.name))
		}
	}
	if len(parts) == 0 {
		return p.Name + ": no overrides"
	}
	return p.Name + ": " + strings.Join(parts, ", ")
}

// Binding attaches a profile to a subject, optionally for part of the day.
type Binding struct {
	// Kind is the class of profile being bound.
	Kind Kind `json:"kind" yaml:"kind"`

	// Subject is what it applies to.
	Subject Subject `json:"subject" yaml:"subject"`

	// Profile is the profile's name.
	Profile string `json:"profile" yaml:"profile"`

	// Schedule names the schedule gating this binding. Empty means always.
	Schedule string `json:"schedule,omitempty" yaml:"schedule,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty" yaml:"comments,omitempty"`
}

// String renders the binding.
func (b Binding) String() string {
	when := b.Schedule
	if when == "" {
		when = "always"
	}
	return fmt.Sprintf("%s -> %s %s (%s)", b.Kind, b.Profile, b.Subject, when)
}

// Set is a complete policy document.
type Set struct {
	// Bandwidth holds the bandwidth profiles, keyed by name.
	Bandwidth map[string]BandwidthProfile `json:"bandwidth,omitempty" yaml:"bandwidth,omitempty"`

	// DNS holds the DNS profiles, keyed by name.
	DNS map[string]DNSProfile `json:"dns,omitempty" yaml:"dns,omitempty"`

	// Firewall holds the firewall profiles, keyed by name.
	Firewall map[string]FirewallProfile `json:"firewall,omitempty" yaml:"firewall,omitempty"`

	// Devices holds the device profiles, keyed by name.
	Devices map[string]DeviceProfile `json:"devices,omitempty" yaml:"devices,omitempty"`

	// Bindings attach profiles to subjects.
	Bindings []Binding `json:"bindings,omitempty" yaml:"bindings,omitempty"`

	// Schedules gate the bindings that name them.
	Schedules map[string]schedule.Schedule `json:"schedules,omitempty" yaml:"schedules,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty" yaml:"comments,omitempty"`
}

// Reason is why a profile was or was not selected.
type Reason struct {
	// Binding is the binding in question.
	Binding Binding `json:"binding"`

	// Selected reports whether this binding won.
	Selected bool `json:"selected"`

	// Explanation says why, in a sentence an operator can act on.
	Explanation string `json:"explanation"`

	// Schedule is the schedule that gated the binding, when one did.
	Schedule *schedule.Schedule `json:"schedule,omitempty"`

	// ScheduleResult is what that schedule concluded.
	ScheduleResult *schedule.Result `json:"schedule_result,omitempty"`
}

// Resolution is the effective configuration for one subject at one moment.
type Resolution struct {
	// Subject is who this is for.
	Subject Subject `json:"subject"`

	// At is the moment it was resolved.
	At time.Time `json:"at"`

	// Device is the device's own profile, when one matched.
	Device *DeviceProfile `json:"device,omitempty"`

	// Bandwidth is the effective shaped rate, when one was bound.
	Bandwidth *BandwidthProfile `json:"bandwidth,omitempty"`

	// DNS is the effective resolver configuration, when one was bound.
	DNS *DNSProfile `json:"dns,omitempty"`

	// Firewall is the effective access policy, when one was bound.
	Firewall *FirewallProfile `json:"firewall,omitempty"`

	// Reasons explains every binding that was considered, including the ones
	// that lost.
	Reasons []Reason `json:"reasons,omitempty"`

	// Unresolved names profiles a binding referred to but the set does not
	// contain.
	//
	// It is reported rather than treated as an error at resolution time,
	// because a partially-loaded configuration should still resolve for the
	// subjects it can, and an operator debugging it needs the list.
	Unresolved []string `json:"unresolved,omitempty"`
}

// summary renders the resolution for display.
func (r Resolution) summary() string {
	var parts []string
	if r.Device != nil {
		parts = append(parts, "device="+r.Device.Name)
	}
	if r.Bandwidth != nil {
		parts = append(parts, "bandwidth="+r.Bandwidth.String())
	}
	if r.DNS != nil {
		parts = append(parts, "dns="+r.DNS.String())
	}
	if r.Firewall != nil {
		parts = append(parts, "firewall="+r.Firewall.String())
	}
	if len(parts) == 0 {
		return "no policies apply; the host defaults are in force"
	}
	return strings.Join(parts, "\n  ")
}

// String renders the resolution.
func (r Resolution) String() string {
	return fmt.Sprintf("%s at %s:\n  %s", r.Subject, r.At.Format(time.RFC3339), r.summary())
}

// profile looks a profile up by kind and name.
func (s Set) profile(kind Kind, name string) (string, bool) {
	switch kind {
	case KindBandwidth:
		p, ok := s.Bandwidth[name]
		if !ok {
			return "", false
		}
		return p.Name, true
	case KindDNS:
		p, ok := s.DNS[name]
		if !ok {
			return "", false
		}
		return p.Name, true
	case KindFirewall:
		p, ok := s.Firewall[name]
		if !ok {
			return "", false
		}
		return p.Name, true
	case KindDevice:
		p, ok := s.Devices[name]
		if !ok {
			return "", false
		}
		return p.Name, true
	}
	return "", false
}

// candidate is a binding that matched, with its ranking.
type candidate struct {
	binding Binding

	// priority is the gate schedule's priority; zero for an ungated binding.
	priority int

	// specificity is how precisely the subject names its target.
	specificity int

	// order is the binding's position in the document, so that declaration
	// order can be used as the last tie-break.
	order int

	// schedule and result are set only when a schedule gated the binding.
	schedule *schedule.Schedule
	result   *schedule.Result
}

// winExplanation says why the winner won, and how contested it was.
func winExplanation(win candidate, total int) string {
	base := fmt.Sprintf("selected: the only binding that matched")

	if total > 1 {
		base = fmt.Sprintf("selected: it outranks %d other matching binding(s)", total-1)
	}

	if win.binding.Schedule == "" {
		return base + ", and no schedule gates it"
	}
	return base + "; its schedule is active: " + win.result.Reason
}

// loseExplanation says why a binding lost.
func loseExplanation(winner, loser Binding) string {
	if winner.Subject.specificity() != loser.Subject.specificity() {
		return fmt.Sprintf(
			"matches, but lost to %q: its subject %q is less specific than %q",
			winner.Profile, loser.Subject, winner.Subject)
	}
	return fmt.Sprintf(
		"matches, but lost to %q: equal specificity, and the later declaration wins. "+
			"Reorder or raise a schedule priority to change this", winner.Profile)
}

// resolveKind selects one profile of a kind for a subject.
func (s Set) resolveKind(kind Kind, subject Subject, dev *identity.Device, at time.Time, out *Resolution) {
	var candidates []candidate
	var considered []Reason

	for _, b := range s.Bindings {
		if b.Kind != kind {
			continue
		}
		if !b.SubjectMatches(dev, subject) {
			continue
		}

		// A binding naming no profile cannot apply, and is reported rather
		// than skipped, because it is a line in a document that does nothing.
		if b.Profile == "" {
			considered = append(considered, Reason{
				Binding: b,
				Explanation: "the binding names no profile; it has no effect and is " +
					"reported so a line that does nothing is visible",
			})
			continue
		}

		// Gate on the schedule, if any.
		if b.Schedule != "" {
			sch, ok := s.Schedules[b.Schedule]
			if !ok {
				considered = append(considered, Reason{
					Binding: b,
					Explanation: fmt.Sprintf(
						"the binding names schedule %q, which is not defined; the binding "+
							"is treated as not applying rather than as always applying",
						b.Schedule),
				})
				continue
			}

			result := sch.Active(at)
			r := Reason{Binding: b, Schedule: &sch, ScheduleResult: &result}
			if !result.Active {
				r.Explanation = "scheduled out: " + result.Reason
				considered = append(considered, r)
				continue
			}

			// Carry the schedule's own verdict on the candidate so the
			// selection block can quote it in the winner's reason, rather
			// than the reader having to correlate two separate entries.
			candidates = append(candidates, candidate{
				binding: b, priority: sch.Priority, specificity: b.Subject.specificity(),
				order: len(candidates), schedule: &sch, result: &result,
			})
			continue
		}

		candidates = append(candidates, candidate{
			binding: b, specificity: b.Subject.specificity(), order: len(candidates),
		})
		// No reason is recorded here for a candidate. Every candidate is
		// either selected or loses to one, and the selection block below
		// says which and why. Recording a generic "it matches" for all of
		// them, and then a second reason for the losers, would leave the
		// winner's entry saying nothing about the decision.
	}

	if len(candidates) == 0 {
		out.Reasons = append(out.Reasons, considered...)
		return
	}

	// Rank: a higher schedule priority wins, then a more specific subject, then
	// the LATER declaration.
	//
	// Later-wins is the last resort and is the convention operators expect from
	// an access list and from an override block: you add a line at the bottom to
	// change one above. Taking the first match instead would mean a binding
	// added at the end of a file quietly does nothing, while `thn policy
	// resolve` explained that the later declaration wins — the tool lying about
	// its own rule.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority > candidates[j].priority
		}
		if candidates[i].specificity != candidates[j].specificity {
			return candidates[i].specificity > candidates[j].specificity
		}
		return candidates[i].order > candidates[j].order
	})

	winner := candidates[0]

	// Say what was decided, and what was passed over. Losing silently is how a
	// policy quietly stops applying and nobody notices until the traffic they
	// expected to be limited is not.
	considered = append(considered, Reason{
		Binding:        winner.binding,
		Selected:       true,
		Schedule:       winner.schedule,
		ScheduleResult: winner.result,
		Explanation:    winExplanation(winner, len(candidates)),
	})

	for _, c := range candidates[1:] {
		considered = append(considered, Reason{
			Binding:     c.binding,
			Schedule:    c.schedule,
			Explanation: loseExplanation(winner.binding, c.binding),
		})
	}

	if _, ok := s.profile(kind, winner.binding.Profile); !ok {
		out.Unresolved = append(out.Unresolved, fmt.Sprintf(
			"%s: binding names profile %q, which the set does not contain",
			kind, winner.binding.Profile))
		out.Reasons = append(out.Reasons, considered...)
		return
	}

	switch kind {
	case KindBandwidth:
		p := s.Bandwidth[winner.binding.Profile]
		out.Bandwidth = &p
	case KindDNS:
		p := s.DNS[winner.binding.Profile]
		out.DNS = &p
	case KindFirewall:
		p := s.Firewall[winner.binding.Profile]
		out.Firewall = &p
	case KindDevice:
		p := s.Devices[winner.binding.Profile]
		out.Device = &p
	}

	out.Reasons = append(out.Reasons, considered...)
}

// Normalise fills in the names a map key would otherwise carry.
//
// It exists because Go does not populate a struct field from a map key on
// unmarshal. An operator writes:
//
//	guest:
//	  shaped: true
//
// and the profile comes back with an empty Name. That is not a cosmetic
// problem: bindings refer to profiles by name, so two profiles both called ""
// are indistinguishable, `thn policy list` prints two nameless lines, and a
// resolution reports an empty profile name to whoever has to debug it.
//
// It is idempotent, and a name that is already set is left alone, so calling
// it on a hand-built set does not overwrite a deliberate name.
func (s Set) Normalise() {
	for key, p := range s.Bandwidth {
		if p.Name == "" {
			p.Name = key
		}
		s.Bandwidth[key] = p
	}
	for key, p := range s.DNS {
		if p.Name == "" {
			p.Name = key
		}
		s.DNS[key] = p
	}
	for key, p := range s.Firewall {
		if p.Name == "" {
			p.Name = key
		}
		s.Firewall[key] = p
	}
	for key, p := range s.Devices {
		if p.Name == "" {
			p.Name = key
		}
		s.Devices[key] = p
	}
	for key, sch := range s.Schedules {
		if sch.Name == "" {
			sch.Name = key
		}
		s.Schedules[key] = sch
	}
}

// Resolve computes the effective policies for a subject at a moment.
//
// dev may be nil for a subject that has not been seen. That is not a
// degenerate case: it is the one an operator has before anything connects, and
// a policy document that cannot be checked against a not-yet-seen device is a
// policy document nobody can validate before deploying it.
func (s Set) Resolve(subject Subject, dev *identity.Device, at time.Time) Resolution {
	if at.IsZero() {
		at = time.Now().UTC()
	}

	// Names come from map keys on a loaded document and are absent on a
	// hand-built one. Normalising here rather than at the call sites means a
	// resolution can never be produced with an unnamed profile, however the set
	// was built.
	s.Normalise()

	out := Resolution{Subject: subject, At: at}

	// The device profile is resolved first, because it is what names the other
	// three and their names are needed as a fallback below.
	s.resolveKind(KindDevice, subject, dev, at, &out)

	// Then each remaining kind from its own bindings. A binding is a direct
	// statement about a subject, so it is consulted before the device profile's
	// indirect reference: an explicit "this device uses unfiltered" has to beat
	// a profile the device happens to use, or the operator cannot express the
	// first without editing the second.
	s.resolveKind(KindBandwidth, subject, dev, at, &out)
	s.resolveKind(KindDNS, subject, dev, at, &out)
	s.resolveKind(KindFirewall, subject, dev, at, &out)

	// Finally, whatever no binding claimed comes from the device profile.
	if out.Device != nil {
		if out.Bandwidth == nil && out.Device.Bandwidth != "" {
			if p, ok := s.Bandwidth[out.Device.Bandwidth]; ok {
				out.Bandwidth = &p
			} else {
				out.Unresolved = append(out.Unresolved, fmt.Sprintf(
					"device profile %q names bandwidth profile %q, which the set does not contain",
					out.Device.Name, out.Device.Bandwidth))
			}
		}
		if out.DNS == nil && out.Device.DNS != "" {
			if p, ok := s.DNS[out.Device.DNS]; ok {
				out.DNS = &p
			} else {
				out.Unresolved = append(out.Unresolved, fmt.Sprintf(
					"device profile %q names DNS profile %q, which the set does not contain",
					out.Device.Name, out.Device.DNS))
			}
		}
		if out.Firewall == nil && out.Device.Firewall != "" {
			if p, ok := s.Firewall[out.Device.Firewall]; ok {
				out.Firewall = &p
			} else {
				out.Unresolved = append(out.Unresolved, fmt.Sprintf(
					"device profile %q names firewall profile %q, which the set does not contain",
					out.Device.Name, out.Device.Firewall))
			}
		}
	}

	sort.Strings(out.Unresolved)

	return out
}

// SubjectMatches reports whether a binding's subject covers a device.
//
// The explicit subject argument lets a caller resolve for a device it has a
// name for but no registry entry, which is how a policy document is checked
// before anything has connected.
func (b Binding) SubjectMatches(dev *identity.Device, fallback Subject) bool {
	if dev == nil {
		// With no device, an exact match on the fallback is the only thing that
		// can be established. A catch-all binding still matches, because it
		// names no device to contradict.
		if b.Subject.MAC == "" && b.Subject.DeviceID == "" && b.Subject.Hostname == "" {
			return true
		}
		return b.Subject.MAC == fallback.MAC && b.Subject.DeviceID == ""
	}
	return b.Subject.matches(*dev)
}
