package cli

// Rendering and JSON encoding for M7.1 hardware intelligence.
//
// # What this file is for, and what it must never become
//
// The analyzer lives in internal/host and produces data. This file turns that
// data into two shapes: something an operator reads, and something a program
// consumes. Neither shape contains an opinion the analyzer did not already
// hold.
//
// That constraint is worth stating because the tempting thing to do here is to
// make the output more confident. A sentence like "eth0 is your WAN" is easier
// to render than "eth0 is a strong WAN candidate on observed evidence: carrier
// present, 1000 Mbps, default route uses this interface". The first is wrong —
// the operator picks the WAN — and the wrongness is invisible to anyone who
// did not already know the difference.
//
// # The three headings an operator needs
//
// Current    what the host is doing with this link right now
// Suitable   what this link could reasonably be used for, and why
// Limits     what stands in the way
//
// "Current" is separate from "Suitable" on purpose, and so is the absence of an
// "Assigned" heading. See OBSERVED → SUITABLE → ASSIGNED → ACTIVATED in
// internal/host/hardware.go: this command covers the first arrow and refuses,
// in its output shape, to imply the second.

import (
	"fmt"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

// RenderHardwareAnalysis renders the M7.1 report for a human.
//
// It renders the analysis only. The caller decides where it sits relative to
// the observation, because that ordering is a presentation choice about the
// command rather than a property of the analysis.
func RenderHardwareAnalysis(intel host.HardwareIntelligence) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("Hardware suitability\n")
	w("─────────────────────\n")

	if !intel.Supported {
		w("  the host could not be inspected, so no interface was assessed\n")
		for _, n := range intel.Notes {
			w("  %s\n", n)
		}
		return b.String()
	}

	w("  %d physical port(s): %d Ethernet, %d wireless\n",
		intel.PhysicalPorts, intel.PhysicalEthernet, intel.PhysicalWireless)
	switch {
	case intel.DefaultRouteCount == 0:
		w("  default routes: none observed\n")
	case intel.DefaultRouteCount == 1:
		w("  default routes: 1 via %s\n", strings.Join(intel.DefaultRouteInterfaces, ", "))
	default:
		// Reported as a fact. A host with a wired and a wireless uplink is an
		// ordinary laptop, and calling it broken would teach the operator to
		// distrust the rest of the report.
		w("  default routes: %d paths via %s (an observation, not a fault)\n",
			intel.DefaultRouteCount, strings.Join(intel.DefaultRouteInterfaces, ", "))
	}
	if len(intel.Infrastructure) > 0 {
		w("  virtual infrastructure: %s (recorded, not modified)\n",
			strings.Join(intel.Infrastructure, ", "))
	}

	for _, in := range intel.Interfaces {
		w("\n  %s  [%s]\n", in.SystemName, in.Class.Describe())
		w("      current:  %s", in.Usage.State.Describe())
		if in.Usage.Master != "" {
			w(", enslaved to %s", in.Usage.Master)
		}
		if in.Usage.DefaultRoute {
			w(", carries the default route")
		}
		if in.Usage.Addressed {
			w(", addressed")
		}
		w("\n")
		w("      link:    %s\n", hardwareSpeedLabel(in))

		// The observed facts are printed ONCE, under the interface, rather
		// than repeated under each role. They are the same facts — printing
		// them three times made a report long enough that nobody read it to
		// the end, which is the outcome the report exists to prevent.
		//
		// Each role then shows only what differs: the classification, the
		// confidence, and the caveats that are specific to it.
		for _, e := range sharedEvidence(in) {
			w("         + %s\n", e)
		}

		for _, role := range host.IntelligenceRoles() {
			s := in.SuitabilityFor(role)
			w("      %-6s %-16s %s\n", strings.ToUpper(string(role)),
				s.Suitability.Describe(), s.Confidence)
			for _, e := range roleOnlyEvidence(in, role, s) {
				w("         + %s\n", e)
			}
			for _, l := range s.Limitations {
				w("         ! %s\n", l)
			}
			for _, blocker := range s.Blockers {
				w("         x %s\n", blocker)
			}
		}
	}

	w("\n  Gateway profiles\n")
	w("  ────────────────\n")
	for _, p := range intel.Profiles {
		w("\n  %s\n    %s\n", p.Title, p.Verdict)
		for _, e := range p.Evidence {
			w("    + %s\n", e.Detail)
		}
		for _, role := range host.IntelligenceRoles() {
			if name, ok := p.Candidates[role]; ok {
				w("    %-6s candidate: %s\n", strings.ToUpper(string(role)), name)
			}
		}
		for _, c := range p.Constraints {
			w("    ! %s\n", c)
		}
	}

	if len(intel.Notes) > 0 {
		w("\n  Notes\n")
		w("  ─────\n")
		for _, n := range intel.Notes {
			w("  %s\n", n)
		}
	}

	w("\n  Suitability is not assignment: no role was given to any interface.\n")
	return b.String()
}

// sharedEvidence is the evidence every role for an interface agrees on.
//
// Deduplicated rather than taken from the first role, because an interface
// with no wireless mode report has the same wireless evidence for all three
// roles and printing it three times would imply three observations of the
// same fact.
func sharedEvidence(in host.InterfaceIntelligence) []string {
	var out []string
	for _, role := range host.IntelligenceRoles() {
		for _, e := range in.SuitabilityFor(role).Evidence {
			out = append(out, e.Detail)
		}
		return out
	}
	return out
}

// roleOnlyEvidence returns the evidence a role has that the others do not.
//
// On today's model that is the wireless-mode fact and the uplink-shape fact,
// both of which are only meaningful in the context of one particular question.
func roleOnlyEvidence(in host.InterfaceIntelligence, role host.Role, s host.RoleSuitability) []string {
	shared := map[string]bool{}
	for _, d := range sharedEvidence(in) {
		shared[d] = true
	}

	var out []string
	for _, e := range s.Evidence {
		if !shared[e.Detail] {
			out = append(out, e.Detail)
		}
	}
	return out
}

// hardwareSpeedLabel renders an interface's speed, or says it is unknown.
//
// "unknown" is a first-class answer here. Printing "0 Mbps" would read as a
// measurement, and an operator seeing that would conclude the link is broken
// rather than that nobody reported its speed.
func hardwareSpeedLabel(in host.InterfaceIntelligence) string {
	if !in.SpeedKnown {
		return "speed unknown (the host reported none); this is not a measurement of zero"
	}
	return fmt.Sprintf("%d Mbps", in.SpeedMbps)
}

// hardwareJSON encodes the analysis for a machine consumer.
//
// Structured rather than prose. Every field a consumer needs to reason about
// is a value: a classification, a confidence, a list of evidence codes. The
// only human strings are the explanations attached to those values, and a
// consumer is never required to read them to make a decision.
func hardwareJSON(intel host.HardwareIntelligence) map[string]any {
	out := map[string]any{
		"supported":            intel.Supported,
		"physical_ports":       intel.PhysicalPorts,
		"physical_ethernet":    intel.PhysicalEthernet,
		"physical_wireless":    intel.PhysicalWireless,
		"default_route_count":  intel.DefaultRouteCount,
		"default_route_ifaces": intel.DefaultRouteInterfaces,
		"infrastructure":       intel.Infrastructure,
		"notes":                intel.Notes,
		// Every unknown with its cause. An automation consumer hits the same
		// wall a human does — "why is this unknown?" — and the answer has to
		// be a field rather than a prose note somebody has to parse.
		"unknowns": unknownsJSON(intel),
		// The three that matter most to a consumer, reported as fields
		// rather than only as prose: this analysis assigns nothing, changes
		// nothing, and is not a readiness verdict.
		"assignment_made":      intel.AssignmentMade,
		"network_untouched":    true,
		"is_readiness_verdict": false,
		"statement": "Suitability only. No role was assigned, no configuration was " +
			"changed, and this is not a readiness verdict.",
	}

	ifaces := make([]map[string]any, 0, len(intel.Interfaces))
	for _, in := range intel.Interfaces {
		m := map[string]any{
			"id":          in.ID,
			"id_kind":     string(in.IDKind),
			"system_name": in.SystemName,
			"kind":        in.Kind,
			"physical":    in.Physical,
			"class":       string(in.Class),
			// speed_known is reported alongside the speed so a consumer never
			// has to infer "absent means unknown" — the same rule the rest of
			// the model follows for capability and readiness.
			"speed_known": in.SpeedKnown,
			"current":     currentJSON(in.Usage),
			"suitability": suitabilityJSON(in),
		}
		if in.SpeedKnown {
			m["speed_mbps"] = in.SpeedMbps
		}
		ifaces = append(ifaces, m)
	}
	out["interfaces"] = ifaces
	out["profiles"] = profilesJSON(intel)
	return out
}

// currentJSON encodes what the host is doing with an interface.
func currentJSON(u host.CurrentUsage) map[string]any {
	m := map[string]any{
		"carrier":       u.Carrier,
		"admin_up":      u.AdminUp,
		"addressed":     u.Addressed,
		"ipv4":          u.IPv4,
		"ipv6":          u.IPv6,
		"default_route": u.DefaultRoute,
		"route_count":   u.RouteCount,
		"state":         string(u.State),
		"assigned_role": string(u.AssignedRole),
	}
	if u.Master != "" {
		m["master"] = u.Master
	}
	return m
}

// suitabilityJSON encodes the per-role judgements.
func suitabilityJSON(in host.InterfaceIntelligence) map[string]any {
	out := make(map[string]any, len(host.IntelligenceRoles()))
	for _, role := range host.IntelligenceRoles() {
		s := in.SuitabilityFor(role)
		out[string(role)] = map[string]any{
			"classification": string(s.Suitability),
			"confidence":     string(s.Confidence),
			"candidate":      s.Candidate(),
			"evidence":       evidenceJSON(s.Evidence),
			"blockers":       s.Blockers,
			"limitations":    s.Limitations,
		}
	}
	return out
}

// evidenceJSON encodes evidence as codes plus details.
func evidenceJSON(in []host.Evidence) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, e := range in {
		out = append(out, map[string]any{
			"code":       e.Code,
			"detail":     e.Detail,
			"confidence": string(e.Confidence),
		})
	}
	return out
}

// unknownsJSON encodes every unexplained unknown, with the probe that caused
// it.
//
// Emitted even when empty, as `[]` rather than being omitted. A consumer
// asking "does this host have unknowns THN cannot explain?" must be able to
// distinguish "none" from "this build does not report them", and an absent
// field cannot carry that distinction.
func unknownsJSON(intel host.HardwareIntelligence) []map[string]any {
	out := make([]map[string]any, 0, len(intel.Unknowns))
	for _, u := range intel.Unknowns {
		out = append(out, map[string]any{
			"subject":  u.Subject,
			"question": u.Question,
			"detail":   u.Detail,
			"probe":    probeJSON(u.Probe),
		})
	}
	return out
}

// probeJSON encodes one probe as a flat record.
func probeJSON(p network.Probe) map[string]any {
	m := map[string]any{
		"subsystem": p.Subsystem,
		"operation": p.Operation,
		"stage":     string(p.Stage),
		"outcome":   string(p.Outcome),
		"detail":    p.Detail,
	}
	if p.Reason != "" {
		m["reason"] = p.Reason
	}
	if p.Tool != "" {
		m["tool"] = p.Tool
	}
	if len(p.Args) > 0 {
		m["args"] = p.Args
	}
	if p.Path != "" {
		m["path"] = p.Path
	}
	if p.Count > 0 {
		m["count"] = p.Count
	}
	if p.ExitStatus != 0 {
		m["exit_status"] = p.ExitStatus
	}
	return m
}

// profilesJSON encodes the gateway profiles.
func profilesJSON(intel host.HardwareIntelligence) []map[string]any {
	out := make([]map[string]any, 0, len(intel.Profiles))
	for _, p := range intel.Profiles {
		candidates := map[string]string{}
		for role, name := range p.Candidates {
			candidates[string(role)] = name
		}
		m := map[string]any{
			"id":          string(p.ID),
			"title":       p.Title,
			"verdict":     string(p.Verdict),
			"possible":    p.Possible(),
			"evidence":    evidenceJSON(p.Evidence),
			"constraints": p.Constraints,
		}
		// Named `candidates`, never `roles` or `assignment`. The key name is
		// part of the contract with a consumer reading it, and a consumer who
		// sees a key called "roles" will reasonably assume THN decided
		// something.
		if len(candidates) > 0 {
			m["candidates"] = candidates
		}
		out = append(out, m)
	}
	return out
}
