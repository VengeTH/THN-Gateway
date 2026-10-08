package execution

import (
	"fmt"
	"slices"
	"sort"
	"time"
)

// BackupScope defines the boundaries of state captured for rollback.
type BackupScope struct {
	Interfaces []string `json:"interfaces"`
	Sysctls    []string `json:"sysctls"`
	NFTables   bool     `json:"nftables"`
	Routes     bool     `json:"routes"`
	QDiscs     bool     `json:"qdiscs,omitempty"`
	DNS        bool     `json:"dns,omitempty"`
}

// StateSnapshot captures the network configuration state of managed resources prior to mutation.
//
// # Why QDiscs is a map of structured baselines and not map[string]string
//
// The original field was map[string]string holding an algorithm name, compared
// by equality in MatchesBaseline. Two problems, and the first is the serious
// one:
//
//	THN never populated it.
//
// Both CaptureState implementations omitted qdiscs entirely, so the map was
// always empty, so MatchesBaseline's qdisc loop iterated over nothing and
// passed. A rollback that restored no traffic control reported itself VERIFIED.
// The check was not absent — it was present, empty, and asserting success,
// which is worse than not having it.
//
// So QDiscs is map[string]TcBaseline, where TcBaseline.Captured distinguishes
// "there was nothing there" from "THN did not look". A baseline that was never
// captured now fails the comparison instead of passing it.
type StateSnapshot struct {
	CapturedAt         time.Time             `json:"captured_at"`
	Links              map[string]string     `json:"links"`
	Addresses          map[string][]string   `json:"addresses"`
	DefaultRoute       string                `json:"default_route"`
	Sysctls            map[string]string     `json:"sysctls"`
	NFTablesTHNPresent bool                  `json:"nftables_thn_present"`
	NFTablesTHNContent string                `json:"nftables_thn_content,omitempty"`
	QDiscs             map[string]TcBaseline `json:"qdiscs,omitempty"`
	DNSResolvers       []string              `json:"dns_resolvers,omitempty"`
	// Captures records which subsystems were actually read.
	//
	// A snapshot that did not read a subsystem it was scoped for is not a
	// baseline for it. Without this the absence of a capture is
	// indistinguishable from an absence of state, and both compare equal.
	Captures map[string]bool `json:"captures,omitempty"`
}

// CapturedSubsystem reports whether a subsystem was actually read.
func (s *StateSnapshot) CapturedSubsystem(name string) bool {
	if s == nil || s.Captures == nil {
		return false
	}
	return s.Captures[name]
}

// MarkCaptured records that a subsystem was read.
func (s *StateSnapshot) MarkCaptured(name string) {
	if s == nil {
		return
	}
	if s.Captures == nil {
		s.Captures = make(map[string]bool)
	}
	s.Captures[name] = true
}

// NewStateSnapshot allocates an empty snapshot with initialized maps.
func NewStateSnapshot() *StateSnapshot {
	return &StateSnapshot{
		CapturedAt: time.Now().UTC(),
		Links:      make(map[string]string),
		Addresses:  make(map[string][]string),
		Sysctls:    make(map[string]string),
		QDiscs:     make(map[string]TcBaseline),
		Captures:   make(map[string]bool),
	}
}

// Clone creates a deep copy of a snapshot.
func (s *StateSnapshot) Clone() *StateSnapshot {
	c := &StateSnapshot{
		CapturedAt:         s.CapturedAt,
		Links:              make(map[string]string, len(s.Links)),
		Addresses:          make(map[string][]string, len(s.Addresses)),
		DefaultRoute:       s.DefaultRoute,
		Sysctls:            make(map[string]string, len(s.Sysctls)),
		NFTablesTHNPresent: s.NFTablesTHNPresent,
		NFTablesTHNContent: s.NFTablesTHNContent,
		QDiscs:             make(map[string]TcBaseline, len(s.QDiscs)),
		DNSResolvers:       append([]string(nil), s.DNSResolvers...),
		Captures:           make(map[string]bool, len(s.Captures)),
	}
	for k, v := range s.Links {
		c.Links[k] = v
	}
	for k, v := range s.Addresses {
		c.Addresses[k] = append([]string(nil), v...)
	}
	for k, v := range s.Sysctls {
		c.Sysctls[k] = v
	}
	for k, v := range s.QDiscs {
		// The baseline holds slices, so it is copied rather than aliased. A
		// shallow copy would let a later mutation of the original rewrite
		// the baseline a rollback depends on.
		baseline := v
		baseline.Classes = append([]string(nil), v.Classes...)
		baseline.Filters = append([]string(nil), v.Filters...)
		c.QDiscs[k] = baseline
	}
	for k, v := range s.Captures {
		c.Captures[k] = v
	}
	return c
}

func linkMatches(got, want string) bool {
	if got == want {
		return true
	}
	if (got == "" || got == "down") && (want == "" || want == "down") {
		return true
	}
	return false
}

func sysctlMatches(got, want string) bool {
	if got == want {
		return true
	}
	if (got == "" || got == "0" || got == "disabled") && (want == "" || want == "0" || want == "disabled") {
		return true
	}
	return false
}

// MatchesBaseline compares current observed state against this baseline snapshot.
// Returns true if all managed resources match baseline within scope.
func (s *StateSnapshot) MatchesBaseline(current *StateSnapshot) (bool, []string) {
	var diffs []string

	// Compare links
	allLinks := make(map[string]bool)
	for iface := range s.Links {
		allLinks[iface] = true
	}
	for iface := range current.Links {
		allLinks[iface] = true
	}
	for iface := range allLinks {
		wantLink := s.Links[iface]
		gotLink := current.Links[iface]
		if !linkMatches(gotLink, wantLink) {
			diffs = append(diffs, fmt.Sprintf("interface %s link state mismatch: got %q, want baseline %q", iface, gotLink, wantLink))
		}
	}

	// Compare addresses
	allAddrs := make(map[string]bool)
	for iface := range s.Addresses {
		allAddrs[iface] = true
	}
	for iface := range current.Addresses {
		allAddrs[iface] = true
	}
	for iface := range allAddrs {
		gotAddrs := append([]string(nil), current.Addresses[iface]...)
		wantCopy := append([]string(nil), s.Addresses[iface]...)
		sort.Strings(gotAddrs)
		sort.Strings(wantCopy)
		if !slices.Equal(gotAddrs, wantCopy) {
			diffs = append(diffs, fmt.Sprintf("interface %s addresses mismatch: got %v, want baseline %v", iface, gotAddrs, wantCopy))
		}
	}

	// Compare default route
	if s.DefaultRoute != current.DefaultRoute {
		diffs = append(diffs, fmt.Sprintf("default route mismatch: got %q, want baseline %q", current.DefaultRoute, s.DefaultRoute))
	}

	// Compare sysctls
	allSysctls := make(map[string]bool)
	for k := range s.Sysctls {
		allSysctls[k] = true
	}
	for k := range current.Sysctls {
		allSysctls[k] = true
	}
	for k := range allSysctls {
		wantVal := s.Sysctls[k]
		gotVal := current.Sysctls[k]
		if !sysctlMatches(gotVal, wantVal) {
			diffs = append(diffs, fmt.Sprintf("sysctl %s mismatch: got %q, want baseline %q", k, gotVal, wantVal))
		}
	}

	// Compare nftables THN table presence
	if s.NFTablesTHNPresent != current.NFTablesTHNPresent {
		diffs = append(diffs, fmt.Sprintf("nftables table inet thn presence mismatch: got %t, want baseline %t", current.NFTablesTHNPresent, s.NFTablesTHNPresent))
	}

	// Compare qdiscs
	//
	// This loop previously iterated over an always-empty map, because no
	// CaptureState populated it, and reported success every time. A rollback
	// that had removed a qdisc and restored nothing was certified as
	// verified.
	//
	// The three cases are distinguished deliberately:
	//
	//	baseline captured, kind matches     -> restored
	//	baseline captured, kind differs     -> not restored; report it
	//	baseline never captured              -> NOT VERIFIED; report that
	//
	// The third is the one that matters most. An uncaptured baseline cannot
	// be compared, and treating "I do not know what was there" as "it is the
	// same" is how a rollback certifies a host nobody can reconstruct.
	for iface, baseline := range s.QDiscs {
		current, ok := current.QDiscs[iface]

		if !baseline.Captured {
			diffs = append(diffs, fmt.Sprintf(
				"interface %s: traffic control was never captured before the transaction, "+
					"so its restoration cannot be verified", iface))
			continue
		}
		if !ok || !current.Captured {
			diffs = append(diffs, fmt.Sprintf(
				"interface %s: traffic control could not be read after rollback", iface))
			continue
		}
		if !baseline.Empty() {
			if baseline.Root != current.Root {
				diffs = append(diffs, fmt.Sprintf(
					"interface %s root qdisc mismatch: got %q, want baseline %q",
					iface, current.Root, baseline.Root))
			}
			if !slices.Equal(current.Classes, baseline.Classes) {
				diffs = append(diffs, fmt.Sprintf(
					"interface %s class mismatch: got %d class(es), want baseline %d",
					iface, len(current.Classes), len(baseline.Classes)))
			}
			if !slices.Equal(current.Filters, baseline.Filters) {
				diffs = append(diffs, fmt.Sprintf(
					"interface %s filter mismatch: got %d filter(s), want baseline %d",
					iface, len(current.Filters), len(baseline.Filters)))
			}
			continue
		}
		// The baseline was the kernel default, so restoration means the
		// interface must now be carrying no explicit root discipline.
		if !current.Empty() {
			diffs = append(diffs, fmt.Sprintf(
				"interface %s: rollback left %q in place; the baseline had no root qdisc",
				iface, current.Root))
		}
	}

	// Compare DNS resolvers
	if len(s.DNSResolvers) > 0 || len(current.DNSResolvers) > 0 {
		wantDNS := append([]string(nil), s.DNSResolvers...)
		gotDNS := append([]string(nil), current.DNSResolvers...)
		sort.Strings(wantDNS)
		sort.Strings(gotDNS)
		if !slices.Equal(gotDNS, wantDNS) {
			diffs = append(diffs, fmt.Sprintf("DNS resolvers mismatch: got %v, want baseline %v", gotDNS, wantDNS))
		}
	}

	return len(diffs) == 0, diffs
}
