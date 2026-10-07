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
type StateSnapshot struct {
	CapturedAt         time.Time           `json:"captured_at"`
	Links              map[string]string   `json:"links"`
	Addresses          map[string][]string `json:"addresses"`
	DefaultRoute       string              `json:"default_route"`
	Sysctls            map[string]string   `json:"sysctls"`
	NFTablesTHNPresent bool                `json:"nftables_thn_present"`
	NFTablesTHNContent string              `json:"nftables_thn_content,omitempty"`
	QDiscs             map[string]string   `json:"qdiscs,omitempty"`
	DNSResolvers       []string            `json:"dns_resolvers,omitempty"`
}

// NewStateSnapshot allocates an empty snapshot with initialized maps.
func NewStateSnapshot() *StateSnapshot {
	return &StateSnapshot{
		CapturedAt: time.Now().UTC(),
		Links:      make(map[string]string),
		Addresses:  make(map[string][]string),
		Sysctls:    make(map[string]string),
		QDiscs:     make(map[string]string),
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
		QDiscs:             make(map[string]string, len(s.QDiscs)),
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
		c.QDiscs[k] = v
	}
	if s.DNSResolvers != nil {
		c.DNSResolvers = append([]string(nil), s.DNSResolvers...)
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
	for iface, wantQDisc := range s.QDiscs {
		gotQDisc := current.QDiscs[iface]
		if gotQDisc != wantQDisc {
			diffs = append(diffs, fmt.Sprintf("interface %s qdisc mismatch: got %q, want baseline %q", iface, gotQDisc, wantQDisc))
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
