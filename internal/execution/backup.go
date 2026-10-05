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
}

// NewStateSnapshot allocates an empty snapshot with initialized maps.
func NewStateSnapshot() *StateSnapshot {
	return &StateSnapshot{
		CapturedAt: time.Now().UTC(),
		Links:      make(map[string]string),
		Addresses:  make(map[string][]string),
		Sysctls:    make(map[string]string),
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
	return c
}

// MatchesBaseline compares current observed state against this baseline snapshot.
// Returns true if all managed resources match baseline within scope.
func (s *StateSnapshot) MatchesBaseline(current *StateSnapshot) (bool, []string) {
	var diffs []string

	// Compare links
	for iface, wantLink := range s.Links {
		gotLink := current.Links[iface]
		if gotLink != wantLink {
			diffs = append(diffs, fmt.Sprintf("interface %s link state mismatch: got %q, want baseline %q", iface, gotLink, wantLink))
		}
	}

	// Compare addresses
	for iface, wantAddrs := range s.Addresses {
		gotAddrs := append([]string(nil), current.Addresses[iface]...)
		wantCopy := append([]string(nil), wantAddrs...)
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
	for k, wantVal := range s.Sysctls {
		gotVal := current.Sysctls[k]
		if gotVal != wantVal {
			diffs = append(diffs, fmt.Sprintf("sysctl %s mismatch: got %q, want baseline %q", k, gotVal, wantVal))
		}
	}

	// Compare nftables THN table presence
	if s.NFTablesTHNPresent != current.NFTablesTHNPresent {
		diffs = append(diffs, fmt.Sprintf("nftables table inet thn presence mismatch: got %t, want baseline %t", current.NFTablesTHNPresent, s.NFTablesTHNPresent))
	}

	return len(diffs) == 0, diffs
}
