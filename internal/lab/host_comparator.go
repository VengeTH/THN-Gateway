package lab

// Disposable lab host-state safety comparator (M6.2 hardening).
//
// Invariant:
//   If THN accidentally mutates the host networking state outside the
//   disposable lab boundary, the comparator must detect it.
//
// Meaningful mutations detected:
//   - Added host routes
//   - Removed host routes
//   - Destination/prefix changes
//   - Next-hop gateway changes
//   - Outgoing device changes
//   - Routing table changes
//   - Scope or route type changes
//   - Default route modifications
//   - Lab namespace routes (10.77.0.0/24, 10.77.250.0/24) leaking into host
//
// Legitimate dynamic metadata canonicalized/ignored:
//   - Protocol annotations (kernel, boot, dhcp, ra, systemd, tailscale):
//     network daemons frequently refresh lease/protocol tags without altering routing topology.
//   - Route metrics: dynamic link quality or DHCP lease metric adjustments do not alter the route path.
//   - Cache and transient flags (e.g. cloned, expires, rt_cache):
//     internal kernel routing cache state, not topology changes.
//   - Route output ordering: netlink dump order is nondeterministic across reads.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// HostRoute represents an observed route entry.
type HostRoute struct {
	Destination string   `json:"dst"`
	Gateway     string   `json:"gateway,omitempty"`
	Device      string   `json:"dev,omitempty"`
	Table       string   `json:"table,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	Type        string   `json:"type,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Metric      int      `json:"metric,omitempty"`
	Flags       []string `json:"flags,omitempty"`
}

// SemanticRouteKey defines the invariant routing path identity.
type SemanticRouteKey struct {
	Destination string
	Gateway     string
	Device      string
	Table       string
	Scope       string
	Type        string
}

// CanonicalRouteKey extracts the semantic routing identity from a HostRoute,
// normalizing destination syntax, table aliases, and type defaults while ignoring
// harmless dynamic metadata (metrics, protocol, cache flags).
func CanonicalRouteKey(r HostRoute) SemanticRouteKey {
	dst := strings.TrimSpace(r.Destination)
	if dst == "" || dst == "default" {
		dst = "default"
	} else if prefix, err := netip.ParsePrefix(dst); err == nil {
		dst = prefix.Masked().String()
	} else if addr, err := netip.ParseAddr(dst); err == nil {
		if addr.Is4() {
			dst = addr.String() + "/32"
		} else {
			dst = addr.String() + "/128"
		}
	}

	gw := strings.TrimSpace(r.Gateway)
	if addr, err := netip.ParseAddr(gw); err == nil {
		gw = addr.String()
	}

	table := strings.TrimSpace(strings.ToLower(r.Table))
	if table == "" || table == "254" || table == "main" {
		table = "main"
	}

	routeType := strings.TrimSpace(strings.ToLower(r.Type))
	if routeType == "" || routeType == "unicast" {
		routeType = "unicast"
	}

	scope := strings.TrimSpace(strings.ToLower(r.Scope))
	if scope == "" {
		if gw != "" {
			scope = "global"
		} else {
			scope = "link"
		}
	}

	return SemanticRouteKey{
		Destination: dst,
		Gateway:     gw,
		Device:      strings.TrimSpace(r.Device),
		Table:       table,
		Scope:       scope,
		Type:        routeType,
	}
}

func (k SemanticRouteKey) String() string {
	parts := []string{"dst " + k.Destination}
	if k.Gateway != "" {
		parts = append(parts, "via "+k.Gateway)
	}
	if k.Device != "" {
		parts = append(parts, "dev "+k.Device)
	}
	if k.Table != "main" && k.Table != "" {
		parts = append(parts, "table "+k.Table)
	}
	if k.Scope != "" {
		parts = append(parts, "scope "+k.Scope)
	}
	if k.Type != "unicast" && k.Type != "" {
		parts = append(parts, "type "+k.Type)
	}
	return strings.Join(parts, " ")
}

// ParseHostRoutes parses `ip -j route show` output into HostRoute records.
func ParseHostRoutes(raw []byte) ([]HostRoute, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var routes []HostRoute
	if err := json.Unmarshal(raw, &routes); err != nil {
		return nil, fmt.Errorf("parsing ip route json: %w", err)
	}
	return routes, nil
}

// CompareHostRoutes compares baseline routes against post-test current routes.
// It returns (true, nil) if all routes match semantically, ignoring harmless
// dynamic metadata churn (protocol, dynamic metrics, ephemeral flags).
// It returns (false, diffs) if any route is added, removed, or mutated.
func CompareHostRoutes(baseline, current []HostRoute) (bool, []string) {
	baseMap := make(map[SemanticRouteKey]HostRoute, len(baseline))
	currMap := make(map[SemanticRouteKey]HostRoute, len(current))

	for _, r := range baseline {
		baseMap[CanonicalRouteKey(r)] = r
	}
	for _, r := range current {
		currMap[CanonicalRouteKey(r)] = r
	}

	var diffs []string

	// Detect added routes (in current but not baseline)
	for k := range currMap {
		if _, ok := baseMap[k]; !ok {
			// Check if this was a mutation of an existing route with the same destination
			mutated := false
			for bk := range baseMap {
				if bk.Destination == k.Destination && bk.Table == k.Table {
					mutated = true
					if bk.Gateway != k.Gateway {
						diffs = append(diffs, fmt.Sprintf("route %s gateway changed: got %q, want %q", k.Destination, k.Gateway, bk.Gateway))
					}
					if bk.Device != k.Device {
						diffs = append(diffs, fmt.Sprintf("route %s device changed: got %q, want %q", k.Destination, k.Device, bk.Device))
					}
					if bk.Scope != k.Scope {
						diffs = append(diffs, fmt.Sprintf("route %s scope changed: got %q, want %q", k.Destination, k.Scope, bk.Scope))
					}
					if bk.Type != k.Type {
						diffs = append(diffs, fmt.Sprintf("route %s type changed: got %q, want %q", k.Destination, k.Type, bk.Type))
					}
					break
				}
			}
			if !mutated {
				diffs = append(diffs, fmt.Sprintf("added route: %s", k))
			}
		}
	}

	// Detect removed routes (in baseline but not current)
	for k := range baseMap {
		if _, ok := currMap[k]; !ok {
			// If already reported as a mutation under added routes, don't duplicate
			alreadyReported := false
			for ck := range currMap {
				if ck.Destination == k.Destination && ck.Table == k.Table {
					alreadyReported = true
					break
				}
			}
			if !alreadyReported {
				diffs = append(diffs, fmt.Sprintf("removed route: %s", k))
			}
		}
	}

	// Check default route specifically
	var baseDefault, currDefault *SemanticRouteKey
	for k := range baseMap {
		if k.Destination == "default" && k.Table == "main" {
			key := k
			baseDefault = &key
			break
		}
	}
	for k := range currMap {
		if k.Destination == "default" && k.Table == "main" {
			key := k
			currDefault = &key
			break
		}
	}

	if (baseDefault == nil && currDefault != nil) || (baseDefault != nil && currDefault == nil) {
		diffs = append(diffs, fmt.Sprintf("default route presence mismatch: baseline=%v, current=%v", baseDefault != nil, currDefault != nil))
	} else if baseDefault != nil && currDefault != nil && *baseDefault != *currDefault {
		diffs = append(diffs, fmt.Sprintf("default route changed: got (%s), want (%s)", *currDefault, *baseDefault))
	}

	sort.Strings(diffs)
	// Deduplicate identical error strings if any
	deduped := make([]string, 0, len(diffs))
	for i, d := range diffs {
		if i == 0 || d != diffs[i-1] {
			deduped = append(deduped, d)
		}
	}

	return len(deduped) == 0, deduped
}

// VerifyNoLabRoutesInHost ensures that no lab namespace routes (e.g. 10.77.0.0/24
// or 10.77.250.0/24) accidentally appear in the host routing table.
func VerifyNoLabRoutesInHost(routes []HostRoute, labPrefixes ...string) []string {
	if len(labPrefixes) == 0 {
		labPrefixes = []string{LANPrefix, WANPrefix}
	}

	var leaks []string
	for _, r := range routes {
		key := CanonicalRouteKey(r)
		for _, prefix := range labPrefixes {
			if key.Destination == prefix || strings.HasPrefix(key.Destination, strings.TrimSuffix(prefix, "0/24")) {
				leaks = append(leaks, fmt.Sprintf("lab namespace route leaked into host: %s", key))
			}
		}
	}
	sort.Strings(leaks)
	return leaks
}
