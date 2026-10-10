package schema

import (
	"fmt"
	"sort"
	"strings"
)

// Version is the configuration schema version this build understands.
const Version = 1

// MinimumVersion is the oldest schema version this build can still read.
const MinimumVersion = 1

// Type classifies a configuration value.
type Type string

const (
	// TypeString is a text value.
	TypeString Type = "string"
	// TypeInt is an integer value.
	TypeInt Type = "int"
	// TypeBool is a boolean value.
	TypeBool Type = "bool"
	// TypeCIDR is a network prefix in CIDR notation.
	TypeCIDR Type = "cidr"
	// TypeIP is a single IP address.
	TypeIP Type = "ip"
	// TypeInterface is a network interface name.
	TypeInterface Type = "interface"
	// TypePath is a filesystem path.
	TypePath Type = "path"
	// TypeDuration is a duration string such as "30s".
	TypeDuration Type = "duration"
	// TypeEnum is a value drawn from a fixed set.
	TypeEnum Type = "enum"
	// TypeList is a list of strings.
	TypeList Type = "list"
)

// Field describes one configuration key.
type Field struct {
	// Key is the dotted path, e.g. "network.lan_prefix".
	Key string `json:"key"`
	// Type is the value's type.
	Type Type `json:"type"`
	// Description explains what the field controls.
	Description string `json:"description"`
	// Default is the value used when the field is absent.
	Default string `json:"default,omitempty"`
	// Enum lists permitted values for TypeEnum.
	Enum []string `json:"enum,omitempty"`
	// Required marks a field with no safe default.
	Required bool `json:"required,omitempty"`
	// Mutating marks a field that changes host networking. This drives the
	// `thn plan` summary and the diff's risk classification.
	Mutating bool `json:"mutating,omitempty"`
}

// fields is the authoritative catalogue of configuration keys.
//
// It is declared here rather than derived from the Go struct so that the
// documentation, the validator and any future editor completion all read from
// one list. Adding a struct field without adding it here is caught by
// TestCatalogueCoversConfigStruct.
var fields = []Field{
	{Key: "schema_version", Type: TypeInt, Description: "Configuration schema version", Default: "1"},

	{Key: "gateway.name", Type: TypeString, Description: "Logical gateway name", Default: "thn-gateway", Required: true},
	{Key: "gateway.generation", Type: TypeInt, Description: "Configuration generation counter", Default: "1", Required: true},
	{Key: "gateway.enabled", Type: TypeBool, Description: "This machine is intended to act as a gateway. Hardware that looks like a gateway is evidence, not intent; THN never sets this from an observation", Default: "true", Required: true},

	{Key: "routing.ipv4_forwarding", Type: TypeBool, Description: "Route IPv4 between the WAN and LAN. This is desired state, distinct from the forwarding the kernel currently has", Default: "true", Mutating: true},
	{Key: "routing.ipv6_forwarding", Type: TypeBool, Description: "Route IPv6 between the WAN and LAN", Default: "true", Mutating: true},

	{Key: "network.wan", Type: TypeInterface, Description: "Uplink: a stable interface ID or a kernel interface name (see `thn discover`)", Required: true, Mutating: true},
	{Key: "network.lan", Type: TypeInterface, Description: "Downstream: a stable interface ID or a kernel interface name (see `thn discover`)", Mutating: true},
	{Key: "network.management", Type: TypeInterface, Description: "Administrative interface (dedicated management port)", Mutating: true},
	{Key: "network.lan_prefix", Type: TypeCIDR, Description: "Address to place on the LAN interface", Default: "10.77.0.1/24", Mutating: true},
	{Key: "network.management_prefix", Type: TypeCIDR, Description: "Address to place on the management interface", Mutating: true},
	{Key: "network.dns", Type: TypeList, Description: "Resolvers to configure", Default: "1.1.1.1,9.9.9.9"},
	{Key: "network.mtu", Type: TypeInt, Description: "MTU for gateway interfaces", Default: "1500", Mutating: true},
	{Key: "network.upstream_gateway", Type: TypeIP, Description: "Next hop for the default route", Mutating: true},

	{Key: "nat.enabled", Type: TypeBool, Description: "Masquerade traffic from the LAN", Default: "true", Mutating: true},
	{Key: "nat.interfaces", Type: TypeList, Description: "Interfaces to masquerade from", Mutating: true},
	{Key: "nat.masquerade.enabled", Type: TypeBool, Description: "Source-NAT outbound traffic", Default: "true", Mutating: true},
	{Key: "nat.masquerade.outbound", Type: TypeInterface, Description: "Interface masqueraded traffic leaves by — the logical role `wan`, or a kernel interface name. Required when masquerading is enabled: leaving it empty rewrites traffic leaving every interface, including the LAN", Mutating: true},

	{Key: "firewall.enabled", Type: TypeBool, Description: "Filter unsolicited inbound traffic", Default: "true", Mutating: true},
	{Key: "firewall.backend", Type: TypeEnum, Enum: []string{"nftables"}, Description: "Firewall implementation", Default: "nftables"},
	{Key: "firewall.default_inbound_policy", Type: TypeEnum, Enum: []string{"accept", "drop"}, Description: "Base policy for unmatched traffic", Default: "drop"},
	{Key: "firewall.admin_sources", Type: TypeList, Description: "Networks permitted to administer the gateway; empty means any source", Mutating: true},

	{Key: "qos.enabled", Type: TypeBool, Description: "Shape outbound traffic", Default: "false", Mutating: true},
	{Key: "qos.algorithm", Type: TypeEnum, Enum: []string{"cake", "fq_codel"}, Description: "Shaping algorithm; only cake can enforce a rate", Default: "cake"},
	{Key: "qos.interface", Type: TypeInterface, Description: "Device to shape; must face the bottleneck link", Mutating: true},
	{Key: "qos.download_kbps", Type: TypeInt, Description: "Provisioned download rate in kbps, not the negotiated link speed", Mutating: true},
	{Key: "qos.upload_kbps", Type: TypeInt, Description: "Provisioned upload rate in kbps", Mutating: true},
	{Key: "qos.overhead_percent", Type: TypeInt, Description: "Framing overhead compensation; 0 takes the 10% default", Default: "0", Mutating: true},

	{Key: "dhcp.enabled", Type: TypeBool, Description: "Serve addresses on the LAN", Default: "true", Mutating: true},
	{Key: "dhcp.authoritative", Type: TypeBool, Description: "Declare authority for the LAN", Default: "true", Mutating: true},
	{Key: "dhcp.lease_time", Type: TypeDuration, Description: "Default lease duration", Default: "12h0m0s", Mutating: true},
	{Key: "dhcp.lease_max", Type: TypeInt, Description: "Cap on concurrent leases", Default: "0", Mutating: true},
	{Key: "dhcp.domain", Type: TypeString, Description: "Local domain advertised via option 15", Default: "lan"},
	{Key: "dhcp.ranges", Type: TypeList, Description: "Address pools to hand out", Default: "10.77.0.100-10.77.0.250", Mutating: true},
	{Key: "dhcp.ranges[].start", Type: TypeIP, Description: "First address in a pool", Mutating: true},
	{Key: "dhcp.ranges[].end", Type: TypeIP, Description: "Last address in a pool, inclusive", Mutating: true},
	{Key: "dhcp.ranges[].netmask", Type: TypeIP, Description: "Netmask override for a pool", Mutating: true},
	{Key: "dhcp.reservations", Type: TypeList, Description: "Addresses pinned to devices", Mutating: true},
	{Key: "dhcp.reservations[].mac", Type: TypeString, Description: "Hardware address to match", Mutating: true},
	{Key: "dhcp.reservations[].address", Type: TypeIP, Description: "Address to hand out; empty means any", Mutating: true},
	{Key: "dhcp.reservations[].hostname", Type: TypeString, Description: "Name reported to the client", Mutating: true},
	{Key: "dhcp.reservations[].lease_time", Type: TypeDuration, Description: "Per-device lease override", Mutating: true},

	{Key: "dns.enabled", Type: TypeBool, Description: "Serve DNS on the LAN", Default: "true", Mutating: true},
	{Key: "dns.upstream", Type: TypeList, Description: "Resolvers queries are forwarded to", Default: "1.1.1.1,9.9.9.9", Mutating: true},
	{Key: "dns.local_domain", Type: TypeString, Description: "Domain served for local names", Default: "lan", Mutating: true},
	{Key: "dns.local_records", Type: TypeList, Description: "Additional names THN serves", Mutating: true},
	{Key: "dns.cache_size", Type: TypeInt, Description: "Answers cached", Default: "1000", Mutating: true},
	{Key: "dns.log_queries", Type: TypeBool, Description: "Record every query", Default: "false"},
	{Key: "dns.no_ipv6", Type: TypeBool, Description: "Answer AAAA queries with no answer", Default: "false", Mutating: true},

	{Key: "services.dnsmasq.config_file", Type: TypePath, Description: "Generated dnsmasq configuration", Default: "/etc/thn/dnsmasq.conf", Mutating: true},
	{Key: "services.dnsmasq.lease_file", Type: TypePath, Description: "Lease file dnsmasq writes and THN reads", Default: "/var/lib/thn/dnsmasq.leases"},

	{Key: "paths.config", Type: TypePath, Description: "Path to this file", Default: "/etc/thn/config.yaml"},
	{Key: "paths.state_dir", Type: TypePath, Description: "Directory holding the state database", Default: "/var/lib/thn"},
	{Key: "paths.state_db", Type: TypePath, Description: "Path to the state database", Default: "/var/lib/thn/state.db"},
	{Key: "paths.socket", Type: TypePath, Description: "Unix socket thnd listens on", Default: "/run/thn/thnd.sock"},
	{Key: "paths.run_dir", Type: TypePath, Description: "Directory for runtime files", Default: "/run/thn"},
	{Key: "paths.log_file", Type: TypePath, Description: "Log file; empty means stdout/journal"},

	{Key: "logging.level", Type: TypeEnum, Enum: []string{"debug", "info", "warn", "error"}, Description: "Minimum log level", Default: "info"},
	{Key: "logging.format", Type: TypeEnum, Enum: []string{"json", "text"}, Description: "Log encoding", Default: "json"},
	{Key: "logging.retention", Type: TypeDuration, Description: "How long events are retained", Default: "336h0m0s"},
	{Key: "logging.max_events", Type: TypeInt, Description: "Cap on retained events", Default: "50000"},

	{Key: "activation.auto_recover", Type: TypeBool, Description: "Attempt recovery automatically on failure", Default: "false"},
	{Key: "activation.health_check_interval", Type: TypeDuration, Description: "Health evaluation interval once activation exists", Default: "30s"},
	{Key: "activation.require_physical_presence", Type: TypeBool, Description: "Demand operator confirmation before activation", Default: "true", Required: true},
}

// lookup indexes the catalogue by key.
var lookup = func() map[string]Field {
	m := make(map[string]Field, len(fields))
	for _, f := range fields {
		m[f.Key] = f
	}
	return m
}()

// Catalogue returns every field, sorted by key.
func Catalogue() []Field {
	out := make([]Field, len(fields))
	copy(out, fields)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Lookup returns the field for a key.
func Lookup(key string) (Field, bool) {
	f, ok := lookup[key]
	return f, ok
}

// Keys returns every valid configuration key, sorted.
func Keys() []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.Key)
	}
	sort.Strings(out)
	return out
}

// MutatingKeys returns the keys that change host networking, sorted.
//
// The list drives the `thn plan` risk summary: an operator scanning a plan
// wants to know at a glance which settings alter the host.
func MutatingKeys() []string {
	var out []string
	for _, f := range fields {
		if f.Mutating {
			out = append(out, f.Key)
		}
	}
	sort.Strings(out)
	return out
}

// Mutating reports whether a key changes host networking.
func Mutating(key string) bool {
	f, ok := lookup[key]
	return ok && f.Mutating
}

// Suggest returns catalogue keys close to an unknown key.
//
// This exists because the strictness in this package is only fair if the error
// message helps. "field wan_interface not found" tells the operator nothing;
// "did you mean network.wan?" tells them exactly what to type.
//
// Matching runs strongest-first: an exact section match, then a substring
// relationship in either direction, then a small edit distance. Substring
// matching has to consider the unknown key containing the catalogue key as
// well as the reverse, because the common typo is a *longer* invented name
// such as "network.wan_interface" where "network.wan" was meant.
func Suggest(unknown string) []string {
	needle := strings.ToLower(unknown)
	needleBase := lastSegment(needle)

	var exactSection, substring, near []string

	for _, f := range fields {
		key := strings.ToLower(f.Key)

		if key == needle {
			continue
		}

		// The unknown key names a section that exists, and a base that is
		// close to one of its fields.
		if sectionOf(key) == sectionOf(needle) && key != needle &&
			(editDistance(lastSegment(key), needleBase) <= 2 ||
				strings.Contains(lastSegment(key), needleBase) ||
				strings.Contains(needleBase, lastSegment(key))) {
			exactSection = append(exactSection, f.Key)
			continue
		}

		// One name contains the other, at any depth.
		if strings.Contains(key, needle) || strings.Contains(needle, key) {
			substring = append(substring, f.Key)
			continue
		}

		if editDistance(lastSegment(key), needleBase) <= 2 {
			near = append(near, f.Key)
		}
	}

	out := append(exactSection, substring...)
	out = append(out, near...)

	sort.Strings(out)
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// sectionOf returns the dotted prefix of a key, e.g. "network" for
// "network.wan".
func sectionOf(key string) string {
	if i := strings.Index(key, "."); i >= 0 {
		return key[:i]
	}
	return ""
}

// lastSegment returns the final dotted component of a key.
func lastSegment(key string) string {
	if i := strings.LastIndex(key, "."); i >= 0 {
		return key[i+1:]
	}
	return key
}

// UnknownKeyError describes a key that is not in the catalogue.
type UnknownKeyError struct {
	// Key is the offending key.
	Key string
	// Suggestions are the closest valid keys.
	Suggestions []string
}

// Error implements error.
func (e *UnknownKeyError) Error() string {
	if len(e.Suggestions) > 0 {
		return fmt.Sprintf("unknown configuration key %q; did you mean %s?",
			e.Key, strings.Join(e.Suggestions, ", "))
	}
	return fmt.Sprintf("unknown configuration key %q", e.Key)
}

// UnsupportedVersionError describes a schema version this build cannot read.
type UnsupportedVersionError struct {
	// Found is the version in the document.
	Found int
	// Min is the oldest version supported.
	Min int
	// Max is the newest version supported.
	Max int
}

// Error implements error.
func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf(
		"unsupported schema version %d; this build reads versions %d through %d — upgrade thn/thnd rather than editing the document",
		e.Found, e.Min, e.Max)
}

// CheckVersion verifies a document's schema version is readable.
func CheckVersion(v int) error {
	if v < MinimumVersion || v > Version {
		return &UnsupportedVersionError{Found: v, Min: MinimumVersion, Max: Version}
	}
	return nil
}

// editDistance returns the Levenshtein distance between a and b, bailing out
// once it exceeds max so that suggestion generation stays cheap.
func editDistance(a, b string) int {
	const max = 3

	ar := []rune(a)
	br := []rune(b)

	prev := make([]int, len(br)+1)
	curr := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= len(ar); i++ {
		curr[0] = i
		best := curr[0]
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
			if curr[j] < best {
				best = curr[j]
			}
		}
		if best > max {
			return max + 1
		}
		prev, curr = curr, prev
	}
	return prev[len(br)]
}

// min3 returns the smallest of three integers.
func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
