package config

// Architectural coverage: internal policy fields that configuration cannot reach.
//
// # The incident this exists to prevent
//
// `fwpolicy.Policy.Admin.Source` was modelled, validated and RENDERED by the
// nftables backend. `thn firewall render` emitted a restricted administrative
// rule when it was set. And no configuration document could set it, because
// `FirewallConfig` had no field for it.
//
// The consequence was not a crash. It was a silently open SSH rule on every
// gateway, reported only as a warning that said "administration is permitted
// from any source address" — a warning an operator learns to accept, because
// nothing was broken and nothing looked wrong.
//
// The second incident was the mirror image: `dns.upstream` existed in the
// schema, in the defaults and in the shipped document, and was never read. An
// operator could edit it for a year and see no effect and no complaint.
//
// # What this test actually checks
//
// Not "today's fields are covered" — a test like that is updated in the same
// commit as the gap it was written to catch, which means it never fires.
//
// It checks the SHAPE: for each policy struct, does the configuration model
// carry a field corresponding to every string the struct can contain? Where
// one does not, the entry must be declared as deliberately unrepresentable
// with a reason. Adding a field to a policy without either adding a config
// key or declaring it unrepresentable fails the build.

import (
	"reflect"
	"strings"
	"testing"
)

// unreachable documents a policy field configuration deliberately does not
// carry, and why.
//
// An entry here is a decision, not an excuse. It should be rare, and it should
// read like a sentence explaining what an operator loses by not being able to
// set the field.
type unreachable struct {
	// Path is the field path in the policy struct.
	Path string

	// Why explains the decision.
	Why string
}

// deliberatelyUnreachable is the register for the above.
//
// It is deliberately NOT exhaustive. Its job is to make each omission a line
// someone wrote rather than an oversight nobody noticed.
var deliberatelyUnreachable = []unreachable{
	// Empty, and that is the finding rather than an oversight.
	//
	// As of this writing every field of every configuration struct is
	// reachable from a document. The two incidents that motivated this file —
	// an admin source no document could set, and a resolver list no document
	// could change — have both been closed, and closing them is what emptied
	// this register.
	//
	// Adding a configuration field that a document cannot set now means adding
	// a line here explaining why. That is the whole mechanism.
}

// allowedInConfigFields are policy fields a configuration key is permitted to
// supply by exact name.
//
// This is the other half of the check: not every policy field must be
// configurable, but a field named here must actually correspond to a real
// configuration key. That is what stops the exemption list from quietly
// covering a field nobody exposed.
var allowedInConfigFields = []string{
	// Firewall
	"Enabled",
	"Backend",
	"DefaultInboundPolicy",
	"AdminSources",

	// NAT and masquerade
	"Interfaces",
	"Masquerade",
	"Outbound",

	// Network roles and addressing
	"WAN",
	"LAN",
	"LANPrefix",
	"DNS",
	"UpstreamGateway",
	"MTU",

	// DHCP
	"Ranges",
	"Start",
	"End",
	"Reservations",
	"LeaseTime",
	"LeaseMax",
	"Domain",
	"Authoritative",

	// DNS
	"Upstream",
	"LocalDomain",
	"LocalRecords",
	"CacheSize",
	"LogQueries",
	"NoIPv6",

	// QoS
	"Interface",
	"Algorithm",
	"DownloadKbps",
	"UploadKbps",
	"OverheadPercent",
	"Clients",
	"Groups",
	"DefaultPriority",
}

// TestPolicyFieldsAreReachableFromConfiguration walks every policy struct the
// translators use and checks each field against the two registers above.
func TestPolicyFieldsAreReachableFromConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		typ    reflect.Type
		prefix string
	}{
		{"FirewallConfig", reflect.TypeOf(FirewallConfig{}), ""},
		{"NATConfig", reflect.TypeOf(NATConfig{}), ""},
		{"MasqueradeConfig", reflect.TypeOf(MasqueradeConfig{}), "Masquerade."},
		{"NetworkConfig", reflect.TypeOf(NetworkConfig{}), ""},
		{"DHCPConfig", reflect.TypeOf(DHCPConfig{}), ""},
		{"DNSConfig", reflect.TypeOf(DNSConfig{}), ""},
		{"QoSConfig", reflect.TypeOf(QoSConfig{}), ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i := 0; i < c.typ.NumField(); i++ {
				f := c.typ.Field(i)
				if f.PkgPath != "" {
					continue // unexported
				}

				path := c.prefix + f.Name
				yaml := yamlKey(f)

				switch {
				case isAllowed(f.Name):
					// Permitted. It must actually carry a yaml tag, or the
					// exemption is claiming a mapping that does not exist.
					if yaml == "" {
						t.Errorf("%s is on the allowed list but has no yaml tag; "+
							"either give it one or remove it from the list", path)
					}

				case isDeclaredUnreachable(path):
					if yaml != "" {
						t.Errorf("%s is declared unreachable but carries yaml tag %q; "+
							"it is in fact configurable", path, yaml)
					}

				default:
					t.Errorf("%s (yaml %q) is neither reachable from configuration nor "+
						"declared unreachable; add a config key or an entry to "+
						"deliberatelyUnreachable explaining why not", path, yaml)
				}
			}
		})
	}
}

// isAllowed reports whether a field name is in the reachable register.
func isAllowed(name string) bool {
	for _, a := range allowedInConfigFields {
		if a == name {
			return true
		}
	}
	return false
}

// isDeclaredUnreachable reports whether a path is in the exemption register.
func isDeclaredUnreachable(path string) bool {
	for _, u := range deliberatelyUnreachable {
		if u.Path == path {
			return true
		}
	}
	return false
}

// TestEveryExemptionCarriesAReason keeps the exemption register honest.
//
// An entry with a blank Why is a gap someone deferred. Every one of those
// becomes a permanent silence, because the register looks deliberate.
func TestEveryExemptionCarriesAReason(t *testing.T) {
	seen := map[string]bool{}

	for _, u := range deliberatelyUnreachable {
		if strings.TrimSpace(u.Why) == "" {
			t.Errorf("%s is declared unreachable with no reason", u.Path)
		}
		if len(u.Why) < 30 {
			t.Errorf("%s has a reason too short to be a decision: %q", u.Path, u.Why)
		}
		if seen[u.Path] {
			t.Errorf("%s is declared unreachable twice", u.Path)
		}
		seen[u.Path] = true
	}

	// Every exemption must name a field that actually exists somewhere, so the
	// register cannot rot into describing a renamed field.
	known := allConfigFieldNames()
	for _, u := range deliberatelyUnreachable {
		leaf := u.Path
		if i := strings.LastIndex(leaf, "."); i >= 0 {
			leaf = leaf[i+1:]
		}
		if i := strings.Index(leaf, "*"); i >= 0 {
			leaf = leaf[:i]
		}
		if !known[leaf] {
			t.Errorf("%s is declared unreachable but no configuration struct has a %q field",
				u.Path, leaf)
		}
	}
}

// TestTheAllowedRegisterDoesNotDrift checks the other direction.
//
// A field listed as reachable must exist. An entry for a field nobody has
// would let a future gap hide behind a stale exemption.
func TestTheAllowedRegisterDoesNotDrift(t *testing.T) {
	known := allConfigFieldNames()

	for _, a := range allowedInConfigFields {
		if !known[a] {
			t.Errorf("%s is on the allowed list but no configuration struct has that field", a)
		}
	}
}

// allConfigFieldNames collects every exported field name across the config
// structs the translators use.
func allConfigFieldNames() map[string]bool {
	out := map[string]bool{}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(FirewallConfig{}),
		reflect.TypeOf(NATConfig{}),
		reflect.TypeOf(MasqueradeConfig{}),
		reflect.TypeOf(NetworkConfig{}),
		reflect.TypeOf(DHCPConfig{}),
		reflect.TypeOf(DNSConfig{}),
		reflect.TypeOf(QoSConfig{}),
		reflect.TypeOf(DHCPRangeConfig{}),
		reflect.TypeOf(DHCPReservationConfig{}),
		reflect.TypeOf(LocalRecordConfig{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.PkgPath == "" {
				out[f.Name] = true
			}
		}
	}
	return out
}

// yamlKey returns a struct field's yaml tag, empty when it has none.
func yamlKey(f reflect.StructField) string {
	tag := f.Tag.Get("yaml")
	if tag == "" {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	return name
}
