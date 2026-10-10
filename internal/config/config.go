// Package config defines THN's configuration model and its layered loading
// and validation rules.
//
// # Layering
//
// Configuration is resolved from four layers, each overriding the one before:
//
//  1. compiled defaults (internal/config.Defaults)
//  2. the on-disk config file
//  3. environment variables (THN_*)
//  4. explicit CLI flags
//
// This is the standard precedence for a system daemon and it means an operator
// can drop a file in /etc/thn and override a single value from the shell
// without editing the file.
//
// # Trust model
//
// The configuration file is parsed with yaml.Decoder.KnownFields(true), so a
// misspelled or misspelt key is a hard error rather than a silently ignored
// setting. On a device that is reached over SSH by someone who is guessing at
// key names, silent acceptance of a typo is how you end up with a gateway that
// is quietly not doing what the operator believes it is doing.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/VengeTH/THN-Gateway/internal/policy"
)

// SchemaVersion is the configuration schema version. It is written into the
// state database alongside each accepted configuration so that a later build
// can detect a downgrade and refuse to operate on a document it does not
// understand.
const SchemaVersion = 1

// Config is the complete THN configuration document.
type Config struct {
	// SchemaVersion identifies the document layout.
	SchemaVersion int `yaml:"schema_version"`

	// Gateway holds identity and lifecycle settings.
	Gateway GatewayConfig `yaml:"gateway"`

	// Routing carries packet-forwarding intent.
	//
	// It is a block of its own rather than a field on Network because
	// forwarding is a distinct decision from addressing. Whether to place
	// 10.77.0.1/24 on the LAN and whether to route between WAN and LAN are
	// separate statements, they fail for different reasons, and an operator
	// who wants one without the other must be able to say so.
	Routing RoutingConfig `yaml:"routing"`

	// Network describes intended interface roles and addressing.
	Network NetworkConfig `yaml:"network"`

	// NAT controls masquerading intent.
	NAT NATConfig `yaml:"nat"`

	// Firewall controls filtering intent.
	Firewall FirewallConfig `yaml:"firewall"`

	// QoS controls traffic shaping intent.
	QoS QoSConfig `yaml:"qos"`

	// MultiWAN controls multi-uplink routing, failover and load balancing.
	MultiWAN MultiWANConfig `yaml:"multi_wan"`

	// DHCP controls address assignment intent.
	DHCP DHCPConfig `yaml:"dhcp"`

	// DNS controls name resolution intent.
	DNS DNSConfig `yaml:"dns"`

	// Services locates the backing services THN compiles to.
	Services ServicesConfig `yaml:"services"`

	// Paths locates runtime sockets, state and logs.
	Paths PathsConfig `yaml:"paths"`

	// Logging configures the daemon log sink.
	Logging LoggingConfig `yaml:"logging"`

	// Activation governs the state machine and its safety gates.
	Activation ActivationConfig `yaml:"activation"`

	// Management controls the local management API and dashboard server policy.
	Management ManagementConfig `yaml:"management"`

	// Networks defines logical networks and future VLAN / client-isolation zones.
	Networks []NetworkDefinition `yaml:"networks"`

	// Policies holds named settings that can be selected per device and per
	// time.
	//
	// It is a block of its own rather than fields added to qos, dns and
	// firewall, because a per-device override and a host-wide default are the
	// same kind of setting applied to different subjects. Splitting them would
	// mean two places to look for "what rate does this device get" and no
	// single answer.
	//
	// The host-wide defaults stay in their own blocks; a device with no profile
	// here gets exactly what it got before this block existed.
	Policies policy.Set `yaml:"policies"`
}

// GatewayConfig holds gateway identity and the explicit statement of intent.
type GatewayConfig struct {
	// Name is the logical gateway name, reported by `thn status`.
	Name string `yaml:"name"`

	// Generation is the operator-managed configuration generation counter.
	// Every accepted configuration increments it, giving plans and
	// activations a monotonic identifier to refer back to.
	Generation uint64 `yaml:"generation"`

	// Enabled states that this machine is intended to be a gateway.
	//
	// # Why this field exists
	//
	// Everything else in this document describes WHAT a gateway would be
	// made of — which interfaces, which address, whether to masquerade. None
	// of it says whether the operator wants any of that to happen. THN can
	// observe that a machine has two NICs, that forwarding is enabled in the
	// kernel, and that NAT appears possible, and it will report all three as
	// capability. None of those observations is a request.
	//
	// So the request has to be written down. Without this field the only
	// honest description of the machine was "a host with gateway-shaped
	// hardware", and THN has no way to tell that apart from "a gateway the
	// operator asked for" — which is the difference between an observation
	// and an instruction, and the whole subject of this milestone.
	//
	// It defaults to true because a THN document that names a WAN, a LAN and
	// a LAN address is describing a gateway, and silently disabling it would
	// break every existing deployment for the sake of a stricter default. What
	// the field guarantees is the opposite direction: an operator who sets it
	// false is never asked for gateway roles they did not ask for.
	Enabled bool `yaml:"enabled"`
}

// RoutingConfig carries packet-forwarding intent.
//
// Forwarding here is DESIRED state. It is a different value from the
// forwarding the kernel currently has, which is an observation, and the two
// are never conflated: a host may have forwarding on and want it off, and a
// host may have it off and want it on. The planner compares them; it does not
// copy one into the other.
type RoutingConfig struct {
	// IPv4Forwarding requests IPv4 packet forwarding between interfaces.
	//
	// This is the switch that makes a host a router rather than two hosts
	// sharing a chassis. It is stated explicitly because "THN observed
	// forwarding is on, so it must be wanted" is the inference this milestone
	// exists to refuse.
	IPv4Forwarding bool `yaml:"ipv4_forwarding"`

	// IPv6Forwarding requests IPv6 packet forwarding.
	IPv6Forwarding bool `yaml:"ipv6_forwarding"`
}

// NetworkConfig describes intended interface roles.
type NetworkConfig struct {
	// WAN is the uplink: the interface carrying the internet connection.
	//
	// It accepts either a kernel interface name (the advanced, explicit
	// form) or a stable interface identity produced by `thn discover`. The
	// second is preferred, because it survives the NIC moving slots.
	WAN string `yaml:"wan"`

	// LAN is the downstream interface: the network the operator's own
	// devices sit on. Same two accepted forms as WAN.
	//
	// Empty means "not yet identified". That is the expected state while THN
	// is developed against hardware that is not present, and THN will NOT
	// pick one for you: an unassigned LAN stays unassigned.
	LAN string `yaml:"lan"`

	// Management is the dedicated administrative interface.
	Management string `yaml:"management,omitempty" json:"management,omitempty"`

	// Mgmt is an alias for Management.
	Mgmt string `yaml:"mgmt,omitempty" json:"mgmt,omitempty"`

	// LANPrefix is the address to place on the LAN interface.
	LANPrefix string `yaml:"lan_prefix"`

	// ManagementPrefix is the address to place on the management interface.
	ManagementPrefix string `yaml:"management_prefix,omitempty" json:"management_prefix,omitempty"`

	// MgmtPrefix is an alias for ManagementPrefix.
	MgmtPrefix string `yaml:"mgmt_prefix,omitempty" json:"mgmt_prefix,omitempty"`

	// DNS lists resolvers to configure.
	DNS []string `yaml:"dns"`

	// MTU is the MTU to apply to gateway interfaces.
	MTU int `yaml:"mtu"`

	// UpstreamGateway is the next hop for the default route.
	UpstreamGateway string `yaml:"upstream_gateway"`
}

// NATConfig controls masquerading intent.
type NATConfig struct {
	Enabled bool `yaml:"enabled"`

	// Interfaces to masquerade traffic from.
	//
	// This is the INBOUND side: which networks get their source addresses
	// rewritten. The outbound side — the interface traffic leaves by — is
	// Masquerade.Outbound, and it is a separate field on purpose, because
	// conflating them is how a ruleset ends up masquerading onto the LAN.
	Interfaces []string `yaml:"interfaces"`

	// Masquerade carries the source-NAT intent.
	Masquerade MasqueradeConfig `yaml:"masquerade"`
}

// MasqueradeConfig is the source-NAT half of NAT.
type MasqueradeConfig struct {
	// Enabled reports whether outbound traffic is source-NATed.
	//
	// It is separate from NAT.Enabled so that "rewrite what leaves this host"
	// and "which networks get rewritten" can be reasoned about separately.
	// Masquerading without NAT is a legitimate transient state while an
	// operator brings an uplink up.
	Enabled bool `yaml:"enabled"`

	// Outbound is the interface masqueraded traffic leaves by — the logical
	// WAN role in practice.
	//
	// It may be a role ("wan") or an interface name. A role is resolved at
	// plan time against the observed host; a name is taken literally. Empty
	// means "unset", which policy validation reports, because a masquerade
	// rule with no outbound interface applies to EVERY interface including
	// the LAN — which breaks LAN-to-LAN traffic in a way that looks like
	// intermittent hardware failure.
	Outbound string `yaml:"outbound"`
}

// FirewallConfig controls filtering intent.
type FirewallConfig struct {
	Enabled bool `yaml:"enabled"`

	// Backend is the firewall implementation to plan against. Only "nftables"
	// is supported.
	Backend string `yaml:"backend"`

	// DefaultInboundPolicy is "accept" or "drop".
	DefaultInboundPolicy string `yaml:"default_inbound_policy"`

	// AdminSources are the networks permitted to administer the gateway.
	//
	// Empty means any source, which policy validation reports as a risk
	// finding rather than an error: an operator who has not yet decided where
	// management traffic comes from should get a warning, not a refusal.
	//
	// This field exists because the firewall policy already models, validates
	// and RENDERS an admin source restriction — without it, that restriction
	// could not be expressed by any document, so the emitted rule would always
	// be the open one. Naming it here makes the existing capability reachable.
	//
	// The values are networks, not addresses or interface names. Every entry
	// becomes an nftables saddr match on the admin rule.
	AdminSources []string `yaml:"admin_sources"`
}

// QoSClientConfig configures bandwidth ceilings, guarantees and priority for one client or subnet.
type QoSClientConfig struct {
	ID              string `yaml:"id" json:"id"`
	IP              string `yaml:"ip" json:"ip"`
	MAC             string `yaml:"mac,omitempty" json:"mac,omitempty"`
	DownloadKbps    int    `yaml:"download_kbps" json:"download_kbps"`
	UploadKbps      int    `yaml:"upload_kbps" json:"upload_kbps"`
	MinDownloadKbps int    `yaml:"min_download_kbps,omitempty" json:"min_download_kbps,omitempty"`
	MinUploadKbps   int    `yaml:"min_upload_kbps,omitempty" json:"min_upload_kbps,omitempty"`
	Priority        string `yaml:"priority,omitempty" json:"priority,omitempty"`
	Group           string `yaml:"group,omitempty" json:"group,omitempty"`
	Disabled        bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// QoSGroupConfig configures an aggregate bandwidth pool shared across multiple clients.
type QoSGroupConfig struct {
	Name         string `yaml:"name" json:"name"`
	DownloadKbps int    `yaml:"download_kbps" json:"download_kbps"`
	UploadKbps   int    `yaml:"upload_kbps" json:"upload_kbps"`
	Priority     string `yaml:"priority,omitempty" json:"priority,omitempty"`
}

// QoSConfig controls traffic shaping intent.
type QoSConfig struct {
	Enabled bool `yaml:"enabled"`

	// Algorithm is the shaping algorithm: "cake" or "fq_codel".
	//
	// Only cake can enforce the configured rate. fq_codel is accepted as an
	// explicit choice but is reported as rate-unaware, and THN falls back to
	// it when a kernel cannot provide cake.
	Algorithm string `yaml:"algorithm"`

	// Interface is the egress device to shape.
	Interface string `yaml:"interface"`

	// DownloadKbps is the shaped download rate in kilobits per second.
	DownloadKbps int `yaml:"download_kbps"`

	// UploadKbps is the shaped upload rate in kilobits per second.
	UploadKbps int `yaml:"upload_kbps"`

	// OverheadPercent compensates for protocol and Ethernet framing overhead.
	// Zero means "not configured", which is not the same as zero: THN applies
	// its 10 percent default rather than shaping at the payload rate, which
	// would leave the link permanently a tenth under-utilised.
	OverheadPercent int `yaml:"overhead_percent"`

	// Clients configures per-client bandwidth limits, guarantees, and priorities.
	Clients []QoSClientConfig `yaml:"clients,omitempty" json:"clients,omitempty"`

	// Groups configures aggregate bandwidth pools.
	Groups []QoSGroupConfig `yaml:"groups,omitempty" json:"groups,omitempty"`

	// DefaultPriority sets the priority for unclassified traffic (default: "normal").
	DefaultPriority string `yaml:"default_priority,omitempty" json:"default_priority,omitempty"`
}

// MultiWANConfig controls multi-uplink routing, failover and load balancing.
type MultiWANConfig struct {
	// Enabled explicitly requests multi-WAN routing management.
	Enabled bool `yaml:"enabled"`

	// Mode is "single", "failover", or "load_balance".
	Mode string `yaml:"mode"`

	// Policy is the routing policy: "default" (session/connection-oriented).
	Policy string `yaml:"policy"`

	// Members lists the individual WAN connections.
	Members []WANMemberConfig `yaml:"members"`

	// HealthCheck configures health evaluation for WAN links.
	HealthCheck WANHealthCheckConfig `yaml:"health_check"`
}

// WANMemberConfig is one logical WAN link.
type WANMemberConfig struct {
	// ID is the logical identifier, e.g. "wan1", "pldt".
	ID string `yaml:"id"`

	// Interface is the interface selector (stable ID "hw:..." or system name).
	Interface string `yaml:"interface"`

	// Weight is the relative connection distribution in load_balance mode.
	Weight int `yaml:"weight"`

	// Priority is the preference rank in failover mode (higher = preferred).
	Priority int `yaml:"priority"`

	// Enabled states whether this WAN is administratively active.
	Enabled bool `yaml:"enabled"`

	// Gateway optionally specifies the upstream next-hop address.
	Gateway string `yaml:"gateway"`

	// Description is an optional human label.
	Description string `yaml:"description"`
}

// WANHealthCheckConfig configures health checks.
type WANHealthCheckConfig struct {
	// Target is an optional address or host to verify connectivity toward.
	Target string `yaml:"target"`

	// Interval is the health assessment period.
	Interval time.Duration `yaml:"interval"`

	// Timeout is the maximum time for a health probe.
	Timeout time.Duration `yaml:"timeout"`
}

// DHCPRangeConfig is one address pool handed out by DHCP.
type DHCPRangeConfig struct {
	// Start is the first address in the pool.
	Start string `yaml:"start"`

	// End is the last address in the pool, inclusive.
	End string `yaml:"end"`

	// Netmask optionally overrides the netmask derived from the LAN prefix.
	Netmask string `yaml:"netmask"`
}

// DHCPReservationConfig pins an address to a device.
//
// A reservation is declarative intent, not lease state: the server still
// issues the lease and THN still observes it.
type DHCPReservationConfig struct {
	// MAC is the hardware address to match.
	MAC string `yaml:"mac"`

	// Address is the address to hand out. Empty means "any", which keeps the
	// device on the same address across renewals.
	Address string `yaml:"address"`

	// Hostname is the name to report to the client.
	Hostname string `yaml:"hostname"`

	// LeaseTime overrides the pool's lease time for this device.
	LeaseTime time.Duration `yaml:"lease_time"`
}

// DHCPConfig controls address assignment intent.
type DHCPConfig struct {
	// Enabled reports whether THN should serve addresses on the LAN.
	Enabled bool `yaml:"enabled"`

	// Authoritative marks the server authoritative for the LAN. Without it a
	// client that fails to reach this server falls back to another one, which
	// on a home gateway means a device could obtain an address from the
	// upstream network and bypass this gateway entirely.
	Authoritative bool `yaml:"authoritative"`

	// LeaseTime is the default lease duration. Too short churns the table and
	// breaks clients that sleep; too long delays reclaiming abandoned
	// addresses.
	LeaseTime time.Duration `yaml:"lease_time"`

	// Ranges are the address pools.
	Ranges []DHCPRangeConfig `yaml:"ranges"`

	// Reservations pin addresses to devices.
	Reservations []DHCPReservationConfig `yaml:"reservations"`

	// LeaseMax caps how many leases the server will hold.
	LeaseMax int `yaml:"lease_max"`

	// Domain is the local domain advertised via option 15.
	Domain string `yaml:"domain"`
}

// LocalRecordConfig is a name THN serves for a local address.
type LocalRecordConfig struct {
	// Hostname is the name to serve, without the domain suffix.
	Hostname string `yaml:"hostname"`

	// Address is the address it resolves to.
	Address string `yaml:"address"`

	// Aliases are additional names for the same address.
	Aliases []string `yaml:"aliases"`
}

// DNSConfig controls name resolution intent.
type DNSConfig struct {
	// Enabled reports whether THN should serve DNS on the LAN.
	Enabled bool `yaml:"enabled"`

	// Upstream are the resolvers queries are forwarded to.
	Upstream []string `yaml:"upstream"`

	// LocalDomain is the domain served for local names.
	LocalDomain string `yaml:"local_domain"`

	// LocalRecords are additional names THN serves.
	LocalRecords []LocalRecordConfig `yaml:"local_records"`

	// CacheSize is the number of answers cached. Zero uses the backend default.
	CacheSize int `yaml:"cache_size"`

	// LogQueries records every query. Valuable for security, but it writes to
	// disk continuously, so it is off by default.
	LogQueries bool `yaml:"log_queries"`

	// NoIPv6 answers AAAA queries with no answer. Useful while IPv6 is not
	// working, because a half-configured AAAA response sends clients down a
	// path that fails slowly.
	NoIPv6 bool `yaml:"no_ipv6"`
}

// ServicesConfig locates the backing services THN compiles to.
//
// THN never starts these. It renders configuration for them and observes what
// they report.
type ServicesConfig struct {
	// Dnsmasq is the DHCP and DNS backend.
	Dnsmasq DnsmasqConfig `yaml:"dnsmasq"`
}

// DnsmasqConfig locates the dnsmasq backend's files.
type DnsmasqConfig struct {
	// ConfigFile is the file THN generates. It is THN-owned: overwriting it is
	// safe, but hand edits are lost on the next render.
	ConfigFile string `yaml:"config_file"`

	// LeaseFile is the file dnsmasq writes and THN reads. THN never writes
	// it; the file belongs to the server.
	LeaseFile string `yaml:"lease_file"`
}

// PathsConfig locates runtime files.
type PathsConfig struct {
	// Config is the path to the configuration file.
	Config string `yaml:"config"`

	// StateDir holds the SQLite state database.
	StateDir string `yaml:"state_dir"`

	// StateDB is the full path to the SQLite database.
	StateDB string `yaml:"state_db"`

	// Socket is the Unix domain socket the daemon listens on.
	Socket string `yaml:"socket"`

	// RunDir holds runtime-only files such as pidfiles.
	RunDir string `yaml:"run_dir"`

	// LogFile is the daemon log file. Empty means stdout, which is what
	// systemd's journal captures.
	LogFile string `yaml:"log_file"`
}

// LoggingConfig configures log level and format.
type LoggingConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `yaml:"level"`

	// Format is "json" or "text".
	Format string `yaml:"format"`

	// Retention is how long events are retained in the state database.
	Retention time.Duration `yaml:"retention"`

	// MaxEvents caps retained events; zero means unlimited.
	MaxEvents int `yaml:"max_events"`
}

// ActivationConfig governs the activation state machine.
type ActivationConfig struct {
	// AutoRecover enables automatic recovery attempts on failure. It has no
	// effect while the build lacks an apply path.
	AutoRecover bool `yaml:"auto_recover"`

	// HealthCheckInterval is how often health would be evaluated once
	// activation exists.
	HealthCheckInterval time.Duration `yaml:"health_check_interval"`

	// RequirePhysicalPresence demands an explicit operator confirmation token
	// before any activation is permitted. This exists so that being logged in
	// as root on a remote host is not by itself sufficient to activate.
	RequirePhysicalPresence bool `yaml:"require_physical_presence"`

	// Development carries relaxations an operator may opt into when bringing
	// THN up on development or controlled home-lab hardware.
	//
	// # Why this block exists and what it is not
	//
	// Every default in this document is production policy. Relaxing one of
	// them belongs in a block an operator has to write deliberately, name
	// after what it relaxes, and cannot reach by setting a single flag.
	//
	// It is NOT a way to weaken production. Nothing here changes what the
	// firewall, NAT, routing or rollback gates require; it changes exactly
	// one hardware question — whether a slower-than-Gigabit LAN adapter may
	// fill the LAN role — and only for adapters the operator named by stable
	// identity.
	//
	// The default is the zero value, which permits nothing.
	Development DevelopmentConfig `yaml:"development"`
}

// DevelopmentConfig holds the opt-in relaxations available for development and
// controlled home-lab use.
//
// # Both fields are required together, deliberately
//
// AllowFastEthernetLAN without ApprovedFastEthernetLAN would be a blanket
// bypass: every 100 Mbps adapter on the host would become acceptable because
// a flag was set. Naming the adapters is what makes this an approval rather
// than a category exemption, and the configuration validator refuses the
// flag-without-a-list combination rather than letting it sit inert and
// surprising.
//
// Requiring both also means an operator cannot relax the check by accident.
// There is no single keystroke that does it, and the list is a thing they had
// to read off `thn discover`.
type DevelopmentConfig struct {
	// AllowFastEthernetLAN permits a Fast Ethernet (sub-1000 Mbps) wired
	// adapter to fill the LAN role.
	//
	// It only ever applies to the identities in ApprovedFastEthernetLAN.
	// Unnamed adapters remain rejected exactly as they are in production.
	AllowFastEthernetLAN bool `yaml:"allow_fast_ethernet_lan"`

	// ApprovedFastEthernetLAN names the specific adapters the exception
	// applies to, by stable identity (`hw:...`) or kernel name.
	//
	// It must not be empty when AllowFastEthernetLAN is true.
	ApprovedFastEthernetLAN []string `yaml:"approved_fast_ethernet_lan"`
}

// ManagementConfig governs the management service, binding policy and roles.
type ManagementConfig struct {
	// Enabled controls whether the management plane and dashboard are available.
	Enabled bool `yaml:"enabled"`

	// BindAddress is the network address and port to bind the management HTTP server.
	// Defaults to 127.0.0.1:8080. For LAN access, configure a LAN/MGMT address.
	BindAddress string `yaml:"bind_address"`

	// AllowedNetworks specifies CIDRs permitted to query and manage the gateway.
	AllowedNetworks []string `yaml:"allowed_networks"`

	// WANAccess must remain false. The dashboard is never exposed to the public Internet.
	WANAccess bool `yaml:"wan_access"`

	// SessionTTL defines duration before an authenticated operator session expires.
	SessionTTL time.Duration `yaml:"session_ttl"`
}

// NetworkDefinition establishes the model for future VLANs and client-isolation zones.
type NetworkDefinition struct {
	ID                 string `yaml:"id" json:"id"`
	Name               string `yaml:"name" json:"name"`
	Role               string `yaml:"role" json:"role"` // MGMT, LAN, GUEST, DMZ
	VLANID             int    `yaml:"vlan_id" json:"vlan_id"`
	Subnet             string `yaml:"subnet" json:"subnet"`
	Gateway            string `yaml:"gateway" json:"gateway"`
	InternetAccess     bool   `yaml:"internet_access" json:"internet_access"`
	ClientIsolation    bool   `yaml:"client_isolation" json:"client_isolation"`
	InterNetworkPolicy string `yaml:"inter_network_policy" json:"inter_network_policy"` // isolated, restricted, open
}

// Severity classifies a validation finding.
type Severity string

const (
	// SeverityError marks a configuration that must not be accepted.
	SeverityError Severity = "error"
	// SeverityWarning marks a configuration that is accepted but suspect.
	SeverityWarning Severity = "warning"
	// SeverityInfo marks an informational note.
	SeverityInfo Severity = "info"
)

// Finding is a single validation result.
type Finding struct {
	// Field is the dotted path of the offending field.
	Field string `json:"field"`
	// Severity classifies the finding.
	Severity Severity `json:"severity"`
	// Message describes the problem.
	Message string `json:"message"`
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s: %s", f.Severity, f.Field, f.Message)
}

// usableHostCount reports how many addresses a prefix leaves for hosts.
//
// The address THN is told to place on the LAN is one of them, so a /30 offers
// the gateway and two devices, not four.
func usableHostCount(prefix netip.Prefix) int {
	bits := prefix.Bits()
	if !prefix.Addr().Is4() || bits < 0 || bits > 30 {
		return 0
	}
	total := uint64(1) << (32 - bits)
	if total <= 2 {
		return 0
	}
	return int(total - 2)
}

// ValidationResult aggregates findings from a validation pass.
type ValidationResult struct {
	Findings []Finding `json:"findings"`
}

// HasErrors reports whether any finding is an error.
func (v ValidationResult) HasErrors() bool {
	for _, f := range v.Findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Add appends a finding.
func (v *ValidationResult) Add(field string, sev Severity, msg string) {
	v.Findings = append(v.Findings, Finding{Field: field, Severity: sev, Message: msg})
}

// Defaults returns the compiled default configuration. The defaults describe
// the intended deployment layout: a state database under /var/lib/thn and a
// socket under /run/thn.
func Defaults() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Gateway: GatewayConfig{
			Name:       "thn-gateway",
			Generation: 1,
			// A document that configures a gateway is a gateway. Disabling
			// this by default would make every installed THN a non-gateway
			// that silently ignored its own configuration, which is a worse
			// failure than being explicit and defaulting to what the rest of
			// the defaults already assume.
			Enabled: true,
		},
		Routing: RoutingConfig{
			// Forwarding was previously hardcoded true in
			// desired.FromConfigWithResolution, so every derived desired
			// state already requested it. It is stated here now so the
			// intent is the operator's rather than the model's, and the
			// derived default is unchanged.
			IPv4Forwarding: true,
			IPv6Forwarding: true,
		},
		Network: NetworkConfig{
			// WAN is EMPTY on purpose.
			//
			// It used to default to "enp0s31f6" — a kernel interface name
			// copied from the development machine. Shipping that as a
			// default meant every host THN was installed on, and every
			// configuration derived from Defaults(), silently asserted that
			// it owned a NIC by that name. On any other machine the
			// assertion was false; the only outcomes were a validation
			// error naming a NIC that never existed, or — worse, when a
			// document omitted network.wan entirely — a default that
			// happened to match some unrelated interface.
			//
			// An empty WAN is the honest default: nobody has told THN which
			// connection is the internet one yet. `thn discover` is how that
			// gets answered.
			WAN: "",
			LAN: "",
			// 10.77.0.1/24 is a documentation-friendly example LAN, not a
			// property of any hardware. It is overridable and every operator
			// changes it; it is kept because a default document with no
			// addresses in it cannot express what a gateway is for.
			LANPrefix: "10.77.0.1/24",
			DNS:       []string{"1.1.1.1", "9.9.9.9"},
			MTU:       1500,
		},
		NAT: NATConfig{
			Enabled:    true,
			Interfaces: []string{},
		},
		Firewall: FirewallConfig{
			// Defaulted off in the sense that nothing is restricted yet,
			// which is what every previous default did. Policy validation
			// warns about this on every run until an operator narrows it.
			AdminSources:         []string{},
			Enabled:              true,
			Backend:              "nftables",
			DefaultInboundPolicy: "drop",
		},
		QoS: QoSConfig{
			// QoS is off by default because the correct shaped rate depends
			// on the uplink the operator actually has, which THN cannot know
			// while being developed against absent hardware. Enabling it with
			// a guessed rate would silently cap a real link.
			Enabled:   false,
			Algorithm: "cake",
			Interface: "",
		},
		MultiWAN: MultiWANConfig{
			Enabled: false,
			Mode:    "single",
			Policy:  "default",
			Members: []WANMemberConfig{},
			HealthCheck: WANHealthCheckConfig{
				Interval: 10 * time.Second,
				Timeout:  2 * time.Second,
			},
		},
		DHCP: DHCPConfig{
			// DHCP is disabled by default: THN implements no runtime DHCP
			// server in this build. Leaving it disabled separates core gateway
			// functionality (routing, NAT, firewall) from optional service intent.
			Enabled:       false,
			Authoritative: true,
			// 12 hours is long enough that a sleeping laptop keeps its
			// address, and short enough that an abandoned address is
			// reclaimed within a day.
			LeaseTime: 12 * time.Hour,
			// LeaseMax 0 leaves the cap to the server default.
			LeaseMax: 0,
			Domain:   "lan",
			Ranges: []DHCPRangeConfig{
				{
					// Start at .100 so the first 99 addresses stay available
					// for static hosts and for the gateway itself.
					Start: "10.77.0.100",
					End:   "10.77.0.250",
				},
			},
			Reservations: []DHCPReservationConfig{},
		},
		DNS: DNSConfig{
			// DNS is disabled by default: THN implements no runtime DNS
			// server in this build. Clients use upstream resolvers directly.
			Enabled:      false,
			Upstream:     []string{},
			LocalDomain:  "lan",
			LocalRecords: []LocalRecordConfig{},
			CacheSize:    1000,
			// Logging every query writes to disk continuously. It is the
			// most useful DNS setting for security work and one of the
			// fastest ways to fill a small filesystem, so it is opt-in.
			LogQueries: false,
			// Off until IPv6 is actually configured. A working AAAA record
			// for a path that does not work yet makes clients fail slowly
			// rather than fall back quickly.
			NoIPv6: false,
		},
		Services: ServicesConfig{
			Dnsmasq: DnsmasqConfig{
				ConfigFile: "/etc/thn/dnsmasq.conf",
				LeaseFile:  "/var/lib/thn/dnsmasq.leases",
			},
		},
		Paths: PathsConfig{
			Config:   "/etc/thn/config.yaml",
			StateDir: "/var/lib/thn",
			StateDB:  "/var/lib/thn/state.db",
			Socket:   "/run/thn/thnd.sock",
			RunDir:   "/run/thn",
			LogFile:  "",
		},
		Logging: LoggingConfig{
			Level:     "info",
			Format:    "json",
			Retention: 14 * 24 * time.Hour,
			MaxEvents: 50000,
		},
		Activation: ActivationConfig{
			AutoRecover:             false,
			HealthCheckInterval:     30 * time.Second,
			RequirePhysicalPresence: true,
		},
		Management: ManagementConfig{
			Enabled:         true,
			BindAddress:     "127.0.0.1:8080",
			AllowedNetworks: []string{"10.10.99.0/24", "10.77.0.0/24", "127.0.0.0/8"},
			WANAccess:       false,
			SessionTTL:      24 * time.Hour,
		},
		Networks: []NetworkDefinition{
			{
				ID:                 "mgmt",
				Name:               "Management",
				Role:               "MGMT",
				VLANID:             99,
				Subnet:             "10.10.99.0/24",
				Gateway:            "10.10.99.1",
				InternetAccess:     true,
				ClientIsolation:    true,
				InterNetworkPolicy: "isolated",
			},
			{
				ID:                 "lan",
				Name:               "Family LAN",
				Role:               "LAN",
				VLANID:             10,
				Subnet:             "10.77.0.0/24",
				Gateway:            "10.77.0.1",
				InternetAccess:     true,
				ClientIsolation:    false,
				InterNetworkPolicy: "restricted",
			},
			{
				ID:                 "neighbors",
				Name:               "Neighbors",
				Role:               "LAN",
				VLANID:             20,
				Subnet:             "10.10.20.0/24",
				Gateway:            "10.10.20.1",
				InternetAccess:     true,
				ClientIsolation:    true,
				InterNetworkPolicy: "isolated",
			},
			{
				ID:                 "guest",
				Name:               "Guest Network",
				Role:               "GUEST",
				VLANID:             30,
				Subnet:             "10.10.30.0/24",
				Gateway:            "10.10.30.1",
				InternetAccess:     true,
				ClientIsolation:    true,
				InterNetworkPolicy: "isolated",
			},
		},
	}
}

// DefaultPath is the canonical configuration file location.
func DefaultPath() string { return Defaults().Paths.Config }

// Load reads the configuration document at path, layers it over the defaults
// and applies environment overrides. A missing file is not an error: the
// defaults are returned so that `thn status` works on a freshly imaged device
// before an operator has written a config.
//
// Callers that require an explicit file (for example `thn config validate
// --strict`) should check Exists separately.
func Load(path string) (Config, error) {
	cfg := Defaults()

	exists, err := Exists(path)
	if err != nil {
		return cfg, err
	}

	if exists {
		raw, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("reading %s: %w", path, err)
		}
		if err := cfg.applyDocument(raw); err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", path, err)
		}
	}

	applyEnv(&cfg)

	if err := cfg.Normalize(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Exists reports whether a configuration file is present at path.
func Exists(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	return true, nil
}

// applyDocument decodes raw over the receiver. Unknown keys are rejected.
func (c *Config) applyDocument(raw []byte) error {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return err
	}
	return nil
}

// applyEnv applies THN_* environment overrides. This is the escape hatch that
// lets a systemd unit or a CI job point THN at a scratch state directory
// without writing a config file.
func applyEnv(c *Config) {
	if v := os.Getenv("THN_STATE_DB"); v != "" {
		c.Paths.StateDB = v
		c.Paths.StateDir = filepath.Dir(v)
	}
	if v := os.Getenv("THN_SOCKET"); v != "" {
		c.Paths.Socket = v
	}
	if v := os.Getenv("THN_RUN_DIR"); v != "" {
		c.Paths.RunDir = v
	}
	if v := os.Getenv("THN_LOG_LEVEL"); v != "" {
		c.Logging.Level = v
	}
	if v := os.Getenv("THN_LOG_FORMAT"); v != "" {
		c.Logging.Format = v
	}
	if v := os.Getenv("THN_LOG_FILE"); v != "" {
		c.Paths.LogFile = v
	}
	if v := os.Getenv("THN_WAN"); v != "" {
		c.Network.WAN = v
	}
	if v := os.Getenv("THN_LAN"); v != "" {
		c.Network.LAN = v
	}
}

// Normalize canonicalises derived and dependent values. It is called after
// every load so that the rest of the codebase can assume:
//   - the state database path agrees with the state directory
//   - logging level and format are lowercase
//   - empty string lists become empty, non-nil slices
func (c *Config) Normalize() error {
	c.Logging.Level = strings.ToLower(strings.TrimSpace(c.Logging.Level))
	c.Logging.Format = strings.ToLower(strings.TrimSpace(c.Logging.Format))
	c.NAT.Masquerade.Outbound = strings.TrimSpace(c.NAT.Masquerade.Outbound)
	c.Firewall.Backend = strings.ToLower(strings.TrimSpace(c.Firewall.Backend))
	c.Firewall.DefaultInboundPolicy = strings.ToLower(strings.TrimSpace(c.Firewall.DefaultInboundPolicy))
	c.QoS.Algorithm = strings.ToLower(strings.TrimSpace(c.QoS.Algorithm))
	c.Network.WAN = strings.TrimSpace(c.Network.WAN)
	c.Network.LAN = strings.TrimSpace(c.Network.LAN)
	if c.Network.Management == "" && c.Network.Mgmt != "" {
		c.Network.Management = c.Network.Mgmt
	}
	if c.Network.ManagementPrefix == "" && c.Network.MgmtPrefix != "" {
		c.Network.ManagementPrefix = c.Network.MgmtPrefix
	}
	c.Network.Management = strings.TrimSpace(c.Network.Management)
	c.Network.LANPrefix = strings.TrimSpace(c.Network.LANPrefix)
	c.Network.ManagementPrefix = strings.TrimSpace(c.Network.ManagementPrefix)

	if c.Paths.StateDir != "" && c.Paths.StateDB == "" {
		c.Paths.StateDB = filepath.Join(c.Paths.StateDir, "state.db")
	}

	// The NAT interface list defaults to the LAN interface when the operator
	// has enabled NAT but not named an explicit interface. Doing this here
	// rather than at each call site keeps the rule in one place.
	if c.NAT.Enabled && len(c.NAT.Interfaces) == 0 && c.Network.LAN != "" {
		c.NAT.Interfaces = []string{c.Network.LAN}
	}
	if c.QoS.Enabled && c.QoS.Interface == "" {
		c.QoS.Interface = c.Network.WAN
	}

	return nil
}

// Marshal renders the configuration as YAML.
func (c Config) Marshal() ([]byte, error) {
	return yaml.Marshal(c)
}

// Write persists the configuration to path, creating parent directories as
// needed with owner-only permissions.
//
// The file may contain upstream gateway addresses and interface names. It is
// written 0600 so that a non-root reader on the host cannot learn the gateway
// topology, and so that a future addition of credentials has somewhere safe
// to live.
func (c Config) Write(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}

	data, err := c.Marshal()
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}

// Validate checks the configuration for internal consistency.
//
// Validation is separated from parsing on purpose. A syntactically valid
// document can still be nonsensical: a LAN prefix that is not a prefix, a QoS
// rate of zero, a WAN interface that matches the LAN interface. Those are
// operator errors, and catching them in `thn config validate` before any
// device is touched is the entire point of the observe -> plan -> validate
// pipeline.
func (c Config) Validate() ValidationResult {
	var v ValidationResult

	if c.SchemaVersion != SchemaVersion {
		v.Add("schema_version", SeverityError,
			fmt.Sprintf("unsupported schema version %d (this build understands %d)",
				c.SchemaVersion, SchemaVersion))
	}

	if strings.TrimSpace(c.Gateway.Name) == "" {
		v.Add("gateway.name", SeverityError, "must not be empty")
	}

	if c.Gateway.Generation == 0 {
		v.Add("gateway.generation", SeverityError, "must be greater than zero")
	}

	// --- Gateway intent ---

	// A document that does not want a gateway must not be told to configure
	// one. This is checked before the network rules below because those rules
	// exist to make a gateway coherent, and a machine that is not meant to be
	// one has no reason to satisfy them.
	//
	// The roles are still checked for coherence when they ARE present: an
	// operator who writes both roles as the same interface has made a mistake
	// whether or not they enabled the gateway, and hiding that behind
	// gateway.enabled would make the flag a way to suppress a finding.
	if c.Gateway.Enabled && c.Network.WAN == "" {
		v.Add("network.wan", SeverityError,
			"must name the uplink; run `thn discover` to see this host's interfaces, "+
				"then set network.wan to a stable ID or a kernel interface name")
	}

	// --- Network ---

	if c.Network.LAN != "" && c.Network.LAN == c.Network.WAN {
		v.Add("network.lan", SeverityError,
			fmt.Sprintf("LAN and WAN must be different interfaces (both are %q)", c.Network.LAN))
	}
	if c.Network.Management != "" && c.Network.Management == c.Network.WAN {
		v.Add("network.management", SeverityError,
			fmt.Sprintf("Management and WAN must be different interfaces (both are %q)", c.Network.Management))
	}
	if c.Network.Management != "" && c.Network.Management == c.Network.LAN {
		v.Add("network.management", SeverityError,
			fmt.Sprintf("Management and LAN must be different interfaces (both are %q)", c.Network.Management))
	}

	var lanPrefixParsed netip.Prefix
	if c.Network.LANPrefix != "" {
		prefix, err := netip.ParsePrefix(c.Network.LANPrefix)
		switch {
		case err != nil:
			v.Add("network.lan_prefix", SeverityError,
				fmt.Sprintf("%q is not a valid CIDR prefix", c.Network.LANPrefix))
		case prefix.Addr().IsLoopback() || prefix.Addr().IsUnspecified():
			v.Add("network.lan_prefix", SeverityError,
				"LAN prefix must be a routable address, not loopback or unspecified")
		case prefix.Addr().IsMulticast():
			v.Add("network.lan_prefix", SeverityError,
				"LAN prefix must not be a multicast address")
		default:
			lanPrefixParsed = prefix
		}

		if prefix.IsValid() && prefix.Addr().Is4() && prefix.Bits() > 29 {
			// IPv4 only. /64 is an ordinary IPv6 LAN size, so applying this
			// to both families reports every IPv6 configuration as too narrow.
			v.Add("network.lan_prefix", SeverityWarning,
				fmt.Sprintf("%s leaves only %d usable host address(es)", prefix, usableHostCount(prefix)))
		}
	} else {
		// An absent LAN prefix is pending rather than broken — the LAN
		// interface may not have been identified yet — so this warns instead
		// of erroring. It used to produce no finding here at all, which made
		// the gap visible only as a side effect of DNS being configured, in
		// internal/validation. THN's own principle is that an absent reading
		// is reported as absent rather than as zero, and this is the field
		// the absence actually belongs to.
		v.Add("network.lan_prefix", SeverityWarning,
			"no LAN address is configured. Everything downstream of the LAN address "+
				"(DHCP scope, DNS zone, NAT interface, anti-spoofing) stays pending until "+
				"this is set, e.g. 10.77.0.1/24")
	}

	var mgmtPrefixParsed netip.Prefix
	if c.Network.ManagementPrefix != "" {
		prefix, err := netip.ParsePrefix(c.Network.ManagementPrefix)
		switch {
		case err != nil:
			v.Add("network.management_prefix", SeverityError,
				fmt.Sprintf("%q is not a valid CIDR prefix", c.Network.ManagementPrefix))
		case prefix.Addr().IsLoopback() || prefix.Addr().IsUnspecified():
			v.Add("network.management_prefix", SeverityError,
				"Management prefix must be a routable address, not loopback or unspecified")
		case prefix.Addr().IsMulticast():
			v.Add("network.management_prefix", SeverityError,
				"Management prefix must not be a multicast address")
		default:
			mgmtPrefixParsed = prefix
		}
	}

	if lanPrefixParsed.IsValid() && mgmtPrefixParsed.IsValid() {
		if lanPrefixParsed.Overlaps(mgmtPrefixParsed) {
			v.Add("network.management_prefix", SeverityError,
				fmt.Sprintf("Management prefix %s conflicts with LAN prefix %s (overlapping subnets)",
					mgmtPrefixParsed, lanPrefixParsed))
		}
	}

	for i, s := range c.Network.DNS {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			v.Add(fmt.Sprintf("network.dns[%d]", i), SeverityError,
				fmt.Sprintf("%q is not a valid IP address", s))
			continue
		}
		if addr.IsUnspecified() {
			v.Add(fmt.Sprintf("network.dns[%d]", i), SeverityError,
				"resolver must not be the unspecified address")
		}
	}

	if c.Network.MTU != 0 && (c.Network.MTU < 576 || c.Network.MTU > 9000) {
		v.Add("network.mtu", SeverityError,
			fmt.Sprintf("MTU %d is outside the valid range 576-9000", c.Network.MTU))
	}

	if c.Network.UpstreamGateway != "" {
		upstream, err := netip.ParseAddr(c.Network.UpstreamGateway)
		if err != nil {
			v.Add("network.upstream_gateway", SeverityError,
				fmt.Sprintf("%q is not a valid IP address", c.Network.UpstreamGateway))
		} else {
			if lanPrefixParsed.IsValid() && lanPrefixParsed.Contains(upstream) {
				v.Add("network.upstream_gateway", SeverityError,
					fmt.Sprintf("the upstream gateway %s is inside the LAN prefix %s; "+
						"the default route must leave through the WAN, not back into the LAN",
						upstream, lanPrefixParsed))
			}
			if mgmtPrefixParsed.IsValid() && mgmtPrefixParsed.Contains(upstream) {
				v.Add("network.upstream_gateway", SeverityError,
					fmt.Sprintf("the upstream gateway %s is inside the Management prefix %s; "+
						"the default route must leave through the WAN, not back into the management network",
						upstream, mgmtPrefixParsed))
			}
		}
	}

	// --- NAT ---

	if c.NAT.Enabled {
		// An unidentified LAN is the expected state while THN is developed
		// against hardware that is not present. It is incomplete, not
		// incoherent: a plan can still be generated, and the operator will
		// see exactly which step is pending. Activation is what requires
		// completeness, and that gate lives in the activation state machine.
		if c.Network.LAN == "" && len(c.NAT.Interfaces) == 0 {
			v.Add("nat.interfaces", SeverityWarning,
				"NAT is enabled but no LAN interface is identified yet; plans will show NAT as pending until one is set")
		}
		for i, iface := range c.NAT.Interfaces {
			if iface == "" {
				v.Add(fmt.Sprintf("nat.interfaces[%d]", i), SeverityError, "interface name must not be empty")
			}
			if iface == c.Network.WAN {
				v.Add(fmt.Sprintf("nat.interfaces[%d]", i), SeverityError,
					"cannot masquerade traffic from the WAN interface")
			}
		}
	}

	// The masquerade outbound must name something. It accepts a logical role
	// or a literal interface, so which of the two was written is not knowable
	// here without importing the role vocabulary this package deliberately
	// sits below; that resolution belongs to the gateway intent layer, which
	// already owns the role system.
	//
	// What IS knowable here is that an empty outbound is never valid, and that
	// masquerading out of the LAN is a routing loop. Both are checked because
	// they are document-internal contradictions: no host inspection is needed
	// to see that rewriting source addresses on every interface — including
	// the LAN — breaks LAN-to-LAN traffic in a way that presents as
	// intermittent hardware failure.
	if c.NAT.Enabled && c.NAT.Masquerade.Enabled {
		switch out := strings.TrimSpace(c.NAT.Masquerade.Outbound); {
		case out == "":
			v.Add("nat.masquerade.outbound", SeverityError,
				"masquerading is enabled with no outbound interface, so source addresses "+
					"would be rewritten on every interface including the LAN; "+
					`set nat.masquerade.outbound to the "wan" role, or to the uplink interface`)
		case c.Network.LAN != "" && out == c.Network.LAN:
			v.Add("nat.masquerade.outbound", SeverityError,
				fmt.Sprintf("masqueraded traffic must leave through the WAN, not the LAN (%s); "+
					`set nat.masquerade.outbound to the "wan" role`, out))
		case c.Network.Management != "" && (out == c.Network.Management || out == "mgmt"):
			v.Add("nat.masquerade.outbound", SeverityError,
				fmt.Sprintf("masqueraded traffic must leave through the WAN, not the Management interface (%s); "+
					`set nat.masquerade.outbound to the "wan" role`, out))
		}
	}

	// --- Routing intent ---

	//
	// These checks are about the relationship between three independent
	// statements — the gateway is wanted, forwarding is wanted, NAT is wanted
	// — and about combinations that describe a machine that cannot do what
	// the document describes.
	//
	// They are deliberately not inferences in the other direction. A host
	// with forwarding already on does not thereby have it wanted; that value
	// was observed, and only this document says anything about what should
	// happen.
	if c.Gateway.Enabled && !c.Routing.IPv4Forwarding && c.Network.WAN != "" && c.Network.LAN != "" {
		// Forwarding off with both roles assigned is the shape of a bridge,
		// and it is a legitimate thing to want. What is not legitimate is
		// asking for it while also asking to masquerade LAN traffic, because
		// no LAN packet will ever reach the masquerade rule.
		if c.NAT.Enabled && c.NAT.Masquerade.Enabled {
			v.Add("routing.ipv4_forwarding", SeverityError,
				"NAT is enabled but IPv4 forwarding is disabled, so no LAN traffic "+
					"will ever reach the masquerade rule; "+
					"set routing.ipv4_forwarding to true, or disable NAT")
		}
	}

	// --- Firewall ---

	switch c.Firewall.Backend {
	case "":
		v.Add("firewall.backend", SeverityError, "must be set; supported backends: nftables")
	case "nftables":
	default:
		v.Add("firewall.backend", SeverityError,
			fmt.Sprintf("unsupported backend %q; supported backends: nftables", c.Firewall.Backend))
	}

	switch c.Firewall.DefaultInboundPolicy {
	case "", "accept", "drop":
	default:
		v.Add("firewall.default_inbound_policy", SeverityError,
			fmt.Sprintf("must be \"accept\" or \"drop\", got %q", c.Firewall.DefaultInboundPolicy))
	}

	if c.Firewall.Enabled && c.Firewall.DefaultInboundPolicy == "accept" {
		v.Add("firewall.default_inbound_policy", SeverityWarning,
			"an accept-by-default policy on a gateway provides little protection against unintended exposure")
	}

	// --- QoS ---

	// fq_codel is accepted as an explicit choice, not only as a fallback. An
	// operator who knows their kernel lacks CAKE, or who wants flow
	// separation without shaping, should be able to say so rather than have
	// the decision made for them. internal/qos reports it as rate-unaware
	// either way.
	switch c.QoS.Algorithm {
	case "":
		if c.QoS.Enabled {
			v.Add("qos.algorithm", SeverityError,
				"must be set when QoS is enabled; supported algorithms: cake, fq_codel")
		}
	case "cake", "fq_codel":
		if c.QoS.Algorithm == "fq_codel" && c.QoS.Enabled {
			// Not an error, and not a rule that should be worked around: it
			// says plainly what the operator is giving up.
			v.Add("qos.algorithm", SeverityWarning,
				"fq_codel is not rate-aware; it smooths bursts and controls the local queue but cannot "+
					"reduce bufferbloat on the bottleneck link. Use cake if latency under load is the problem")
		}
	default:
		v.Add("qos.algorithm", SeverityError,
			fmt.Sprintf("unsupported algorithm %q; supported algorithms: cake, fq_codel", c.QoS.Algorithm))
	}

	if c.QoS.Enabled {
		if c.QoS.Interface == "" {
			v.Add("qos.interface", SeverityError, "QoS is enabled but no shaping interface is set")
		}
		if c.QoS.DownloadKbps <= 0 {
			v.Add("qos.download_kbps", SeverityError,
				"must be a positive rate when QoS is enabled")
		}
		if c.QoS.UploadKbps <= 0 {
			v.Add("qos.upload_kbps", SeverityError,
				"must be a positive rate when QoS is enabled")
		}
		if c.QoS.DownloadKbps > 0 && c.QoS.UploadKbps > c.QoS.DownloadKbps {
			v.Add("qos.upload_kbps", SeverityWarning,
				fmt.Sprintf("upload rate (%d kbps) exceeds download rate (%d kbps), which is unusual for a WAN uplink",
					c.QoS.UploadKbps, c.QoS.DownloadKbps))
		}

		// Phase 2: Per-client policy and group validation
		seenClientIDs := make(map[string]bool)
		seenClientIPs := make(map[string]bool)
		var totalMinDown, totalMinUp int

		for i, client := range c.QoS.Clients {
			prefix := fmt.Sprintf("qos.clients[%d]", i)
			if client.ID == "" {
				v.Add(prefix+".id", SeverityError, "client id must not be empty")
			} else if seenClientIDs[client.ID] {
				v.Add(prefix+".id", SeverityError, fmt.Sprintf("duplicate client id %q", client.ID))
			} else {
				seenClientIDs[client.ID] = true
			}

			if client.IP == "" {
				v.Add(prefix+".ip", SeverityError, "client ip must not be empty")
			} else {
				if _, err := netip.ParseAddr(client.IP); err != nil {
					if _, err := netip.ParsePrefix(client.IP); err != nil {
						v.Add(prefix+".ip", SeverityError, fmt.Sprintf("invalid client ip or cidr %q", client.IP))
					}
				}
				if seenClientIPs[client.IP] {
					v.Add(prefix+".ip", SeverityError, fmt.Sprintf("duplicate client ip match %q", client.IP))
				} else {
					seenClientIPs[client.IP] = true
				}
			}

			if client.DownloadKbps <= 0 {
				v.Add(prefix+".download_kbps", SeverityError, "client download_kbps must be positive")
			}
			if client.UploadKbps <= 0 {
				v.Add(prefix+".upload_kbps", SeverityError, "client upload_kbps must be positive")
			}
			if client.MinDownloadKbps < 0 {
				v.Add(prefix+".min_download_kbps", SeverityError, "min_download_kbps cannot be negative")
			}
			if client.MinUploadKbps < 0 {
				v.Add(prefix+".min_upload_kbps", SeverityError, "min_upload_kbps cannot be negative")
			}
			if client.MinDownloadKbps > 0 && client.MinDownloadKbps > client.DownloadKbps {
				v.Add(prefix+".min_download_kbps", SeverityError, "min_download_kbps cannot exceed download_kbps")
			}
			if client.MinUploadKbps > 0 && client.MinUploadKbps > client.UploadKbps {
				v.Add(prefix+".min_upload_kbps", SeverityError, "min_upload_kbps cannot exceed upload_kbps")
			}
			if client.Priority != "" {
				switch strings.ToLower(client.Priority) {
				case "critical", "high", "normal", "low":
				default:
					v.Add(prefix+".priority", SeverityError, fmt.Sprintf("invalid priority %q; must be critical, high, normal, or low", client.Priority))
				}
			}

			totalMinDown += client.MinDownloadKbps
			totalMinUp += client.MinUploadKbps
		}

		if c.QoS.DownloadKbps > 0 && totalMinDown > c.QoS.DownloadKbps {
			v.Add("qos.clients", SeverityError, fmt.Sprintf("sum of guaranteed client download rates (%d kbps) exceeds total link download capacity (%d kbps)", totalMinDown, c.QoS.DownloadKbps))
		}
		if c.QoS.UploadKbps > 0 && totalMinUp > c.QoS.UploadKbps {
			v.Add("qos.clients", SeverityError, fmt.Sprintf("sum of guaranteed client upload rates (%d kbps) exceeds total link upload capacity (%d kbps)", totalMinUp, c.QoS.UploadKbps))
		}
	}

	// --- Paths ---

	if c.Paths.StateDB == "" {
		v.Add("paths.state_db", SeverityError, "must be set")
	} else if dir := filepath.Dir(c.Paths.StateDB); dir != "" {
		// Only a warning: the directory may legitimately not exist yet on a
		// freshly imaged device, and thnd creates it on first start.
		if st, err := os.Stat(dir); err == nil && !st.IsDir() {
			v.Add("paths.state_db", SeverityError,
				fmt.Sprintf("parent path %s exists but is not a directory", dir))
		}
	}

	if c.Paths.Socket == "" {
		v.Add("paths.socket", SeverityError, "must be set")
	} else if !strings.HasPrefix(c.Paths.Socket, "/") && !strings.Contains(c.Paths.Socket, "://") {
		v.Add("paths.socket", SeverityError, "must be an absolute path to a Unix domain socket")
	}

	// --- Logging ---

	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		v.Add("logging.level", SeverityError,
			fmt.Sprintf("must be one of debug, info, warn, error; got %q", c.Logging.Level))
	}

	switch c.Logging.Format {
	case "json", "text":
	default:
		v.Add("logging.format", SeverityError,
			fmt.Sprintf("must be json or text; got %q", c.Logging.Format))
	}

	if c.Logging.Retention < 0 {
		v.Add("logging.retention", SeverityError, "must not be negative")
	}
	if c.Logging.MaxEvents < 0 {
		v.Add("logging.max_events", SeverityError, "must not be negative")
	}

	// --- Activation ---

	if c.Activation.HealthCheckInterval < 0 {
		v.Add("activation.health_check_interval", SeverityError, "must not be negative")
	}
	if !c.Activation.RequirePhysicalPresence {
		v.Add("activation.require_physical_presence", SeverityError,
			"must remain true: THN is developed remotely against an unattended device, so root access alone must not be sufficient to activate")
	}

	// --- Activation development overrides ---

	dev := c.Activation.Development

	// A blanket relaxation is refused rather than accepted-and-ignored.
	//
	// If this were only a warning, the document would load, the flag would
	// read as "development mode is on" in every report, and the adapters it
	// would have covered would still be rejected by the gate. That is the
	// worst of both outcomes: the operator believes a limit was lifted and
	// the gate disagrees, with nothing to explain the disagreement.
	if dev.AllowFastEthernetLAN && len(dev.ApprovedFastEthernetLAN) == 0 {
		v.Add("activation.development.approved_fast_ethernet_lan", SeverityError,
			"must name at least one interface when allow_fast_ethernet_lan is true; "+
				"an unnamed list would permit every Fast Ethernet adapter on the host, "+
				"which is the blanket bypass this setting exists to avoid. "+
				"Run `thn discover` and list the exact interface identity")
	}

	// A list with no flag is a contradiction, not a harmless leftover. It
	// reads as "these adapters were approved" and approves nothing.
	for _, id := range dev.ApprovedFastEthernetLAN {
		if !dev.AllowFastEthernetLAN {
			v.Add("activation.development.approved_fast_ethernet_lan", SeverityError,
				fmt.Sprintf("names %q but allow_fast_ethernet_lan is false; the list approves nothing. "+
					"Set allow_fast_ethernet_lan to true, or remove the entry", id))
		}
		if strings.TrimSpace(id) == "" {
			v.Add("activation.development.approved_fast_ethernet_lan", SeverityError,
				"must not contain an empty entry")
		}
	}

	if dev.AllowFastEthernetLAN && len(dev.ApprovedFastEthernetLAN) > 0 {
		v.Add("activation.development", SeverityWarning,
			"DEVELOPMENT MODE: a Fast Ethernet LAN adapter has been approved by name. "+
				"LAN throughput is capped at 100 Mbps and this configuration is NOT approved "+
				"for production deployment. Set allow_fast_ethernet_lan to false to restore "+
				"production policy")
	}

	// --- Management ---
	if c.Management.WANAccess {
		v.Add("management.wan_access", SeverityError,
			"WAN access to management service is strictly prohibited by safety policy")
	}

	// --- Networks (VLAN and Isolation model) ---
	seenVLANs := make(map[int]string)
	seenNets := make(map[string]bool)
	for idx, net := range c.Networks {
		field := fmt.Sprintf("networks[%d]", idx)
		if strings.TrimSpace(net.ID) == "" {
			v.Add(field+".id", SeverityError, "network id must not be empty")
		} else if seenNets[net.ID] {
			v.Add(field+".id", SeverityError, fmt.Sprintf("duplicate network id %q", net.ID))
		}
		seenNets[net.ID] = true

		if net.VLANID < 0 || net.VLANID > 4094 {
			v.Add(field+".vlan_id", SeverityError, fmt.Sprintf("VLAN ID %d out of valid range (0-4094)", net.VLANID))
		} else if net.VLANID > 0 {
			if prev, ok := seenVLANs[net.VLANID]; ok {
				v.Add(field+".vlan_id", SeverityError, fmt.Sprintf("VLAN ID %d already assigned to network %q", net.VLANID, prev))
			}
			seenVLANs[net.VLANID] = net.ID
		}

		if net.Subnet != "" {
			pfx, err := netip.ParsePrefix(net.Subnet)
			if err != nil {
				v.Add(field+".subnet", SeverityError, fmt.Sprintf("invalid subnet CIDR %q", net.Subnet))
			} else if net.Gateway != "" {
				gw, err := netip.ParseAddr(net.Gateway)
				if err != nil {
					v.Add(field+".gateway", SeverityError, fmt.Sprintf("invalid gateway IP %q", net.Gateway))
				} else if !pfx.Contains(gw) {
					v.Add(field+".gateway", SeverityError, fmt.Sprintf("gateway %s is outside subnet %s", gw, pfx))
				}
			}
		}
	}

	return v
}
