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

	"github.com/venth/thn-gateway/internal/policy"
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

	// Network describes intended interface roles and addressing.
	Network NetworkConfig `yaml:"network"`

	// NAT controls masquerading intent.
	NAT NATConfig `yaml:"nat"`

	// Firewall controls filtering intent.
	Firewall FirewallConfig `yaml:"firewall"`

	// QoS controls traffic shaping intent.
	QoS QoSConfig `yaml:"qos"`

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

// GatewayConfig holds gateway identity.
type GatewayConfig struct {
	// Name is the logical gateway name, reported by `thn status`.
	Name string `yaml:"name"`

	// Generation is the operator-managed configuration generation counter.
	// Every accepted configuration increments it, giving plans and
	// activations a monotonic identifier to refer back to.
	Generation uint64 `yaml:"generation"`
}

// NetworkConfig describes intended interface roles.
type NetworkConfig struct {
	// WAN is the uplink interface name, e.g. "enp0s31f6".
	WAN string `yaml:"wan"`

	// LAN is the downstream interface name, e.g. "enx001122334455".
	// Empty means "not yet identified", which is the expected state while
	// THN is being developed against hardware that is not present.
	LAN string `yaml:"lan"`

	// LANPrefix is the address to place on the LAN interface.
	LANPrefix string `yaml:"lan_prefix"`

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
		},
		Network: NetworkConfig{
			WAN:       "enp0s31f6",
			LAN:       "",
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
		DHCP: DHCPConfig{
			// DHCP is on by default: a gateway that does not serve
			// addresses on its own LAN is not usable out of the box.
			//
			// Authoritative is deliberately true. Without it a client that
			// cannot reach this server falls back to the upstream, so a
			// device could obtain an address from the ISP network and
			// bypass this gateway entirely — including its firewall.
			Enabled:       true,
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
			Enabled: true,
			// Upstream is deliberately EMPTY by default.
			//
			// dns.upstream is the authoritative list for the DNS service, but
			// populating it here would make every document that set
			// network.dns — which is most of them, and is the older field —
			// disagree with itself. Setting both by default made the two
			// fields conflict for reasons no operator had done anything to
			// cause.
			//
			// An empty list falls back to network.dns, which is populated
			// below. A document that wants the DNS service to forward
			// somewhere other than the host's own resolvers sets this.
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
	c.Firewall.Backend = strings.ToLower(strings.TrimSpace(c.Firewall.Backend))
	c.Firewall.DefaultInboundPolicy = strings.ToLower(strings.TrimSpace(c.Firewall.DefaultInboundPolicy))
	c.QoS.Algorithm = strings.ToLower(strings.TrimSpace(c.QoS.Algorithm))
	c.Network.WAN = strings.TrimSpace(c.Network.WAN)
	c.Network.LAN = strings.TrimSpace(c.Network.LAN)
	c.Network.LANPrefix = strings.TrimSpace(c.Network.LANPrefix)

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

	// --- Network ---

	if c.Network.WAN == "" {
		v.Add("network.wan", SeverityError,
			"must name the uplink interface, e.g. \"enp0s31f6\"")
	}
	if c.Network.LAN != "" && c.Network.LAN == c.Network.WAN {
		v.Add("network.lan", SeverityError,
			"LAN and WAN must be different interfaces")
	}

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
		case prefix.Addr().Is4() && prefix.Bits() > 29:
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
		} else if c.Network.LANPrefix != "" {
			// A default route pointing back into the downstream segment is a
			// routing loop, and it was only caught by internal/validation —
			// so `thn config validate` passed a document `thn validate`
			// rejected. The two layers must not answer differently about one
			// file, which is the same dual-modelling trap the gate catches in
			// forwarding and NAT.
			if prefix, perr := netip.ParsePrefix(c.Network.LANPrefix); perr == nil &&
				prefix.Contains(upstream) {
				v.Add("network.upstream_gateway", SeverityError,
					fmt.Sprintf("the upstream gateway %s is inside the LAN prefix %s; "+
						"the default route must leave through the WAN, not back into the LAN",
						upstream, prefix))
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

	return v
}
