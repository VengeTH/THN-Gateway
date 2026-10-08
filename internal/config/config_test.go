package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// namedDefaults is the compiled defaults plus the one thing a document cannot
// derive: which physical connection is the uplink.
//
// Most tests here are about a rule unrelated to interface selection — a LAN
// prefix, a DHCP range, a firewall backend. Building them on raw Defaults()
// would make each of them depend on a rule it is not testing, and would have
// hidden the fact that removing the hardware default was a behaviour change.
func namedDefaults() Config {
	cfg := Defaults()
	cfg.Network.WAN = "eth0"
	return cfg
}

// TestDefaultsNameNoInterface is the device-independence rule, in the one
// place it is easiest to break.
//
// Defaults() used to set network.wan to "enp0s31f6" — a kernel interface
// name copied from the development machine. Every configuration derived from
// those defaults therefore asserted that the host owned a NIC by that name,
// which was false on every machine but one.
//
// Nothing in THN may reintroduce a hardware name into the compiled defaults.
// The assertion is over the whole document, not just the WAN, because the next
// person to add one would add it somewhere else.
func TestDefaultsNameNoInterface(t *testing.T) {
	cfg := Defaults()

	hardwareNames := []string{"enp0s31f6", "enp1s0", "eth0", "eth1", "wlp2s0", "wlan0"}
	fields := map[string]string{
		"network.wan":             cfg.Network.WAN,
		"network.lan":             cfg.Network.LAN,
		"nat.masquerade.outbound": cfg.NAT.Masquerade.Outbound,
		"qos.interface":           cfg.QoS.Interface,
	}
	for field, value := range fields {
		for _, name := range hardwareNames {
			if strings.Contains(value, name) {
				t.Errorf("compiled default %s = %q names the hardware interface %q",
					field, value, name)
			}
		}
	}
}

// TestDefaultsAreValidOnceAnUplinkIsNamed states the contract honestly.
//
// The compiled defaults are NOT a complete configuration, and cannot be: the
// one thing they cannot supply is which physical connection is the internet
// one. That is a fact about the machine, not about the document, and a
// document cannot guess it.
//
// So the defaults must be valid once the operator has answered that question,
// and must otherwise report exactly that one thing as missing — not a
// scattering of unrelated errors that hide it.
func TestDefaultsAreValidOnceAnUplinkIsNamed(t *testing.T) {
	cfg := Defaults()
	cfg.Network.WAN = "eth0" // any selector the operator might legitimately choose
	if v := cfg.Validate(); v.HasErrors() {
		t.Errorf("defaults plus an uplink must be valid, got:")
		for _, f := range v.Findings {
			if f.Severity == SeverityError {
				t.Errorf("  %s", f)
			}
		}
	}

	// And with no uplink, the operator is told precisely that, and only that.
	empty := Defaults().Validate()
	if !hasField(empty, "network.wan", SeverityError) {
		t.Error("a document that names no uplink must be told to name one")
	}
	for _, f := range empty.Findings {
		if f.Severity != SeverityError {
			continue
		}
		if f.Field != "network.wan" {
			t.Errorf("unexpected extra error on %s: %s", f.Field, f.Message)
		}
	}
}

func TestDefaultsDeriveStateDBFromStateDir(t *testing.T) {
	cfg := Defaults()
	cfg.Paths.StateDB = ""
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := filepath.Join(cfg.Paths.StateDir, "state.db")
	if cfg.Paths.StateDB != want {
		t.Errorf("StateDB = %q, want %q", cfg.Paths.StateDB, want)
	}
}

func TestNormalizeDerivesNATInterface(t *testing.T) {
	cfg := Defaults()
	cfg.Network.LAN = "enx001122334455"
	cfg.NAT.Enabled = true
	cfg.NAT.Interfaces = nil

	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(cfg.NAT.Interfaces) != 1 || cfg.NAT.Interfaces[0] != cfg.Network.LAN {
		t.Errorf("NAT.Interfaces = %v, want [%s]", cfg.NAT.Interfaces, cfg.Network.LAN)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// "wan_interface" is a plausible guess at the key name, but the real key
	// is "wan". Silent acceptance would produce a gateway quietly pointing at
	// the wrong interface.
	doc := "network:\n  wan_interface: enp0s31f6\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted an unknown key, want error")
	}
	if !strings.Contains(err.Error(), "wan_interface") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	if cfg.Gateway.Name != Defaults().Gateway.Name {
		t.Errorf("missing file should yield defaults, got name %q", cfg.Gateway.Name)
	}
}

func TestLoadAppliesFileOverDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	doc := "gateway:\n  name: edge-01\nnetwork:\n  wan: eth9\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Gateway.Name != "edge-01" {
		t.Errorf("name = %q, want edge-01", cfg.Gateway.Name)
	}
	if cfg.Network.WAN != "eth9" {
		t.Errorf("wan = %q, want eth9", cfg.Network.WAN)
	}
	// Untouched keys must retain their defaults.
	if cfg.Firewall.Backend != "nftables" {
		t.Errorf("firewall.backend = %q, want the default nftables", cfg.Firewall.Backend)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("network:\n  wan: from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("THN_WAN", "from-env")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Network.WAN != "from-env" {
		t.Errorf("wan = %q, want from-env (env must beat file)", cfg.Network.WAN)
	}
}

func TestEnvOverridesStatePaths(t *testing.T) {
	t.Setenv("THN_STATE_DB", filepath.Join(t.TempDir(), "custom.db"))
	t.Setenv("THN_SOCKET", "/tmp/custom.sock")

	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.HasSuffix(cfg.Paths.StateDB, "custom.db") {
		t.Errorf("StateDB = %q, want custom.db", cfg.Paths.StateDB)
	}
	if cfg.Paths.Socket != "/tmp/custom.sock" {
		t.Errorf("Socket = %q, want /tmp/custom.sock", cfg.Paths.Socket)
	}
}

func TestWriteRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")

	original := Defaults()
	original.Gateway.Name = "round-trip"
	original.Logging.Retention = 3 * time.Hour

	if err := original.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Gateway.Name != original.Gateway.Name {
		t.Errorf("name = %q, want %q", loaded.Gateway.Name, original.Gateway.Name)
	}
	if loaded.Logging.Retention != original.Logging.Retention {
		t.Errorf("retention = %v, want %v", loaded.Logging.Retention, original.Logging.Retention)
	}
}

// TestWriteUsesRestrictivePermissions documents the trust decision that the
// config file is 0600: it describes the gateway topology.
func TestWriteUsesRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")

	if err := Defaults().Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode = %o, want 600", perm)
	}
}

func TestValidateRejectsBadLANPrefix(t *testing.T) {
	cases := []struct {
		prefix string
		field  string
	}{
		{"10.77.0.1", "network.lan_prefix"},   // missing prefix length
		{"not-an-ip", "network.lan_prefix"},   // unparseable
		{"127.0.0.1/8", "network.lan_prefix"}, // loopback
		{"0.0.0.0/0", "network.lan_prefix"},   // unspecified
		{"224.0.0.0/4", "network.lan_prefix"}, // multicast
	}
	for _, c := range cases {
		cfg := Defaults()
		cfg.Network.LANPrefix = c.prefix
		v := cfg.Validate()
		if !hasField(v, c.field, SeverityError) {
			t.Errorf("prefix %q: want error on %s", c.prefix, c.field)
		}
	}
}

func TestValidateRejectsLANEqualToWAN(t *testing.T) {
	cfg := Defaults()
	cfg.Network.WAN = "eth0"
	cfg.Network.LAN = cfg.Network.WAN
	v := cfg.Validate()
	if !hasField(v, "network.lan", SeverityError) {
		t.Error("LAN equal to WAN must be an error")
	}
}

func TestValidateNATWithoutLANIsWarningNotError(t *testing.T) {
	// This is the expected state during remote development: NAT is enabled by
	// intent, but no LAN interface has been identified because the hardware is
	// not attached. That is incomplete, not incoherent.
	cfg := Defaults()
	cfg.NAT.Enabled = true
	cfg.Network.LAN = ""
	cfg.NAT.Interfaces = nil
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	v := cfg.Validate()
	if !hasField(v, "nat.interfaces", SeverityWarning) {
		t.Error("NAT without a LAN interface should warn")
	}
	if hasField(v, "nat.interfaces", SeverityError) {
		t.Error("NAT without a LAN interface must not be an error; the LAN is simply not attached yet")
	}
}

func TestValidateNATCannotMasqueradeFromWAN(t *testing.T) {
	// Naming the WAN explicitly as a masquerade source is incoherent and must
	// remain an error.
	cfg := Defaults()
	cfg.NAT.Enabled = true
	cfg.Network.LAN = "enx001122334455"
	cfg.NAT.Interfaces = []string{cfg.Network.WAN}

	v := cfg.Validate()
	if !hasField(v, "nat.interfaces[0]", SeverityError) {
		t.Error("masquerading from the WAN interface must be an error")
	}
}

func TestValidateRejectsUnsupportedBackendAndAlgorithm(t *testing.T) {
	cfg := Defaults()
	cfg.Firewall.Backend = "iptables"
	cfg.QoS.Algorithm = "htb"

	v := cfg.Validate()
	if !hasField(v, "firewall.backend", SeverityError) {
		t.Error("unsupported firewall backend must be an error")
	}
	if !hasField(v, "qos.algorithm", SeverityError) {
		t.Error("unsupported qos algorithm must be an error")
	}
}

func TestValidateRejectsNonPositiveQoSRates(t *testing.T) {
	cfg := Defaults()
	cfg.QoS.Enabled = true
	cfg.QoS.DownloadKbps = 0
	cfg.QoS.UploadKbps = 0
	cfg.QoS.Interface = "enp0s31f6"

	v := cfg.Validate()
	if !hasField(v, "qos.download_kbps", SeverityError) {
		t.Error("zero download rate with QoS enabled must be an error")
	}
	if !hasField(v, "qos.upload_kbps", SeverityError) {
		t.Error("zero upload rate with QoS enabled must be an error")
	}
}

func TestValidateRejectsBadLogSettings(t *testing.T) {
	cfg := Defaults()
	cfg.Logging.Level = "verbose"
	cfg.Logging.Format = "xml"

	v := cfg.Validate()
	if !hasField(v, "logging.level", SeverityError) {
		t.Error("invalid log level must be an error")
	}
	if !hasField(v, "logging.format", SeverityError) {
		t.Error("invalid log format must be an error")
	}
}

func TestValidateRejectsRelativeSocket(t *testing.T) {
	cfg := Defaults()
	cfg.Paths.Socket = "thnd.sock"

	v := cfg.Validate()
	if !hasField(v, "paths.socket", SeverityError) {
		t.Error("relative socket path must be an error")
	}
}

func TestValidateRejectsSchemaMismatch(t *testing.T) {
	cfg := Defaults()
	cfg.SchemaVersion = SchemaVersion + 99

	v := cfg.Validate()
	if !hasField(v, "schema_version", SeverityError) {
		t.Error("unknown schema version must be an error")
	}
}

// TestValidateRequiresPhysicalPresence locks in the safety default. If this
// ever becomes settable to false by configuration, an operator with remote
// root could activate a gateway on hardware they cannot reach.
func TestValidateRequiresPhysicalPresence(t *testing.T) {
	cfg := Defaults()
	cfg.Activation.RequirePhysicalPresence = false

	v := cfg.Validate()
	if !hasField(v, "activation.require_physical_presence", SeverityError) {
		t.Error("disabling the physical-presence gate must be an error")
	}
}

// TestValidateRejectsManagementWANAccess locks in the rule that WAN access
// to the management API cannot be enabled.
func TestValidateRejectsManagementWANAccess(t *testing.T) {
	cfg := Defaults()
	cfg.Management.WANAccess = true

	v := cfg.Validate()
	if !hasField(v, "management.wan_access", SeverityError) {
		t.Error("enabling management.wan_access must fail validation with an error")
	}
}

func TestValidateAcceptsFullySpecifiedGateway(t *testing.T) {
	cfg := Defaults()
	cfg.Network.WAN = "enp0s31f6"
	cfg.Network.LAN = "enx001122334455"
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.QoS.Enabled = true
	cfg.QoS.DownloadKbps = 100_000
	cfg.QoS.UploadKbps = 20_000
	cfg.QoS.Interface = "enp0s31f6"

	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	if v := cfg.Validate(); v.HasErrors() {
		t.Errorf("a fully specified gateway must validate, got:")
		for _, f := range v.Findings {
			t.Errorf("  %s", f)
		}
	}
}

// hasField reports whether v contains a finding for field at severity.
func hasField(v ValidationResult, field string, sev Severity) bool {
	for _, f := range v.Findings {
		if f.Field == field && f.Severity == sev {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------ LAN prefix

// The empty case, which had no coverage and no finding at all.
//
// LANPrefix is the address THN would place on the LAN interface, so an empty
// one is the single fact behind a dozen pending steps. The LAN interface
// itself may not be identified yet, which makes this incomplete rather than
// incoherent — it warns, it does not error. What it must never do is pass
// without a word.
func TestEmptyLANPrefixIsReportedNotSilent(t *testing.T) {
	cases := []struct {
		name string
		cfg  func(*Config)
	}{
		{"LAN identified", func(c *Config) { c.Network.LAN = "enx001122334455" }},
		{"LAN not identified", func(c *Config) { c.Network.LAN = "" }},
		{"no resolvers either", func(c *Config) {
			c.Network.LAN = ""
			c.Network.DNS = nil
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := namedDefaults()
			c.cfg(&cfg)
			cfg.Network.LANPrefix = ""

			v := cfg.Validate()

			if !hasField(v, "network.lan_prefix", SeverityWarning) {
				t.Errorf("an empty LAN prefix must warn on network.lan_prefix, got %v", v.Findings)
			}
			if v.HasErrors() {
				t.Errorf("an empty LAN prefix is pending, not invalid; got errors %v", v.Findings)
			}
		})
	}
}

// The shipped document clears nothing, but a document that clears both the LAN
// and its address is a real state: absent, not broken.
func TestAnEmptyLANPrefixDoesNotBlockAUsableConfig(t *testing.T) {
	cfg := namedDefaults()
	cfg.Network.LAN = ""
	cfg.Network.LANPrefix = ""
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}

	if v := cfg.Validate(); v.HasErrors() {
		t.Errorf("an unbuilt gateway must still validate, got: %v", v.Findings)
	}
}

// Host bits are required here, and rejecting them would be wrong.
//
// Unlike a network address, LANPrefix names the address THN assigns to the LAN
// interface — 10.77.0.1/24, gateway host bits set and all. A rule borrowed
// from tools that want a masked network would reject the one correct value.
func TestLANPrefixAcceptsAGatewayAddressWithHostBits(t *testing.T) {
	for _, prefix := range []string{"10.77.0.1/24", "192.168.1.1/16", "172.16.0.1/20"} {
		cfg := namedDefaults()
		cfg.Network.LANPrefix = prefix

		if v := cfg.Validate(); v.HasErrors() {
			t.Errorf("prefix %q must be valid, got %v", prefix, v.Findings)
		}
	}
}

// A LAN is expected to be private or ULA. A public one is legal and routes, so
// it warns in internal/validation; this layer must not turn it into an error,
// and must not stay silent about it either.
func TestAPublicLANPrefixWarnsButDoesNotError(t *testing.T) {
	cfg := namedDefaults()
	cfg.Network.LANPrefix = "203.0.113.1/24"

	v := cfg.Validate()

	if v.HasErrors() {
		t.Errorf("a public LAN prefix must not be an error, got %v", v.Findings)
	}
}

// IPv6 is parsed by the same field, so it must be exercised rather than assumed.
func TestIPv6LANPrefixesAreAccepted(t *testing.T) {
	cfg := namedDefaults()
	cfg.Network.LANPrefix = "fd00::1/64"

	v := cfg.Validate()

	if v.HasErrors() {
		t.Errorf("a ULA LAN prefix must be valid, got %v", v.Findings)
	}
	// A /64 leaves more addresses than are worth counting, so the narrow-prefix
	// warning must not fire on the arithmetic overflowing.
	if hasField(v, "network.lan_prefix", SeverityWarning) {
		t.Errorf("a /64 must not be reported as too narrow: %v", v.Findings)
	}
}

// The narrow-prefix threshold has to agree between this layer and
// internal/validation, which re-runs config.Validate and then adds findings of
// its own. The two disagreed at /30: this layer thought four addresses were
// enough, the other thought otherwise, and `thn config validate` and
// `thn validate` printed different verdicts for one document.
func TestNarrowLANPrefixThresholdAgreesWithValidation(t *testing.T) {
	for _, prefix := range []string{"10.77.0.1/30", "10.77.0.1/31", "10.77.0.1/32"} {
		cfg := Defaults()
		cfg.Network.LANPrefix = prefix

		v := cfg.Validate()

		if !hasField(v, "network.lan_prefix", SeverityWarning) {
			t.Errorf("prefix %q: want a warning about the number of usable addresses, got %v",
				prefix, v.Findings)
		}
	}
}

func TestAReasonableLANPrefixDoesNotWarnAboutSize(t *testing.T) {
	cfg := Defaults()
	cfg.Network.LANPrefix = "10.77.0.1/24"

	if hasField(cfg.Validate(), "network.lan_prefix", SeverityWarning) {
		t.Error("a /24 is a normal LAN and must not warn about size")
	}
}

// Overlapping WAN and LAN is the incoherence that matters most: the gateway
// would route the internet into its own downstream segment.
func TestUpstreamGatewayInsideTheLANIsRejected(t *testing.T) {
	cfg := Defaults()
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.Network.UpstreamGateway = "10.77.0.99"

	if !hasField(cfg.Validate(), "network.upstream_gateway", SeverityError) {
		t.Error("a default route pointing into the LAN must be an error")
	}
}

func TestUpstreamGatewayOutsideTheLANIsAccepted(t *testing.T) {
	cfg := namedDefaults()
	cfg.Network.LANPrefix = "10.77.0.1/24"
	cfg.Network.UpstreamGateway = "203.0.113.1"

	if v := cfg.Validate(); v.HasErrors() {
		t.Errorf("an upstream gateway outside the LAN is the normal case, got %v", v.Findings)
	}
}
