package management

import (
	"time"
)

// GatewayStatus represents the normalized top-level gateway state.
type GatewayStatus struct {
	Hostname        string    `json:"hostname"`
	Version         string    `json:"version"`
	Uptime          string    `json:"uptime"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	ActivationState string    `json:"activation_state"` // PREPARE, VALIDATED, GATED, ACTIVE
	ReadinessState  string    `json:"readiness_state"`  // READY, READY_WITH_WARNINGS, BLOCKED
	HealthState     string    `json:"health_state"`     // healthy, degraded, unhealthy, unknowable
	InternetStatus  string    `json:"internet_status"`  // online, degraded, offline, unknowable
	WANStatus       string    `json:"wan_status"`       // up, down, unassigned
	ActiveClients   int       `json:"active_clients"`
	TotalClients    int       `json:"total_clients"`
	QoSStatus       string    `json:"qos_status"`       // enabled, disabled
	FirewallStatus  string    `json:"firewall_status"`  // active, unmanaged
	NATStatus       string    `json:"nat_status"`       // active, disabled
	ClientIsolation string    `json:"client_isolation"` // enabled, partial, disabled
	ObservedAt      time.Time `json:"observed_at"`
}

// SystemMetrics captures host CPU, memory, disk and hardware vitals.
type SystemMetrics struct {
	CPUUsagePercent       float64    `json:"cpu_usage_percent"` // -1 when unknown
	CPULoadAverage        [3]float64 `json:"cpu_load_average"`
	MemoryUsedBytes       uint64     `json:"memory_used_bytes"`
	MemoryAvailableBytes  uint64     `json:"memory_available_bytes"`
	MemoryTotalBytes      uint64     `json:"memory_total_bytes"`
	StorageUsedBytes      uint64     `json:"storage_used_bytes"`
	StorageAvailableBytes uint64     `json:"storage_available_bytes"`
	StorageTotalBytes     uint64     `json:"storage_total_bytes"`
	TemperatureCelsius    float64    `json:"temperature_celsius"` // -1 when unknown
	Status                string     `json:"status"`              // healthy, warning, critical, unknown
}

// InterfaceMonitoring represents an interface with role and telemetry.
type InterfaceMonitoring struct {
	Name      string   `json:"name"`      // kernel name e.g. enp0s31f6
	StableID  string   `json:"stable_id"` // hw:...
	Role      string   `json:"role"`      // WAN, LAN, MGMT, GUEST, DMZ, UNASSIGNED
	State     string   `json:"state"`     // up, down, unknown
	Physical  bool     `json:"physical"`
	SpeedMbps int      `json:"speed_mbps"`
	Duplex    string   `json:"duplex"` // full, half, unknown
	IPv4      []string `json:"ipv4"`
	IPv6      []string `json:"ipv6"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
	RxErrors  uint64   `json:"rx_errors"`
	TxErrors  uint64   `json:"tx_errors"`
	RxDrops   uint64   `json:"rx_drops"`
	TxDrops   uint64   `json:"tx_drops"`
	Driver    string   `json:"driver,omitempty"`
}

// WANHealth captures uplink quality and gateway connectivity.
type WANHealth struct {
	LinkUp            bool     `json:"link_up"`
	InterfaceName     string   `json:"interface_name"`
	StableID          string   `json:"stable_id"`
	GatewayIP         string   `json:"gateway_ip"`
	GatewayReachable  bool     `json:"gateway_reachable"`
	InternetReachable bool     `json:"internet_reachable"`
	DNSServers        []string `json:"dns_servers"`
	DNSReachable      bool     `json:"dns_reachable"`
	LatencyMs         float64  `json:"latency_ms"`      // -1 if unmeasured
	PacketLossPct     float64  `json:"packet_loss_pct"` // -1 if unmeasured
	RxThroughputBps   uint64   `json:"rx_throughput_bps"`
	TxThroughputBps   uint64   `json:"tx_throughput_bps"`
	Status            string   `json:"status"` // online, degraded, offline, unknown
}

// ClientDevice represents a network client with policy and status.
type ClientDevice struct {
	ID              string    `json:"id"`
	MAC             string    `json:"mac"`
	IPv4            string    `json:"ipv4"`
	IPv6            string    `json:"ipv6,omitempty"`
	Hostname        string    `json:"hostname"`
	Interface       string    `json:"interface"`
	NetworkID       string    `json:"network_id"`
	LogicalGroup    string    `json:"logical_group"` // family, neighbor, guest, management, unknown
	Online          bool      `json:"online"`
	LastSeen        time.Time `json:"last_seen"`
	LeaseExpires    time.Time `json:"lease_expires,omitempty"`
	RxBytes         uint64    `json:"rx_bytes"`
	TxBytes         uint64    `json:"tx_bytes"`
	CurrentRxBps    uint64    `json:"current_rx_bps"`
	CurrentTxBps    uint64    `json:"current_tx_bps"`
	QoSPolicy       string    `json:"qos_policy,omitempty"`

	// QoSDirection names which direction the recorded limit constrains:
	// "both", "download" or "upload". Download and upload are shaped by two
	// separate disciplines on two interfaces, so a limit that does not say
	// which one it means cannot be checked against the kernel.
	QoSDirection string `json:"qos_direction,omitempty"`

	// QoSDownloadMbps and QoSUploadMbps are the configured ceilings, or zero
	// when that direction is not limited. They are reported separately rather
	// than as one number because a download-only limit is a real and common
	// configuration, and collapsing it into a single figure loses that.
	QoSDownloadMbps int `json:"qos_download_mbps,omitempty"`
	QoSUploadMbps   int `json:"qos_upload_mbps,omitempty"`

	IsolationStatus string    `json:"isolation_status"` // isolated, standard
	Blocked         bool      `json:"blocked"`
	Notes           string    `json:"notes,omitempty"`
}

// QoSStatusSummary models the operational state of QoS and client tiers.
type QoSStatusSummary struct {
	Enabled                bool              `json:"enabled"`
	Algorithm              string            `json:"algorithm"`
	Interface              string            `json:"interface"`
	WanUploadCeilingKbps   int               `json:"wan_upload_ceiling_kbps"`
	WanDownloadCeilingKbps int               `json:"wan_download_ceiling_kbps"`
	OverheadPercent        int               `json:"overhead_percent"`
	ClientPolicies         []ClientQoSDetail `json:"client_policies"`
	TotalClientsShaped     int               `json:"total_clients_shaped"`
}

// ClientQoSDetail shows bandwidth allocations per client.
type ClientQoSDetail struct {
	ID                string  `json:"id"`
	IP                string  `json:"ip"`
	DownloadLimitKbps int     `json:"download_limit_kbps"`
	UploadLimitKbps   int     `json:"upload_limit_kbps"`
	MinDownloadKbps   int     `json:"min_download_kbps"`
	MinUploadKbps     int     `json:"min_upload_kbps"`
	Priority          string  `json:"priority"` // critical, high, normal, low
	Group             string  `json:"group,omitempty"`
	CurrentRxKbps     float64 `json:"current_rx_kbps"`
	CurrentTxKbps     float64 `json:"current_tx_kbps"`
}

// FirewallStatusSummary models current firewall and NAT operational status.
type FirewallStatusSummary struct {
	Active               bool     `json:"active"`
	Backend              string   `json:"backend"` // nftables
	THNTablePresent      bool     `json:"thn_table_present"`
	ForwardingState      string   `json:"forwarding_state"` // enabled, disabled
	DefaultInboundPolicy string   `json:"default_inbound_policy"`
	WanToLanPolicy       string   `json:"wan_to_lan_policy"` // drop, forward
	LanToWanPolicy       string   `json:"lan_to_wan_policy"` // accept
	ManagementProtected  bool     `json:"management_protected"`
	ProtectedServices    []string `json:"protected_services"` // SSH (22), Tailscale (41641), Web (8080)
	NATActive            bool     `json:"nat_active"`
	MasqueradingState    string   `json:"masquerading_state"` // active, disabled
}

// ManagementNetworkModel defines the dedicated THN management network concept.
type ManagementNetworkModel struct {
	Role            string   `json:"role"`    // MGMT
	Subnet          string   `json:"subnet"`  // 10.10.99.0/24
	Gateway         string   `json:"gateway"` // 10.10.99.1
	Access          string   `json:"access"`  // LAN only
	AllowedNetworks []string `json:"allowed_networks"`
	WanAccess       bool     `json:"wan_access"` // false (prohibited)
	BindAddress     string   `json:"bind_address"`
}

// NetworkZone represents a network segment / future VLAN zone.
type NetworkZone struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Role               string `json:"role"` // MGMT, LAN, GUEST, DMZ
	VLANID             int    `json:"vlan_id"`
	Subnet             string `json:"subnet"`
	Gateway            string `json:"gateway"`
	InternetAccess     bool   `json:"internet_access"`
	ClientIsolation    bool   `json:"client_isolation"`
	InterNetworkPolicy string `json:"inter_network_policy"` // isolated, restricted, open
	ActiveClients      int    `json:"active_clients"`
}

// DashboardEvent models an alert or state notification.
type DashboardEvent struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Severity     string    `json:"severity"` // info, warning, critical
	Category     string    `json:"category"` // network, security, qos, system, client, activation
	Message      string    `json:"message"`
	Source       string    `json:"source"`
	Acknowledged bool      `json:"acknowledged"`
	AckBy        string    `json:"ack_by,omitempty"`
	AckAt        string    `json:"ack_at,omitempty"`
}

// AuditEvent models a security log entry for operator actions.
type AuditEvent struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Role      string    `json:"role"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	Success   bool      `json:"success"`
}
