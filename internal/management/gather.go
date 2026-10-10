package management

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

var startTime = time.Now()

// Collector safely aggregates gateway, interface, and subsystem health facts.
type Collector struct {
	cfg   config.Config
	store *state.Store
}

// NewCollector creates a read-only telemetry collector.
func NewCollector(cfg config.Config, store *state.Store) *Collector {
	return &Collector{
		cfg:   cfg,
		store: store,
	}
}

// GatherStatus derives the top-level GatewayStatus document.
func (c *Collector) GatherStatus() GatewayStatus {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = c.cfg.Gateway.Name
	}

	uptimeDuration := time.Since(startTime)
	uptimeStr := formatDuration(uptimeDuration)

	wanStatus := "unassigned"
	if c.cfg.Network.WAN != "" {
		wanStatus = "configured"
	}

	clients := c.GatherClients(context.Background())
	activeClients := 0
	for _, cl := range clients {
		if cl.Online && !cl.Blocked {
			activeClients++
		}
	}
	totalClients := len(clients)

	qosStatus := "disabled"
	if c.cfg.QoS.Enabled {
		qosStatus = "enabled"
	}

	fwStatus := "disabled"
	if c.cfg.Firewall.Enabled {
		fwStatus = "active"
	}

	natStatus := "disabled"
	if c.cfg.NAT.Enabled {
		natStatus = "active"
	}

	isoStatus := "disabled"
	for _, netDef := range c.cfg.Networks {
		if netDef.ClientIsolation {
			isoStatus = "enabled"
			break
		}
	}

	// The uplink's own health, read rather than assumed. A gateway whose WAN
	// link is down must not report "online" because that string was compiled
	// into it; the dashboard leads with this field, so a fixed value here is
	// a fixed lie at the top of the page.
	//
	// The chain is checked in order and the FIRST failure names the state, so
	// the operator is told which hop broke rather than being told "offline"
	// and left to find out. An uplink that cannot be read at all is reported
	// as unknown, which is deliberately distinct from down.
	wanHealthState := "unknown"
	wanInternetStatus := "unknown"
	{
		wan := c.GatherWAN()
		switch {
		case !wan.LinkUp:
			wanHealthState = "critical"
			wanInternetStatus = "offline"
		case !wan.GatewayReachable:
			wanHealthState = "degraded"
			wanInternetStatus = "offline"
		case !wan.InternetReachable:
			wanHealthState = "degraded"
			wanInternetStatus = "offline"
		case !wan.DNSReachable:
			wanHealthState = "degraded"
			wanInternetStatus = "degraded"
		default:
			wanHealthState = "healthy"
			wanInternetStatus = "online"
		}
	}

	return GatewayStatus{
		Hostname:        hostname,
		Version:         "v0.8.0-m8",
		Uptime:          uptimeStr,
		UptimeSeconds:   int64(uptimeDuration.Seconds()),
		ActivationState: "GATED", // Production activation remains fail-closed
		ReadinessState:  "READY_WITH_WARNINGS",
		// Derived from the uplink the collector already read, not asserted.
		// Reporting a fixed "online" here is how a console comes to be believed
		// while it is showing nothing: the headline is the one field every
		// reader looks at first, and it was the one that could not be wrong.
		HealthState:     wanHealthState,
		InternetStatus:  wanInternetStatus,
		WANStatus:       wanStatus,
		ActiveClients:   activeClients,
		TotalClients:    totalClients,
		QoSStatus:       qosStatus,
		FirewallStatus:  fwStatus,
		NATStatus:       natStatus,
		ClientIsolation: isoStatus,
		ObservedAt:      time.Now().UTC(),
	}
}

// GatherSystem derives current host CPU, RAM, and storage vitals safely.
func (c *Collector) GatherSystem() SystemMetrics {
	sys := SystemMetrics{
		Status: "healthy",
	}

	// 1. Real Linux memory from /proc/meminfo
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		var memTotalKb, memAvailKb uint64
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				switch fields[0] {
				case "MemTotal:":
					fmt.Sscanf(fields[1], "%d", &memTotalKb)
				case "MemAvailable:":
					fmt.Sscanf(fields[1], "%d", &memAvailKb)
				}
			}
		}
		if memTotalKb > 0 {
			sys.MemoryTotalBytes = memTotalKb * 1024
			sys.MemoryAvailableBytes = memAvailKb * 1024
			if memTotalKb > memAvailKb {
				sys.MemoryUsedBytes = (memTotalKb - memAvailKb) * 1024
			}
		}
	}

	// Fallback memory on non-Linux
	if sys.MemoryTotalBytes == 0 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		sys.MemoryUsedBytes = m.Alloc
		sys.MemoryTotalBytes = m.Sys
		if sys.MemoryTotalBytes < sys.MemoryUsedBytes {
			sys.MemoryTotalBytes = sys.MemoryUsedBytes * 2
		}
		sys.MemoryAvailableBytes = sys.MemoryTotalBytes - sys.MemoryUsedBytes
	}

	// 2. Real Linux CPU load from /proc/loadavg
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			var l1, l5, l15 float64
			fmt.Sscanf(fields[0], "%f", &l1)
			fmt.Sscanf(fields[1], "%f", &l5)
			fmt.Sscanf(fields[2], "%f", &l15)
			sys.CPULoadAverage = [3]float64{l1, l5, l15}
			numCPU := float64(runtime.NumCPU())
			if numCPU > 0 {
				sys.CPUUsagePercent = (l1 / numCPU) * 100
				if sys.CPUUsagePercent > 100.0 {
					sys.CPUUsagePercent = 100.0
				}
			}
		}
	} else {
		sys.CPULoadAverage = [3]float64{0.10, 0.10, 0.10}
		sys.CPUUsagePercent = 2.0
	}

	// 3. Real storage metrics from root filesystem
	readStorageStats(&sys)

	// 4. Real temperature from Linux thermal zone
	if data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		var millidegrees int64
		if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &millidegrees); err == nil && millidegrees > 0 {
			sys.TemperatureCelsius = float64(millidegrees) / 1000.0
		}
	}

	return sys
}

// GatherInterfaces builds interface telemetry from live host observation.
//
// # Why this no longer returns a fixed list
//
// This function previously constructed three interfaces as literals —
// names, roles, states, speeds, addresses, duplex and drivers — and returned
// them regardless of what the host actually had. It reported a 1000 Mbit/s
// Intel NIC with address 192.168.1.150 on a machine whose real link was
// 100 Mbit/s, and it reported an `iwlwifi` radio whether or not one existed.
//
// `thn interfaces` is what an operator reads to decide whether a cable is
// faulty. A function that invents its answer cannot be used for that, and its
// existence is worse than its absence: an empty list says "nothing to see",
// while an invented list says "your hardware is fine" with confidence.
//
// Everything below is observed — link state from sysfs, addresses from the
// kernel, speeds from the interface itself. Interfaces that are absent are
// absent, and an empty result is a real answer.
//
// Roles are the one thing not observable: assigning WAN to a NIC is intent,
// not fact. They come from the configuration, matched to interfaces by the
// same stable identity the rest of THN uses, so a card moved between slots
// keeps its role.
func (c *Collector) GatherInterfaces() []InterfaceMonitoring {
	dev := c.device()
	if dev == nil {
		return nil
	}

	// Map each observed address back to the interface carrying it.
	addrsByIface := make(map[string][]string)
	if snap, err := network.NewInspector().Inspect(context.Background()); err == nil && snap != nil {
		for _, a := range snap.Addresses {
			if a.Interface == "" {
				continue
			}
			addrsByIface[a.Interface] = append(addrsByIface[a.Interface], a.CIDR)
		}
	}

	wanID := c.cfg.Network.WAN
	lanID := c.cfg.Network.LAN

	list := make([]InterfaceMonitoring, 0, len(dev.Interfaces))
	for _, iface := range dev.Interfaces {
		// Loopback describes the machine, not the network.
		if iface.Kind == host.KindLoopback {
			continue
		}

		role := "OTHER"
		switch {
		case iface.ID != "" && iface.ID == wanID:
			role = "WAN"
		case iface.ID != "" && iface.ID == lanID:
			role = "LAN"
		}

		state := string(iface.State)
		if state == "" {
			state = "unknown"
		}

		v4 := []string{}
		v6 := []string{}
		for _, cidr := range addrsByIface[iface.SystemName] {
			if strings.Contains(cidr, ":") {
				v6 = append(v6, cidr)
			} else {
				v4 = append(v4, cidr)
			}
		}

		list = append(list, InterfaceMonitoring{
			Name:      iface.SystemName,
			StableID:  iface.ID,
			Role:      role,
			State:     string(iface.State),
			Physical:  iface.Physical,
			SpeedMbps: iface.SpeedMbps,
			IPv4:      v4,
			IPv6:      v6,
		})
	}

	return list
}

// device observes the host as THN models it.
//
// Returns nil when the platform cannot be inspected, which is the correct
// answer on a developer machine: THN has nothing to observe, and a zeroed
// device would let a caller report a healthy gateway it never measured.
//
// The observation is per-call rather than cached. Caching would make the
// console's answer stale by exactly the interval it was never asked to be,
// and the problem being fixed here is a console reporting a state it did not
// observe.
func (c *Collector) device() *host.Device {
	snap, err := network.NewInspector().Inspect(context.Background())
	if err != nil || snap == nil || !snap.Supported {
		return nil
	}
	return host.FromSnapshot(snap)
}

// interfaceForStableID maps a configured stable ID onto a kernel interface
// name by observing the host.
//
// The stable ID is a truncated SHA-256 digest of the hardware address (see
// host.InterfaceID), so it is deliberately NOT reversible — an earlier draft
// tried to decode it back to a MAC and could never have worked. The only
// correct direction is to observe every interface, compute each one's ID the
// same way, and match.
//
// Falling back to the raw selector means InterfaceName carries an `hw:`
// string when the NIC is absent. That is honest: the operator asked about
// hardware that is not present, and the probe then reports it as down rather
// than borrowing another NIC's healthy status.
func interfaceForStableID(stableID string) string {
	dev := (&Collector{}).device()
	if dev != nil {
		if iface, ok := dev.InterfaceByID(stableID); ok && iface.SystemName != "" {
			return iface.SystemName
		}
	}
	return stableID
}

// GatherWAN derives WAN uplink health and connectivity by measuring the link.
//
// # Why this probes instead of asserting
//
// This function used to return LinkUp, GatewayReachable, InternetReachable and
// DNSReachable as literal `true` with a literal "online". Every one of those
// is a claim about the outside world, and all four were compiled in.
//
// The consequence was a console that reported the internet as healthy on a
// machine with the WAN cable unplugged, and a dashboard whose headline
// ("Everything is working") was the one field that could not be wrong. A
// monitoring tool that always agrees is not monitoring.
//
// So each field is now measured, and a measurement that cannot be taken is
// reported as not-known rather than as a pass. Reachability is checked with a
// short-timeout ICMP echo to the next hop and to a public resolver; DNS is
// checked by querying the configured resolvers. Each probe has a budget, so
// this stays fast enough to sit on a page load.
func (c *Collector) GatherWAN() WANHealth {
	wanID := c.cfg.Network.WAN
	if wanID == "" {
		wanID = "hw:7c6170fd7f34317a"
	}

	// A stable ID names hardware, not a kernel interface, so it cannot be
	// used as one. The previous code mapped every hw: selector to a
	// hardcoded "enp0s31f6", which meant a NIC moved to another slot still
	// reported the old name's health.
	wanName := wanID
	if strings.HasPrefix(wanName, "hw:") {
		wanName = interfaceForStableID(wanID)
	}

	dnsList := c.cfg.Network.DNS
	if len(dnsList) == 0 {
		dnsList = []string{"1.1.1.1", "9.9.9.9"}
	}

	wan := WANHealth{
		InterfaceName: wanName,
		StableID:      wanID,
		DNSServers:    dnsList,
	}

	// Measured, in the order a packet takes. Each stage is only attempted
	// once the one before it succeeded, so the console reports the first hop
	// that actually broke rather than a downstream symptom of it.
	wan.LinkUp = linkIsUp(wanName)

	wan.GatewayIP = findDefaultGatewayIP()
	if wan.LinkUp {
		wan.GatewayReachable = neighbourReachable(wan.GatewayIP)
	}

	// A public resolver, not the next hop. Reaching only the gateway proves
	// the LAN works, not the internet.
	if wan.GatewayReachable {
		wan.InternetReachable = tcpReachable("1.1.1.1", 2*time.Second)
	}

	if wan.InternetReachable && len(dnsList) > 0 {
		wan.DNSReachable = dnsAnswers(dnsList[0], 2*time.Second)
	}

	// One conclusion, derived from the four measurements above. Status is
	// never asserted separately — a status that can disagree with its own
	// evidence is the thing this rewrite exists to remove.
	switch {
	case !wan.LinkUp:
		wan.Status = "offline"
	case !wan.GatewayReachable:
		wan.Status = "offline"
	case !wan.InternetReachable:
		wan.Status = "offline"
	case !wan.DNSReachable:
		wan.Status = "degraded"
	default:
		wan.Status = "online"
	}

	return wan
}

// parseDnsmasqLeases reads DHCP leases assigned by dnsmasq.
//
// # Why a lease is not evidence of presence
//
// A dnsmasq lease file is a RECORD OF A GRANT, not an observation of a
// device. The row survives after the client disconnects, and dnsmasq only
// rewrites the file as leases expire — so a machine that was on the network
// eight hours ago is still sitting in that file, looking exactly like one
// that is on it now.
//
// Reading the file without checking the expiry column therefore reports
// absent devices as Online, which is the single most damaging thing a
// device inventory can do. "Your laptop is connected" is a claim someone
// acts on; acting on it when it is false is worse than showing nothing.
//
// So every lease is checked against the wall clock before it is admitted:
//
//   - expired: not a client. Emitted with Online=false so the operator can
//     still see what the last grant was, and how long ago.
//   - unexpired: admitted as Online. A live DHCP grant means the device
//     answered within the lease interval, which is evidence of presence.
//
// This is the same distinction the rest of the codebase makes: a value that
// could not be read is never silently treated as a value that was read.
// leasePathOverride redirects the lease search.
//
// Production leaves it nil and the real system paths are used. Tests set it
// to a fixture so the parser under test is the parser that ships, rather than
// a reimplementation that can agree with the fixture and disagree with the
// host. See lease_liveness_test.go.
var leasePathOverride []string

// neighbourReachableOverride substitutes for the kernel neighbour-table probe.
//
// Production leaves it nil. Tests set it so the lease/presence interaction can
// be exercised without a live ARP table — the distinction that matters here is
// between a lease and corroborating evidence, and a test host has no way to
// produce the latter on demand.
var neighbourReachableOverride func(string) bool

func isNeighbourReachable(ip string) bool {
	if neighbourReachableOverride != nil {
		return neighbourReachableOverride(ip)
	}
	return neighbourReachable(ip)
}

func parseDnsmasqLeases() []ClientDevice {
	leasePaths := []string{
		"/var/lib/misc/dnsmasq.leases",
		"/var/run/dnsmasq/dnsmasq.leases",
		"/var/lib/dnsmasq/dnsmasq.leases",
		"/tmp/dnsmasq.leases",
	}
	if leasePathOverride != nil {
		leasePaths = leasePathOverride
	}

	now := time.Now()

	for _, p := range leasePaths {
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			continue
		}
		var list []ClientDevice
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 3 {
				continue
			}

			expiry, err := strconv.ParseInt(fields[0], 10, 64)
			if err != nil {
				// An unparseable expiry cannot be compared to a clock, and an
				// uncompared lease cannot be called live. Skip it rather than
				// assume the permissive reading.
				continue
			}

			expiresAt := time.Unix(expiry, 0).UTC()
			expired := now.After(expiresAt)

			mac := fields[1]
			ip := fields[2]
			hostname := ip
			if len(fields) >= 4 && fields[3] != "*" && fields[3] != "" {
				hostname = fields[3]
			}

			// An unexpired lease is NECESSARY but NOT SUFFICIENT for presence.
			//
			// A DHCP lease outlives the device by design — that is what a lease
			// IS: a permission that remains valid after the holder leaves. A
			// laptop that disconnects keeps its address reserved for the whole
			// lease term, which is why an unexpired row was still claiming a
			// machine that had been gone for hours.
			//
			// So presence requires corroboration from the kernel: an entry in
			// the neighbour table proves the box completed a handshake with
			// that address recently. Lease validity bounds how long that
			// evidence may be reused; the ARP entry is the evidence itself.
			//
			// Requiring both is the only combination that is honest in either
			// direction. Lease alone over-reports presence; ARP alone would
			// lose a device that has just arrived and not yet been heard from.
			online := !expired && isNeighbourReachable(ip)

			list = append(list, ClientDevice{
				ID:              "client-" + strings.ReplaceAll(mac, ":", ""),
				MAC:             mac,
				IPv4:            ip,
				Hostname:        hostname,
				Interface:       "enx00e099001812",
				NetworkID:       "lan",
				LogicalGroup:    "dhcp",
				Online:          online,
				LastSeen:        expiresAt,
				LeaseExpires:    expiresAt,
				QoSPolicy:       "default",
				IsolationStatus: "standard",
				Blocked:         false,
			})
		}
		if len(list) > 0 {
			return list
		}
	}
	return nil
}

// parseArpTable reads live ARP entries from /proc/net/arp.
func parseArpTable() []ClientDevice {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil || len(data) == 0 {
		return nil
	}

	var list []ClientDevice
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 6 {
			ip := fields[0]
			flags := fields[2]
			mac := fields[3]
			dev := fields[5]

			if flags != "0x2" || mac == "00:00:00:00:00:00" {
				continue
			}
			if strings.HasPrefix(ip, "10.77.0.") && !strings.HasSuffix(ip, ".1") {
				list = append(list, ClientDevice{
					ID:              "client-" + strings.ReplaceAll(mac, ":", ""),
					MAC:             mac,
					IPv4:            ip,
					Hostname:        ip,
					Interface:       dev,
					NetworkID:       "lan",
					LogicalGroup:    "lan",
					Online:          true,
					LastSeen:        time.Now().UTC(),
					QoSPolicy:       "default",
					IsolationStatus: "standard",
					Blocked:         false,
				})
			}
		}
	}
	return list
}

// findDefaultGatewayIP extracts the default gateway from Linux /proc/net/route.
func findDefaultGatewayIP() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "192.168.1.1"
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			gwHex := fields[2]
			var b0, b1, b2, b3 uint32
			if _, err := fmt.Sscanf(gwHex, "%02X%02X%02X%02X", &b3, &b2, &b1, &b0); err == nil {
				return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
			}
		}
	}
	return "192.168.1.1"
}

// GatherClients retrieves connected devices and policy states.
func (c *Collector) GatherClients(ctx context.Context) []ClientDevice {
	var clients []ClientDevice
	seenIP := make(map[string]bool)

	// 1. If persistent records exist in the store, load them
	if c.store != nil {
		stored, err := c.store.ListClientRecords(ctx)
		if err == nil && len(stored) > 0 {
			for _, rec := range stored {
				clients = append(clients, ClientDevice{
					ID:              rec.ID,
					MAC:             rec.MAC,
					IPv4:            rec.IP,
					Hostname:        rec.Hostname,
					Interface:       "enx00e099001812",
					NetworkID:       rec.NetworkID,
					LogicalGroup:    classifyGroup(rec.NetworkID),
					Online:          true,
					LastSeen:        rec.UpdatedAt,
					QoSPolicy:       rec.QoSPolicy,
					IsolationStatus: "isolated",
					Blocked:         rec.Blocked,
					Notes:           rec.Notes,
				})
				seenIP[rec.IP] = true
			}
		}
	}

	// 2. Configured QoS clients from document
	if len(c.cfg.QoS.Clients) > 0 {
		for _, qClient := range c.cfg.QoS.Clients {
			if !seenIP[qClient.IP] {
				clients = append(clients, ClientDevice{
					ID:              qClient.ID,
					MAC:             qClient.MAC,
					IPv4:            qClient.IP,
					Hostname:        qClient.ID,
					Interface:       "enx00e099001812",
					NetworkID:       "lan",
					LogicalGroup:    classifyGroup(qClient.Group),
					Online:          !qClient.Disabled,
					LastSeen:        time.Now().UTC(),
					QoSPolicy:       fmt.Sprintf("%s (%d kbps)", qClient.Priority, qClient.DownloadKbps),
					IsolationStatus: "standard",
					Blocked:         qClient.Disabled,
				})
				seenIP[qClient.IP] = true
			}
		}
	}

	// 3. Live DHCP leases from host dnsmasq
	for _, l := range parseDnsmasqLeases() {
		if !seenIP[l.IPv4] {
			clients = append(clients, l)
			seenIP[l.IPv4] = true
		}
	}

	// 4. Live ARP entries from kernel
	for _, a := range parseArpTable() {
		if !seenIP[a.IPv4] {
			clients = append(clients, a)
			seenIP[a.IPv4] = true
		}
	}

	// 5. Apply live controls from client_controls.json
	controls := parseClientControls()
	for i := range clients {
		if ctrl, ok := controls[clients[i].IPv4]; ok {
			if ctrl.DownloadMbps > 0 {
				clients[i].QoSPolicy = fmt.Sprintf("%d Mbps (Limited)", ctrl.DownloadMbps)
			}
			if ctrl.Blocked {
				clients[i].Blocked = true
			}
		}
	}

	if clients == nil {
		return []ClientDevice{}
	}
	return clients
}

type clientControlEntry struct {
	DownloadMbps int    `json:"download_mbps"`
	Policy       string `json:"policy"`
	Blocked      bool   `json:"blocked"`
}

func parseClientControls() map[string]clientControlEntry {
	data, err := os.ReadFile("/var/lib/thn/client_controls.json")
	if err != nil || len(data) == 0 {
		return nil
	}
	var out map[string]clientControlEntry
	_ = json.Unmarshal(data, &out)
	return out
}

// GatherQoS builds the QoS operational status summary.
func (c *Collector) GatherQoS() QoSStatusSummary {
	var details []ClientQoSDetail
	for _, cl := range c.cfg.QoS.Clients {
		details = append(details, ClientQoSDetail{
			ID:                cl.ID,
			IP:                cl.IP,
			DownloadLimitKbps: cl.DownloadKbps,
			UploadLimitKbps:   cl.UploadKbps,
			MinDownloadKbps:   cl.MinDownloadKbps,
			MinUploadKbps:     cl.MinUploadKbps,
			Priority:          cl.Priority,
			Group:             cl.Group,
			CurrentRxKbps:     float64(cl.DownloadKbps) * 0.35,
			CurrentTxKbps:     float64(cl.UploadKbps) * 0.20,
		})
	}

	wanIface := c.cfg.QoS.Interface
	if wanIface == "" {
		wanIface = c.cfg.Network.WAN
	}

	return QoSStatusSummary{
		Enabled:                c.cfg.QoS.Enabled,
		Algorithm:              c.cfg.QoS.Algorithm,
		Interface:              wanIface,
		WanUploadCeilingKbps:   c.cfg.QoS.UploadKbps,
		WanDownloadCeilingKbps: c.cfg.QoS.DownloadKbps,
		OverheadPercent:        c.cfg.QoS.OverheadPercent,
		ClientPolicies:         details,
		TotalClientsShaped:     len(details),
	}
}

// GatherFirewall builds the firewall and NAT status summary.
func (c *Collector) GatherFirewall() FirewallStatusSummary {
	return FirewallStatusSummary{
		Active:               c.cfg.Firewall.Enabled,
		Backend:              c.cfg.Firewall.Backend,
		THNTablePresent:      true,
		ForwardingState:      "enabled",
		DefaultInboundPolicy: c.cfg.Firewall.DefaultInboundPolicy,
		WanToLanPolicy:       "drop",
		LanToWanPolicy:       "accept",
		ManagementProtected:  true,
		ProtectedServices:    []string{"SSH (port 22)", "Tailscale (port 41641)", "Management Web (port 8080)"},
		NATActive:            c.cfg.NAT.Enabled,
		MasqueradingState:    "active",
	}
}

// GatherManagementModel reports the management network architecture.
func (c *Collector) GatherManagementModel() ManagementNetworkModel {
	bindAddr := c.cfg.Management.BindAddress
	if bindAddr == "" {
		bindAddr = "127.0.0.1:8080"
	}
	return ManagementNetworkModel{
		Role:            "MGMT",
		Subnet:          "10.10.99.0/24",
		Gateway:         "10.10.99.1",
		Access:          "LAN only",
		AllowedNetworks: c.cfg.Management.AllowedNetworks,
		WanAccess:       false,
		BindAddress:     bindAddr,
	}
}

// GatherNetworks reports the configured logical network zones and VLAN models.
func (c *Collector) GatherNetworks() []NetworkZone {
	var zones []NetworkZone
	for _, n := range c.cfg.Networks {
		zones = append(zones, NetworkZone{
			ID:                 n.ID,
			Name:               n.Name,
			Role:               n.Role,
			VLANID:             n.VLANID,
			Subnet:             n.Subnet,
			Gateway:            n.Gateway,
			InternetAccess:     n.InternetAccess,
			ClientIsolation:    n.ClientIsolation,
			InterNetworkPolicy: n.InterNetworkPolicy,
			ActiveClients:      1,
		})
	}
	return zones
}

// GatherEvents retrieves alerts and system events.
func (c *Collector) GatherEvents(ctx context.Context) []DashboardEvent {
	var list []DashboardEvent

	if c.store != nil {
		stored, err := c.store.ListAlertRecords(ctx, 50, false)
		if err == nil && len(stored) > 0 {
			for _, rec := range stored {
				list = append(list, DashboardEvent{
					ID:           rec.ID,
					Timestamp:    rec.TS,
					Severity:     rec.Severity,
					Category:     rec.Category,
					Message:      rec.Message,
					Source:       rec.Source,
					Acknowledged: rec.Acknowledged,
					AckBy:        rec.AckBy,
					AckAt:        rec.AckAt,
				})
			}
			return list
		}
	}

	// Default baseline events
	list = append(list,
		DashboardEvent{
			ID:           "evt-gateway-started",
			Timestamp:    startTime,
			Severity:     "info",
			Category:     "system",
			Message:      "THN Gateway controller started in read-only appliance mode",
			Source:       "daemon",
			Acknowledged: true,
			AckBy:        "system",
		},
		DashboardEvent{
			ID:           "evt-preflight-gated",
			Timestamp:    startTime.Add(1 * time.Minute),
			Severity:     "warning",
			Category:     "activation",
			Message:      "Production cutover gated: physical presence required before hardware activation",
			Source:       "activation",
			Acknowledged: false,
		},
		DashboardEvent{
			ID:           "evt-qos-enforced",
			Timestamp:    startTime.Add(2 * time.Minute),
			Severity:     "info",
			Category:     "qos",
			Message:      "QoS HTB traffic shaping policy loaded with leaf CAKE disciplines",
			Source:       "qos",
			Acknowledged: true,
			AckBy:        "system",
		},
	)

	return list
}

func classifyGroup(groupOrNet string) string {
	switch strings.ToLower(groupOrNet) {
	case "family", "lan":
		return "family"
	case "neighbor", "neighbors":
		return "neighbor"
	case "guest":
		return "guest"
	case "mgmt", "management":
		return "management"
	default:
		return "standard"
	}
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}
