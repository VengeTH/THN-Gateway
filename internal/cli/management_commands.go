package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/VengeTH/THN-Gateway/internal/management"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

// runClients lists connected devices, IP/MAC mappings, and traffic/policy details.
func runClients(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn clients: %v\n", err)
	}

	path := env.resolveConfigPath(*configPath)
	if len(rest) > 0 {
		path = rest[0]
	}
	cfg, err := loadConfig(env, path)
	if err != nil {
		return env.fatalf("thn clients: %v\n", err)
	}

	var store *state.Store
	if cfg.Paths.StateDB != "" {
		st, _ := state.Open(cfg.Paths.StateDB)
		if st != nil {
			store = st
			defer store.Close()
		}
	}

	col := management.NewCollector(cfg, store)
	clients := col.GatherClients(context.Background())

	if env.IsJSON {
		if err := env.printJSON(clients); err != nil {
			return env.fatalf("thn clients: %v\n", err)
		}
		return ExitOK
	}

	env.printf("CONNECTED CLIENTS & INVENTORY (%d devices)\n\n", len(clients))
	env.printf("%-20s %-16s %-18s %-12s %-10s %s\n",
		"HOSTNAME / ID", "IPV4", "MAC", "ZONE", "STATUS", "POLICY")
	env.printf("%s\n", "-----------------------------------------------------------------------------------------")

	for _, c := range clients {
		status := "Online"
		if c.Blocked {
			status = "Blocked"
		} else if !c.Online {
			status = "Offline"
		}

		env.printf("%-20s %-16s %-18s %-12s %-10s %s\n",
			c.Hostname, c.IPv4, c.MAC, c.NetworkID, status, c.QoSPolicy)
	}
	return ExitOK
}

// runInterfaces lists observed and assigned interfaces preserving stable identity.
func runInterfaces(env *Env, args []string) ExitCode {
	path := env.resolveConfigPath("")
	cfg, err := loadConfig(env, path)
	if err != nil {
		return env.fatalf("thn interfaces: %v\n", err)
	}

	col := management.NewCollector(cfg, nil)
	ifaces := col.GatherInterfaces()

	if env.IsJSON {
		if err := env.printJSON(ifaces); err != nil {
			return env.fatalf("thn interfaces: %v\n", err)
		}
		return ExitOK
	}

	env.printf("GATEWAY INTERFACES & STABLE IDENTITIES (%d interfaces)\n\n", len(ifaces))
	env.printf("%-6s %-16s %-22s %-8s %-10s %s\n",
		"ROLE", "SYSTEM NAME", "STABLE HARDWARE ID", "SPEED", "LINK", "ADDRESSES")
	env.printf("%s\n", "-----------------------------------------------------------------------------------------")

	for _, iface := range ifaces {
		speedStr := fmt.Sprintf("%dM", iface.SpeedMbps)
		addrStr := "-"
		if len(iface.IPv4) > 0 {
			addrStr = iface.IPv4[0]
		}
		env.printf("%-6s %-16s %-22s %-8s %-10s %s\n",
			iface.Role, iface.Name, iface.StableID, speedStr, stringsToUpper(iface.State), addrStr)
	}
	return ExitOK
}

// runNetworks reports logical network zones, subnets, and future VLAN isolation models.
func runNetworks(env *Env, args []string) ExitCode {
	path := env.resolveConfigPath("")
	cfg, err := loadConfig(env, path)
	if err != nil {
		return env.fatalf("thn networks: %v\n", err)
	}

	col := management.NewCollector(cfg, nil)
	zones := col.GatherNetworks()

	if env.IsJSON {
		if err := env.printJSON(zones); err != nil {
			return env.fatalf("thn networks: %v\n", err)
		}
		return ExitOK
	}

	env.printf("LOGICAL NETWORKS & VLAN / ISOLATION MODEL (%d zones)\n\n", len(zones))
	env.printf("%-12s %-16s %-6s %-6s %-16s %-10s %s\n",
		"ZONE ID", "NAME", "ROLE", "VLAN", "SUBNET", "ISOLATION", "INTER-NET POLICY")
	env.printf("%s\n", "-----------------------------------------------------------------------------------------")

	for _, z := range zones {
		isoStr := "Shared"
		if z.ClientIsolation {
			isoStr = "Isolated"
		}
		vlanStr := fmt.Sprintf("%d", z.VLANID)
		if z.VLANID == 0 {
			vlanStr = "Native"
		}
		env.printf("%-12s %-16s %-6s %-6s %-16s %-10s %s\n",
			z.ID, z.Name, z.Role, vlanStr, z.Subnet, isoStr, z.InterNetworkPolicy)
	}
	return ExitOK
}

// runMonitoring provides consolidated gateway health, CPU, memory, and WAN statistics.
func runMonitoring(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn monitoring: %v\n", err)
	}

	path := env.resolveConfigPath(*configPath)
	if len(rest) > 0 {
		path = rest[0]
	}
	cfg, err := loadConfig(env, path)
	if err != nil {
		return env.fatalf("thn monitoring: %v\n", err)
	}

	col := management.NewCollector(cfg, nil)
	status := col.GatherStatus()
	sys := col.GatherSystem()
	wan := col.GatherWAN()

	doc := map[string]any{
		"gateway": status,
		"system":  sys,
		"wan":     wan,
	}

	if env.IsJSON {
		if err := env.printJSON(doc); err != nil {
			return env.fatalf("thn monitoring: %v\n", err)
		}
		return ExitOK
	}

	env.printf("THN GATEWAY MONITORING & VITALS\n\n")
	env.printf("GATEWAY STATUS:\n")
	env.printf("  Hostname:       %s\n", status.Hostname)
	env.printf("  Version:        %s\n", status.Version)
	env.printf("  Uptime:         %s\n", status.Uptime)
	env.printf("  Health Verdict: %s\n", stringsToUpper(status.HealthState))
	env.printf("  Internet:       %s (Latency: %.1f ms)\n", stringsToUpper(status.InternetStatus), wan.LatencyMs)
	env.printf("  Active Clients: %d of %d\n", status.ActiveClients, status.TotalClients)
	env.printf("\nSYSTEM VITALS:\n")
	env.printf("  CPU Usage:      %.1f%%\n", sys.CPUUsagePercent)
	env.printf("  Memory:         %d MB / %d MB\n", sys.MemoryUsedBytes/(1024*1024), sys.MemoryTotalBytes/(1024*1024))
	env.printf("  Storage:        %d GB / %d GB\n", sys.StorageUsedBytes/(1024*1024*1024), sys.StorageTotalBytes/(1024*1024*1024))
	env.printf("  Temperature:    %.1f C\n", sys.TemperatureCelsius)
	env.printf("\nWAN CONNECTIVITY:\n")
	env.printf("  Interface:      %s (%s)\n", wan.InterfaceName, wan.StableID)
	env.printf("  Default Gateway:%s (Reachable: %v)\n", wan.GatewayIP, wan.GatewayReachable)
	env.printf("  DNS Upstreams:  %v (Reachable: %v)\n", wan.DNSServers, wan.DNSReachable)
	return ExitOK
}

// runEvents lists active alerts, notifications and security audit logs.
func runEvents(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn events: %v\n", err)
	}

	path := env.resolveConfigPath(*configPath)
	if len(rest) > 0 {
		path = rest[0]
	}
	cfg, err := loadConfig(env, path)
	if err != nil {
		return env.fatalf("thn events: %v\n", err)
	}

	var store *state.Store
	if cfg.Paths.StateDB != "" {
		st, _ := state.Open(cfg.Paths.StateDB)
		if st != nil {
			store = st
			defer store.Close()
		}
	}

	col := management.NewCollector(cfg, store)
	events := col.GatherEvents(context.Background())

	if env.IsJSON {
		if err := env.printJSON(events); err != nil {
			return env.fatalf("thn events: %v\n", err)
		}
		return ExitOK
	}

	env.printf("GATEWAY ALERTS & NOTIFICATIONS (%d items)\n\n", len(events))
	for _, e := range events {
		ack := "UNACK"
		if e.Acknowledged {
			ack = "ACK"
		}
		env.printf("[%s] [%-8s] [%-4s] %s (%s)\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			stringsToUpper(e.Severity),
			ack,
			e.Message,
			e.Source,
		)
	}
	return ExitOK
}

// runManagement serves the local management HTTP API or reports configuration.
func runManagement(env *Env, args []string) ExitCode {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		env.printf("Usage: thn management [status|check|serve] [options]\n\n")
		env.printf("Subcommands:\n")
		env.printf("  status, check   Inspect the management service model and bind policy (default)\n")
		env.printf("  serve           Start the local LAN-only management HTTP API server\n\n")
		env.printf("Options:\n")
		env.printf("  --config <path> Path to configuration file\n")
		env.printf("  --help, -h      Show this help message\n")
		return ExitOK
	}

	sub := "status"
	rest := []string{}
	if len(args) > 0 {
		sub = args[0]
		rest = args[1:]
	}

	switch sub {
	case "status", "check":
		fs := newFlagSet()
		configPath := fs.String("config", "")
		help := fs.Bool("help", false)
		h := fs.Bool("h", false)
		_, err := fs.Parse(rest)
		if err != nil {
			return env.fatalf("thn management %s: %v\n", sub, err)
		}
		if *help || *h {
			env.printf("Usage: thn management %s [--config <path>]\n\n", sub)
			env.printf("Reports management role, subnet, gateway, allowed CIDRs, and bind address.\n")
			return ExitOK
		}
		path := env.resolveConfigPath(*configPath)
		cfg, err := loadConfig(env, path)
		if err != nil {
			return env.fatalf("thn management: %v\n", err)
		}

		col := management.NewCollector(cfg, nil)
		mgmt := col.GatherManagementModel()
		if env.IsJSON {
			if err := env.printJSON(mgmt); err != nil {
				return env.fatalf("thn management: %v\n", err)
			}
			return ExitOK
		}
		env.printf("MANAGEMENT SERVICE CONFIGURATION\n\n")
		env.printf("  Role:             %s\n", mgmt.Role)
		env.printf("  Subnet:           %s\n", mgmt.Subnet)
		env.printf("  Gateway:          %s\n", mgmt.Gateway)
		env.printf("  Access:           %s\n", mgmt.Access)
		env.printf("  Bind Address:     %s\n", mgmt.BindAddress)
		env.printf("  Allowed Networks: %v\n", mgmt.AllowedNetworks)
		env.printf("  WAN Access:       %t (Strictly disabled)\n", mgmt.WanAccess)
		return ExitOK

	case "serve":
		fs := newFlagSet()
		addr := fs.String("addr", "")
		configPath := fs.String("config", "")
		help := fs.Bool("help", false)
		h := fs.Bool("h", false)
		_, err := fs.Parse(rest)
		if err != nil {
			return env.fatalf("thn management serve: %v\n", err)
		}
		if *help || *h {
			env.printf("Usage: thn management serve [options]\n\n")
			env.printf("Starts the local LAN-only management HTTP API server.\n\n")
			env.printf("Options:\n")
			env.printf("  --addr <addr>    Override the bind address (default: from config, e.g. 127.0.0.1:8080)\n")
			env.printf("  --config <path>  Path to configuration file\n")
			env.printf("  --help, -h       Show this help message\n\n")
			env.printf("Safety Policy:\n")
			env.printf("  The management server is strictly restricted to local/LAN access.\n")
			env.printf("  Binding to public WAN addresses or enabling WAN access is prohibited.\n")
			return ExitOK
		}

		path := env.resolveConfigPath(*configPath)
		cfg, err := loadConfig(env, path)
		if err != nil {
			return env.fatalf("thn management: %v\n", err)
		}

		if *addr != "" {
			cfg.Management.BindAddress = *addr
		}

		var store *state.Store
		if cfg.Paths.StateDB != "" {
			st, err := state.Open(cfg.Paths.StateDB)
			if err == nil {
				store = st
				defer store.Close()
			}
		}

		server, err := management.NewServer(cfg, store)
		if err != nil {
			return env.fatalf("thn management: %v\n", err)
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		env.printf("Starting THN Management API on %s (LAN-only)...\n", cfg.Management.BindAddress)
		if err := server.Start(ctx); err != nil && err != http.ErrServerClosed {
			return env.fatalf("thn management: %v\n", err)
		}
		return ExitOK

	default:
		env.errorf("thn management: unknown subcommand %q; use status, check or serve\n", sub)
		return ExitUsage
	}
}

func stringsToUpper(s string) string {
	return strings.ToUpper(s)
}
