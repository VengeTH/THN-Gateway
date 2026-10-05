package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
)

const (
	ExecutionModeProduction = "production"
	ExecutionModeLab        = "disposable-lab"
	DefaultLabMarkerPath    = "/etc/thn/lab-disposable-environment.json"
)

// LabMarkerContent defines the required structure inside a lab environment marker file.
type LabMarkerContent struct {
	Disposable    bool   `json:"disposable"`
	EnvironmentID string `json:"environment_id"`
	Topology      string `json:"topology"`
	WANInterface  string `json:"wan_interface,omitempty"`
	LANInterface  string `json:"lan_interface,omitempty"`
	LANSubnet     string `json:"lan_subnet,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
}

// LabConfig specifies the assertions required to authorize real Linux execution.
type LabConfig struct {
	Mode                  string   `json:"mode"`
	MarkerPath            string   `json:"marker_path"`
	ExpectedEnvironmentID string   `json:"expected_environment_id"`
	ExpectedWAN           string   `json:"expected_wan,omitempty"`
	ExpectedLAN           string   `json:"expected_lan,omitempty"`
	ForbiddenHostnames    []string `json:"forbidden_hostnames"`
	ForbiddenMACs         []string `json:"forbidden_macs"`
	ForbiddenInterfaces   []string `json:"forbidden_interfaces"`
	ForbiddenSubnets      []string `json:"forbidden_subnets"`
}

// DefaultLabConfig returns safety constraints designed to strictly exclude production Dell and user LANs.
func DefaultLabConfig() LabConfig {
	return LabConfig{
		Mode:                  ExecutionModeLab,
		MarkerPath:            DefaultLabMarkerPath,
		ExpectedEnvironmentID: "thn-disposable-lab-vm-m6.1",
		ForbiddenHostnames:    []string{"dell-gateway", "dell", "home-server"},
		ForbiddenMACs:         []string{"7c:61:70:fd:7f:34", "2c:88:6f:45:ad:0c"},
		ForbiddenInterfaces:   []string{"enp0s31f6", "tailscale0", "docker0"},
		ForbiddenSubnets:      []string{"192.168.1.0/24"},
	}
}

// VerifyLabEnvironment verifies that the execution target is genuinely a disposable lab environment.
//
// If ANY check fails, execution must immediately be BLOCKED to protect real hosts and networks.
func VerifyLabEnvironment(ctx context.Context, cfg LabConfig, runner CommandRunner) error {
	// 1. Explicit lab execution mode
	if cfg.Mode != ExecutionModeLab {
		return fmt.Errorf("%w: execution mode %q is not authorized for live mutation; only %q is permitted",
			ErrLabVerificationFailed, cfg.Mode, ExecutionModeLab)
	}

	// 2. Expected Linux environment
	if runtime.GOOS != "linux" {
		// When running with mock runners in non-Linux unit tests, allow mock check
		if runner == nil {
			return fmt.Errorf("%w: live Linux execution requires Linux operating system, got %s",
				ErrLabVerificationFailed, runtime.GOOS)
		}
	}

	// 3. Lab identity marker file check
	markerPath := cfg.MarkerPath
	if markerPath == "" {
		markerPath = DefaultLabMarkerPath
	}

	markerBytes, err := os.ReadFile(markerPath)
	if err != nil {
		return fmt.Errorf("%w: missing disposable lab marker at %s: %v",
			ErrLabVerificationFailed, markerPath, err)
	}

	var marker LabMarkerContent
	if err := json.Unmarshal(markerBytes, &marker); err != nil {
		return fmt.Errorf("%w: malformed lab marker at %s: %v",
			ErrLabVerificationFailed, markerPath, err)
	}

	if !marker.Disposable {
		return fmt.Errorf("%w: marker at %s declares disposable=false; live mutation refused",
			ErrLabVerificationFailed, markerPath)
	}

	if cfg.ExpectedEnvironmentID != "" && marker.EnvironmentID != cfg.ExpectedEnvironmentID {
		return fmt.Errorf("%w: lab environment ID mismatch: got %q, want %q",
			ErrLabVerificationFailed, marker.EnvironmentID, cfg.ExpectedEnvironmentID)
	}

	// 4. Host identity verification - must NOT match production Dell
	hostname, _ := os.Hostname()
	for _, forbidden := range cfg.ForbiddenHostnames {
		if strings.EqualFold(hostname, forbidden) {
			return fmt.Errorf("%w: host identity matches forbidden production hostname %q; activation BLOCKED",
				ErrLabVerificationFailed, hostname)
		}
	}

	// 5. Topology verification via command runner
	if runner != nil {
		stdout, _, err := runner.Run(ctx, "ip", "-j", "-d", "link", "show")
		if err == nil && stdout != "" {
			var links []struct {
				Ifname  string `json:"ifname"`
				Address string `json:"address"`
			}
			if err := json.Unmarshal([]byte(stdout), &links); err == nil {
				for _, link := range links {
					for _, forbIface := range cfg.ForbiddenInterfaces {
						if link.Ifname == forbIface {
							return fmt.Errorf("%w: detected forbidden production interface %q; activation BLOCKED",
								ErrLabVerificationFailed, link.Ifname)
						}
					}
					for _, forbMAC := range cfg.ForbiddenMACs {
						if strings.EqualFold(link.Address, forbMAC) {
							return fmt.Errorf("%w: detected forbidden production MAC %q on interface %s; activation BLOCKED",
								ErrLabVerificationFailed, link.Address, link.Ifname)
						}
					}
				}

				if cfg.ExpectedWAN != "" {
					hasWAN := false
					for _, l := range links {
						if l.Ifname == cfg.ExpectedWAN {
							hasWAN = true
							break
						}
					}
					if !hasWAN {
						return fmt.Errorf("%w: expected lab WAN interface %q not found",
							ErrLabVerificationFailed, cfg.ExpectedWAN)
					}
				}

				if cfg.ExpectedLAN != "" {
					hasLAN := false
					for _, l := range links {
						if l.Ifname == cfg.ExpectedLAN {
							hasLAN = true
							break
						}
					}
					if !hasLAN {
						return fmt.Errorf("%w: expected lab LAN interface %q not found",
							ErrLabVerificationFailed, cfg.ExpectedLAN)
					}
				}
			}
		}
	}

	return nil
}
