package activation

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// ManagementSafetyReport details the safety assessment of the remote management path.
type ManagementSafetyReport struct {
	Safe                  bool     `json:"safe"`
	SSHPathPreserved      bool     `json:"ssh_path_preserved"`
	TailscalePreserved    bool     `json:"tailscale_preserved"`
	ManagementInterface   string   `json:"management_interface,omitempty"`
	ManagementAddress     string   `json:"management_address,omitempty"`
	DefaultRoutePreserved bool     `json:"default_route_preserved"`
	Findings              []string `json:"findings,omitempty"`
	Reason                string   `json:"reason,omitempty"`
}

// ManagementSafetyInput carries observed facts about remote management paths.
type ManagementSafetyInput struct {
	// TailscalePresent indicates tailscale0 exists on the host.
	TailscalePresent bool
	// TailscaleInterface is the name of the Tailscale interface (typically "tailscale0").
	TailscaleInterface string
	// ActiveSSHIP is the local address carrying an active SSH session.
	ActiveSSHIP string
	// ActiveSSHInterface is the interface carrying ActiveSSHIP.
	ActiveSSHInterface string
	// HasDefaultRoute indicates the host currently has a default gateway.
	HasDefaultRoute bool
	// PlannedDefaultRoute indicates whether the plan retains/configures a default route.
	PlannedDefaultRoute bool
	// TouchedInterfaces lists interfaces the plan mutates.
	TouchedInterfaces []string
	// InterfaceDownActions lists interfaces the plan sets down.
	InterfaceDownActions []string
	// RemovedAddresses lists CIDRs the plan deletes, mapped by interface.
	RemovedAddresses map[string][]string
	// PlanSteps are summary strings of steps for review.
	PlanSteps []string
}

// EvaluateManagementSafety evaluates whether planned network operations preserve remote management access.
func EvaluateManagementSafety(in ManagementSafetyInput) ManagementSafetyReport {
	rep := ManagementSafetyReport{
		Safe:                  true,
		SSHPathPreserved:      true,
		TailscalePreserved:    true,
		DefaultRoutePreserved: true,
	}

	if in.TailscaleInterface == "" {
		in.TailscaleInterface = "tailscale0"
	}

	// 1. Detect SSH from environment if not explicitly set
	if in.ActiveSSHIP == "" {
		if conn := os.Getenv("SSH_CONNECTION"); conn != "" {
			fields := strings.Fields(conn)
			if len(fields) >= 3 {
				in.ActiveSSHIP = fields[2]
			}
		}
	}
	rep.ManagementAddress = in.ActiveSSHIP
	rep.ManagementInterface = in.ActiveSSHInterface

	// 2. Tailscale safety boundary
	if in.TailscalePresent {
		for _, iface := range in.TouchedInterfaces {
			if iface == in.TailscaleInterface {
				rep.TailscalePreserved = false
				rep.Safe = false
				msg := fmt.Sprintf("plan mutates unmanaged Tailscale management interface %s", in.TailscaleInterface)
				rep.Findings = append(rep.Findings, msg)
				if rep.Reason == "" {
					rep.Reason = msg
				}
			}
		}
		for _, iface := range in.InterfaceDownActions {
			if iface == in.TailscaleInterface {
				rep.TailscalePreserved = false
				rep.Safe = false
				msg := fmt.Sprintf("plan sets down unmanaged Tailscale management interface %s", in.TailscaleInterface)
				rep.Findings = append(rep.Findings, msg)
				if rep.Reason == "" {
					rep.Reason = msg
				}
			}
		}
	}

	// 3. Active SSH safety boundary
	if in.ActiveSSHInterface != "" {
		for _, iface := range in.InterfaceDownActions {
			if iface == in.ActiveSSHInterface {
				rep.SSHPathPreserved = false
				rep.Safe = false
				msg := fmt.Sprintf("plan sets down the active SSH management interface %s", in.ActiveSSHInterface)
				rep.Findings = append(rep.Findings, msg)
				if rep.Reason == "" {
					rep.Reason = msg
				}
			}
		}

		if in.ActiveSSHIP != "" {
			if removed, ok := in.RemovedAddresses[in.ActiveSSHInterface]; ok {
				targetAddr, err := netip.ParseAddr(in.ActiveSSHIP)
				if err == nil {
					for _, rem := range removed {
						prefix, err := netip.ParsePrefix(rem)
						if err == nil && prefix.Addr() == targetAddr {
							rep.SSHPathPreserved = false
							rep.Safe = false
							msg := fmt.Sprintf("plan removes the active SSH management IP %s on interface %s", in.ActiveSSHIP, in.ActiveSSHInterface)
							rep.Findings = append(rep.Findings, msg)
							if rep.Reason == "" {
								rep.Reason = msg
							}
						}
					}
				}
			}
		}
	}

	// 4. Default route preservation
	if in.HasDefaultRoute && !in.PlannedDefaultRoute {
		rep.DefaultRoutePreserved = false
		rep.Safe = false
		msg := "plan eliminates the default route without replacement, risking management reachability"
		rep.Findings = append(rep.Findings, msg)
		if rep.Reason == "" {
			rep.Reason = msg
		}
	}

	return rep
}
