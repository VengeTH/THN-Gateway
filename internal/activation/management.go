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

	// Steps are the operations the assessment was made over.
	//
	// They are carried so the verdict is auditable: an operator who is told
	// "safe" can see exactly which operations were considered, rather than
	// having to trust that the assessor looked at the right plan.
	Steps []string `json:"steps,omitempty"`
}

// ManagementSafetyInput carries observed facts about remote management paths.
type ManagementSafetyInput struct {
	// TailscalePresent indicates an overlay tunnel exists on the host.
	TailscalePresent bool
	// TailscaleInterface is the name of that tunnel interface.
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
	}

	// The address the session arrives on is checked across every interface
	// the plan removes addresses from, not only the one named as the SSH
	// interface. A plan can delete an address from a link the caller did not
	// think carried the session, and matching by interface alone would miss
	// exactly the case where the two disagree.
	if in.ActiveSSHIP != "" {
		targetAddr, err := netip.ParseAddr(in.ActiveSSHIP)
		if err == nil {
			for iface, removed := range in.RemovedAddresses {
				for _, rem := range removed {
					prefix, perr := netip.ParsePrefix(rem)
					if perr != nil {
						continue
					}
					if prefix.Addr() != targetAddr {
						continue
					}
					rep.SSHPathPreserved = false
					rep.Safe = false
					msg := fmt.Sprintf("plan removes the active SSH management IP %s from interface %s", in.ActiveSSHIP, iface)
					rep.Findings = append(rep.Findings, msg)
					if rep.Reason == "" {
						rep.Reason = msg
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
