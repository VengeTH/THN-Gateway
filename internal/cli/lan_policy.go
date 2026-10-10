package cli

import (
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
)

// The Fast Ethernet LAN exception, as a value the gates read.
//
// # The problem this file exists to solve
//
// THN's production policy is that a LAN role must be filled by a Gigabit
// wired interface. That policy is correct and it stays. But the hardware an
// operator is standing in front of while developing THN may not be the
// hardware THN will eventually ship on — a 100 Mbps USB Ethernet adapter is a
// perfectly reasonable thing to develop against, and refusing to activate on
// it means the rest of the system cannot be exercised on the hardware the
// operator actually owns.
//
// The temptation is to delete the speed check. That is the wrong fix, because
// the check is not the obstacle; the *absence of a way to say "this specific
// adapter, deliberately"* is. An operator with no sanctioned route to a
// development configuration will either patch the source or abandon the test,
// and both outcomes are worse than a scoped exception.
//
// # What this type is
//
// A decision, expressed once, derived from configuration, and consulted by
// exactly one gate. It answers a single question: may THIS adapter, at THIS
// link speed, fill the LAN role on this host?
//
// It deliberately cannot answer anything else. It does not touch the WAN
// role, it does not touch the firewall, the routing, the authentication, the
// management-path or the rollback gates, and there is no field on it that
// could be used to reach any of those. Relaxing LAN hardware is the whole of
// what it can do.

// lanPolicy is the operator's explicit decision about which LAN adapters may
// be slow.
//
// The zero value is production policy: nothing is approved, and every
// sub-Gigabit wired LAN adapter is rejected. That direction is the important
// one — code that constructs a lanPolicy without consulting configuration gets
// the safe behaviour, not the permissive one.
type lanPolicy struct {
	// productionApproved names adapters explicitly approved for production deployment.
	productionApproved map[string]bool

	// developmentApproved names adapters permitted under a development override.
	developmentApproved map[string]bool
}

// productionLANPolicy is the default: production policy, nothing approved.
func productionLANPolicy() lanPolicy {
	return lanPolicy{}
}

// lanPolicyFromConfig derives the policy from the operator's document.
func lanPolicyFromConfig(cfg config.Config) lanPolicy {
	prodApproved := make(map[string]bool)
	for _, entry := range cfg.Activation.ApprovedFastEthernetLAN {
		if entry = strings.TrimSpace(entry); entry != "" {
			prodApproved[entry] = true
		}
	}

	devApproved := make(map[string]bool)
	dev := cfg.Activation.Development
	if dev.AllowFastEthernetLAN && len(dev.ApprovedFastEthernetLAN) > 0 {
		for _, entry := range dev.ApprovedFastEthernetLAN {
			if entry = strings.TrimSpace(entry); entry != "" {
				devApproved[entry] = true
			}
		}
	}

	return lanPolicy{
		productionApproved:  prodApproved,
		developmentApproved: devApproved,
	}
}

// permitsProductionFastEthernetLAN reports whether this adapter is explicitly
// approved for production deployment at Fast Ethernet line rates.
func (p lanPolicy) permitsProductionFastEthernetLAN(iface host.Interface) bool {
	if len(p.productionApproved) == 0 || iface.ID == "" {
		return false
	}
	return p.productionApproved[iface.ID] || (iface.SystemName != "" && p.productionApproved[iface.SystemName])
}

// permitsDevelopmentFastEthernetLAN reports whether this adapter is permitted
// under an operator development override.
func (p lanPolicy) permitsDevelopmentFastEthernetLAN(iface host.Interface) bool {
	if len(p.developmentApproved) == 0 || iface.ID == "" {
		return false
	}
	return p.developmentApproved[iface.ID] || (iface.SystemName != "" && p.developmentApproved[iface.SystemName])
}

// permitsFastEthernetLAN reports whether this specific adapter may fill the
// LAN role despite running below Gigabit speed (under either production approval
// or development override).
func (p lanPolicy) permitsFastEthernetLAN(iface host.Interface) bool {
	return p.permitsProductionFastEthernetLAN(iface) || p.permitsDevelopmentFastEthernetLAN(iface)
}
