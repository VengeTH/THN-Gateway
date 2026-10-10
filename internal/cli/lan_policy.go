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
	// allowFastEthernet is the operator's deliberate opt-in. It is only
	// meaningful when at least one adapter is named below.
	allowFastEthernet bool

	// approved matches an interface by stable identity ("hw:...") or by
	// kernel name.
	//
	// Both forms are accepted because they are the two things an operator
	// has in front of them: `thn discover` prints the name, and the
	// configuration is written with the identity. Accepting the identity is
	// what makes the exception survive a rename or a different enumeration
	// order across reboots, which is the reason stable identities exist.
	approved map[string]bool
}

// productionLANPolicy is the default: production policy, nothing approved.
//
// It is returned whenever a caller has no configuration in hand. Making the
// fallback explicit — rather than assuming a zero value appears somewhere on
// its own — means a future code path that forgets to read the configuration
// fails closed and visibly, instead of silently inheriting whatever the last
// caller decided.
func productionLANPolicy() lanPolicy {
	return lanPolicy{}
}

// lanPolicyFromConfig derives the policy from the operator's document.
//
// A malformed document yields production policy rather than an error. The
// document validator already reports the malformed case as an error, and this
// function is on the path that builds gate verdicts; returning production
// policy here means a document that fails validation is also refused by the
// gates, which is the same refusal from two independent directions.
func lanPolicyFromConfig(cfg config.Config) lanPolicy {
	dev := cfg.Activation.Development

	if !dev.AllowFastEthernetLAN || len(dev.ApprovedFastEthernetLAN) == 0 {
		return productionLANPolicy()
	}

	approved := make(map[string]bool, len(dev.ApprovedFastEthernetLAN))
	for _, entry := range dev.ApprovedFastEthernetLAN {
		if entry = strings.TrimSpace(entry); entry != "" {
			approved[entry] = true
		}
	}
	if len(approved) == 0 {
		return productionLANPolicy()
	}

	return lanPolicy{allowFastEthernet: true, approved: approved}
}

// permitsFastEthernetLAN reports whether this specific adapter may fill the
// LAN role despite running below Gigabit speed.
//
// Both conditions are required. The flag alone is not authority — otherwise
// one boolean would admit every Fast Ethernet adapter on the host, which is
// the blanket bypass this type exists to prevent — and the name alone is not
// authority either, because a list with no flag is a contradiction an
// operator may have left behind by accident.
//
// An empty identity never matches, not even against an empty approval set.
// That is deliberate: an interface THN could not identify is not an adapter
// anybody approved.
func (p lanPolicy) permitsFastEthernetLAN(iface host.Interface) bool {
	if !p.allowFastEthernet || len(p.approved) == 0 {
		return false
	}
	if iface.ID == "" {
		return false
	}
	return p.approved[iface.ID] || (iface.SystemName != "" && p.approved[iface.SystemName])
}
