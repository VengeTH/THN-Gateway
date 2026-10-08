package tc

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// HTBRootArgs builds the arguments to install an HTB root queue discipline on an interface.
//
// defaultClassID is the minor handle (e.g. "99") traffic without a matching filter falls into.
func HTBRootArgs(iface, defaultClassID string) ([]string, error) {
	if iface == "" {
		return nil, fmt.Errorf("interface must not be empty")
	}
	if defaultClassID == "" {
		defaultClassID = "99"
	}
	return []string{
		"qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", defaultClassID,
	}, nil
}

// HTBClassArgs builds the arguments to install an HTB class.
//
// rateKbps is the guaranteed minimum rate.
// ceilKbps is the ceiling maximum rate.
// prio is the 0-7 integer priority band (0 is highest priority).
func HTBClassArgs(iface, parent, classID string, rateKbps, ceilKbps, prio int) ([]string, error) {
	if iface == "" {
		return nil, fmt.Errorf("interface must not be empty")
	}
	if parent == "" {
		return nil, fmt.Errorf("parent must not be empty")
	}
	if classID == "" {
		return nil, fmt.Errorf("classID must not be empty")
	}
	if rateKbps <= 0 {
		rateKbps = 100 // fallback base
	}
	if ceilKbps < rateKbps {
		ceilKbps = rateKbps
	}
	if prio < 0 || prio > 7 {
		prio = 2
	}

	rateStr, err := rateArg(rateKbps)
	if err != nil {
		return nil, fmt.Errorf("invalid rate: %w", err)
	}
	ceilStr, err := rateArg(ceilKbps)
	if err != nil {
		return nil, fmt.Errorf("invalid ceil: %w", err)
	}

	return []string{
		"class", "replace", "dev", iface, "parent", parent, "classid", classID,
		"htb", "rate", rateStr, "ceil", ceilStr, "prio", strconv.Itoa(prio),
	}, nil
}

// FilterFwmarkArgs builds a tc filter that classifies packets by their fwmark.
func FilterFwmarkArgs(iface, parent string, prio int, handleHex string, targetClassID string) ([]string, error) {
	if iface == "" || parent == "" || targetClassID == "" {
		return nil, fmt.Errorf("iface, parent, and targetClassID must not be empty")
	}
	if prio <= 0 {
		prio = 1
	}
	if handleHex == "" {
		return nil, fmt.Errorf("fwmark handle must not be empty")
	}
	if !strings.HasPrefix(handleHex, "0x") && !strings.HasPrefix(handleHex, "0X") {
		handleHex = "0x" + handleHex
	}

	return []string{
		"filter", "replace", "dev", iface, "parent", parent,
		"protocol", "ip", "prio", strconv.Itoa(prio),
		"handle", handleHex, "fw", "classid", targetClassID,
	}, nil
}

// FilterIPArgs builds a u32 filter matching source or destination IP.
func FilterIPArgs(iface, parent string, prio int, ipMatch string, isSrc bool, targetClassID string) ([]string, error) {
	if iface == "" || parent == "" || targetClassID == "" {
		return nil, fmt.Errorf("iface, parent, and targetClassID must not be empty")
	}
	if prio <= 0 {
		prio = 1
	}
	// Parse IP or CIDR
	cidr := ipMatch
	if !strings.Contains(cidr, "/") {
		if addr, err := netip.ParseAddr(ipMatch); err == nil {
			if addr.Is4() {
				cidr = addr.String() + "/32"
			} else {
				cidr = addr.String() + "/128"
			}
		} else {
			return nil, fmt.Errorf("invalid ip match %q: %w", ipMatch, err)
		}
	} else {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return nil, fmt.Errorf("invalid cidr match %q: %w", cidr, err)
		}
	}

	dir := "dst"
	if isSrc {
		dir = "src"
	}

	return []string{
		"filter", "replace", "dev", iface, "parent", parent,
		"protocol", "ip", "prio", strconv.Itoa(prio),
		"u32", "match", "ip", dir, cidr, "flowid", targetClassID,
	}, nil
}

// CakeLeafArgs builds a leaf CAKE qdisc attached under an HTB class in unshaped mode (unlimited).
//
// Running CAKE with "unlimited" under an HTB class allows HTB to control rate,
// ceiling, priority, and borrowing without double-shaping or conflicting with
// CAKE's internal deficit shaper, while retaining CAKE's flow isolation and COBALT AQM.
func CakeLeafArgs(iface, parentClassID, handle string, isIngress bool) ([]string, error) {
	if iface == "" || parentClassID == "" || handle == "" {
		return nil, fmt.Errorf("iface, parent, and handle must not be empty")
	}

	args := []string{
		"qdisc", "replace", "dev", iface, "parent", parentClassID, "handle", handle,
		"cake", "unlimited", "besteffort",
	}
	if isIngress {
		args = append(args, "ingress")
	}
	return args, nil
}

// CakeShapedLeafArgs builds a leaf CAKE qdisc with an explicit internal rate shaper.
func CakeShapedLeafArgs(iface, parentClassID, handle string, bandwidthKbps int, isIngress bool) ([]string, error) {
	if iface == "" || parentClassID == "" || handle == "" {
		return nil, fmt.Errorf("iface, parent, and handle must not be empty")
	}
	if bandwidthKbps <= 0 {
		return nil, fmt.Errorf("bandwidth must be positive")
	}

	rateStr, err := rateArg(bandwidthKbps)
	if err != nil {
		return nil, err
	}

	args := []string{
		"qdisc", "replace", "dev", iface, "parent", parentClassID, "handle", handle,
		"cake", "bandwidth", rateStr, "besteffort",
	}
	if isIngress {
		args = append(args, "ingress")
	}
	return args, nil
}

// FqCodelLeafArgs builds a leaf fq_codel qdisc attached under an HTB class.
func FqCodelLeafArgs(iface, parentClassID, handle string, mtu int) ([]string, error) {
	if iface == "" || parentClassID == "" || handle == "" {
		return nil, fmt.Errorf("iface, parent, and handle must not be empty")
	}
	if mtu <= 0 {
		mtu = 1500
	}
	return []string{
		"qdisc", "replace", "dev", iface, "parent", parentClassID, "handle", handle,
		"fq_codel", "limit", "1024", "flows", "64", "quantum", strconv.Itoa(mtu),
	}, nil
}
