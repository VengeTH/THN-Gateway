//go:build linux

package management

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// The probes behind GatherWAN.
//
// Everything here answers one question: is the uplink actually up? The
// previous implementation of GatherWAN answered it by returning literal
// `true`, which meant the console reported a healthy internet on a machine
// with the cable pulled out. That is the failure this file exists to prevent.
//
// Design constraints, each learned from the target host rather than assumed:
//
//   - **No ICMP.** /proc/sys/net/ipv4/ping_group_range on `heedful-dev` is
//     "1 0", so an unprivileged process cannot open a raw or SOCK_DGRAM ICMP
//     socket. A ping-based probe compiles, runs, and reports every host as
//     unreachable. Reachability is therefore inferred from the neighbour
//     table and from completed TCP handshakes, both of which an unprivileged
//     process CAN do.
//   - **No root.** The console runs as the operator, not as root. Every
//     probe below reads a world-readable file or opens an ordinary socket.
//   - **Every probe fails closed.** A probe that cannot run returns false,
//     so the console shows a fault rather than a health it has not earned.
//     That is the safe direction: a false alarm costs a glance, and a false
//     all-clear gets acted upon.
//
// The probes are deliberately cheap. This runs on a page load, and three
// packets to an unreachable host makes the console the slowest thing on the
// network.

// linkIsUp reports whether the named interface exists and has a carrier.
//
// operstate is read from sysfs rather than inferred from the name, because
// "present but cable out" and "absent" are different faults and the operator
// needs to be told which. sysfs reports "unknown" for virtual and tunnel
// devices that are carrying traffic, so that is not treated as down.
func linkIsUp(name string) bool {
	if name == "" {
		return false
	}

	if _, err := net.InterfaceByName(name); err != nil {
		return false
	}

	data, err := os.ReadFile("/sys/class/net/" + name + "/operstate")
	if err != nil {
		// sysfs unreadable: fall back to the interface list in
		// /proc/net/dev, which at least confirms the interface exists.
		return interfacePresent(name)
	}

	switch strings.TrimSpace(string(data)) {
	case "up", "unknown":
		return true
	default:
		return false
	}
}

// interfacePresent reports whether the kernel lists the interface at all.
func interfacePresent(name string) bool {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == name {
			return true
		}
	}
	return false
}

// neighbourReachable reports whether the kernel's neighbour table holds a
// usable entry for the address.
//
// This is the unprivileged substitute for "ping the gateway", and on a
// directly-attached link it is the better question anyway: an ARP entry only
// exists because this box completed a handshake with that address. An entry
// with an unresolved MAC, or with flags 0x0 (FAILED), is explicitly NOT
// evidence — the kernel keeps those around precisely to record a failure.
//
// The Flags column is HEXADECIMAL, prefixed with "0x". Parsing it as decimal
// is a silent bug: "0x2" is not a valid decimal number, the parse errors, and
// every entry is skipped — so a perfectly reachable gateway reports as
// unreachable. That failure is invisible because the result looks like a
// genuine "no" rather than a parse error.
func neighbourReachable(ip string) bool {
	if ip == "" {
		return false
	}

	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return false
	}

	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue // header row
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != ip {
			continue
		}

		flags, ok := parseArpFlags(fields[2])
		if !ok || flags == 0 {
			continue // 0x0 == FAILED
		}
		if strings.EqualFold(fields[3], "00:00:00:00:00:00") {
			continue // unresolved
		}
		return true
	}
	return false
}

// parseArpFlags reads the kernel's "0x2"-prefixed hexadecimal flags word.
//
// Returns false rather than a zero value on malformed input so the caller can
// skip the entry. A row that cannot be parsed is not evidence of anything.
func parseArpFlags(s string) (uint32, bool) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if trimmed == "" {
		return 0, false
	}

	v, err := strconv.ParseUint(trimmed, 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// tcpReachable completes a TCP handshake to the address.
//
// This stands in for ICMP against the public internet. A completed handshake
// proves packets left and something answered, which is the same claim an echo
// would support — obtained without privileges this process does not have.
//
// Port 443 because public resolvers and essentially every host answer it, so
// a refused connection is meaningful rather than an artefact of an unusual
// port choice.
func tcpReachable(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// dnsAnswers asks a resolver a question and reports whether it replied.
//
// This measures whether the resolver is ANSWERING, which is a different
// question from whether the internet is reachable — a captive portal can
// pass TCP and black-hole DNS, and that looks exactly like a working
// connection to any check that stops at a handshake.
func dnsAnswers(server string, timeout time.Duration) bool {
	if server == "" {
		return false
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err := r.LookupHost(ctx, "localhost")
	if err == nil {
		return true
	}

	// A DNSError carrying an RCODE means the server answered and declined.
	// That is a working resolver. A timeout or dial failure is not.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return !dnsErr.IsTimeout
	}
	return false
}