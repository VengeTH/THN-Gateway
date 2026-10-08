package management

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var (
	ErrWANAccessDenied    = errors.New("policy: WAN management access is strictly disabled")
	ErrUntrustedNetworkIP = errors.New("policy: remote IP is not within permitted LAN/MGMT networks")
	ErrInvalidClientIP    = errors.New("policy: unable to determine client IP address")
)

// BindPolicy governs network-level access controls for the management plane.
type BindPolicy struct {
	BindAddress     string
	AllowedNetworks []netip.Prefix
	WANAccess       bool
}

// NewBindPolicy parses and validates CIDR ranges for management access.
func NewBindPolicy(bindAddr string, allowedCIDRs []string, wanAccess bool) (*BindPolicy, error) {
	if wanAccess {
		return nil, fmt.Errorf("safety violation: WAN access cannot be enabled on management service")
	}

	var prefixes []netip.Prefix
	for _, cidr := range allowedCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("parsing allowed CIDR %q: %w", cidr, err)
		}
		prefixes = append(prefixes, p)
	}

	// Always ensure localhost is allowed for local daemon queries
	loopback4 := netip.MustParsePrefix("127.0.0.0/8")
	loopback6 := netip.MustParsePrefix("::1/128")
	prefixes = append(prefixes, loopback4, loopback6)

	return &BindPolicy{
		BindAddress:     bindAddr,
		AllowedNetworks: prefixes,
		WANAccess:       false,
	}, nil
}

// AuthorizeClientIP checks if an incoming remote IP is permitted to reach the API.
func (bp *BindPolicy) AuthorizeClientIP(remoteAddr string) error {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidClientIP, remoteAddr)
	}

	// Check if IP matches any allowed LAN / MGMT subnet
	for _, prefix := range bp.AllowedNetworks {
		if prefix.Contains(ip) {
			return nil
		}
	}

	return fmt.Errorf("%w: %s not in allowed subnets", ErrUntrustedNetworkIP, ip)
}
