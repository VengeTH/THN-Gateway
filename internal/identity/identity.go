package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Confidence describes how strongly an identity is established.
type Confidence string

const (
	// ConfidenceStrong means established by hardware address, which is the
	// strongest signal available on a wired or wireless LAN.
	ConfidenceStrong Confidence = "strong"
	// ConfidenceProbable means established by a combination of signals that
	// agree, such as a MAC plus a consistent hostname.
	ConfidenceProbable Confidence = "probable"
	// ConfidenceWeak means established by a self-reported value alone, such as
	// a hostname, which any client can claim.
	ConfidenceWeak Confidence = "weak"
	// ConfidenceUnknown means nothing beyond an address is known.
	ConfidenceUnknown Confidence = "unknown"
)

// rank orders confidences for comparison.
func (c Confidence) rank() int {
	switch c {
	case ConfidenceStrong:
		return 3
	case ConfidenceProbable:
		return 2
	case ConfidenceWeak:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether c is at least as strong as other.
func (c Confidence) AtLeast(other Confidence) bool { return c.rank() >= other.rank() }

// Device is a persistent identity on the network.
type Device struct {
	// ID is a stable synthetic identifier, derived from the hardware address
	// so that the same device keeps the same ID across restarts and across
	// backends.
	ID string `json:"id"`

	// MAC is the normalised hardware address that defines the device.
	MAC string `json:"mac"`

	// Hostnames are the names the device has reported, most recent first.
	Hostnames []string `json:"hostnames,omitempty"`

	// ClientID is the DHCP client identifier, when the device sent one.
	ClientID string `json:"client_id,omitempty"`

	// VendorClass is the option 43 vendor class, when present.
	VendorClass string `json:"vendor_class,omitempty"`

	// Confidence records how the identity was established.
	Confidence Confidence `json:"confidence"`

	// FirstSeen is when THN first observed the device.
	FirstSeen time.Time `json:"first_seen"`

	// LastSeen is the most recent observation.
	LastSeen time.Time `json:"last_seen"`

	// Addresses are the addresses this device has held, most recent first.
	// This is the device's address history, which is what makes it possible
	// to answer a question about an address that is no longer current.
	Addresses []netip.Addr `json:"addresses,omitempty"`
}

// CurrentAddress returns the most recent address, if any.
func (d Device) CurrentAddress() (netip.Addr, bool) {
	if len(d.Addresses) == 0 {
		return netip.Addr{}, false
	}
	return d.Addresses[0], true
}

// PrimaryHostname returns the most recently reported hostname, or "".
func (d Device) PrimaryHostname() string {
	if len(d.Hostnames) == 0 {
		return ""
	}
	return d.Hostnames[0]
}

// Age returns how long the device has been known.
func (d Device) Age(now time.Time) time.Duration { return now.Sub(d.FirstSeen) }

// IDFor derives the stable device ID from a hardware address.
//
// The ID is derived rather than random so that two THN installations observing
// the same device agree on its identity, and so that a device keeps its ID
// across a restart without needing to be persisted first.
func IDFor(mac string) string {
	sum := sha256.Sum256([]byte("thn-device:" + strings.ToLower(strings.TrimSpace(mac))))
	return "dev_" + hex.EncodeToString(sum[:])[:16]
}

// Registry holds known devices and correlates observations to them.
//
// The registry is safe for concurrent use. It is held in memory and owned by
// the daemon; persistence is the store's job.
type Registry struct {
	mu      sync.RWMutex
	devices map[string]*Device
	maxHost int
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		devices: make(map[string]*Device),
		maxHost: 8,
	}
}

// Len returns the number of known devices.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.devices)
}

// Observe records an observation and returns the device it correlates to.
//
// Correlation is by hardware address. An observation with no MAC cannot be
// correlated, because an address alone does not identify a device: DHCP
// reassigns addresses, and treating an address as an identity is precisely
// the mistake this package exists to avoid.
func (r *Registry) Observe(o Observation, now time.Time) (Device, bool) {
	mac := normaliseMAC(o.MAC)
	if mac == "" {
		return Device{}, false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	id := IDFor(mac)

	d, known := r.devices[id]
	if !known {
		d = &Device{
			ID:         id,
			MAC:        mac,
			FirstSeen:  now,
			Confidence: ConfidenceUnknown,
		}
		r.devices[id] = d
	}

	d.LastSeen = now

	if o.Address.IsValid() {
		d.Addresses = promote(d.Addresses, o.Address)
	}
	if o.Hostname != "" {
		d.Hostnames = promoteString(d.Hostnames, o.Hostname, r.maxHost)
	}
	if o.ClientID != "" {
		d.ClientID = o.ClientID
	}
	if o.VendorClass != "" {
		d.VendorClass = o.VendorClass
	}

	// Confidence is the strongest signal this observation carried, not the
	// sum of them: a device does not become more trustworthy because it has
	// been seen more times.
	if c := confidenceOf(o); c.rank() > d.Confidence.rank() {
		d.Confidence = c
	}

	return *d, known
}

// Get returns a device by its ID.
func (r *Registry) Get(id string) (Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.devices[id]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// ByMAC returns a device by hardware address.
func (r *Registry) ByMAC(mac string) (Device, bool) {
	return r.Get(IDFor(mac))
}

// All returns every known device, ordered by MAC so that output is stable.
func (r *Registry) All() []Device {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Device, 0, len(r.devices))
	for _, d := range r.devices {
		out = append(out, *d)
	}
	sortBy(out, func(a, b Device) bool { return a.MAC < b.MAC })
	return out
}

// FindByAddress returns devices that have held an address.
func (r *Registry) FindByAddress(addr netip.Addr) []Device {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []Device
	for _, d := range r.devices {
		for _, a := range d.Addresses {
			if a == addr {
				out = append(out, *d)
				break
			}
		}
	}
	sortBy(out, func(a, b Device) bool { return a.MAC < b.MAC })
	return out
}

// Observation is a sighting of a device.
type Observation struct {
	// MAC is the hardware address, when the source provides one.
	MAC string `json:"mac,omitempty"`
	// Address is the address the device held.
	Address netip.Addr `json:"address,omitempty"`
	// Hostname is the name the device reported.
	Hostname string `json:"hostname,omitempty"`
	// ClientID is the DHCP client identifier.
	ClientID string `json:"client_id,omitempty"`
	// VendorClass is the option 43 vendor class.
	VendorClass string `json:"vendor_class,omitempty"`
}

// confidenceOf derives the confidence an observation supports.
//
// A hardware address alone is strong: it is the only signal that does not
// depend on the device claiming something about itself. A hostname alone is
// weak, because any client can send any name. Both together are probable,
// because they are independent sources.
func confidenceOf(o Observation) Confidence {
	hasMAC := normaliseMAC(o.MAC) != ""
	hasName := o.Hostname != ""

	switch {
	case hasMAC && hasName:
		return ConfidenceProbable
	case hasMAC:
		return ConfidenceStrong
	case hasName:
		return ConfidenceWeak
	default:
		return ConfidenceUnknown
	}
}

// normaliseMAC returns the MAC in lowercase colon form, or "".
func normaliseMAC(mac string) string {
	s := strings.ToLower(strings.TrimSpace(mac))
	if s == "" {
		return ""
	}
	return s
}

// promote moves v to the front of the list if present, or prepends it.
func promote(list []netip.Addr, v netip.Addr) []netip.Addr {
	for i, existing := range list {
		if existing == v {
			copy(list[i:], list[i+1:])
			list[len(list)-1] = v
			return list
		}
	}
	return append([]netip.Addr{v}, list...)
}

// promoteString moves v to the front of the list if present, or prepends it.
func promoteString(list []string, v string, max int) []string {
	for i, existing := range list {
		if strings.EqualFold(existing, v) {
			copy(list[i:], list[i+1:])
			list[len(list)-1] = v
			return list
		}
	}
	list = append([]string{v}, list...)
	if max > 0 && len(list) > max {
		list = list[:max]
	}
	return list
}

// sortBy orders a slice using a comparison function.
func sortBy[T any](s []T, less func(a, b T) bool) {
	// Insertion sort: the registry holds one entry per device, which is a few
	// dozen at most on a home network, so a comparison sort's setup cost is
	// not worth avoiding.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && less(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// String renders a device for display.
func (d Device) String() string {
	name := d.PrimaryHostname()
	if name == "" {
		name = "(unnamed)"
	}
	addr, ok := d.CurrentAddress()
	if !ok {
		return fmt.Sprintf("%-16s %-17s (no address)", name, d.MAC)
	}
	return fmt.Sprintf("%-16s %-16s %s", name, addr.String(), d.MAC)
}
