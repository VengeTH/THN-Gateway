package dhcp

import (
	"context"
	"fmt"
	"time"

	"github.com/venth/thn-gateway/internal/identity"
	"github.com/venth/thn-gateway/internal/sandbox"
)

// LeaseSource reads leases from a backing server.
//
// This is the seam that keeps THN independent of which server issues leases.
// Today the only implementation is dnsmasq; a Kea or Kea-backed deployment
// implements the same two-method interface and nothing above it changes.
type LeaseSource interface {
	// Name identifies the backend, recorded on the leases it returns.
	Name() string

	// Leases reads the current lease set.
	//
	// It returns whatever it could read plus the problems it hit, rather than
	// failing: a lease file that is missing during startup is a normal state,
	// and one truncated line must not hide every other lease.
	Leases(ctx context.Context, root sandbox.Root) (*LeaseSet, error)
}

// LeaseSet is a lease observation with its provenance.
type LeaseSet struct {
	// Leases are the leases read.
	Leases []Lease `json:"leases"`

	// Source records which backend produced them.
	Source string `json:"source"`

	// CollectedAt is when the read happened.
	CollectedAt time.Time `json:"collected_at"`

	// Problems describes anything that could not be read.
	Problems []string `json:"problems,omitempty"`
}

// Active returns only the leases within their window at now.
func (s LeaseSet) Active(now time.Time) []Lease {
	out := make([]Lease, 0, len(s.Leases))
	for _, l := range s.Leases {
		if l.Active(now) {
			out = append(out, l)
		}
	}
	return out
}

// Collector reads leases and correlates them with device identity.
//
// It is read-only with respect to the lease file: it never writes to it, never
// deletes from it, and never asks the server to do either. The lease file
// belongs to the server, and a THN that modified it would race with the server
// that owns it.
type Collector struct {
	source LeaseSource
	reg    *identity.Registry
}

// NewCollector returns a collector reading from a source.
func NewCollector(src LeaseSource, reg *identity.Registry) *Collector {
	if reg == nil {
		reg = identity.NewRegistry()
	}
	return &Collector{source: src, reg: reg}
}

// Registry returns the device registry the collector populates.
func (c *Collector) Registry() *identity.Registry { return c.reg }

// Collect reads leases and correlates them.
//
// Devices are updated but never created from an address alone: a lease with no
// hardware address is recorded as a lease and left uncorrelated, because an
// address does not identify a device.
func (c *Collector) Collect(ctx context.Context, root sandbox.Root, now time.Time) (*LeaseSet, []DeviceChange, error) {
	set, err := c.source.Leases(ctx, root)
	if err != nil {
		return nil, nil, fmt.Errorf("reading leases from %s: %w", c.source.Name(), err)
	}
	if set == nil {
		return nil, nil, fmt.Errorf("lease source %s returned nothing", c.source.Name())
	}

	set.Source = c.source.Name()
	set.CollectedAt = now

	// Correlate each lease to a device, and note the devices that appeared.
	var changes []DeviceChange
	seen := make(map[string]bool, len(set.Leases))

	for i := range set.Leases {
		l := &set.Leases[i]
		l.Source = c.source.Name()

		obs := identity.Observation{
			MAC:         l.MAC,
			Address:     l.Address,
			Hostname:    l.Hostname,
			ClientID:    l.ClientID,
			VendorClass: l.VendorClass,
		}

		dev, wasKnown := c.reg.Observe(obs, now)
		if dev.ID == "" {
			// No hardware address, so no correlation is possible.
			continue
		}

		l.DeviceID = dev.ID

		if !wasKnown {
			changes = append(changes, DeviceChange{Device: dev, Kind: ChangeAppeared})
		} else if !seen[dev.ID] {
			seen[dev.ID] = true
		}
	}

	sortByMAC(changes)

	return set, changes, nil
}

// DeviceChangeKind classifies a change to the device registry.
type DeviceChangeKind string

const (
	// ChangeAppeared means THN saw hardware it had not seen before. This is
	// the first signal of an unexpected device on the network.
	ChangeAppeared DeviceChangeKind = "appeared"
	// ChangeAddress means a known device changed address.
	ChangeAddress DeviceChangeKind = "address"
)

// DeviceChange records one change to a known device.
type DeviceChange struct {
	// Device is the device after the change.
	Device identity.Device `json:"device"`
	// Kind classifies the change.
	Kind DeviceChangeKind `json:"kind"`
	// From is the previous address for a ChangeAddress.
	From string `json:"from,omitempty"`
}

// sortByMAC orders changes by hardware address for stable output.
func sortByMAC(changes []DeviceChange) {
	for i := 1; i < len(changes); i++ {
		for j := i; j > 0 && changes[j].Device.MAC < changes[j-1].Device.MAC; j-- {
			changes[j], changes[j-1] = changes[j-1], changes[j]
		}
	}
}
