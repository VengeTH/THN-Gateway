package dnsmasq

import (
	"context"
	"os"
	"strconv"

	"github.com/VengeTH/THN-Gateway/internal/dhcp"
	"github.com/VengeTH/THN-Gateway/internal/sandbox"
)

// LeaseSource reads leases from a dnsmasq lease file.
//
// It is read-only. It never writes, truncates or deletes the lease file, and
// never signals the dnsmasq process: the file belongs to the server, and a
// reader that modifies it races with the writer that owns it.
type LeaseSource struct {
	// Path is the lease file, as configured. It is resolved against the
	// sandbox root rather than used directly, so a test never reads the host's
	// real lease file by accident.
	Path string
}

// Name identifies the backend.
func (s LeaseSource) Name() string { return BackendName }

// Leases reads the lease file and parses it.
//
// A missing file is reported as a problem on the set rather than as an error:
// before dnsmasq has ever run there is no lease file, and that is a normal
// state during development rather than a fault.
func (s LeaseSource) Leases(ctx context.Context, root sandbox.Root) (*dhcp.LeaseSet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	full := root.Resolve(s.Path)

	data, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			return &dhcp.LeaseSet{
				Leases:   []dhcp.Lease{},
				Source:   BackendName,
				Problems: []string{"lease file " + s.Path + " does not exist; no leases have been issued"},
			}, nil
		}
		return nil, err
	}

	parsed := ParseLeases(string(data), BackendName)

	set := &dhcp.LeaseSet{
		Leases: parsed.Leases,
		Source: BackendName,
	}

	// A parse problem is surfaced as a problem on the set. The leases that
	// did parse are still returned, because a truncated final line must not
	// hide every other lease in the file.
	for _, e := range parsed.Errors {
		set.Problems = append(set.Problems,
			"lease file line "+itoa(e.Line)+": "+e.Message)
	}

	return set, nil
}

// itoa renders an int without importing strconv at every call site.
func itoa(n int) string { return strconv.Itoa(n) }

// WriteLeaseFile writes a lease set in dnsmasq's format.
//
// This exists for tests and for a future lease writer. No production path
// calls it: the lease file belongs to the server, and THN writing it would
// create two writers for one file.
func WriteLeaseFile(root sandbox.Root, path string, leases []dhcp.Lease) error {
	return root.WriteFile(path, FormatLeases(leases), 0o644)
}
