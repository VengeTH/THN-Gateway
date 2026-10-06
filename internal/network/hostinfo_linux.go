//go:build linux

package network

// Linux implementation of HostInfo.
//
// Two sources, both the kernel's own:
//
//   - nl80211 through a bare `iw dev` dump, which is the only one that works
//     on a current mac80211 driver;
//   - /sys/class/net/<iface>, the kernel's own attribute for link speed and
//     the legacy Wireless Extensions view as a fallback.
//
// Everything here reads. Nothing writes, nothing creates, and the single
// external command is a dump through internal/guard.

import (
	"context"
	"runtime"
)

// sysfsNetClass is where the kernel exposes one directory per interface.
const sysfsNetClass = "/sys/class/net"

// newHostInfo returns the live source for this host.
//
// It runs `iw dev` once at construction so that a snapshot's interfaces and
// its wireless modes come from the same instant rather than from two reads
// that could straddle a mode change.
func newHostInfo(ctx context.Context) HostInfo {
	modes, known, probe := readWirelessModes(ctx)

	describe := "sysfs " + sysfsNetClass
	if known {
		describe += " + nl80211 via `iw dev`"
	} else {
		// Said plainly, because a missing source must never read as a
		// negative finding.
		describe += "; `iw dev` was unavailable, so wireless mode could not be established"
	}

	return &sysfsHostInfo{
		root:       sysfsNetClass,
		modes:      modes,
		modesKnown: known,
		describe:   describe + " on " + runtime.GOOS,
		probes:     []Probe{probe},
	}
}
