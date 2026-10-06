//go:build !linux

package network

// Everything except Linux.
//
// Host inspection is a Linux activity: /sys/class/net does not exist, `iw`
// speaks nl80211, and `ip -j -d link` is the shape of the data. On any other
// platform this source answers "unknown" for everything.
//
// That is the correct answer rather than a stub that returns something
// plausible. A link speed of zero and a link speed of "the NIC family this
// usually is" must not look alike to a caller, and the second one is how a
// planner ends up shaping a link it never measured.
//
// The snapshot reports Supported=false on these platforms anyway, so these
// methods are unreachable in normal use. They exist because the interface
// must be total, not because anything calls them here.

import (
	"context"
	"runtime"
)

// newHostInfo returns a source that knows nothing, and says so.
func newHostInfo(ctx context.Context) HostInfo {
	return &sysfsHostInfo{
		describe: "host facts are unavailable on " + runtime.GOOS +
			"; /sys/class/net and nl80211 are Linux interfaces",
		// Recorded as not-checked rather than left blank, so that a report
		// from a non-Linux host says plainly that nothing was looked at
		// instead of carrying an empty list that reads as "nothing to say".
		probes: []Probe{NotChecked("host-info", "sysfs-and-nl80211")},
	}
}
