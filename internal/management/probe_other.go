//go:build !linux

package management

import "time"

// Non-Linux stubs.
//
// THN's host inspection is Linux-only by design: the probes read sysfs,
// /proc/net/route and /proc/net/arp, none of which exist elsewhere. This file
// exists so a developer laptop can build and run the console without the
// package failing to compile.
//
// Every probe returns false, which fails closed — the console reports the
// uplink as unreachable rather than inventing a healthy one. That is the
// correct behaviour for a machine that cannot observe the question: a
// developer running `next dev` sees "unknown/unreachable", not a fabricated
// all-clear.
//
// This mirrors how internal/network reports an unsupported host: an explicit
// "nothing was observed", never a silent success.

func linkIsUp(string) bool { return false }

func neighbourReachable(string) bool { return false }

func tcpReachable(string, time.Duration) bool { return false }

func dnsAnswers(string, time.Duration) bool { return false }