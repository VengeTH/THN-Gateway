//go:build linux

package network

import "runtime"

// goos is the runtime platform, exposed so Snapshot can report it.
const goos = runtime.GOOS

// arch is the runtime architecture, exposed so Platform can report it without
// importing runtime twice.
const arch = runtime.GOARCH

// supported reports whether host inspection is available. Linux is the
// deployment target and the only platform where iproute2 output is meaningful.
const supported = true
