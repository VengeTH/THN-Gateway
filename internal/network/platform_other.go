//go:build !linux

package network

import "runtime"

// goos is the runtime platform, exposed so Snapshot can report it.
const goos = runtime.GOOS

// arch is the runtime architecture, exposed so Platform can report it.
const arch = runtime.GOARCH

// supported is false off Linux: THN targets a Linux gateway, and there is
// nothing meaningful to observe on a developer laptop. Reporting
// "unsupported" keeps `thn status` honest instead of inventing interfaces.
const supported = false
