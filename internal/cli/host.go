package cli

import (
	"context"
	"os"
	"time"
)

// cmdTimeout bounds every host inspection the CLI performs.
//
// A read-only observation should complete in milliseconds. A generous but
// finite timeout means that a hung iproute2 or an unresponsive netlink query
// produces a clear error rather than an apparently hung command, which matters
// because these commands run unattended in CI.
const cmdTimeout = 10 * time.Second

// cmdContext returns a context bounded by cmdTimeout.
//
// Every call spawns a fresh context, so cancelling one inspection cannot
// affect another.
func cmdContext() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	// The cancel function is intentionally not threaded through: the context
	// is bounded by a timeout, so the timer is released without it. Attaching
	// it would require every caller to defer cancel, which is easy to forget
	// in a function that returns a struct rather than an error.
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}

// hostname returns the local hostname, or an empty string when it cannot be
// determined.
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
