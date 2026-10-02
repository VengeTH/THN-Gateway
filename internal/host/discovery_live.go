package host

// The live discovery seam.
//
// # What this file is
//
// `Discovery` was declared in this package and had no implementation. The
// model could be built from a snapshot — which the tests do — but nothing
// connected it to a machine. So `thn discover` and `thn readiness` assembled
// a snapshot themselves, each slightly differently, and there was no single
// place where "observe this host" was decided.
//
// This file supplies that place, and it is deliberately thin: it runs the
// read-only inspector, then hands the result to FromSnapshot. FromSnapshot
// remains the ONE function that turns an observation into a Device.
//
// # Why it is this thin
//
// Everything that could make discovery unsafe would have to live here: an
// `exec` call, a `/sys` write, a netlink mutation. None of it does any such
// thing, and the reason is structural rather than a matter of care:
//
//   - the only capability this type has is a network.Inspector, whose sole
//     method is Inspect;
//   - internal/network runs every command through internal/guard, whose
//     allowlist contains inspection verbs only and fails closed;
//   - and TestRepoContainsNoUnguardedExec AST-walks every .go file in the
//     repository and fails if any exec call names a binary outside that
//     allowlist.
//
// So "discovery cannot change the host" is not a property of this code being
// careful. It is a property of the types it is allowed to hold.
//
// # Injectable, so the model can be tested without a machine
//
// The inspector is a field rather than a direct call to network.NewInspector.
// That is what lets TestLiveDiscoveryTranslatesAnInspection exercise the real
// translation path on a laptop with no network interfaces to look at, and it
// is also what lets the Linux integration test be the only place that needs
// Linux.

import (
	"context"
	"fmt"
	"runtime"

	"github.com/venth/thn-gateway/internal/network"
)

// Live is the Discovery backed by the real machine.
type Live struct {
	inspector network.Inspector
}

// NewDiscovery returns a Discovery that observes this host.
//
// It performs no I/O. Nothing is read until Discover is called, so
// constructing one is free and safe.
func NewDiscovery() *Live {
	return &Live{inspector: network.NewInspector()}
}

// NewDiscoveryWith returns a Live discovery over a supplied inspector.
//
// It exists for tests, and for any future caller that already has a snapshot
// in hand. It does not bypass the translation: the result still goes through
// FromSnapshot, so an injected inspector cannot produce a Device that the real
// one would not.
func NewDiscoveryWith(insp network.Inspector) *Live {
	return &Live{inspector: insp}
}

// Discover observes the host with a background context.
//
// It is the interface method. Callers that have their own context — the CLI
// has one, so that Ctrl-C stops a hung inspection — should use
// DiscoverContext, because a background context cannot be cancelled and a
// hung `ip` call would then hang the process.
func (l *Live) Discover() (*Device, error) {
	return l.DiscoverContext(context.Background())
}

// DiscoverContext observes the host and translates it into a Device.
//
// It returns a Device even when the host cannot be inspected. An unsupported
// platform or a missing `ip` produces a Device with Supported=false, no
// interfaces and a diagnostic saying why — NOT an error, because "this
// machine could not be inspected" is an answer the operator needs, and an
// error would read as "THN is broken" instead.
//
// The error return is reserved for the case where the result cannot be
// represented at all.
func (l *Live) DiscoverContext(ctx context.Context) (*Device, error) {
	_, d, err := l.Observe(ctx)
	return d, err
}

// Observe returns both the raw snapshot and the translated Device.
//
// Two callers need both and one needs only the Device. Rather than have the
// Device-wanting caller run the inspector a second time — which on a live
// gateway means two `ip` invocations that can disagree, because the network
// changed between them — the snapshot and its translation are produced once
// and handed out together.
//
// The two are therefore guaranteed to describe the same instant. That
// guarantee is why this exists rather than two independent calls.
func (l *Live) Observe(ctx context.Context) (*network.Snapshot, *Device, error) {
	if l == nil || l.inspector == nil {
		return nil, nil, fmt.Errorf("host: no inspector configured")
	}

	snap, err := l.inspector.Inspect(ctx)
	if snap == nil {
		if err != nil {
			return nil, nil, fmt.Errorf("host: inspection produced no snapshot: %w", err)
		}
		return nil, nil, fmt.Errorf("host: inspection produced no snapshot and no error")
	}

	d := FromSnapshot(snap)
	if d.Supported && len(d.Interfaces) == 0 {
		// A supported host with no interfaces at all is either genuinely
		// empty or a parse that silently matched nothing. Saying so
		// explicitly is the difference between "this machine has no network"
		// and "THN cannot read this machine's network", and only one of those
		// is a reason for an operator to go looking at the hardware.
		d.Diagnostics = append(d.Diagnostics,
			fmt.Sprintf("host inspection reported %s/%s as supported but observed no interfaces; "+
				"either the host truly has none, or `ip -j -d link show` produced nothing THN could read",
				d.OS, d.Arch))
	}
	return snap, d, nil
}

// Describe names the implementation, for `thn discover --json` and for
// diagnostics that need to say where a Device came from.
//
// It states the platform rather than claiming universality, because the
// honest answer on a developer laptop is "this is the Linux inspector, and it
// does not run here" — and a caller that prints that has told the operator
// something useful.
func (l *Live) Describe() string {
	return fmt.Sprintf("live inspection via internal/network on %s/%s", runtime.GOOS, runtime.GOARCH)
}

// compile-time proof that the seam is closed.
var _ Discovery = (*Live)(nil)

// staticDiscovery is a Discovery over a fixed snapshot.
//
// It exists so that a caller which needs a Discovery value — a test, or a
// future UI binding — can have one without a machine. It is not used in
// production: a Discovery that always returns the same thing would be a very
// effective way to make a test pass and a gateway wrong.
type staticDiscovery struct{ device *Device }

func (s staticDiscovery) Discover() (*Device, error) { return s.device, nil }
func (s staticDiscovery) Describe() string           { return "static snapshot; not a live host" }

// NewStaticDiscovery returns a Discovery over a pre-built Device.
//
// It is exported so that the Linux integration test and any future consumer
// can bind the interface without a machine. It deliberately describes itself
// as static, so a Device that reaches an operator through it is visibly not
// a live observation.
func NewStaticDiscovery(d *Device) Discovery { return staticDiscovery{device: d} }

var _ Discovery = staticDiscovery{}
