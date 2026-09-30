// Package netns provides an isolated network namespace for testing traffic
// shaping.
//
// # Why a namespace
//
// Traffic shaping attaches to a network interface, so testing it properly
// means touching a network interface. Doing that on the host would change the
// host's networking — which is exactly the thing this project must never do.
//
// A network namespace gives an isolated network stack: its own interfaces,
// its own routes, its own qdiscs. A test can create a dummy interface, attach
// CAKE to it, read statistics, and tear the whole thing down, with none of it
// visible to the host or to anything running on it.
//
// # What a namespace can and cannot do
//
// A namespace gives isolation, not a fake kernel. It does not simulate a
// congested link, a slow uplink or a real bottleneck queue. What it does give
// is the thing that cannot be tested any other way — that the generated
// commands are accepted by a real kernel, that the qdisc reports the
// bandwidth it was given, and that statistics parse from real tc output.
//
// That is worth having. It is not the same as testing under load, and this
// package does not pretend otherwise.
//
// # This package is the one place exec is allowed
//
// The rest of THN routes every external process through internal/guard, which
// permits inspection and nothing else. This package deliberately sits outside
// that: it runs `tc qdisc add` and `ip link add` on purpose.
//
// The safety argument is that it cannot reach the host. Every command it runs
// is scoped to a namespace created and destroyed within a single call, so
// there is no code path from here to a real interface. The guard test in
// internal/guard exempts this file explicitly, and that exemption is reviewed
// rather than assumed — widening it to any other package would break the
// invariant the whole project rests on.
package netns

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// Namespace is an isolated network namespace.
type Namespace struct {
	// Name identifies the namespace, used to find it again.
	Name string

	// Path is the bind mount at /var/run/netns/<Name>.
	Path string

	mu      sync.Mutex
	created bool
}

// ErrUnsupported is returned when namespaces are unavailable on this platform.
var ErrUnsupported = fmt.Errorf("network namespaces are only supported on Linux")

// ErrNoPermission is returned when the process lacks the capability to create
// one.
var ErrNoPermission = fmt.Errorf("creating a network namespace requires root or CAP_SYS_ADMIN")

// run executes a command and returns its combined output.
//
// This is the single place in the package that builds a process, so the
// invariant "nothing here reaches the host" is checkable by reading one
// function.
func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Available reports whether namespaces can be created on this host.
//
// It performs the cheapest possible probe, so it is safe to call during
// start-up. It creates nothing.
func Available() error {
	if runtime.GOOS != "linux" {
		return ErrUnsupported
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("iproute2 is not installed: %w", err)
	}
	if _, err := exec.LookPath("tc"); err != nil {
		return fmt.Errorf("tc is not installed: %w", err)
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		return fmt.Errorf("util-linux is not installed: %w", err)
	}
	if os.Geteuid() != 0 {
		return ErrNoPermission
	}
	return nil
}

// Create creates a new network namespace.
//
// unshare creates the namespace and bind-mounts it to a file, which is how it
// survives the process that created it.
func Create(name string) (*Namespace, error) {
	if err := Available(); err != nil {
		return nil, err
	}

	n := &Namespace{Name: name, Path: "/var/run/netns/" + name}

	if _, err := run("unshare", "--net", "--mount", n.Path); err != nil {
		return nil, fmt.Errorf("creating namespace %s: %w", name, err)
	}

	n.created = true
	return n, nil
}

// Close destroys the namespace.
//
// It is safe to call more than once. Tearing down a namespace removes every
// interface in it, so a qdisc attached inside goes with it and the host is
// left untouched.
func (n *Namespace) Close() error {
	if n == nil {
		return nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.created {
		return nil
	}
	n.created = false

	// Order matters: unmount the bind first, then destroy the namespace. The
	// other order leaves a dangling mount.
	if _, err := run("umount", n.Path); err != nil {
		// Continuing anyway. The namespace is destroyed next regardless, and
		// a failed unmount is not a reason to skip the cleanup that matters.
		_ = err
	}
	if _, err := run("ip", "netns", "delete", n.Name); err != nil {
		return fmt.Errorf("destroying namespace %s: %w", n.Name, err)
	}
	return nil
}

// Run executes a command inside the namespace via `ip netns exec`.
//
// `ip netns exec` also remounts /proc and /sys, which is occasionally
// convenient and occasionally a permission problem. RunTC is the form to
// prefer for anything that only touches networking.
func (n *Namespace) Run(name string, args ...string) (string, error) {
	full := make([]string, 0, len(args)+3)
	full = append(full, "netns", "exec", n.Name)
	full = append(full, name)
	full = append(full, args...)
	return run("ip", full...)
}

// RunTC executes tc with the namespace as its network namespace only.
//
// tc touches nothing but the network stack, so nsenter is the tighter and
// more predictable way to run it.
func (n *Namespace) RunTC(args ...string) (string, error) {
	return run("nsenter", append([]string{"--net=" + n.Path, "tc"}, args...)...)
}

// Setup prepares a namespace for shaping tests.
//
// It brings up loopback and creates a dummy interface, which is the cheapest
// interface that accepts a qdisc. A dummy interface generates no traffic, so
// this produces a qdisc that is correctly configured and idle — which is what
// the command-acceptance tests need, and explicitly not what a load test
// needs.
func (n *Namespace) Setup(iface string) error {
	if _, err := n.Run("ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("bringing up loopback: %w", err)
	}
	if _, err := n.Run("ip", "link", "add", iface, "type", "dummy"); err != nil {
		return fmt.Errorf("creating dummy interface %s: %w", iface, err)
	}
	if _, err := n.Run("ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("bringing up %s: %w", iface, err)
	}
	return nil
}

// SetLinkSpeed sets a dummy interface's reported speed.
//
// A dummy interface reports 0 Mbps, which makes any rate cross-check look
// wrong. Setting an explicit speed gives the bandwidth assertions something
// realistic to compare against.
func (n *Namespace) SetLinkSpeed(iface string, mbps int) error {
	if _, err := n.Run("ip", "link", "set", iface, "down"); err != nil {
		return fmt.Errorf("taking %s down to set its speed: %w", iface, err)
	}
	if _, err := n.Run("ip", "link", "set", iface, "type", "dummy", "speed", fmt.Sprintf("%d", mbps)); err != nil {
		return fmt.Errorf("setting %s speed to %dMbps: %w", iface, mbps, err)
	}
	if _, err := n.Run("ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("bringing %s back up: %w", iface, err)
	}
	return nil
}

// Teardown removes the interface and any qdisc attached to it.
//
// This runs before the namespace is destroyed so that a failure leaves a
// diagnosable state rather than nothing at all.
func (n *Namespace) Teardown(iface string) {
	// Replacing the root qdisc removes any shaper. Best-effort: the namespace
	// is destroyed next regardless.
	_, _ = n.RunTC("qdisc", "del", "dev", iface, "root")
	_, _ = n.Run("ip", "link", "del", iface)
}

// HasCake reports whether the running kernel supports CAKE.
//
// The probe attaches CAKE to the dummy interface and removes it again. There
// is no cheaper reliable check: a kernel may have the module available but not
// loaded, and adding the qdisc is what loads it.
func (n *Namespace) HasCake(iface string) bool {
	return n.probeQdisc(iface, "cake", "bandwidth", "1000kbit")
}

// HasFqCodel reports whether the running kernel supports fq_codel.
func (n *Namespace) HasFqCodel(iface string) bool {
	return n.probeQdisc(iface, "fq_codel")
}

// probeQdisc attaches a qdisc and removes it, reporting whether it worked.
func (n *Namespace) probeQdisc(iface, kind string, extra ...string) bool {
	args := append([]string{"qdisc", "add", "dev", iface, "root", kind}, extra...)
	if _, err := n.RunTC(args...); err != nil {
		return false
	}
	_, _ = n.RunTC("qdisc", "del", "dev", iface, "root")
	return true
}

// QdiscJSON reads the qdisc state of an interface as tc's JSON form.
//
// This is the read the statistics parser consumes, obtained from a real
// kernel rather than a fixture. It is what makes the netns test worth having:
// it exercises the same code path an operator's `thn qos stats` will, on
// output the kernel actually produced.
func (n *Namespace) QdiscJSON(iface string) (string, error) {
	return n.RunTC("-j", "-s", "qdisc", "show", "dev", iface)
}

// ApplyCake attaches CAKE to an interface inside the namespace.
//
// The arguments are passed through unchanged so that a test can check exactly
// what the renderer produces, rather than a re-derivation of it.
func (n *Namespace) ApplyCake(iface string, args []string) error {
	full := append([]string{"qdisc", "replace", "dev", iface, "root", "cake"}, args...)
	if _, err := n.RunTC(full...); err != nil {
		return err
	}
	return nil
}

// ApplyFqCodel attaches fq_codel to an interface inside the namespace.
func (n *Namespace) ApplyFqCodel(iface string, args []string) error {
	full := append([]string{"qdisc", "replace", "dev", iface, "root", "fq_codel"}, args...)
	if _, err := n.RunTC(full...); err != nil {
		return err
	}
	return nil
}
