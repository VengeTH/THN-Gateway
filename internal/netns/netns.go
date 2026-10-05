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
//
// # It carries the M6.2 gateway lab, not just QoS
//
// The topology helpers below (veth pairs, bridges, addresses, routes) exist for
// internal/lab, which wires a client, a gateway and a WAN-side target together
// and moves real packets between them. Those commands are namespace-local
// exactly as the shaping ones are, including the one that hands a veth peer to
// a second namespace, so the exemption's justification is unchanged.
package netns

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
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
	// nsenter, not unshare: RunTC reaches the namespace through nsenter, and
	// probing a util-linux binary this package never calls would report a
	// dependency that does not exist while missing one that does.
	if _, err := exec.LookPath("nsenter"); err != nil {
		return fmt.Errorf("util-linux (nsenter) is not installed: %w", err)
	}
	if os.Geteuid() != 0 {
		return ErrNoPermission
	}
	return nil
}

// storeDir is where the kernel-facing namespace handles live. It is iproute2's
// own convention, not this package's, so `ip link set <peer> netns <name>`
// finds a namespace created here and vice versa.
const storeDir = "/var/run/netns/"

// Create creates a new network namespace.
//
// It delegates to `ip netns add` rather than assembling one from unshare,
// bind-mounts and a shared mount tree by hand. That is not a style preference.
//
// A persistent namespace is a bind mount of /proc/self/ns/net onto a file under
// the namespace store, and it only survives the process that made it if that
// directory is a SHARED mount — otherwise the mount dies with the mount
// namespace and the handle silently evaporates. `ip netns add` arranges all of
// that: it creates the store, marks it MS_SHARED|MS_REC, unshares the network
// namespace, and binds the handle. It is the mechanism every other tool on a
// Linux host uses, so a namespace created here is one `ip netns exec`,
// `ip netns delete` and `ip link set ... netns` all understand.
//
// Getting that wrong does not fail loudly. It produces a namespace that seems
// to be created and is gone by the next command, which surfaces much later as
// an unrelated-looking error.
func Create(name string) (*Namespace, error) {
	if err := Available(); err != nil {
		return nil, err
	}
	if err := checkToken("namespace", name); err != nil {
		return nil, err
	}

	if _, err := run("ip", "netns", "add", name); err != nil {
		return nil, fmt.Errorf("creating namespace %s: %w", name, err)
	}

	return &Namespace{Name: name, Path: storeDir + name, created: true}, nil
}

// Remove destroys a named namespace.
//
// Separate from Close because a namespace can outlive the Namespace value that
// created it: a test killed mid-run leaves one behind, and the next attempt to
// create it fails with an error that names neither the cause nor the fix.
//
// The unmount is unconditional and best-effort. A stale bind mount outlives the
// namespace it pointed at, and `ip netns delete` refuses to remove a path that
// is still mounted — so the unmount has to be attempted whether or not the
// mount is believed to be there.
func Remove(name string) error {
	if err := checkToken("namespace", name); err != nil {
		return err
	}
	if _, err := run("umount", storeDir+name); err != nil {
		_ = err
	}
	if _, err := run("ip", "netns", "delete", name); err != nil {
		return fmt.Errorf("removing namespace %s: %w", name, err)
	}
	return nil
}

// Exists reports whether a named namespace is present.
//
// It is a real query rather than an assumption, because "did the last run clean
// up after itself?" is a question with an answer and guessing it is how a lab
// starts failing for reasons nobody can reproduce.
func Exists(name string) bool {
	if err := checkToken("namespace", name); err != nil {
		return false
	}
	_, err := os.Stat(storeDir + name)
	return err == nil
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

// -------------------------------------------------------------- topology
//
// Everything below builds a wired topology. It exists because the M6.2
// gateway tests need more than one interface, and because a veth pair is the
// only way to give two namespaces a real link to carry real packets over.
//
// The safety argument is unchanged. Every command here runs *inside* a
// namespace, including the one that moves a veth peer into a second
// namespace: `ip link set <peer> netns <name>` resolves <name> through
// /var/run/netns and enters it, so no link is ever created on the host. A
// namespace carries its links to its destruction, so there is no code path
// from here to a host interface.

// LinkAdd creates a link of the given kind inside the namespace.
//
// kind is a plain word ("bridge", "dummy") and every extra argument is checked
// as a single token, so nothing here can reach a shell. The link exists only
// inside the namespace and disappears with it.
func (n *Namespace) LinkAdd(name, kind string, extra ...string) error {
	if err := checkToken("interface", name); err != nil {
		return err
	}
	if err := checkToken("link kind", kind); err != nil {
		return err
	}
	args := []string{"link", "add", name, "type", kind}
	for _, arg := range extra {
		if err := checkToken("argument", arg); err != nil {
			return err
		}
		args = append(args, arg)
	}
	if _, err := n.Run("ip", args...); err != nil {
		return fmt.Errorf("creating %s link %s: %w", kind, name, err)
	}
	return nil
}

// Enslave attaches an interface to a bridge or bond inside the namespace.
func (n *Namespace) Enslave(iface, master string) error {
	if err := checkToken("interface", iface); err != nil {
		return err
	}
	if err := checkToken("interface", master); err != nil {
		return err
	}
	if _, err := n.Run("ip", "link", "set", iface, "master", master); err != nil {
		return fmt.Errorf("enslaving %s to %s: %w", iface, master, err)
	}
	return nil
}

// LinkUp brings an interface up inside the namespace.
func (n *Namespace) LinkUp(iface string) error {
	if err := checkToken("interface", iface); err != nil {
		return err
	}
	_, err := n.Run("ip", "link", "set", iface, "up")
	if err != nil {
		return fmt.Errorf("bringing %s up: %w", iface, err)
	}
	return nil
}

// LinkDown brings an interface down inside the namespace.
func (n *Namespace) LinkDown(iface string) error {
	if err := checkToken("interface", iface); err != nil {
		return err
	}
	_, err := n.Run("ip", "link", "set", iface, "down")
	if err != nil {
		return fmt.Errorf("bringing %s down: %w", iface, err)
	}
	return nil
}

// AddrAdd assigns a CIDR to an interface inside the namespace.
func (n *Namespace) AddrAdd(iface, cidr string) error {
	if err := checkToken("interface", iface); err != nil {
		return err
	}
	if _, err := netip.ParsePrefix(cidr); err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if _, err := n.Run("ip", "addr", "add", cidr, "dev", iface); err != nil {
		return fmt.Errorf("assigning %s to %s: %w", cidr, iface, err)
	}
	return nil
}

// AddrDel removes a CIDR from an interface inside the namespace.
func (n *Namespace) AddrDel(iface, cidr string) error {
	if err := checkToken("interface", iface); err != nil {
		return err
	}
	if _, err := n.Run("ip", "addr", "del", cidr, "dev", iface); err != nil {
		return fmt.Errorf("removing %s from %s: %w", cidr, iface, err)
	}
	return nil
}

// RouteAdd installs a route inside the namespace.
//
// via is optional: a connected or blackhole route has no next hop.
func (n *Namespace) RouteAdd(dest, via, dev string) error {
	if err := checkDestination(dest); err != nil {
		return err
	}
	args := []string{"route", "add", dest}
	if via != "" {
		if _, err := netip.ParseAddr(via); err != nil {
			return fmt.Errorf("invalid next hop %q: %w", via, err)
		}
		args = append(args, "via", via)
	}
	if dev != "" {
		if err := checkToken("interface", dev); err != nil {
			return err
		}
		args = append(args, "dev", dev)
	}
	if _, err := n.Run("ip", args...); err != nil {
		return fmt.Errorf("adding route %s: %w", dest, err)
	}
	return nil
}

// RouteDel removes a route inside the namespace.
func (n *Namespace) RouteDel(dest, via, dev string) error {
	if err := checkDestination(dest); err != nil {
		return err
	}
	args := []string{"route", "del", dest}
	if via != "" {
		args = append(args, "via", via)
	}
	if dev != "" {
		if err := checkToken("interface", dev); err != nil {
			return err
		}
		args = append(args, "dev", dev)
	}
	if _, err := n.Run("ip", args...); err != nil {
		return fmt.Errorf("deleting route %s: %w", dest, err)
	}
	return nil
}

// CreateVeth creates a veth pair inside the namespace. Both ends stay here.
//
// # Which end to create here
//
// Create the pair in the namespace that will KEEP one of its ends under the
// name it is going to be addressed by, and move only the far end out. The
// alternative — create both ends here and move one away — makes the departing
// name live here for the microseconds between creation and the move, and if
// that transient name matches anything already in this namespace the kernel
// refuses the pair with RTNETLINK "File exists" before anything has been
// diagnosed.
//
// That failure is particularly nasty because it depends on ordering rather than
// on state: the same code succeeds or fails depending on whether the clashing
// interface was created first. Creating the pair where the name belongs makes
// the collision impossible rather than merely unlikely.
func (n *Namespace) CreateVeth(local, peer string) error {
	if err := checkToken("interface", local); err != nil {
		return err
	}
	if err := checkToken("interface", peer); err != nil {
		return err
	}
	if _, err := n.Run("ip", "link", "add", local, "type", "veth", "peer", "name", peer); err != nil {
		return fmt.Errorf("creating veth pair %s/%s: %w", local, peer, err)
	}
	return nil
}

// MoveLinkTo moves an interface into another named namespace.
//
// The link keeps its name on arrival, so the caller is responsible for the name
// being free in the destination. Executing this from inside a third namespace is
// fine: `ip link set … netns <name>` resolves <name> through the shared
// namespace store and passes the descriptor to the kernel.
func (n *Namespace) MoveLinkTo(iface, namespace string) error {
	if err := checkToken("interface", iface); err != nil {
		return err
	}
	if err := checkToken("namespace", namespace); err != nil {
		return err
	}
	if _, err := n.Run("ip", "link", "set", iface, "netns", namespace); err != nil {
		// The pair is half-connected and unreachable. Remove what stayed here
		// so the failure does not leave a link shadowing the name the next
		// attempt would use.
		_, _ = n.Run("ip", "link", "del", iface)
		return fmt.Errorf("moving %s into namespace %s: %w", iface, namespace, err)
	}
	return nil
}

// LinkNames lists the kernel interface names present in the namespace.
//
// It exists so a topology can be checked against what it intended to build,
// rather than against what it believes it built. A harness that only asserts on
// the interfaces it addressed cannot see an interface it did not expect — which
// is exactly the shape of damage a name collision does.
func (n *Namespace) LinkNames() ([]string, error) {
	out, err := n.Run("ip", "-j", "link", "show")
	if err != nil {
		return nil, fmt.Errorf("listing links in %s: %w", n.Name, err)
	}

	var links []struct {
		Ifname string `json:"ifname"`
	}
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		return nil, fmt.Errorf("parsing links in %s: %w", n.Name, err)
	}

	names := make([]string, 0, len(links))
	for _, l := range links {
		names = append(names, l.Ifname)
	}
	sort.Strings(names)
	return names, nil
}

// LoopbackUp brings the namespace's loopback up, which it needs before any
// TCP probe inside it can complete a handshake.
func (n *Namespace) LoopbackUp() error {
	if _, err := n.Run("ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("bringing up loopback: %w", err)
	}
	return nil
}

// tokenPattern is the set of names accepted as a single argv token.
//
// These functions build argument vectors, never a shell string, so this is not
// an injection boundary. It exists because a name containing a space would
// otherwise be silently split by a caller and produce a confusing failure much
// later, and because a namespace name is used as a path component.
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,63}$`)

func checkToken(what, s string) error {
	if !tokenPattern.MatchString(s) {
		return fmt.Errorf("invalid %s name %q", what, s)
	}
	return nil
}

func checkDestination(dest string) error {
	if dest == "default" {
		return nil
	}
	if _, err := netip.ParsePrefix(dest); err != nil {
		return fmt.Errorf("invalid route destination %q: %w", dest, err)
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
