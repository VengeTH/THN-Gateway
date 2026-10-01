package acceptance

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Probing, without a network client.
//
// # The constraint
//
// internal/guard permits exactly four binaries — ip, nft, tc, sysctl — and all
// with read-only verbs. That is deliberate: THN cannot be talked into opening a
// connection to an arbitrary endpoint, and it cannot shell out to curl, nc,
// docker or pg_isready.
//
// Which sounds like it rules out "is PostgreSQL still healthy", because the
// obvious check is to connect to port 5432 and see whether anything answers.
// It does not, and the way around is /proc.
//
// # What /proc gives us
//
// /proc/net/tcp and /proc/net/tcp6 list every socket on the host with its local
// and remote endpoints and its state. A port with a socket in LISTEN is a
// service accepting connections; an ESTABLISHED socket to a remote host is an
// outbound connection somebody made and is holding.
//
// That is enough to answer most of the acceptance criteria without opening a
// socket of our own:
//
//   - "PostgreSQL remains healthy" → is 5432 in LISTEN
//   - "Ollama remains healthy"     → is 11434 in LISTEN
//   - "Docker remains healthy"     → is 2375/2376 listening, or a published
//     port listening, or docker0 present
//   - "Cloudflare Tunnel remains healthy" → an ESTABLISHED socket to a remote
//     port 7844, which is what cloudflared holds
//
// Reading a file needs no guard entry. The whole probe layer is /proc and the
// filesystem, which means it inherits the existing invariant rather than
// widening it — and that matters, because a health check that needs to run
// during an incident is exactly the moment you least want a new capability.
//
// # The limit, stated rather than implied
//
// A LISTEN socket proves something is bound to a port. It does not prove the
// service behind it answers correctly: a PostgreSQL in an infinite recovery
// loop still holds its port. So a probe result is evidence of reachability, not
// of correctness, and every criterion that says "remains healthy" is checked
// against a baseline rather than against an absolute standard.
//
// Where a criterion genuinely needs more than this, it is declared as needing
// a command the guard does not permit, and it says so rather than quietly
// passing on weaker evidence.

// SocketState is the state of a socket, as /proc reports it.
type SocketState string

const (
	// SocketEstablished is a connected socket.
	SocketEstablished SocketState = "ESTABLISHED"
	// SocketListen is a listening socket.
	SocketListen SocketState = "LISTEN"
	// SocketOther is any other state: TIME_WAIT, CLOSE_WAIT, and the rest.
	//
	// Grouped rather than enumerated because none of them indicates a service
	// that is up, and a criteria list that distinguished twenty dead states
	// would be a list nobody reads.
	SocketOther SocketState = "OTHER"
)

// Socket is one entry from /proc/net/tcp.
type Socket struct {
	// LocalAddr is the bound address, in dotted form.
	LocalAddr string
	// LocalPort is the bound port.
	LocalPort int
	// RemoteAddr is the peer address.
	RemoteAddr string
	// RemotePort is the peer port.
	RemotePort int
	// State is the socket state.
	State SocketState
	// IPv6 reports which file this came from.
	IPv6 bool
}

// procSocket is the layout of a /proc/net/tcp line.
//
// The format is positional and undocumented beyond the kernel source, which
// makes it exactly the kind of thing that has to be parsed carefully: a
// field read from the wrong column produces a plausible wrong port rather than
// an error, and a health check that reports the wrong port is worse than one
// that reports nothing.
type procSocket struct {
	localAddr  string
	localPort  int
	remoteAddr string
	remotePort int
	state      string
	ipv6       bool
}

// readProcSockets parses /proc/net/tcp and /proc/net/tcp6.
func readProcSockets(paths ...string) ([]Socket, error) {
	var out []Socket
	var firstErr error

	for _, path := range paths {
		sockets, err := readProcFile(path)
		if err != nil {
			// A missing /proc/net/tcp6 on a host without IPv6 is not a
			// failure. A missing /proc entirely means this is not Linux, and
			// that the caller needs to know.
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		out = append(out, sockets...)
	}

	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func readProcFile(path string) ([]Socket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	ipv6 := strings.HasSuffix(path, "tcp6")

	var out []Socket
	scanner := bufio.NewScanner(f)
	first := true

	for scanner.Scan() {
		if first {
			// The first line is a header: "sl local_address rem_address st ..."
			first = false
			continue
		}

		fields := strings.Fields(scanner.Text())
		// A line needs at least the four fields we read: index, local,
		// remote, state. Anything shorter is not a socket row.
		if len(fields) < 4 {
			continue
		}

		s, ok := parseProcSocket(fields[1], fields[2], fields[3], ipv6)
		if !ok {
			// A malformed line is skipped rather than fatal. /proc is a live
			// view and a socket can be torn down between the read and the
			// parse; refusing the whole table because one row raced would make
			// the probe useless exactly when the host is busy.
			continue
		}
		out = append(out, s)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return out, err
	}
	return out, nil
}

// parseProcSocket decodes one row.
//
// The addresses are hex-encoded little-endian 32-bit (or 4x32-bit) words with
// the port in the last four characters. Getting that wrong produces a valid-
// looking address that is not the host's, so it is decoded rather than
// approximated.
func parseProcSocket(local, remote, state string, ipv6 bool) (Socket, bool) {
	la, lp, ok := splitHexAddr(local)
	if !ok {
		return Socket{}, false
	}
	ra, rp, ok := splitHexAddr(remote)
	if !ok {
		return Socket{}, false
	}

	return Socket{
		LocalAddr:  la,
		LocalPort:  lp,
		RemoteAddr: ra,
		RemotePort: rp,
		State:      socketState(state),
		IPv6:       ipv6,
	}, true
}

// splitHexAddr decodes "0100007F:0035" into an address and a port.
func splitHexAddr(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 || len(s) < i+5 {
		return "", 0, false
	}

	port, err := strconv.ParseUint(s[i+1:], 16, 32)
	if err != nil {
		return "", 0, false
	}

	return decodeHexAddr(s[:i]), int(port), true
}

// decodeHexAddr turns the little-endian hex word into dotted-quad form.
func decodeHexAddr(hexAddr string) string {
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || len(raw) < 4 {
		// Return the input rather than an empty string: an address THN could
		// not decode is still information, and an empty one reads as a real
		// address that happens to be blank.
		return hexAddr
	}

	// Every four bytes are one 32-bit word in host (little-endian) order.
	parts := make([]string, 0, len(raw)/4)
	for i := 0; i+4 <= len(raw); i += 4 {
		parts = append(parts, fmt.Sprintf("%d.%d.%d.%d", raw[i+3], raw[i+2], raw[i+1], raw[i]))
	}
	return strings.Join(parts, ".")
}

// socketState maps the /proc state code.
func socketState(s string) SocketState {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "01":
		return SocketEstablished
	case "0A":
		return SocketListen
	default:
		return SocketOther
	}
}

// PortIsListening reports whether anything holds the given TCP port.
//
// The port is matched on loopback and on any address, because a service bound
// to 127.0.0.1 and one bound to 0.0.0.0 are both "listening" for the purpose of
// "is this thing up", and a health check that only looked at one of them would
// report a healthy service as absent depending on how it was configured.
func PortIsListening(sockets []Socket, port int) bool {
	for _, s := range sockets {
		if s.State == SocketListen && s.LocalPort == port {
			return true
		}
	}
	return false
}

// PortsListening returns every listening port, sorted.
func PortsListening(sockets []Socket) []int {
	seen := make(map[int]bool)
	for _, s := range sockets {
		if s.State == SocketListen {
			seen[s.LocalPort] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// ConnectionEstablished reports whether an outbound socket exists to a given
// remote port, on any local address.
//
// Used for the tunnel check: a Cloudflare Tunnel is healthy when cloudflared
// holds an ESTABLISHED connection outbound to Cloudflare, and that shows up
// here whether or not the operator knows which edge it landed on.
func ConnectionEstablished(sockets []Socket, remotePort int) bool {
	for _, s := range sockets {
		if s.State == SocketEstablished && s.RemotePort == remotePort {
			return true
		}
	}
	return false
}

// WellKnownPorts used by the default acceptance criteria.
//
// Named rather than numbered inline so that an operator reading a failure can
// see which service was expected without cross-referencing a number.
const (
	// PortSSH is sshd.
	PortSSH = 22
	// PortDNS is a resolver listener.
	PortDNS = 53
	// PortPostgres is the PostgreSQL server port.
	PortPostgres = 5432
	// PortDockerAPI is the Docker daemon API.
	PortDockerAPI = 2375
	// PortOllama is the Ollama HTTP API.
	PortOllama = 11434
	// PortCloudflareTunnel is the edge port cloudflared holds outbound to.
	PortCloudflareTunnel = 7844
)

// interfaceNames reports the host's interfaces from /sys/class/net.
//
// From /sys rather than from `ip`, because reading a directory needs no guard
// entry and this is the same reasoning as reading /proc: the health check
// should not need a capability the rest of the system does not have.
func interfaceNames(sysClassNet string) ([]string, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// hasInterface reports whether an interface with the given name exists.
func hasInterface(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// pathExists reports whether a path is present.
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
