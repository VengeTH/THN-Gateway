// Command thnd is the THN Gateway controller daemon.
//
// # What it does
//
// Runs on the gateway. Observes the host on an interval, records what it saw
// durably, and answers questions over a local unix socket.
//
//	control plane ──► thnd ──► Linux networking
//
// The kernel moves packets. This daemon watches, records and reports.
//
// # What it does not do
//
// It does not change the network. It has no verb that applies a configuration,
// activates anything, restarts a service or touches an interface. That is not a
// setting that is turned off — the verb table contains no such entry, so there
// is no code performing one and nothing for a reviewer to audit.
//
// The daemon will not even start in ACTIVE mode, and refuses with a distinct
// error explaining why. Refusing to start is a stronger statement than starting
// and declining to act: a daemon that came up and then quietly did nothing would
// be indistinguishable, from the outside, from one that came up and did something
// harmless.
//
// # Why it exists before it is useful for changing things
//
// Because "what was this host doing at three in the morning" has to be
// answerable by a process that was running at three in the morning, and nobody
// can be watching a gateway in Alabang on a Tuesday from Sto. Tomas.
//
// Three things work today and need no privilege:
//
//   - a periodic observation loop, recorded durably;
//   - a query surface, so `thn status` can ask a running daemon rather than
//     take its own reading;
//   - an honest account of what it could and could not read, because a daemon
//     started unprivileged sees the network but not the nftables ruleset.
//
// # Privileged observations degrade rather than fail
//
// Reading interfaces, addresses and routes needs nothing. Reading the loaded
// ruleset and the queue disciplines needs CAP_NET_ADMIN. Started unprivileged,
// the daemon reports a partial observation and names the gap, rather than
// failing or — worse — reporting an empty firewall as an absent one.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/daemon"
)

// These match the paths the CLI already uses, so one installation serves both
// binaries. The environment overrides exist so that a test, a second instance or
// a development checkout can each have their own.
const (
	// defaultSocket is where thnd listens when nothing says otherwise.
	defaultSocket = "/run/thn/thnd.sock"

	// defaultStateDB is the state database thnd records into.
	defaultStateDB = "/var/lib/thn/state.db"

	// defaultRunDir is the directory holding the socket.
	defaultRunDir = "/run/thn"
)

func main() {
	os.Exit(int(run(os.Args[1:])))
}

// run is main, separated so the exit path is testable.
func run(args []string) int {
	cfg, showVersion, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	if showVersion {
		fmt.Printf("thnd %s\n", versionString())
		fmt.Println("  mode: DEVELOPMENT or PREPARED; ACTIVE is not available in this build")
		fmt.Println("  verbs: serve read-only queries on a local socket; this daemon cannot apply")
		return 0
	}

	// The socket's directory has to exist before the socket can be created, and
	// on a real gateway /run is a tmpfs that is empty at boot — so this is not
	// a case that can be left to installation.
	if err := ensureDir(filepath.Dir(cfg.Socket)); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	d, err := daemon.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		if errors.Is(err, daemon.ErrActiveUnsupported) {
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "THN Gateway is not physically deployed.\n\n")
			fmt.Fprintf(os.Stderr, "Activation refused.\n\n")
			fmt.Fprintf(os.Stderr, "Reason:\n")
			fmt.Fprintf(os.Stderr, "ACTIVE mode requires an installed gateway that nobody can\n")
			fmt.Fprintf(os.Stderr, "remove from a production network.\n\n")
			fmt.Fprintf(os.Stderr, "Current network remains untouched.\n")
		}
		return 1
	}
	defer func() { _ = d.Close() }()

	// A signal context inside Run handles SIGINT and SIGTERM; the outer one
	// exists so that a caller embedding the daemon can cancel it too.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return 0
}

// parseArgs reads the command line.
//
// The flag set is hand-rolled for the same reason the CLI's is: thnd is the
// process that would eventually run as root, and a dependency that parses flags
// on its behalf is a dependency whose behaviour a security argument would have
// to be written about.
func parseArgs(args []string) (daemon.Config, bool, error) {
	cfg := daemon.Config{
		Mode:     daemon.ModeDevelopment,
		Socket:   envOr("THN_SOCKET", defaultSocket),
		StateDB:  envOr("THN_STATE_DB", defaultStateDB),
		Interval: daemon.DefaultInterval,
	}
	showVersion := false

	// The configuration supplies the shaping interface to watch. Loading it is
	// best-effort: a daemon that cannot read the configuration should still come
	// up and observe the network, because a daemon that will not start is a
	// gateway nobody can ask anything.
	if path := os.Getenv("THN_CONFIG"); path != "" {
		if c, err := config.Load(path); err == nil {
			cfg.QoSInterface = c.QoS.Interface
		}
	}

	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--version" || a == "-v":
			showVersion = true

		case a == "--help" || a == "-h":
			showVersion = true

		case a == "--mode" || a == "-m":
			if i+1 >= len(args) {
				return cfg, false, fmt.Errorf("--mode requires a value")
			}
			i++
			m, err := daemon.ParseMode(args[i])
			if err != nil {
				return cfg, false, err
			}
			cfg.Mode = m

		case a == "--socket" || a == "-s":
			if i+1 >= len(args) {
				return cfg, false, fmt.Errorf("--socket requires a value")
			}
			i++
			cfg.Socket = args[i]

		case a == "--state-db":
			if i+1 >= len(args) {
				return cfg, false, fmt.Errorf("--state-db requires a value")
			}
			i++
			cfg.StateDB = args[i]

		case a == "--interval":
			if i+1 >= len(args) {
				return cfg, false, fmt.Errorf("--interval requires a value")
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return cfg, false, fmt.Errorf("--interval %q is not a duration", args[i])
			}
			cfg.Interval = d

		case a == "--no-state":
			// Persistence is optional so the daemon can be run on a machine
			// where /var/lib is not writable, which is a legitimate thing to do
			// while evaluating it.
			cfg.StateDB = ""

		default:
			return cfg, false, fmt.Errorf("unknown flag %q; try --help", a)
		}
	}

	return cfg, showVersion, nil
}

// ensureDir creates a directory if it is missing.
//
// Created 0700: the socket inside it is the control surface, and a directory
// that other users can list is a directory where they can see it.
func ensureDir(path string) error {
	if path == "" || path == "/" {
		return nil
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// versionString names this build.
//
// There is no version command elsewhere in THN yet, and a daemon that writes to
// a state database wants to be identifiable in that database's records.
func versionString() string { return "development (no apply path)" }
