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
// Because the verb table *is* the safety argument, it is printable without
// starting anything:
//
//	thnd --verbs
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
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/daemon"
)

// defaultConfigPath mirrors the compiled default configuration location.
//
// Duplicated as a constant rather than imported so that the dependency
// direction stays one-way; internal/config asserts in its own tests that the
// two agree.
const defaultConfigPath = "/etc/thn/config.yaml"

func main() {
	os.Exit(int(run(os.Args[1:])))
}

// loadConfigDoc resolves the configuration thnd should start from.
//
// Best-effort by design, and the fallback is the compiled default rather than
// an empty value: a daemon that cannot read its configuration should still come
// up and observe the network, because a daemon that will not start is a gateway
// nobody can ask anything. The failure is reported on stderr so it is not
// silent — a daemon quietly running on defaults while the operator believes it
// is running on their configuration is exactly the confusion this avoids.
//
// THN_CONFIG is honoured, and then the default location, so that the daemon
// reads the same file the CLI does by default.
func loadConfigDoc() config.Config {
	path := os.Getenv("THN_CONFIG")
	if path == "" {
		path = defaultConfigPath
	}

	doc, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"thnd: could not read %s (%v); falling back to compiled defaults\n", path, err)

		// config.Defaults has not been through Load, so the THN_* overrides
		// it would have applied are applied here rather than lost.
		doc = config.Defaults()
		applyEnvironment(&doc)
		if err := doc.Normalize(); err != nil {
			return config.Defaults()
		}
	}
	return doc
}

// applyEnvironment mirrors the THN_* overrides that config.Load applies, for
// the path where loading failed and only the defaults are available.
func applyEnvironment(c *config.Config) {
	if v := os.Getenv("THN_SOCKET"); v != "" {
		c.Paths.Socket = v
	}
	if v := os.Getenv("THN_STATE_DB"); v != "" {
		c.Paths.StateDB = v
	}
}

// run is main, separated so the exit path is testable.
func run(args []string) int {
	cfg, verbList, showVersion, err := parseArgs(args)
	if err != nil {
		// Not "thnd: %v": the errors from internal/daemon already name the
		// binary, and a doubled prefix reads like two processes failing.
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	// The verb table is the daemon's whole safety argument — "there is no code
	// path that can modify host networking" is a claim about this list, so the
	// list has to be readable without starting anything. Answering it here, from
	// the package, also means the answer cannot be a stale claim the daemon makes
	// about itself.
	if verbList {
		printVerbs(os.Stdout)
		return 0
	}

	if showVersion {
		fmt.Printf("thnd %s\n", versionString(cfg.Mode))
		fmt.Printf("  mode: %s", cfg.Mode)
		if !cfg.Mode.Supported() {
			fmt.Print(" (refused at startup; see the ACTIVE message)")
		}
		fmt.Println()
		fmt.Println("  verbs: serve read-only queries on a local socket; this daemon cannot apply")
		return 0
	}

	// The socket's directory has to exist before the socket can be created, and
	// on a real gateway /run is a tmpfs that is empty at boot — so this is not
	// a case that can be left to installation.
	if err := ensureDir(filepath.Dir(cfg.Socket)); err != nil {
		fmt.Fprintf(os.Stderr, "thnd: %v\n", err)
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

	// Same rule as the argument errors above: internal/daemon already names
	// the binary, so prefixing again prints "thnd: thnd: another daemon is
	// already listening" — which reads like two processes failing and is the
	// first thing an operator sees when they accidentally start a second one.
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
func parseArgs(args []string) (daemon.Config, bool, bool, error) {
	// Resolve the socket and the state database from the same configuration the
	// CLI reads, in the same order.
	//
	// This used to be two hardcoded constants plus THN_SOCKET and THN_STATE_DB,
	// which meant the configuration file was consulted for the shaping
	// interface and nothing else. An operator who set `paths.socket` in
	// /etc/thn/config.yaml got a daemon listening on /run/thn/thnd.sock and a
	// `thn status` looking at the configured path — so the two binaries
	// disagreed and the daemon could never be reached. config.Load already
	// applies the THN_* environment overrides on top of the document, so
	// delegating to it makes flag > environment > file > default the single
	// precedence order for both binaries.
	doc := loadConfigDoc()

	cfg := daemon.Config{
		Mode:         daemon.ModeDevelopment,
		Doc:          doc,
		Socket:       doc.Paths.Socket,
		StateDB:      doc.Paths.StateDB,
		QoSInterface: doc.QoS.Interface,
		Interval:     daemon.DefaultInterval,
	}
	showVersion := false
	verbList := false

	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--version" || a == "-v":
			showVersion = true

		case a == "--help" || a == "-h":
			showVersion = true

		case a == "--verbs":
			// Independent of mode, and honoured before anything can start the
			// daemon: asking what this daemon may do must not itself start it.
			verbList = true

		case a == "--mode" || a == "-m":
			if i+1 >= len(args) {
				return cfg, false, false, fmt.Errorf("--mode requires a value")
			}
			i++
			m, err := daemon.ParseMode(args[i])
			if err != nil {
				return cfg, false, false, err
			}
			cfg.Mode = m

		case a == "--socket" || a == "-s":
			if i+1 >= len(args) {
				return cfg, false, false, fmt.Errorf("--socket requires a value")
			}
			i++
			cfg.Socket = args[i]

		case a == "--state-db":
			if i+1 >= len(args) {
				return cfg, false, false, fmt.Errorf("--state-db requires a value")
			}
			i++
			cfg.StateDB = args[i]

		case a == "--interval":
			if i+1 >= len(args) {
				return cfg, false, false, fmt.Errorf("--interval requires a value")
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return cfg, false, false, fmt.Errorf("--interval %q is not a duration", args[i])
			}
			cfg.Interval = d

		case a == "--no-state":
			// Persistence is optional so the daemon can be run on a machine
			// where /var/lib is not writable, which is a legitimate thing to do
			// while evaluating it.
			cfg.StateDB = ""

		default:
			return cfg, false, false, fmt.Errorf("unknown flag %q; try --help", a)
		}
	}

	return cfg, verbList, showVersion, nil
}

// printVerbs writes the verb table with each verb's description.
//
// Descriptions are printed because the question being asked of this table is
// "what is this allowed to do", and names alone do not answer it.
func printVerbs(w io.Writer) {
	all := daemon.Verbs()
	for _, v := range all {
		fmt.Fprintf(w, "  %-8s %s\n", v.Name, v.Description)
	}
	fmt.Fprintf(w, "\n  %d verbs, none of which modify the host.\n", len(all))
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

// versionString names this build.
//
// There is no version command elsewhere in THN yet, and a daemon that writes to
// a state database wants to be identifiable in that database's records.
//
// The mode is part of the string rather than printed beside it: a record saying
// "thnd development" when the process was started with --mode PREPARED is a
// record that cannot be trusted later.
func versionString(mode daemon.Mode) string {
	return fmt.Sprintf("%s (no apply path)", strings.ToLower(string(mode)))
}
