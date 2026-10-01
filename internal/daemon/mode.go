package daemon
// Package daemon implements thnd, the long-running controller on the gateway.
//
// # What thnd is
//
// The diagram this project is organised around puts a daemon between the
// control plane and Linux:
//
//	control plane ──► thnd ──► Linux networking
//
// The kernel moves packets. The Go daemon controls the system. That separation
// is the point, and this package is the middle of it.
//
// # What thnd is not, yet
//
// It is not privileged. It cannot apply anything.
//
// This is deliberate and it is the whole reason the daemon can be written now
// while the Dell sits in Alabang running Coolify, PostgreSQL, Redis, Ollama,
// Docker and a Cloudflare Tunnel. A daemon with an apply path is a daemon that
// can be made to drop a production firewall by a mistake three thousand
// kilometres away. Until physical deployment, there is nothing for that ability
// to do that the operator could not do more safely by hand.
//
// So thnd observes, records, and answers questions. Its query surface has no
// mutating verb, and that is structural rather than a promise: the verb table
// contains no entry that could change anything, so there is no code to review
// for safety because there is no such code.
//
// # What it is for, then
//
// Three things that are genuinely useful today and do not need privilege:
//
//   - A periodic observation loop, so that "what was this host doing at 03:00"
//     has an answer that does not depend on somebody having been looking.
//   - Durable state, through internal/state, so that history survives a restart.
//   - A local query surface, so that `thn status` can ask a running daemon
//     instead of guessing — which is what the CLI has been saying it wants all
//     along.
//
// # Privilege is not assumed, it is degraded through
//
// Reading interfaces, addresses and routes needs no privilege. Reading the
// loaded nftables ruleset does, and so does reading qdisc statistics. A daemon
// started unprivileged therefore observes what it can and reports what it
// could not, rather than failing or pretending.
//
// The same principle as everywhere else in this codebase: an absent reading is
// not a reading, and it is reported as absent rather than as zero.

// Package daemon's mode is the safety-relevant half of its lifecycle.
package daemon

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Mode is how much authority thnd has.
//
// The three modes come from the project's operating modes, and thnd's mode is
// a statement about what it is *allowed* to do rather than what it currently
// happens to be doing.
type Mode string

const (
	// ModeDevelopment is the mode this build ships in.
	//
	// THN is installed, configured and tested. It changes nothing. This is the
	// mode a remote machine in somebody's house runs in, and it is the only one
	// that can be entered without someone standing at the device.
	ModeDevelopment Mode = "DEVELOPMENT"

	// ModePrepared means everything is defined and nothing is applied.
	//
	// Interfaces, firewall rules, DHCP, DNS and QoS are all specified, a
	// rollback exists, and the network is still exactly as it was. This is the
	// mode a gateway is in on the bench before it is installed.
	ModePrepared Mode = "PREPARED"

	// ModeActive means THN owns the network.
	//
	// Unreachable in this build, and refusing to start in it is deliberate
	// rather than incidental — see ErrActiveUnsupported.
	ModeActive Mode = "ACTIVE"
)

// Modes are the acceptable values, for error messages and usage.
var Modes = []Mode{ModeDevelopment, ModePrepared, ModeActive}

// Errors returned for mode problems.
var (
	// ErrActiveUnsupported is returned when ACTIVE is requested.
	//
	// A distinct error rather than a generic "not implemented", because the
	// two are different conversations. An unimplemented feature is work
	// waiting to be done; an unsupported *mode* is a safety boundary, and
	// reaching it requires somebody to be at the device.
	ErrActiveUnsupported = errors.New(
		"thnd: ACTIVE mode is not available in this build; activation requires a physically deployed gateway")

	// ErrUnknownMode is returned for an unrecognised mode name.
	ErrUnknownMode = errors.New("thnd: unknown mode")
)

// ParseMode reads a mode name.
//
// ACTIVE is a *valid name* and parses successfully. It is refused later, by
// New, and that separation is deliberate: there is exactly one place where
// activation is declined, so there is exactly one place to look when asking why
// the daemon would not start, and exactly one to change when it is eventually
// allowed. A parser that also refused would put the same decision in two places
// and let them disagree.
//
// Case-insensitive, because an operator typing "active" at a shell should get
// the refusal rather than a spelling complaint.
func ParseMode(s string) (Mode, error) {
	m := Mode(strings.ToUpper(strings.TrimSpace(s)))
	switch m {
	case ModeDevelopment, ModePrepared, ModeActive:
		return m, nil
	case "":
		return "", fmt.Errorf("%w: no mode given; expected one of %s",
			ErrUnknownMode, modeList())
	default:
		return "", fmt.Errorf("%w: %q; expected one of %s",
			ErrUnknownMode, s, modeList())
	}
}

// Supported reports whether a mode can be entered in this build.
//
// True for DEVELOPMENT and PREPARED. False for ACTIVE.
func (m Mode) Supported() bool {
	switch m {
	case ModeDevelopment, ModePrepared:
		return true
	default:
		return false
	}
}

// Supported reports whether a mode can be entered in this build.
//
// True for DEVELOPMENT and PREPARED. False for ACTIVE.
//
// This is the predicate for "may the daemon start in this mode", as opposed to
// Applies, which is the predicate for "may the daemon change the host". Both
// are false for ACTIVE here, for different reasons: Supported is about refusing
// to start, Applies is about there being nothing to do.
func (m Mode) Supported() bool {
	switch m {
	case ModeDevelopment, ModePrepared:
		return true
	default:
		return false
	}
}

func modeList() string {
	parts := make([]string, 0, len(Modes))
	for _, m := range Modes {
		parts = append(parts, string(m))
	}
	return strings.Join(parts, ", ")
}

// String renders the mode.
func (m Mode) String() string { return string(m) }

// Applies reports whether this mode allows the daemon to change the host.
//
// Every mode returns false in this build, and the function exists so that the
// answer is written down in one place rather than implied by the absence of
// code. When ACTIVE is eventually implemented, this is the single line that has
// to change — and having it present means the change is visible in a diff
// rather than spread across a package.
func (m Mode) Applies() bool { return false }

// Description explains the mode, for the daemon's own status output.
func (m Mode) Description() string {
	switch m {
	case ModeDevelopment:
		return "THN is installed, configured and tested. It observes and reports. " +
			"The network is not touched."
	case ModePrepared:
		return "Configuration, firewall rules, DHCP, DNS and QoS are all defined and a " +
			"rollback exists. None of it has been applied; the network is still as it was."
	default:
		return "unrecognised mode"
	}
}

// Status is what the daemon reports about itself.
type Status struct {
	// Mode is the mode it was started in.
	Mode Mode `json:"mode"`

	// ModeDescription explains what that mode permits.
	ModeDescription string `json:"mode_description"`

	// StartedAt is when the daemon came up.
	StartedAt time.Time `json:"started_at"`

	// Uptime is how long it has been running.
	Uptime string `json:"uptime"`

	// Socket is where it listens.
	Socket string `json:"socket"`

	// Privileged reports whether it can read the nftables and qdisc state.
	//
	// False is not an error. It means the firewall and shaping observations
	// will be reported as unreadable rather than as absent.
	Privileged bool `json:"privileged"`

	// Observations is how many observation cycles have completed.
	Observations int64 `json:"observations"`

	// LastObservationAt is when the last one finished.
	LastObservationAt time.Time `json:"last_observation_at,omitempty"`

	// LastError is the most recent observation error, if any.
	LastError string `json:"last_error,omitempty"`

	// Applies reports whether this daemon can change the host. Always false in
	// this build, and reported rather than assumed.
	Applies bool `json:"applies"`

	// Verbs are the query verbs this daemon serves.
	//
	// Listed because a control surface with no published vocabulary is a
	// control surface nobody can audit, and because a caller that needs a verb
	// not in this list has discovered it does not exist.
	Verbs []string `json:"verbs"`
}