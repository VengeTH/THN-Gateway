// Package deployment decides whether this host is an approved THN deployment.
//
// # Why this is its own question
//
// "Can this activate?" has two quite different answers, and conflating them
// produces a message that is wrong in one direction or the other.
//
//   - This machine is not a gateway. It is a laptop, a CI runner, a
//     development box. Nothing here should ever have changed, and saying so is
//     the most useful thing an operator can be told.
//   - This machine is a gateway, running a build that cannot apply. That is a
//     software limitation on real hardware, and it is a different sentence with
//     a different remedy.
//
// A tool that always answers the second is talking about itself on a box where
// the honest answer is the first. A tool that always answers the first will
// eventually tell a real operator their deployed gateway is not deployed.
//
// So this package computes the question from observation and lets the caller
// report whichever answer is true.
//
// # What "deployed" means here
//
// Not a marker file somebody created, and not a flag in the configuration. A
// marker file proves somebody ran a command; a flag proves somebody typed
// something. Neither proves the hardware is there.
//
// What proves it is that the interfaces the configuration names are actually
// present on the host, on a platform where the host can be inspected at all.
// That is the definition that cannot be satisfied by configuration alone, which
// is what makes it worth checking.
//
// # The consequence of not being deployed
//
// The network is untouched, and that is not an aspiration — it is the whole
// point. Nothing in this package can change anything, and neither can anything
// that consults it.
package deployment

import (
	"fmt"
	"sort"
	"strings"
)

// Signal is one piece of evidence about whether this host is a deployment.
type Signal struct {
	// Name identifies it.
	Name string `json:"name"`

	// WhatItChecks is a short statement of the question.
	WhatItChecks string `json:"what_it_checks"`

	// Met reports whether the answer was yes.
	Met bool `json:"met"`

	// Detail says what was actually seen.
	Detail string `json:"detail"`

	// Blocking reports whether failing this signal alone means the host is not
	// a deployment.
	//
	// Only signals that prove hardware presence are blocking. A gateway with a
	// perfectly good uplink and a missing descriptive name is still a
	// deployment, and refusing to describe it as one would be pedantry.
	Blocking bool `json:"blocking"`
}

// Status is the answer.
type Status struct {
	// Deployed reports whether this host is an approved THN deployment.
	Deployed bool `json:"deployed"`

	// Headline is the one-line verdict, for a status line.
	Headline string `json:"headline"`

	// Reason explains the verdict in the operator's terms.
	//
	// Empty when deployed. When not deployed it names the first unmet blocking
	// signal, because an operator needs the thing to go and look at rather than
	// a list.
	Reason string `json:"reason,omitempty"`

	// Signals are all the evidence, met or not, so the verdict can be checked
	// rather than believed.
	Signals []Signal `json:"signals"`
}

// Observation is everything this package is allowed to look at.
//
// Declared rather than importing the observation packages so that the question
// stays answerable without a host, and so that a test can ask it directly. The
// rule this maintains is the same one the guard maintains: the answer to a
// safety question depends on a fixed, visible set of inputs.
type Observation struct {
	// HostSupported reports whether the host could be inspected at all.
	//
	// False means nothing below was learned. That is a distinct state from
	// "inspected and the interfaces are absent", and the distinction is the
	// whole reason this field exists.
	HostSupported bool

	// HostPlatform is for the message, e.g. "linux".
	HostPlatform string

	// ConfiguredWAN is the interface the configuration names for the uplink.
	ConfiguredWAN string

	// ConfiguredLAN is the interface the configuration names downstream. Empty
	// when the configuration leaves it unset, which is a deliberate
	// development state rather than an error.
	ConfiguredLAN string

	// Interfaces are the interfaces present on the host.
	Interfaces []string

	// GatewayName is the configured gateway name.
	GatewayName string
}

// Detect answers whether this host is an approved deployment.
func Detect(o Observation) Status {
	var signals []Signal

	// 1. Can we look at all?
	signals = append(signals, Signal{
		Name:         "host-inspectable",
		WhatItChecks: "the host's network can be read at all",
		Met:          o.HostSupported,
		Blocking:     true,
		Detail:       hostDetail(o),
	})

	// 2. Is the uplink the configuration describes actually there?
	signals = append(signals, Signal{
		Name:         "wan-attached",
		WhatItChecks: "the configured uplink interface is present on this host",
		Met:          present(o.Interfaces, o.ConfiguredWAN),
		Blocking:     true,
		Detail:       ifaceDetail("uplink", o.ConfiguredWAN, o.Interfaces),
	})

	// 3. Is the downstream interface attached?
	//
	// An unset LAN is reported as not met, and that is correct: a gateway whose
	// downstream interface has not been chosen is not yet a gateway. It is
	// informational about *which* stage development is at, not a fault.
	signals = append(signals, Signal{
		Name:         "lan-attached",
		WhatItChecks: "the configured downstream interface is present on this host",
		Met:          present(o.Interfaces, o.ConfiguredLAN),
		Blocking:     true,
		Detail:       ifaceDetail("downstream", o.ConfiguredLAN, o.Interfaces),
	})

	// 4. Is it named? Not blocking: an unnamed gateway is still hardware.
	signals = append(signals, Signal{
		Name:         "named",
		WhatItChecks: "the configuration gives this gateway a name",
		Met:          strings.TrimSpace(o.GatewayName) != "",
		Blocking:     false,
		Detail:       nameDetail(o.GatewayName),
	})

	st := Status{Signals: signals}

	for _, s := range signals {
		if s.Met || !s.Blocking {
			continue
		}
		st.Reason = s.Detail
		break
	}
	if st.Reason != "" {
		st.Headline = "THN Gateway is not physically deployed."
		return st
	}

	st.Deployed = true
	st.Headline = "This host is an approved THN deployment."
	return st
}

func hostDetail(o Observation) string {
	if o.HostSupported {
		return fmt.Sprintf("host network state was read on %s; %d interface(s) present",
			platformName(o), len(o.Interfaces))
	}
	if o.HostPlatform == "" {
		return "this build could not inspect the host's network, so nothing below " +
			"was learned. Host inspection is Linux-only; on any other platform THN " +
			"is not able to tell what hardware it is running on."
	}
	return fmt.Sprintf(
		"this build cannot inspect host networking on %s, so nothing below was "+
			"learned. THN reads host state on Linux only, and refusing to guess is "+
			"the whole point: a gateway that cannot see itself cannot be told it "+
			"is one.", platformName(o))
}

func ifaceDetail(role, configured string, present []string) string {
	if strings.TrimSpace(configured) == "" {
		return fmt.Sprintf(
			"no %s interface is configured. The configuration names none, which is "+
				"the state a box is in while its hardware is still being chosen", role)
	}
	if has(present, configured) {
		return fmt.Sprintf("the %s interface %s is present", role, configured)
	}
	return fmt.Sprintf(
		"the %s interface %s named by the configuration is not on this host. "+
			"Present: %s", role, configured, listOr(present, "nothing"))
}

func nameDetail(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return "the configuration gives this gateway no name"
	}
	return fmt.Sprintf("this gateway is named %q", n)
}

func platformName(o Observation) string {
	if o.HostPlatform == "" {
		return "an unnamed platform"
	}
	return o.HostPlatform
}

func present(interfaces []string, want string) bool {
	if strings.TrimSpace(want) == "" {
		return false
	}
	return has(interfaces, want)
}

func has(haystack []string, want string) bool {
	for _, h := range haystack {
		if h == want {
			return true
		}
	}
	return false
}

func listOr(items []string, empty string) string {
	if len(items) == 0 {
		return empty
	}
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	return strings.Join(sorted, ", ")
}

// Blocking returns the signals that are unmet and blocking.
func (s Status) Blocking() []Signal {
	var out []Signal
	for _, sig := range s.Signals {
		if !sig.Met && sig.Blocking {
			out = append(out, sig)
		}
	}
	return out
}

// Render formats the status for a terminal.
func Render(s Status) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s\n", s.Headline)
	if s.Reason != "" {
		fmt.Fprintf(&sb, "\n%s\n", s.Reason)
	}
	sb.WriteString("\n")
	sb.WriteString("Evidence\n")
	sb.WriteString("--------\n")
	for _, sig := range s.Signals {
		mark := "no "
		if sig.Met {
			mark = "yes"
		}
		fmt.Fprintf(&sb, "  [%s] %-18s %s\n", strings.TrimSpace(mark), sig.Name, sig.Detail)
	}
	return sb.String()
}
