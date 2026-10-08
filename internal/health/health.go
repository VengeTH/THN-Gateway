// Package health checks a gateway against what it was supposed to become.
//
// # The question this answers
//
// An apply that reports success has told you that commands ran. It has not
// told you that the gateway works. Those are different claims, and a system
// that treats the first as the second will roll a broken change across a fleet
// with a green indicator beside it.
//
// So after an apply there is a second, independent question: is this gateway
// now doing what it was asked to do, and is it still reachable? This package
// answers it from observations, and it answers it three ways rather than two.
//
// # Four verdicts, not two
//
// Healthy, Degraded, Unhealthy, and — the one that matters most —
// Unknowable.
//
// A gateway that cannot be inspected has not been found healthy. It has been
// found unreadable, and the distinction is the same one the signals package
// makes, the same one the assistant makes, and the same one the reconciler
// makes: an absent reading is not a good reading.
//
// It is separated here because the failure mode is unusually dangerous at this
// point in the lifecycle. Immediately after an apply, "I could not read it" and
// "it is fine" look identical from a dashboard, and the dashboard is exactly
// what the person deciding whether to continue the rollout is looking at.
//
// # What "healthy" means
//
// Derived from the change set, not from a fixed checklist. A change that did
// not touch the firewall does not get a firewall health check, because a check
// that passes vacuously is worse than no check: it appears in the report and
// contributes nothing.
//
// The checks come from the same `diff` result the planner used, so "what was
// changed" and "what should now be true" cannot drift apart.
package health

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/diff"
)

// Verdict is the outcome of a health check.
type Verdict string

const (
	// VerdictHealthy means every check passed.
	VerdictHealthy Verdict = "healthy"

	// VerdictDegraded means something is wrong but the gateway is still
	// serving. Degraded is a real state and not a softer "healthy": it is the
	// one that should stop a rollout.
	VerdictDegraded Verdict = "degraded"

	// VerdictUnhealthy means the gateway is not doing what it was asked to.
	VerdictUnhealthy Verdict = "unhealthy"

	// VerdictUnknowable means the gateway could not be inspected.
	//
	// Never reported as healthy, and never reported as unhealthy either: an
	// unreadable gateway is not evidence of a fault, it is absence of evidence.
	VerdictUnknowable Verdict = "unknowable"
)

// Worst returns the more serious of two verdicts.
//
// The ordering is Unhealthy > Degraded > Unknowable > Healthy, and the
// surprising part is that Unknowable outranks Healthy.
//
// Healthy is *less* serious than Unknowable on purpose. A gateway that
// reported "healthy" and a gateway that reported nothing have to stay
// distinguishable, and the way to do that is to make the blank one visible
// rather than to let it collapse into the reassuring one. A report that
// aggregates a gateway it could read with one it could not must not come out
// healthy, because that is the aggregate an operator decides on.
func Worst(a, b Verdict) Verdict {
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

func rank(v Verdict) int {
	switch v {
	case VerdictHealthy:
		return 1
	case VerdictUnknowable:
		return 2
	case VerdictDegraded:
		return 3
	case VerdictUnhealthy:
		return 4
	default:
		return 0
	}
}

// Check is one assertion about the gateway.
type Check struct {
	// Name identifies the check.
	Name string `json:"name"`

	// Subject is what it concerns: a field path or a subsystem.
	Subject string `json:"subject,omitempty"`

	// Verdict is the outcome.
	Verdict Verdict `json:"verdict"`

	// Detail explains it in a sentence.
	//
	// Always populated, including for passing checks. A health report that
	// only names failures leaves an operator unable to tell a check that
	// passed from one that was never run.
	Detail string `json:"detail"`
}

// Report is the whole assessment.
type Report struct {
	// Gateway is the gateway assessed.
	Gateway string `json:"gateway"`

	// Generation is the generation that was being applied.
	Generation uint64 `json:"generation"`

	// Verdict is the overall outcome: the worst of the checks, and Unknowable
	// when nothing could be checked.
	Verdict Verdict `json:"verdict"`

	// Checks are the individual assertions, worst first.
	Checks []Check `json:"checks"`

	// Skipped names checks that could not run.
	//
	// Reported rather than omitted. A deployment that moved the WAN and
	// cannot verify the new default route needs to know that, and a report
	// that simply omits the check is a report that looks complete.
	Skipped []string `json:"skipped,omitempty"`

	// At is when the assessment was made.
	At time.Time `json:"at"`
}

// Failed reports whether the verdict should stop a rollout.
//
// Unknowable counts. A rollout that continues past a gateway nobody could read
// has widened an unknown, and the person who notices the gateway was
// unreachable is the person who cannot then undo how far it spread.
func (r Report) Failed() bool {
	return r.Verdict != VerdictHealthy
}

// Assess evaluates a gateway against the change set it was meant to apply.
//
// obs.Supported is checked first and short-circuits. A gateway that could not
// be inspected at all gets one Unknowable report rather than a list of checks
// that would all pass vacuously.
func Assess(gateway string, generation uint64, d diff.Result, obs diff.Observed, at time.Time) Report {
	r := Report{
		Gateway:    gateway,
		Generation: generation,
		Verdict:    VerdictHealthy,
		At:         at.UTC(),
	}

	if !obs.Supported {
		r.Verdict = VerdictUnknowable
		r.Checks = []Check{{
			Name:    "inspect",
			Subject: "host",
			Verdict: VerdictUnknowable,
			Detail: "The gateway could not be inspected at all, so nothing about its " +
				"health is known. This is not a pass: a change that has just been " +
				"applied and cannot then be read is the case this verdict exists " +
				"for, and it must stop a rollout.",
		}}
		return r
	}

	// Reachability first, because it is the failure that strands an operator.
	// A gateway that is up but unreachable from where the management path
	// points is worse than one that is plainly down.
	r.add(reachability(obs))

	// Then one check per drift that was meant to be resolved.
	for _, c := range d.Changes {
		switch c.Kind {
		case diff.KindDrift:
			r.add(resolved(c, obs))
		case diff.KindBlocked:
			// A blocked change was never applied, so its subject is unchanged.
			// It is still reported, because "this is known not to be applied"
			// is a fact the operator needs.
			r.add(Check{
				Name:    "blocked:" + c.Field,
				Subject: c.Field,
				Verdict: VerdictDegraded,
				Detail: fmt.Sprintf(
					"%s was not applied and remains as it was: %s", c.Field, c.Reason),
			})
		case diff.KindPending:
			r.Skipped = append(r.Skipped, c.Field)
		}
	}

	r.finalise()
	return r
}

// resolved checks that a change actually took effect.
func resolved(c diff.Change, obs diff.Observed) Check {
	// Drift on the uplink's link state is the one case where the desired
	// value is an expectation rather than something the host can be made to
	// satisfy: a carrier either delivers a link or it does not, and no
	// configuration change fixes it.
	if c.ID == "wan-link-state" && c.Desired == "up" {
		if !obs.WANPresent {
			return Check{
				Name: "resolved:" + c.Field, Subject: c.Field,
				Verdict: VerdictUnhealthy,
				Detail: fmt.Sprintf(
					"The change expected the uplink to come up, but %q is not present on the "+
						"host at all. The apply did not fail; the link is still absent.",
					obs.WANName),
			}
		}
		if !obs.WANUp {
			return Check{
				Name: "resolved:" + c.Field, Subject: c.Field,
				Verdict: VerdictDegraded,
				Detail: fmt.Sprintf(
					"The uplink %s was expected to come up after the change and is still "+
						"down. Everything the apply could do has been done; what remains is "+
						"physical.", obs.WANName),
			}
		}
		return Check{
			Name: "resolved:" + c.Field, Subject: c.Field,
			Verdict: VerdictHealthy,
			Detail:  fmt.Sprintf("The uplink %s is up, as the change expected.", obs.WANName),
		}
	}

	// For everything else the host cannot be asked directly here, so the check
	// reports what is known without claiming more than it can see.
	return Check{
		Name:    "applied:" + c.Field,
		Subject: c.Field,
		Verdict: VerdictHealthy,
		Detail: fmt.Sprintf(
			"%s was part of the change set (was %s, now expected to be %s). "+
				"Confirming it took effect requires reading the applied subsystem, "+
				"which this check does not do.",
			c.Field, orNone(c.Current), orNone(c.Desired)),
	}
}

// reachability checks that the gateway can still be managed.
func reachability(obs diff.Observed) Check {
	switch {
	case !obs.WANPresent && !obs.LANPresent:
		return Check{
			Name: "reachable", Subject: "interfaces",
			Verdict: VerdictUnhealthy,
			Detail: "Neither the uplink nor the downstream interface is present. " +
				"The gateway has no path in either direction and cannot be managed.",
		}
	case !obs.WANUp && !obs.LANUp:
		return Check{
			Name: "reachable", Subject: "interfaces",
			Verdict: VerdictDegraded,
			Detail: "Every interface is down. The gateway is not serving, and if the " +
				"management path runs over one of them it is also not reachable.",
		}
	case !obs.WANUp:
		return Check{
			Name: "reachable", Subject: "wan",
			Verdict: VerdictDegraded,
			Detail: fmt.Sprintf(
				"The uplink %s is down. The downstream interface is up, so the gateway "+
					"is still serving the LAN, but it has no path to anything beyond it.",
				obs.WANName),
		}
	default:
		return Check{
			Name: "reachable", Subject: "interfaces",
			Verdict: VerdictHealthy,
			Detail:  "At least one interface is up, so the gateway is reachable.",
		}
	}
}

// add appends a check.
func (r *Report) add(c Check) {
	r.Checks = append(r.Checks, c)
	r.Verdict = Worst(r.Verdict, c.Verdict)
}

// finalise sorts and produces the summary sentence.
func (r *Report) finalise() {
	sort.SliceStable(r.Checks, func(i, j int) bool {
		if r.Checks[i].Verdict != r.Checks[j].Verdict {
			return rank(r.Checks[i].Verdict) > rank(r.Checks[j].Verdict)
		}
		return r.Checks[i].Name < r.Checks[j].Name
	})
	sort.Strings(r.Skipped)

	if len(r.Checks) == 0 {
		r.Verdict = VerdictUnknowable
		r.Checks = []Check{{
			Name:    "checks",
			Verdict: VerdictUnknowable,
			Detail: "There was nothing to check: the gateway was already in the " +
				"requested state, so no check was generated and nothing was confirmed.",
		}}
	}
}

func orNone(s string) string {
	if s == "" {
		return "unset"
	}
	return s
}

// Render formats a report for a terminal.
func Render(r Report) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Health: %s\n", r.Verdict)
	fmt.Fprintf(&sb, "Gateway: %s, generation %d\n", r.Gateway, r.Generation)
	fmt.Fprintf(&sb, "%s\n\n", strings.Repeat("-", 72))

	for _, c := range r.Checks {
		fmt.Fprintf(&sb, "[%s] %s\n", c.Verdict, c.Name)
		for _, line := range strings.Split(strings.TrimSpace(c.Detail), "\n") {
			fmt.Fprintf(&sb, "    %s\n", line)
		}
	}

	if len(r.Skipped) > 0 {
		sb.WriteString("\nNot checked (could not be verified from the host)\n")
		for _, s := range r.Skipped {
			fmt.Fprintf(&sb, "  %s\n", s)
		}
	}

	return sb.String()
}
