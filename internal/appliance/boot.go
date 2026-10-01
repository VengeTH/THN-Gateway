package appliance

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Boot is the decision an appliance makes about itself before it serves traffic.
//
// # The question
//
// An appliance has verified its image, or has not. What does it do next?
//
// The tempting answer is "refuse to boot". It is wrong, and wrong in the
// worst possible direction: an appliance that will not start cannot be
// reached to be fixed, cannot be told what is wrong with it, and becomes a
// device that has to be carried to somebody with a keyboard.
//
// So the appliance always starts. What it varies is what it serves.
//
//	Verified       serve normally
//	Tampered       do not serve the network; keep management up so it can be
//	               diagnosed, or fall back to the other slot
//	BothBad        serve nothing; report as far as the management path allows
//
// # Why management survives
//
// The management path is the thing that must keep working when the data plane
// is wrong. A device that refuses to serve AND refuses to be talked to has
// turned a configuration problem into a site visit, and the site visit is the
// expensive part.
//
// Keeping management up when the image is tampered with is not a convenience.
// It is the difference between a recoverable fault and a brick, and it is the
// only reason the decision below prefers a reduced mode over no mode.
//
// # What it does not do
//
// It does not repair anything, and it does not decide which slot to boot —
// that is the bootloader's job, before this code runs. It reports what the
// situation is, and the surrounding system acts.

// Mode is what the appliance is willing to do.
type Mode string

const (
	// ModeNormal serves the data plane and management.
	ModeNormal Mode = "normal"

	// ModeSafe serves management but not the data plane.
	//
	// The gateway is a router: with a bad image, continuing to route traffic
	// means forwarding packets using software that is not the software that was
	// signed. Stopping means a site outage; continuing means an outage with an
	// unknown cause and an unverified forwarding path. The second is worse,
	// because it is harder to detect and harder to reason about afterwards.
	ModeSafe Mode = "safe"

	// ModeRescue serves management only, with the data plane explicitly off.
	//
	// The same decision as ModeSafe with the reason stated rather than
	// implied. Kept separate because an operator reading a log needs to tell
	// "degraded because a subsystem failed" from "degraded because the image
	// is not what was signed".
	ModeRescue Mode = "rescue"
)

// Decision is what the appliance decided and why.
type Decision struct {
	// Mode is what it will do.
	Mode Mode `json:"mode"`

	// Reason is a sentence for the operator, and is always populated.
	Reason string `json:"reason"`

	// ImageOK reports whether the filesystem matched its manifest.
	ImageOK bool `json:"image_ok"`

	// Findings are the verification discrepancies behind the decision.
	Findings []Finding `json:"findings,omitempty"`

	// Slot is the slot that is running.
	Slot string `json:"slot,omitempty"`

	// FallbackTo names the slot to try instead, when there is one.
	FallbackTo string `json:"fallback_to,omitempty"`

	// At is when the decision was made.
	At time.Time `json:"at"`
}

// BootInput is what the decision is made from.
type BootInput struct {
	// Verification is the result of checking the filesystem.
	Verification Report

	// Slots is the slot table, used to decide whether a fallback exists.
	//
	// A pointer because SlotTable contains a mutex and BootInput is passed by
	// value: copying it would copy the lock, and two copies would each believe
	// they owned the table. The same mistake made twice is still two slot
	// tables, which is worse than one that is slightly out of date.
	Slots *SlotTable

	// Running is the slot that is currently booted.
	Running string

	// MinServices is how many subsystems must be verified for the data plane
	// to be considered sound.
	//
	// The image manifest covers the files. It does not prove that the
	// services those files configure are running, and a gateway with a
	// correct image and a dead DHCP server is not serving. The health report
	// covers that, and this is where the two are joined.
	Health *HealthSummary
}

// HealthSummary is the service-level half of the boot decision.
type HealthSummary struct {
	// Services are the subsystems and whether they are up.
	Services map[string]bool

	// Unobservable names services that could not be checked.
	//
	// Carried separately because a service that could not be checked is not a
	// service that is down, and treating the two alike produces a gateway
	// that refuses to serve because nobody could ask.
	Unobservable []string
}

// Decide is the boot decision.
//
// Order matters and is the safety argument in one function: the image check
// comes before the service check, because a wrong image makes the service
// readings meaningless — a dhcpd reported as healthy by a tampered binary is
// not a healthy dhcpd.
func Decide(in BootInput, at time.Time) Decision {
	d := Decision{
		ImageOK:  in.Verification.OK,
		Findings: in.Verification.Findings,
		Slot:     in.Running,
		At:       at.UTC(),
	}

	// A tampered image is the first thing, and it dominates everything else.
	if !in.Verification.OK {
		d.Mode = ModeRescue
		d.Reason = fmt.Sprintf(
			"This filesystem does not match the image it was built from: %d "+
				"discrepancy/discrepancies. The data plane will not be served, because "+
				"forwarding packets using software that is not the software that was "+
				"signed is worse than not forwarding. Management stays up so this can be "+
				"diagnosed and corrected.",
			len(in.Verification.Findings))

		// A fallback is only worth naming if one exists, and saying "there is
		// nothing to fall back to" is more useful to an operator than an empty
		// field they have to interpret.
		if in.Slots == nil {
			d.Reason += " No slot table was supplied, so there is nothing to fall back to."
			return d
		}
		if alt, ok := in.Slots.FallbackTo(in.Running); ok {
			d.FallbackTo = alt
			d.Reason += fmt.Sprintf(
				" Slot %s holds a different image and can be tried instead.", alt)
		} else {
			d.Reason += " No other slot holds a different image, so there is nothing to fall back to."
		}
		return d
	}

	// The image is correct. Now the services.
	if in.Health != nil {
		if down := in.Health.downServices(); len(down) > 0 {
			d.Mode = ModeSafe
			d.Reason = fmt.Sprintf(
				"The image matches, but %d service(s) are not running: %s. Management is "+
					"served and the data plane is not, because a gateway missing a service "+
					"is failing clients in a way that is harder to diagnose than stopping.",
				len(down), strings.Join(down, ", "))
			return d
		}

		if len(in.Health.Unobservable) > 0 {
			// Unobservable is not down. A gateway whose services could not be
			// checked keeps serving, and says so — the same reasoning as
			// everywhere else in this project: absent evidence is not evidence
			// of absence, and refusing to serve because nobody could ask would
			// make every monitoring outage an outage.
			d.Mode = ModeNormal
			d.Reason = fmt.Sprintf(
				"The image matches and every checked service is running, but %d could not "+
					"be checked at all: %s. Serving, and recording that those are unverified.",
				len(in.Health.Unobservable), strings.Join(in.Health.Unobservable, ", "))
			return d
		}
	}

	d.Mode = ModeNormal
	d.Reason = "The filesystem matches the image and every service is running."
	return d
}

// downServices lists services reported as not running.
func (h *HealthSummary) downServices() []string {
	var out []string
	for name, up := range h.Services {
		if !up {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ServesDataPlane reports whether the mode permits forwarding traffic.
func (d Decision) ServesDataPlane() bool { return d.Mode == ModeNormal }

// ServesManagement reports whether the mode permits the device to be managed.
//
// Every mode does. That is the point: a decision that took management down
// with the data plane would turn a recoverable fault into a site visit.
func (d Decision) ServesManagement() bool { return d.Mode != "" }

// Render formats a decision for a terminal.
func Render(d Decision) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Mode:        %s\n", d.Mode)
	fmt.Fprintf(&sb, "Image:       %s\n", okFail(d.ImageOK))
	if d.Slot != "" {
		fmt.Fprintf(&sb, "Slot:        %s\n", d.Slot)
	}
	if d.FallbackTo != "" {
		fmt.Fprintf(&sb, "Fallback:    %s\n", d.FallbackTo)
	}
	fmt.Fprintf(&sb, "Data plane:  %s\n", onOff(d.ServesDataPlane()))
	fmt.Fprintf(&sb, "Management:  %s\n", onOff(d.ServesManagement()))
	sb.WriteString(strings.Repeat("-", 72) + "\n")
	sb.WriteString(d.Reason)

	if len(d.Findings) > 0 {
		sb.WriteString("\nDiscrepancies\n")
		for _, f := range d.Findings {
			fmt.Fprintf(&sb, "  [%s] %s\n", f.Kind, f.Path)
			for _, line := range strings.Split(strings.TrimSpace(f.Reason), "\n") {
				fmt.Fprintf(&sb, "      %s\n", line)
			}
		}
	}

	return sb.String()
}

func okFail(b bool) string {
	if b {
		return "matches the manifest"
	}
	return "DOES NOT MATCH THE MANIFEST"
}

func onOff(b bool) string {
	if b {
		return "served"
	}
	return "not served"
}
