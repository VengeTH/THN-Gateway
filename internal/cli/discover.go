package cli

// `thn discover` — what this machine is.
//
// # Why this exists
//
// An operator configuring a gateway for the first time does not know this
// machine's interface names, and should not have to. This command reports what
// was observed, what each observed interface could be used for, and what the
// host can do — so that choosing which NIC is the uplink is an informed act
// rather than a guess about what "eth0" means on this box.
//
// # Read-only
//
// It observes and renders. It assigns nothing, changes nothing, and activates
// nothing. Like `thn network inspect` it runs only guarded read-only commands.
//
// # MAC addresses are not printed
//
// A hardware address is a stable identifier and half of it is a network
// identifier. It is useful for configuration and it is not something to put
// on a screen in a shared terminal. The stable ID is shown instead, and the
// raw MAC is available behind --mac for the case where it is genuinely needed
// to write a configuration.

import (
	"fmt"
	"os"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
	"github.com/VengeTH/THN-Gateway/internal/profile"
)

// runDiscover implements `thn discover`.
func runDiscover(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.Bool("mac", false)
	fs.Bool("json", false)
	fs.Bool("emit", false)
	fs.String("config", "")

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn discover: %v\n", err)
	}
	showMAC := *fs.bools["mac"]
	emit := *fs.bools["emit"]

	// Observation goes through the same seam `thn readiness` uses. If the two
	// commands each assembled a snapshot themselves they would eventually
	// disagree, and the disagreement would show up as `discover` naming a
	// different interface than `readiness` gated on — on the one machine
	// where that matters most.
	_, d, err := host.NewDiscovery().Observe(cmdContext())
	if err != nil {
		env.errorf("thn discover: %v\n", err)
		return ExitProblems
	}

	// Resolve whatever roles the current document already assigns, so that
	// `thn discover` can answer "what does this machine look like RIGHT NOW"
	// rather than only "what hardware exists". Resolution is read-only and
	// assigns nothing: an unassigned interface stays unassigned.
	assign := []host.Assignment{}
	if cfg, cerr := loadConfigIfPresent(env, *fs.strings["config"]); cerr == nil {
		assign = roleAssignments(cfg)
	}
	res := host.Resolve(d, assign)

	// Write the resolved roles back onto the device so the renderer, the
	// assignment emitter and the JSON all read one model rather than three
	// that can disagree.
	applyResolutionTo(d, res)

	reps := evaluateProfiles(d, res)

	if env.IsJSON {
		if err := env.printJSON(discoveryJSON(d, showMAC, res, reps)); err != nil {
			env.errorf("thn discover: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	printDiscovery(env, d, showMAC, res, reps)

	if emit {
		env.printf("\n%s", RenderAssignments(d))
	}

	if !d.Supported {
		// Reporting nothing successfully would be the wrong answer: the
		// operator asked what this machine is and was not told.
		return ExitProblems
	}
	return ExitOK
}

// applyResolutionTo writes resolved roles onto the device's interfaces.
func applyResolutionTo(d *host.Device, res host.Resolution) {
	for n := range d.Interfaces {
		d.Interfaces[n].Role = host.RoleUnassigned
	}
	for _, a := range res.Assigned {
		for n := range d.Interfaces {
			if d.Interfaces[n].ID == a.ID {
				d.Interfaces[n].Role = a.Role
			}
		}
	}
}

// evaluateProfiles reports every profile's verdict against this host.
func evaluateProfiles(d *host.Device, res host.Resolution) []profile.Report {
	out := make([]profile.Report, 0, len(profile.All()))
	for _, p := range profile.All() {
		def, err := profile.Lookup(string(p))
		if err != nil {
			continue
		}
		out = append(out, profile.Evaluate(d, res, def))
	}
	return out
}

// loadConfigIfPresent loads a configuration if one exists, and tolerates its
// absence.
//
// Discovery must work on a machine that has never been configured. Failing
// because /etc/thn/config.yaml is missing would make the one command that
// helps an operator configure it the one command that will not run.
func loadConfigIfPresent(env *Env, explicit string) (config.Config, error) {
	path := env.resolveConfigPath(explicit)
	if _, statErr := os.Stat(path); statErr != nil {
		return config.Config{}, statErr
	}
	return loadConfig(env, path)
}

// discoveryJSON renders the device for a machine consumer.
func discoveryJSON(d *host.Device, showMAC bool, res host.Resolution, reps []profile.Report) map[string]any {
	ifaces := make([]map[string]any, 0, len(d.Interfaces))
	for _, i := range d.Interfaces {
		entry := map[string]any{
			"id":          i.ID,
			"id_kind":     string(i.IDKind),
			"system_name": i.SystemName,
			"kind":        i.Kind,
			"raw_kind":    i.RawKind,
			"state":       string(i.State),
			"link_up":     i.LinkUp,
			"admin_up":    i.AdminUp,
			"physical":    i.Physical,
			"virtual":     i.Virtual,
			"mtu":         i.MTU,
			"assignable":  i.Assignable,
			"role":        string(i.Role),
			"ipv4":        i.IPv4(),
			"ipv6":        i.IPv6(),
		}
		if i.Master != "" {
			entry["master"] = i.Master
		}
		if i.WirelessMode != "" {
			entry["wireless_mode"] = i.WirelessMode
		}
		if i.SpeedMbps > 0 {
			entry["speed_mbps"] = i.SpeedMbps
		}
		if len(i.Addresses) > 0 {
			entry["addresses"] = i.Addresses
		}
		if showMAC && i.MAC != "" {
			entry["mac"] = i.MAC
		}
		ifaces = append(ifaces, entry)
	}

	caps := make(map[string]any, len(d.Capabilities))
	for c, s := range d.Capabilities {
		caps[string(c)] = map[string]any{
			"available":  s.Available,
			"confidence": s.Confidence,
			"reason":     s.Reason,
		}
	}

	assignments := make([]map[string]any, 0, len(res.Assigned))
	for r, i := range res.Assigned {
		assignments = append(assignments, map[string]any{
			"role":          string(r),
			"selector":      i.ID,
			"system_name":   i.SystemName,
			"identity_kind": string(i.IDKind),
		})
	}

	profileReports := make([]map[string]any, 0, len(reps))
	for _, rep := range reps {
		profileReports = append(profileReports, map[string]any{
			"profile":   string(rep.Profile),
			"satisfied": rep.Satisfied,
			"findings":  rep.Findings,
		})
	}

	return map[string]any{
		"hostname":           d.Hostname,
		"os":                 d.OS,
		"arch":               d.Arch,
		"supported":          d.Supported,
		"observed_at":        d.ObservedAt,
		"forwarding_enabled": d.ForwardingEnabled,
		"interfaces":         ifaces,
		"capabilities":       caps,
		"diagnostics":        d.Diagnostics,
		"network_untouched":  true,
		"roles_available":    roleNames(),
		"roles_assigned":     assignments,
		"role_problems":      res.Problems,
		"role_candidates":    roleCandidateNames(d),
		"profiles":           profileReports,
		"statement":          "Current network remains untouched.",
	}
}

// roleCandidateNames lists the interfaces an operator MAY choose from.
//
// It is a list, not a decision. Rendering it is the whole difference between
// asking "which connection goes to the internet?" and answering it for them.
func roleCandidateNames(d *host.Device) []string {
	cands := d.RoleCandidates()
	out := make([]string, 0, len(cands))
	for _, i := range cands {
		out = append(out, i.SystemName)
	}
	return out
}

// roleNames lists assignable roles for a consumer.
func roleNames() []string {
	roles := host.KnownRoles()
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, string(r))
	}
	return out
}

// printDiscovery renders the device for a human.
//
// The three sections come from three models — the device, the role
// resolution, and the profile evaluations — and are printed together because
// an operator asking "what is this machine?" needs all three at once: what it
// has, what it has been told to do, and what it could be told to do.
func printDiscovery(env *Env, d *host.Device, showMAC bool, res host.Resolution, reps []profile.Report) {
	env.printf("%s", RenderDiscovery(d, showMAC))

	if len(res.Problems) > 0 {
		env.printf("\nUnresolved assignments\n")
		env.printf("──────────────────────\n")
		for _, s := range host.Suggestions(res) {
			env.printf("  - %s\n", s)
		}
		env.printf("\n  Nothing was changed. Assign an interface with `thn` or\n")
		env.printf("  edit the configuration, then run `thn validate`.\n")
	}

	env.printf("%s", RenderProfiles(reps))
}

// RenderAssignments renders a ready-to-paste configuration fragment binding
// the roles currently observed on this host.
//
// It emits STABLE IDENTITIES, not kernel names, wherever one exists. That is
// the whole value of the exercise: the configuration an operator writes on a
// laptop still works on the gateway after a NIC moves slots or predictable
// naming is turned off.
//
// Loopback is omitted because it can never hold a role, and a block naming it
// would be a block that fails validation on the next machine.
func RenderAssignments(d *host.Device) string {
	var b strings.Builder
	assigned := d.RoleAssignments()
	if len(assigned) == 0 {
		return ""
	}

	b.WriteString("Configuration fragment\n")
	b.WriteString("────────────────────\n")
	b.WriteString("  # Stable identities survive the NIC moving slots or being renamed.\n")
	b.WriteString("  network:\n")
	for _, a := range assigned {
		// No column padding: this fragment is meant to be copied into YAML,
		// and "wan :" is valid YAML but reads like a mistake to a human.
		fmt.Fprintf(&b, "    %s: %s\n", string(a.Role), a.Selector)
	}
	b.WriteString("\n  # Nothing above was applied. Review it, then copy it into your\n")
	b.WriteString("  # configuration and run `thn validate`.\n")
	return b.String()
}

// RenderProfiles renders what each profile would need from this host.
//
// It is here rather than in internal/profile so that a future UI and this CLI
// render the same facts, and so the rendering can be asserted in a test
// without executing anything.
func RenderProfiles(reps []profile.Report) string {
	var b strings.Builder
	b.WriteString("\nProfiles\n")
	b.WriteString("───────\n")
	for _, rep := range reps {
		def, err := profile.Lookup(string(rep.Profile))
		if err != nil {
			continue
		}
		word := "AVAILABLE"
		if !rep.Satisfied {
			word = "NOT AVAILABLE"
		}
		fmt.Fprintf(&b, "  %-14s %-14s %s\n", rep.Profile, word, def.Title)
		if !rep.Satisfied {
			for _, f := range rep.Blocked() {
				fmt.Fprintf(&b, "      - %s\n", f.Message)
			}
		}
	}
	return b.String()
}

// RenderDiscovery renders a device as the operator sees it.
//
// It is separate from printDiscovery so that a test can show the exact output
// a simulated host produces without a second implementation drifting from this
// one. Two renderers that format the same model differently is precisely how a
// CLI starts telling an operator something the model does not say.
func RenderDiscovery(d *host.Device, showMAC bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("THN Host\n")
	w("────────\n")
	w("  OS:           %s/%s\n", d.OS, d.Arch)
	if d.Hostname != "" {
		w("  Hostname:     %s\n", d.Hostname)
	}
	w("  Observed:     %s\n", d.ObservedAt.Format("2006-01-02T15:04:05Z"))
	w("  Inspection:   %s\n", supportedWord(d.Supported))
	w("  IPv4 forward: %t\n\n", d.ForwardingEnabled)

	if len(d.Interfaces) == 0 {
		w("No network interfaces were observed.\n")
	}

	for n, i := range d.Interfaces {
		w("%d. %s\n", n+1, describeKind(i.Kind))
		w("   System:  %s\n", i.SystemName)
		w("   ID:      %s (%s)\n", i.ID, i.IDKind)
		w("   Link:    %s\n", linkLabel(i))
		w("   Admin:   %s\n", adminLabel(i))
		w("   Hardware: %s\n", hardwareLabel(i))
		w("   Speed:   %s\n", speedLabel(i.SpeedMbps))
		w("   MTU:     %d\n", i.MTU)
		if showMAC && i.MAC != "" {
			w("   MAC:     %s\n", i.MAC)
		}
		if i.WirelessMode != "" {
			w("   Wireless: %s\n", i.WirelessMode)
		}
		if i.Master != "" {
			w("   Master:  %s\n", i.Master)
		}
		if i.Role != "" && i.Role != host.RoleUnassigned {
			w("   Role:    %s\n", i.Role)
		}
		if !i.Assignable {
			w("   Assign:  no — %s\n", unassignableReason(i.Kind))
		}
		if v4 := i.IPv4(); len(v4) > 0 {
			w("   IPv4:    %s\n", strings.Join(v4, ", "))
		}
		if v6 := i.IPv6(); len(v6) > 0 {
			w("   IPv6:    %s\n", strings.Join(v6, ", "))
		}
		w("\n")
	}

	w("Role candidates\n")
	w("───────────────\n")
	cands := d.RoleCandidates()
	if len(cands) == 0 {
		w("  none — this host has no interface that can hold a role\n")
	}
	for _, i := range cands {
		w("  %-16s %-10s %s\n", i.SystemName, describeKind(i.Kind), speedLabel(i.SpeedMbps))
	}
	w("\n  These are options, not choices. Nothing is assigned.\n")

	w("\nCapabilities\n")
	w("─────────────\n")
	for _, c := range host.AllCapabilities() {
		s, ok := d.Capabilities[c]
		if !ok {
			w("  %-18s UNKNOWN\n", c)
			continue
		}
		word := "NOT AVAILABLE"
		if s.Available {
			word = "AVAILABLE"
		}
		w("  %-18s %-14s (%s)\n", c, word, s.Confidence)
		if s.Reason != "" {
			w("      %s\n", s.Reason)
		}
	}

	w("\nRoles you can assign: %s\n", strings.Join(roleNames(), ", "))

	if len(d.Diagnostics) > 0 {
		w("\nDiagnostics\n")
		w("───────────\n")
		for _, diag := range d.Diagnostics {
			w("  - %s\n", diag)
		}
	}

	w("\nCurrent network remains untouched.\n")
	return b.String()
}

func supportedWord(ok bool) string {
	if ok {
		return "available"
	}
	return "unavailable on this platform — nothing was observed"
}

// describeKind renders an interface kind for a human.
func describeKind(kind string) string {
	switch kind {
	case "":
		return "Interface"
	case "ethernet":
		return "Ethernet"
	case "loopback":
		return "Loopback"
	case "wireless":
		return "Wireless"
	case "vlan":
		return "VLAN"
	case "bridge":
		return "Bridge"
	case "tunnel":
		return "Tunnel"
	default:
		return strings.ToUpper(kind[:1]) + kind[1:]
	}
}

func linkLabel(i host.Interface) string {
	if i.LinkUp {
		return "UP"
	}
	if i.State == network.LinkDown {
		return "DOWN (no carrier)"
	}
	if i.Kind == "loopback" {
		return "UP (loopback, no carrier)"
	}
	return "UNKNOWN"
}

func speedLabel(mbps int) string {
	switch {
	case mbps <= 0:
		return "not reported"
	case mbps >= 1000:
		return fmt.Sprintf("%d Gbps", mbps/1000)
	default:
		return fmt.Sprintf("%d Mbps", mbps)
	}
}

// adminLabel renders the administrative state separately from carrier.
//
// The two are different facts and collapsing them loses the interesting one: a
// cable that is unplugged looks identical to an interface that was never
// brought up, unless both are reported.
func adminLabel(i host.Interface) string {
	if i.AdminUp {
		if i.LinkUp {
			return "up, carrier present"
		}
		return "up, no carrier"
	}
	return "down"
}

// hardwareLabel says whether the link is real hardware, and says WHY when it
// is not. "virtual" on its own leaves an operator guessing which of a dozen
// virtual link types they are looking at.
func hardwareLabel(i host.Interface) string {
	if i.Physical {
		return "yes (physical interface)"
	}
	if i.Master != "" {
		return fmt.Sprintf("no (virtual %s, enslaved to %s)", i.Kind, i.Master)
	}
	if i.Kind == "" {
		return "not determined"
	}
	return fmt.Sprintf("no (virtual %s)", i.Kind)
}

// unassignableReason explains a refusal in terms the operator can act on.
func unassignableReason(kind string) string {
	switch kind {
	case host.KindLoopback:
		return "loopback cannot hold a role"
	case host.KindVeth:
		return "a container endpoint disappears when the container stops, " +
			"so a gateway role bound to it would silently expire"
	case host.KindDummy:
		return "a dummy interface has no peer and never will"
	default:
		return kind + " cannot hold a role"
	}
}
