package cli

import (
	"sort"
	"time"

	"github.com/venth/thn-gateway/internal/config"
	"github.com/venth/thn-gateway/internal/identity"
	"github.com/venth/thn-gateway/internal/policy"
)

// This file implements `thn policy`.
//
// # Why this command exists at all
//
// A per-device, time-varying policy layer is the kind of thing that is easy to
// write and impossible to predict. Which rate does the guest get at half past
// ten on a Sunday? Three bindings match, two schedules are active, and the
// answer comes out of a ranking rule an operator has to know rather than infer.
//
// So the command does not just report the answer. It reports every binding it
// considered, which one won, and why the others lost. A policy layer whose
// selection is invisible is one nobody will leave enabled.
//
// # It is pure
//
// No host access, no daemon, no privileges. That is what makes it safe to run
// on a laptop pointed at a production gateway, and what makes the whole policy
// document checkable before it is deployed anywhere.

// runPolicy implements the `thn policy` group.
func runPolicy(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn policy: expected a subcommand (list, resolve)\n")
	}

	switch args[0] {
	case "list":
		return runPolicyList(env, args[1:])
	case "resolve":
		return runPolicyResolve(env, args[1:])
	default:
		return env.fatalf("thn policy: unknown subcommand %q; expected list or resolve\n", args[0])
	}
}

// runPolicyList prints the policy document.
func runPolicyList(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	verbose := fs.Bool("long", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn policy list: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	cfg, path, code := loadConfigForPolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	set := cfg.Policies

	// Names come from map keys, and the list is exactly the place an operator
	// would notice them missing.
	set.Normalise()

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config":   path,
			"policies": set,
			"counts":   policyCounts(set),
		}); err != nil {
			env.errorf("thn policy list: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	counts := policyCounts(set)

	env.printf("Policies (%s)\n", path)
	env.printf("───────\n\n")

	if counts["total"] == 0 {
		env.printf("No per-device or per-time policies are configured.\n")
		env.printf("\n")
		env.printf("Every device gets the host defaults from the qos, dns and\n")
		env.printf("firewall blocks. That is a complete configuration; this command\n")
		env.printf("shows nothing because there is nothing to show.\n")
		return ExitOK
	}

	env.printf("Profiles\n")
	for _, p := range sortedBandwidth(set) {
		env.printf("  bandwidth  %s\n", p.String())
	}
	for _, p := range sortedDNS(set) {
		env.printf("  dns        %s\n", p.String())
	}
	for _, p := range sortedFirewall(set) {
		env.printf("  firewall   %s\n", p.String())
	}
	for _, p := range sortedDevices(set) {
		env.printf("  device     %s\n", p.String())
	}

	env.printf("\nSchedules\n")
	if len(set.Schedules) == 0 {
		env.printf("  none; every binding applies whenever it matches\n")
	}
	for _, name := range sortedScheduleNames(set) {
		env.printf("  %s\n", set.Schedules[name].String())
	}

	env.printf("\nBindings\n")
	if len(set.Bindings) == 0 {
		env.printf("  none\n")
	}
	for _, b := range set.Bindings {
		env.printf("  %s\n", b.String())
	}

	if *verbose {
		env.printf("\n")
		env.printf("Selection order\n")
		env.printf("───────\n")
		env.printf("When more than one binding matches a subject, the winner is chosen\n")
		env.printf("by, in order:\n\n")
		env.printf("  1. the higher schedule priority, so a deliberate priority beats\n")
		env.printf("     an accidental specificity match\n")
		env.printf("  2. the more specific subject: a MAC beats a device ID, which\n")
		env.printf("     beats a hostname, which beats a catch-all\n")
		env.printf("  3. the later declaration, when 1 and 2 are equal\n")
		env.printf("\n")
		env.printf("`thn policy resolve` prints which rule decided, and why the others\n")
		env.printf("lost. Rule 3 means a binding added at the bottom of the list wins,\n")
		env.printf("which is how an override is written: keep the general rule above\n")
		env.printf("and the exception below it.\n")
	}

	return ExitOK
}

// runPolicyResolve answers the question the whole layer exists for.
func runPolicyResolve(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	mac := fs.String("mac", "")
	deviceID := fs.String("device", "")
	hostname := fs.String("hostname", "")
	at := fs.String("at", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn policy resolve: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	if *mac == "" && *deviceID == "" && *hostname == "" {
		env.errorf("thn policy resolve: name a device with --mac, --device or --hostname.\n")
		env.errorf("\n")
		env.errorf("Without a subject, resolution reports the catch-all bindings, which is\n")
		env.errorf("the house default and rarely what was meant.\n")
		return ExitUsage
	}

	cfg, path, code := loadConfigForPolicy(env, *configPath)
	if code != ExitOK {
		return code
	}

	when := time.Now().UTC()
	if *at != "" {
		parsed, perr := time.Parse(time.RFC3339, *at)
		if perr != nil {
			return env.fatalf("thn policy resolve: --at %q is not an RFC 3339 timestamp\n", *at)
		}
		when = parsed.UTC()
	}

	subject := policy.Subject{Kind: policy.SubjectDevice, DeviceID: *deviceID, Hostname: *hostname}
	if *mac != "" {
		subject = policy.NewDeviceSubject(*mac)
	}

	// A device is looked up so a hostname or device ID can be resolved against
	// real data. This build has no lease source, so there is nothing to look
	// it up from and the subject match rests on what the operator typed. That
	// is a real limitation and it is stated in the output rather than left for
	// the reader to notice the absence.
	var dev *identity.Device

	got := cfg.Policies.Resolve(subject, dev, when)

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config":     path,
			"resolution": got,
		}); err != nil {
			env.errorf("thn policy resolve: %v\n", err)
			return ExitProblems
		}
		if len(got.Unresolved) > 0 {
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Policy resolution for %s\n", subject)
	env.printf("───────\n")
	env.printf("At %s, from %s\n", when.Format(time.RFC3339), path)
	env.printf("\n")

	if got.Device != nil {
		env.printf("  device profile:  %s\n", got.Device.Name)
	}
	if got.Bandwidth != nil {
		env.printf("  bandwidth:       %s\n", got.Bandwidth.String())
	}
	if got.DNS != nil {
		env.printf("  dns:             %s\n", got.DNS.String())
	}
	if got.Firewall != nil {
		env.printf("  firewall:        %s\n", got.Firewall.String())
	}
	if got.Device == nil && got.Bandwidth == nil && got.DNS == nil && got.Firewall == nil {
		env.printf("  No policies apply. The host defaults from the qos, dns and\n")
		env.printf("  firewall blocks are in force for this device.\n")
	}

	env.printf("\nWhy\n")
	if len(got.Reasons) == 0 {
		env.printf("  No bindings matched this subject.\n")
	}
	for _, r := range got.Reasons {
		mark := "  "
		if r.Selected {
			mark = "->"
		}
		env.printf("  %s %s -> %s\n", mark, r.Binding.Subject, r.Binding.Profile)
		env.printf("     %s\n", r.Explanation)
	}

	if len(got.Unresolved) > 0 {
		env.printf("\nProblems\n")
		for _, u := range got.Unresolved {
			env.printf("  %s\n", u)
		}
		env.printf("\nThese are configuration errors, not device faults. The resolution\n")
		env.printf("above is what the rest of the document produces.\n")
		return ExitProblems
	}

	// The next transition, so an operator can see when the answer changes
	// without having to run the command twice.
	var soonest time.Time
	for _, name := range sortedScheduleNames(cfg.Policies) {
		sch := cfg.Policies.Schedules[name]
		next := sch.Active(when).NextChange
		if next.IsZero() {
			continue
		}
		if soonest.IsZero() || next.Before(soonest) {
			soonest = next
		}
	}
	if !soonest.IsZero() {
		env.printf("\nNext scheduled change: %s\n", soonest.Format(time.RFC3339))
	}

	return ExitOK
}

// loadConfigForPolicy loads a configuration for the policy commands.
func loadConfigForPolicy(env *Env, path string) (config.Config, string, ExitCode) {
	var zero config.Config

	resolved := env.resolveConfigPath(path)
	cfg, err := loadConfig(env, resolved)
	if err != nil {
		env.errorf("thn policy: %v\n", err)
		return zero, resolved, ExitProblems
	}
	return cfg, resolved, ExitOK
}

// policyCounts summarises a policy document for display.
func policyCounts(set policy.Set) map[string]int {
	return map[string]int{
		"bandwidth": len(set.Bandwidth),
		"dns":       len(set.DNS),
		"firewall":  len(set.Firewall),
		"device":    len(set.Devices),
		"schedules": len(set.Schedules),
		"bindings":  len(set.Bindings),
		"total": len(set.Bandwidth) + len(set.DNS) + len(set.Firewall) +
			len(set.Devices),
	}
}

// sortedBandwidth returns the bandwidth profiles in name order.
func sortedBandwidth(set policy.Set) []policy.BandwidthProfile {
	out := make([]policy.BandwidthProfile, 0, len(set.Bandwidth))
	for _, p := range set.Bandwidth {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// sortedDNS returns the DNS profiles in name order.
func sortedDNS(set policy.Set) []policy.DNSProfile {
	out := make([]policy.DNSProfile, 0, len(set.DNS))
	for _, p := range set.DNS {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// sortedFirewall returns the firewall profiles in name order.
func sortedFirewall(set policy.Set) []policy.FirewallProfile {
	out := make([]policy.FirewallProfile, 0, len(set.Firewall))
	for _, p := range set.Firewall {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// sortedDevices returns the device profiles in name order.
func sortedDevices(set policy.Set) []policy.DeviceProfile {
	out := make([]policy.DeviceProfile, 0, len(set.Devices))
	for _, p := range set.Devices {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// sortedScheduleNames returns the schedule names in order.
func sortedScheduleNames(set policy.Set) []string {
	out := make([]string, 0, len(set.Schedules))
	for name := range set.Schedules {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
