package cli

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/dhcp"
	"github.com/VengeTH/THN-Gateway/internal/dhcp/dnsmasq"
	"github.com/VengeTH/THN-Gateway/internal/dns"
	"github.com/VengeTH/THN-Gateway/internal/gateway"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/identity"
	"github.com/VengeTH/THN-Gateway/internal/multiwan"
	"github.com/VengeTH/THN-Gateway/internal/qos"
	"github.com/VengeTH/THN-Gateway/internal/sandbox"
)

// dhcpPolicyFromConfig derives a DHCP policy from configuration.
func dhcpPolicyFromConfig(cfg config.Config) (dhcp.Policy, error) {
	var prefix netip.Prefix
	if cfg.Network.LANPrefix != "" {
		p, err := netip.ParsePrefix(cfg.Network.LANPrefix)
		if err != nil {
			return dhcp.Policy{}, fmt.Errorf("network.lan_prefix %q is not valid: %w", cfg.Network.LANPrefix, err)
		}
		prefix = p
	}

	var gateway netip.Addr
	if prefix.IsValid() {
		gateway = prefix.Addr()
	}

	storePath := resolveStorePath(cfg, "")
	stored := loadBindings(storePath)
	lanSel := bindingSelector(cfg, stored, host.RoleLAN)

	p := dhcp.Policy{
		Enabled:        cfg.DHCP.Enabled,
		Interface:      lanSel,
		LANPrefix:      prefix,
		Authoritative:  cfg.DHCP.Authoritative,
		LeaseTime:      cfg.DHCP.LeaseTime,
		LeaseMax:       cfg.DHCP.LeaseMax,
		Domain:         cfg.DHCP.Domain,
		GatewayAddress: gateway,
		Backend: dhcp.BackendConfig{
			Name:       "dnsmasq",
			ConfigFile: cfg.Services.Dnsmasq.ConfigFile,
			LeaseFile:  cfg.Services.Dnsmasq.LeaseFile,
		},
	}

	for _, rg := range cfg.DHCP.Ranges {
		start, err := netip.ParseAddr(rg.Start)
		if err != nil {
			return dhcp.Policy{}, fmt.Errorf("dhcp.ranges.start %q is not an address: %w", rg.Start, err)
		}
		end, err := netip.ParseAddr(rg.End)
		if err != nil {
			return dhcp.Policy{}, fmt.Errorf("dhcp.ranges.end %q is not an address: %w", rg.End, err)
		}
		var mask netip.Addr
		if rg.Netmask != "" {
			if mask, err = netip.ParseAddr(rg.Netmask); err != nil {
				return dhcp.Policy{}, fmt.Errorf("dhcp.ranges.netmask %q is not an address: %w", rg.Netmask, err)
			}
		}
		p.Ranges = append(p.Ranges, dhcp.Range{Start: start, End: end, Netmask: mask})
	}

	for _, res := range cfg.DHCP.Reservations {
		var addr netip.Addr
		if res.Address != "" {
			a, err := netip.ParseAddr(res.Address)
			if err != nil {
				return dhcp.Policy{}, fmt.Errorf("dhcp.reservations.address %q is not an address: %w", res.Address, err)
			}
			addr = a
		}
		p.Reservations = append(p.Reservations, dhcp.Reservation{
			MAC:       res.MAC,
			Address:   addr,
			Hostname:  res.Hostname,
			LeaseTime: res.LeaseTime,
		})
	}

	if len(p.Ranges) == 0 && cfg.DHCP.Enabled && prefix.IsValid() {
		p.Ranges = dhcp.DerivePool(prefix, 100, 150)
	}

	return p, nil
}

// dnsPolicyFromConfig derives a DNS policy from configuration.
// upstreamResolvers decides which resolvers the DNS service forwards to.
//
// # Two fields, one concept, and why this is explicit
//
// A configuration can name resolvers twice:
//
//	network.dns    the resolvers the HOST should use
//	dns.upstream   the resolvers the DNS SERVICE should forward to
//
// Those are different concerns, and both are legitimate. They are not
// different VALUES though: a document that set them to different resolvers
// would be describing a machine whose own queries go one way and whose
// clients' queries go another, and nothing in the rest of the model could
// act on the difference.
//
// So: dns.upstream is canonical for the service, network.dns is the fallback
// for documents that predate it, and a document that sets both to DIFFERENT
// values is rejected by validation. Silently preferring one is what made this
// invisible before — editing dns.upstream did nothing and said nothing.
//
// Which field was used is returned so the policy can record its provenance and
// a caller can report it.
func upstreamResolvers(cfg config.Config) (list []string, from string, err error) {
	if len(cfg.DNS.Upstream) > 0 {
		return cfg.DNS.Upstream, "dns.upstream", nil
	}
	if len(cfg.Network.DNS) > 0 {
		return cfg.Network.DNS, "network.dns", nil
	}
	return nil, "", nil
}

func dnsPolicyFromConfig(cfg config.Config) (dns.Policy, error) {
	storePath := resolveStorePath(cfg, "")
	stored := loadBindings(storePath)
	lanSel := bindingSelector(cfg, stored, host.RoleLAN)

	p := dns.Policy{
		Enabled:              cfg.DNS.Enabled,
		Interface:            lanSel,
		LocalDomain:          cfg.DNS.LocalDomain,
		CacheSize:            cfg.DNS.CacheSize,
		LogQueries:           cfg.DNS.LogQueries,
		NoIPv6:               cfg.DNS.NoIPv6,
		RejectUnmappedBlocks: true,
	}

	if cfg.Network.LANPrefix != "" {
		if prefix, err := netip.ParsePrefix(cfg.Network.LANPrefix); err == nil {
			p.ListenAddress = prefix.Addr()
		}
	}

	upstreams, from, err := upstreamResolvers(cfg)
	if err != nil {
		return dns.Policy{}, err
	}
	for _, u := range upstreams {
		addr, perr := netip.ParseAddr(u)
		if perr != nil {
			return dns.Policy{}, fmt.Errorf("%s %q is not an address: %w", from, u, perr)
		}
		p.Upstream = append(p.Upstream, addr)
	}

	for _, rec := range cfg.DNS.LocalRecords {
		addr, err := netip.ParseAddr(rec.Address)
		if err != nil {
			return dns.Policy{}, fmt.Errorf("dns.local_records.address %q is not an address: %w", rec.Address, err)
		}
		p.LocalRecords = append(p.LocalRecords, dns.Record{
			Hostname: rec.Hostname,
			Address:  addr,
			Aliases:  rec.Aliases,
		})
	}

	return p, nil
}

// dhcpIntent builds the DHCP intent report for a document and its gateway
// intent.
//
// The LAN role is read from the gateway intent rather than from the
// configuration a second time, so DHCP can never conclude that the LAN
// resolves when the gateway layer concluded it does not. One resolution, one
// answer, shared by the report, the desired state and the plan.
func dhcpIntent(cfg config.Config, gw gateway.Intent) dhcp.Report {
	lan := dhcp.LANRole{
		Declared: cfg.Network.LAN != "" || cfg.Network.LANPrefix != "",
		Prefix:   cfg.Network.LANPrefix,
	}
	ri := gw.Roles[host.RoleLAN]
	lan.Selector = ri.Selector
	lan.Resolved = ri.Resolved
	lan.Interface = ri.Interface
	lan.StableID = ri.StableID
	if ri.Declared {
		lan.Declared = true
	}

	policy, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		// The policy could not be built at all. Report that as the whole
		// intent rather than guessing a pool: a DHCP intent derived from a
		// document whose bounds do not parse would be fiction.
		return dhcp.Report{
			Intent:  dhcp.Intent{Enabled: cfg.DHCP.Enabled, LAN: lan},
			Verdict: dhcp.VerdictBlocked,
			Summary: "DHCP cannot be read from this document",
			Findings: []dhcp.Finding{{
				Field:    "dhcp.ranges",
				Code:     dhcp.CodeRangeInvalid,
				Severity: dhcp.SeverityError,
				Message:  err.Error(),
				Hint:     "write each pool bound as an address, for example 10.77.0.100",
			}},
		}
	}

	return dhcp.ValidateIntent(dhcp.FromPolicy(policy, lan))
}

// dnsIntent builds the DNS intent report for a document and its gateway
// intent.
//
// The upstream source rule is taken from dns.ResolveUpstream, the same
// function the desired state uses. Deriving it here as well would mean two
// answers to "which field wins", and the one printed beside the other would
// be whichever disagreed.
func dnsIntent(cfg config.Config, gw gateway.Intent) dns.Report {
	lan := dns.LANRole{
		Declared: cfg.Network.LAN != "" || cfg.Network.LANPrefix != "",
		Prefix:   cfg.Network.LANPrefix,
	}
	ri := gw.Roles[host.RoleLAN]
	lan.Selector = ri.Selector
	lan.Resolved = ri.Resolved
	lan.Interface = ri.Interface
	lan.StableID = ri.StableID
	if ri.Declared {
		lan.Declared = true
	}

	dec := dns.ResolveUpstream(cfg.DNS.Upstream, cfg.Network.DNS)

	policy, err := dnsPolicyFromConfig(cfg)
	if err != nil {
		return dns.Report{
			Intent:  dns.Intent{Enabled: cfg.DNS.Enabled, LAN: lan},
			Verdict: dns.VerdictBlocked,
			Summary: "DNS cannot be read from this document",
			Findings: []dns.Finding{{
				Field:    "dns",
				Code:     dns.CodeUpstreamInvalid,
				Severity: dns.SeverityError,
				Message:  err.Error(),
				Hint:     "check the upstream resolvers and local records are addresses",
			}},
		}
	}

	return dns.ValidateIntent(dns.FromPolicy(policy, lan, dec))
}

// qosIntent builds the QoS intent report for a document and its gateway intent.
//
// # Capability comes from the host, never from a flag
//
// The capability evidence is read from the observed device through
// internal/host's M7.1.1 capability model. It is NOT taken from
// `--assume-cake`, which exists for `thn qos validate`'s own command and
// represents an operator's hypothesis rather than a fact about the machine.
//
// With no observation at all — a static `thn validate` in CI — the result is
// unknown. That is the correct answer, not a default: a CI job has not
// established anything about the gateway's kernel, and reporting the CAKE
// capability it cannot see as available would put a guess into the desired
// digest.
func qosIntent(cfg config.Config, gw gateway.Intent, dev *host.Device) qos.Report {
	role := qos.LANRole{
		Selector: cfg.QoS.Interface,
		Declared: cfg.QoS.Interface != "" || cfg.Network.WAN != "",
	}
	if role.Selector == "" {
		role.Selector = string(host.RoleWAN)
		role.Declared = cfg.Network.WAN != ""
	}

	ri := gw.Roles[host.RoleWAN]
	lan := gw.Roles[host.RoleLAN]

	role.Resolved = ri.Resolved
	role.Interface = ri.Interface
	role.StableID = ri.StableID
	if ri.Declared {
		role.Declared = true
	}

	// Check for role conflicts:
	// 1. If qos.interface explicitly specifies the LAN role or points to LAN interface
	// 2. Or if gateway intent has a conflict between WAN and LAN
	if strings.EqualFold(cfg.QoS.Interface, "lan") ||
		(lan.Declared && cfg.QoS.Interface != "" && (cfg.QoS.Interface == lan.Selector || (lan.Interface != "" && cfg.QoS.Interface == lan.Interface))) {
		role.Conflict = true
	} else if ri.Declared && lan.Declared && ri.Resolved && lan.Resolved && ri.Interface == lan.Interface && ri.Interface != "" {
		role.Conflict = true
	}

	// An explicit qos.interface is preserved as written, and resolves only if
	// it names the WAN role the gateway actually resolved. Otherwise the
	// kernel name is left unresolved rather than paired with an unrelated
	// identity.
	if cfg.QoS.Interface != "" && !role.Conflict {
		role.Selector = cfg.QoS.Interface
		if role.Selector == ri.Selector || (ri.Interface != "" && role.Selector == ri.Interface) {
			role.Interface = ri.Interface
			role.StableID = ri.StableID
			role.Resolved = ri.Resolved
		} else {
			role.Resolved = false
			role.Interface = ""
			role.StableID = ""
		}
	}

	policy := qosPolicyFromConfig(cfg)
	cap := qos.CakeCapability(dev)
	observed := observedQdiscKinds(dev)

	return qos.ValidateIntent(qos.FromPolicy(policy, role, cap, observed))
}

// observedQdiscKinds lists the queue disciplines currently attached, sorted by
// the caller.
//
// Nothing here is adopted or removed: THN observes qdiscs and reports them.
// Ownership is a separate question this milestone deliberately does not
// answer.
func observedQdiscKinds(dev *host.Device) []string {
	if dev == nil {
		return nil
	}
	out := make([]string, 0, len(dev.TrafficControl.Qdiscs))
	for _, q := range dev.TrafficControl.Qdiscs {
		if q.Kind != "" {
			out = append(out, q.Kind)
		}
	}
	return out
}

// multiWANIntent builds the Multi-WAN intent report for a document and its gateway intent.
func multiWANIntent(cfg config.Config, gw gateway.Intent, dev *host.Device) multiwan.Report {
	otherRoles := make(map[string]string)
	for r, ri := range gw.Roles {
		if r != host.RoleWAN && !r.IsWAN() {
			roleName := string(r)
			if ri.StableID != "" {
				otherRoles[ri.StableID] = roleName
			}
			if ri.Interface != "" {
				otherRoles[ri.Interface] = roleName
			}
			if ri.Selector != "" {
				otherRoles[ri.Selector] = roleName
			}
		}
	}

	intent := multiwan.FromConfig(cfg, otherRoles, dev)
	return multiwan.ValidateIntent(intent)
}

// multiwanFindings projects Multi-WAN findings into the shared rendering view.
func multiwanFindings(in []multiwan.Finding) []findingView {
	out := make([]findingView, 0, len(in))
	for _, f := range in {
		out = append(out, findingView{
			severity: string(f.Severity),
			field:    f.Field,
			code:     f.Code,
			message:  f.Message,
			hint:     f.Hint,
		})
	}
	return out
}

// runDHCP implements the `thn dhcp` group.
func runDHCP(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn dhcp: expected a subcommand (render, validate, leases)\n")
	}

	switch args[0] {
	case "render":
		return runDHCPRender(env, args[1:])
	case "validate":
		return runDHCPValidate(env, args[1:])
	case "leases":
		return runDHCPLeases(env, args[1:])
	default:
		return env.fatalf("thn dhcp: unknown subcommand %q; expected render, validate or leases\n", args[0])
	}
}

// resolveServiceRoot determines the sandbox root.
//
// --root confines every file operation to a directory, which is what makes the
// whole pipeline testable without touching a real system. It is the same
// switch CI uses.
func resolveServiceRoot(env *Env, explicit string) sandbox.Root {
	if explicit != "" {
		return sandbox.New(explicit)
	}
	if v := env.Getenv("THN_ROOT"); v != "" {
		return sandbox.New(v)
	}
	return sandbox.System()
}

// servicePolicies loads configuration and derives both policies.
func servicePolicies(env *Env, configPath string) (dhcp.Policy, dns.Policy, string, ExitCode) {
	path := env.resolveConfigPath(configPath)

	cfg, err := loadConfig(env, path)
	if err != nil {
		env.errorf("thn: %v\n", err)
		return dhcp.Policy{}, dns.Policy{}, path, ExitProblems
	}

	dp, err := dhcpPolicyFromConfig(cfg)
	if err != nil {
		env.errorf("thn: %v\n", err)
		return dhcp.Policy{}, dns.Policy{}, path, ExitProblems
	}

	np, err := dnsPolicyFromConfig(cfg)
	if err != nil {
		env.errorf("thn: %v\n", err)
		return dhcp.Policy{}, dns.Policy{}, path, ExitProblems
	}

	return dp, np, path, ExitOK
}

// runDHCPValidate implements `thn dhcp validate`.
func runDHCPValidate(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn dhcp validate: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	dp, np, path, code := servicePolicies(env, *configPath)
	if code != ExitOK {
		return code
	}

	dhcpResult := dhcp.Validate(dp)
	dnsResult := dns.Validate(np)

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config": path,
			"dhcp": map[string]any{
				"valid":    dhcpResult.Valid,
				"findings": dhcpResult.Findings,
			},
			"dns": map[string]any{
				"valid":    dnsResult.Valid,
				"findings": dnsResult.Findings,
			},
		}); err != nil {
			env.errorf("thn dhcp validate: %v\n", err)
			return ExitProblems
		}
	} else {
		printServiceValidation(env, path, dp, np, dhcpResult, dnsResult)
	}

	if !dhcpResult.Valid || !dnsResult.Valid {
		return ExitProblems
	}
	return ExitOK
}

// printServiceValidation renders DHCP and DNS validation.
func printServiceValidation(env *Env, path string, dp dhcp.Policy, np dns.Policy, dr dhcp.Result, nr dns.Result) {
	env.printf("DHCP (from %s)\n", path)
	env.printf("────────────\n")
	env.printf("%s\n", dp)
	env.printf("Result: %s (%d error, %d warning, %d info)\n",
		passFail(dr.Valid), dr.ErrorCount, dr.WarningCount, dr.InfoCount)
	printFindings(env, dhcpFindings(dr.Findings))

	env.printf("\nDNS\n")
	env.printf("────────────\n")
	env.printf("%s\n", np)
	env.printf("Result: %s (%d error, %d warning, %d info)\n",
		passFail(nr.Valid), nr.ErrorCount, nr.WarningCount, nr.InfoCount)
	printFindings(env, dnsFindings(nr.Findings))
}

// dhcpFindings projects DHCP findings into the shared view.
func dhcpFindings(in []dhcp.Finding) []findingView {
	out := make([]findingView, 0, len(in))
	for _, f := range in {
		out = append(out, findingView{
			severity: string(f.Severity),
			field:    f.Field,
			code:     f.Code,
			message:  f.Message,
			hint:     f.Hint,
		})
	}
	return out
}

// dnsFindings projects DNS findings into the shared view.
func dnsFindings(in []dns.Finding) []findingView {
	out := make([]findingView, 0, len(in))
	for _, f := range in {
		out = append(out, findingView{
			severity: string(f.Severity),
			field:    f.Field,
			code:     f.Code,
			message:  f.Message,
			hint:     f.Hint,
		})
	}
	return out
}

// printFindings renders a finding list.
func printFindings(env *Env, findings []findingView) {
	if len(findings) == 0 {
		env.printf("\nNo findings.\n")
		return
	}
	env.printf("\n")
	for _, f := range findings {
		env.printf("  %-8s %-30s %s\n", f.severity, f.field, f.message)
		if f.hint != "" {
			env.printf("  %-8s %-30s hint: %s\n", "", "", f.hint)
		}
	}
}

// findingView is a minimal projection of a finding, so that the two services'
// finding types can be rendered by one function despite being distinct types.
type findingView struct {
	severity string
	field    string

	// code is the stable, machine-readable classification.
	//
	// Empty where the producing layer has not classified the finding. It is
	// shown by the intent printers in place of the field path, because a code
	// is something an operator can grep and a field path is something they can
	// edit — and a terminal block has room for only one of them.
	code    string
	message string
	hint    string
}

// runDHCPRender implements `thn dhcp render`.
//
// Render produces the dnsmasq configuration. It does not start dnsmasq, does
// not reload it, and does not touch the running server: loading the file is a
// deliberate operator action.
func runDHCPRender(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	rootPath := fs.String("root", "")
	out := fs.String("out", "")
	force := fs.Bool("force", false)
	skipValidate := fs.Bool("no-validate", false)

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn dhcp render: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	dp, np, path, code := servicePolicies(env, *configPath)
	if code != ExitOK {
		return code
	}

	if !*skipValidate {
		dhcpResult := dhcp.Validate(dp)
		dnsResult := dns.Validate(np)
		if !dhcpResult.Valid || !dnsResult.Valid {
			env.errorf("thn dhcp render: the configuration is not valid; not rendering.\n\n")
			printServiceValidation(env, path, dp, np, dhcpResult, dnsResult)
			env.errorf("\nFix the findings above, or pass --no-validate to render anyway.\n")
			return ExitProblems
		}
	}

	content := dnsmasq.Render(dp, np, dp.LANPrefix, dp.GatewayAddress)

	// The generated file is checked against dnsmasq's directive vocabulary
	// before it is offered. A typo produces a file dnsmasq accepts and
	// ignores, which is how a gateway ends up with no DNS and no indication
	// why.
	issues := dnsmasq.ValidateConfig(content)
	if len(issues) > 0 && !*skipValidate {
		env.errorf("thn dhcp render: the generated file contains unknown directives:\n\n")
		for _, is := range issues {
			env.errorf("  line %d: %s\n", is.Line, is.Message)
		}
		env.errorf("\nThis build would generate a file dnsmasq silently ignores.\n")
		return ExitProblems
	}

	root := resolveServiceRoot(env, *rootPath)
	target := *out
	if target == "" {
		target = dp.Backend.ConfigFile
	}

	if *out == "" {
		if env.IsJSON {
			if err := env.printJSON(map[string]any{
				"config":      path,
				"root":        root.String(),
				"config_file": target,
				"content":     content,
				"written":     false,
			}); err != nil {
				env.errorf("thn dhcp render: %v\n", err)
				return ExitProblems
			}
			return ExitOK
		}
		env.printf("%s", content)
		return ExitOK
	}

	if root.Exists(target) && !*force {
		env.errorf("thn dhcp render: %s already exists; pass --force to overwrite it.\n", target)
		env.errorf("The generated file is THN-owned, so overwriting is safe, but this\n")
		env.errorf("check exists so a render cannot overwrite a file by accident.\n")
		return ExitProblems
	}

	if err := root.WriteFile(target, content, 0o644); err != nil {
		env.errorf("thn dhcp render: %v\n", err)
		return ExitProblems
	}

	if !env.IsJSON {
		env.errorf("Wrote %d bytes to %s\n", len(content), root.Resolve(target))
		env.errorf("\n")
		env.errorf("Nothing has been applied. dnsmasq has not been started or reloaded.\n")
		env.errorf("To check and load it:\n")
		env.errorf("  dnsmasq --test --conf-file=%s\n", root.Resolve(target))
		env.errorf("  systemctl reload dnsmasq\n")
	}
	return ExitOK
}

// runDHCPLeases implements `thn dhcp leases`, reading the lease file.
func runDHCPLeases(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	rootPath := fs.String("root", "")
	asJSON := fs.Bool("json", false)
	limit := fs.String("limit", "0")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn dhcp leases: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	dp, _, path, code := servicePolicies(env, *configPath)
	if code != ExitOK {
		return code
	}

	root := resolveServiceRoot(env, *rootPath)
	source := dnsmasq.LeaseSource{Path: dp.Backend.LeaseFile}
	collector := dhcp.NewCollector(source, identity.NewRegistry())

	now := time.Now().UTC()
	set, changes, err := collector.Collect(context.Background(), root, now)
	if err != nil {
		env.errorf("thn dhcp leases: %v\n", err)
		return ExitProblems
	}

	reserved := reservedSet(dp.Reservations)
	summary := dhcp.Summarise(set.Leases, dp.TotalAddresses(), now, reserved)

	// Sorting by address is how an operator reads a lease table.
	leases := make([]dhcp.Lease, len(set.Leases))
	copy(leases, set.Leases)
	dhcp.SortLeases(leases)

	if *limit != "" && *limit != "0" {
		if n, convErr := parsePort(*limit); convErr == nil && n > 0 && n < len(leases) {
			leases = leases[:n]
		}
	}

	if env.IsJSON || *asJSON {
		if err := env.printJSON(map[string]any{
			"config":     path,
			"root":       root.String(),
			"lease_file": dp.Backend.LeaseFile,
			"summary":    summary,
			"leases":     leases,
			"devices":    collector.Registry().All(),
			"problems":   set.Problems,
			"changes":    changes,
		}); err != nil {
			env.errorf("thn dhcp leases: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	printLeases(env, path, root, dp, set, summary, leases, collector.Registry(), changes)
	return ExitOK
}

// reservedSet returns the set of reserved hardware addresses.
func reservedSet(reservations []dhcp.Reservation) map[string]bool {
	out := make(map[string]bool, len(reservations))
	for _, r := range reservations {
		out[dhcp.NormalisedMAC(r.MAC)] = true
	}
	return out
}

// printLeases renders the lease table and device inventory.
func printLeases(env *Env, path string, root sandbox.Root, dp dhcp.Policy,
	set *dhcp.LeaseSet, summary dhcp.Summary, leases []dhcp.Lease,
	reg *identity.Registry, changes []dhcp.DeviceChange) {

	env.printf("Leases (from %s)\n", path)
	env.printf("────────────\n")
	env.printf("Lease file: %s\n", dp.Backend.LeaseFile)
	env.printf("Root:       %s\n", root.String())
	env.printf("Source:     %s\n", set.Source)
	env.printf("Collected:  %s\n", set.CollectedAt.Format(time.RFC3339))
	env.printf("\n")
	env.printf("Total:      %d\n", summary.Total)
	env.printf("Active:     %d\n", summary.Active)
	env.printf("Expired:    %d\n", summary.Expired)
	env.printf("Reserved:   %d\n", summary.Reserved)
	env.printf("Uncorrelated: %d\n", summary.Uncorrelated)
	env.printf("Addresses:  %d of %d in pool\n", summary.AddressesInUse, summary.PoolCapacity)
	if summary.PoolCapacity > 0 {
		env.printf("Utilisation: %.1f%%\n", summary.PoolUtilisation)
	}
	if summary.ShortestRemaining > 0 {
		env.printf("Shortest lease: %s\n", roundDuration(summary.ShortestRemaining))
	}

	if len(set.Problems) > 0 {
		env.printf("\nProblems\n")
		for _, p := range set.Problems {
			env.printf("  %s\n", p)
		}
	}

	if len(changes) > 0 {
		env.printf("\nNew since last observation\n")
		for _, c := range changes {
			env.printf("  %-17s %s  %s\n", c.Device.MAC, c.Device.String(), c.Kind)
		}
	}

	env.printf("\n%-15s %-15s %-17s %-10s %s\n", "HOSTNAME", "ADDRESS", "MAC", "LEASE", "DEVICE")
	now := set.CollectedAt
	for _, l := range leases {
		host := l.Hostname
		if host == "" {
			host = "-"
		}
		dev := "-"
		if l.DeviceID != "" {
			if d, ok := reg.Get(l.DeviceID); ok {
				dev = d.ID
			}
		}
		env.printf("%-15s %-15s %-17s %-10s %s\n",
			truncate(host, 15), l.Address.String(), l.MAC,
			roundDuration(l.Remaining(now)), dev)
	}

	devices := reg.All()
	if len(devices) > 0 {
		env.printf("\nDevices (%d)\n", len(devices))
		env.printf("%-16s %-15s %-17s %-9s %s\n", "HOSTNAME", "ADDRESS", "MAC", "CONFIDENCE", "AGE")
		for _, d := range devices {
			addr := "-"
			if a, ok := d.CurrentAddress(); ok {
				addr = a.String()
			}
			env.printf("%-16s %-15s %-17s %-9s %s\n",
				truncate(d.PrimaryHostname(), 16), addr, d.MAC,
				string(d.Confidence), roundDuration(d.Age(now)))
		}
	}
}

// runDNS implements the `thn dns` group.
func runDNS(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn dns: expected a subcommand (render, validate, lookup)\n")
	}

	switch args[0] {
	case "render":
		return runDHCPRender(env, args[1:])
	case "validate":
		return runDHCPValidate(env, args[1:])
	case "lookup":
		return runDNSLookup(env, args[1:])
	default:
		return env.fatalf("thn dns: unknown subcommand %q; expected render, validate or lookup\n", args[0])
	}
}

// runDNSLookup reports what a name would resolve to under the policy.
//
// It answers from the configuration alone. A name that is not a local record
// would be forwarded upstream, and THN does not query upstream resolvers: doing
// so from a planning tool would make its output depend on the internet.
func runDNSLookup(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	configPath := fs.String("config", "")
	name := fs.String("name", "")

	rest, err := fs.Parse(args)
	if err != nil {
		return env.fatalf("thn dns lookup: %v\n", err)
	}
	if len(rest) > 0 {
		*configPath = rest[0]
	}

	_, np, path, code := servicePolicies(env, *configPath)
	if code != ExitOK {
		return code
	}

	if *name == "" {
		return env.fatalf("thn dns lookup: --name is required\n")
	}

	// The gateway's own name always resolves to itself.
	matches := findRecords(np, *name)

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"config":    path,
			"name":      *name,
			"answers":   matches,
			"forwarded": len(matches) == 0,
		}); err != nil {
			env.errorf("thn dns lookup: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("%s\n", *name)
	if len(matches) == 0 {
		env.printf("  no local record; the query would be forwarded upstream to %s\n",
			strings.Join(np.UpstreamStrings(), ", "))
		return ExitOK
	}
	for _, m := range matches {
		env.printf("  %-30s %s\n", m, "local record")
	}
	return ExitOK
}

// findRecords returns the addresses a name resolves to locally.
func findRecords(p dns.Policy, name string) []string {
	query := strings.ToLower(strings.TrimSuffix(name, "."))
	var out []string

	for _, rec := range p.LocalRecords {
		names := append([]string{rec.Hostname}, rec.Aliases...)
		for _, n := range names {
			if strings.ToLower(n) == query ||
				strings.ToLower(rec.FQDN(p.LocalDomain)) == query {
				out = append(out, rec.Address.String())
				break
			}
		}
	}

	return out
}

// truncate shortens a string for table display.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

// roundDuration renders a duration to a readable, fixed-width form.
//
// A sub-second duration is rendered as "just now" rather than "expired":
// "expired" means a lease has lapsed, and using it for a device first seen
// moments ago would report a newly-discovered device as if it were gone.
func roundDuration(d time.Duration) string {
	if d < 0 {
		return "expired"
	}
	if d < time.Second {
		return "just now"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		days := int(d.Hours()) / 24
		return fmt.Sprintf("%dd%02dh", days, int(d.Hours())%24)
	}
}

// writeIfRequested writes content to a path inside the sandbox root.
func writeIfRequested(root sandbox.Root, path, content string, force bool) error {
	if root.Exists(path) && !force {
		return fmt.Errorf("%s already exists; pass --force to overwrite it", path)
	}
	return root.WriteFile(path, content, 0o644)
}

// ensureRootExists creates the sandbox root, for tests and CI.
func ensureRootExists(root sandbox.Root) error {
	if root.Base == "" {
		return nil
	}
	return os.MkdirAll(root.Base, 0o755)
}
