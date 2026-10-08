package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// trafficProbeTimeout bounds a real-traffic health check.
//
// Long enough to cross a veth pair, be forwarded, translated and answered; a
// second is plenty on a healthy lab and a short timeout would let a slow host
// report a firewall problem that does not exist.
const trafficProbeTimeout = 3 * time.Second

// LinuxDriver performs real Linux networking mutations using guarded system tools.
//
// To enforce safety, it requires an approved LabConfig and verifies that it is operating
// inside a disposable lab environment before permitting any mutation.
type LinuxDriver struct {
	runner       CommandRunner
	labCfg       LabConfig
	labVerified  bool
	capabilities Capabilities
	prober       TrafficProber
}

// NewLinuxDriver constructs a Linux driver.
func NewLinuxDriver(runner CommandRunner, labCfg LabConfig) *LinuxDriver {
	if runner == nil {
		runner = NewDefaultCommandRunner()
	}
	return &LinuxDriver{
		runner: runner,
		labCfg: labCfg,
	}
}

// SetTrafficProber installs the prober used by real-traffic health checks.
//
// It is optional. A driver without one still runs every structural check; it
// simply reports a traffic check as unevaluable rather than passing it, which
// is the only safe reading of "I could not try".
func (d *LinuxDriver) SetTrafficProber(p TrafficProber) *LinuxDriver {
	d.prober = p
	return d
}

func (d *LinuxDriver) Name() string {
	return "linux"
}

// CanApply reports whether the driver is authorized to mutate host networking.
// Requires successful disposable lab verification.
func (d *LinuxDriver) CanApply() bool {
	return d.labVerified
}

// AuthorizeLab runs the explicit lab verification checks.
func (d *LinuxDriver) AuthorizeLab(ctx context.Context) error {
	if err := VerifyLabEnvironment(ctx, d.labCfg, d.runner); err != nil {
		d.labVerified = false
		return err
	}
	d.labVerified = true
	return nil
}

// DetectCapabilities checks whether ip, nft, sysctl, and tc are available on this host.
func (d *LinuxDriver) DetectCapabilities(ctx context.Context) (Capabilities, error) {
	caps := Capabilities{Details: make(map[string]string)}

	if p, err := d.runner.LookPath("ip"); err == nil && p != "" {
		if _, _, err := d.runner.Run(ctx, "ip", "link", "show"); err == nil {
			caps.IP = true
			caps.Details["ip"] = "available"
		}
	}

	if p, err := d.runner.LookPath("nft"); err == nil && p != "" {
		if _, _, err := d.runner.Run(ctx, "nft", "list", "tables"); err == nil {
			caps.NFT = true
			caps.Details["nft"] = "available"
		}
	}

	if p, err := d.runner.LookPath("sysctl"); err == nil && p != "" {
		if _, _, err := d.runner.Run(ctx, "sysctl", "-n", "net.ipv4.ip_forward"); err == nil {
			caps.Sysctl = true
			caps.Details["sysctl"] = "available"
		}
	}

	if p, err := d.runner.LookPath("tc"); err == nil && p != "" {
		if _, _, err := d.runner.Run(ctx, "tc", "qdisc", "show"); err == nil {
			caps.TC = true
			caps.Details["tc"] = "available"
		}
	}

	d.capabilities = caps
	return caps, nil
}

// Execute translates a structured Operation into bounded arguments and runs it safely.
func (d *LinuxDriver) Execute(ctx context.Context, op Operation) error {
	if !d.CanApply() {
		return fmt.Errorf("%w: lab environment has not been verified or authorization failed", ErrCannotApply)
	}

	if err := op.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrOperationFailed, err)
	}

	switch o := op.(type) {
	case OpLinkSetUp:
		_, _, err := d.runner.Run(ctx, "ip", "link", "set", o.Interface, "up")
		return err

	case OpLinkSetDown:
		_, _, err := d.runner.Run(ctx, "ip", "link", "set", o.Interface, "down")
		return err

	case OpAddressAdd:
		_, _, err := d.runner.Run(ctx, "ip", "addr", "add", o.CIDR, "dev", o.Interface)
		return err

	case OpAddressDelete:
		_, _, err := d.runner.Run(ctx, "ip", "addr", "del", o.CIDR, "dev", o.Interface)
		return err

	case OpRouteAdd:
		args := []string{"route", "add", o.Destination, "via", o.Gateway}
		if o.Device != "" {
			args = append(args, "dev", o.Device)
		}
		_, _, err := d.runner.Run(ctx, "ip", args...)
		return err

	case OpRouteReplace:
		args := []string{"route", "replace", o.Destination, "via", o.Gateway}
		if o.Device != "" {
			args = append(args, "dev", o.Device)
		}
		_, _, err := d.runner.Run(ctx, "ip", args...)
		return err

	case OpRouteDelete:
		args := []string{"route", "del", o.Destination}
		if o.Gateway != "" {
			args = append(args, "via", o.Gateway)
		}
		if o.Device != "" {
			args = append(args, "dev", o.Device)
		}
		_, _, err := d.runner.Run(ctx, "ip", args...)
		return err

	case OpSysctlSet:
		_, _, err := d.runner.Run(ctx, "sysctl", "-w", fmt.Sprintf("%s=%s", o.Key, o.Value))
		return err

	case OpNFTApplyTHNTable:
		return d.applyTHNTable(ctx, o)

	case OpNFTDeleteTHNTable:
		// Delete only table inet thn
		_, _, err := d.runner.Run(ctx, "nft", "delete", "table", "inet", "thn")
		return err

	case OpQDiscApply:
		args := []string{"qdisc", "replace", "dev", o.Interface, "root", o.Algorithm}
		if o.DownloadKbps > 0 || o.UploadKbps > 0 {
			args = append(args, "bandwidth", fmt.Sprintf("%dkbit", o.DownloadKbps), "upload", fmt.Sprintf("%dkbit", o.UploadKbps))
		}
		_, _, err := d.runner.Run(ctx, "tc", args...)
		return err

	case OpQDiscDelete:
		_, _, err := d.runner.Run(ctx, "tc", "qdisc", "del", "dev", o.Interface, "root")
		return err

	case OpDNSApply:
		// Refused, not ignored. See the identical case in driver_production.go.
		//
		// The lab has the same limitation as production — no DNS service is
		// implemented — and a lab that silently accepted this would let a
		// "commit" in CI stand in for a behaviour the real host would not have.
		return fmt.Errorf("%w: applying resolvers %s requires a DNS service, "+
			"which THN does not implement in any environment",
			ErrCapabilityMissing, strings.Join(o.Servers, ", "))

	default:
		return fmt.Errorf("unknown operation type: %T", op)
	}
}

// applyTHNTable installs `table inet thn`, which is the only nftables table
// THN owns.
//
// Every other table on the host is left alone, so a foreign firewall — a VPN
// client, a container runtime, the operator's own rules — survives a THN
// transaction untouched. The flush below is scoped to this table for the same
// reason: it makes apply idempotent without ever reaching the ruleset.
func (d *LinuxDriver) applyTHNTable(ctx context.Context, o OpNFTApplyTHNTable) error {
	run := func(args ...string) error {
		_, _, err := d.runner.Run(ctx, "nft", args...)
		return err
	}

	if err := run("add", "table", "inet", "thn"); err != nil {
		return err
	}
	// Scope of the flush is exactly `inet thn`. `nft flush ruleset` is
	// forbidden by ValidateCommand and is never constructed here.
	if err := run("flush", "table", "inet", "thn"); err != nil {
		return err
	}

	if err := run("add", "chain", "inet", "thn", "input",
		"{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", o.InboundPolicy, ";", "}"); err != nil {
		return err
	}
	if err := run("add", "chain", "inet", "thn", "forward",
		"{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", o.InboundPolicy, ";", "}"); err != nil {
		return err
	}

	if o.AllowEstablished {
		if err := run("add", "rule", "inet", "thn", "input", "ct", "state", "established,related", "accept"); err != nil {
			return err
		}
		// Return traffic for a forwarded session has to be permitted in the
		// forward chain too. Without it a client can open a connection and
		// every reply is dropped, which presents as a hang rather than as a
		// firewall problem.
		if err := run("add", "rule", "inet", "thn", "forward", "ct", "state", "established,related", "accept"); err != nil {
			return err
		}
	}

	if o.AllowLoopback {
		if err := run("add", "rule", "inet", "thn", "input", "iifname", "lo", "accept"); err != nil {
			return err
		}
		if err := run("add", "rule", "inet", "thn", "forward", "iifname", "lo", "accept"); err != nil {
			return err
		}
	}

	if o.GatewayPath() {
		// LAN to WAN is the one direction a gateway exists to permit. The
		// chain policy is drop, so this rule is what makes the device forward
		// at all — there is no implicit allow.
		forward := []string{"add", "rule", "inet", "thn", "forward",
			"iifname", o.LANInterface, "oifname", o.WANInterface}
		if o.LANSubnet != "" {
			forward = append(forward, "ip", "saddr", o.LANSubnet)
		}
		forward = append(forward, "accept")
		if err := run(forward...); err != nil {
			return err
		}

		// The LAN is the trusted segment, so a client can reach the gateway's
		// own services. WAN-to-LAN is deliberately absent: with a drop policy
		// it is refused, and no rule below grants it.
		input := []string{"add", "rule", "inet", "thn", "input", "iifname", o.LANInterface}
		if o.LANSubnet != "" {
			input = append(input, "ip", "saddr", o.LANSubnet)
		}
		input = append(input, "accept")
		if err := run(input...); err != nil {
			return err
		}
	}

	if len(o.NATInterfaces) > 0 {
		if err := run("add", "chain", "inet", "thn", "postrouting",
			"{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "policy", "accept", ";", "}"); err != nil {
			return err
		}
		for _, iface := range o.NATInterfaces {
			if err := run("add", "rule", "inet", "thn", "postrouting", "oifname", iface, "masquerade"); err != nil {
				return err
			}
		}
	}

	return nil
}

// CaptureState inspects actual Linux network state for scoped resources.
func (d *LinuxDriver) CaptureState(ctx context.Context, scope BackupScope) (*StateSnapshot, error) {
	snap := NewStateSnapshot()

	// 1. Links
	for _, iface := range scope.Interfaces {
		stdout, _, err := d.runner.Run(ctx, "ip", "-j", "link", "show", iface)
		if err == nil && stdout != "" {
			var links []struct {
				Operstate string   `json:"operstate"`
				Flags     []string `json:"flags"`
			}
			if err := json.Unmarshal([]byte(stdout), &links); err == nil && len(links) > 0 {
				state := "down"
				for _, flag := range links[0].Flags {
					if flag == "UP" {
						state = "up"
						break
					}
				}
				snap.Links[iface] = state
			}
		}
	}

	// 2. Addresses
	for _, iface := range scope.Interfaces {
		stdout, _, err := d.runner.Run(ctx, "ip", "-j", "addr", "show", iface)
		if err == nil && stdout != "" {
			var addrs []struct {
				AddrInfo []struct {
					Local     string `json:"local"`
					Prefixlen int    `json:"prefixlen"`
				} `json:"addr_info"`
			}
			if err := json.Unmarshal([]byte(stdout), &addrs); err == nil && len(addrs) > 0 {
				var cidrs []string
				for _, a := range addrs[0].AddrInfo {
					if a.Local != "" && a.Prefixlen > 0 {
						cidrs = append(cidrs, fmt.Sprintf("%s/%d", a.Local, a.Prefixlen))
					}
				}
				snap.Addresses[iface] = cidrs
			}
		}
	}

	// 3. Routes
	if scope.Routes {
		stdout, _, err := d.runner.Run(ctx, "ip", "-j", "route", "show", "default")
		if err == nil && stdout != "" {
			var routes []struct {
				Gateway string `json:"gateway"`
			}
			if err := json.Unmarshal([]byte(stdout), &routes); err == nil && len(routes) > 0 {
				snap.DefaultRoute = routes[0].Gateway
			}
		}
	}

	// 4. Sysctls
	for _, k := range scope.Sysctls {
		stdout, _, err := d.runner.Run(ctx, "sysctl", "-n", k)
		if err == nil {
			snap.Sysctls[k] = strings.TrimSpace(stdout)
		}
	}

	// 5. NFTables
	if scope.NFTables {
		stdout, _, err := d.runner.Run(ctx, "nft", "list", "table", "inet", "thn")
		if err == nil && !strings.Contains(stdout, "No such file or directory") {
			snap.NFTablesTHNPresent = true
			snap.NFTablesTHNContent = stdout
		} else {
			snap.NFTablesTHNPresent = false
		}
	}

	return snap, nil
}

// VerifyHealth queries Linux state to evaluate post-apply health checks.
func (d *LinuxDriver) VerifyHealth(ctx context.Context, checks []HealthCheck) (HealthResult, error) {
	var results []HealthCheckResult
	allPassed := len(checks) > 0

	// No checks is not health.
	//
	// An empty list would otherwise walk out of the loop below with everything
	// passing and certify a gateway nobody asked a question about. That is the
	// same fail-open as an unrecognised check, one step earlier in the same
	// function, and it is the last place a plan's verification can be made to
	// mean nothing.
	if len(checks) == 0 {
		return HealthResult{
			Healthy:       false,
			FailureReason: "no health checks were supplied, so the gateway's state is unverified",
		}, nil
	}

	for _, hc := range checks {
		res := HealthCheckResult{
			Target:      hc.Target,
			Check:       hc.Check,
			Expectation: hc.Expectation,
			Passed:      true,
		}

		switch hc.Check {
		case "link_carrier":
			stdout, _, err := d.runner.Run(ctx, "ip", "-j", "link", "show", hc.Target)
			if err != nil {
				res.Passed = false
				res.Error = err.Error()
				allPassed = false
			} else {
				var links []struct {
					Operstate string   `json:"operstate"`
					Flags     []string `json:"flags"`
				}
				if err := json.Unmarshal([]byte(stdout), &links); err == nil && len(links) > 0 {
					up := false
					for _, f := range links[0].Flags {
						if f == "UP" {
							up = true
							break
						}
					}
					if !up {
						res.Passed = false
						res.Observed = "link state is DOWN"
						allPassed = false
					} else {
						res.Observed = "link state is UP"
					}
				}
			}

		case "address_assigned":
			iface := hc.Target
			if idx := strings.Index(iface, ":"); idx >= 0 {
				iface = iface[:idx]
			}
			stdout, _, err := d.runner.Run(ctx, "ip", "-j", "addr", "show", iface)
			if err != nil {
				res.Passed = false
				res.Error = err.Error()
				allPassed = false
			} else if want, ok := expectedCIDR(hc.Expectation); ok {
				// The CIDR is read from the plan's own expectation rather than
				// assumed, so the check verifies the address the operator asked
				// for. A hardcoded 10.77.0.1 would pass on a lab configured for
				// something else, which is the opposite of a check.
				if interfaceHasAddress(stdout, want) {
					res.Observed = fmt.Sprintf("%s assigned to %s", want, iface)
				} else {
					res.Passed = false
					res.Observed = fmt.Sprintf("%s not found on interface %s (kernel reports %s)", want, iface, strings.TrimSpace(stdout))
					allPassed = false
				}
			} else if interfaceHasAddress(stdout, "10.77.0.1/24") {
				res.Observed = "address assigned"
			} else {
				res.Passed = false
				res.Observed = "10.77.0.1 not found on interface"
				allPassed = false
			}

		case "kernel_forwarding":
			stdout, _, err := d.runner.Run(ctx, "sysctl", "-n", "net.ipv4.ip_forward")
			val := strings.TrimSpace(stdout)
			if err != nil || val != "1" {
				res.Passed = false
				res.Observed = fmt.Sprintf("net.ipv4.ip_forward = %q", val)
				allPassed = false
			} else {
				res.Observed = "net.ipv4.ip_forward = 1"
			}

		case "firewall_active":
			stdout, _, err := d.runner.Run(ctx, "nft", "list", "table", "inet", "thn")
			if err != nil || !strings.Contains(stdout, "table inet thn") {
				res.Passed = false
				res.Observed = "table inet thn absent or error"
				allPassed = false
			} else {
				res.Observed = "table inet thn active"
			}

		case "nat_masquerade":
			res, allPassed = d.checkNAT(ctx, hc, res, allPassed)

		case "lan_to_wan_traffic":
			res, allPassed = d.checkTraffic(ctx, hc, res, allPassed, ProbeSideLAN, true)

		case "wan_to_lan_blocked":
			res, allPassed = d.checkTraffic(ctx, hc, res, allPassed, ProbeSideWAN, false)

		default:
			// An unrecognised check fails rather than passing.
			//
			// The alternative is worse than useless: a plan carrying a check
			// this build cannot evaluate would report the gateway healthy on
			// the strength of the checks that happened to be understood.
			res.Passed = false
			res.Observed = "check was not evaluated"
			res.Error = fmt.Sprintf("unsupported health check %q", hc.Check)
			allPassed = false
		}

		results = append(results, res)
	}

	failReason := ""
	if !allPassed {
		failReason = "one or more health checks failed against live Linux state"
	}

	return HealthResult{
		Healthy:       allPassed,
		Checks:        results,
		FailureReason: failReason,
	}, nil
}

// checkNAT confirms a masquerade rule is really installed.
//
// The rule's presence in the table is not enough on its own: masquerade has to
// be in the postrouting chain to be consulted, and a rule naming an interface
// that does not exist never matches.
func (d *LinuxDriver) checkNAT(ctx context.Context, hc HealthCheck, res HealthCheckResult, allPassed bool) (HealthCheckResult, bool) {
	stdout, _, err := d.runner.Run(ctx, "nft", "list", "table", "inet", "thn")
	if err != nil {
		res.Passed, allPassed = false, false
		res.Observed = "table inet thn absent or error"
		return res, allPassed
	}

	if !strings.Contains(stdout, "chain postrouting") {
		res.Passed, allPassed = false, false
		res.Observed = "no postrouting chain"
		return res, allPassed
	}
	if !strings.Contains(stdout, "masquerade") {
		res.Passed, allPassed = false, false
		res.Observed = "postrouting chain has no masquerade rule"
		return res, allPassed
	}

	for _, iface := range interfacesNamedIn(hc.Expectation) {
		if !strings.Contains(stdout, iface) {
			res.Passed, allPassed = false, false
			res.Observed = fmt.Sprintf("masquerade rule does not name interface %s", iface)
			return res, allPassed
		}
	}

	res.Observed = "masquerade rule active in postrouting"
	return res, allPassed
}

// interfacesNamedIn extracts interface names from an expectation of the form
// "masquerade rule active for eth0, thnwan0".
func interfacesNamedIn(expectation string) []string {
	const marker = " active for "
	idx := strings.Index(expectation, marker)
	if idx < 0 {
		return nil
	}
	var out []string
	for _, part := range strings.Split(expectation[idx+len(marker):], ",") {
		if name := strings.TrimSpace(part); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// checkTraffic performs a real connection and judges the result.
//
// wantReachable is the point of the check. For the LAN-to-WAN check it is
// true and a refusal is a failure of the gateway; for the WAN-to-LAN check it
// is false and a success is the failure. The two are otherwise the same probe,
// which is the point: a firewall that is open and a firewall that is shut are
// distinguished by a packet, not by a rule listing.
func (d *LinuxDriver) checkTraffic(ctx context.Context, hc HealthCheck, res HealthCheckResult, allPassed bool, side string, wantReachable bool) (HealthCheckResult, bool) {
	if d.prober == nil {
		res.Passed, allPassed = false, false
		res.Observed = "not evaluated"
		res.Error = "no traffic prober is configured; real-traffic checks cannot be claimed"
		return res, allPassed
	}

	probeCtx, cancel := context.WithTimeout(ctx, trafficProbeTimeout)
	defer cancel()

	outcome, err := d.prober.Probe(probeCtx, side, hc.Target, trafficProbeTimeout)
	if err != nil {
		// A probe that could not run is not a probe that failed. Reporting it
		// as either would be a claim about the firewall the code has not made.
		res.Passed, allPassed = false, false
		res.Observed = "probe could not be executed"
		res.Error = err.Error()
		return res, allPassed
	}

	res.Observed = describeProbe(outcome)

	if outcome.Reachable != wantReachable {
		res.Passed, allPassed = false, false
		if wantReachable {
			res.Error = fmt.Sprintf("connection from %s to %s failed: %s", side, hc.Target, outcome.Error)
		} else {
			res.Error = fmt.Sprintf("connection from %s to %s succeeded and should not have", side, hc.Target)
		}
		return res, allPassed
	}

	return res, allPassed
}

func describeProbe(p ProbeResult) string {
	if !p.Reachable {
		return fmt.Sprintf("no connection (source %s): %s", orNone(p.SourceAddress), p.Error)
	}
	seen := p.ObservedSource
	if seen == "" {
		seen = "(not reported)"
	}
	return fmt.Sprintf("connected from %s; endpoint observed source %s",
		orNone(p.SourceAddress), seen)
}

func orNone(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

// expectedCIDR extracts the address a plan expects an interface to carry.
//
// Expectations are rendered as "interface eth1 carries CIDR 10.77.0.1/24",
// so the CIDR is the last whitespace-separated token that parses as one.
// Anything that does not parse yields no expectation, and the caller falls back
// to the address the whole project has always treated as canonical.
func expectedCIDR(expectation string) (string, bool) {
	fields := strings.Fields(expectation)
	if len(fields) == 0 {
		return "", false
	}
	last := fields[len(fields)-1]
	if _, err := netip.ParsePrefix(last); err != nil {
		return "", false
	}
	return last, true
}

// interfaceHasAddress reports whether `ip -j addr show` output carries a
// specific CIDR.
//
// The comparison is over parsed fields rather than a substring. `ip` reports
// the address and its prefix length separately, so a substring search for
// "10.77.0.1/24" against real kernel output fails on a correct interface — and
// a substring search for "10.77.0.1" would match 10.77.0.10. Either error turns
// a health check into noise.
func interfaceHasAddress(jsonOutput, cidr string) bool {
	want, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}

	var links []struct {
		AddrInfo []struct {
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(jsonOutput), &links); err != nil {
		return false
	}

	for _, link := range links {
		for _, info := range link.AddrInfo {
			addr, err := netip.ParseAddr(info.Local)
			if err != nil {
				continue
			}
			if addr == want.Addr() && info.Prefixlen == want.Bits() {
				return true
			}
		}
	}
	return false
}
