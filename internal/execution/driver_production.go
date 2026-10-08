package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/VengeTH/THN-Gateway/internal/activation"
)

// ProductionAuth carries the required authorization inputs for production execution.
type ProductionAuth struct {
	Confirmed         bool
	GatesResult       *activation.GateResult
	ManagementSafe    bool
	ManagementProblem string
	PlanID            string
	ObservedDigest    string
	DesiredDigest     string
	AssignmentDigest  string
}

// ProductionDriver represents the execution driver for production Linux hosts (including the Dell server).
//
// By default, live activation is fail-closed: CanApply() reports false until explicitly authorized
// with operator confirmation and all safety gates satisfied.
type ProductionDriver struct {
	mu           sync.RWMutex
	runner       CommandRunner
	authorized   bool
	auth         ProductionAuth
	capabilities Capabilities
	journal      JournalStore
}

func NewProductionDriver() *ProductionDriver {
	return NewProductionDriverWithRunner(NewDefaultCommandRunner(), nil)
}

func NewProductionDriverWithRunner(runner CommandRunner, journal JournalStore) *ProductionDriver {
	if runner == nil {
		runner = NewDefaultCommandRunner()
	}
	return &ProductionDriver{
		runner:  runner,
		journal: journal,
	}
}

func (d *ProductionDriver) Name() string {
	return "production"
}

var _ activation.Applier = (*ProductionDriver)(nil)

// Available reports whether this driver is currently authorized to act.
func (d *ProductionDriver) Available() bool {
	return d.CanApply()
}

// Describe explains this applier for status, inspect, and diagnostics reporting.
func (d *ProductionDriver) Describe() string {
	if d.CanApply() {
		return "production Linux driver: execution.ProductionDriver (authorized)"
	}
	return "production Linux driver: execution.ProductionDriver (fail-closed, requires explicit authorization and all 13 gates)"
}

// Apply satisfies activation.Applier; live activation must be driven through
// Executor.ExecutePlan with full evidence and digests.
func (d *ProductionDriver) Apply(ctx activation.Context) error {
	if !d.CanApply() {
		return ErrProductionActivationDisabled
	}
	return nil
}

// CanApply reports whether this driver is authorized to mutate host state.
// Permanently reports false unless explicitly authorized via Authorize.
func (d *ProductionDriver) CanApply() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.authorized
}

// Authorize performs strict fail-closed validation of all required activation prerequisites.
func (d *ProductionDriver) Authorize(auth ProductionAuth) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !auth.Confirmed {
		d.authorized = false
		return errors.New("production execution requires explicit confirmation (--confirm)")
	}
	if auth.GatesResult == nil || !auth.GatesResult.AllSatisfied {
		d.authorized = false
		var blocking []string
		if auth.GatesResult != nil {
			blocking = auth.GatesResult.Blocking
		}
		return fmt.Errorf("activation safety gates unsatisfied: %s", strings.Join(blocking, ", "))
	}
	if !auth.ManagementSafe {
		d.authorized = false
		return fmt.Errorf("remote management safety cannot be verified: %s", auth.ManagementProblem)
	}
	if auth.PlanID == "" || auth.ObservedDigest == "" ||
		auth.DesiredDigest == "" || auth.AssignmentDigest == "" {
		d.authorized = false
		return errors.New("production authorization requires the plan ID and all three input " +
			"digests (observed, desired, assignment); a driver that is not told what it is " +
			"authorized to apply cannot refuse a plan it was not shown")
	}

	d.authorized = true
	d.auth = auth
	return nil
}

func (d *ProductionDriver) DetectCapabilities(ctx context.Context) (Capabilities, error) {
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

func (d *ProductionDriver) Execute(ctx context.Context, op Operation) error {
	if !d.CanApply() {
		return ErrProductionActivationDisabled
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
		_, _, err := d.runner.Run(ctx, "nft", "delete", "table", "inet", "thn")
		return err

	case OpQDiscApply:
		// The argument vector comes from the shared builder in
		// internal/qos/tc, the same one `thn qos render` uses.
		//
		// It used to be formatted inline here, and the two copies drifted:
		// this one emitted `bandwidth <d>kbit upload <u>kbit` while the
		// renderer emitted `uplink`. Neither is a CAKE option, so both were
		// rejected, and a second hand-written copy of one command is what let
		// that go unnoticed.
		//
		// An error here is a refusal, not a best-effort fallback: an
		// unshaped discipline would install successfully and look healthy.
		args, err := o.Args()
		if err != nil {
			return fmt.Errorf("refusing to apply traffic control: %w", err)
		}
		_, _, err = d.runner.Run(ctx, "tc", args...)
		return err

	case OpQDiscReplace:
		// Restoring a captured baseline. The spec was validated structurally
		// by splitTCSpec when it was captured, and again by Validate.
		args, err := splitTCSpec(o.Spec)
		if err != nil {
			return fmt.Errorf("refusing to restore the captured qdisc: %w", err)
		}
		_, _, err = d.runner.Run(ctx, "tc", args...)
		return err

	case OpTCStateRestore:
		return RestoreTcBaseline(ctx, d.runner, o.Baseline)

	case OpQDiscDelete:
		_, _, err := d.runner.Run(ctx, "tc", "qdisc", "del", "dev", o.Interface, "root")
		return err

	case OpTCClassApply:
		args, err := o.Args()
		if err != nil {
			return fmt.Errorf("refusing to apply tc class: %w", err)
		}
		_, _, err = d.runner.Run(ctx, "tc", args...)
		return err

	case OpTCClassDelete:
		_, _, err := d.runner.Run(ctx, "tc", "class", "del", "dev", o.Interface, "classid", o.ClassID)
		return err

	case OpTCFilterApply:
		args, err := o.Args()
		if err != nil {
			return fmt.Errorf("refusing to apply tc filter: %w", err)
		}
		_, _, err = d.runner.Run(ctx, "tc", args...)
		return err

	case OpTCFilterDelete:
		_, _, err := d.runner.Run(ctx, "tc", "filter", "del", "dev", o.Interface, "parent", o.Parent, "prio", strconv.Itoa(o.Prio))
		return err

	case OpDNSApply:
		// Refused rather than ignored.
		//
		// This used to return nil, which the transaction recorded as a
		// successfully applied operation and then committed. A plan that
		// asked for a resolver set would have produced an apply log full of
		// successes and a host that resolved exactly as it did before.
		//
		// OpDNSApply now also requires a "dns" capability that no driver
		// reports, so the executor blocks before BACKUP. Returning an error
		// here as well means the refusal survives any future caller that
		// reaches Execute without going through that check.
		return fmt.Errorf("%w: applying resolvers %s requires a DNS service, which THN's "+
			"production execution layer does not implement; this subsystem is left "+
			"unapplied rather than falsely reported as applied",
			ErrCapabilityMissing, strings.Join(o.Servers, ", "))

	default:
		return fmt.Errorf("unknown operation type: %T", op)
	}
}

// applyTHNTable installs table inet thn, ensuring ownership boundaries:
// only table inet thn is ever created or flushed. Foreign tables (Docker, Tailscale) are untouched.
func (d *ProductionDriver) applyTHNTable(ctx context.Context, o OpNFTApplyTHNTable) error {
	run := func(args ...string) error {
		_, _, err := d.runner.Run(ctx, "nft", args...)
		return err
	}

	if err := run("add", "table", "inet", "thn"); err != nil {
		return err
	}
	// Flush ONLY table inet thn. Broad `nft flush ruleset` is forbidden.
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
		forward := []string{"add", "rule", "inet", "thn", "forward",
			"iifname", o.LANInterface, "oifname", o.WANInterface}
		if o.LANSubnet != "" {
			forward = append(forward, "ip", "saddr", o.LANSubnet)
		}
		forward = append(forward, "accept")
		if err := run(forward...); err != nil {
			return err
		}

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

	if len(o.QoSClassificationRules) > 0 {
		if err := run("add", "chain", "inet", "thn", "qos_prerouting",
			"{", "type", "filter", "hook", "prerouting", "priority", "mangle", ";", "policy", "accept", ";", "}"); err != nil {
			return err
		}
		// Management traffic protection: SSH port 22 and Tailscale port 41641 to/from the local host.
		// Using fib daddr/saddr local ensures arbitrary transit LAN traffic to external port 22
		// cannot spoof the management exemption and bypass client shaping limits.
		_ = run("add", "rule", "inet", "thn", "qos_prerouting", "tcp", "dport", "22", "fib", "daddr", "type", "local", "meta", "mark", "set", "0x1", "return")
		_ = run("add", "rule", "inet", "thn", "tcp", "sport", "22", "fib", "saddr", "type", "local", "meta", "mark", "set", "0x1", "return")
		_ = run("add", "rule", "inet", "thn", "qos_prerouting", "udp", "dport", "41641", "fib", "daddr", "type", "local", "meta", "mark", "set", "0x1", "return")
		_ = run("add", "rule", "inet", "thn", "qos_prerouting", "udp", "sport", "41641", "fib", "saddr", "type", "local", "meta", "mark", "set", "0x1", "return")
		_ = run("add", "rule", "inet", "thn", "qos_prerouting", "iifname", "tailscale0", "meta", "mark", "set", "0x1", "return")
		_ = run("add", "rule", "inet", "thn", "qos_prerouting", "oifname", "tailscale0", "meta", "mark", "set", "0x1", "return")

		for _, rule := range o.QoSClassificationRules {
			if rule.ClientIP != "" && rule.MarkHex != "" {
				_ = run("add", "rule", "inet", "thn", "qos_prerouting", "ip", "saddr", rule.ClientIP, "meta", "mark", "set", rule.MarkHex)
				_ = run("add", "rule", "inet", "thn", "qos_prerouting", "ip", "daddr", rule.ClientIP, "meta", "mark", "set", rule.MarkHex)
			}
		}
	}

	return nil
}

func (d *ProductionDriver) CaptureState(ctx context.Context, scope BackupScope) (*StateSnapshot, error) {
	snap := NewStateSnapshot()

	// 1. Links
	for _, iface := range scope.Interfaces {
		stdout, _, err := d.runner.Run(ctx, "ip", "-j", "link", "show", iface)
		if err == nil && stdout != "" {
			var links []struct {
				Flags []string `json:"flags"`
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

	// 6. Traffic control.
	//
	// Absent before this, on both drivers. See the identical section in
	// linux_driver.go: the snapshot carried a QDiscs field, MatchesBaseline
	// compared it, and nothing ever populated it.
	if scope.QDiscs {
		for _, iface := range scope.Interfaces {
			baseline := CaptureTcBaseline(ctx, d, iface)
			snap.QDiscs[iface] = baseline
		}
		snap.MarkCaptured("qdiscs")
	}

	return snap, nil
}

// RunTCOutput runs a read-only tc query. See linux_driver.go for why the
// capability is narrower than the tc allowlist.
func (d *ProductionDriver) RunTCOutput(ctx context.Context, args ...string) (string, error) {
	switch {
	case len(args) >= 2 && args[0] == "qdisc" && (args[1] == "show" || args[1] == "list"):
	case len(args) >= 2 && args[0] == "class" && (args[1] == "show" || args[1] == "list"):
	case len(args) >= 2 && args[0] == "filter" && (args[1] == "show" || args[1] == "list"):
	default:
		return "", fmt.Errorf("RunTCOutput permits only show/list queries, got %v", args)
	}
	stdout, _, err := d.runner.Run(ctx, "tc", args...)
	return stdout, err
}

func (d *ProductionDriver) VerifyHealth(ctx context.Context, checks []HealthCheck) (HealthResult, error) {
	if len(checks) == 0 {
		return HealthResult{
			Healthy:       false,
			FailureReason: "no health checks supplied; gateway state unverified",
		}, nil
	}

	var results []HealthCheckResult
	allPassed := true

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
					Flags []string `json:"flags"`
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
				if interfaceHasAddress(stdout, want) {
					res.Observed = fmt.Sprintf("%s assigned to %s", want, iface)
				} else {
					res.Passed = false
					res.Observed = fmt.Sprintf("%s not found on interface %s", want, iface)
					allPassed = false
				}
			} else {
				res.Observed = "address assigned"
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
			stdout, _, err := d.runner.Run(ctx, "nft", "list", "table", "inet", "thn")
			if err != nil || !strings.Contains(stdout, "masquerade") {
				res.Passed = false
				res.Observed = "masquerade rule absent"
				allPassed = false
			} else {
				res.Observed = "masquerade rule active"
			}

		default:
			res.Passed = false
			res.Observed = "check unsupported in production driver"
			res.Error = fmt.Sprintf("unsupported health check %q", hc.Check)
			allPassed = false
		}

		results = append(results, res)
	}

	failReason := ""
	if !allPassed {
		failReason = "one or more health checks failed against production host state"
	}

	return HealthResult{
		Healthy:       allPassed,
		Checks:        results,
		FailureReason: failReason,
	}, nil
}
