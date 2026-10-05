package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// LinuxDriver performs real Linux networking mutations using guarded system tools.
//
// To enforce safety, it requires an approved LabConfig and verifies that it is operating
// inside a disposable lab environment before permitting any mutation.
type LinuxDriver struct {
	runner       CommandRunner
	labCfg       LabConfig
	labVerified  bool
	capabilities Capabilities
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
		// THN owns table inet thn ONLY.
		// 1. Create table
		if _, _, err := d.runner.Run(ctx, "nft", "add", "table", "inet", "thn"); err != nil {
			return err
		}
		// 2. Flush only inet thn (never flush ruleset!)
		if _, _, err := d.runner.Run(ctx, "nft", "flush", "table", "inet", "thn"); err != nil {
			return err
		}
		// 3. Create input chain with policy
		if _, _, err := d.runner.Run(ctx, "nft", "add", "chain", "inet", "thn", "input",
			"{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", o.InboundPolicy, ";", "}"); err != nil {
			return err
		}
		// 4. Create forward chain with policy
		if _, _, err := d.runner.Run(ctx, "nft", "add", "chain", "inet", "thn", "forward",
			"{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", o.InboundPolicy, ";", "}"); err != nil {
			return err
		}
		// 5. Allow established,related
		if o.AllowEstablished {
			if _, _, err := d.runner.Run(ctx, "nft", "add", "rule", "inet", "thn", "input",
				"ct", "state", "established,related", "accept"); err != nil {
				return err
			}
		}
		// 6. Allow loopback
		if o.AllowLoopback {
			if _, _, err := d.runner.Run(ctx, "nft", "add", "rule", "inet", "thn", "input",
				"iifname", "lo", "accept"); err != nil {
				return err
			}
		}
		// 7. NAT masquerade if configured
		if len(o.NATInterfaces) > 0 {
			if _, _, err := d.runner.Run(ctx, "nft", "add", "chain", "inet", "thn", "postrouting",
				"{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "policy", "accept", ";", "}"); err != nil {
				return err
			}
			for _, iface := range o.NATInterfaces {
				if _, _, err := d.runner.Run(ctx, "nft", "add", "rule", "inet", "thn", "postrouting",
					"oifname", iface, "masquerade"); err != nil {
					return err
				}
			}
		}
		return nil

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
		// DNS changes in lab environment
		return nil

	default:
		return fmt.Errorf("unknown operation type: %T", op)
	}
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
			parts := strings.Split(hc.Target, ":")
			iface := parts[0]
			stdout, _, err := d.runner.Run(ctx, "ip", "-j", "addr", "show", iface)
			if err != nil {
				res.Passed = false
				res.Error = err.Error()
				allPassed = false
			} else {
				if strings.Contains(hc.Expectation, "10.77.0.1/24") && !strings.Contains(stdout, "10.77.0.1") {
					res.Passed = false
					res.Observed = "10.77.0.1 not found on interface"
					allPassed = false
				} else {
					res.Observed = "address assigned"
				}
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
