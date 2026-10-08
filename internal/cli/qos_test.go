package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/config"
)

// qosConfigFile writes a configuration with QoS enabled and returns its path.
func qosConfigFile(t *testing.T, enabled bool, algorithm string, down, up int) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	body := "schema_version: 1\n" +
		"gateway:\n" +
		"  name: thn-test\n" +
		"  generation: 1\n" +
		"network:\n" +
		"  wan: eth0\n" +
		"  lan: eth1\n" +
		"  lan_prefix: 10.77.0.1/24\n" +
		"  mtu: 1500\n" +
		"paths:\n" +
		"  state_db: " + filepath.ToSlash(filepath.Join(dir, "state.db")) + "\n" +
		"qos:\n" +
		"  enabled: " + boolText(enabled) + "\n" +
		"  algorithm: " + algorithm + "\n" +
		"  interface: eth0\n" +
		"  download_kbps: " + itoa(down) + "\n" +
		"  upload_kbps: " + itoa(up) + "\n"

	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

// boolText renders a bool for YAML.
func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// itoa renders an int for YAML.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// runCLI executes a command line and captures its output.
//
// The buffers are read after Run returns. Returning out.String() inline would
// evaluate it before the command had written anything, so every assertion
// would see an empty buffer and the test would pass for the wrong reason.
func runCLI(t *testing.T, args ...string) (string, string, ExitCode) {
	t.Helper()

	var out, errBuf bytes.Buffer
	env := &Env{
		Stdout: &out,
		Stderr: &errBuf,
		Args:   args,
		Getenv: func(string) string { return "" },
		Getwd:  func() (string, error) { return t.TempDir(), nil },
	}

	code := Run(env)

	return out.String(), errBuf.String(), code
}

// TestQoSIsRegisteredAsPure is a safety assertion, not a convenience one.
//
// Every command declares a tier, and the tier is what tells a reader which
// commands are safe to run unattended against an unreachable gateway. A
// command that touches host networking while claiming to be pure is exactly
// the failure this project is built to make impossible.
func TestQoSIsRegisteredAsPure(t *testing.T) {
	cmd, ok := commands["qos"]
	if !ok {
		t.Fatal("the qos command is not registered")
	}
	if cmd.Tier != TierPure {
		t.Errorf("qos tier = %q, want pure", cmd.Tier)
	}
}

// TestQoSWithoutASubcommandIsAUsageError.
func TestQoSWithoutASubcommandIsAUsageError(t *testing.T) {
	_, errOut, code := runCLI(t, "qos")

	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	for _, want := range []string{"render", "validate", "stats", "available"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("the usage message does not list %q", want)
		}
	}
}

// TestQoSUnknownSubcommandIsRejected.
func TestQoSUnknownSubcommandIsRejected(t *testing.T) {
	_, _, code := runCLI(t, "qos", "apply")

	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
}

// TestQoSValidateWithCakeAssumed is the ordinary path.
func TestQoSValidateWithCakeAssumed(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 100_000, 20_000)

	stdout, _, code := runCLI(t, "qos", "validate", "--config", cfgPath, "--assume-cake")

	if code != ExitOK {
		t.Errorf("exit = %d, want 0; stdout:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "cake") {
		t.Errorf("output does not name the selected algorithm:\n%s", stdout)
	}
}

// TestQoSValidateReportsTheFallback is the case the design exists for. Without
// cake, the operator must be told — in the output and in the exit code.
func TestQoSValidateReportsTheFallback(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 100_000, 20_000)

	stdout, _, code := runCLI(t, "qos", "validate", "--config", cfgPath)

	if code != ExitProblems {
		t.Errorf("exit = %d, want %d; a degraded policy must be visible to CI", code, ExitProblems)
	}
	if !strings.Contains(stdout, "DEGRADED") {
		t.Errorf("output does not mark the degradation:\n%s", stdout)
	}
	if !strings.Contains(stdout, "fq_codel") {
		t.Errorf("output does not name what will actually be applied:\n%s", stdout)
	}
}

// TestQoSValidateRejectsAnInvalidPolicyAndSaysWhy.
func TestQoSValidateRejectsAnInvalidPolicyAndSaysWhy(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 0, 0)

	stdout, _, code := runCLI(t, "qos", "validate", "--config", cfgPath, "--assume-cake")

	if code != ExitProblems {
		t.Errorf("exit = %d, want %d", code, ExitProblems)
	}
	if !strings.Contains(stdout, "FAIL") {
		t.Errorf("output does not report failure:\n%s", stdout)
	}
}

// TestQoSRenderRefusesAnInvalidPolicy is the important one: a render is the
// artefact an operator applies, so producing one from a policy known to be
// wrong would hand them a command that throttles their link.
func TestQoSRenderRefusesAnInvalidPolicy(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 0, 0)

	stdout, errOut, code := runCLI(t, "qos", "render", "--config", cfgPath, "--assume-cake")

	if code != ExitProblems {
		t.Errorf("exit = %d, want %d", code, ExitProblems)
	}
	if strings.Contains(stdout, "tc qdisc replace") {
		t.Errorf("a command was rendered from an invalid policy:\n%s", stdout)
	}
	if !strings.Contains(errOut, "not rendering") {
		t.Errorf("the refusal is not explained:\n%s", errOut)
	}
	if !strings.Contains(errOut, "--no-validate") {
		t.Errorf("the refusal does not offer the override:\n%s", errOut)
	}
}

// TestQoSRenderProducesTheCommand is the happy path.
func TestQoSRenderProducesTheCommand(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 100_000, 20_000)

	stdout, _, code := runCLI(t, "qos", "render", "--config", cfgPath, "--assume-cake")

	if code != ExitOK {
		t.Errorf("exit = %d, want 0; stdout:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "tc qdisc replace dev eth0 root cake") {
		t.Errorf("no CAKE command was rendered:\n%s", stdout)
	}
	if !strings.Contains(stdout, "bandwidth 22Mbit") {
		t.Errorf("the upload wire rate is wrong; overhead was not applied:\n%s", stdout)
	}
	if !strings.Contains(stdout, "tc qdisc replace dev eth1 root cake bandwidth 110Mbit") {
		t.Errorf("the download discipline was not rendered on LAN egress:\n%s", stdout)
	}
}

// TestQoSRenderNeverAppliesAnything: the whole point of the render is that it
// produces text for review.
func TestQoSRenderNeverAppliesAnything(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 100_000, 20_000)

	stdout, _, _ := runCLI(t, "qos", "render", "--config", cfgPath, "--assume-cake")

	// The removal command appears only as a comment; an uncommented one would
	// mean the script tears down shaping the moment it is applied.
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "pfifo_fast") && !strings.HasPrefix(trimmed, "#") {
			t.Errorf("the teardown command is live, not commented: %q", trimmed)
		}
	}
}

// TestQoSRenderToFileWritesIntoTheSandbox: --root must confine the write, or a
// render aimed at a test directory would land on the host.
func TestQoSRenderToFileWritesIntoTheSandbox(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 100_000, 20_000)
	root := t.TempDir()

	_, _, code := runCLI(t, "qos", "render", "--config", cfgPath, "--assume-cake",
		"--root", root, "--out", "/etc/thn/qos.sh")

	if code != ExitOK {
		t.Fatalf("exit = %d, want 0", code)
	}

	written := filepath.Join(root, "etc", "thn", "qos.sh")
	data, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("the script was not written into the sandbox root: %v", err)
	}
	if !strings.Contains(string(data), "tc qdisc replace dev eth0 root cake") ||
		!strings.Contains(string(data), "tc qdisc replace dev eth1 root cake") {
		t.Errorf("the written script has no command:\n%s", data)
	}
}

// TestQoSRenderRefusesToOverwrite: the file may have been hand-corrected, and
// a render must not discard that silently.
func TestQoSRenderRefusesToOverwrite(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 100_000, 20_000)
	root := t.TempDir()
	target := filepath.Join(root, "qos.sh")

	if err := os.WriteFile(target, []byte("# hand-corrected\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, errOut, code := runCLI(t, "qos", "render", "--config", cfgPath, "--assume-cake",
		"--root", root, "--out", "/qos.sh")

	if code != ExitProblems {
		t.Errorf("exit = %d, want %d", code, ExitProblems)
	}
	if !strings.Contains(errOut, "--force") {
		t.Errorf("the refusal does not mention the override:\n%s", errOut)
	}

	data, _ := os.ReadFile(target)
	if string(data) != "# hand-corrected\n" {
		t.Error("the existing file was overwritten without --force")
	}
}

// TestQoSRenderForceOverwrites.
func TestQoSRenderForceOverwrites(t *testing.T) {
	cfgPath := qosConfigFile(t, true, "cake", 100_000, 20_000)
	root := t.TempDir()
	target := filepath.Join(root, "qos.sh")

	if err := os.WriteFile(target, []byte("# stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, code := runCLI(t, "qos", "render", "--config", cfgPath, "--assume-cake",
		"--root", root, "--out", "/qos.sh", "--force")

	if code != ExitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	data, _ := os.ReadFile(target)
	if !strings.Contains(string(data), "tc qdisc replace") {
		t.Errorf("--force did not replace the file:\n%s", data)
	}
}

// TestQoSRenderDisabledPolicyProducesNoCommand: a gateway with shaping off
// must not have a qdisc script waiting to be applied.
func TestQoSRenderDisabledPolicyProducesNoCommand(t *testing.T) {
	cfgPath := qosConfigFile(t, false, "cake", 0, 0)

	stdout, _, code := runCLI(t, "qos", "render", "--config", cfgPath, "--assume-cake")

	if code != ExitOK {
		t.Errorf("exit = %d, want 0; a disabled policy is not an error", code)
	}
	if strings.Contains(stdout, "tc qdisc replace dev") {
		t.Errorf("a command was rendered for a disabled policy:\n%s", stdout)
	}
}

// TestQoSAvailableReportsWhyItCannotProbe: on a host without privileges the
// command must say so rather than printing a guess.
func TestQoSAvailableReportsWhyItCannotProbe(t *testing.T) {
	stdout, _, _ := runCLI(t, "qos", "available")

	// On Windows this will always be the unavailable path. On Linux with root
	// it may genuinely probe, in which case it must say so instead.
	if strings.Contains(stdout, "Available:  unknown") {
		if !strings.Contains(stdout, "Reason:") {
			t.Errorf("an unknown result must give a reason:\n%s", stdout)
		}
		return
	}
	if strings.Contains(stdout, "network namespace") {
		t.Log("probed inside a namespace; the host was not modified")
	}
}

// TestQoSStatsRequiresAnInterface: reading the wrong interface would report
// another link's queue, so the flag is mandatory rather than defaulted.
func TestQoSStatsRequiresAnInterface(t *testing.T) {
	_, errOut, code := runCLI(t, "qos", "stats")

	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "--interface") {
		t.Errorf("the message does not name the required flag:\n%s", errOut)
	}
}

// TestQoSPolicyFromConfigDerivesTheRightLimits: CAKE's and fq_codel's queue
// parameters are not interchangeable, and using the wrong set costs
// throughput.
func TestQoSPolicyFromConfigDerivesTheRightLimits(t *testing.T) {
	cfg := config.Config{}
	cfg.Network.MTU = 9000

	cfg.QoS.Enabled = true
	cfg.QoS.Algorithm = "cake"
	cfg.QoS.Interface = "eth0"
	cfg.QoS.DownloadKbps = 100_000
	cfg.QoS.UploadKbps = 20_000

	cake := qosPolicyFromConfig(cfg)
	if cake.Limits.Quantum != 1514 {
		t.Errorf("cake quantum = %d, want 1514 (CAKE's own default)", cake.Limits.Quantum)
	}

	cfg.QoS.Algorithm = "fq_codel"
	fq := qosPolicyFromConfig(cfg)
	if fq.Limits.Quantum != 9000 {
		t.Errorf("fq_codel quantum = %d, want 9000 (the interface MTU)", fq.Limits.Quantum)
	}
}

// TestQoSPolicyFromConfigKeepsTheConfiguredRate: the rate is what the
// operator provisioned, and it must reach the policy unchanged.
func TestQoSPolicyFromConfigKeepsTheConfiguredRate(t *testing.T) {
	cfg := config.Config{}
	cfg.Network.MTU = 1500
	cfg.QoS.Enabled = true
	cfg.QoS.Algorithm = "cake"
	cfg.QoS.Interface = "eth0"
	cfg.QoS.DownloadKbps = 123_456
	cfg.QoS.UploadKbps = 7_890

	p := qosPolicyFromConfig(cfg)

	if p.Bandwidth.DownloadKbps != 123_456 {
		t.Errorf("download = %d, want 123456", p.Bandwidth.DownloadKbps)
	}
	if p.Bandwidth.UploadKbps != 7_890 {
		t.Errorf("upload = %d, want 7890", p.Bandwidth.UploadKbps)
	}
}

// TestQoSPolicyFromConfigDefaultsOverhead: an unconfigured overhead field must
// leave the default in place rather than zeroing it, because zero would
// under-shape the link by a tenth.
func TestQoSPolicyFromConfigDefaultsOverhead(t *testing.T) {
	cfg := config.Config{}
	cfg.QoS.Enabled = true
	cfg.QoS.Algorithm = "cake"
	cfg.QoS.DownloadKbps = 100_000
	cfg.QoS.UploadKbps = 20_000

	if got := qosPolicyFromConfig(cfg).Bandwidth.OverheadPercent; got != 10 {
		t.Errorf("overhead = %d, want the 10%% default", got)
	}

	cfg.QoS.OverheadPercent = 8
	if got := qosPolicyFromConfig(cfg).Bandwidth.OverheadPercent; got != 8 {
		t.Errorf("overhead = %d, want 8", got)
	}
}

// TestQoSPolicyFromConfigDisabledClearsTheAlgorithm: a disabled policy must
// not carry a live algorithm, or a later render would apply it.
func TestQoSPolicyFromConfigDisabledClearsTheAlgorithm(t *testing.T) {
	cfg := config.Config{}
	cfg.QoS.Enabled = false
	cfg.QoS.Algorithm = "cake"
	cfg.QoS.DownloadKbps = 100_000

	p := qosPolicyFromConfig(cfg)

	if p.Enabled {
		t.Error("the derived policy is enabled when the configuration is not")
	}
	if p.Algorithm.String() != "none" {
		t.Errorf("algorithm = %q, want none", p.Algorithm)
	}
}
