package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/appliance"
	"github.com/venth/thn-gateway/internal/authority"
)

// This file is the gate phase for the appliance image.
//
// # What is new here
//
// Every other safety property in this project is about what THN will not do.
// internal/guard keeps THN from mutating a host; internal/authority keeps a
// control plane from mutating a fleet; internal/reconcile keeps a gateway from
// removing its own management path.
//
// None of them is about whether THN is the code that was shipped. A binary that
// has been replaced satisfies all of them, because every one of them is a
// statement about behaviour and this one is a statement about identity.
//
// So the gate holds that property too. It is the one check in the repository
// that would notice a compromised image rather than a compromised caller.

// applianceRoot builds a fake image root on disk.
func applianceRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for path, body := range map[string]string{
		"usr/bin/thn":           "binary\n",
		"etc/thn/config.yaml":   "gateway:\n  name: site-001\n",
		"etc/thn/dnsmasq.conf":  "# dnsmasq\n",
		"etc/thn/firewall.nft":  "# nft\n",
		"etc/thn/qos.sh":        "# tc\n",
		"etc/thn/manifest.json": "{}\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// The command must not be able to do anything to the device.
func TestGateApplianceCommandIsPure(t *testing.T) {
	cmd, ok := commands["appliance"]
	if !ok {
		t.Fatal("the appliance command is not registered")
	}
	if cmd.Tier != TierPure {
		t.Errorf("appliance is %s; describing an image cannot change one", cmd.Tier)
	}

	// It must still be the only destructive command that exists. Packaging a
	// system into an OS is exactly the moment it becomes possible to add one,
	// and this is where that would be noticed.
	var destructive []string
	for name, c := range commands {
		if c.Tier == TierDestructive {
			destructive = append(destructive, name)
		}
	}
	if len(destructive) != 1 || destructive[0] != "activate" {
		t.Errorf("destructive commands are %v, want exactly [activate]", destructive)
	}

	// Adding a device manifest must not create a route to changing a host.
	assertActivationRemainsGated(t, "adding an appliance manifest")
}

// There must be no way to rewrite the manifest from the command line. A device
// that can regenerate its own manifest is a device whose manifest means
// nothing, and the verification above it becomes circular.
func TestGateApplianceCommandCannotRewriteAManifest(t *testing.T) {
	source, err := os.ReadFile("appliance.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)

	// Every write in this file would be a way to change the device. There are
	// none, and the count is asserted rather than the absence assumed.
	for _, forbidden := range []string{
		"os.WriteFile", "os.Create", "os.Remove", "os.Rename", "os.Mkdir",
		"ioutil.WriteFile", "os.Chmod", "os.Truncate",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("appliance.go uses %s; the command must not write to the device", forbidden)
		}
	}
}

// A changed binary must be detected. This is the property the whole package
// exists for, asserted at the seam the command uses.
func TestGateApplianceDetectsAReplacedBinary(t *testing.T) {
	root := applianceRoot(t)

	m, err := appliance.Build(root, appliance.DefaultFiles())
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "thn"),
		[]byte("not the binary we shipped\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	report := appliance.Verify(root, m, appliance.Options{}, time.Now().UTC())
	if report.OK {
		t.Fatal("a replaced THN binary was not detected; every other check in this " +
			"repository passes on a compromised image")
	}

	var found bool
	for _, f := range report.Findings {
		if strings.Contains(f.Path, "usr/bin/thn") {
			found = true
		}
	}
	if !found {
		t.Errorf("the replaced binary was not named: %+v", report.Findings)
	}
}

// The boot decision must refuse the data plane on a bad image, and must keep
// management up. A device that takes both down has become a site visit.
func TestGateApplianceBadImageStopsTrafficButNotManagement(t *testing.T) {
	slots := appliance.NewSlotTable()

	d := appliance.Decide(appliance.BootInput{
		Verification: appliance.Report{OK: false, Findings: []appliance.Finding{
			{Path: "usr/bin/thn", Kind: appliance.FindingChanged, Reason: "replaced"},
		}},
		Slots:   slots,
		Running: appliance.SlotA,
	}, time.Now().UTC())

	if d.ServesDataPlane() {
		t.Error("a bad image was allowed to forward traffic")
	}
	if !d.ServesManagement() {
		t.Error("a bad image took management down; that turns a fault into a site visit")
	}
}

// Packaging does not relax the authority floor. An appliance is a different
// delivery mechanism, not a different permission model.
func TestGateApplianceDidNotWeakenTheAuthorityFloor(t *testing.T) {
	p := authority.NewPolicy("permissive")
	for _, op := range []authority.Operation{
		authority.OpShellCommand,
		authority.OpFactoryReset,
		authority.OpDisableFirewall,
	} {
		if got := p.Effective(op); got != authority.TierForbidden {
			t.Errorf("%s is %s; packaging must not have relaxed the floor", op, got)
		}
	}
}

// The command has to actually work, or the gate proves nothing about it.
func TestGateApplianceCommandRuns(t *testing.T) {
	root := applianceRoot(t)

	env, out, errOut := newTestEnv("--root", root)
	if code := runAppliance(env, []string{"manifest", "--root", root}); code != ExitOK {
		t.Errorf("`appliance manifest` exited %d:\n%s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "usr/bin/thn") {
		t.Errorf("the manifest does not list the binary:\n%s", out.String())
	}

	env2, out2, _ := newTestEnv("--root", root)
	runAppliance(env2, []string{"verify", "--root", root})
	if !strings.Contains(out2.String(), "matches the image") {
		t.Errorf("`appliance verify` did not confirm a clean image:\n%s", out2.String())
	}
}
