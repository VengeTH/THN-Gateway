package appliance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/appliance"
)

var at = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// imageRoot builds a fake appliance root on disk.
func imageRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	for path, body := range map[string]string{
		"usr/bin/thn":           "#!/bin/sh\necho thn\n",
		"etc/thn/config.yaml":   "gateway:\n  name: site-001\n",
		"etc/thn/dnsmasq.conf":  "# dnsmasq\n",
		"etc/thn/firewall.nft":  "#!/usr/sbin/nft -f\n",
		"etc/thn/qos.sh":        "#!/bin/sh\n",
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

func manifestFor(t *testing.T, root string) appliance.Manifest {
	t.Helper()
	m, err := appliance.Build(root, appliance.DefaultFiles())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return m
}

// -------------------------------------------------------- manifest integrity

// A clean image must verify. If this fails, everything above it is untestable.
func TestAFreshlyBuiltImageVerifies(t *testing.T) {
	root := imageRoot(t)
	m := manifestFor(t, root)

	if err := m.Verify(); err != nil {
		t.Fatalf("a freshly built manifest does not verify against itself: %v", err)
	}

	r := appliance.Verify(root, m, appliance.Options{}, at)
	if !r.OK {
		t.Fatalf("a freshly built image did not verify: %+v", r.Findings)
	}
	if r.Checked != len(m.Entries) {
		t.Errorf("Checked = %d, want %d", r.Checked, len(m.Entries))
	}
}

// The whole point of a manifest: a changed file is detected.
func TestAChangedFileIsDetected(t *testing.T) {
	root := imageRoot(t)
	m := manifestFor(t, root)

	if err := os.WriteFile(filepath.Join(root, "etc", "thn", "config.yaml"),
		[]byte("gateway:\n  name: evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := appliance.Verify(root, m, appliance.Options{}, at)
	if r.OK {
		t.Fatal("a changed configuration file was not detected")
	}
	if !hasKind(r, appliance.FindingChanged) {
		t.Errorf("no changed finding: %+v", r.Findings)
	}
	if !strings.Contains(reasonFor(r, appliance.FindingChanged), "configuration") {
		t.Errorf("the finding does not say what the file is for: %s",
			reasonFor(r, appliance.FindingChanged))
	}
}

func TestAMissingFileIsDetected(t *testing.T) {
	root := imageRoot(t)
	m := manifestFor(t, root)

	if err := os.Remove(filepath.Join(root, "etc", "thn", "firewall.nft")); err != nil {
		t.Fatal(err)
	}

	r := appliance.Verify(root, m, appliance.Options{}, at)
	if r.OK {
		t.Fatal("a missing file was not detected")
	}
	if !hasKind(r, appliance.FindingMissing) {
		t.Errorf("no missing finding: %+v", r.Findings)
	}
}

// A manifest whose entries were altered must be refused before any file is
// checked. Verifying against altered entries would report every altered file
// as changed, sending the operator after the wrong files.
func TestAnAlteredManifestIsRefusedBeforeFileChecks(t *testing.T) {
	root := imageRoot(t)
	m := manifestFor(t, root)

	// Change an entry and leave the digest alone, as an attacker would.
	for i := range m.Entries {
		if strings.Contains(m.Entries[i].Path, "config.yaml") {
			m.Entries[i].Digest = strings.Repeat("0", 64)
		}
	}

	r := appliance.Verify(root, m, appliance.Options{}, at)
	if r.OK {
		t.Fatal("an altered manifest verified")
	}
	if r.Checked != 0 {
		t.Errorf("Checked = %d; files were checked against an untrusted manifest", r.Checked)
	}
	if !strings.Contains(reasonFor(r, appliance.FindingChanged), "manifest") {
		t.Errorf("the finding does not name the manifest: %s",
			reasonFor(r, appliance.FindingChanged))
	}
}

// The manifest arrives from somewhere. A path that climbs out of the image
// root would make the verifier report on files the image never contained.
func TestPathsThatEscapeTheRootAreRefused(t *testing.T) {
	root := imageRoot(t)

	_, err := appliance.Build(root, []appliance.File{
		{Path: "../../etc/shadow", Role: "an escape attempt"},
	})
	if err == nil {
		t.Fatal("a path escaping the image root was accepted into a manifest")
	}
	if !strings.Contains(err.Error(), "escapes") {
		t.Errorf("the refusal does not say what is wrong: %v", err)
	}
}

// Permission changes are a different problem from content changes and must be
// reported differently: a world-writable config is not a corrupted config.
func TestModeChangesAreDetectedSeparatelyWhenAsked(t *testing.T) {
	root := imageRoot(t)
	m := manifestFor(t, root)

	target := filepath.Join(root, "etc", "thn", "config.yaml")

	// Windows does not model Unix permission bits: os.Chmod succeeds and
	// changes only the read-only flag, so the mode round-trips unchanged and
	// the test would report a defect that is not there.
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Skipf("cannot change modes on this filesystem: %v", err)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() == before.Mode().Perm() {
		t.Skipf("this filesystem does not preserve permission bits")
	}

	off := appliance.Verify(root, m, appliance.Options{}, at)
	if !off.OK {
		t.Error("mode checking is off by default and should not have produced a finding")
	}

	on := appliance.Verify(root, m, appliance.Options{CheckMode: true}, at)
	if on.OK {
		t.Fatal("a world-writable configuration was not detected with CheckMode on")
	}
	if !hasKind(on, appliance.FindingMode) {
		t.Errorf("no mode finding: %+v", on.Findings)
	}
}

// An extra file is how an addition to a running system shows up. Off by
// default because it costs a directory listing and has its own false positives.
func TestUnexpectedFilesAreFoundOnlyWhenAsked(t *testing.T) {
	root := imageRoot(t)
	m := manifestFor(t, root)

	if err := os.WriteFile(filepath.Join(root, "etc", "thn", "backdoor.sh"),
		[]byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if r := appliance.Verify(root, m, appliance.Options{}, at); !r.OK {
		t.Error("an unexpected file was reported with scanning off")
	}

	on := appliance.Verify(root, m, appliance.Options{ScanForUnexpected: true}, at)
	if on.OK {
		t.Fatal("an undeclared file was not detected with scanning on")
	}
	if !hasKind(on, appliance.FindingUnexpected) {
		t.Errorf("no unexpected finding: %+v", on.Findings)
	}
}

// ------------------------------------------------------------------- slots

func TestStagingTheActiveSlotIsRefused(t *testing.T) {
	tbl := appliance.NewSlotTable()
	now := at

	if err := tbl.Stage(appliance.SlotA, "img-a"); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Activate(appliance.SlotA, now); err != nil {
		t.Fatal(err)
	}

	// Overwriting the slot that is currently executing is how an upgrade bricks
	// a device mid-write.
	if err := tbl.Stage(appliance.SlotA, "img-a2"); err == nil {
		t.Fatal("the running slot was staged over")
	}
	if err := tbl.Stage(appliance.SlotB, "img-b"); err != nil {
		t.Errorf("staging the idle slot was refused: %v", err)
	}
}

// A slot that fails every boot must stop being retried. Retrying forever burns
// the other slot's attempts and turns one bad image into two unusable slots.
func TestASlotThatKeepsFailingIsMarkedFailed(t *testing.T) {
	tbl := appliance.NewSlotTable()
	if err := tbl.Stage(appliance.SlotA, "img-a"); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Activate(appliance.SlotA, at); err != nil {
		t.Fatal(err)
	}

	var lastErr error
	for i := 0; i < appliance.MaxBootAttempts; i++ {
		lastErr = tbl.BootFailed(appliance.SlotA, "kernel panic", at)
	}
	if lastErr == nil {
		t.Fatal("a slot that never boots was not marked failed")
	}

	s, _ := tbl.Get(appliance.SlotA)
	if s.State != appliance.SlotFailed {
		t.Errorf("State = %s, want failed", s.State)
	}
	if s.Usable() {
		t.Error("a failed slot reports itself usable")
	}
	if err := tbl.Activate(appliance.SlotA, at); err == nil {
		t.Error("a failed slot was activated")
	}
}

// A failed slot must not be offered as a fallback however good it looks.
func TestAFailedSlotIsNotAFallback(t *testing.T) {
	tbl := appliance.NewSlotTable()
	if err := tbl.Stage(appliance.SlotA, "img-a"); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Stage(appliance.SlotB, "img-b"); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Activate(appliance.SlotA, at); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < appliance.MaxBootAttempts; i++ {
		_ = tbl.BootFailed(appliance.SlotB, "will not boot", at)
	}

	if alt, ok := tbl.FallbackTo(appliance.SlotA); ok {
		t.Errorf("slot %s was offered as a fallback having failed every boot", alt)
	}
}

// A slot that has booted before is a slot known to run on this hardware.
func TestFallbackPrefersASlotThatHasBooted(t *testing.T) {
	tbl := appliance.NewSlotTable()
	if err := tbl.Stage(appliance.SlotA, "img-a"); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Stage(appliance.SlotB, "img-b"); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Activate(appliance.SlotA, at); err != nil {
		t.Fatal(err)
	}
	if err := tbl.BootSucceeded(appliance.SlotB); err != nil {
		t.Fatal(err)
	}

	alt, ok := tbl.FallbackTo(appliance.SlotA)
	if !ok {
		t.Fatal("no fallback was offered")
	}
	if alt != appliance.SlotB {
		t.Errorf("fallback = %s, want the slot that has booted", alt)
	}
}

// ------------------------------------------------------------------- boot

// The central decision. A tampered image must not serve the data plane.
func TestATamperedImageDoesNotServeTheDataPlane(t *testing.T) {
	tbl := appliance.NewSlotTable()
	// Both slots hold an image, so a fallback exists to name.
	_ = tbl.Stage(appliance.SlotA, "img-a")
	_ = tbl.Stage(appliance.SlotB, "img-b")
	_ = tbl.Activate(appliance.SlotB, at)

	d := appliance.Decide(appliance.BootInput{
		Verification: appliance.Report{OK: false, Findings: []appliance.Finding{{
			Path: "usr/bin/thn", Kind: appliance.FindingChanged,
			Reason: "the THN binary does not match the image",
		}}},
		Slots:   tbl,
		Running: appliance.SlotB,
	}, at)

	if d.ServesDataPlane() {
		t.Fatal("a tampered image was allowed to serve traffic")
	}
	if d.Mode != appliance.ModeRescue {
		t.Errorf("Mode = %s, want rescue", d.Mode)
	}
	if d.FallbackTo == "" {
		t.Error("no fallback was named although slot a holds an image")
	}
}

// A device that refuses to serve AND refuses to be talked to has turned a
// configuration problem into a site visit. Management always survives.
func TestManagementSurvivesEveryMode(t *testing.T) {
	for _, v := range []appliance.Report{
		{OK: true},
		{OK: false},
	} {
		d := appliance.Decide(appliance.BootInput{
			Verification: v, Slots: appliance.NewSlotTable(), Running: appliance.SlotA,
		}, at)
		if !d.ServesManagement() {
			t.Errorf("mode %s took management down", d.Mode)
		}
	}
}

// A correct image with a dead service serves management but not traffic.
func TestADeadServiceStopsTheDataPlaneButNotManagement(t *testing.T) {
	d := appliance.Decide(appliance.BootInput{
		Verification: appliance.Report{OK: true},
		Health: &appliance.HealthSummary{
			Services: map[string]bool{"dnsmasq": false, "firewall": true},
		},
		Slots: appliance.NewSlotTable(), Running: appliance.SlotA,
	}, at)

	if d.Mode != appliance.ModeSafe {
		t.Errorf("Mode = %s, want safe", d.Mode)
	}
	if d.ServesDataPlane() {
		t.Error("a gateway missing DHCP was allowed to forward traffic")
	}
	if !strings.Contains(d.Reason, "dnsmasq") {
		t.Errorf("the reason does not name the service: %s", d.Reason)
	}
}

// A service that could not be checked is not a service that is down. Refusing
// to serve because nobody could ask turns every monitoring outage into an
// outage.
func TestUnobservableServicesDoNotStopTheDataPlane(t *testing.T) {
	d := appliance.Decide(appliance.BootInput{
		Verification: appliance.Report{OK: true},
		Health: &appliance.HealthSummary{
			Services:     map[string]bool{"dnsmasq": true, "firewall": true},
			Unobservable: []string{"qos"},
		},
		Slots: appliance.NewSlotTable(), Running: appliance.SlotA,
	}, at)

	if !d.ServesDataPlane() {
		t.Errorf("an unobservable service stopped the data plane: %s", d.Reason)
	}
	if !strings.Contains(d.Reason, "unverified") {
		t.Errorf("the decision does not record that something is unverified: %s", d.Reason)
	}
}

// The image check dominates: a dhcpd reported healthy by a tampered binary is
// not a healthy dhcpd.
func TestAServiceCheckCannotOverrideAFailedImage(t *testing.T) {
	d := appliance.Decide(appliance.BootInput{
		Verification: appliance.Report{OK: false},
		Health: &appliance.HealthSummary{
			Services: map[string]bool{"dnsmasq": true, "firewall": true},
		},
		Slots: appliance.NewSlotTable(), Running: appliance.SlotA,
	}, at)

	if d.Mode != appliance.ModeRescue {
		t.Errorf("Mode = %s; healthy services must not rescue a tampered image", d.Mode)
	}
}

func TestACleanSystemRunsNormally(t *testing.T) {
	d := appliance.Decide(appliance.BootInput{
		Verification: appliance.Report{OK: true},
		Health: &appliance.HealthSummary{
			Services: map[string]bool{"dnsmasq": true, "firewall": true},
		},
		Slots: appliance.NewSlotTable(), Running: appliance.SlotA,
	}, at)

	if !d.ServesDataPlane() {
		t.Errorf("a clean system did not serve the data plane: %s", d.Reason)
	}
	if d.Reason == "" {
		t.Error("the decision carries no reason")
	}
}

// Every mode must render something an operator can act on.
func TestEveryDecisionRenders(t *testing.T) {
	for _, in := range []appliance.BootInput{
		{Verification: appliance.Report{OK: true}, Slots: appliance.NewSlotTable()},
		{Verification: appliance.Report{OK: false, Findings: []appliance.Finding{{Path: "x"}}},
			Slots: appliance.NewSlotTable()},
		{Verification: appliance.Report{OK: true},
			Health: &appliance.HealthSummary{Services: map[string]bool{"a": false}},
			Slots:  appliance.NewSlotTable()},
	} {
		d := appliance.Decide(in, at)
		out := appliance.Render(d)
		if !strings.Contains(out, "Mode:") || !strings.Contains(out, "Management:") {
			t.Errorf("mode %s rendered without its essentials:\n%s", d.Mode, out)
		}
		if strings.TrimSpace(d.Reason) == "" {
			t.Errorf("mode %s has no reason", d.Mode)
		}
	}
}

// The filesystem root is the case an appliance actually verifies against, and
// it is where a naive prefix check breaks: Clean("/") is the separator alone on
// Windows, so "root + separator" is a doubled separator nothing begins with.
func TestTheFilesystemRootIsAUsableImageRoot(t *testing.T) {
	root := imageRoot(t)

	// Re-root the fake image at "/"-shaped form by verifying from a root whose
	// cleaned form is exactly the separator.
	if _, err := appliance.Build(string(os.PathSeparator), appliance.DefaultFiles()); err != nil {
		// The real filesystem root will not contain the declared files, so the
		// error that matters is the escape refusal, not a missing file.
		if !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("verifying against the filesystem root was refused for the wrong reason: %v", err)
		}
		t.Fatalf("the filesystem root was rejected as an image root")
	}

	// The same check that refuses traversal must accept an ordinary path under
	// a root that happens to be the separator.
	m := manifestFor(t, root)
	r := appliance.Verify(root, m, appliance.Options{}, at)
	if !r.OK {
		t.Errorf("an ordinary root stopped working after the change: %+v", r.Findings)
	}
}

// Every declaration must be usable relative to whatever root it is given, so
// the default file list cannot contain a path that only works somewhere.
func TestEveryDefaultFilePathIsValid(t *testing.T) {
	root := imageRoot(t)
	for _, f := range appliance.DefaultFiles() {
		if strings.HasPrefix(f.Path, "/") {
			t.Errorf("%s is absolute; manifest paths are relative to the root", f.Path)
		}
		if strings.Contains(f.Path, "..") {
			t.Errorf("%s contains a parent-directory segment", f.Path)
		}
		if f.Role == "" {
			t.Errorf("%s has no role, so a finding about it cannot be acted on", f.Path)
		}
	}
	if _, err := appliance.Build(root, appliance.DefaultFiles()); err != nil {
		t.Fatalf("the default file list does not build: %v", err)
	}
}

// A verification that checked nothing must never be reported as a pass.
//
// This is the vacuous-check failure the rest of this project keeps arguing
// against, and the first version of this package had it: run against a root
// with none of the declared files in it, it reported "the filesystem matches
// the image" having verified zero files. A wrong --root would have produced the
// most reassuring possible wrong answer.
func TestAVerificationThatCheckedNothingIsNotAPass(t *testing.T) {
	root := imageRoot(t)

	// A manifest built from a root that has none of the declared files.
	empty := t.TempDir()
	m, err := appliance.Build(empty, appliance.DefaultFiles())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 0 {
		t.Fatalf("setup: expected an empty manifest, got %d entries", len(m.Entries))
	}

	r := appliance.Verify(root, m, appliance.Options{}, at)
	if r.OK {
		t.Fatal("a verification that checked zero files reported success")
	}
	if r.Checked != 0 {
		t.Errorf("Checked = %d, want 0", r.Checked)
	}
	if !strings.Contains(reasonFor(r, appliance.FindingChanged), "wrong root") {
		t.Errorf("the finding does not name the likely cause:\n%s",
			reasonFor(r, appliance.FindingChanged))
	}

	// And the boot decision must not treat it as a clean image either.
	d := appliance.Decide(appliance.BootInput{
		Verification: r, Slots: appliance.NewSlotTable(), Running: appliance.SlotA,
	}, at)
	if d.ServesDataPlane() {
		t.Error("a gateway with nothing verified was allowed to serve traffic")
	}
}

func hasKind(r appliance.Report, k appliance.FindingKind) bool {
	for _, f := range r.Findings {
		if f.Kind == k {
			return true
		}
	}
	return false
}

func reasonFor(r appliance.Report, k appliance.FindingKind) string {
	for _, f := range r.Findings {
		if f.Kind == k {
			return f.Reason
		}
	}
	return ""
}
