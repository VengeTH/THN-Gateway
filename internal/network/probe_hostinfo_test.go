package network

// Diagnostic tests for the sysfs read path.
//
// # Why these are an internal test
//
// newHostInfo hard-codes /sys/class/net and shells out to `iw`. Reaching the
// read logic without either would mean testing a copy of it, and a copy is
// not the code an operator's machine runs. sysfsHostInfo takes its root as a
// field precisely so this file can point it at a directory built in t.TempDir
// and exercise the real path building, the real error classification and the
// real probe recording.
//
// The split from probe_test.go is deliberate: that file stays external so it
// can only reach the exported surface, and this one exists only because the
// thing under test is unexported and its behaviour is worth pinning.
//
// # What the fixtures reproduce
//
// A real gateway produces all three of these, which is why each has its own
// case:
//
//	1000     the driver knows and reports a speed
//	-1       the driver does not know — the file exists and declines to answer
//	absent   no file at all, which is normal for virtual links
//
// The middle one is the interesting case and the one that was invisible
// before. An absent speed file and a -1 speed file both produced SpeedMbps: 0
// with no record of which, and they mean different things: the first is
// unremarkable, and the second is the kernel declining to answer a question
// it was asked.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sysfsFixture builds a sysfsHostInfo over a test directory.
//
// modesKnown is FALSE on purpose, so the Wireless Extensions fallback is the
// path under test. That fallback is what a server without `iw` takes — nl80211
// was never consulted — and it is the only path that reads a file, so it is
// the only one that can produce the read-path failures these tests are about.
//
// Setting it true would short-circuit to an empty nl80211 map and return false
// for every interface without touching the filesystem, which is a correct
// answer reached by the wrong route.
func sysfsFixture(t *testing.T, root string) HostInfo {
	t.Helper()
	return &sysfsHostInfo{
		root:       root,
		modes:      map[string]string{},
		modesKnown: false,
		describe:   "sysfs " + root,
	}
}

func mkDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatalf("creating %s: %v", path, err)
	}
}

func mkFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// probeByPath finds the record for one file read.
func probeByPath(t *testing.T, info HostInfo, path string) Probe {
	t.Helper()
	for _, p := range info.Probes() {
		if p.Path == path {
			return p
		}
	}
	t.Fatalf("no probe recorded for %s: %+v", path, info.Probes())
	return Probe{}
}

// TestSysfsSpeedReadsAreEachRecorded is the main case: three reads, three
// different and correct answers.
func TestSysfsSpeedReadsAreEachRecorded(t *testing.T) {
	root := t.TempDir()

	reported := filepath.Join(root, "reported0")
	mkDir(t, reported)
	mkFile(t, filepath.Join(reported, "speed"), "1000\n")

	// The kernel's way of saying "this driver does not report a speed". The
	// file exists and is readable; it declines to answer.
	declined := filepath.Join(root, "declined0")
	mkDir(t, declined)
	mkFile(t, filepath.Join(declined, "speed"), "-1\n")

	// No attribute at all, which is ordinary for a virtual link.
	bare := filepath.Join(root, "bare0")
	mkDir(t, bare)

	info := sysfsFixture(t, root)

	if mbps, ok := info.LinkSpeed("reported0"); !ok || mbps != 1000 {
		t.Fatalf("LinkSpeed(reported0) = %d, %t; want 1000, true", mbps, ok)
	}
	if _, ok := info.LinkSpeed("declined0"); ok {
		t.Error("a -1 speed attribute was reported as a speed")
	}
	if _, ok := info.LinkSpeed("bare0"); ok {
		t.Error("an absent speed attribute was reported as a speed")
	}

	// A read that succeeded is positive evidence.
	got := probeByPath(t, info, filepath.Join(reported, "speed"))
	if got.Outcome != ProbeEvidence {
		t.Errorf("a readable speed reported %q, want %q", got.Outcome, ProbeEvidence)
	}
	if !strings.Contains(got.Detail, "1000 Mbps") {
		t.Errorf("the detail does not name the value observed: %q", got.Detail)
	}

	// A file that was read and declined is a working probe with no evidence.
	// It is NOT a missing file and NOT a failure, and conflating it with
	// either is what made "speed unknown" unanswerable before.
	declineProbe := probeByPath(t, info, filepath.Join(declined, "speed"))
	if declineProbe.Outcome != ProbeNoEvidence {
		t.Errorf("a -1 attribute reported %q, want %q; the file WAS read",
			declineProbe.Outcome, ProbeNoEvidence)
	}
	if !strings.Contains(declineProbe.Reason, "-1") {
		t.Errorf("the kernel's own value was not preserved: %q", declineProbe.Reason)
	}

	// An absent attribute is a different answer again.
	bareProbe := probeByPath(t, info, filepath.Join(bare, "speed"))
	if bareProbe.Outcome != ProbeToolUnavailable {
		t.Errorf("an absent attribute reported %q, want %q",
			bareProbe.Outcome, ProbeToolUnavailable)
	}
}

// TestAnUnknownSpeedIsAlwaysExplained is the guarantee the M7.1 analyzer
// depends on.
//
// Every one of these produced SpeedMbps: 0 with nothing recorded, so "speed
// unknown" arrived at the report unexplained. Each must now leave a record.
func TestAnUnknownSpeedIsAlwaysExplained(t *testing.T) {
	root := t.TempDir()
	mkDir(t, filepath.Join(root, "bare0"))
	info := sysfsFixture(t, root)

	if _, ok := info.LinkSpeed("bare0"); ok {
		t.Fatal("an absent speed attribute was reported as a speed")
	}

	probes := info.Probes()
	if len(probes) != 1 {
		t.Fatalf("recorded %d probes for one read: %+v", len(probes), probes)
	}
	p := probes[0]
	if p.Detail == "" {
		t.Error("the probe does not explain what happened")
	}
	if p.Reason == "" {
		t.Error("the probe carries no cause; an unknown with no reason is the thing this exists to prevent")
	}
	if p.Subsystem != "link-speed" {
		t.Errorf("subsystem = %q, want link-speed", p.Subsystem)
	}
}

// TestUnsafeInterfaceNameIsRecordedAsAThnDecision is the security check's own
// diagnostic.
//
// Refusing to read "../../etc/passwd" is THN's decision. Recorded as a missing
// file it would read as a kernel fact, and an operator investigating why a
// real interface reported no speed would be sent to look at the kernel.
func TestUnsafeInterfaceNameIsRecordedAsAThnDecision(t *testing.T) {
	info := sysfsFixture(t, t.TempDir())

	for _, name := range []string{"../escape", "a/b", ".", "..", ""} {
		if _, ok := info.LinkSpeed(name); ok {
			t.Errorf("the unsafe name %q was accepted", name)
		}
		if _, ok := info.WirelessMode(name); ok {
			t.Errorf("the unsafe name %q was accepted by WirelessMode", name)
		}
	}

	for _, p := range info.Probes() {
		if p.Outcome == ProbeToolUnavailable {
			t.Errorf("a refused name was recorded as a missing file: %+v", p)
		}
		if !strings.Contains(p.Detail, "rejected as unsafe") {
			t.Errorf("the record does not say the refusal was THN's: %q", p.Detail)
		}
		if !strings.Contains(p.Reason, "refused before reading") {
			t.Errorf("the reason does not distinguish a refusal from a kernel failure: %q", p.Reason)
		}
	}
}

// TestWirelessModeIsRecordedPerInterface keeps the per-radio records apart.
//
// A host with several radios produces one record per radio, and a reader
// debugging one of them needs to know which record is theirs.
func TestWirelessModeIsRecordedPerInterface(t *testing.T) {
	root := t.TempDir()
	radio := filepath.Join(root, "wlan0")
	mkDir(t, filepath.Join(radio, "wireless"))
	// The real shape of /proc/net/wireless's status line. It reports the
	// association state, not a mode name, which is why this fallback is
	// weaker than nl80211 and why a mode derived from it carries less weight.
	mkFile(t, filepath.Join(radio, "wireless", "status"), "associated\n")

	info := sysfsFixture(t, root)

	mode, ok := info.WirelessMode("wlan0")
	if !ok {
		t.Fatal("a radio with a readable status file reported no mode")
	}
	if mode != WirelessModeClient {
		t.Errorf("mode = %q, want %q", mode, WirelessModeClient)
	}

	p := probeByPath(t, info, filepath.Join(radio, "wireless", "status"))
	if p.Outcome != ProbeEvidence {
		t.Errorf("a readable mode reported %q, want %q", p.Outcome, ProbeEvidence)
	}
	if p.Subsystem != "wireless" {
		t.Errorf("subsystem = %q, want wireless", p.Subsystem)
	}
}

// TestWirelessModeWhenTheStatusFileIsUnreadable proves the fallback records
// its own failure rather than returning a bare false.
//
// This is the exact case the M7.1 requirement about not inferring AP
// capability rests on: the interface IS a radio, and THN cannot tell what it
// is doing. Both halves have to be visible.
func TestWirelessModeWhenTheStatusFileIsUnreadable(t *testing.T) {
	root := t.TempDir()
	radio := filepath.Join(root, "wlan0")
	mkDir(t, filepath.Join(radio, "wireless"))
	// A status file whose first token is not a recognised association state:
	// the directory proves this is a radio, and the content declines to say
	// what it is doing. That is the case M7.1 must report as an unknown mode
	// rather than inferring AP capability from.
	mkFile(t, filepath.Join(radio, "wireless", "status"), "ssid: something\n")

	info := sysfsFixture(t, root)

	if mode, ok := info.WirelessMode("wlan0"); ok {
		t.Errorf("a status file with no mode reported %q", mode)
	}

	p := probeByPath(t, info, filepath.Join(radio, "wireless", "status"))
	if p.Outcome != ProbeNoEvidence {
		t.Errorf("an unreadable mode reported %q, want %q", p.Outcome, ProbeNoEvidence)
	}
	if p.Stage != StageParse {
		t.Errorf("stage = %q, want %q; the file was read but not understood",
			p.Stage, StageParse)
	}
	if !strings.Contains(p.Detail, "no operating mode") {
		t.Errorf("the record does not say what is missing: %q", p.Detail)
	}
}

// TestProbesNeverGrowWithoutBound guards the one place that could leak.
//
// Every read records a probe, so a host with many interfaces produces many.
// That is fine and intended — but the list must not include output, and this
// checks the only field that could.
func TestProbesNeverGrowWithoutBound(t *testing.T) {
	root := t.TempDir()
	big := strings.Repeat("9", 4096)
	mkDir(t, filepath.Join(root, "big0"))
	mkFile(t, filepath.Join(root, "big0", "speed"), big+"\n")

	info := sysfsFixture(t, root)
	info.LinkSpeed("big0")

	for _, p := range info.Probes() {
		if len(p.Reason) > 300 || len(p.Detail) > 300 {
			t.Errorf("a probe field is %d bytes; probes must not carry raw file content",
				len(p.Reason)+len(p.Detail))
		}
	}
}

// TestProbesAreReturnedInOrder proves the list is deterministic.
//
// Two runs over the same host must produce the same diagnostics, or two
// reports cannot be diffed against each other.
func TestProbesAreReturnedInOrder(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"zz0", "aa0", "mm0"} {
		mkDir(t, filepath.Join(root, name))
		mkFile(t, filepath.Join(root, name, "speed"), "1000\n")
	}

	info := sysfsFixture(t, root)
	info.LinkSpeed("zz0")
	info.LinkSpeed("aa0")
	info.LinkSpeed("mm0")

	first := info.Probes()
	for i := 0; i < 5; i++ {
		again := info.Probes()
		for j := range first {
			if first[j].Path != again[j].Path {
				t.Fatalf("probe order changed between calls: %s became %s",
					first[j].Path, again[j].Path)
			}
		}
	}
}
