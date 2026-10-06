package network

// Host facts that `ip` does not report authoritatively.
//
// # Why this layer exists at all
//
// M3 classified an interface as wireless only when `ip -j -d link show`
// emitted a `wireless` object. On a real gateway that object was absent, and
// a Wi-Fi adapter was reported as "Ethernet".
//
// The reason is not that the parser was careless. `ip` sources that block from
// the Wireless Extensions ioctls, and current mac80211 drivers do not
// implement Wireless Extensions. There is no flag that makes `ip` ask
// nl80211 instead, because `ip` does not speak nl80211.
//
// So THN has to ask something that does. Two sources are used, and both are
// the kernel's own:
//
//	nl80211 via `iw dev`   authoritative, works on every mac80211 driver
//	/sys/class/net/X/wireless  the Wireless Extensions view, when the driver
//	                          happens to provide one
//
// Neither is consulted unless the interface has been observed, and neither
// is a heuristic over the interface name.
//
// # Link speed
//
// `ip -j -d link show` emits `speed` only when iproute2 can query the driver
// for it. Many drivers do not, and none of them do while there is no carrier
// — so on the real gateway the speed column was empty for the one interface
// an operator most wanted to know about.
//
// `/sys/class/net/<if>/speed` is the kernel's own attribute, backed by the
// same ethtool query, and it exists for every link whether or not `ip`
// reported it. A file that says `-1` means the driver does not know, and is
// carried through as "not reported" rather than as zero.
//
// # Nothing here writes
//
// The only external command is a bare `iw dev` / `iw phy` dump, through
// internal/guard, whose policy for `iw` permits zero operands and therefore
// cannot reach any mutating form. The rest is reading files under /sys.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/venth/thn-gateway/internal/guard"
)

// HostInfo supplies the facts `ip` cannot be relied upon to report.
//
// Both methods are read-only and may fail. A false `ok` means "the kernel did
// not say", which callers must carry as unknown rather than substitute.
//
// # Why the false answer needs a companion probe
//
// A false `ok` is one value standing for at least three unrelated facts: the
// attribute is not there, it is there and could not be read, or it is there
// and did not parse. Those lead to different conclusions — a missing
// /sys/class/net/X/speed on a virtual link is uninteresting, while the same
// file present-but-unreadable means the kernel is telling THN something it is
// refusing to hear.
//
// Probes() returns why each read came back the way it did, so the unknown
// survives into the report with its cause attached rather than arriving
// unexplained.
type HostInfo interface {
	// LinkSpeed returns the negotiated link speed in Mbps for an interface.
	//
	// ok is false when the driver does not report a speed, when the link has
	// no carrier, and when the interface is not physical. All three are the
	// same answer: unknown. Probes says which one it was.
	LinkSpeed(iface string) (mbps int, ok bool)

	// WirelessMode returns the operating mode of a WIRELESS interface.
	//
	// ok is false when the interface is not wireless, or when it is wireless
	// and the kernel did not report a mode. The distinction matters: the
	// first means "this is not a radio", the second means "this is a radio
	// and THN cannot tell what it is doing".
	WirelessMode(iface string) (mode string, ok bool)

	// Describe names the source, for diagnostics.
	Describe() string

	// Probes returns the structured record of every read this source made.
	//
	// Recorded as it goes rather than returned per call, because the two
	// methods are called in a loop over the interface list and the whole
	// point is to report every one of them. The zero return is legitimate:
	// a source with nothing to say says nothing.
	Probes() []Probe
}

// Wireless operating modes, normalised.
//
// `iw` reports "managed" for a station, "AP" (or "__ap"/"master" on older
// builds) for an access point, and "monitor" for a capture interface. THN
// uses one vocabulary so that a kernel rename does not change a verdict.
const (
	WirelessModeClient  = "client"
	WirelessModeAP      = "ap"
	WirelessModeMonitor = "monitor"
	WirelessModeMesh    = "mesh"
	WirelessModeAdhoc   = "adhoc"
)

// NormaliseWirelessMode maps a kernel-reported mode onto THN's vocabulary.
//
// The mapping is total and lossy-by-design: anything unrecognised becomes
// "unknown", which every capability rule treats as "not established". A mode
// THN has never heard of must not be guessed into the nearest thing it
// recognises — that is how a monitor interface ends up reported as a client.
func NormaliseWirelessMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "managed", "station", "client":
		return WirelessModeClient
	case "ap", "__ap", "master":
		return WirelessModeAP
	case "monitor":
		return WirelessModeMonitor
	case "mesh", "mesh point", "mesh point <<-> mp", "mesh peer":
		return WirelessModeMesh
	case "adhoc", "ad-hoc", "ibss":
		return WirelessModeAdhoc
	default:
		return "unknown"
	}
}

// ParseWirelessInterfaces reads the output of `iw dev`.
//
// It is separated from the exec call for the same reason ParseLinks is: the
// decision about whether THN understands a machine must be testable on a
// machine that is not the one being understood. A parser welded to exec can
// only ever be exercised on the device it was written for.
//
// `iw dev` groups interfaces under a PHY:
//
//	phy#0
//		Interface wlp2s0
//			ifindex 3
//			type managed
//		Interface wlp2s1
//			ifindex 4
//			type monitor
//
// The interface line opens a block; `type` inside it names the mode. An
// interface with no `type` line is wireless — `iw` lists nothing else —
// with an unknown mode, which is a different and more honest answer than
// omitting it.
func ParseWirelessInterfaces(raw string) map[string]string {
	out := map[string]string{}

	var current string
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "Interface":
			if len(fields) < 2 {
				current = ""
				continue
			}
			current = fields[1]
			// Presence in this map IS the wireless fact.
			if _, seen := out[current]; !seen {
				out[current] = "unknown"
			}
		case "type":
			// A `type` line outside an Interface block belongs to the PHY
			// (for example "type: monitor" describing the phy itself). It
			// must not be attributed to whichever interface preceded it.
			if current == "" || len(fields) < 2 {
				continue
			}
			out[current] = NormaliseWirelessMode(fields[1])
		}
	}
	return out
}

// ParseSpeedFile reads the contents of /sys/class/net/<if>/speed.
//
// The kernel writes a decimal Mbps value, or -1 when the driver does not
// report a speed. A file that cannot be read at all is equally unknown.
// Anything else — a stray byte, an empty file — is unknown rather than zero,
// because zero is a number a planner could act on and "unknown" is not.
func ParseSpeedFile(content string) (int, bool) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return 0, false
	}
	n, err := strconv.Atoi(trimmed)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// ParseWirelessStatus reads the WEXT status file.
//
// `/sys/class/net/<if>/wireless/status` says "associated" or "unassociated"
// rather than naming a mode, so it establishes only that the interface is a
// station. It is a weaker source than nl80211 and is used only where nl80211
// is unavailable.
func ParseWirelessStatus(content string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(content))
	if len(fields) == 0 {
		return "", false
	}
	switch strings.ToLower(fields[0]) {
	case "associated", "unassociated", "disassociated", "notassociated":
		return WirelessModeClient, true
	default:
		return "", false
	}
}

// sysfsHostInfo reads the kernel's own interface attributes.
//
// sysRoot is injected rather than hard-coded so that tests can point it at a
// fixture directory and exercise the real parsing and the real path building
// without a Linux host.
type sysfsHostInfo struct {
	// root is the directory holding one subdirectory per interface.
	root string

	// modes is the nl80211 view, keyed by interface name. Empty when iw is
	// unavailable, which is not an error — it is a missing source.
	modes map[string]string

	// modesKnown records whether nl80211 was successfully consulted, so that
	// an absent entry means "not wireless" rather than "we did not look".
	modesKnown bool

	// describe is reported in diagnostics.
	describe string

	// probes accumulates every read this source made, with its cause.
	probes []Probe
}

var _ HostInfo = (*sysfsHostInfo)(nil)

// record attaches a probe, keeping the list non-nil.
//
// Non-nil so that a JSON consumer gets `[]` rather than `null`: "no reads
// happened" and "the field is absent" are not the same, and this is the same
// rule the CLI applies to its own empty lists.
func (s *sysfsHostInfo) record(p Probe) {
	if s.probes == nil {
		s.probes = []Probe{}
	}
	s.probes = append(s.probes, p)
}

// Probes implements HostInfo.
func (s *sysfsHostInfo) Probes() []Probe {
	if s.probes == nil {
		return []Probe{}
	}
	return append([]Probe(nil), s.probes...)
}

// LinkSpeed implements HostInfo.
func (s *sysfsHostInfo) LinkSpeed(iface string) (int, bool) {
	if !safeIfaceName(iface) {
		// Refusing the name is THN's decision, not the kernel's, and the
		// record says so — otherwise a security check reads as a missing
		// file.
		s.record(Probe{
			Subsystem: "link-speed",
			Operation: "sysfs-speed",
			Stage:     StageLocate,
			Outcome:   ProbeParseFailed,
			Detail:    "the interface name was rejected as unsafe, so no file was read",
			Reason:    "refused before reading: " + iface + " is not a plain kernel interface name",
		})
		return 0, false
	}

	path := filepath.Join(s.root, iface, "speed")
	b, err := os.ReadFile(path)
	if err != nil {
		outcome, detail := classifyFileError(err)
		s.record(FileProbe("link-speed", "sysfs-speed", path, StageLocate, outcome, detail, err))
		return 0, false
	}

	mbps, ok := ParseSpeedFile(string(b))
	if !ok {
		s.record(Probe{
			Subsystem: "link-speed",
			Operation: "sysfs-speed",
			Stage:     StageParse,
			Outcome:   ProbeNoEvidence,
			Path:      path,
			Detail:    "the kernel reported no link speed for this interface",
			// The file's own content is the reason, and it is a safe one:
			// a sysfs speed attribute is a single integer or the literal -1,
			// never host configuration.
			Reason: "unparseable or negative speed attribute: " + redacted(string(b)),
		})
		return 0, false
	}

	s.record(Succeeded(Probe{
		Subsystem: "link-speed",
		Operation: "sysfs-speed",
		Path:      path,
	}, fmt.Sprintf("the kernel reported a link speed of %d Mbps", mbps), 1))
	return mbps, true
}

// classifyFileError maps a file-read error onto a probe outcome.
//
// A missing file and an unreadable file are separated because they mean
// opposite things about the host: absent is normal for a link with no
// ethtool backing, while present-but-unreadable means THN was refused by the
// kernel or the mount options.
func classifyFileError(err error) (ProbeOutcome, string) {
	if os.IsNotExist(err) {
		return ProbeToolUnavailable, "the file is not present"
	}
	if os.IsPermission(err) {
		return ProbeExecutionFailed, "the file is present but could not be read: permission denied"
	}
	return ProbeExecutionFailed, "the file is present but could not be read"
}

// WirelessMode implements HostInfo.
func (s *sysfsHostInfo) WirelessMode(iface string) (string, bool) {
	if !safeIfaceName(iface) {
		s.record(Probe{
			Subsystem: "wireless",
			Operation: "sysfs-wireless-mode",
			Stage:     StageLocate,
			Outcome:   ProbeParseFailed,
			Detail:    "the interface name was rejected as unsafe, so no file was read",
			Reason:    "refused before reading: " + iface + " is not a plain kernel interface name",
		})
		return "", false
	}

	if s.modesKnown {
		mode, ok := s.modes[iface]
		// nl80211 answered, and this interface is not in its output. That is a
		// working probe finding nothing — a fact about the host, not a
		// failure — and it is recorded as such rather than as "not checked".
		p := NotChecked("wireless", "nl80211-modes/"+iface)
		if ok {
			p = Succeeded(p, "nl80211 reported mode "+mode, 1)
		} else {
			p.Outcome = ProbeNoEvidence
			p.Detail = "nl80211 was consulted and did not list this interface as a radio"
		}
		s.record(p)
		return mode, ok
	}

	// Fall back to the Wireless Extensions view. Its mere existence is
	// evidence the interface is a radio, so a directory read is required
	// before the status file is trusted.
	wirelessDir := filepath.Join(s.root, iface, "wireless")
	if _, err := os.Stat(wirelessDir); err != nil {
		outcome, detail := classifyFileError(err)
		s.record(FileProbe("wireless", "sysfs-wireless-directory", wirelessDir,
			StageLocate, outcome, detail, err))
		return "", false
	}

	status := filepath.Join(wirelessDir, "status")
	b, err := os.ReadFile(status)
	if err != nil {
		outcome, detail := classifyFileError(err)
		s.record(FileProbe("wireless", "sysfs-wireless-status", status,
			StageLocate, outcome, detail, err))
		return "", false
	}

	mode, ok := ParseWirelessStatus(string(b))
	if !ok {
		s.record(Probe{
			Subsystem: "wireless",
			Operation: "sysfs-wireless-status",
			Stage:     StageParse,
			Outcome:   ProbeNoEvidence,
			Path:      status,
			Detail:    "this is a radio but no operating mode could be read from it",
			Reason:    "unparseable wireless status: " + redacted(string(b)),
		})
		return "", false
	}

	s.record(Succeeded(Probe{
		Subsystem: "wireless",
		Operation: "sysfs-wireless-status",
		Path:      status,
	}, "the Wireless Extensions view reported mode "+mode, 1))
	return mode, true
}

// Describe implements HostInfo.
func (s *sysfsHostInfo) Describe() string {
	if s.describe == "" {
		return "sysfs"
	}
	return s.describe
}

// safeIfaceName rejects anything that is not a plain kernel interface name.
//
// Interface names come from the kernel rather than from a document, so this
// is defence in depth rather than a response to an attacker: it makes it
// impossible for an observed name to escape the sysfs root through a path
// separator or a parent-directory segment, whatever produced it.
func safeIfaceName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, "/\\") {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// enrichLinks folds the authoritative host facts into an observed interface
// list.
//
// It runs AFTER `ip`, and only ever ADDS a fact or corrects a classification
// that the weaker source got wrong. The order matters: `ip` has already told
// us the link type, flags, master and address; this step answers the two
// questions it is not authoritative about.
//
// # Why a correction is allowed at all
//
// `ip` reports a wireless adapter as an Ethernet link. That is not a parse
// error — it is iproute2 declining to ask nl80211. The observation is
// incomplete rather than wrong, and this is where the missing half is added.
//
// The correction is narrow and in one direction only: an interface that a
// wireless source positively identifies as wireless BECOMES wireless. Nothing
// here can demote a wireless interface to something else, and nothing here
// can invent a wireless interface — if no source names it, it is not wireless.
func enrichLinks(ctx context.Context, ifaces []Interface, info HostInfo, diags *[]Diagnostic) {
	if info == nil {
		return
	}

	wireless := map[string]string{}

	for i := range ifaces {
		name := ifaces[i].Name

		// Speed: the observed value is kept when `ip` supplied one. Two
		// sources disagreeing is a reason to prefer the kernel attribute,
		// not to average them or to pick the larger.
		if ifaces[i].SpeedMbps == 0 {
			if mbps, ok := info.LinkSpeed(name); ok {
				ifaces[i].SpeedMbps = mbps
			}
		}

		mode, isWireless := info.WirelessMode(name)
		if !isWireless {
			continue
		}
		wireless[name] = mode

		// An interface `ip` already called wireless keeps its identity; the
		// only thing possibly improved is the mode.
		if ifaces[i].Kind == "wlan" {
			if ifaces[i].WirelessMode == "" {
				ifaces[i].WirelessMode = mode
			}
			continue
		}

		ifaces[i].Kind = "wlan"
		ifaces[i].Physical = true
		ifaces[i].WirelessMode = mode
		*diags = append(*diags, Diagnostic{
			Subject:  "interfaces",
			Severity: "info",
			Message: fmt.Sprintf(
				"%s reports link_type %q but is a wireless interface in %s mode per %s; "+
					"corrected from the authoritative source",
				name, ifaces[i].LinkType, mode, info.Describe()),
		})
	}

	// A wire less name is worth a note, because an operator who expected a
	// radio to be visible will otherwise conclude there is none.
	if len(wireless) == 0 {
		*diags = append(*diags, Diagnostic{
			Subject:  "wireless",
			Severity: "info",
			Message: fmt.Sprintf(
				"no wireless interfaces were observed; %s reported none", info.Describe()),
		})
	}
}

// readWirelessModes consults nl80211 through `iw`.
//
// A failure is not an error. `iw` is not installed on every minimal server,
// and a host with no radio has nothing to report either way. The returned flag
// says whether the source was successfully consulted, because "we asked and
// there were none" and "we could not ask" are different answers.
//
// The probe is recorded rather than folded into the boolean: on a host where
// nl80211 could not be reached, wireless mode for every radio falls back to
// the Wireless Extensions view, and an operator looking at an unknown mode
// needs to know that a weaker source was used rather than guessing which.
func readWirelessModes(ctx context.Context) (map[string]string, bool, Probe) {
	out, err := guard.Exec(ctx, "iw", "dev")
	p := ExecProbe("wireless", "nl80211-modes", "iw", []string{"dev"}, out, err)
	if err != nil {
		return nil, false, p
	}

	modes := ParseWirelessInterfaces(out.Stdout)
	p = Succeeded(p, fmt.Sprintf("iw dev listed %d interface(s)", len(modes)), len(modes))
	return modes, true, p
}
