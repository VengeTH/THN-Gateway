package network

// What this machine IS, as distinct from what it can DO.
//
// # Why the distribution matters at all
//
// M6.x could answer "is there a kernel with nftables on it" and that was
// enough. M7.0 has to answer a different question â€” "should an operator trust
// what this host reports, and what should they check by hand" â€” and the answer
// to that depends heavily on the distribution.
//
//	Ubuntu 24.04   systemd-resolved owns DNS; /etc/resolv.conf is a stub
//	Debian 12      /etc/resolv.conf is edited by hand or by a package
//	Alpine         musl, busybox ip, no systemd at all
//
// The same file means different things on different systems. Reporting "there
// is a resolv.conf with 127.0.0.53 in it" without saying the distribution is
// managed DNS produces a confident, confident, wrong answer.
//
// # Everything here is read-only
//
// Two files are opened and nothing else. There is no command execution in this
// file at all, which is a stronger guarantee than the one guard provides:
// there is no argv for a policy mistake to go wrong in.
//
// # Parsers are separated from file reads
//
// ParseOSRelease takes a string. Reading the file is two lines and is not the
// part that can be wrong. The parser is the part that decides whether THN
// understands the machine it is standing on, and a parser welded to a file
// read can only ever be tested on the distribution it was written for.

import (
	"os"
	"strings"
)

// System identifies the running system.
//
// Every field except OS and Architecture is best-effort: a distribution that
// ships no os-release, or one that ships a malformed one, still yields a usable
// Platform. An empty Distribution means "not established", never "none".
type System struct {
	// OS is the kernel family: always "linux" where THN runs.
	OS string `json:"os"`

	// Architecture is the runtime architecture, e.g. "amd64".
	Architecture string `json:"architecture"`

	// Distribution is the os-release ID: "ubuntu", "debian", "alpine".
	Distribution string `json:"distribution,omitempty"`

	// Name is the os-release NAME field.
	Name string `json:"name,omitempty"`

	// Version is the os-release VERSION_ID field.
	Version string `json:"version,omitempty"`

	// PrettyName is the human-facing name, e.g. "Ubuntu 24.04.1 LTS".
	PrettyName string `json:"pretty_name,omitempty"`

	// Codename is VERSION_CODENAME, e.g. "noble".
	Codename string `json:"codename,omitempty"`

	// Kernel is the kernel release string, from /proc/sys/kernel/osrelease.
	//
	// This is the same string `uname -r` prints, read from procfs rather than
	// by executing `uname` â€” one fewer binary to allowlist, and the answer is
	// identical because both read the same kernel variable.
	Kernel string `json:"kernel,omitempty"`

	// Hostname is the machine's hostname, e.g. "heedful-dev".
	//
	// It is its own field rather than being derived from an interface
	// address, because it is a different fact. 127.0.0.1/8 is an address the
	// loopback interface has on every Linux host; it identifies nothing and
	// answers no question an operator asks. The hostname is what an operator
	// recognises the machine by, and it is the only one of the two that
	// differs between two machines on the same desk.
	//
	// Read through os.Hostname, which queries the kernel's own name cache.
	// That is the same value the `hostname` binary prints, reached without
	// spawning a process and so with nothing to allowlist.
	Hostname string `json:"hostname,omitempty"`
}

// Describe renders a one-line human description of the platform.
//
// It prefers the distribution's own PRETTY_NAME because that is what the
// machine's owner would recognise, and falls back through progressively less
// specific descriptions rather than ever returning nothing.
func (p System) Describe() string {
	switch {
	case p.PrettyName != "":
		return p.PrettyName
	case p.Name != "" && p.Version != "":
		return p.Name + " " + p.Version
	case p.Name != "":
		return p.Name
	case p.Distribution != "":
		return p.Distribution
	default:
		return p.OS
	}
}

// osReleasePaths are the locations os-release is read from, in order.
//
// /etc/os-release is the specification's primary location and is a symlink on
// most current distributions; /usr/lib/os-release is the fallback for systems
// that only implement the vendor path. A system with neither is simply one
// THN knows nothing about, which is a supported outcome.
var osReleasePaths = []string{
	"/etc/os-release",
	"/usr/lib/os-release",
}

// kernelReleasePath is where the kernel exposes its own release string.
//
// Read from procfs rather than by running `uname -r`. Same value, no process.
const kernelReleasePath = "/proc/sys/kernel/osrelease"

// readSystem observes the running system.
//
// Both files are optional. A failure on either leaves the corresponding field
// empty rather than producing a diagnostic: on a Linux host these files
// existing is the normal case, and a host missing os-release is one THN
// should describe plainly rather than complain about.
func readSystem() System {
	p := System{
		OS:           goos,
		Architecture: arch,
	}
	for _, path := range osReleasePaths {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		p.applyOSRelease(ParseOSRelease(string(b)))
		break
	}
	if b, err := os.ReadFile(kernelReleasePath); err == nil {
		p.Kernel = strings.TrimSpace(string(b))
	}
	// A host that cannot report its own name is described without one. An
	// empty Hostname means "not established", never "unnamed": the renderer
	// omits the line rather than printing a blank one.
	if h, err := os.Hostname(); err == nil {
		p.Hostname = strings.TrimSpace(h)
	}
	return p
}

// ParseOSRelease parses an os-release file.
//
// The format is a shell-compatible key=value file: values may be bare,
// single-quoted or double-quoted, `#` begins a comment, and quoting may be
// mixed. This parser handles all of it rather than only the shape Ubuntu
// emits, because the alternative is silently reporting an empty distribution
// on every system that formats its os-release differently.
//
// Malformed lines are skipped rather than failing the parse. An os-release
// with one unparseable line still tells us the distribution, and refusing to
// read a machine because of a single bad line would make THN less useful
// exactly where it is needed most.
func ParseOSRelease(content string) System {
	var p System
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = unquoteOSReleaseValue(strings.TrimSpace(value))
		switch key {
		case "ID":
			p.Distribution = value
		case "NAME":
			p.Name = value
		case "VERSION_ID":
			p.Version = value
		case "PRETTY_NAME":
			p.PrettyName = value
		case "VERSION_CODENAME":
			p.Codename = value
		}
	}
	return p
}

// applyOSRelease copies the non-empty fields of a parsed os-release.
//
// Applied rather than assigned so that a fallback file missing a field cannot
// blank out one an earlier file established.
func (p *System) applyOSRelease(q System) {
	if q.Distribution != "" {
		p.Distribution = q.Distribution
	}
	if q.Name != "" {
		p.Name = q.Name
	}
	if q.Version != "" {
		p.Version = q.Version
	}
	if q.PrettyName != "" {
		p.PrettyName = q.PrettyName
	}
	if q.Codename != "" {
		p.Codename = q.Codename
	}
}

// unquoteOSReleaseValue removes shell quoting from an os-release value.
//
// Both quote styles are accepted because distributions use both, and an
// os-release with single-quoted values is not a hypothetical:
// Alpine's does exactly this.
func unquoteOSReleaseValue(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
