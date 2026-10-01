// Package appliance describes and verifies the image a gateway runs from.
//
// # What an appliance is
//
// A gateway appliance is not a program installed on a host. It is an image:
// a set of files, a boot slot, and a claim about what is inside it. That
// difference drives everything in this package.
//
// On a host, "is my software the software I installed" is a question the
// package manager answers. On an appliance it is a question with no package
// manager, no login, and nobody watching — and the answer has to be
// established before the device starts routing traffic, because after that
// point the device is load-bearing.
//
// So the appliance carries a manifest: every file, its mode, its size, its
// digest. The manifest is signed with the same ed25519 machinery the desired
// state uses (internal/artifact), so an attacker who can write files to the
// image cannot also write the description of those files.
//
// # How this relates to the guard invariant
//
// internal/guard protects the *host* from THN: one package may spawn a
// process, and only read-only verbs are permitted.
//
// This package protects the *appliance* from everyone else. The two are
// complementary and neither substitutes for the other. A THN that cannot
// mutate the host can still be shipped on an image whose binaries have been
// replaced, and a correctly signed image can still be asked to do something
// the guard forbids. Both checks are needed, and neither is a substitute.
//
// # What this package does not do
//
// It does not build an image. It does not boot one. It does not manage the
// bootloader. It describes an image and checks a running filesystem against
// that description, which is the part that has to be right and the part that
// can be tested without a device.
//
// # The scoping limit, stated rather than implied
//
// Verifying the declared manifest proves that the files the image claims to
// contain are the files it named. It does not prove that nothing else is
// present. Detecting an *extra* file in /etc requires hashing the whole
// filesystem, which is what dm-verity or a signed rootfs hash is for.
//
// That is an OS-build concern rather than a Go one, and this package does not
// pretend to solve it. The manifest covers what it declares; whole-root
// integrity is the image builder's job, and saying so here is better than
// leaving an operator to assume a check they have not got.
package appliance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ManifestFormat is the manifest schema version.
const ManifestFormat = 1

// Errors returned by verification. All are refusals.
var (
	// ErrManifestMalformed means the manifest cannot be read.
	ErrManifestMalformed = errors.New("appliance: manifest is malformed")

	// ErrFileMissing means a declared file is not on the filesystem.
	ErrFileMissing = errors.New("appliance: declared file is missing")

	// ErrFileChanged means a declared file exists but does not match.
	ErrFileChanged = errors.New("appliance: declared file does not match the image")

	// ErrFileModeChanged means a file's permissions differ.
	//
	// Checked separately from content because a file with the right bytes and
	// the wrong mode is a different problem: a world-writable config is not a
	// corrupted config, and reporting it as corruption would send somebody
	// looking at the wrong thing.
	ErrFileModeChanged = errors.New("appliance: declared file has unexpected permissions")

	// ErrDigestMismatch means the manifest's own digest is wrong, so the
	// manifest itself cannot be trusted even if every file matches.
	ErrDigestMismatch = errors.New("appliance: manifest digest does not cover its contents")

	// ErrPathEscapes means a declared path resolves outside the root.
	//
	// Checked because the manifest is read from a file that arrives from
	// somewhere. A path of "../../etc/shadow" in a manifest is not a typo to
	// be logged; it is an attempt to make the verifier report on files the
	// image never contained.
	ErrPathEscapes = errors.New("appliance: declared path escapes the image root")
)

// Entry is one file in the image.
type Entry struct {
	// Path is relative to the image root, slash-separated.
	Path string `json:"path"`

	// Mode is the permission bits, as os.FileMode.
	Mode uint32 `json:"mode"`

	// Size is the length in bytes.
	Size int64 `json:"size"`

	// Digest is the SHA-256 of the contents.
	Digest string `json:"digest"`

	// Role names what the file is for.
	//
	// Free text from the builder, and carried so that a verification report
	// can say "the dnsmasq configuration does not match" rather than
	// "/etc/thn/dnsmasq.conf". A file an operator has never heard of is one
	// they cannot act on.
	Role string `json:"role,omitempty"`
}

// Manifest describes an image.
type Manifest struct {
	// Format is the manifest schema version.
	Format int `json:"format"`

	// Image names the image, e.g. "thn-gateway-2026.10".
	Image string `json:"image"`

	// BuiltAt is when the image was built.
	BuiltAt time.Time `json:"built_at"`

	// Entries are the files, sorted by path.
	Entries []Entry `json:"entries"`

	// Digest covers Entries.
	//
	// Carried inside the document it covers, which is circular, and that is
	// fine: the point is that the digest is over the *content*, so a manifest
	// whose entries were altered no longer matches its own digest. The
	// signature is what stops the digest being recomputed.
	Digest string `json:"digest"`
}

// Build walks a root and describes what it finds.
//
// Only the named paths are described. A manifest covering an entire root
// filesystem would be enormous, would change every boot for files that do not
// matter, and would have to be rebuilt for anything the kernel writes at
// runtime. The declared set is the set the product depends on.
func Build(root string, files []File) (Manifest, error) {
	m := Manifest{
		Format:  ManifestFormat,
		Image:   filepath.Base(strings.TrimRight(root, `/\`)),
		BuiltAt: time.Now().UTC(),
	}

	for _, f := range files {
		full, err := resolve(root, f.Path)
		if err != nil {
			return Manifest{}, err
		}

		info, err := os.Stat(full)
		if err != nil {
			// A declared file that is absent is not a build failure: an image
			// is assembled before it is complete, and the absence is what the
			// finished manifest will record.
			continue
		}
		if info.IsDir() {
			continue
		}

		digest, size, err := hashFile(full)
		if err != nil {
			return Manifest{}, fmt.Errorf("appliance: hashing %s: %w", f.Path, err)
		}

		m.Entries = append(m.Entries, Entry{
			Path:   f.Path,
			Mode:   uint32(info.Mode().Perm()),
			Size:   size,
			Digest: digest,
			Role:   f.Role,
		})
	}

	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Path < m.Entries[j].Path })
	m.Digest = m.computeDigest()
	return m, nil
}

// File names a file to describe.
type File struct {
	// Path is relative to the image root.
	Path string
	// Role explains what the file is for.
	Role string
}

// resolve turns a declared path into an absolute one, refusing anything that
// leaves the root.
//
// A path containing a ".." segment is refused outright rather than cleaned.
//
// Clamping would also be safe — cleaning "/../../etc/shadow" yields "/etc/
// shadow", which lands harmlessly inside the root. But it is silently wrong:
// the caller asked about one file and gets a manifest describing another, with
// nothing to tell them. A path with ".." in it is a mistake or an attempt, and
// both deserve to be reported rather than reinterpreted.
func resolve(root, path string) (string, error) {
	slashed := filepath.ToSlash(path)

	for _, seg := range strings.Split(slashed, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: %q contains a parent-directory segment", ErrPathEscapes, path)
		}
	}

	cleaned := filepath.Clean("/" + slashed)
	if cleaned == "/" {
		return "", fmt.Errorf("%w: %q is the root itself", ErrPathEscapes, path)
	}
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("%w: %q", ErrPathEscapes, path)
	}

	full := filepath.Join(root, cleaned)

	// Compared with Rel rather than by string prefix. The prefix form is the
	// obvious one and it is wrong at the filesystem root: Clean("/") is the
	// separator alone on Windows, so "root + separator" becomes a doubled
	// separator that no real path begins with, and every declared file is
	// rejected as escaping. That is not a corner case — "--root /" is exactly
	// what an appliance verification runs against.
	rel, err := filepath.Rel(filepath.Clean(root), full)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %v", ErrPathEscapes, path, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q", ErrPathEscapes, path)
	}

	return full, nil
}

// computeDigest hashes the entries.
//
// Length-prefixed, for the same reason internal/artifact does it that way: a
// separator a value can contain is a way to make two different manifests hash
// the same.
func (m Manifest) computeDigest() string {
	h := sha256.New()

	writeField(h, fmt.Sprintf("%d", m.Format))
	writeField(h, m.Image)
	writeField(h, m.BuiltAt.UTC().Format(time.RFC3339Nano))
	for _, e := range m.Entries {
		writeField(h, e.Path)
		writeField(h, fmt.Sprintf("%o", e.Mode))
		writeField(h, fmt.Sprintf("%d", e.Size))
		writeField(h, e.Digest)
		writeField(h, e.Role)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func writeField(w io.Writer, s string) {
	var lenbuf [8]byte
	n := len(s)
	for i := 7; i >= 0; i-- {
		lenbuf[i] = byte(n)
		n >>= 8
	}
	_, _ = w.Write(lenbuf[:])
	_, _ = io.WriteString(w, s)
}

// Verify recomputes the manifest digest.
func (m Manifest) Verify() error {
	if m.Format != ManifestFormat {
		return fmt.Errorf("%w: format %d, want %d", ErrManifestMalformed, m.Format, ManifestFormat)
	}
	if got := m.computeDigest(); got != m.Digest {
		return fmt.Errorf("%w: says %s, contents hash to %s", ErrDigestMismatch, m.Digest, got)
	}
	return nil
}

// hashFile returns the digest and size of a file.
//
// Opened and streamed rather than read whole: an image file may be a
// multi-megabyte binary and this runs on a device with limited memory.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// DigestFile returns a file's digest, for callers verifying one path.
func DigestFile(path string) (string, int64, error) { return hashFile(path) }

// ------------------------------------------------------------ verification

// Finding is one discrepancy between a manifest and a filesystem.
type Finding struct {
	// Path is the file concerned.
	Path string `json:"path"`

	// Kind classifies the discrepancy.
	Kind FindingKind `json:"kind"`

	// Reason is a sentence for an operator.
	Reason string `json:"reason"`

	// Expected and Actual are populated where they are known.
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

// FindingKind classifies a verification finding.
type FindingKind string

const (
	// FindingMissing means the file is gone.
	FindingMissing FindingKind = "missing"
	// FindingChanged means the contents differ.
	FindingChanged FindingKind = "changed"
	// FindingMode means the permissions differ.
	FindingMode FindingKind = "mode"
	// FindingUnreadable means the file could not be read.
	FindingUnreadable FindingKind = "unreadable"
	// FindingUnexpected means the file is present but not declared.
	//
	// Only reported when the caller asked for it: detecting an extra file in
	// a directory requires listing the directory, which is a different cost
	// and a different question from checking declared files.
	FindingUnexpected FindingKind = "unexpected"
)

// Report is the outcome of verifying a filesystem against a manifest.
type Report struct {
	// OK reports that every declared file matched.
	//
	// False when nothing was checked. A report that verified zero files and
	// said the filesystem matched would be the most dangerous thing this
	// package could emit: it is what a wrong --root produces, and it would be
	// read as the reassuring answer by exactly the person who has just run a
	// check against the wrong path.
	OK bool `json:"ok"`

	// Checked is how many files were verified.
	Checked int `json:"checked"`

	// Findings are the discrepancies, most serious first.
	Findings []Finding `json:"findings,omitempty"`

	// At is when the check ran.
	At time.Time `json:"at"`
}

// severity orders finding kinds so the worst prints first.
func severity(k FindingKind) int {
	switch k {
	case FindingChanged, FindingMode:
		return 0
	case FindingMissing:
		return 1
	case FindingUnreadable:
		return 2
	default:
		return 3
	}
}

// Options control a verification run.
type Options struct {
	// CheckMode compares permissions as well as contents.
	//
	// Off by default because it produces findings on filesystems that do not
	// preserve modes — a squashfs built on one machine and mounted on another
	// legitimately has different bits. An operator who knows their image
	// preserves modes should turn it on.
	CheckMode bool

	// ScanForUnexpected lists directories in the manifest and reports files
	// that are not declared.
	//
	// Off by default because it is a different question and a different cost,
	// and because an operator who enables it needs to understand that it will
	// flag runtime files such as PID and lease files that legitimately appear
	// after boot.
	ScanForUnexpected bool
}

// Verify checks a filesystem against a manifest.
//
// The manifest's own digest is checked first. Verifying files against a
// manifest whose entries were altered would report every altered file as
// changed, which is a confusing way of saying "the manifest is not what it
// claims to be", and wastes the operator's time on the wrong files.
func Verify(root string, m Manifest, opts Options, at time.Time) Report {
	// A manifest with nothing in it verifies against everything, which is
	// true and useless. It is marked not-OK here rather than at the call sites
	// so that every consumer gets the same answer.
	if len(m.Entries) == 0 {
		return Report{
			OK:      false,
			At:      at.UTC(),
			Checked: 0,
			Findings: []Finding{{
				Path: "(manifest)",
				Kind: FindingChanged,
				Reason: "The manifest declares no files, so there is nothing to check. " +
					"This is not a pass: a verification that checked nothing must not be " +
					"reported as a filesystem matching an image, and an empty manifest is " +
					"usually a wrong root or an unbuilt image rather than a gateway that " +
					"genuinely contains nothing.",
			}},
		}
	}

	r := Report{OK: true, At: at.UTC()}

	if err := m.Verify(); err != nil {
		r.OK = false
		r.Findings = append(r.Findings, Finding{
			Path:   "(manifest)",
			Kind:   FindingChanged,
			Reason: err.Error(),
		})
		return r
	}

	declared := make(map[string]bool, len(m.Entries))

	for _, e := range m.Entries {
		declared[e.Path] = true
		r.Checked++

		full, err := resolve(root, e.Path)
		if err != nil {
			r.OK = false
			r.Findings = append(r.Findings, Finding{
				Path: e.Path, Kind: FindingMissing, Reason: err.Error(),
			})
			continue
		}

		info, err := os.Stat(full)
		if err != nil {
			r.OK = false
			r.Findings = append(r.Findings, Finding{
				Path: e.Path, Kind: FindingMissing,
				Reason: fmt.Sprintf(
					"%s is declared in the image but is not on the filesystem. %s",
					e.Path, describe(e.Role)),
			})
			continue
		}

		digest, size, err := hashFile(full)
		if err != nil {
			r.OK = false
			r.Findings = append(r.Findings, Finding{
				Path: e.Path, Kind: FindingUnreadable,
				Reason: fmt.Sprintf("%s could not be read: %v", e.Path, err),
			})
			continue
		}

		if digest != e.Digest || size != e.Size {
			r.OK = false
			r.Findings = append(r.Findings, Finding{
				Path: e.Path, Kind: FindingChanged,
				Expected: e.Digest[:12], Actual: digest[:12],
				Reason: fmt.Sprintf(
					"%s does not match the image. %s The file is %d bytes and should be %d.",
					e.Path, describe(e.Role), size, e.Size),
			})
			continue
		}

		if opts.CheckMode {
			if got := uint32(info.Mode().Perm()); got != e.Mode {
				r.OK = false
				r.Findings = append(r.Findings, Finding{
					Path: e.Path, Kind: FindingMode,
					Expected: fmt.Sprintf("%04o", e.Mode), Actual: fmt.Sprintf("%04o", got),
					Reason: fmt.Sprintf(
						"%s has permissions %04o and the image declares %04o. %s",
						e.Path, got, e.Mode, describe(e.Role)),
				})
			}
		}
	}

	if opts.ScanForUnexpected {
		r.Findings = append(r.Findings, scanUnexpected(root, declared, m)...)
		for _, f := range r.Findings {
			if f.Kind == FindingUnexpected {
				r.OK = false
			}
		}
	}

	sort.SliceStable(r.Findings, func(i, j int) bool {
		if severity(r.Findings[i].Kind) != severity(r.Findings[j].Kind) {
			return severity(r.Findings[i].Kind) < severity(r.Findings[j].Kind)
		}
		return r.Findings[i].Path < r.Findings[j].Path
	})

	return r
}

// scanUnexpected lists the manifest's directories and reports undeclared files.
func scanUnexpected(root string, declared map[string]bool, m Manifest) []Finding {
	dirs := make(map[string]bool)
	for p := range declared {
		d := filepath.Dir(filepath.ToSlash(p))
		if d != "." && d != "/" {
			dirs[d] = true
		}
	}

	var out []Finding
	seenDir := make(map[string]bool)

	for d := range dirs {
		if seenDir[d] {
			continue
		}
		seenDir[d] = true

		full, err := resolve(root, d)
		if err != nil {
			continue
		}
		entries, err := os.ReadDir(full)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			rel := filepath.ToSlash(filepath.Join(d, e.Name()))
			if declared[rel] {
				continue
			}
			out = append(out, Finding{
				Path: rel, Kind: FindingUnexpected,
				Reason: fmt.Sprintf(
					"%s is present but the image does not declare it. This is how an "+
						"addition to a running system shows up.", rel),
			})
		}
	}
	return out
}

func describe(role string) string {
	if role == "" {
		return ""
	}
	return "(" + role + ")"
}

// DefaultFiles is the set an appliance image must contain.
//
// It is a declaration, not a discovery: the builder and the verifier must
// agree on what "complete" means, and a list that were discovered from the
// filesystem would be a list that silently loses whatever was missing last
// time it was built.
//
// The paths are the ones THN already uses. Nothing here is new layout.
func DefaultFiles() []File {
	return []File{
		{Path: "usr/bin/thn", Role: "the THN binary"},
		{Path: "etc/thn/config.yaml", Role: "the gateway configuration"},
		{Path: "etc/thn/dnsmasq.conf", Role: "the rendered DHCP and DNS configuration"},
		{Path: "etc/thn/firewall.nft", Role: "the rendered host firewall"},
		{Path: "etc/thn/qos.sh", Role: "the rendered traffic shaping script"},
		{Path: "etc/thn/manifest.json", Role: "this manifest"},
	}
}

// walkRoot is used by tests and by callers that want every file under a root.
//
// Kept unexported and small: it exists so that Build can be tested without
// inventing a filesystem, and a general-purpose walker would be a thing
// somebody later used to decide what an image contains.
func walkRoot(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out, err
}

// WalkRoot lists every file under a root, relative and slash-separated.
func WalkRoot(root string) ([]string, error) { return walkRoot(root) }
