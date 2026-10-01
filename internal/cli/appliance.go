package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/appliance"
)

// This file implements `thn appliance`.
//
// # What it reports
//
// What the appliance image contains, whether the running filesystem still
// matches it, which slot is running, and what the device has decided to do
// about the difference.
//
// It is a read-only inspection of the device's own integrity. It cannot
// rebuild an image, cannot switch slots, and cannot mark a slot good — those
// belong to the image builder and the bootloader respectively, and a command
// that could do them from a management shell would be a way to make the device
// unbootable remotely.
//
// # Why it matters more than it looks
//
// Every other safety property in THN is about what THN will not do. This one is
// about whether THN is what it claims to be. A gateway whose binary has been
// replaced satisfies every other check in this repository, because all of them
// are about the code's behaviour and none of them are about the code's
// identity.

// runAppliance implements `thn appliance`.
func runAppliance(env *Env, args []string) ExitCode {
	if len(args) == 0 {
		return env.fatalf("thn appliance: expected a subcommand\n\n")
	}

	switch args[0] {
	case "manifest":
		return runApplianceManifest(env, args[1:])
	case "verify":
		return runApplianceVerify(env, args[1:])
	case "status", "boot":
		return runApplianceStatus(env, args[1:])
	default:
		return env.fatalf(
			"thn appliance: unknown subcommand %q; expected manifest, verify or status\n", args[0])
	}
}

// runApplianceManifest describes the image at a root.
//
// It writes nothing. "Build the manifest" would be a mutation of the running
// device's description of itself, and a device that can rewrite its own
// manifest is a device whose manifest means nothing.
func runApplianceManifest(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.String("root", "")
	fs.Bool("json", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn appliance manifest: %v\n", err)
	}

	root := fsValue(fs, "root")
	if root == "" {
		return env.fatalf("thn appliance manifest: --root is required.\n")
	}

	m, err := appliance.Build(root, appliance.DefaultFiles())
	if err != nil {
		return env.fatalf("thn appliance manifest: %v\n", err)
	}

	if env.IsJSON || *fs.bools["json"] {
		if err := env.printJSON(m); err != nil {
			env.errorf("thn appliance manifest: %v\n", err)
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Image     %s\n", m.Image)
	env.printf("Built     %s\n", m.BuiltAt.Format(time.RFC3339))
	env.printf("Digest    %s\n", m.Digest)
	env.printf("Files     %d\n\n", len(m.Entries))

	for _, e := range m.Entries {
		env.printf("  %04o %8d  %s  %s\n", e.Mode, e.Size, e.Digest[:12], e.Path)
		if e.Role != "" {
			env.printf("            %s\n", e.Role)
		}
	}

	env.printf("\nThis manifest describes what is there. Signing it is the control\n")
	env.printf("plane's job; `thn appliance verify` checks a filesystem against it.\n")
	return ExitOK
}

// runApplianceVerify checks a filesystem against a manifest.
func runApplianceVerify(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.String("root", "")
	fs.String("manifest", "")
	fs.Bool("mode", false)
	fs.Bool("scan", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn appliance verify: %v\n", err)
	}

	root := fsValue(fs, "root")
	if root == "" {
		return env.fatalf("thn appliance verify: --root is required.\n")
	}

	m, err := loadManifest(fsValue(fs, "manifest"), root)
	if err != nil {
		return env.fatalf("thn appliance verify: %v\n", err)
	}

	report := appliance.Verify(root, m, appliance.Options{
		CheckMode:         *fs.bools["mode"],
		ScanForUnexpected: *fs.bools["scan"],
	}, time.Now().UTC())

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"root":      root,
			"report":    report,
			"mode_note": "--mode compares permissions; it needs a filesystem that preserves them",
		}); err != nil {
			env.errorf("thn appliance verify: %v\n", err)
			return ExitProblems
		}
		if !report.OK {
			return ExitProblems
		}
		return ExitOK
	}
	if report.OK {
		env.printf("The filesystem matches the image.\n")
		env.printf("%d file(s) verified, digest %s.\n", report.Checked, m.Digest)
		env.printf("\nThis checks the files the manifest declares. It does not prove\n")
		env.printf("nothing else is present: that needs a whole-root hash, which is\n")
		env.printf("the image builder's job, not this command's.\n")
		return ExitOK
	}

	env.printf("DOES NOT MATCH\n")
	env.printf("%s\n\n", strings.Repeat("─", 72))
	env.printf("%d file(s) checked, %d discrepanc(y/ies).\n\n", report.Checked, len(report.Findings))

	for _, f := range report.Findings {
		env.printf("[%s] %s\n", f.Kind, f.Path)
		for _, line := range strings.Split(strings.TrimSpace(f.Reason), "\n") {
			env.printf("    %s\n", line)
		}
	}

	env.printf("\nAn appliance that does not match its image should not serve the\n")
	env.printf("data plane. `thn appliance status` reports what this device has\n")
	env.printf("decided to do about it.\n")
	return ExitProblems
}

// runApplianceStatus reports the boot decision.
func runApplianceStatus(env *Env, args []string) ExitCode {
	fs := newFlagSet()
	fs.String("root", "")
	fs.String("manifest", "")
	fs.Bool("mode", false)
	fs.Bool("scan", false)

	if _, err := fs.Parse(args); err != nil {
		return env.fatalf("thn appliance status: %v\n", err)
	}

	root := fsValue(fs, "root")
	if root == "" {
		return env.fatalf("thn appliance status: --root is required.\n")
	}

	m, err := loadManifest(fsValue(fs, "manifest"), root)
	if err != nil {
		return env.fatalf("thn appliance verify: %v\n", err)
	}

	report := appliance.Verify(root, m, appliance.Options{
		CheckMode:         *fs.bools["mode"],
		ScanForUnexpected: *fs.bools["scan"],
	}, time.Now().UTC())

	slots := appliance.NewSlotTable()
	decision := appliance.Decide(appliance.BootInput{
		Verification: report,
		Slots:        slots,
	}, time.Now().UTC())

	if env.IsJSON {
		if err := env.printJSON(map[string]any{
			"root":     root,
			"slots":    slots.All(),
			"decision": decision,
		}); err != nil {
			env.errorf("thn appliance status: %v\n", err)
			return ExitProblems
		}
		if !decision.ServesDataPlane() {
			return ExitProblems
		}
		return ExitOK
	}

	env.printf("Appliance\n")
	env.printf("%s\n\n", strings.Repeat("─", 72))
	env.printf("%s", appliance.Render(decision))
	env.printf("\n\n%s", slots.String())

	env.printf("\nThis build has no slot persistence, so both slots read empty and no\n")
	env.printf("fallback can be named. The bootloader owns that state in a real\n")
	env.printf("appliance image.\n")

	if !decision.ServesDataPlane() {
		return ExitProblems
	}
	return ExitOK
}

// loadManifest reads a manifest, or builds one from the root when none is
// given.
//
// Building one on the fly is a convenience for inspecting a filesystem nobody
// has signed for. The callers say so, because a manifest that describes
// whatever happens to be present is not evidence that anything is correct — it
// is only a starting point for comparison.
func loadManifest(path, root string) (appliance.Manifest, error) {
	if path == "" {
		return appliance.Build(root, appliance.DefaultFiles())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return appliance.Manifest{}, fmt.Errorf("reading the manifest: %w", err)
	}
	var m appliance.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return appliance.Manifest{}, fmt.Errorf("%w: %v", appliance.ErrManifestMalformed, err)
	}
	return m, nil
}
