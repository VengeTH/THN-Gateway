package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Root resolves absolute paths against a base directory.
type Root struct {
	// Base is the directory every path is resolved under. An empty Base
	// means "resolve as given", which is what a real deployment wants.
	Base string
}

// New returns a Root rooted at base.
func New(base string) Root { return Root{Base: base} }

// System returns a Root that resolves paths as given.
//
// This is the production root. It is a named value rather than a zero value so
// that a call site says which mode it is in: using the host filesystem
// directly is a decision, not an accident.
func System() Root { return Root{} }

// Resolve returns the filesystem path for an absolute configuration path.
//
// An empty path resolves to the base itself, so a caller that has no
// configured path writes somewhere predictable rather than to the process's
// working directory.
func (r Root) Resolve(path string) string {
	if r.Base == "" {
		return path
	}
	if path == "" {
		return r.Base
	}
	if !filepath.IsAbs(path) {
		// A relative path is joined to the base rather than resolved against
		// the process working directory, which is not predictable.
		return filepath.Join(r.Base, path)
	}
	return filepath.Join(r.Base, filepath.FromSlash(strings.TrimPrefix(path, "/")))
}

// WriteFile writes content to a path inside the root, creating parents.
//
// The file is written with 0644: it contains no secrets, and for the lease
// file it must remain readable by the server process.
func (r Root) WriteFile(path, content string, perm os.FileMode) error {
	full := r.Resolve(path)

	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", path, err)
	}
	if err := os.WriteFile(full, []byte(content), perm); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// ReadFile reads a path inside the root.
//
// A missing file is reported as an error the caller can distinguish, because
// "no lease file yet" is a normal state during development and not a fault.
func (r Root) ReadFile(path string) (string, error) {
	full := r.Resolve(path)

	data, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%s does not exist: %w", path, err)
		}
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return string(data), nil
}

// Exists reports whether a path exists inside the root.
func (r Root) Exists(path string) bool {
	_, err := os.Stat(r.Resolve(path))
	return err == nil
}

// String renders the root for display.
func (r Root) String() string {
	if r.Base == "" {
		return "(system)"
	}
	return r.Base
}
