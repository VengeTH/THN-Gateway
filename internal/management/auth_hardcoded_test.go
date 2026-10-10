package management

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

// Regression tests for hardcoded management credentials.
//
// The build used to construct three accounts on every startup —
// admin/thn-admin-password plus operator and viewer roles — with the passwords
// written literally in the source. Every deployment therefore shipped known
// working credentials, and the console sat on a house LAN holding that house's
// DHCP and NAT.
//
// These tests pin the two properties the fix required: that nothing is
// created implicitly, and that an unconfigured management plane SAYS SO rather
// than reporting a wrong password.

// newUnconfiguredServer builds a management server with no credentials, which
// is what Defaults() produces and what a freshly installed gateway looks like.
func newUnconfiguredServer(t *testing.T) *Server {
	t.Helper()

	cfg := config.Defaults()
	cfg.Management.Enabled = true
	cfg.Management.BindAddress = "127.0.0.1:8080"
	cfg.Management.AllowedNetworks = []string{"127.0.0.0/8"}

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := state.Open(dbPath)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv, err := NewServer(cfg, st)
	if err != nil {
		t.Fatalf("creating server: %v", err)
	}
	return srv
}

// TestNoDefaultCredentialsExist is the core assertion: a fresh server has no
// account at all.
func TestNoDefaultCredentialsExist(t *testing.T) {
	srv := newUnconfiguredServer(t)

	if srv.auth.HasUsers() {
		t.Fatal("a freshly constructed AuthManager has accounts; no credential " +
			"may be created without the operator supplying one")
	}
}

// TestDocumentedDefaultPasswordsAreRejected pins the specific credentials that
// used to ship, so a regression cannot reintroduce them quietly.
func TestDocumentedDefaultPasswordsAreRejected(t *testing.T) {
	srv := newUnconfiguredServer(t)

	for _, cred := range []struct{ user, pass string }{
		{"admin", "thn-admin-password"},
		{"operator", "thn-operator-password"},
		{"viewer", "thn-viewer-password"},
	} {
		if _, err := srv.auth.Authenticate(cred.user, cred.pass); err == nil {
			t.Fatalf("the documented default %q/%q authenticated; those credentials "+
				"must never exist", cred.user, cred.pass)
		}
	}
}

// TestUnconfiguredLoginReportsMisconfigurationNotBadCredentials is the
// behavioural half.
//
// Returning "Invalid credentials" here sends an operator to reset a password
// that does not exist. The state is a configuration to complete, and it has
// to read as one.
func TestUnconfiguredLoginReportsMisconfigurationNotBadCredentials(t *testing.T) {
	srv := newUnconfiguredServer(t)

	body := []byte(`{"username": "admin", "password": "whatever"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for an unconfigured management plane, got %d: %s",
			w.Code, w.Body.String())
	}

	if bytes.Contains(w.Body.Bytes(), []byte("Invalid credentials")) {
		t.Fatal("an unconfigured gateway must not report a wrong password; " +
			"no credential exists to be wrong")
	}
}

// TestConfiguredOperatorCanAuthenticate proves the replacement path works:
// credentials supplied in configuration produce a working admin account.
func TestConfiguredOperatorCanAuthenticate(t *testing.T) {
	cfg := config.Defaults()
	cfg.Management.Enabled = true
	cfg.Management.BindAddress = "127.0.0.1:8080"
	cfg.Management.AllowedNetworks = []string{"127.0.0.0/8"}
	cfg.Management.OperatorUsername = "the-operator"
	cfg.Management.OperatorPassword = "a-real-password"

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := state.Open(dbPath)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	srv, err := NewServer(cfg, st)
	if err != nil {
		t.Fatalf("creating server: %v", err)
	}

	sess, err := srv.auth.Authenticate("the-operator", "a-real-password")
	if err != nil {
		t.Fatalf("the configured operator could not authenticate: %v", err)
	}
	if sess.Role != RoleAdmin {
		t.Fatalf("configured operator has role %q, want %q", sess.Role, RoleAdmin)
	}
}

// TestBootstrapOperatorIsIdempotent guards against a restart silently resetting
// or duplicating the operator account.
func TestBootstrapOperatorIsIdempotent(t *testing.T) {
	am := NewAuthManager(0)

	if err := am.BootstrapOperator("op", "first-password"); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	if err := am.BootstrapOperator("op", "first-password"); err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}

	if _, err := am.Authenticate("op", "first-password"); err != nil {
		t.Fatalf("operator cannot authenticate after repeat bootstrap: %v", err)
	}
}

// TestBootstrapOperatorWithEmptyValuesIsANoOp ensures a config that names a
// user but no password does not fall back to anything.
func TestBootstrapOperatorWithEmptyValuesIsANoOp(t *testing.T) {
	am := NewAuthManager(0)

	if err := am.BootstrapOperator("", ""); err != nil {
		t.Fatalf("empty bootstrap returned an error: %v", err)
	}
	if err := am.BootstrapOperator("op", ""); err != nil {
		t.Fatalf("empty-password bootstrap returned an error: %v", err)
	}

	if am.HasUsers() {
		t.Fatal("empty credentials must not create an account; there is nothing to authenticate against")
	}
}
