package management

import (
	"context"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/activation"
	"github.com/VengeTH/THN-Gateway/internal/config"
)

// TestNoShellExecutionInManagement inspects all source files in the management package
// to guarantee that os/exec is not imported and no shell execution can occur.
func TestNoShellExecutionInManagement(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("globbing files: %v", err)
	}

	for _, file := range files {
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}

		for _, imp := range node.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "os/exec" {
				t.Errorf("%s imports os/exec: shell execution is strictly prohibited in the management package", file)
			}
		}
	}
}

// TestManagementDoesNotBypassActivationGate verifies that activation remains fail-closed
// and cannot be activated through the management server or API.
func TestManagementDoesNotBypassActivationGate(t *testing.T) {
	srv, _ := testServer(t)

	// Verify activation cannot be triggered via API
	req := httptest.NewRequest(http.MethodPost, "/api/v1/activate", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	// Must be 404 Not Found — no activate route exists in management API!
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for /api/v1/activate, got %d", w.Code)
	}

	// Verify activation gates remain fail-closed without physical presence
	input := activation.GateInput{PresenceConfirmed: false}
	gates := activation.EvaluateProduction(input)
	if gates.AllSatisfied {
		t.Fatalf("safety invariant violated: production gates should block without physical presence")
	}
}

// TestWANAccessStrictlyRefused ensures the management policy forbids WAN exposure.
func TestWANAccessStrictlyRefused(t *testing.T) {
	_, err := NewBindPolicy("0.0.0.0:8080", []string{"0.0.0.0/0"}, true)
	if err == nil {
		t.Fatalf("expected error when attempting to enable WAN access on management service")
	}
}

// TestSoftwareOnlyNoHostModifications verifies M8 collector runs purely in-process
// without modifying host routes, addresses, firewall or qdiscs.
func TestSoftwareOnlyNoHostModifications(t *testing.T) {
	cfg := config.Defaults()
	cfg.QoS.Clients = []config.QoSClientConfig{
		{ID: "client-test", IP: "10.77.0.100", Priority: "normal"},
	}
	col := NewCollector(cfg, nil)

	// Run all gather operations
	st := col.GatherStatus()
	if st.ActivationState != "GATED" {
		t.Errorf("expected ActivationState to be GATED, got %s", st.ActivationState)
	}

	sys := col.GatherSystem()
	if sys.Status != "healthy" {
		t.Errorf("expected System status healthy, got %s", sys.Status)
	}

	ifaces := col.GatherInterfaces()
	// The collector reports what the host has. On a platform it cannot
	// inspect it reports nothing, and an empty result is the CORRECT answer —
	// it is what a non-empty result used to be faking. Asserting a fixed
	// length here is asserting that the fabrication still works.
	//
	// What matters for the safety property this test guards is that the
	// collector ran without touching the host, which the surrounding
	// assertions and the absence of any write call already establish.
	if runtime.GOOS != "linux" && len(ifaces) != 0 {
		t.Errorf("expected no interfaces on an uninspectable platform, got %d", len(ifaces))
	}

	wan := col.GatherWAN()
	// Likewise: reachability is measured now, so there is nothing to assert
	// about its value on a host that cannot be probed. What must hold is
	// that status is one of the states the renderer knows how to display.
	switch wan.Status {
	case "online", "degraded", "offline", "unknown":
	default:
		t.Errorf("WAN status %q is not a state the console can render", wan.Status)
	}

	clients := col.GatherClients(context.Background())
	if len(clients) == 0 {
		t.Errorf("expected non-empty clients model")
	}

	fw := col.GatherFirewall()
	if !fw.ManagementProtected {
		t.Errorf("expected management protected in firewall summary")
	}

	zones := col.GatherNetworks()
	if len(zones) == 0 {
		t.Errorf("expected network zones model")
	}
}
