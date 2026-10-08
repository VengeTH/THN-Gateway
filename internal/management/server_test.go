package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

func testServer(t *testing.T) (*Server, *state.Store) {
	t.Helper()

	cfg := config.Defaults()
	cfg.Management.Enabled = true
	cfg.Management.BindAddress = "127.0.0.1:8080"
	cfg.Management.AllowedNetworks = []string{"10.10.99.0/24", "10.77.0.0/24", "127.0.0.0/8"}
	cfg.Management.WANAccess = false

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_state.db")
	st, err := state.Open(dbPath)
	if err != nil {
		t.Fatalf("opening test store: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})

	srv, err := NewServer(cfg, st)
	if err != nil {
		t.Fatalf("creating test server: %v", err)
	}
	return srv, st
}

func TestManagementAPIEndpoints(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	endpoints := []string{
		"/api/v1/status",
		"/api/v1/system",
		"/api/v1/interfaces",
		"/api/v1/wan",
		"/api/v1/clients",
		"/api/v1/qos",
		"/api/v1/firewall",
		"/api/v1/management",
		"/api/v1/networks",
		"/api/v1/events",
		"/api/v1/health",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, ep, nil)
			req.RemoteAddr = "127.0.0.1:54321" // Local permitted IP
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("endpoint %s returned status %d, expected 200: %s", ep, w.Code, w.Body.String())
			}

			var body map[string]any
			// Some endpoints return arrays, some return objects
			raw := bytes.TrimSpace(w.Body.Bytes())
			if len(raw) == 0 || (raw[0] != '{' && raw[0] != '[') {
				t.Fatalf("endpoint %s returned non-JSON: %s", ep, w.Body.String())
			}
			_ = json.Unmarshal(raw, &body)
		})
	}
}

func TestLANOnlyPolicyDeniesWAN(t *testing.T) {
	srv, _ := testServer(t)
	handler := srv.Handler()

	// 1. Connection from unauthorized WAN IP (e.g. 203.0.113.10)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "203.0.113.10:44123"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for WAN IP, got %d", w.Code)
	}

	// 2. Connection from permitted LAN IP (10.10.99.15)
	reqLAN := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	reqLAN.RemoteAddr = "10.10.99.15:44123"
	wLAN := httptest.NewRecorder()

	handler.ServeHTTP(wLAN, reqLAN)

	if wLAN.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for LAN IP, got %d", wLAN.Code)
	}
}

func TestAuthenticationAndRoleSeparation(t *testing.T) {
	srv, store := testServer(t)
	handler := srv.Handler()

	// 1. Unauthenticated attempt to block a client -> Denied
	blockPayload := []byte(`{"blocked": true}`)
	reqBlock := httptest.NewRequest(http.MethodPost, "/api/v1/clients/client-test/block", bytes.NewReader(blockPayload))
	reqBlock.RemoteAddr = "127.0.0.1:12345"
	wBlock := httptest.NewRecorder()

	handler.ServeHTTP(wBlock, reqBlock)
	if wBlock.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated operator action, got %d", wBlock.Code)
	}

	// 2. Authenticate as Viewer
	loginViewer := []byte(`{"username": "viewer", "password": "thn-viewer-password"}`)
	reqLoginViewer := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginViewer))
	reqLoginViewer.RemoteAddr = "127.0.0.1:12345"
	wLoginViewer := httptest.NewRecorder()

	handler.ServeHTTP(wLoginViewer, reqLoginViewer)
	if wLoginViewer.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid viewer login, got %d", wLoginViewer.Code)
	}

	var viewerSess Session
	if err := json.Unmarshal(wLoginViewer.Body.Bytes(), &viewerSess); err != nil {
		t.Fatalf("decoding session: %v", err)
	}

	// 3. Viewer attempts operator block action -> Denied
	reqViewerBlock := httptest.NewRequest(http.MethodPost, "/api/v1/clients/client-test/block", bytes.NewReader(blockPayload))
	reqViewerBlock.RemoteAddr = "127.0.0.1:12345"
	reqViewerBlock.Header.Set("Authorization", "Bearer "+viewerSess.Token)
	wViewerBlock := httptest.NewRecorder()

	handler.ServeHTTP(wViewerBlock, reqViewerBlock)
	if wViewerBlock.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401/403 for viewer attempting operator block, got %d", wViewerBlock.Code)
	}

	// 4. Authenticate as Operator
	loginOp := []byte(`{"username": "operator", "password": "thn-operator-password"}`)
	reqLoginOp := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginOp))
	reqLoginOp.RemoteAddr = "127.0.0.1:12345"
	wLoginOp := httptest.NewRecorder()

	handler.ServeHTTP(wLoginOp, reqLoginOp)
	if wLoginOp.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid operator login, got %d", wLoginOp.Code)
	}

	var opSess Session
	if err := json.Unmarshal(wLoginOp.Body.Bytes(), &opSess); err != nil {
		t.Fatalf("decoding session: %v", err)
	}

	// 5. Operator executes block action -> Permitted
	reqOpBlock := httptest.NewRequest(http.MethodPost, "/api/v1/clients/client-test/block", bytes.NewReader(blockPayload))
	reqOpBlock.RemoteAddr = "127.0.0.1:12345"
	reqOpBlock.Header.Set("Authorization", "Bearer "+opSess.Token)
	wOpBlock := httptest.NewRecorder()

	handler.ServeHTTP(wOpBlock, reqOpBlock)
	if wOpBlock.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator block action, got %d: %s", wOpBlock.Code, wOpBlock.Body.String())
	}

	// 6. Verify audit event was stored
	auditEntries, err := store.ListManagementAudit(context.Background(), 10)
	if err != nil {
		t.Fatalf("reading audit entries: %v", err)
	}
	if len(auditEntries) == 0 {
		t.Fatalf("expected audit log entries to be recorded, found 0")
	}

	foundAction := false
	for _, a := range auditEntries {
		if a.Actor == "operator" && a.Action == "client_block_toggle" && a.Target == "client-test" {
			foundAction = true
			if !a.Success {
				t.Errorf("expected audit action success=true")
			}
		}
	}
	if !foundAction {
		t.Errorf("operator block audit entry not found in store")
	}

	// 7. Test QoSToggle and EventAck with Operator session
	qosPayload := []byte(`{"client_id": "client-test", "enabled": false}`)
	reqQoS := httptest.NewRequest(http.MethodPost, "/api/v1/qos/toggle", bytes.NewReader(qosPayload))
	reqQoS.RemoteAddr = "127.0.0.1:12345"
	reqQoS.Header.Set("Authorization", "Bearer "+opSess.Token)
	wQoS := httptest.NewRecorder()
	handler.ServeHTTP(wQoS, reqQoS)
	if wQoS.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator QoS toggle, got %d", wQoS.Code)
	}

	reqAck := httptest.NewRequest(http.MethodPost, "/api/v1/events/evt-preflight-gated/ack", nil)
	reqAck.RemoteAddr = "127.0.0.1:12345"
	reqAck.Header.Set("Authorization", "Bearer "+opSess.Token)
	wAck := httptest.NewRecorder()
	handler.ServeHTTP(wAck, reqAck)
	if wAck.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator alert ack, got %d", wAck.Code)
	}

	// 8. Invalid credentials rejected
	badLogin := []byte(`{"username": "admin", "password": "wrong-password"}`)
	reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(badLogin))
	reqBad.RemoteAddr = "127.0.0.1:12345"
	wBad := httptest.NewRecorder()
	handler.ServeHTTP(wBad, reqBad)
	if wBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for bad login, got %d", wBad.Code)
	}

	// 9. Logout invalidates session
	reqLogout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	reqLogout.RemoteAddr = "127.0.0.1:12345"
	reqLogout.Header.Set("Authorization", "Bearer "+opSess.Token)
	wLogout := httptest.NewRecorder()
	handler.ServeHTTP(wLogout, reqLogout)
	if wLogout.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for logout, got %d", wLogout.Code)
	}

	// Token should now be invalid
	reqPostLogout := httptest.NewRequest(http.MethodPost, "/api/v1/qos/toggle", bytes.NewReader(qosPayload))
	reqPostLogout.RemoteAddr = "127.0.0.1:12345"
	reqPostLogout.Header.Set("Authorization", "Bearer "+opSess.Token)
	wPostLogout := httptest.NewRecorder()
	handler.ServeHTTP(wPostLogout, reqPostLogout)
	if wPostLogout.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized after session logout, got %d", wPostLogout.Code)
	}
}

func TestDataCorrectnessStableIdentities(t *testing.T) {
	srv, _ := testServer(t)
	ifaces := srv.collector.GatherInterfaces()

	if len(ifaces) < 2 {
		t.Fatalf("expected at least WAN and LAN interfaces, got %d", len(ifaces))
	}

	wanFound := false
	lanFound := false

	for _, iface := range ifaces {
		if iface.Role == "WAN" {
			wanFound = true
			if iface.StableID == "" || iface.StableID == iface.Name {
				t.Errorf("WAN stable ID should be distinct hardware identity, got %s", iface.StableID)
			}
		}
		if iface.Role == "LAN" {
			lanFound = true
			if iface.StableID == "" || iface.StableID == iface.Name {
				t.Errorf("LAN stable ID should be distinct hardware identity, got %s", iface.StableID)
			}
		}
	}

	if !wanFound || !lanFound {
		t.Errorf("missing WAN or LAN in gathered interfaces")
	}
}

func TestVLANAndIsolationDataModel(t *testing.T) {
	srv, _ := testServer(t)
	zones := srv.collector.GatherNetworks()

	if len(zones) == 0 {
		t.Fatalf("no network zones gathered")
	}

	seenVLANs := make(map[int]bool)
	hasIsolated := false

	for _, z := range zones {
		if z.VLANID > 0 {
			if seenVLANs[z.VLANID] {
				t.Errorf("duplicate VLAN ID %d in zones", z.VLANID)
			}
			seenVLANs[z.VLANID] = true
		}
		if z.ClientIsolation {
			hasIsolated = true
		}
	}

	if !hasIsolated {
		t.Errorf("expected at least one network zone with client isolation enabled")
	}
}
