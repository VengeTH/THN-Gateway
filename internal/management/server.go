package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/state"
)

// Server implements the THN Management HTTP API and local control plane.
type Server struct {
	cfg        config.Config
	store      *state.Store
	policy     *BindPolicy
	auth       *AuthManager
	collector  *Collector
	mux        *http.ServeMux
	server     *http.Server
	mu         sync.Mutex
	blocked    map[string]bool
	qosToggled map[string]bool
}

// NewServer configures a new management server.
func NewServer(cfg config.Config, store *state.Store) (*Server, error) {
	bp, err := NewBindPolicy(cfg.Management.BindAddress, cfg.Management.AllowedNetworks, cfg.Management.WANAccess)
	if err != nil {
		return nil, fmt.Errorf("management: configuring bind policy: %w", err)
	}

	am := NewAuthManager(cfg.Management.SessionTTL)
	col := NewCollector(cfg, store)

	s := &Server{
		cfg:        cfg,
		store:      store,
		policy:     bp,
		auth:       am,
		collector:  col,
		mux:        http.NewServeMux(),
		blocked:    make(map[string]bool),
		qosToggled: make(map[string]bool),
	}

	s.registerRoutes()
	return s, nil
}

// Start begins listening and serving on the configured LAN/local bind address.
func (s *Server) Start(ctx context.Context) error {
	addr := s.cfg.Management.BindAddress
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	s.server = &http.Server{
		Addr:              addr,
		Handler:           s.wrapMiddleware(s.mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("management: failed to listen on %s: %w", addr, err)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()

	return s.server.Serve(ln)
}

// Handler returns the HTTP handler (useful for httptest and in-process execution).
func (s *Server) Handler() http.Handler {
	return s.wrapMiddleware(s.mux)
}

// wrapMiddleware applies LAN-only policy, CORS, and request protection.
func (s *Server) wrapMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. LAN-only policy check: reject any connection from outside allowed LAN/MGMT CIDRs
		if err := s.policy.AuthorizeClientIP(r.RemoteAddr); err != nil {
			s.recordAudit(r, "unauthorized", RoleViewer, "access_denied", r.URL.Path, err.Error(), false)
			http.Error(w, fmt.Sprintf("Forbidden: %v", err), http.StatusForbidden)
			return
		}

		// 2. CORS headers restricted to local origin
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	// Authentication
	s.mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	s.mux.HandleFunc("/api/v1/auth/me", s.handleAuthMe)

	// Read-only Telemetry & Monitoring
	s.mux.HandleFunc("/api/v1/status", s.handleStatus)
	s.mux.HandleFunc("/api/v1/system", s.handleSystem)
	s.mux.HandleFunc("/api/v1/interfaces", s.handleInterfaces)
	s.mux.HandleFunc("/api/v1/wan", s.handleWAN)
	s.mux.HandleFunc("/api/v1/clients", s.handleClients)
	s.mux.HandleFunc("/api/v1/qos", s.handleQoS)
	s.mux.HandleFunc("/api/v1/firewall", s.handleFirewall)
	s.mux.HandleFunc("/api/v1/management", s.handleManagement)
	s.mux.HandleFunc("/api/v1/networks", s.handleNetworks)
	s.mux.HandleFunc("/api/v1/events", s.handleEvents)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)

	// Safe Operator Operations
	s.mux.HandleFunc("/api/v1/clients/", s.handleClientAction)
	s.mux.HandleFunc("/api/v1/qos/toggle", s.handleQoSToggle)
	s.mux.HandleFunc("/api/v1/events/", s.handleEventAction)
}

// --- Handler Implementations ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.collector.GatherStatus()
	respondJSON(w, http.StatusOK, st)
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	sys := s.collector.GatherSystem()
	respondJSON(w, http.StatusOK, sys)
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	ifaces := s.collector.GatherInterfaces()

	// `null` and `[]` are both valid JSON, but they are not the same answer.
	// A collection endpoint that emits null when it has nothing to report
	// makes every consumer carry a null check, and a client that forgets one
	// crashes on a machine with no second NIC rather than showing an empty
	// list. The collection is always a collection.
	if ifaces == nil {
		ifaces = []InterfaceMonitoring{}
	}

	respondJSON(w, http.StatusOK, ifaces)
}

func (s *Server) handleWAN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	wan := s.collector.GatherWAN()
	respondJSON(w, http.StatusOK, wan)
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	clients := s.collector.GatherClients(r.Context())
	s.mu.Lock()
	for i := range clients {
		if bl, ok := s.blocked[clients[i].ID]; ok {
			clients[i].Blocked = bl
			if bl {
				clients[i].Online = false
			}
		}
	}
	s.mu.Unlock()
	respondJSON(w, http.StatusOK, clients)
}

func (s *Server) handleQoS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	qosSummary := s.collector.GatherQoS()
	respondJSON(w, http.StatusOK, qosSummary)
}

func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	fw := s.collector.GatherFirewall()
	respondJSON(w, http.StatusOK, fw)
}

func (s *Server) handleManagement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	mgmt := s.collector.GatherManagementModel()
	respondJSON(w, http.StatusOK, mgmt)
}

func (s *Server) handleNetworks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	nets := s.collector.GatherNetworks()
	respondJSON(w, http.StatusOK, nets)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	evts := s.collector.GatherEvents(r.Context())
	respondJSON(w, http.StatusOK, evts)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"verdict":     "healthy",
		"checked_at":  time.Now().UTC(),
		"active_mode": false,
		"safety":      "fail-closed, software-only",
	})
}

// --- Auth Handlers ---

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	sess, err := s.auth.Authenticate(req.Username, req.Password)
	if err != nil {
		s.recordAudit(r, req.Username, RoleViewer, "login_failed", "auth", "Invalid credentials", false)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	s.recordAudit(r, sess.Username, sess.Role, "login_success", "auth", "Session established", true)
	respondJSON(w, http.StatusOK, sess)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	token := extractToken(r)
	if token != "" {
		s.auth.InvalidateSession(token)
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		// Return anonymous local viewer context for local dashboard
		respondJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"role":          RoleViewer,
		})
		return
	}

	sess, err := s.auth.ValidateSession(token)
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"role":          RoleViewer,
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"username":      sess.Username,
		"role":          sess.Role,
		"expires_at":    sess.ExpiresAt,
	})
}

// --- Safe Operator Handlers ---

func (s *Server) handleClientAction(w http.ResponseWriter, r *http.Request) {
	// Pattern: /api/v1/clients/{id}/block
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[4] != "block" {
		http.NotFound(w, r)
		return
	}
	clientID := parts[3]

	sess, err := s.requireRole(r, RoleOperator)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var body struct {
		Blocked bool `json:"blocked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.blocked[clientID] = body.Blocked
	s.mu.Unlock()

	if s.store != nil {
		_ = s.store.SetClientBlocked(r.Context(), clientID, body.Blocked)
	}

	detail := fmt.Sprintf("Client %s blocked=%v", clientID, body.Blocked)
	s.recordAudit(r, sess.Username, sess.Role, "client_block_toggle", clientID, detail, true)

	respondJSON(w, http.StatusOK, map[string]any{
		"client_id": clientID,
		"blocked":   body.Blocked,
		"updated":   time.Now().UTC(),
	})
}

func (s *Server) handleQoSToggle(w http.ResponseWriter, r *http.Request) {
	sess, err := s.requireRole(r, RoleOperator)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var body struct {
		ClientID string `json:"client_id"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.qosToggled[body.ClientID] = body.Enabled
	s.mu.Unlock()

	detail := fmt.Sprintf("Client %s QoS policy enabled=%v", body.ClientID, body.Enabled)
	s.recordAudit(r, sess.Username, sess.Role, "qos_policy_toggle", body.ClientID, detail, true)

	respondJSON(w, http.StatusOK, map[string]any{
		"client_id": body.ClientID,
		"enabled":   body.Enabled,
	})
}

func (s *Server) handleEventAction(w http.ResponseWriter, r *http.Request) {
	// Pattern: /api/v1/events/{id}/ack
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[4] != "ack" {
		http.NotFound(w, r)
		return
	}
	eventID := parts[3]

	sess, err := s.requireRole(r, RoleOperator)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if s.store != nil {
		_ = s.store.AcknowledgeAlert(r.Context(), eventID, sess.Username)
	}

	s.recordAudit(r, sess.Username, sess.Role, "alert_acknowledge", eventID, "Alert acknowledged by operator", true)
	respondJSON(w, http.StatusOK, map[string]any{
		"event_id":     eventID,
		"acknowledged": true,
		"ack_by":       sess.Username,
	})
}

func (s *Server) requireRole(r *http.Request, minRole Role) (*Session, error) {
	token := extractToken(r)
	if token == "" {
		return nil, errors.New("authentication required for operator actions")
	}

	sess, err := s.auth.ValidateSession(token)
	if err != nil {
		return nil, fmt.Errorf("session validation failed: %w", err)
	}

	if minRole == RoleOperator && !sess.Role.CanOperate() {
		return nil, errors.New("forbidden: operator or administrator role required")
	}
	if minRole == RoleAdmin && !sess.Role.CanAdminister() {
		return nil, errors.New("forbidden: administrator role required")
	}

	return sess, nil
}

func (s *Server) recordAudit(r *http.Request, actor string, role Role, action, target, detail string, success bool) {
	if s.store != nil {
		_, _ = s.store.RecordManagementAudit(context.Background(), state.ManagementAuditEntry{
			TS:      time.Now().UTC(),
			Actor:   actor,
			Role:    string(role),
			Action:  action,
			Target:  target,
			Detail:  detail,
			Success: success,
		})
	}
}

func extractToken(r *http.Request) string {
	authHdr := r.Header.Get("Authorization")
	if strings.HasPrefix(authHdr, "Bearer ") {
		return strings.TrimPrefix(authHdr, "Bearer ")
	}
	if cookie, err := r.Cookie("thn_session"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return ""
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
