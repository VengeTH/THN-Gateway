package management

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("auth: invalid username or password")
	ErrSessionExpired     = errors.New("auth: session has expired")
	ErrSessionNotFound    = errors.New("auth: session not found")
	ErrInvalidCSRFToken   = errors.New("auth: invalid CSRF token")
	ErrUnauthorized       = errors.New("auth: unauthorized action for role")
)

// Session represents an active operator or viewer session.
type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// IsExpired checks if the session has exceeded its TTL.
func (s *Session) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

// User represents an authenticated identity.
type User struct {
	Username     string
	PasswordHash string // formatted as "pbkdf2:rounds:salt:hash"
	Role         Role
}

// AuthManager handles authentication, password verification and session lifecycles.
type AuthManager struct {
	mu       sync.RWMutex
	users    map[string]User
	sessions map[string]*Session
	ttl      time.Duration
}

// NewAuthManager creates an AuthManager with a default session TTL.
//
// # Why there are no built-in accounts
//
// This previously seeded three users with fixed passwords —
// admin/thn-admin-password and two lesser roles — on every construction, so
// any host running this build had three working logins whose credentials are
// published in the source. Salted or not, a credential that ships in the
// repository is a credential that is public.
//
// It also cannot be defended as a development convenience, because the thing
// this build talks to is a gateway on a house LAN holding DHCP and NAT for
// that house. The console is reachable by anything on the subnet, so a
// default password is not a nuisance; it is an unauthenticated write path
// into someone's network.
//
// So no account is created implicitly. Credentials come from the
// configuration, and an empty configuration means an unauthenticated
// management plane that says so — which is the state an operator can see and
// act on, rather than one they have to discover from a failed login.
func NewAuthManager(ttl time.Duration) *AuthManager {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	am := &AuthManager{
		users:    make(map[string]User),
		sessions: make(map[string]*Session),
		ttl:      ttl,
	}
	return am
}

// BootstrapOperator installs a single admin account from configuration.
//
// This is the supported way in: the operator supplies a username and
// password at activation time rather than inheriting one written into the
// binary. It is idempotent, so a restart does not reset the password and an
// accidental second call cannot silently overwrite an existing operator.
//
// Called with empty values it does nothing, which is deliberate — a config
// that names a user but no password must not fall back to a default.
func (am *AuthManager) BootstrapOperator(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hashing operator password: %w", err)
	}
	am.users[username] = User{
		Username:     username,
		PasswordHash: hash,
		Role:         RoleAdmin,
	}
	return nil
}

// HasUsers reports whether any credential has been installed.
//
// The management plane consults this to decide whether to require
// authentication. An empty store is a real state that must be reported as
// unconfigured, not quietly treated as authenticated.
func (am *AuthManager) HasUsers() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.users) > 0
}

// HashPassword hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	iterations := 100000
	hash := pbkdf2Sha256([]byte(password), salt, iterations, 32)
	return fmt.Sprintf("pbkdf2:%d:%s:%s", iterations, hex.EncodeToString(salt), hex.EncodeToString(hash)), nil
}

// VerifyPassword checks a plaintext password against a stored PBKDF2 hash.
func VerifyPassword(password, stored string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	rounds, err := strconv.Atoi(parts[1])
	if err != nil || rounds <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expectedHash, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}

	computed := pbkdf2Sha256([]byte(password), salt, rounds, len(expectedHash))
	return subtle.ConstantTimeCompare(computed, expectedHash) == 1
}

// pbkdf2Sha256 derives a key using standard PBKDF2 with SHA-256.
func pbkdf2Sha256(password, salt []byte, iterations, keyLen int) []byte {
	prf := func(msg []byte) []byte {
		mac := hmac.New(sha256.New, password)
		mac.Write(msg)
		return mac.Sum(nil)
	}

	numBlocks := (keyLen + 31) / 32
	var result []byte

	for block := 1; block <= numBlocks; block++ {
		var blockNum [4]byte
		blockNum[0] = byte(block >> 24)
		blockNum[1] = byte(block >> 16)
		blockNum[2] = byte(block >> 8)
		blockNum[3] = byte(block)

		u := prf(append(salt, blockNum[:]...))
		xorSum := make([]byte, len(u))
		copy(xorSum, u)

		for i := 1; i < iterations; i++ {
			u = prf(u)
			for j := 0; j < len(u); j++ {
				xorSum[j] ^= u[j]
			}
		}
		result = append(result, xorSum...)
	}

	if len(result) > keyLen {
		return result[:keyLen]
	}
	return result
}

// AddUser registers or updates a user with a hashed password.
func (am *AuthManager) AddUser(username, password string, role Role) {
	hash, err := HashPassword(password)
	if err != nil {
		return
	}
	am.mu.Lock()
	defer am.mu.Unlock()
	am.users[strings.ToLower(username)] = User{
		Username:     username,
		PasswordHash: hash,
		Role:         role,
	}
}

// Authenticate verifies credentials and generates an authenticated session.
func (am *AuthManager) Authenticate(username, password string) (*Session, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, ok := am.users[strings.ToLower(username)]
	if !ok || !VerifyPassword(password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	tokenBytes := make([]byte, 32)
	csrfBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}
	if _, err := rand.Read(csrfBytes); err != nil {
		return nil, fmt.Errorf("generating csrf token: %w", err)
	}

	sess := &Session{
		Token:     hex.EncodeToString(tokenBytes),
		Username:  user.Username,
		Role:      user.Role,
		CSRFToken: hex.EncodeToString(csrfBytes),
		ExpiresAt: time.Now().UTC().Add(am.ttl),
		CreatedAt: time.Now().UTC(),
	}

	am.sessions[sess.Token] = sess
	return sess, nil
}

// ValidateSession retrieves and validates a session by token.
func (am *AuthManager) ValidateSession(token string) (*Session, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	sess, ok := am.sessions[token]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if sess.IsExpired() {
		return nil, ErrSessionExpired
	}
	return sess, nil
}

// InvalidateSession logs out a session.
func (am *AuthManager) InvalidateSession(token string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.sessions, token)
}
