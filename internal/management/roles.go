package management

import (
	"strings"
)

// Role defines an authorization tier for gateway management.
type Role string

const (
	// RoleViewer can inspect status, topology, devices, traffic and QoS.
	RoleViewer Role = "Viewer"

	// RoleOperator can view everything and perform safe predefined operational
	// actions (e.g. block/unblock a client, toggle client QoS policy, acknowledge alerts).
	RoleOperator Role = "Operator"

	// RoleAdmin has full configuration review, management and future activation rights.
	RoleAdmin Role = "Administrator"
)

// ParseRole parses a role string case-insensitively.
func ParseRole(s string) (Role, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer", "view":
		return RoleViewer, true
	case "operator", "op":
		return RoleOperator, true
	case "administrator", "admin":
		return RoleAdmin, true
	default:
		return RoleViewer, false
	}
}

// CanView checks if a role has read-only visibility.
func (r Role) CanView() bool {
	return r == RoleViewer || r == RoleOperator || r == RoleAdmin
}

// CanOperate checks if a role can execute safe operational actions.
func (r Role) CanOperate() bool {
	return r == RoleOperator || r == RoleAdmin
}

// CanAdminister checks if a role has administrator permissions.
func (r Role) CanAdminister() bool {
	return r == RoleAdmin
}
