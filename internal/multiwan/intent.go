package multiwan

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/host"
)

// Mode defines how multiple WAN links are utilized.
type Mode string

const (
	// ModeSingle uses exactly one primary WAN.
	ModeSingle Mode = "single"

	// ModeFailover uses a primary WAN, switching to secondary links when higher-priority links fail.
	ModeFailover Mode = "failover"

	// ModeLoadBalance distributes new connections/sessions across healthy WANs according to weights.
	ModeLoadBalance Mode = "load_balance"
)

// Valid reports whether the mode is recognized by THN.
func (m Mode) Valid() bool {
	switch m {
	case ModeSingle, ModeFailover, ModeLoadBalance:
		return true
	}
	return false
}

// String renders the mode name.
func (m Mode) String() string { return string(m) }

// RoutingPolicy defines traffic steering rules.
type RoutingPolicy string

const (
	// RoutingPolicyDefault routes new sessions across eligible WANs, preserving connection affinity.
	RoutingPolicyDefault RoutingPolicy = "default"
)

// HealthState is how healthy a WAN connection is determined to be.
type HealthState string

const (
	// HealthHealthy means the link is confirmed usable.
	HealthHealthy HealthState = "healthy"

	// HealthDegraded means the link is up but experiencing issues.
	HealthDegraded HealthState = "degraded"

	// HealthUnhealthy means the link is confirmed down or unusable.
	HealthUnhealthy HealthState = "unhealthy"

	// HealthUnknown means reachability could not be determined without mutating probes.
	HealthUnknown HealthState = "unknown"
)

// HealthEvidence captures the observation details for a WAN link's health.
type HealthEvidence struct {
	State     HealthState `json:"state"`
	Source    string      `json:"source,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	CarrierUp bool        `json:"carrier_up"`
	AdminUp   bool        `json:"admin_up"`
	HasIP     bool        `json:"has_ip"`
	HasRoute  bool        `json:"has_route"`
}

// Member describes one logical WAN uplink.
type Member struct {
	// ID is the logical identifier (e.g. "wan1", "pldt", "converge").
	ID string `json:"id"`

	// Selector is what the operator wrote: stable ID or system name.
	Selector string `json:"selector"`

	// Interface is the observed kernel interface name, empty when unresolved.
	Interface string `json:"interface,omitempty"`

	// StableID is the rename-stable hardware identity.
	StableID string `json:"stable_id,omitempty"`

	// Resolved reports whether the selector matched an observed interface.
	Resolved bool `json:"resolved"`

	// Declared reports whether the selector was declared.
	Declared bool `json:"declared"`

	// Conflict reports whether this member conflicts with another role/interface.
	Conflict bool `json:"conflict,omitempty"`

	// ConflictReason explains a role or duplicate interface conflict.
	ConflictReason string `json:"conflict_reason,omitempty"`

	// Enabled reports whether this member is administratively enabled.
	Enabled bool `json:"enabled"`

	// Priority is preference rank in failover (higher = more preferred, e.g. 100 > 50).
	Priority int `json:"priority"`

	// Weight is relative connection distribution in load_balance (positive integer).
	Weight int `json:"weight"`

	// Gateway is the optional next-hop gateway address.
	Gateway string `json:"gateway,omitempty"`

	// Health records the observed health evidence.
	Health HealthEvidence `json:"health"`
}

// HealthPolicy defines the health-checking parameters.
type HealthPolicy struct {
	Target   string        `json:"target,omitempty"`
	Interval time.Duration `json:"interval,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
}

// Intent represents the operator's desired multi-WAN behavior.
type Intent struct {
	Enabled       bool          `json:"enabled"`
	Mode          Mode          `json:"mode"`
	RoutingPolicy RoutingPolicy `json:"routing_policy"`
	Members       []Member      `json:"members"`
	HealthPolicy  HealthPolicy  `json:"health_policy"`
}

// Verdict is the overall validation outcome.
type Verdict string

const (
	VerdictValid   Verdict = "VALID"
	VerdictPending Verdict = "PENDING"
	VerdictBlocked Verdict = "BLOCKED"
)

// Severity classifies one finding.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

// Stable machine-readable finding codes.
const (
	CodeMultiWANDisabled   = "multiwan-disabled"
	CodeModeInvalid        = "multiwan-mode-invalid"
	CodeMembersEmpty       = "multiwan-members-empty"
	CodeMemberMissing      = "multiwan-member-missing"
	CodeMemberUnresolved   = "multiwan-member-unresolved"
	CodeDuplicateInterface = "multiwan-duplicate-interface"
	CodeDuplicateMemberID  = "multiwan-duplicate-id"
	CodeRoleConflict       = "multiwan-role-conflict"
	CodeWeightInvalid      = "multiwan-weight-invalid"
	CodePriorityInvalid    = "multiwan-priority-invalid"
	CodeAllUnhealthy       = "multiwan-all-unhealthy"
	CodeHealthUnknown      = "multiwan-health-unknown"
	CodeMemberDisabled     = "multiwan-member-disabled"
	CodeSingleModeExcess   = "multiwan-single-mode-excess"
)

// Finding represents one structured diagnostic finding.
type Finding struct {
	Field    string   `json:"field"`
	Code     string   `json:"code,omitempty"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Hint     string   `json:"hint,omitempty"`
}

// Report is the result of validating a Multi-WAN intent.
type Report struct {
	Intent         Intent    `json:"intent"`
	Verdict        Verdict   `json:"verdict"`
	Summary        string    `json:"summary"`
	Findings       []Finding `json:"findings"`
	ActiveMembers  []Member  `json:"active_members"`
	StandbyMembers []Member  `json:"standby_members"`
}

// Blocking returns error-severity findings.
func (r Report) Blocking() []Finding { return r.bySeverity(SeverityError) }

// Warnings returns warning-severity findings.
func (r Report) Warnings() []Finding { return r.bySeverity(SeverityWarning) }

func (r Report) bySeverity(s Severity) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

// EvaluateHealth deduces health evidence safely without network mutation.
func EvaluateHealth(carrierUp, adminUp, hasIP, hasRoute bool, probeOk, probeChecked bool, reason string) HealthEvidence {
	ev := HealthEvidence{
		CarrierUp: carrierUp,
		AdminUp:   adminUp,
		HasIP:     hasIP,
		HasRoute:  hasRoute,
	}

	if !adminUp || !carrierUp {
		ev.State = HealthUnhealthy
		ev.Source = "interface-carrier"
		ev.Reason = "physical link is down or carrier not detected"
		return ev
	}

	if probeChecked {
		if probeOk {
			ev.State = HealthHealthy
			ev.Source = "probe"
			ev.Reason = reason
			if ev.Reason == "" {
				ev.Reason = "probe succeeded; upstream connectivity confirmed"
			}
		} else {
			ev.State = HealthUnknown
			ev.Source = "probe"
			ev.Reason = reason
			if ev.Reason == "" {
				ev.Reason = "probe did not conclude; upstream reachability unproven without mutation"
			}
		}
		return ev
	}

	// Read-only baseline: carrier up and IP present does NOT prove Internet healthy without probing.
	// But it is NOT unhealthy either.
	ev.State = HealthUnknown
	ev.Source = "observation"
	ev.Reason = "interface has carrier, but upstream Internet connectivity was not probed without live network mutation"
	return ev
}

// FromConfig derives Multi-WAN intent from configuration, resolved role bindings,
// and host device observations.
func FromConfig(cfg config.Config, otherRoles map[string]string, dev *host.Device) Intent {
	in := Intent{
		Enabled:       cfg.MultiWAN.Enabled,
		Mode:          Mode(cfg.MultiWAN.Mode),
		RoutingPolicy: RoutingPolicyDefault,
		HealthPolicy: HealthPolicy{
			Target:   cfg.MultiWAN.HealthCheck.Target,
			Interval: cfg.MultiWAN.HealthCheck.Interval,
			Timeout:  cfg.MultiWAN.HealthCheck.Timeout,
		},
	}
	if in.Mode == "" {
		in.Mode = ModeSingle
	}

	// Backward compatibility: If no members are explicitly configured in multi_wan,
	// synthesize a single-member intent from network.wan.
	if len(cfg.MultiWAN.Members) == 0 {
		wanSel := cfg.Network.WAN
		if in.Enabled && wanSel == "" {
			wanSel = "wan"
		}
		if wanSel != "" {
			m := resolveMember(config.WANMemberConfig{
				ID:        "wan",
				Interface: wanSel,
				Weight:    1,
				Priority:  100,
				Enabled:   true,
			}, otherRoles, dev)
			in.Members = append(in.Members, m)
		}
		return in
	}

	for _, mc := range cfg.MultiWAN.Members {
		m := resolveMember(mc, otherRoles, dev)
		in.Members = append(in.Members, m)
	}

	sortMembers(in.Members)
	return in
}

// resolveMember binds a configured WAN member against observed host interfaces.
func resolveMember(mc config.WANMemberConfig, otherRoles map[string]string, dev *host.Device) Member {
	m := Member{
		ID:       mc.ID,
		Selector: mc.Interface,
		Declared: mc.Interface != "",
		Enabled:  mc.Enabled,
		Priority: mc.Priority,
		Weight:   mc.Weight,
		Gateway:  mc.Gateway,
	}
	if m.Priority == 0 {
		m.Priority = 100
	}
	if m.Weight == 0 {
		m.Weight = 1
	}

	if dev == nil || !dev.Supported {
		m.Health = HealthEvidence{
			State:  HealthUnknown,
			Source: "not-observed",
			Reason: "no host observation taken",
		}
		return m
	}

	iface, ok := matchDeviceInterface(dev, m.Selector)
	if ok {
		m.Resolved = true
		m.Interface = iface.SystemName
		m.StableID = iface.ID

		// Check role conflict against LAN, DMZ, GUEST.
		if otherRole, conflict := otherRoles[iface.ID]; conflict {
			m.Conflict = true
			m.ConflictReason = fmt.Sprintf("interface %s (%s) is already assigned to role %s",
				iface.SystemName, iface.ID, otherRole)
		} else if otherRole, conflict := otherRoles[iface.SystemName]; conflict {
			m.Conflict = true
			m.ConflictReason = fmt.Sprintf("interface %s is already assigned to role %s",
				iface.SystemName, otherRole)
		}

		m.Health = EvaluateHealth(iface.LinkUp, iface.AdminUp, len(iface.Addresses) > 0, false, false, false, "")
	} else {
		m.Resolved = false
		m.Health = HealthEvidence{
			State:  HealthUnknown,
			Source: "unresolved",
			Reason: fmt.Sprintf("selector %q did not match any observed interface", m.Selector),
		}
	}

	return m
}

// matchDeviceInterface finds a device interface by ID or SystemName.
func matchDeviceInterface(dev *host.Device, sel string) (host.Interface, bool) {
	for _, i := range dev.Interfaces {
		if i.ID == sel || i.SystemName == sel {
			return i, true
		}
	}
	return host.Interface{}, false
}

// sortMembers orders members deterministically by ID.
func sortMembers(members []Member) {
	sort.SliceStable(members, func(i, j int) bool {
		return members[i].ID < members[j].ID
	})
}

// ValidateIntent validates multi-WAN intent deterministically.
func ValidateIntent(in Intent) Report {
	rep := Report{
		Intent: in,
	}

	if !in.Enabled && len(in.Members) <= 1 {
		rep.Verdict = VerdictValid
		rep.Summary = "multi-WAN routing not requested (single-WAN default)"
		rep.Findings = append(rep.Findings, Finding{
			Field:    "enabled",
			Code:     CodeMultiWANDisabled,
			Severity: SeverityInfo,
			Message:  "multi-WAN management is not enabled; using standard single uplink routing",
			Hint:     "set multi_wan.enabled to true to configure failover or load balancing",
		})
		if len(in.Members) == 1 && in.Members[0].Resolved {
			rep.ActiveMembers = in.Members
		}
		return rep
	}

	if !in.Mode.Valid() {
		rep.Findings = append(rep.Findings, Finding{
			Field:    "mode",
			Code:     CodeModeInvalid,
			Severity: SeverityError,
			Message:  fmt.Sprintf("unknown multi-WAN mode %q", in.Mode),
			Hint:     "supported modes are single, failover, and load_balance",
		})
	}

	if len(in.Members) == 0 {
		rep.Findings = append(rep.Findings, Finding{
			Field:    "members",
			Code:     CodeMembersEmpty,
			Severity: SeverityError,
			Message:  "multi-WAN is enabled but no WAN members are configured",
			Hint:     "configure at least one WAN member under multi_wan.members",
		})
		rep.Verdict = VerdictBlocked
		rep.Summary = "no WAN members configured"
		return rep
	}

	seenIDs := make(map[string]bool)
	seenInterfaces := make(map[string]string) // interface ID/name -> member ID

	unresolvedCount := 0
	conflictCount := 0
	disabledCount := 0
	unhealthyCount := 0

	for _, m := range in.Members {
		// ID check
		if m.ID == "" {
			rep.Findings = append(rep.Findings, Finding{
				Field:    "members",
				Code:     CodeMemberMissing,
				Severity: SeverityError,
				Message:  "a WAN member has no identifier",
				Hint:     "assign a unique id to each member (e.g. wan1, pldt)",
			})
		} else if seenIDs[m.ID] {
			rep.Findings = append(rep.Findings, Finding{
				Field:    "members." + m.ID,
				Code:     CodeDuplicateMemberID,
				Severity: SeverityError,
				Message:  fmt.Sprintf("duplicate WAN member identifier %q", m.ID),
				Hint:     "ensure every member has a distinct id",
			})
		}
		seenIDs[m.ID] = true

		// Selector declaration
		if !m.Declared {
			rep.Findings = append(rep.Findings, Finding{
				Field:    "members." + m.ID + ".interface",
				Code:     CodeMemberMissing,
				Severity: SeverityError,
				Message:  fmt.Sprintf("WAN member %q has no interface selector configured", m.ID),
				Hint:     "specify an interface name or stable ID for this member",
			})
		}

		// Weight validation
		if m.Weight <= 0 {
			rep.Findings = append(rep.Findings, Finding{
				Field:    "members." + m.ID + ".weight",
				Code:     CodeWeightInvalid,
				Severity: SeverityError,
				Message:  fmt.Sprintf("WAN member %q has invalid weight %d; weight must be positive", m.ID, m.Weight),
				Hint:     "set weight to a positive integer (e.g. 1, 2, 3)",
			})
		}

		// Priority validation
		if m.Priority < 0 {
			rep.Findings = append(rep.Findings, Finding{
				Field:    "members." + m.ID + ".priority",
				Code:     CodePriorityInvalid,
				Severity: SeverityError,
				Message:  fmt.Sprintf("WAN member %q has negative priority %d", m.ID, m.Priority),
				Hint:     "priority must be non-negative (e.g. 100 for primary, 50 for backup)",
			})
		}

		// Resolution & Conflicts
		if m.Conflict {
			conflictCount++
			rep.Findings = append(rep.Findings, Finding{
				Field:    "members." + m.ID + ".interface",
				Code:     CodeRoleConflict,
				Severity: SeverityError,
				Message:  fmt.Sprintf("WAN member %q conflict: %s", m.ID, m.ConflictReason),
				Hint:     "WAN members cannot share physical interfaces with LAN, DMZ, or other roles",
			})
		} else if m.Resolved {
			targetKey := m.StableID
			if targetKey == "" {
				targetKey = m.Interface
			}
			if targetKey == "" {
				targetKey = m.Selector
			}
			if targetKey != "" {
				if otherMember, exists := seenInterfaces[targetKey]; exists {
					rep.Findings = append(rep.Findings, Finding{
						Field:    "members." + m.ID + ".interface",
						Code:     CodeDuplicateInterface,
						Severity: SeverityError,
						Message: fmt.Sprintf("WAN members %q and %q claim the same physical interface %s",
							otherMember, m.ID, targetKey),
						Hint: "each WAN member must use a distinct network interface",
					})
				} else {
					seenInterfaces[targetKey] = m.ID
				}
			}
		} else if m.Declared {
			unresolvedCount++
			rep.Findings = append(rep.Findings, Finding{
				Field:    "members." + m.ID + ".interface",
				Code:     CodeMemberUnresolved,
				Severity: SeverityWarning,
				Message: fmt.Sprintf("WAN member %q selector %q has not been resolved against a host interface",
					m.ID, m.Selector),
				Hint: "attach the physical network interface or verify the selector",
			})
		}

		if !m.Enabled {
			disabledCount++
			rep.Findings = append(rep.Findings, Finding{
				Field:    "members." + m.ID + ".enabled",
				Code:     CodeMemberDisabled,
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("WAN member %q is administratively disabled", m.ID),
				Hint:     "set enabled to true to participate in routing",
			})
		}

		if m.Health.State == HealthUnhealthy {
			unhealthyCount++
		}
	}

	// In single mode with multiple active members
	if in.Mode == ModeSingle && len(in.Members) > 1 {
		rep.Findings = append(rep.Findings, Finding{
			Field:    "mode",
			Code:     CodeSingleModeExcess,
			Severity: SeverityInfo,
			Message:  "single mode is selected with multiple members configured; only the primary member will route traffic",
			Hint:     "change mode to failover or load_balance to utilize secondary links",
		})
	}

	// Active and standby member classification
	rep.ActiveMembers, rep.StandbyMembers = partitionMembers(in)

	if len(rep.ActiveMembers) == 0 && len(in.Members) > 0 && conflictCount == 0 && unresolvedCount == 0 {
		rep.Findings = append(rep.Findings, Finding{
			Field:    "members",
			Code:     CodeAllUnhealthy,
			Severity: SeverityWarning,
			Message:  "all configured WAN links are confirmed unhealthy or disabled; Internet routing will be unavailable",
			Hint:     "check physical uplink cables, carrier state, or enable at least one WAN member",
		})
	}

	sortFindings(rep.Findings)
	rep.Verdict = verdictOf(rep.Findings)
	rep.Summary = summarise(rep)
	return rep
}

// partitionMembers divides members into active and standby according to mode,
// health, and priority.
func partitionMembers(in Intent) (active, standby []Member) {
	var eligible []Member
	for _, m := range in.Members {
		if m.Enabled && m.Resolved && !m.Conflict && m.Health.State != HealthUnhealthy {
			eligible = append(eligible, m)
		} else {
			standby = append(standby, m)
		}
	}

	if len(eligible) == 0 {
		return nil, standby
	}

	// Sort eligible by Priority desc, then ID asc (deterministic tie-breaker)
	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].Priority != eligible[j].Priority {
			return eligible[i].Priority > eligible[j].Priority
		}
		return eligible[i].ID < eligible[j].ID
	})

	switch in.Mode {
	case ModeSingle:
		active = append(active, eligible[0])
		standby = append(standby, eligible[1:]...)
	case ModeFailover:
		// Highest priority tier is active, lower priority tiers are standby
		highestPriority := eligible[0].Priority
		for _, m := range eligible {
			if m.Priority == highestPriority {
				active = append(active, m)
			} else {
				standby = append(standby, m)
			}
		}
	case ModeLoadBalance:
		// All healthy eligible members participate
		active = eligible
	default:
		active = append(active, eligible[0])
		standby = append(standby, eligible[1:]...)
	}

	sortMembers(active)
	sortMembers(standby)
	return active, standby
}

// sortFindings sorts findings deterministically by severity rank, field, code.
func sortFindings(in []Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Severity.rank() != b.Severity.rank() {
			return a.Severity.rank() < b.Severity.rank()
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		return a.Code < b.Code
	})
}

// verdictOf reduces findings to a deterministic verdict.
func verdictOf(findings []Finding) Verdict {
	pending := false
	for _, f := range findings {
		switch f.Severity {
		case SeverityError:
			return VerdictBlocked
		case SeverityWarning:
			pending = true
		}
	}
	if pending {
		return VerdictPending
	}
	return VerdictValid
}

// summarise generates the one-line summary for human output.
func summarise(rep Report) string {
	switch rep.Verdict {
	case VerdictValid:
		if len(rep.ActiveMembers) > 1 {
			return fmt.Sprintf("multi-WAN routing ready: %d active uplink(s) in %s mode (session-distributed)",
				len(rep.ActiveMembers), rep.Intent.Mode)
		}
		return fmt.Sprintf("uplink routing ready: 1 active uplink in %s mode", rep.Intent.Mode)
	case VerdictPending:
		return fmt.Sprintf("multi-WAN configuration is incomplete: %d warning(s), nothing blocking",
			len(rep.Warnings()))
	default:
		return fmt.Sprintf("multi-WAN routing cannot be built as configured: %d blocking finding(s)",
			len(rep.Blocking()))
	}
}

// Summary renders human-readable multi-WAN intent summary.
func (in Intent) Summary() string {
	var b strings.Builder
	modeLabel := in.Mode.String()
	if modeLabel == "" {
		modeLabel = "single"
	}
	fmt.Fprintf(&b, "Multi-WAN: %s (mode: %s)\n", enabledLabel(in.Enabled), modeLabel)
	fmt.Fprintf(&b, "Routing:  connection/session affinity (non-bonding)\n")
	if len(in.Members) == 0 {
		fmt.Fprintf(&b, "Members:  (none configured)\n")
		return b.String()
	}

	fmt.Fprintf(&b, "Members:  %d configured\n", len(in.Members))
	for _, m := range in.Members {
		status := "unresolved"
		if m.Resolved {
			status = fmt.Sprintf("%s [%s]", m.Interface, m.StableID)
		}
		stateStr := string(m.Health.State)
		if stateStr == "" {
			stateStr = "unknown"
		}
		fmt.Fprintf(&b, "  - %-10s -> %-24s priority: %-4d weight: %-3d health: %s\n",
			m.ID, status, m.Priority, m.Weight, stateStr)
	}

	return b.String()
}

func enabledLabel(on bool) string {
	if on {
		return "requested"
	}
	return "standard (single uplink)"
}
