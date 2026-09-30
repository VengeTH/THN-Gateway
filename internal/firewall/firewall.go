// Package firewall implements read-only inspection of the host's packet
// filtering and traffic shaping state.
//
// Like internal/network, this package only observes. `nft list ruleset` and
// `tc qdisc show` are the only external commands involved, both read-only and
// both validated by internal/guard before execution.
//
// The purpose is to let `thn status` answer "is a firewall configured?" and
// `thn plan` answer "what would change?" without any possibility of changing
// anything.
package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/venth/thn-gateway/internal/guard"
)

// Status summarises whether a capability is active on the host.
type Status string

const (
	// StatusActive means the facility is present and configured.
	StatusActive Status = "ACTIVE"
	// StatusInactive means the facility is not configured.
	StatusInactive Status = "NOT ACTIVE"
	// StatusUnknown means the state could not be determined, usually because
	// the tooling is not installed.
	StatusUnknown Status = "UNKNOWN"
)

// FirewallState is an observed packet filter configuration.
type FirewallState struct {
	// Status reports whether filtering is active.
	Status Status `json:"status"`
	// Backend is the detected firewall backend, e.g. "nftables".
	Backend string `json:"backend,omitempty"`
	// Tables are the observed nftables tables.
	Tables []NftTable `json:"tables,omitempty"`
	// RuleCount is the total number of rules observed.
	RuleCount int `json:"rule_count"`
	// DetectedAt is when the observation was taken.
	DetectedAt time.Time `json:"detected_at"`
	// Diagnostics records why the state could not be read, if it could not.
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// NftTable is an observed nftables table.
type NftTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle,omitempty"`
	// Rules are the table's rule chains.
	Rules []NftChain `json:"rules,omitempty"`
}

// NftChain is an observed nftables chain.
type NftChain struct {
	Name string `json:"name"`
	Hook string `json:"hook,omitempty"`
	// Policy is the chain's base policy for base chains.
	Policy string `json:"policy,omitempty"`
	// Priority orders the chain relative to others on the same hook.
	Priority string `json:"priority,omitempty"`
}

// Diagnostic is an inspection finding.
type Diagnostic struct {
	Subject  string `json:"subject"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// QoSState is an observed traffic shaping configuration.
type QoSState struct {
	// Status reports whether shaping is active.
	Status Status `json:"status"`
	// Algorithm is the detected algorithm, e.g. "cake".
	Algorithm string `json:"algorithm,omitempty"`
	// Device is the shaped interface.
	Device string `json:"device,omitempty"`
	// Queue is the observed queue discipline description.
	Queue string `json:"queue,omitempty"`
	// DetectedAt is when the observation was taken.
	DetectedAt time.Time `json:"detected_at"`
	// Diagnostics records why the state could not be read, if it could not.
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// Observer reads firewall and shaping state.
type Observer interface {
	// ObserveFirewall returns the observed packet filter state.
	ObserveFirewall(ctx context.Context) *FirewallState
	// ObserveQoS returns the observed shaping state on device. An empty
	// device inspects every root discipline without attributing it to an
	// interface.
	ObserveQoS(ctx context.Context, device string) *QoSState
}

// NewObserver returns an Observer for the current platform.
func NewObserver() Observer { return &observer{} }

type observer struct{}

// ObserveFirewall reads the nftables ruleset.
//
// A missing nft binary is reported as UNKNOWN with an explanatory diagnostic
// rather than as "inactive". The distinction matters: an operator who has not
// installed nftables needs to know the question was not answered, not that
// the answer is "no firewall".
func (o *observer) ObserveFirewall(ctx context.Context) *FirewallState {
	st := &FirewallState{
		Status:     StatusUnknown,
		DetectedAt: time.Now().UTC(),
	}

	out, err := guard.Exec(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		sev := "warning"
		msg := fmt.Sprintf("could not read the nftables ruleset: %v", err)
		if strings.Contains(err.Error(), "executable file not found") ||
			strings.Contains(err.Error(), "cannot find") {
			msg = "nftables tooling is not installed on this host, so firewall state could not be determined"
		}
		st.Status = StatusUnknown
		st.Diagnostics = append(st.Diagnostics, Diagnostic{
			Subject: "firewall", Severity: sev, Message: msg,
		})
		return st
	}

	var doc nftRuleset
	if err := json.Unmarshal([]byte(out.Stdout), &doc); err != nil {
		st.Status = StatusUnknown
		st.Diagnostics = append(st.Diagnostics, Diagnostic{
			Subject:  "firewall",
			Severity: "warning",
			Message:  fmt.Sprintf("could not parse the nftables ruleset: %v", err),
		})
		return st
	}

	st.Backend = "nftables"

	// `nft -j list ruleset` emits a flat stream of objects: a table object,
	// then chain objects and rule objects that reference it by family+name.
	// Tables are therefore accumulated in a map keyed by family and name,
	// and chains are attached as they are encountered. Iterating the stream
	// once and merging afterwards keeps that shape explicit.
	type tableKey struct{ family, name string }
	tables := map[tableKey]*NftTable{}

	for _, item := range doc.Nftables {
		switch {
		case item.Table != nil:
			k := tableKey{item.Table.Family, item.Table.Name}
			if _, seen := tables[k]; !seen {
				tables[k] = &NftTable{
					Family: item.Table.Family,
					Name:   item.Table.Name,
					Handle: item.Table.Handle,
				}
			}

		case item.Chain != nil:
			k := tableKey{item.Chain.Family, item.Chain.Table}
			t, ok := tables[k]
			if !ok {
				// A chain whose table was not declared first would indicate
				// an unrecognised output shape; skip it rather than
				// attributing it to the wrong table.
				continue
			}
			t.Rules = append(t.Rules, chainFromJSON(item.Chain))

		case item.Rule != nil && item.Rule.Chain != nil:
			k := tableKey{item.Rule.Chain.Family, item.Rule.Chain.Table}
			if _, ok := tables[k]; !ok {
				continue
			}
			st.RuleCount++
		}
	}

	for _, t := range tables {
		sort.Slice(t.Rules, func(a, b int) bool { return t.Rules[a].Name < t.Rules[b].Name })
		st.Tables = append(st.Tables, *t)
	}
	sort.Slice(st.Tables, func(a, b int) bool {
		if st.Tables[a].Family != st.Tables[b].Family {
			return st.Tables[a].Family < st.Tables[b].Family
		}
		return st.Tables[a].Name < st.Tables[b].Name
	})

	if len(st.Tables) == 0 {
		st.Status = StatusInactive
	} else {
		st.Status = StatusActive
	}
	return st
}

// ObserveQoS reads the root queue discipline on device.
//
// The device is a parameter rather than a discovery step because `tc qdisc
// show` does not report which interface a discipline is attached to; that
// information only appears when the query is scoped with `dev`. Passing an
// empty device inspects every root discipline, which is useful for discovery
// but cannot attribute the result to an interface.
func (o *observer) ObserveQoS(ctx context.Context, device string) *QoSState {
	st := &QoSState{
		Status:     StatusUnknown,
		Device:     device,
		DetectedAt: time.Now().UTC(),
	}

	args := []string{"qdisc", "show"}
	if device != "" {
		args = append(args, "dev", device)
	}

	out, err := guard.Exec(ctx, "tc", args...)
	if err != nil {
		st.Diagnostics = append(st.Diagnostics, Diagnostic{
			Subject:  "qos",
			Severity: "warning",
			Message:  fmt.Sprintf("could not read queue disciplines: %v", err),
		})
		return st
	}

	// tc has no JSON form for qdisc, so the text output is parsed. Lines look
	// like: qdisc cake 8001: root refcnt 2 bandwidth 100Mbit
	root, found := parseRootQdisc(out.Stdout)
	if !found {
		st.Status = StatusInactive
		return st
	}

	st.Queue = root.handle
	st.Algorithm = root.algorithm
	st.Status = StatusActive
	return st
}

// qdiscLine is a parsed `tc qdisc show` line.
type qdiscLine struct {
	handle    string
	algorithm string
	isRoot    bool
}

// parseRootQdisc extracts the first root queue discipline from tc output.
func parseRootQdisc(output string) (qdiscLine, bool) {
	for _, raw := range strings.Split(output, "\n") {
		fields := strings.Fields(raw)
		// Expected shape: qdisc <algorithm> <handle>: root ...
		if len(fields) < 4 || fields[0] != "qdisc" {
			continue
		}

		line := qdiscLine{
			algorithm: fields[1],
			handle:    strings.TrimSuffix(fields[2], ":"),
		}
		// The parent token immediately follows the handle. On a root
		// discipline it reads "root"; otherwise "parent <handle>".
		if fields[3] == "root" {
			line.isRoot = true
		}
		if line.isRoot {
			return line, true
		}
	}
	return qdiscLine{}, false
}

// chainFromJSON converts a decoded chain object into the public shape.
func chainFromJSON(c *nftChainJSON) NftChain {
	return NftChain{
		Name:     c.Name,
		Hook:     c.Hook,
		Policy:   c.Policy,
		Priority: c.Priority,
	}
}

// nftRuleset mirrors `nft -j list ruleset`.
//
// The stream is flat: table, chain and rule objects are siblings, each
// identifying its parent by family and table name rather than by nesting.
type nftRuleset struct {
	Nftables []nftItem `json:"nftables"`
}

type nftItem struct {
	Table *nftTableJSON `json:"table,omitempty"`
	Chain *nftChainJSON `json:"chain,omitempty"`
	Rule  *nftRuleJSON  `json:"rule,omitempty"`
}

type nftTableJSON struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
}

type nftRuleJSON struct {
	Family string        `json:"family"`
	Table  string        `json:"table"`
	Chain  *nftChainJSON `json:"chain,omitempty"`
}

type nftChainJSON struct {
	Name     string `json:"name"`
	Family   string `json:"family"`
	Table    string `json:"table"`
	Hook     string `json:"hook"`
	Policy   string `json:"policy"`
	Priority string `json:"priority"`
}
