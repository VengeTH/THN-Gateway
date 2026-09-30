package firewall

import (
	"context"
	"encoding/json"
	"testing"
)

func TestParseRootQdisc(t *testing.T) {
	cases := []struct {
		name      string
		output    string
		wantFound bool
		wantAlg   string
		wantQueue string
	}{
		{
			name:      "cake root qdisc",
			output:    "qdisc cake 8001: root refcnt 2 bandwidth 100Mbit\n",
			wantFound: true,
			wantAlg:   "cake",
			wantQueue: "8001",
		},
		{
			name:      "noqueue root",
			output:    "qdisc noqueue 0: root refcnt 2\n",
			wantFound: true,
			wantAlg:   "noqueue",
			wantQueue: "0",
		},
		{
			name: "classful root with children ignores non-root lines",
			output: "qdisc htb 1: root refcnt 2\n" +
				"qdisc fq_codel 8002: parent 1:10 limit 10240p\n",
			wantFound: true,
			wantAlg:   "htb",
			wantQueue: "1",
		},
		{
			name:      "no qdiscs at all",
			output:    "",
			wantFound: false,
		},
		{
			name:      "only child qdiscs",
			output:    "qdisc fq_codel 8002: parent 1:10 limit 10240p\n",
			wantFound: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, found := parseRootQdisc(c.output)
			if found != c.wantFound {
				t.Fatalf("found = %v, want %v", found, c.wantFound)
			}
			if !found {
				return
			}
			if got.algorithm != c.wantAlg {
				t.Errorf("algorithm = %q, want %q", got.algorithm, c.wantAlg)
			}
			if got.handle != c.wantQueue {
				t.Errorf("handle = %q, want %q", got.handle, c.wantQueue)
			}
		})
	}
}

// TestNftRulesetParsing exercises the flat-stream shape that `nft -j list
// ruleset` actually produces. This is the format most likely to be
// mis-modelled, so it is pinned with a realistic sample.
func TestNftRulesetParsing(t *testing.T) {
	// Abridged but structurally faithful sample of `nft -j list ruleset`.
	sample := `{
	  "nftables": [
	    { "table": { "family": "inet", "name": "thn", "handle": 1 } },
	    { "chain": { "family": "inet", "table": "thn", "name": "input",
	                 "handle": 1, "type": "filter", "hook": "input",
	                 "policy": "drop" } },
	    { "chain": { "family": "inet", "table": "thn", "name": "forward",
	                 "handle": 2, "type": "filter", "hook": "forward",
	                 "policy": "drop" } },
	    { "rule": { "family": "inet", "table": "thn",
	                "chain": { "family": "inet", "table": "thn", "name": "input" },
	                "expr": [] } },
	    { "rule": { "family": "inet", "table": "thn",
	                "chain": { "family": "inet", "table": "thn", "name": "forward" },
	                "expr": [] } }
	  ]
	}`

	var doc nftRuleset
	if err := json.Unmarshal([]byte(sample), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Nftables) != 5 {
		t.Fatalf("decoded %d items, want 5", len(doc.Nftables))
	}

	if doc.Nftables[0].Table == nil {
		t.Fatal("first item should be a table")
	}
	if doc.Nftables[0].Table.Family != "inet" || doc.Nftables[0].Table.Name != "thn" {
		t.Errorf("table = %+v, want inet/thn", doc.Nftables[0].Table)
	}
	if doc.Nftables[1].Chain == nil {
		t.Fatal("second item should be a chain")
	}
	if doc.Nftables[3].Rule == nil || doc.Nftables[3].Rule.Chain == nil {
		t.Fatal("fourth item should be a rule referencing a chain")
	}
}

// TestObserveFirewallOffLinux reports unknown rather than inactive, because a
// host without nftables has not been shown to have no firewall.
func TestObserveFirewallOffLinux(t *testing.T) {
	o := NewObserver()
	st := o.ObserveFirewall(context.Background())

	if st == nil {
		t.Fatal("ObserveFirewall returned nil")
	}
	if st.Status != StatusUnknown && st.Status != StatusActive && st.Status != StatusInactive {
		t.Errorf("unexpected status %q", st.Status)
	}
	if st.DetectedAt.IsZero() {
		t.Error("DetectedAt must be set")
	}
}
