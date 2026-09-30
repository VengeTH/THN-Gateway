package schema

import (
	"strings"
	"testing"
)

func TestCatalogueIsSortedAndComplete(t *testing.T) {
	cat := Catalogue()
	if len(cat) == 0 {
		t.Fatal("catalogue must not be empty")
	}
	for i := 1; i < len(cat); i++ {
		if cat[i].Key <= cat[i-1].Key {
			t.Errorf("catalogue is not sorted: %q then %q", cat[i-1].Key, cat[i].Key)
		}
	}
	for _, f := range cat {
		if f.Key == "" || f.Description == "" {
			t.Errorf("field %+v is missing a key or description", f)
		}
	}
}

func TestKeysMatchCatalogue(t *testing.T) {
	cat := Catalogue()
	keys := Keys()

	if len(cat) != len(keys) {
		t.Errorf("catalogue has %d fields but Keys() returns %d", len(cat), len(keys))
	}
	for i := range cat {
		if cat[i].Key != keys[i] {
			t.Errorf("Keys()[%d] = %q, catalogue has %q", i, keys[i], cat[i].Key)
		}
	}
}

func TestLookup(t *testing.T) {
	f, ok := Lookup("network.lan_prefix")
	if !ok {
		t.Fatal("network.lan_prefix must be in the catalogue")
	}
	if f.Type != TypeCIDR {
		t.Errorf("type = %q, want %q", f.Type, TypeCIDR)
	}
	if !f.Mutating {
		t.Error("lan_prefix changes host networking and must be marked mutating")
	}

	if _, ok := Lookup("network.nonexistent"); ok {
		t.Error("Lookup must not find an unknown key")
	}
}

// TestMutatingKeysAreAccurate locks in which settings change the host. The
// `thn plan` risk summary and the operator's mental model both depend on this
// list being right.
func TestMutatingKeysAreAccurate(t *testing.T) {
	mut := MutatingKeys()
	if len(mut) == 0 {
		t.Fatal("expected some mutating keys")
	}

	// Settings that must be marked mutating.
	for _, k := range []string{
		"network.wan", "network.lan", "network.lan_prefix", "network.mtu",
		"nat.enabled", "firewall.enabled", "qos.enabled",
	} {
		if !Mutating(k) {
			t.Errorf("%q changes host networking and must be marked mutating", k)
		}
	}

	// Settings that must not be marked mutating: they affect only THN itself.
	for _, k := range []string{
		"logging.level", "logging.format", "paths.state_db", "paths.socket",
		"gateway.name",
	} {
		if Mutating(k) {
			t.Errorf("%q does not change host networking and must not be marked mutating", k)
		}
	}

	for i := 1; i < len(mut); i++ {
		if mut[i] <= mut[i-1] {
			t.Errorf("MutatingKeys is not sorted: %q then %q", mut[i-1], mut[i])
		}
	}
}

func TestEnumFieldsDeclareTheirValues(t *testing.T) {
	for _, f := range Catalogue() {
		if f.Type == TypeEnum && len(f.Enum) == 0 {
			t.Errorf("field %q is an enum but declares no permitted values", f.Key)
		}
	}
}

// TestPhysicalPresenceIsRequired locks in the safety property that the
// physical-presence gate must remain required. If this ever became optional,
// remote root access would by itself permit activation of an unattended
// device, which is the failure mode this project exists to prevent.
func TestPhysicalPresenceIsRequired(t *testing.T) {
	f, ok := Lookup("activation.require_physical_presence")
	if !ok {
		t.Fatal("activation.require_physical_presence must be in the catalogue")
	}
	if !f.Required {
		t.Error("activation.require_physical_presence must be marked required")
	}
	if f.Default != "true" {
		t.Errorf("default = %q, want \"true\"", f.Default)
	}
}

func TestCheckVersion(t *testing.T) {
	if err := CheckVersion(Version); err != nil {
		t.Errorf("the current version must be accepted, got %v", err)
	}
	if err := CheckVersion(MinimumVersion); err != nil {
		t.Errorf("the minimum version must be accepted, got %v", err)
	}
	if err := CheckVersion(Version + 1); err == nil {
		t.Error("a newer schema version must be rejected")
	}
	if err := CheckVersion(0); err == nil {
		t.Error("version zero must be rejected")
	}
	if err := CheckVersion(-1); err == nil {
		t.Error("a negative version must be rejected")
	}
}

func TestUnsupportedVersionErrorIsActionable(t *testing.T) {
	err := CheckVersion(Version + 5)
	if err == nil {
		t.Fatal("expected an error")
	}

	msg := err.Error()
	// The message must tell an operator what to do, not just what went wrong.
	if !strings.Contains(msg, "upgrade") {
		t.Errorf("error should suggest upgrading, got: %s", msg)
	}
	if !strings.Contains(msg, "rather than editing") {
		t.Errorf("error should warn against hand-editing the version, got: %s", msg)
	}
}

func TestSuggestFindsCloseKeys(t *testing.T) {
	cases := []struct {
		unknown string
		wantAny []string
	}{
		{"network.wan_interface", []string{"network.wan"}},
		{"network.lan_prefix_len", []string{"network.lan_prefix"}},
		{"firewall.defualt_inbound_policy", []string{"firewall.default_inbound_policy"}},
		{"qos.algorthm", []string{"qos.algorithm"}},
	}

	for _, c := range cases {
		got := Suggest(c.unknown)
		if len(got) == 0 {
			t.Errorf("Suggest(%q) returned nothing; the strict loader must stay usable", c.unknown)
			continue
		}
		var matched bool
		for _, g := range got {
			for _, w := range c.wantAny {
				if g == w {
					matched = true
				}
			}
		}
		if !matched {
			t.Errorf("Suggest(%q) = %v, want one of %v", c.unknown, got, c.wantAny)
		}
	}
}

func TestSuggestIsBounded(t *testing.T) {
	got := Suggest("x")
	if len(got) > 5 {
		t.Errorf("Suggest returned %d suggestions; it must stay readable", len(got))
	}
}

func TestUnknownKeyErrorNamesSuggestions(t *testing.T) {
	err := &UnknownKeyError{Key: "network.wann", Suggestions: []string{"network.wan"}}

	msg := err.Error()
	if !strings.Contains(msg, "network.wann") {
		t.Errorf("error must name the offending key, got: %s", msg)
	}
	if !strings.Contains(msg, "did you mean") {
		t.Errorf("error must suggest a correction, got: %s", msg)
	}
}

func TestUnknownKeyErrorWithoutSuggestions(t *testing.T) {
	err := &UnknownKeyError{Key: "zzzz"}

	if !strings.Contains(err.Error(), "zzzz") {
		t.Errorf("error must still name the key, got: %s", err.Error())
	}
	if strings.Contains(err.Error(), "did you mean") {
		t.Errorf("error must not suggest when nothing is close, got: %s", err.Error())
	}
}

func TestEditDistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"abc", "ab", 1},
		{"wan", "wann", 1},
	}

	for _, c := range cases {
		if got := editDistance(c.a, c.b); got != c.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestEditDistanceBailsOutOnLargeInputs(t *testing.T) {
	// The bailing-out guard keeps suggestion generation cheap for keys that
	// are nothing like a real one.
	if got := editDistance("completely-different-thing", "network.wan"); got <= 3 {
		t.Errorf("editDistance should exceed the bail-out threshold, got %d", got)
	}
}
