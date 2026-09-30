package state

import (
	"encoding/json"
	"fmt"
)

// marshalAttrs renders event attributes as a JSON object. encoding/json
// already emits map keys in sorted order, so the output is deterministic
// without extra work.
func marshalAttrs(attrs map[string]string) (string, error) {
	if len(attrs) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(attrs)
	if err != nil {
		return "", fmt.Errorf("encoding event attributes: %w", err)
	}
	return string(b), nil
}

// unmarshalAttrs parses a stored attributes document. A malformed value
// returns nil rather than an error: a diagnostic reader should still be able
// to show the event even if its attributes are unreadable.
func unmarshalAttrs(raw string) map[string]string {
	if raw == "" || raw == "{}" {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
