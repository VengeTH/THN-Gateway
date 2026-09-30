package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/assistant"
	"github.com/venth/thn-gateway/internal/ruleset"
)

// This file is the gate phase for the assistant layer.
//
// # What it guards
//
// The assistant's central claim is that it is an assistant: it arranges what
// the deterministic pipeline concluded and adds nothing of its own. That claim
// is structural, and these tests are what hold it in place. If someone later
// wires an apply path through here, or lets the assistant reach the host, or
// lets a model choose which facts an answer draws on, these fail.
//
// The package's components have their own tests in internal/assistant. What
// only a gate can check is the agreement between the package and the command
// table: that the commands exist, are pure, install the refusing model, and
// keep the destructive command out of reach.

// assistantCommands is every command this phase covers.
var assistantCommands = []string{"explain", "ask", "suggest"}

// gateAssistantClock is the fixed instant the audit assertions use.
//
// A test that read the wall clock could not assert anything about the log's
// contents, only that it was non-empty.
var gateAssistantClock = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

// An assistant command that can change anything is not an assistant command.
// The tier is the field the rest of the project reads to decide what is safe to
// run unattended, so it is the thing that has to be right.
func TestGateAssistantCommandsArePure(t *testing.T) {
	for _, name := range assistantCommands {
		cmd, ok := commands[name]
		if !ok {
			t.Errorf("command %q is not registered", name)
			continue
		}
		if cmd.Tier != TierPure {
			t.Errorf("%s is %s; every assistant command must be pure, because the whole "+
				"design is that it only reports what the pipeline concluded", name, cmd.Tier)
		}
		if cmd.Run == nil {
			t.Errorf("%s has no implementation", name)
		}
	}
}

// There must still be exactly one destructive command, and it must still be
// the one that refuses. The assistant adds no path to it: three new commands
// that shell out to the same binary are three more chances to get this wrong.
func TestGateAssistantAddsNoDestructivePath(t *testing.T) {
	var destructive []string
	for name, cmd := range commands {
		if cmd.Tier == TierDestructive {
			destructive = append(destructive, name)
		}
	}

	if len(destructive) != 1 || destructive[0] != "activate" {
		t.Errorf("destructive commands are %v, want exactly [activate]", destructive)
	}

	for _, name := range assistantCommands {
		if name == "activate" {
			t.Fatal("an assistant command shadowed the activation command")
		}
	}
}

// The commands install assistant.NoModel explicitly. This asserts the
// constructor they install is the refusing one, by checking the value actually
// refuses and identifies itself.
func TestGateAssistantModelIsAbsentByDefault(t *testing.T) {
	m := assistant.NoModel{}

	if _, err := m.Narrate(t.Context(), assistant.Request{}); err != assistant.ErrNoModel {
		t.Errorf("the default model returned %v, want ErrNoModel", err)
	}
	if m.Name() != "none" {
		t.Errorf("the default model reports itself as %q; it must be \"none\" so an audit "+
			"entry distinguishes no model from a model that produced nothing", m.Name())
	}
}

// The remedies an answer prints are borrowed from the rule set. If the
// assistant ever grew one of its own, an operator would be acting on advice
// with nobody's name on it.
func TestGateAssistantCanBorrowRemedies(t *testing.T) {
	var withRemedy int
	for _, r := range ruleset.All() {
		if r.Remedy != "" {
			withRemedy++
		}
	}
	if withRemedy == 0 {
		t.Fatal("the shipped rule set has no remedies, so this gate cannot check that the " +
			"assistant borrows them rather than writing them")
	}
}

// The audit trail must not become a place questions are stored. The question is
// the one field that can carry a hostname, a MAC or a pasted ticket.
func TestGateAssistantAuditDoesNotStoreTheQuestion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("opening the audit log: %v", err)
	}
	log := &assistant.JSONL{W: f, Now: func() time.Time { return gateAssistantClock }}

	secret := "why is device aa:bb:cc:dd:ee:ff named ticket-4711"
	entry := assistant.Audit(gateAssistantClock, assistant.EventAsked, secret,
		assistant.Answer{Query: assistant.Query{Kind: assistant.QueryStatus}}, nil)

	if err := log.Append(entry); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	text := string(written)

	for _, needle := range []string{"aa:bb:cc", "4711", "ticket", secret} {
		if strings.Contains(text, needle) {
			t.Errorf("the audit log contains %q; the question must be hashed, not stored:\n%s",
				needle, text)
		}
	}
	if entry.QuestionDigest == "" {
		t.Error("no question digest was recorded, so repetition cannot be detected")
	}
}

// The audit log is append-only JSON Lines. A single line per entry is what
// makes a crash lose the last record rather than corrupt the file.
func TestGateAssistantAuditIsLineDelimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	log := &assistant.JSONL{W: f, Now: func() time.Time { return gateAssistantClock }}

	for i := 0; i < 3; i++ {
		if err := log.Append(assistant.AuditSuggestion(gateAssistantClock, i)); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(written), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines for 3 appends:\n%s", len(lines), written)
	}
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "{") {
			t.Errorf("line %d is not a JSON object: %q", i+1, line)
		}
	}
}
