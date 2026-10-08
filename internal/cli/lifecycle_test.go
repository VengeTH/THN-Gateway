package cli

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/artifact"
)

// These tests drive the lifecycle commands end to end.
//
// The package-level tests prove the logic; these prove the wiring. A command
// that reads the wrong file, or passes the wrong gateway to a verifier, is
// just as broken as a wrong comparison, and no unit test above notices.

func writeFile(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// signedFixture produces a signed artifact plus a trust file, and returns their
// paths.
func signedFixture(t *testing.T, dir string, mutate func(*artifact.Metadata)) (string, string) {
	t.Helper()

	signer, err := artifact.GenerateSigner("key-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	meta := artifact.Metadata{
		Version: artifact.FormatVersion, Org: "acme", Gateway: "site-001",
		Generation: 41, IssuedAt: now,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		Labels: map[string]string{"rollout": "canary"},
	}
	if mutate != nil {
		mutate(&meta)
	}

	env, err := signer.Sign(meta, []byte("wan: enp0s31f6\nlan: enx001122334455\n"), now)
	if err != nil {
		t.Fatal(err)
	}
	envJSON, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	trust := map[string]any{
		"keys": map[string]string{
			"key-1": base64.StdEncoding.EncodeToString(signer.Public().Key),
		},
		"revoked": map[string]string{},
	}
	trustJSON, err := json.MarshalIndent(trust, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	return writeFile(t, dir, "artifact.json", envJSON),
		writeFile(t, dir, "trust.json", trustJSON)
}

func runVerifyCmd(t *testing.T, args ...string) (string, string) {
	t.Helper()
	env, out, errOut := newTestEnv(args...)
	runVerify(env, args)
	return out.String(), errOut.String()
}

// A genuine artifact from a trusted key is accepted, and the command says what
// it accepted.
func TestVerifyAcceptsAGenuineArtifact(t *testing.T) {
	dir := t.TempDir()
	artifactPath, trustPath := signedFixture(t, dir, nil)

	out, _ := runVerifyCmd(t,
		"--file", artifactPath, "--key", trustPath,
		"--org", "acme", "--gateway", "site-001")

	if !strings.Contains(out, "ACCEPTED") {
		t.Fatalf("a genuine artifact was not accepted:\n%s", out)
	}
	for _, want := range []string{"site-001", "acme", "41", "key-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not mention %q:\n%s", want, out)
		}
	}
	// And it must say the generation has to be persisted, because a verifier
	// that forgets can be replayed against next time it runs.
	if !strings.Contains(out, "Persist this generation") {
		t.Errorf("the output does not warn about persisting the generation:\n%s", out)
	}
}

// An artifact from a key the gateway does not trust is refused.
func TestVerifyRefusesAnUnknownKey(t *testing.T) {
	dir := t.TempDir()
	artifactPath, _ := signedFixture(t, dir, nil)

	emptyTrust := writeFile(t, dir, "empty-trust.json",
		[]byte(`{"keys":{},"revoked":{}}`))

	// The refusal is a report, so it goes to stdout: an operator reading the
	// command's output needs to see why it said no.
	out, _ := runVerifyCmd(t,
		"--file", artifactPath, "--key", emptyTrust,
		"--org", "acme", "--gateway", "site-001")

	if !strings.Contains(out, "REFUSED") {
		t.Fatalf("an untrusted key was not refused:\n%s", out)
	}
	if !strings.Contains(out, "not trusted") {
		t.Errorf("the refusal does not say the key is untrusted:\n%s", out)
	}
}

// An artifact for one organisation must not be accepted by another.
func TestVerifyRefusesTheWrongOrganisation(t *testing.T) {
	dir := t.TempDir()
	artifactPath, trustPath := signedFixture(t, dir, nil)

	out, _ := runVerifyCmd(t,
		"--file", artifactPath, "--key", trustPath,
		"--org", "other-co", "--gateway", "site-001")

	if !strings.Contains(out, "REFUSED") {
		t.Fatalf("an artifact from another organisation was accepted:\n%s", out)
	}
}

// Replay protection has to reach the command, not just the package.
func TestVerifyRefusesAReplayedGeneration(t *testing.T) {
	dir := t.TempDir()
	artifactPath, trustPath := signedFixture(t, dir, nil)

	out, _ := runVerifyCmd(t,
		"--file", artifactPath, "--key", trustPath,
		"--org", "acme", "--gateway", "site-001",
		"--min-generation", "50")

	if !strings.Contains(out, "REFUSED") {
		t.Fatalf("an artifact below the persisted floor was accepted:\n%s", out)
	}
}

func TestVerifyRequiresAFile(t *testing.T) {
	_, errOut := runVerifyCmd(t)
	if !strings.Contains(errOut, "--file is required") {
		t.Errorf("the usage message does not say what is required:\n%s", errOut)
	}
}

// Health and rollout have to be wired too, or the gate tests above pass while
// the commands do nothing useful.
func TestHealthReportsAVerdict(t *testing.T) {
	env, out, errOut := newTestEnv("--local")
	runHealth(env, []string{"--local"})

	// On any host this must render a verdict. Which verdict it is depends on
	// the platform; what must not happen is silence or a crash.
	combined := out.String() + errOut.String()
	if !strings.Contains(combined, "Health:") {
		t.Errorf("`thn health` produced no verdict:\n%s", combined)
	}
}

func TestRolloutHaltsOnUnhealthyReports(t *testing.T) {
	dir := t.TempDir()
	reports := writeFile(t, dir, "reports.json", []byte(
		`[{"gateway":"a","verdict":"unhealthy"},{"gateway":"b","verdict":"unhealthy"},`+
			`{"gateway":"c","verdict":"unhealthy"},{"gateway":"d","verdict":"unhealthy"}]`))

	env, out, _ := newTestEnv(
		"--change", "gen-41", "--fleet", "50", "--stage", "small",
		"--reports", reports, "--max-unhealthy", "1")
	code := runRollout(env, []string{
		"--change", "gen-41", "--fleet", "50", "--stage", "small",
		"--reports", reports, "--max-unhealthy", "1",
	})

	if !strings.Contains(out.String(), "rollback") && !strings.Contains(out.String(), "halt") {
		t.Errorf("a fleet of unhealthy gateways did not stop the rollout:\n%s", out.String())
	}
	if code == ExitOK {
		t.Error("the command exited zero after a halting decision")
	}
}

func TestRolloutReportsAKnownHealthyStage(t *testing.T) {
	dir := t.TempDir()
	reports := writeFile(t, dir, "reports.json", []byte(
		`[{"gateway":"a","verdict":"healthy"},{"gateway":"b","verdict":"healthy"}]`))

	env, out, _ := newTestEnv(
		"--change", "gen-41", "--fleet", "50", "--stage", "small", "--reports", reports)
	runRollout(env, []string{
		"--change", "gen-41", "--fleet", "50", "--stage", "small", "--reports", reports,
	})

	if !strings.Contains(out.String(), "Action: advance") {
		t.Errorf("a healthy stage did not advance:\n%s", out.String())
	}
}
