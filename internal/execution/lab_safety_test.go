package execution

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type mockLabRunner struct {
	linksJSON string
}

func (m *mockLabRunner) LookPath(file string) (string, error) {
	return "/bin/" + file, nil
}

func (m *mockLabRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if name == "ip" && len(args) >= 3 && args[len(args)-1] == "show" {
		return m.linksJSON, "", nil
	}
	return "", "", nil
}

func writeLabMarker(t *testing.T, path string, marker LabMarkerContent) {
	t.Helper()
	data, err := json.Marshal(marker)
	if err != nil {
		t.Fatalf("marshal lab marker: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write lab marker: %v", err)
	}
}

func TestLabSafetyVerification(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	markerPath := filepath.Join(tempDir, "lab-environment.json")

	validMarker := LabMarkerContent{
		Disposable:    true,
		EnvironmentID: "thn-disposable-lab-vm-m6.1",
		Topology:      "disposable-lan",
		WANInterface:  "eth0",
		LANInterface:  "eth1",
		LANSubnet:     "10.77.0.0/24",
	}

	validLinks := `[
		{"ifname": "lo", "address": "00:00:00:00:00:00"},
		{"ifname": "eth0", "address": "52:54:00:12:34:56"},
		{"ifname": "eth1", "address": "52:54:00:78:9a:bc"}
	]`

	// 1. Missing lab marker -> BLOCKED
	cfgMissingMarker := DefaultLabConfig()
	cfgMissingMarker.MarkerPath = filepath.Join(tempDir, "non-existent.json")
	runner := &mockLabRunner{linksJSON: validLinks}

	err := VerifyLabEnvironment(ctx, cfgMissingMarker, runner)
	if err == nil || !errors.Is(err, ErrLabVerificationFailed) {
		t.Errorf("expected ErrLabVerificationFailed for missing marker, got %v", err)
	}

	// 2. Marker with disposable=false -> BLOCKED
	writeLabMarker(t, markerPath, LabMarkerContent{
		Disposable:    false,
		EnvironmentID: "thn-disposable-lab-vm-m6.1",
	})
	cfgNotDisposable := DefaultLabConfig()
	cfgNotDisposable.MarkerPath = markerPath
	err = VerifyLabEnvironment(ctx, cfgNotDisposable, runner)
	if err == nil || !errors.Is(err, ErrLabVerificationFailed) {
		t.Errorf("expected ErrLabVerificationFailed when disposable=false, got %v", err)
	}

	// 3. Execution mode is production -> BLOCKED
	writeLabMarker(t, markerPath, validMarker)
	cfgProdMode := DefaultLabConfig()
	cfgProdMode.MarkerPath = markerPath
	cfgProdMode.Mode = ExecutionModeProduction
	err = VerifyLabEnvironment(ctx, cfgProdMode, runner)
	if err == nil || !errors.Is(err, ErrLabVerificationFailed) {
		t.Errorf("expected ErrLabVerificationFailed for production mode, got %v", err)
	}

	// 4. Production Dell MAC detected -> BLOCKED
	dellLinks := `[
		{"ifname": "enp0s31f6", "address": "7c:61:70:fd:7f:34"},
		{"ifname": "eth1", "address": "52:54:00:78:9a:bc"}
	]`
	dellRunner := &mockLabRunner{linksJSON: dellLinks}
	cfgValid := DefaultLabConfig()
	cfgValid.MarkerPath = markerPath
	cfgValid.ExpectedWAN = "eth0"
	cfgValid.ExpectedLAN = "eth1"

	err = VerifyLabEnvironment(ctx, cfgValid, dellRunner)
	if err == nil || !errors.Is(err, ErrLabVerificationFailed) {
		t.Errorf("expected ErrLabVerificationFailed when production Dell MAC is detected, got %v", err)
	}

	// 5. Forbidden production interface detected (tailscale0 / docker0) -> BLOCKED
	tailscaleLinks := `[
		{"ifname": "eth0", "address": "52:54:00:12:34:56"},
		{"ifname": "tailscale0", "address": "00:00:00:00:00:00"}
	]`
	tailscaleRunner := &mockLabRunner{linksJSON: tailscaleLinks}
	err = VerifyLabEnvironment(ctx, cfgValid, tailscaleRunner)
	if err == nil || !errors.Is(err, ErrLabVerificationFailed) {
		t.Errorf("expected ErrLabVerificationFailed when tailscale0 is detected, got %v", err)
	}

	// 6. Valid disposable lab environment -> PASSES
	validCfg := DefaultLabConfig()
	validCfg.MarkerPath = markerPath
	validCfg.ExpectedWAN = "eth0"
	validCfg.ExpectedLAN = "eth1"
	validLabRunner := &mockLabRunner{linksJSON: validLinks}

	if err := VerifyLabEnvironment(ctx, validCfg, validLabRunner); err != nil {
		t.Errorf("expected VerifyLabEnvironment to succeed on valid disposable lab, got: %v", err)
	}
}
