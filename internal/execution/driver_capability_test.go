package execution

import (
	"context"
	"errors"
	"testing"
)

type mockCapabilityRunner struct {
	availableTools map[string]bool
}

func (m *mockCapabilityRunner) LookPath(file string) (string, error) {
	if m.availableTools[file] {
		return "/usr/sbin/" + file, nil
	}
	return "", errors.New("executable file not found in $PATH")
}

func (m *mockCapabilityRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if m.availableTools[name] {
		return "ok", "", nil
	}
	return "", "not found", errors.New("command not available")
}

func TestLinuxDriverCapabilityDetection(t *testing.T) {
	ctx := context.Background()

	// 1. All capabilities available
	fullRunner := &mockCapabilityRunner{
		availableTools: map[string]bool{"ip": true, "nft": true, "sysctl": true, "tc": true},
	}
	driver := NewLinuxDriver(fullRunner, DefaultLabConfig())
	caps, err := driver.DetectCapabilities(ctx)
	if err != nil {
		t.Fatalf("DetectCapabilities failed: %v", err)
	}

	if !caps.IP || !caps.NFT || !caps.Sysctl || !caps.TC {
		t.Errorf("expected all capabilities true, got %+v", caps)
	}

	sat, missing := caps.Satisfies([]string{"ip", "nft", "sysctl", "tc"})
	if !sat {
		t.Errorf("expected Satisfies=true, got false (%s)", missing)
	}

	// 2. Missing NFT capability
	noNFTRunner := &mockCapabilityRunner{
		availableTools: map[string]bool{"ip": true, "nft": false, "sysctl": true, "tc": true},
	}
	driverNoNFT := NewLinuxDriver(noNFTRunner, DefaultLabConfig())
	capsNoNFT, err := driverNoNFT.DetectCapabilities(ctx)
	if err != nil {
		t.Fatalf("DetectCapabilities failed: %v", err)
	}

	if capsNoNFT.NFT {
		t.Error("expected NFT capability false when nft binary is missing")
	}

	satNoNFT, missingNoNFT := capsNoNFT.Satisfies([]string{"ip", "nft"})
	if satNoNFT {
		t.Error("expected Satisfies=false when nft capability is required but missing")
	}
	if missingNoNFT == "" {
		t.Error("expected missing reason to be non-empty")
	}
}
