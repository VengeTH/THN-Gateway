package execution

import (
	"context"
	"errors"
	"fmt"
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

// policyRunner applies THN's real command policy before reporting a tool as
// present. It is the seam the disposable lab uses: namespaceRunner validates
// with ValidateCommand and then runs, so the driver is judged by the same rules
// it ships with.
type policyRunner struct {
	tools map[string]bool
}

func (p *policyRunner) LookPath(file string) (string, error) {
	if p.tools[file] {
		return "/usr/sbin/" + file, nil
	}
	return "", errors.New("executable file not found in $PATH")
}

func (p *policyRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	if !p.tools[name] {
		return "", "not found", errors.New("command not available")
	}
	if err := ValidateCommand(name, args...); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrDisallowedCommand, err)
	}
	return "ok", "", nil
}

// TestLinuxDriverProbesSurviveTheRealCommandPolicy is the test that was
// missing, and it is the one that would have caught this.
//
// mockCapabilityRunner answers from a map. It never validates anything, so
// every probe DetectCapabilities issues passed unconditionally and the driver
// looked healthy in every test — while on a real host, behind the validator the
// shipped driver actually enforces, its own `tc qdisc show` probe was refused.
// The driver was therefore only ever tested against a mock more permissive
// than reality.
//
// This one runs the probes through ValidateCommand. A probe the driver cannot
// issue is a probe that will report a working tool as absent.
func TestLinuxDriverProbesSurviveTheRealCommandPolicy(t *testing.T) {
	runner := &policyRunner{tools: map[string]bool{
		"ip": true, "nft": true, "sysctl": true, "tc": true,
	}}
	d := NewLinuxDriver(runner, DefaultLabConfig())

	caps, err := d.DetectCapabilities(context.Background())
	if err != nil {
		t.Fatalf("DetectCapabilities failed: %v", err)
	}

	for _, c := range []struct {
		name string
		got  bool
	}{
		{"ip", caps.IP},
		{"nft", caps.NFT},
		{"sysctl", caps.Sysctl},
		{"tc", caps.TC},
	} {
		if !c.got {
			t.Errorf("capability %q reported absent on a host that has it; "+
				"the driver's own probe was refused by ValidateCommand: %s",
				c.name, caps.Details[c.name])
		}
	}

	if sat, missing := caps.Satisfies([]string{"ip", "nft", "sysctl", "tc"}); !sat {
		t.Errorf("Satisfies = false on a fully capable host: %s", missing)
	}
}
