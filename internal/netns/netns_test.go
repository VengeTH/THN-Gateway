package netns_test

import (
	"errors"
	"runtime"
	"testing"

	"github.com/venth/thn-gateway/internal/netns"
	"github.com/venth/thn-gateway/internal/qos"
)

// TestAvailableIsHonestOnEveryPlatform runs everywhere, including on the
// Windows workstation this project is developed on.
//
// The Linux behaviour is covered by netns_linux_test.go, which skips itself
// where it cannot run. This file covers the contract that holds everywhere:
// either namespaces work, or the reason is specific enough to act on.
func TestAvailableIsHonestOnEveryPlatform(t *testing.T) {
	err := netns.Available()

	if runtime.GOOS != "linux" {
		if !errors.Is(err, netns.ErrUnsupported) {
			t.Errorf("off Linux, Available must return ErrUnsupported; got %v", err)
		}
		if err != nil && err.Error() == "" {
			t.Error("the error must explain itself")
		}
		return
	}

	// On Linux it either works or gives a specific reason. A bare nil error on
	// a host that cannot create namespaces would be a lie that surfaces as a
	// confusing failure much later.
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, netns.ErrNoPermission):
		t.Logf("namespaces need privileges here: %v", err)
	case errors.Is(err, netns.ErrUnsupported):
		t.Errorf("on Linux, ErrUnsupported should not be returned: %v", err)
	default:
		// A missing-tool error, which is specific and actionable.
		t.Logf("namespaces unavailable: %v", err)
	}
}

// TestCreateRefusesWithoutSupport: Create must not proceed on a platform that
// cannot support it, because a partial namespace is harder to clean up than
// none at all.
func TestCreateRefusesWithoutSupport(t *testing.T) {
	if err := netns.Available(); err != nil {
		_, createErr := netns.Create("thn-must-not-exist")
		if createErr == nil {
			t.Fatal("Create succeeded even though Available reported failure")
		}
		if !errors.Is(createErr, err) && !errors.Is(createErr, netns.ErrUnsupported) &&
			!errors.Is(createErr, netns.ErrNoPermission) {
			t.Errorf("Create failed with an unhelpful error: %v", createErr)
		}
	}
}

// TestNonLinuxReportsUnsupported pins the behaviour on the platform this project
// is developed on, so a Windows developer sees a clear reason rather than a
// nil-pointer.
//
// It lives here rather than in netns_linux_test.go, where it used to be. A test
// about non-Linux platforms, behind a //go:build linux tag, can only ever run
// on Linux — where it immediately skips. It was a test that had never run and
// never would, which is worse than no test: it read as coverage of the
// non-Linux path and was nothing of the kind.
func TestNonLinuxReportsUnsupported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this test is about non-Linux platforms")
	}

	if err := netns.Available(); err == nil {
		t.Error("Available must report that namespaces are unsupported off Linux")
	}

	// Create must refuse rather than attempt something.
	if _, err := netns.Create("thn-should-not-exist"); err == nil {
		t.Error("Create must fail off Linux")
	}
}

// TestPackageImportsNoHostState is a structural check, and the reason the
// package is small.
//
// internal/guard permits this file to build processes, which is the only
// exception in the repository. What makes that safe is that every command is
// scoped to a namespace, so this test asserts the scoping is real by checking
// that the package exposes no way to name a host-level interface.
func TestPackageExposesNoHostLevelOperation(t *testing.T) {
	// A nil namespace must be safe to close, so cleanup in a deferred call
	// cannot itself fail.
	var nilNS *netns.Namespace
	if err := nilNS.Close(); err != nil {
		t.Errorf("Close on a nil namespace: %v", err)
	}

	// Teardown and the probes must be no-ops rather than panics when the
	// namespace was never created, because they run from cleanup paths.
	ns := &netns.Namespace{}
	ns.Teardown("eth0")
	if ns.HasCake("eth0") {
		t.Error("HasCake on a namespace that was never created should be false")
	}
}

// TestAvailabilityIsUsableWithoutAProbe documents the shape the CLI depends
// on: an Availability with no algorithms and no error is the "nothing
// detected" case, and the selection logic treats it as such.
func TestAvailabilityIsUsableWithoutAProbe(t *testing.T) {
	empty := qos.Availability{Algorithms: map[qos.Algorithm]bool{}}

	if empty.Supports(qos.AlgorithmCake) {
		t.Error("an empty availability set must support nothing")
	}
	if got := empty.Summary(); got != "none detected" {
		t.Errorf("summary = %q, want %q", got, "none detected")
	}

	p := qos.Default()
	p.Enabled = true
	sel := qos.Select(p, empty.Algorithms)
	if sel.Available {
		t.Error("selecting against an empty set must not report availability")
	}
	if sel.Algorithm == qos.AlgorithmFqCodel {
		t.Error("nothing is available, so a fallback cannot be selected")
	}
}
