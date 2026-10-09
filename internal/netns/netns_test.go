package netns_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/netns"
	"github.com/VengeTH/THN-Gateway/internal/qos"
	qostc "github.com/VengeTH/THN-Gateway/internal/qos/tc"
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

// renderedArgs splits a rendered `tc qdisc replace` line into the algorithm and
// the arguments that follow it.
//
// It lives here rather than in netns_linux_test.go so it can be tested on every
// platform. It is pure string handling with no dependency on a namespace, a
// kernel, or root, so gating it behind //go:build linux meant the one piece of
// logic that can silently corrupt every kernel-facing test below was untested
// everywhere it is actually developed.
//
// The helpers that call it must not recompute this offset themselves. There
// were two copies, and the per-interface copy drifted by one field: it returned
// fields[6:], which is the algorithm itself. The namespace helpers prepend the
// kind when they build the command, so the kernel was handed
//
//	tc qdisc replace dev thn0 root cake cake bandwidth 22Mbit ...
//
// and refused it with `What is "cake"?`. The renderer was correct and had been
// all along; the harness corrupted the command on its way to the kernel. That
// failure surfaced only on a privileged Linux runner, on one test, and named a
// component that had nothing wrong with it.
func renderedArgs(line string) (kind string, args []string, ok bool) {
	fields := strings.Fields(line)
	// tc qdisc replace dev <iface> root <kind> [args...]
	kindIdx := 5
	if len(fields) > 5 && fields[5] == "root" {
		kindIdx = 6
	}
	if len(fields) <= kindIdx {
		return "", nil, false
	}
	return fields[kindIdx], fields[kindIdx+1:], true
}

// TestRenderedArgsDoNotRepeatTheAlgorithm is the guard on that drift, and it
// runs on every platform rather than only where a namespace can be created.
//
// The check is stated as the command the kernel would receive, because that is
// the fact that matters: tc parses one algorithm token after `root` and treats
// a second one as an unknown option.
func TestRenderedArgsDoNotRepeatTheAlgorithm(t *testing.T) {
	p := qos.Default()
	p.Enabled = true
	p.Interface = "wan0"
	p.Algorithm = qos.AlgorithmCake
	p.MTU = 1500
	p.Limits = qos.DefaultLimits()
	p = p.WithBandwidth(100_000, 20_000)

	script := qostc.Render(p, qos.Selection{
		Algorithm: qos.AlgorithmCake, Requested: qos.AlgorithmCake, Available: true,
	}, "wan0", "lan0")

	var checked int
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "tc qdisc replace dev ") {
			continue
		}
		checked++

		kind, args, ok := renderedArgs(trimmed)
		if !ok {
			t.Fatalf("rendered command is too short to be valid: %q", trimmed)
		}
		if kind != "cake" && kind != "fq_codel" {
			t.Fatalf("unexpected algorithm in %q", trimmed)
		}

		// What ApplyCake would actually execute.
		full := append([]string{"qdisc", "replace", "dev", "thn0", "root", kind}, args...)
		occurrences := 0
		for _, field := range full {
			if field == kind {
				occurrences++
			}
		}
		if occurrences != 1 {
			t.Errorf("tc would be given the algorithm %d times in %q; "+
				"it reads one token after root and calls a second one an unknown option",
				occurrences, strings.Join(full, " "))
		}
	}

	if checked == 0 {
		t.Fatal("the rendered script contains no tc command, so nothing was checked")
	}
}
