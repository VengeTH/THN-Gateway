package acceptance

import (
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// healthy is a gateway that passes everything an observation can settle.
func healthy() Evidence {
	return Evidence{
		HostSupported:         true,
		Interfaces:            []string{"bond0", "docker0", "enp0s31f6", "tailscale0"},
		DefaultRoutePresent:   true,
		DefaultRouteInterface: "enp0s31f6",
		WANUp:                 true,
		LANConfigured:         "bond0",
		LANUp:                 true,
		LANAddressPresent:     true,
		DHCPLeaseFileReadable: true,
		DHCPLeaseCount:        3,
		ResolversConfigured:   2,
		ForwardingEnabled:     true,
		MasqueradePresent:     true,
		FirewallLoaded:        true,
		FirewallTablePresent:  true,
		FirewallChainCount:    4,
		QoSPresent:            true,
		QoSAlgorithm:          "cake",
		ListeningPorts:        []int{22, 53, 5432, 11434, 2375},
		TunnelEstablished:     true,
	}
}

// baselineOf records what healthy looked like.
func baselineOf(e Evidence) *Baseline {
	b := Capture("site-001", e, at.Add(-time.Hour))
	return &b
}

// complete records every lifecycle event the catalogue asks for.
func complete() LifecycleEvidence {
	return LifecycleEvidence{
		RebootAt:                   at.Add(-30 * time.Minute),
		RebootPriorConfigDigest:    "abc123def456",
		RebootPostConfigDigest:     "abc123def456",
		GatewayRunningAfterReboot:  true,
		RollbackAt:                 at.Add(-20 * time.Minute),
		RollbackFromGeneration:     42,
		RollbackToGeneration:       41,
		RollbackReachedTarget:      true,
		RecoveryAt:                 at.Add(-10 * time.Minute),
		RecoveryWasGenuinelyBroken: true,
		RecoveryRestored:           true,
	}
}

// ----------------------------------------------- the lifecycle refusal

// The most important test in this package.
//
// Four of the seventeen criteria are claims about events, not about a running
// host. A tool that reports them as passed without having observed a reboot or
// performed a rollback is inventing its evidence, and an acceptance test that
// does that is worse than no acceptance test.
func TestLifecycleCriteriaAreRefusedWithoutEvidence(t *testing.T) {
	r := Evaluate("site-001", healthy(), baselineOf(healthy()),
		LifecycleEvidence{}, at)

	lifecycle := []string{
		"survives-reboot",
		"config-survives-reboot",
		"rollback-works",
		"recovers-from-failed-config",
	}

	for _, id := range lifecycle {
		res, ok := findResult(r, id)
		if !ok {
			t.Errorf("criterion %s is missing from the report", id)
			continue
		}
		if res.Verdict.Passed() {
			t.Errorf("%s reported PASS with no recorded event; it cannot be observed by "+
				"inspecting a running gateway", id)
		}
		if res.Verdict != VerdictNotAttempted {
			t.Errorf("%s = %s, want not-attempted", id, res.Verdict)
		}
		if res.Detail == "" {
			t.Errorf("%s is not attempted but does not say why", id)
		}
	}

	if r.Successful() {
		t.Error("the gateway was reported successful with four criteria never attempted")
	}
}

// Evidence that something happened makes the criterion answerable.
func TestLifecycleCriteriaPassWithRecordedEvidence(t *testing.T) {
	r := Evaluate("site-001", healthy(), baselineOf(healthy()), complete(), at)

	for _, id := range []string{
		"survives-reboot", "config-survives-reboot",
		"rollback-works", "recovers-from-failed-config",
	} {
		if res, _ := findResult(r, id); !res.Verdict.Passed() {
			t.Errorf("%s did not pass with evidence recorded: %s (%s)",
				id, res.Verdict, res.Detail)
		}
	}

	if !r.Successful() {
		t.Errorf("a fully evidenced healthy gateway was not called successful:\n%s",
			Render(r))
	}
}

// A reboot that happened but did not bring the gateway back is a failure, not
// an unattempted check.
func TestARebootThatLostTheGatewayFails(t *testing.T) {
	life := complete()
	life.GatewayRunningAfterReboot = false

	r := Evaluate("site-001", healthy(), baselineOf(healthy()), life, at)
	if res, _ := findResult(r, "survives-reboot"); res.Verdict != VerdictFail {
		t.Errorf("survives-reboot = %s, want fail", res.Verdict)
	}
	if r.Successful() {
		t.Error("a gateway that did not survive a reboot was called successful")
	}
}

// A configuration that changed across a reboot is a failure, and the report has
// to show both digests so the operator can see what happened.
func TestAConfigurationThatChangedAcrossRebootFails(t *testing.T) {
	life := complete()
	life.RebootPostConfigDigest = "fedcba987654"

	r := Evaluate("site-001", healthy(), baselineOf(healthy()), life, at)
	res := mustResult(r, "config-survives-reboot")

	if res.Verdict != VerdictFail {
		t.Errorf("config-survives-reboot = %s, want fail", res.Verdict)
	}
	if !strings.Contains(res.Observed, "abc123def456") ||
		!strings.Contains(res.Observed, "fedcba987654") {
		t.Errorf("the failure does not show both digests: %q", res.Observed)
	}
}

// "Recovered from a failed configuration" is a claim about a failure. If the
// applied configuration succeeded, nothing was recovered from.
func TestARecoveryFromSomethingThatDidNotFailDoesNotPass(t *testing.T) {
	life := complete()
	life.RecoveryWasGenuinelyBroken = false

	r := Evaluate("site-001", healthy(), baselineOf(healthy()), life, at)
	if res, _ := findResult(r, "recovers-from-failed-config"); res.Verdict.Passed() {
		t.Error("a recovery from a configuration that never failed was reported as a pass")
	}
}

// ------------------------------------------------------ baseline criteria

// The criterion that catches a firewall change quietly cutting somebody off.
func TestSomethingThatStoppedListeningFails(t *testing.T) {
	e := healthy()
	e.ListeningPorts = []int{22, 53} // PostgreSQL and Ollama gone

	r := Evaluate("site-001", e, baselineOf(healthy()), complete(), at)

	res, _ := findResult(r, "apps-reachable")
	if res.Verdict != VerdictFail {
		t.Fatalf("apps-reachable = %s, want fail", res.Verdict)
	}
	if !strings.Contains(res.Observed, "5432") || !strings.Contains(res.Observed, "11434") {
		t.Errorf("the failure does not name what was lost: %q", res.Observed)
	}
	if r.Successful() {
		t.Error("a gateway that lost two services was called successful")
	}
}

// Without a baseline there is nothing to compare, and the criterion must say so
// rather than passing on an empty comparison.
func TestBaselineCriteriaAreUnknowableWithoutABaseline(t *testing.T) {
	r := Evaluate("site-001", healthy(), nil, complete(), at)

	for _, id := range []string{
		"apps-reachable", "docker-healthy", "postgres-healthy",
		"cloudflare-healthy", "ollama-healthy",
	} {
		if res, _ := findResult(r, id); res.Verdict != VerdictUnknowable {
			t.Errorf("%s = %s without a baseline, want unknowable", id, res.Verdict)
		}
	}
	if r.Successful() {
		t.Error("the gateway was called successful with no baseline recorded")
	}
}

// A service that was never running cannot have been broken. Reporting it as a
// failure would send an operator looking for a fault that does not exist.
func TestAServiceThatWasNotRunningIsNotAFailure(t *testing.T) {
	before := healthy()
	before.ListeningPorts = []int{22, 53} // no PostgreSQL, no Ollama at baseline

	base := Capture("site-001", before, at.Add(-time.Hour))

	r := Evaluate("site-001", healthy(), &base, complete(), at)

	for _, id := range []string{"postgres-healthy", "ollama-healthy"} {
		res, _ := findResult(r, id)
		if res.Verdict != VerdictPass {
			t.Errorf("%s = %s for a service that was never running", id, res.Verdict)
		}
	}
}

// ------------------------------------------------------ state criteria

// The specific failure M5 is gated on: no firewall loaded.
func TestAMissingFirewallFailsAndSaysWhy(t *testing.T) {
	e := healthy()
	e.FirewallLoaded = false
	e.FirewallTablePresent = false

	r := Evaluate("site-001", e, baselineOf(healthy()), complete(), at)

	res, _ := findResult(r, "firewall-works")
	if res.Verdict != VerdictFail {
		t.Fatalf("firewall-works = %s, want fail", res.Verdict)
	}
	if !strings.Contains(res.Detail, "not being filtered") {
		t.Errorf("the detail does not explain the consequence: %q", res.Detail)
	}
}

// Forwarding on but no masquerade is the NAT failure that only shows up as
// "the internet does not work for my laptop".
func TestForwardingWithoutMasqueradeFails(t *testing.T) {
	e := healthy()
	e.MasqueradePresent = false

	r := Evaluate("site-001", e, baselineOf(healthy()), complete(), at)
	if mustResult(r, "nat-works").Verdict != VerdictFail {
		t.Error("NAT passed with forwarding on and no masquerade rule")
	}
}

// No LAN configured is not a working LAN. It has to be unknowable, not a pass.
func TestNoConfiguredLANIsNotAPass(t *testing.T) {
	e := healthy()
	e.LANConfigured = ""

	r := Evaluate("site-001", e, baselineOf(healthy()), complete(), at)
	res, _ := findResult(r, "lan-works")

	if res.Verdict != VerdictUnknowable {
		t.Errorf("lan-works = %s, want unknowable", res.Verdict)
	}
	if !strings.Contains(res.Detail, "not satisfied by having no LAN") {
		t.Errorf("the detail does not make the distinction: %q", res.Detail)
	}
}

// Tailscale is how the box gets managed when the WAN is down, so its absence
// is a gateway that is one bad uplink from unreachable.
func TestMissingTailscaleFails(t *testing.T) {
	e := healthy()
	e.Interfaces = []string{"bond0", "docker0", "enp0s31f6"}

	r := Evaluate("site-001", e, baselineOf(healthy()), complete(), at)
	if mustResult(r, "tailscale-works").Verdict != VerdictFail {
		t.Error("a gateway with no tailscale0 passed")
	}
}

// A host nobody could read fails everything, and does not pass vacuously.
func TestAnUnreadableHostPassesNothing(t *testing.T) {
	e := healthy()
	e.HostSupported = false

	r := Evaluate("site-001", e, nil, complete(), at)

	if r.Successful() {
		t.Fatal("an unreadable host was called successful")
	}
	if r.Summary.Pass > 0 {
		t.Errorf("%d criteria passed on a host nobody could read", r.Summary.Pass)
	}
	res, _ := findResult(r, "wan-works")
	if res.Verdict != VerdictUnknowable {
		t.Errorf("wan-works = %s, want unknowable", res.Verdict)
	}
}

// ------------------------------------------------------- the catalogue

// Every criterion must be evaluable. A criterion in the catalogue with no case
// in the evaluator returns not-attempted forever, which is safe but is a gap,
// and a gap in an acceptance test should be visible as one.
func TestEveryCriterionHasATitleAndAReason(t *testing.T) {
	criteria := Criteria()
	if len(criteria) < 17 {
		t.Errorf("the catalogue has %d criteria; the acceptance test has 17 lines", len(criteria))
	}

	seen := make(map[string]bool)
	for _, c := range criteria {
		if c.ID == "" || c.Title == "" {
			t.Errorf("a criterion is missing an ID or title: %+v", c)
		}
		if seen[c.ID] {
			t.Errorf("duplicate criterion ID %q", c.ID)
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.WhatItProves) == "" {
			t.Errorf("%s does not say what it proves", c.ID)
		}
		if strings.HasSuffix(c.WhatItProves, ".") == false && c.WhatItProves != "" {
			// Not enforced; kept as a reminder in the data.
			_ = c
		}
	}

	for _, c := range criteria {
		if !seen[c.ID] {
			t.Errorf("%s is not in the catalogue", c.ID)
		}
	}
}

// Four criteria are procedures rather than checks, and mislabelling one would
// let it be evaluated by inspection.
func TestExactlyFourCriteriaAreProcedures(t *testing.T) {
	var lifecycle []string
	for _, c := range Criteria() {
		if c.Class == ClassLifecycle {
			lifecycle = append(lifecycle, c.ID)
		}
	}
	if len(lifecycle) != 4 {
		t.Errorf("%d criteria are lifecycle procedures (%v), want 4", len(lifecycle), lifecycle)
	}
}

// -------------------------------------------------------------- rendering

func TestTheReportNamesWhatIsBlocking(t *testing.T) {
	r := Evaluate("site-001", healthy(), nil, complete(), at)
	out := Render(r)

	if !strings.Contains(out, "NOT SUCCESSFUL") {
		t.Errorf("the report does not lead with the verdict:\n%s", out)
	}
	if !strings.Contains(out, "Not successful because") {
		t.Errorf("the report does not say what is blocking:\n%s", out)
	}
	if !strings.Contains(out, "apps-reachable") {
		t.Errorf("the blocking list does not name a blocking criterion:\n%s", out)
	}
}

func TestASuccessfulReportSaysSo(t *testing.T) {
	r := Evaluate("site-001", healthy(), baselineOf(healthy()), complete(), at)
	if !r.Successful() {
		t.Fatalf("expected success:\n%s", Render(r))
	}
	if !strings.Contains(Render(r), "SUCCESSFUL") {
		t.Error("a successful run did not say so")
	}
}

// Worst first, because a report read top-down should start with what is broken.
func TestTheWorstCriterionIsReportedFirst(t *testing.T) {
	e := healthy()
	e.FirewallLoaded = false
	e.ListeningPorts = []int{22, 53}

	r := Evaluate("site-001", e, baselineOf(healthy()), complete(), at)

	if len(r.Results) == 0 {
		t.Fatal("no results")
	}
	for i, res := range r.Results {
		if res.Verdict == VerdictFail {
			return
		}
		if i > 2 {
			t.Errorf("the first failure is at position %d; failures should sort first", i)
			break
		}
	}
}

// findResult returns a criterion's result and whether it was in the report.
//
// The bool exists so that a criterion missing from the report is a test
// failure rather than a zero-valued Result whose Verdict is "" — which compares
// unequal to everything and would make a missing criterion look like a
// peculiar verdict rather than a gap in the report.
func findResult(r Report, id string) (Result, bool) {
	for _, res := range r.Results {
		if res.Criterion.ID == id {
			return res, true
		}
	}
	return Result{}, false
}

// mustResult is findResult for a criterion known to be present, and fails loudly
// when it is not. A missing criterion and a zero-valued result are different
// things, and a test that cannot tell them apart is not testing the report.
func mustResult(r Report, id string) Result {
	res, ok := findResult(r, id)
	if !ok {
		panic("criterion " + id + " is missing from the report")
	}
	return res
}
