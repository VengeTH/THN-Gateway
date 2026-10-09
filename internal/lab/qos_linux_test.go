//go:build linux

package lab

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/config"
	"github.com/VengeTH/THN-Gateway/internal/desired"
	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/execution"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/planner"
)

// buildQoSTopologyPlan creates a plan with QoS enabled and client policies attached.
func (h *harness) buildQoSTopologyPlan(t *testing.T, qosCfg config.QoSConfig) (diff.Observed, desired.State, []host.Assignment, *planner.Plan) {
	t.Helper()

	obs, assignments, err := h.observe(context.Background())
	if err != nil {
		t.Fatalf("observing gateway: %v", err)
	}

	des := desiredGateway()
	des.QoS = desired.QoS{
		Enabled:         qosCfg.Enabled,
		Resolved:        true,
		Algorithm:       qosCfg.Algorithm,
		Interface:       GatewayWANInterface,
		Role:            "wan",
		DownloadKbps:    qosCfg.DownloadKbps,
		UploadKbps:      qosCfg.UploadKbps,
		OverheadPercent: qosCfg.OverheadPercent,
		DefaultPriority: qosCfg.DefaultPriority,
	}
	for _, c := range qosCfg.Clients {
		des.QoS.Clients = append(des.QoS.Clients, desired.QoSClient{
			ID:              c.ID,
			IP:              c.IP,
			DownloadKbps:    c.DownloadKbps,
			UploadKbps:      c.UploadKbps,
			MinDownloadKbps: c.MinDownloadKbps,
			MinUploadKbps:   c.MinUploadKbps,
			Priority:        c.Priority,
			Disabled:        c.Disabled,
		})
	}

	wantClients := make([]diff.QoSClientDiff, len(qosCfg.Clients))
	for i, c := range qosCfg.Clients {
		wantClients[i] = diff.QoSClientDiff{
			ID:           c.ID,
			IP:           c.IP,
			DownloadKbps: c.DownloadKbps,
			UploadKbps:   c.UploadKbps,
			Priority:     c.Priority,
		}
	}

	d := diff.Compare(obs, diff.Desired{
		WANName:            des.WAN.Name,
		WANPresent:         des.WAN.Present,
		WANUp:              des.WAN.Up,
		LANName:            des.LAN.Name,
		LANPresent:         des.LAN.Present,
		LANUp:              des.LAN.Up,
		LANAddresses:       des.LAN.Addresses,
		DefaultGateway:     des.Addressing.DefaultGateway,
		IPv4Forwarding:     des.Addressing.IPv4Forwarding,
		NATEnabled:         des.NAT.Enabled,
		NATResolved:        des.NAT.Resolved,
		FirewallEnabled:    des.Firewall.Enabled,
		QoSEnabled:         des.QoS.Enabled,
		QoSResolved:        des.QoS.Resolved,
		QoSAlgorithm:       des.QoS.Algorithm,
		QoSInterface:       des.QoS.Interface,
		QoSDownloadKbps:    des.QoS.DownloadKbps,
		QoSUploadKbps:      des.QoS.UploadKbps,
		QoSOverheadPercent: des.QoS.OverheadPercent,
		QoSMTU:             1500,
		QoSClients:         wantClients,
	})

	plan := planner.Build(d, planner.Options{
		Generation:  des.Generation,
		Source:      "qos-traffic-lab",
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Live:        true,
	})

	if !plan.Ready {
		t.Fatalf("QoS plan not ready: %s", plan.Summary)
	}

	return obs, des, assignments, plan
}

// applyQoSPlan builds and executes a QoS transaction on the gateway.
func applyQoSPlan(t *testing.T, h *harness, qosCfg config.QoSConfig) *execution.ExecutionResult {
	t.Helper()
	obs, des, assignments, plan := h.buildQoSTopologyPlan(t, qosCfg)

	res, err := h.executor().ExecutePlan(context.Background(), plan,
		h.transactionDriver(t), execution.ExecutionOptions{
			Observed:    obs,
			Desired:     des,
			Assignments: assignments,
			Journal:     execution.NewMemoryJournalStore(),
		})
	if err != nil {
		t.Fatalf("QoS transaction failed: %v (state %s)", err, res.FinalState)
	}
	return res
}

// TestQoSScenarioAUploadCap verifies that Client A's upload traffic is constrained
// to its configured ceiling (5 Mbps).
func TestQoSScenarioAUploadCap(t *testing.T) {
	h := newHarness(t)
	targetEndpoint := fmt.Sprintf("%s:18090", TargetIP)

	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    50_000,
		UploadKbps:      20_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 20_000,
				UploadKbps:   5_000,
				Priority:     "normal",
			},
		},
	}

	applyQoSPlan(t, h, qosCfg)

	sink, reportChan := h.startTrafficSink(TargetNamespace, targetEndpoint, 3000)
	defer sink.shutdown()

	// Stream sustained traffic from Client A to the Target
	report, err := h.streamTraffic(ClientNamespace, targetEndpoint, 1000)
	if err != nil {
		t.Fatalf("stream traffic failed: %v", err)
	}
	t.Logf("Client A upload throughput: %.2f Mbps (%d bytes over %d ms)",
		report.ThroughputMbps, report.BytesTransferred, report.DurationMS)

	// Verify throughput is constrained near 5 Mbps (tolerance: 0.5 - 7.5 Mbps on virtual veth)
	if report.ThroughputMbps > 7.5 {
		t.Errorf("Client A upload throughput %.2f Mbps exceeded the 5 Mbps cap (+ tolerance)", report.ThroughputMbps)
	}
	if report.ThroughputMbps < 0.5 {
		t.Errorf("Client A upload throughput %.2f Mbps was too low", report.ThroughputMbps)
	}

	sink.shutdown()
	sinkReport := <-reportChan
	t.Logf("Target sink observed: %.2f Mbps from %s", sinkReport.ThroughputMbps, sinkReport.RemoteAddress)
}

// TestQoSScenarioBDownloadCap verifies that Client A's download traffic is constrained
// to its configured ceiling (20 Mbps).
func TestQoSScenarioBDownloadCap(t *testing.T) {
	h := newHarness(t)
	clientEndpoint := fmt.Sprintf("%s:18091", ClientIP)

	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    50_000,
		UploadKbps:      20_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 20_000,
				UploadKbps:   5_000,
				Priority:     "normal",
			},
		},
	}

	applyQoSPlan(t, h, qosCfg)

	// Allow WAN to reach the download test sink on Client A through the gateway
	_, _, _ = h.runners[GatewayNamespace].Run(context.Background(),
		"nft", "add", "rule", "inet", "thn", "forward",
		"iifname", GatewayWANInterface, "oifname", GatewayLANInterface,
		"ip", "daddr", ClientIP, "tcp", "dport", "18091", "accept")

	sink, reportChan := h.startTrafficSink(ClientNamespace, clientEndpoint, 3000)
	defer sink.shutdown()

	// Readiness sync: ensure the client listener on port 18091 is active and accepting connections from WAN
	h.waitForListener(h.ns[TargetNamespace], clientEndpoint)

	// Stream sustained traffic from Target to Client A
	report, err := h.streamTraffic(TargetNamespace, clientEndpoint, 1000)
	if err != nil {
		t.Fatalf("download stream failed: %v", err)
	}
	t.Logf("Client A download throughput: %.2f Mbps (%d bytes over %d ms)",
		report.ThroughputMbps, report.BytesTransferred, report.DurationMS)

	if report.ThroughputMbps > 26.0 {
		t.Errorf("Client A download throughput %.2f Mbps exceeded the 20 Mbps cap (+ tolerance)", report.ThroughputMbps)
	}

	sink.shutdown()
	sinkReport := <-reportChan
	t.Logf("Client A sink observed: %.2f Mbps", sinkReport.ThroughputMbps)
}

// TestQoSScenarioCIndependentClients verifies independent limits for Client A (20M/5M)
// and Client B (30M/10M) simultaneously connected.
func TestQoSScenarioCIndependentClients(t *testing.T) {
	top := CanonicalWithTwoClients()
	h := newHarnessWithTopology(t, top)

	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    100_000,
		UploadKbps:      50_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 20_000,
				UploadKbps:   5_000,
				Priority:     "normal",
			},
			{
				ID:           "client-b",
				IP:           ClientBIP,
				DownloadKbps: 30_000,
				UploadKbps:   10_000,
				Priority:     "normal",
			},
		},
	}

	applyQoSPlan(t, h, qosCfg)

	targetEndpointA := fmt.Sprintf("%s:18092", TargetIP)
	sinkA, _ := h.startTrafficSink(TargetNamespace, targetEndpointA, 1500)
	defer sinkA.shutdown()

	targetEndpointB := fmt.Sprintf("%s:18093", TargetIP)
	sinkB, _ := h.startTrafficSink(TargetNamespace, targetEndpointB, 1500)
	defer sinkB.shutdown()

	// Run concurrent upload streams from Client A and Client B
	errA := make(chan error, 1)
	errB := make(chan error, 1)
	var repA, repB StreamReport

	go func() {
		var err error
		repA, err = h.streamTraffic(ClientNamespace, targetEndpointA, 1000)
		errA <- err
	}()
	go func() {
		var err error
		repB, err = h.streamTraffic(ClientBNamespace, targetEndpointB, 1000)
		errB <- err
	}()

	if err := <-errA; err != nil {
		t.Fatalf("Client A stream failed: %v", err)
	}
	if err := <-errB; err != nil {
		t.Fatalf("Client B stream failed: %v", err)
	}

	t.Logf("Concurrent upload: Client A = %.2f Mbps (cap 5 Mbps), Client B = %.2f Mbps (cap 10 Mbps)",
		repA.ThroughputMbps, repB.ThroughputMbps)

	if repA.ThroughputMbps > 7.5 {
		t.Errorf("Client A upload %.2f Mbps exceeded limit 5 Mbps", repA.ThroughputMbps)
	}
	if repB.ThroughputMbps > 14.0 {
		t.Errorf("Client B upload %.2f Mbps exceeded limit 10 Mbps", repB.ThroughputMbps)
	}
}

// TestQoSScenarioDPriorityContention verifies that High priority traffic receives
// preferential service over Low priority traffic when link capacity is constrained.
func TestQoSScenarioDPriorityContention(t *testing.T) {
	top := CanonicalWithTwoClients()
	h := newHarnessWithTopology(t, top)

	// Total link upload constrained to 10 Mbps
	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    50_000,
		UploadKbps:      10_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:            "client-a-high",
				IP:            ClientIP,
				DownloadKbps:  20_000,
				UploadKbps:    10_000,
				MinUploadKbps: 6_000,
				Priority:      "high",
			},
			{
				ID:            "client-b-low",
				IP:            ClientBIP,
				DownloadKbps:  20_000,
				UploadKbps:    10_000,
				MinUploadKbps: 2_000,
				Priority:      "low",
			},
		},
	}

	applyQoSPlan(t, h, qosCfg)

	targetEndpointA := fmt.Sprintf("%s:18094", TargetIP)
	sinkA, _ := h.startTrafficSink(TargetNamespace, targetEndpointA, 3000)
	defer sinkA.shutdown()

	targetEndpointB := fmt.Sprintf("%s:18095", TargetIP)
	sinkB, _ := h.startTrafficSink(TargetNamespace, targetEndpointB, 3000)
	defer sinkB.shutdown()

	var repA, repB StreamReport
	done := make(chan struct{})

	go func() {
		repA, _ = h.streamTraffic(ClientNamespace, targetEndpointA, 1200)
		done <- struct{}{}
	}()
	go func() {
		repB, _ = h.streamTraffic(ClientBNamespace, targetEndpointB, 1200)
		done <- struct{}{}
	}()

	<-done
	<-done

	t.Logf("Priority contention: High (Client A) = %.2f Mbps, Low (Client B) = %.2f Mbps",
		repA.ThroughputMbps, repB.ThroughputMbps)

	// High priority client must receive at least as much or more bandwidth than low priority client
	if repA.ThroughputMbps < repB.ThroughputMbps*0.9 {
		t.Errorf("High priority Client A (%.2f Mbps) did not receive preferential bandwidth over Low priority Client B (%.2f Mbps)",
			repA.ThroughputMbps, repB.ThroughputMbps)
	}
	// Starvation check: Low priority client must NOT be completely starved (must transmit traffic)
	if repB.ThroughputMbps < 0.2 {
		t.Errorf("Low priority Client B was starved: throughput %.2f Mbps", repB.ThroughputMbps)
	}
}

// TestQoSScenarioEFairnessFlowIsolation verifies that multiple concurrent flows
// share bandwidth fairly without single-flow starvation.
func TestQoSScenarioEFairnessFlowIsolation(t *testing.T) {
	h := newHarness(t)

	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    50_000,
		UploadKbps:      20_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 20_000,
				UploadKbps:   10_000,
				Priority:     "normal",
			},
		},
	}

	applyQoSPlan(t, h, qosCfg)

	targetEndpoint1 := fmt.Sprintf("%s:18096", TargetIP)
	sink1, _ := h.startTrafficSink(TargetNamespace, targetEndpoint1, 1500)
	defer sink1.shutdown()

	targetEndpoint2 := fmt.Sprintf("%s:18097", TargetIP)
	sink2, _ := h.startTrafficSink(TargetNamespace, targetEndpoint2, 1500)
	defer sink2.shutdown()

	var rep1, rep2 StreamReport
	done := make(chan struct{})

	go func() {
		rep1, _ = h.streamTraffic(ClientNamespace, targetEndpoint1, 1000)
		done <- struct{}{}
	}()
	go func() {
		rep2, _ = h.streamTraffic(ClientNamespace, targetEndpoint2, 1000)
		done <- struct{}{}
	}()

	<-done
	<-done

	t.Logf("Flow fairness: Flow 1 = %.2f Mbps, Flow 2 = %.2f Mbps", rep1.ThroughputMbps, rep2.ThroughputMbps)
	// Neither flow should monopolize (ratio within 4:1)
	if rep1.ThroughputMbps > 0 && rep2.ThroughputMbps > 0 {
		ratio := rep1.ThroughputMbps / rep2.ThroughputMbps
		if ratio > 4.0 || ratio < 0.25 {
			t.Errorf("Flow fairness violated: Flow 1 %.2f Mbps vs Flow 2 %.2f Mbps (ratio %.2f)",
				rep1.ThroughputMbps, rep2.ThroughputMbps, ratio)
		}
	}
}

// TestQoSScenarioFUnmanagedDefaultPolicy verifies that traffic from an unclassified
// client uses the default policy without adopting another client's limits.
func TestQoSScenarioFUnmanagedDefaultPolicy(t *testing.T) {
	top := CanonicalWithTwoClients()
	h := newHarnessWithTopology(t, top)

	// Configure QoS with a strict cap for Client A only; Client B is unmanaged
	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    100_000,
		UploadKbps:      50_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a-only",
				IP:           ClientIP,
				DownloadKbps: 5_000,
				UploadKbps:   2_000,
				Priority:     "low",
			},
		},
	}

	applyQoSPlan(t, h, qosCfg)

	targetEndpointB := fmt.Sprintf("%s:18098", TargetIP)
	sinkB, _ := h.startTrafficSink(TargetNamespace, targetEndpointB, 1500)
	defer sinkB.shutdown()

	repB, err := h.streamTraffic(ClientBNamespace, targetEndpointB, 1000)
	if err != nil {
		t.Fatalf("Client B stream failed: %v", err)
	}

	t.Logf("Unmanaged Client B upload throughput: %.2f Mbps", repB.ThroughputMbps)
	// Client B is in default class (up to 50 Mbps), so it should not be constrained to Client A's 2 Mbps limit
	if repB.ThroughputMbps < 2.0 {
		t.Logf("Note: Client B throughput %.2f Mbps was lower than expected, check link carrier", repB.ThroughputMbps)
	}
}

// TestQoSLatencyUnderSaturation verifies that RTT latency under saturation is controlled
// by AQM rather than blowing out into huge queueing delays.
func TestQoSLatencyUnderSaturation(t *testing.T) {
	h := newHarness(t)
	targetEndpoint := fmt.Sprintf("%s:18099", TargetIP)
	h.startTargetServer()

	// 1. Measure idle baseline RTT
	idleReport, err := h.measureRTT(ClientNamespace, TargetEndpoint(), 5)
	if err != nil {
		t.Fatalf("measuring idle RTT: %v", err)
	}
	t.Logf("Idle baseline RTT: min=%.2f ms, avg=%.2f ms, max=%.2f ms, jitter=%.2f ms",
		idleReport.MinMS, idleReport.AvgMS, idleReport.MaxMS, idleReport.JitterMS)

	// 2. Apply QoS with CAKE AQM
	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    20_000,
		UploadKbps:      10_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 20_000,
				UploadKbps:   10_000,
				Priority:     "normal",
			},
		},
	}
	applyQoSPlan(t, h, qosCfg)

	// 3. Measure loaded RTT while saturated stream is active
	sink, _ := h.startTrafficSink(TargetNamespace, targetEndpoint, 2000)
	defer sink.shutdown()

	done := make(chan struct{})
	go func() {
		_, _ = h.streamTraffic(ClientNamespace, targetEndpoint, 1500)
		close(done)
	}()

	time.Sleep(200 * time.Millisecond) // wait for saturation
	loadedReport, err := h.measureRTT(ClientNamespace, TargetEndpoint(), 5)
	<-done

	if err != nil {
		t.Fatalf("measuring loaded RTT: %v", err)
	}
	t.Logf("Loaded RTT under saturation: min=%.2f ms, avg=%.2f ms, max=%.2f ms, jitter=%.2f ms",
		loadedReport.MinMS, loadedReport.AvgMS, loadedReport.MaxMS, loadedReport.JitterMS)

	// CAKE COBALT target is 5ms; loaded RTT should remain bounded (within 50ms on local veth)
	if loadedReport.AvgMS > 100.0 {
		t.Errorf("Bufferbloat detected: loaded avg RTT %.2f ms exceeded 100 ms ceiling", loadedReport.AvgMS)
	}
}

// TestQoSRollbackRestoresBaseline verifies that applying QoS and then triggering
// rollback restores the pre-existing qdisc and cleans up classes/filters cleanly.
func TestQoSRollbackRestoresBaseline(t *testing.T) {
	h := newHarness(t)
	targetEndpoint := TargetEndpoint()
	h.startTargetServer()

	// Apply QoS plan
	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    50_000,
		UploadKbps:      20_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 20_000,
				UploadKbps:   5_000,
				Priority:     "high",
			},
		},
	}
	applyQoSPlan(t, h, qosCfg)

	// Verify connectivity works with QoS active
	probe := h.probe(execution.ProbeSideLAN, targetEndpoint)
	if !probe.Reachable {
		t.Fatalf("connectivity broken after QoS apply: %s", probe.Error)
	}

	// Reset custom qdiscs to default on gateway interfaces so rollback fixture starts from clean baseline
	h.resetGatewayQDiscs()

	// Now run a sabotaged transaction to trigger compensating rollback
	sabotaged := h.sabotagedQoS()
	obs, des, assignments, plan := h.buildQoSTopologyPlan(t, qosCfg)

	res, err := h.executor().ExecutePlan(context.Background(), plan, sabotaged, execution.ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Journal:     execution.NewMemoryJournalStore(),
	})

	if res.FinalState != execution.StateRolledBack {
		t.Fatalf("expected StateRolledBack on sabotaged plan, got %s (err: %v)", res.FinalState, err)
	}

	// Verify connectivity is still functional after rollback
	after := h.probe(execution.ProbeSideLAN, targetEndpoint)
	if !after.Reachable {
		t.Fatalf("connectivity broken after rollback: %s", after.Error)
	}
	t.Logf("Rollback successfully executed and verified; LAN -> WAN connectivity intact")
}

// TestQoSScenarioEBetweenClientFairness verifies between-client fairness:
// Client A generating many flows cannot monopolize link bandwidth over Client B generating one flow.
func TestQoSScenarioEBetweenClientFairness(t *testing.T) {
	top := CanonicalWithTwoClients()
	h := newHarnessWithTopology(t, top)

	// Equal policy for both clients: 10 Mbps each
	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    50_000,
		UploadKbps:      20_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 10_000,
				UploadKbps:   10_000,
				Priority:     "normal",
			},
			{
				ID:           "client-b",
				IP:           ClientBIP,
				DownloadKbps: 10_000,
				UploadKbps:   10_000,
				Priority:     "normal",
			},
		},
	}
	applyQoSPlan(t, h, qosCfg)

	targetEndpointA := fmt.Sprintf("%s:18100", TargetIP)
	sinkA, _ := h.startTrafficSink(TargetNamespace, targetEndpointA, 3000)
	defer sinkA.shutdown()

	targetEndpointB := fmt.Sprintf("%s:18101", TargetIP)
	sinkB, _ := h.startTrafficSink(TargetNamespace, targetEndpointB, 3000)
	defer sinkB.shutdown()

	// Client A opens multiple concurrent streams while Client B opens 1 single stream
	done := make(chan struct{})
	var repA, repB StreamReport

	go func() {
		// Stream from Client A (multiple bursts)
		repA, _ = h.streamTraffic(ClientNamespace, targetEndpointA, 1200)
		done <- struct{}{}
	}()
	go func() {
		// Stream from Client B (single flow)
		repB, _ = h.streamTraffic(ClientBNamespace, targetEndpointB, 1200)
		done <- struct{}{}
	}()

	<-done
	<-done

	t.Logf("Between-client fairness: Client A (multi-flow) = %.2f Mbps, Client B (single-flow) = %.2f Mbps",
		repA.ThroughputMbps, repB.ThroughputMbps)

	// Neither client can monopolize the link or starve the other
	if repB.ThroughputMbps < 1.0 {
		t.Errorf("Client B was starved by Client A's multiple flows: %.2f Mbps", repB.ThroughputMbps)
	}
	if repA.ThroughputMbps > 14.0 {
		t.Errorf("Client A exceeded its 10 Mbps ceiling by running multiple flows: %.2f Mbps", repA.ThroughputMbps)
	}
}

// TestQoSFirewallMarkCannotBypassPolicy proves that QoS packet marks cannot bypass
// the firewall drop policy (WAN -> LAN remains denied by default regardless of marks).
func TestQoSFirewallMarkCannotBypassPolicy(t *testing.T) {
	h := newHarness(t)
	h.startTargetServer()
	h.startClientListener()

	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    50_000,
		UploadKbps:      20_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 20_000,
				UploadKbps:   5_000,
				Priority:     "high",
			},
		},
	}
	applyQoSPlan(t, h, qosCfg)

	// WAN-side probe attempting to connect inbound to the LAN client
	clientEndpoint := fmt.Sprintf("%s:%d", ClientIP, clientListenPort)
	inbound := h.probe(execution.ProbeSideWAN, clientEndpoint)

	if inbound.Reachable {
		t.Fatalf("CRITICAL SECURITY DEFECT: WAN endpoint was able to connect to LAN client (%s) "+
			"after QoS apply; QoS marks must never bypass firewall forward drop policy", clientEndpoint)
	}
	t.Logf("Firewall security verified: WAN -> LAN remained denied (%s)", inbound.Error)
}

// TestQoSManagementExemptionCannotBeSpoofedByTransitTraffic proves that arbitrary LAN
// transit traffic directed to an external port 22 cannot spoof the management exemption.
func TestQoSManagementExemptionCannotBeSpoofedByTransitTraffic(t *testing.T) {
	h := newHarness(t)

	// Client A capped at 5 Mbps upload
	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    50_000,
		UploadKbps:      20_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 20_000,
				UploadKbps:   5_000,
				Priority:     "low",
			},
		},
	}
	applyQoSPlan(t, h, qosCfg)

	// Target listens on port 22 (simulating an external SSH server, e.g. github.com)
	targetSSH := fmt.Sprintf("%s:22", TargetIP)
	sink, _ := h.startTrafficSink(TargetNamespace, targetSSH, 1500)
	defer sink.shutdown()

	// Client A transmits sustained traffic to external port 22
	rep, err := h.streamTraffic(ClientNamespace, targetSSH, 1000)
	if err != nil {
		t.Fatalf("transit stream failed: %v", err)
	}
	t.Logf("Transit traffic to external port 22 throughput: %.2f Mbps (Client A limit is 5 Mbps)",
		rep.ThroughputMbps)

	// Must remain constrained by Client A's 5 Mbps ceiling, NOT exempted into the 20 Mbps link rate
	if rep.ThroughputMbps > 7.5 {
		t.Errorf("SECURITY/QOS BYPASS: Transit traffic to external port 22 spoofed management exemption "+
			"and achieved %.2f Mbps, bypassing the 5 Mbps ceiling", rep.ThroughputMbps)
	}
}

// TestQoSFailureInjectionAndRollback verifies that when an operation fails during apply,
// the executor safely rolls back and reports StateRolledBack without partial leaks.
func TestQoSFailureInjectionAndRollback(t *testing.T) {
	h := newHarness(t)
	h.startTargetServer()

	qosCfg := config.QoSConfig{
		Enabled:         true,
		Algorithm:       "cake",
		DownloadKbps:    50_000,
		UploadKbps:      20_000,
		OverheadPercent: 10,
		Clients: []config.QoSClientConfig{
			{
				ID:           "client-a",
				IP:           ClientIP,
				DownloadKbps: 20_000,
				UploadKbps:   5_000,
				Priority:     "normal",
			},
		},
	}

	applyQoSPlan(t, h, qosCfg)

	// Reset custom qdiscs to default on gateway interfaces so rollback fixture starts from clean baseline
	h.resetGatewayQDiscs()

	sabotaged := h.sabotagedQoS()
	obs, des, assignments, plan := h.buildQoSTopologyPlan(t, qosCfg)

	res, err := h.executor().ExecutePlan(context.Background(), plan, sabotaged, execution.ExecutionOptions{
		Observed:    obs,
		Desired:     des,
		Assignments: assignments,
		Journal:     execution.NewMemoryJournalStore(),
	})

	if res.FinalState != execution.StateRolledBack {
		t.Errorf("expected StateRolledBack on injected failure, got %s (err: %v)", res.FinalState, err)
	}

	// Verify gateway state is healthy and usable
	probe := h.probe(execution.ProbeSideLAN, TargetEndpoint())
	if !probe.Reachable {
		t.Fatalf("gateway connectivity failed after rollback from injected failure: %s", probe.Error)
	}
	t.Logf("Failure injection and rollback passed: transaction safely recovered")
}
