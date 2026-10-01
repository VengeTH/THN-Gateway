package acceptance

import (
	"fmt"
	"strings"
	"time"
)

// LifecycleEvidence is what a lifecycle criterion needs before it can be
// reported at all.
//
// Every field is a record of something that happened. There is no field that
// means "assume it works", and that is deliberate: the entire value of
// separating these criteria out is that they cannot be satisfied by inspection.
type LifecycleEvidence struct {
	// RebootAt is when a reboot was observed to have completed.
	//
	// Recorded by the device or by an operator, never inferred. A tool that
	// decided a reboot happened because time has passed would report every
	// unattended gateway as having survived one.
	RebootAt time.Time

	// RebootPriorConfigDigest is the configuration digest before the reboot.
	RebootPriorConfigDigest string

	// RebootPostConfigDigest is the configuration digest after it.
	RebootPostConfigDigest string

	// GatewayRunningAfterReboot reports the device's own view that it came
	// back and is serving.
	GatewayRunningAfterReboot bool

	// RollbackAt is when a rollback was performed.
	RollbackAt time.Time

	// RollbackFromGeneration and RollbackToGeneration record what was reverted.
	RollbackFromGeneration uint64
	RollbackToGeneration   uint64

	// RollbackReachedTarget reports that the revert landed on the intended
	// generation.
	RollbackReachedTarget bool

	// RecoveryAt is when a failed configuration was recovered from.
	RecoveryAt time.Time

	// RecoveryWasGenuinelyBroken reports that the applied configuration
	// actually failed, rather than having succeeded and needing no recovery.
	//
	// Required, because "recovered from a failed configuration" is a claim
	// about a failure. Applying a good configuration and calling the test a
	// pass would make the criterion unfalsifiable.
	RecoveryWasGenuinelyBroken bool

	// RecoveryRestored reports that the previous configuration came back.
	RecoveryRestored bool
}

// Evaluate runs the acceptance test against observed evidence.
//
// The structure is one switch per criterion, and every branch either produces
// a verdict with evidence or an honest "not attempted". There is no default
// branch that passes, because a new criterion added to the catalogue without a
// case here must not be quietly reported as satisfied.
func Evaluate(gateway string, e Evidence, base *Baseline, life LifecycleEvidence, at time.Time) Report {
	r := Report{
		Gateway: gateway,
		At:      at.UTC(),
	}
	if base != nil {
		r.BaselineAt = base.CapturedAt
	}

	// A host that could not be inspected fails every state criterion, and says
	// why. It does not pass them vacuously, and it does not report them as
	// unknown either: the host was readable in principle and was not read.
	if !e.HostSupported {
		for _, c := range Criteria() {
			if c.Class == ClassState || c.Class == ClassBaseline {
				r.add(Result{
					Criterion: c,
					Verdict:   VerdictUnknowable,
					Detail: "The host could not be inspected, so this criterion was not " +
						"evaluated. A gateway nobody can read is not a gateway that passed.",
				})
			}
		}
		for _, c := range Criteria() {
			if c.Class == ClassLifecycle {
				r.add(lifecycleResult(c, life, "not evaluated, because the host could not be inspected"))
			}
		}
		r.sortResults()
		return r
	}

	byID := map[string]Result{}

	// ---- state criteria ----

	byID["wan-works"] = wanResult(e)
	byID["lan-works"] = lanResult(e)
	byID["dhcp-works"] = dhcpResult(e)
	byID["dns-works"] = dnsResult(e)
	byID["nat-works"] = natResult(e)
	byID["firewall-works"] = firewallResult(e)
	byID["qos-works"] = qosResult(e)
	byID["tailscale-works"] = tailscaleResult(e)
	byID["ssh-works"] = sshResult(e)

	// ---- baseline criteria ----
	//
	// These compare against a recorded prior state. With no baseline they are
	// unknowable rather than passing, because "unchanged" is not knowable
	// without something to compare to.

	byID["apps-reachable"] = baselineReachable(e, base)
	byID["docker-healthy"] = baselineService(e, base, PortDockerAPI, "docker0",
		[]string{"/run/docker.sock", "/var/run/docker.sock"})
	byID["postgres-healthy"] = baselineService(e, base, PortPostgres, "", nil)
	byID["cloudflare-healthy"] = baselineTunnel(e, base)
	byID["ollama-healthy"] = baselineService(e, base, PortOllama, "", nil)

	// ---- lifecycle criteria ----

	for _, c := range Criteria() {
		if c.Class == ClassLifecycle {
			byID[c.ID] = lifecycleResult(c, life, "")
		}
	}

	// Emit in catalogue order, then sort worst-first for reading.
	for _, c := range Criteria() {
		if res, ok := byID[c.ID]; ok {
			r.add(res)
		}
	}
	r.sortResults()
	return r
}

func wanResult(e Evidence) Result {
	c, _ := CriterionByID("wan-works")

	switch {
	case !e.DefaultRoutePresent:
		return Result{c, VerdictFail,
			"There is no default route, so nothing leaving this host can reach anywhere.",
			"no default route in the routing table"}
	case !hasInterface(e.Interfaces, e.DefaultRouteInterface):
		return Result{c, VerdictFail,
			"The default route names an interface that is not present.",
			fmt.Sprintf("default route via %s, interfaces present: %s",
				e.DefaultRouteInterface, strings.Join(e.Interfaces, ", "))}
	case !e.WANUp:
		return Result{c, VerdictFail,
			"The default route exists but the uplink is not up.",
			fmt.Sprintf("%s is down", e.DefaultRouteInterface)}
	default:
		return Result{c, VerdictPass,
			fmt.Sprintf("There is a default route through %s and it is up.", e.DefaultRouteInterface), ""}
	}
}

func lanResult(e Evidence) Result {
	c, _ := CriterionByID("lan-works")

	if e.LANConfigured == "" {
		return Result{c, VerdictUnknowable,
			"No LAN interface is configured, so there is nothing to check. The criterion is " +
				"not satisfied by having no LAN.",
			"network.lan is empty in the configuration"}
	}
	if !hasInterface(e.Interfaces, e.LANConfigured) {
		return Result{c, VerdictFail,
			"The configured LAN interface is not present on this host.",
			fmt.Sprintf("%s configured, present: %s",
				e.LANConfigured, strings.Join(e.Interfaces, ", "))}
	}
	if !e.LANUp {
		return Result{c, VerdictFail, "The LAN interface is present but its link is down.",
			fmt.Sprintf("%s is down", e.LANConfigured)}
	}
	if !e.LANAddressPresent {
		return Result{c, VerdictFail,
			"The LAN interface is up but is not holding the configured address.",
			fmt.Sprintf("%s is up with no configured address bound", e.LANConfigured)}
	}
	return Result{c, VerdictPass,
		fmt.Sprintf("%s is up and holds the configured address.", e.LANConfigured), ""}
}

func dhcpResult(e Evidence) Result {
	c, _ := CriterionByID("dhcp-works")

	if !e.DHCPLeaseFileReadable {
		return Result{c, VerdictFail,
			"The DHCP lease file could not be read. A DHCP server that cannot record what it " +
				"handed out is not one an operator can debug.",
			"the lease file named by the configuration is not readable"}
	}
	return Result{c, VerdictPass,
		fmt.Sprintf("The lease file is readable and holds %d lease(s).", e.DHCPLeaseCount), ""}
}

func dnsResult(e Evidence) Result {
	c, _ := CriterionByID("dns-works")

	if e.ResolversConfigured == 0 {
		return Result{c, VerdictFail,
			"No upstream resolvers are configured, so clients cannot resolve anything.",
			"network.dns is empty"}
	}
	if !portListening(e.ListeningPorts, PortDNS) {
		return Result{c, VerdictFail,
			"Resolvers are configured but nothing is listening on the DNS port, so clients " +
				"on the LAN have nothing to ask.",
			describePorts(e.ListeningPorts)}
	}
	return Result{c, VerdictPass,
		fmt.Sprintf("Resolvers are configured and something is listening on %d.", PortDNS), ""}
}

func natResult(e Evidence) Result {
	c, _ := CriterionByID("nat-works")

	if !e.ForwardingEnabled {
		return Result{c, VerdictFail,
			"IP forwarding is off, so the gateway does not route at all.",
			"net.ipv4.ip_forward is 0"}
	}
	if !e.MasqueradePresent {
		return Result{c, VerdictFail,
			"Forwarding is on but there is no masquerade rule in the live ruleset, so LAN " +
				"clients leave with unroutable source addresses.",
			"no masquerade found in the loaded ruleset"}
	}
	return Result{c, VerdictPass, "Forwarding is enabled and masquerade is in the ruleset.", ""}
}

func firewallResult(e Evidence) Result {
	c, _ := CriterionByID("firewall-works")

	switch {
	case !e.FirewallLoaded:
		return Result{c, VerdictFail,
			"No ruleset is loaded. This is the state that a firewall change is supposed to " +
				"prevent, and it means traffic is not being filtered at all.",
			"no ruleset loaded"}
	case !e.FirewallTablePresent:
		return Result{c, VerdictFail,
			"A ruleset is loaded but THN's table is not in it, so the policy THN describes " +
				"is not the policy in force.",
			"THN's table is absent from the loaded ruleset"}
	case e.FirewallChainCount == 0:
		return Result{c, VerdictFail,
			"THN's table is present but contains no chains, so it filters nothing.",
			"the table has no chains"}
	default:
		return Result{c, VerdictPass,
			fmt.Sprintf("A ruleset is loaded with THN's table and %d chain(s).", e.FirewallChainCount), ""}
	}
}

func qosResult(e Evidence) Result {
	c, _ := CriterionByID("qos-works")

	if !e.QoSPresent {
		return Result{c, VerdictFail,
			"No queue discipline is attached to the uplink, so traffic shaping is not in force.",
			"no qdisc on the uplink"}
	}
	return Result{c, VerdictPass,
		fmt.Sprintf("A %s queue discipline is attached to the uplink.", e.QoSAlgorithm), ""}
}

func tailscaleResult(e Evidence) Result {
	c, _ := CriterionByID("tailscale-works")

	// Tailscale names its interface tailscale0. Nothing else does, and nothing
	// else uses that name, so this is an unambiguous check rather than a guess.
	if hasInterface(e.Interfaces, "tailscale0") {
		return Result{c, VerdictPass,
			"tailscale0 is present, so management does not depend on the WAN.", ""}
	}
	return Result{c, VerdictFail,
		"No tailscale0 interface. If management depends on the tunnel, this gateway is one " +
			"bad uplink away from unreachable.",
		fmt.Sprintf("interfaces present: %s", strings.Join(e.Interfaces, ", "))}
}

func sshResult(e Evidence) Result {
	c, _ := CriterionByID("ssh-works")

	if portListening(e.ListeningPorts, PortSSH) {
		return Result{c, VerdictPass, "Something is listening on the SSH port.", ""}
	}
	return Result{c, VerdictFail,
		"Nothing is listening on the SSH port. With the tunnel also required, there may be " +
			"no way in at all.",
		describePorts(e.ListeningPorts)}
}

// baselineReachable checks that nothing stopped listening.
//
// This is the criterion that catches a firewall change quietly cutting somebody
// off, and it is the reason a baseline exists at all.
func baselineReachable(e Evidence, base *Baseline) Result {
	c, _ := CriterionByID("apps-reachable")

	if base == nil {
		return Result{c, VerdictUnknowable,
			"No baseline was recorded, so there is nothing to compare against. This " +
				"criterion cannot pass without one: 'remains reachable' is a claim about " +
				"change, and there has been no recorded change to be a claim about.",
			"no baseline"}
	}

	var lost []string
	for _, p := range base.ListeningPorts {
		if !portListening(e.ListeningPorts, p) {
			lost = append(lost, fmt.Sprintf("%d", p))
		}
	}
	for _, iface := range base.Interfaces {
		if !hasInterface(e.Interfaces, iface) {
			lost = append(lost, iface)
		}
	}

	if len(lost) == 0 {
		return Result{c, VerdictPass,
			fmt.Sprintf("All %d port(s) and %d interface(s) present at baseline are still present.",
				len(base.ListeningPorts), len(base.Interfaces)), ""}
	}
	return Result{c, VerdictFail,
		"Things that were reachable before are not now. This is the failure a firewall or " +
			"interface change causes without anybody noticing for a day.",
		"gone: " + strings.Join(lost, ", ")}
}

// baselineService checks one named service against the baseline.
//
// Without a baseline this is unknowable, not a pass. The first version of this
// function checked whether the service was present and passed, which meant a
// run with no baseline reported four services healthy on the strength of having
// looked at them once. That is the vacuous pass this package exists to refuse:
// nothing had been compared against anything.
func baselineService(e Evidence, base *Baseline, port int, iface string, files []string) Result {
	id := map[int]string{
		PortDockerAPI: "docker-healthy",
		PortPostgres:  "postgres-healthy",
		PortOllama:    "ollama-healthy",
	}[port]
	c, _ := CriterionByID(id)

	present := portListening(e.ListeningPorts, port)
	if !present && iface != "" {
		present = hasInterface(e.Interfaces, iface)
	}
	if !present {
		for _, f := range files {
			if pathExists(f) {
				present = true
			}
		}
	}

	if base == nil {
		return Result{c, VerdictUnknowable,
			"No baseline was recorded, so there is nothing to compare this against. " +
				"This criterion cannot pass without one: \"remains healthy\" is a claim " +
				"about change, and no change has been recorded.",
			"no baseline"}
	}

	// Not configured on this host is a different answer from broken.
	if !wasServicePresent(*base, port, iface, files) {
		return Result{c, VerdictPass,
			"This host was not running this service at baseline, so it cannot have " +
				"been broken by the change.", ""}
	}

	if !present {
		return Result{c, VerdictFail,
			"This service was present at baseline and is not now.",
			fmt.Sprintf("nothing on %d, interfaces: %s", port, strings.Join(e.Interfaces, ", "))}
	}
	return Result{c, VerdictPass, "Present, as it was at baseline.", ""}
}

// baselineTunnel checks the outbound tunnel connection.
func baselineTunnel(e Evidence, base *Baseline) Result {
	c, _ := CriterionByID("cloudflare-healthy")

	if base == nil {
		return Result{c, VerdictUnknowable,
			"No baseline was recorded, so there is nothing to compare this against.", "no baseline"}
	}
	if !base.TunnelEstablished {
		return Result{c, VerdictPass,
			"There was no tunnel connection at baseline, so there was nothing to break.", ""}
	}
	if e.TunnelEstablished {
		return Result{c, VerdictPass, "An outbound tunnel connection is held, as at baseline.", ""}
	}
	return Result{c, VerdictFail,
		"The tunnel was established at baseline and is not now. If anything is managed " +
			"through that tunnel, it is currently unreachable.",
		fmt.Sprintf("no established connection to port %d", PortCloudflareTunnel)}
}

func wasServicePresent(b Baseline, port int, iface string, files []string) bool {
	if b.wasListening(port) {
		return true
	}
	if iface != "" && hasInterface(b.Interfaces, iface) {
		return true
	}
	for _, f := range files {
		if pathExists(f) {
			return true
		}
	}
	return false
}

// lifecycleResult evaluates the criteria that cannot be checked by looking.
//
// Every path either produces a pass backed by a recorded event, or says the
// event has not happened. There is no branch that infers.
func lifecycleResult(c Criterion, life LifecycleEvidence, override string) Result {
	if override != "" {
		return Result{c, VerdictNotAttempted, override, ""}
	}

	switch c.ID {
	case "survives-reboot":
		if life.RebootAt.IsZero() {
			return notAttempted(c,
				"No reboot has been recorded. This cannot be established by inspecting a "+
					"running gateway: an appliance that does not come back cannot report on "+
					"whether it came back. Reboot it and record the observation.")
		}
		if !life.GatewayRunningAfterReboot {
			return Result{c, VerdictFail,
				"A reboot was recorded but this gateway was not running afterwards.", ""}
		}
		return Result{c, VerdictPass,
			fmt.Sprintf("The gateway was running after a reboot at %s.",
				life.RebootAt.Format(time.RFC3339)), ""}

	case "config-survives-reboot":
		if life.RebootAt.IsZero() {
			return notAttempted(c, "No reboot has been recorded, so nothing can be said "+
				"about the configuration surviving one.")
		}
		if life.RebootPriorConfigDigest == "" || life.RebootPostConfigDigest == "" {
			return Result{c, VerdictUnknowable,
				"A reboot happened but the configuration was not digested on both sides, so " +
					"there is nothing to compare.", ""}
		}
		if life.RebootPriorConfigDigest != life.RebootPostConfigDigest {
			return Result{c, VerdictFail,
				"The configuration is not what it was before the reboot. Something " +
					"regenerated or truncated it.",
				fmt.Sprintf("before %s, after %s",
					short(life.RebootPriorConfigDigest), short(life.RebootPostConfigDigest))}
		}
		return Result{c, VerdictPass, "The configuration is byte-identical across the reboot.", ""}

	case "rollback-works":
		if life.RollbackAt.IsZero() {
			return notAttempted(c,
				"No rollback has been performed. An available rollback is not a working "+
					"one; the only way to know is to have done it and checked the result.")
		}
		if !life.RollbackReachedTarget {
			return Result{c, VerdictFail,
				fmt.Sprintf("A rollback from generation %d was performed but did not reach "+
					"generation %d.", life.RollbackFromGeneration, life.RollbackToGeneration),
				""}
		}
		return Result{c, VerdictPass,
			fmt.Sprintf("A rollback from generation %d to %d reached its target.",
				life.RollbackFromGeneration, life.RollbackToGeneration), ""}

	case "recovers-from-failed-config":
		if life.RecoveryAt.IsZero() {
			return notAttempted(c,
				"No recovery from a failed configuration has been performed. Applying a "+
					"good configuration and calling that a recovery test would make this "+
					"criterion unfalsifiable.")
		}
		if !life.RecoveryWasGenuinelyBroken {
			return Result{c, VerdictFail,
				"A recovery was recorded but the applied configuration had not actually " +
					"failed, so nothing was recovered from.", ""}
		}
		if !life.RecoveryRestored {
			return Result{c, VerdictFail,
				"A genuinely failed configuration was applied and the previous one did not " +
					"come back.", ""}
		}
		return Result{c, VerdictPass,
			"A configuration that genuinely failed was applied and the previous one was restored.", ""}
	}

	// A lifecycle criterion with no case here cannot be satisfied. Returning
	// pass would make adding a criterion to the catalogue a one-line change
	// that silently reports success.
	return notAttempted(c,
		"This lifecycle criterion has no evaluation, so it cannot be reported as met. "+
			"That is a gap in the acceptance test, not a result.")
}

func notAttempted(c Criterion, why string) Result {
	return Result{c, VerdictNotAttempted, why, ""}
}

func portListening(ports []int, want int) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}

func describePorts(ports []int) string {
	if len(ports) == 0 {
		return "nothing is listening on any port"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p))
	}
	return "listening on " + strings.Join(parts, ", ")
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}
