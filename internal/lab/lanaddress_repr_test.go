package lab

// Regression coverage for the LAN address representation the live
// `TestWANToLANBlocked` depends on.
//
// # The failure this exists for
//
// The isolation test is the only one that builds a SECOND plan: it brings the
// dataplane up without a firewall, proves the WAN side can reach the client,
// and only then re-observes the gateway and installs the firewall. The second
// observation therefore runs against a LAN that is UP and addressed, while
// every other test plans once against a LAN that is still down.
//
// A link that is down carries no addresses. A link that is up carries the
// address THN assigned it AND the IPv6 link-local address the kernel
// assigns automatically. `network.ParseAddresses` keeps both, so the observed
// LAN address set is
//
//	["10.77.0.1/24", "fe80::…/64"]
//
// while the configured set is
//
//	["10.77.0.1/24"]
//
// `diff.compareAddresses` classified the link-local as EXTRA and emitted
// `lan-address-remove`. The second plan then carried
//
//	lan-address-remove, firewall-absent
//
// which is what the lab log recorded.
//
// # Why this runs on every platform
//
// The bug is entirely in the translation from `ip -j addr show` to a diff, and
// the kernel output is just a JSON document. Asserting it here means a laptop
// reproduces what the lab VM sees, rather than the mismatch only surfacing at
// three in the morning in a privileged namespace.
//
// The fixtures below are verbatim shapes a Linux bridge emits once it is up,
// including the `inet6`/`scope: link` entry the kernel adds by itself.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/host"
	"github.com/VengeTH/THN-Gateway/internal/network"
)

// gatewayLinkJSON is `ip -j -d link show` inside the gateway namespace once
// the dataplane bootstrap has run: both bridges up, the dummy up, and the two
// veth ports enslaved to their bridges.
const gatewayLinkJSON = `[
  {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,
   "operstate":"UNKNOWN","link_type":"ether","address":"00:00:00:00:00:00",
   "addr_info":[]},
  {"ifindex":2,"ifname":"thnwan0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UP","link_type":"ether","address":"8a:3c:11:00:00:01",
   "broadcast":"ff:ff:ff:ff:ff:ff",
   "linkinfo":{"info_kind":"bridge"}},
  {"ifindex":3,"ifname":"thnlan0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UP","link_type":"ether","address":"8a:3c:22:00:00:02",
   "broadcast":"ff:ff:ff:ff:ff:ff",
   "linkinfo":{"info_kind":"bridge"}},
  {"ifindex":4,"ifname":"thnmgmt0","flags":["BROADCAST","NOARP","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UNKNOWN","link_type":"ether","address":"8a:3c:33:00:00:03",
   "broadcast":"ff:ff:ff:ff:ff:ff",
   "linkinfo":{"info_kind":"dummy"}},
  {"ifindex":5,"ifname":"vwan0","flags":["BROADCAST","MULTICAST","SLAVE","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UP","link_type":"ether","address":"8a:3c:44:00:00:04",
   "broadcast":"ff:ff:ff:ff:ff:ff","master":"thnwan0",
   "linkinfo":{"info_kind":"veth"}},
  {"ifindex":6,"ifname":"vlan0","flags":["BROADCAST","MULTICAST","SLAVE","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UP","link_type":"ether","address":"8a:3c:55:00:00:05",
   "broadcast":"ff:ff:ff:ff:ff:ff","master":"thnlan0",
   "linkinfo":{"info_kind":"veth"}}
]`

// gatewayAddrJSON is `ip -j addr show` for the same namespace, after the
// bootstrap transaction committed `lan-link-state` and `lan-address-add`.
//
// The `fe80::` entries are the point of the fixture. The lab never assigns
// them, never configures them, and cannot prevent the kernel from adding them
// to any link it brings up.
const gatewayAddrJSON = `[
  {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,
   "operstate":"UNKNOWN","link_type":"ether","addr_info":[
     {"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},
     {"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},
  {"ifindex":2,"ifname":"thnwan0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UP","link_type":"ether","addr_info":[
     {"family":"inet","local":"10.77.250.1","prefixlen":24,"scope":"global"},
     {"family":"inet6","local":"fe80::8a3c:1100:0:1","prefixlen":64,"scope":"link"}]},
  {"ifindex":3,"ifname":"thnlan0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UP","link_type":"ether","addr_info":[
     {"family":"inet","local":"10.77.0.1","prefixlen":24,"scope":"global"},
     {"family":"inet6","local":"fe80::8a3c:2200:0:2","prefixlen":64,"scope":"link"}]},
  {"ifindex":4,"ifname":"thnmgmt0","flags":["BROADCAST","NOARP","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UNKNOWN","link_type":"ether","addr_info":[
     {"family":"inet","local":"10.77.99.1","prefixlen":24,"scope":"global"},
     {"family":"inet6","local":"fe80::8a3c:3300:0:3","prefixlen":64,"scope":"link"}]},
  {"ifindex":5,"ifname":"vwan0","flags":["BROADCAST","MULTICAST","SLAVE","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UP","link_type":"ether","addr_info":[]},
  {"ifindex":6,"ifname":"vlan0","flags":["BROADCAST","MULTICAST","SLAVE","UP","LOWER_UP"],
   "mtu":1500,"operstate":"UP","link_type":"ether","addr_info":[]}
]`

// staticInspector serves one snapshot through THN's own discovery path, so the
// translation under test is the real one rather than a second parser written
// for a test and therefore agreeing only with itself.
type staticInspector struct{ snap *network.Snapshot }

func (s staticInspector) Inspect(context.Context) (*network.Snapshot, error) { return s.snap, nil }

func snapshotFromKernelJSON(t *testing.T, linksJSON, addrJSON string) *network.Snapshot {
	t.Helper()

	links, err := network.ParseLinks([]byte(linksJSON))
	if err != nil {
		t.Fatalf("parsing `ip -j -d link show`: %v", err)
	}
	addrs, err := network.ParseAddresses([]byte(addrJSON))
	if err != nil {
		t.Fatalf("parsing `ip -j addr show`: %v", err)
	}
	return &network.Snapshot{
		Platform:   "linux",
		Supported:  true,
		Interfaces: links,
		Addresses:  addrs,
	}
}

// observedLANAddresses walks the same path the live harness does: parse,
// discover, resolve roles by stable identity, then read the LAN interface's
// addresses.
func observedLANAddresses(t *testing.T, snap *network.Snapshot) []string {
	t.Helper()

	_, device, err := host.NewDiscoveryWith(staticInspector{snap: snap}).Observe(context.Background())
	if err != nil {
		t.Fatalf("observing the gateway: %v", err)
	}
	if device == nil || !device.Supported {
		t.Fatalf("the gateway was not observed: %+v", device)
	}

	var selector string
	for _, i := range device.Interfaces {
		if i.SystemName == GatewayLANInterface {
			selector = i.ID
		}
	}
	if selector == "" {
		t.Fatalf("no interface named %s was discovered", GatewayLANInterface)
	}

	res := host.Resolve(device, []host.Assignment{{Role: host.RoleLAN, Selector: selector}})
	if !res.OK() {
		t.Fatalf("role resolution failed: %s", strings.Join(host.Suggestions(res), "; "))
	}
	return res.Assigned[host.RoleLAN].Addresses
}

func lanAddressChanges(r diff.Result) map[string]diff.Change {
	out := map[string]diff.Change{}
	for _, c := range r.Changes {
		switch c.ID {
		case "lan-address-add", "lan-address-remove":
			out[c.ID] = c
		}
	}
	return out
}

// TestLANAddressRepresentationSurvivesTheDataplaneBootstrap is the regression
// test for the root cause.
//
// It reproduces stage two of `TestWANToLANBlocked` exactly: a gateway whose
// LAN is already up and already carries 10.77.0.1/24, re-observed against the
// same desired state. The desired state has not changed, and neither has the
// operator's configuration. What changed is that the link came up — and a link
// that is up carries a kernel-assigned IPv6 link-local address.
func TestLANAddressRepresentationSurvivesTheDataplaneBootstrap(t *testing.T) {
	snap := snapshotFromKernelJSON(t, gatewayLinkJSON, gatewayAddrJSON)
	observed := observedLANAddresses(t, snap)

	// Evidence first: the representation really does contain the address THN
	// assigned. If this ever fails, the cause is upstream of the diff and the
	// remove it produced would have been a symptom of something else.
	if !contains(observed, GatewayAddress) {
		t.Fatalf("observed LAN addresses %v do not contain %s; the link-local "+
			"mismatch cannot be the explanation for a spurious remove", observed, GatewayAddress)
	}

	// Evidence second: the kernel-assigned link-local is present in the
	// observation, exactly as a live gateway reports it. Observation is
	// deliberately NOT filtered — `thn discover` should be able to tell an
	// operator that the link carries an address nobody configured.
	var linkLocal []string
	for _, a := range observed {
		if strings.HasPrefix(a, "fe80:") {
			linkLocal = append(linkLocal, a)
		}
	}
	if len(linkLocal) == 0 {
		t.Logf("no IPv6 link-local address in the observation (%v); the case under "+
			"test is carried by the IPv4 link-local entry instead", observed)
	}

	// The desired LAN addressing, exactly as desiredGateway() declares it on
	// the live lab. It is spelled from the canonical constant rather than
	// calling that helper, which lives in the //go:build linux harness.
	desiredLANAddresses := []string{GatewayAddress}

	result := diff.Compare(
		diff.Observed{
			Supported:           true,
			WANPresent:          true,
			WANName:             GatewayWANInterface,
			WANUp:               true,
			LANPresent:          true,
			LANName:             GatewayLANInterface,
			LANUp:               true,
			LANAddresses:        observed,
			IPv4Forwarding:      true,
			IPv4ForwardingKnown: true,
			FirewallActive:      true,
			FirewallRuleCount:   12,
			HasDefaultRoute:     true,
			DefaultGateway:      TargetIP,
		},
		diff.Desired{
			WANName:         GatewayWANInterface,
			WANPresent:      true,
			WANUp:           true,
			LANName:         GatewayLANInterface,
			LANPresent:      true,
			LANUp:           true,
			LANAddresses:    desiredLANAddresses,
			DefaultGateway:  TargetIP,
			UpstreamPresent: true,
			IPv4Forwarding:  true,
			NATEnabled:      true,
			NATResolved:     true,
			FirewallEnabled: true,
		},
	)

	changes := lanAddressChanges(result)

	t.Logf("after bootstrap:\n"+
		"  observed LAN addresses: %v\n"+
		"  desired LAN addresses:  %v", observed, desiredLANAddresses)

	for _, c := range result.Changes {
		t.Logf("  diff: %s\n    current: %s\n    desired: %s\n    reason:   %s",
			c.ID, c.Current, c.Desired, c.Reason)
	}

	if c, ok := changes["lan-address-add"]; ok {
		t.Errorf("lan-address-add was planned for an address the link already carries:\n"+
			"  current: %s\n  desired: %s\n  reason:  %s", c.Current, c.Desired, c.Reason)
	}
	if c, ok := changes["lan-address-remove"]; ok {
		t.Errorf("lan-address-remove was planned after the dataplane bootstrap, but the "+
			"desired LAN addresses are exactly what the link carries:\n"+
			"  observed: %v\n  desired:  %v\n"+
			"  current:  %s\n  desired:  %s\n  reason:   %s",
			observed, desiredLANAddresses, c.Current, c.Desired, c.Reason)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestLANLinkLocalIsNotConfiguredDrift guards the boundary against the fix
// over-reaching.
//
// Filtering link-local addresses must not turn `lan-address-remove` into a
// category that cannot fire: a second, genuinely unconfigured IPv4 address on
// the LAN is real drift, it is high risk, and THN must still report it.
func TestLANLinkLocalIsNotConfiguredDrift(t *testing.T) {
	result := diff.Compare(
		diff.Observed{
			Supported:    true,
			WANPresent:   true,
			WANName:      GatewayWANInterface,
			WANUp:        true,
			LANPresent:   true,
			LANName:      GatewayLANInterface,
			LANUp:        true,
			LANAddresses: []string{GatewayAddress, "fe80::8a3c:2200:0:2/64"},
		},
		diff.Desired{
			WANName:      GatewayWANInterface,
			WANPresent:   true,
			WANUp:        true,
			LANName:      GatewayLANInterface,
			LANPresent:   true,
			LANUp:        true,
			LANAddresses: []string{GatewayAddress},
		},
	)

	if changes := lanAddressChanges(result); len(changes) != 0 {
		t.Fatalf("a LAN carrying only %s and a kernel-assigned link-local produced "+
			"address changes: %s", GatewayAddress, describe(changes))
	}

	// The same interface, plus an address no configuration lists. This is real
	// drift and must still be reported.
	withExtra := result
	withExtra = diff.Compare(
		diff.Observed{
			Supported:    true,
			WANPresent:   true,
			WANName:      GatewayWANInterface,
			WANUp:        true,
			LANPresent:   true,
			LANName:      GatewayLANInterface,
			LANUp:        true,
			LANAddresses: []string{GatewayAddress, "192.168.99.1/24", "fe80::8a3c:2200:0:2/64"},
		},
		diff.Desired{
			WANName:      GatewayWANInterface,
			WANPresent:   true,
			WANUp:        true,
			LANName:      GatewayLANInterface,
			LANPresent:   true,
			LANUp:        true,
			LANAddresses: []string{GatewayAddress},
		},
	)

	c, ok := lanAddressChanges(withExtra)["lan-address-remove"]
	if !ok {
		t.Fatalf("an unconfigured 192.168.99.1/24 on the LAN produced no "+
			"lan-address-remove: %s", describe(lanAddressChanges(withExtra)))
	}
	if !strings.Contains(c.Reason, "192.168.99.1/24") {
		t.Errorf("lan-address-remove did not name the unconfigured address; reason: %s", c.Reason)
	}
	if strings.Contains(c.Reason, "fe80:") {
		t.Errorf("lan-address-remove blamed the kernel-assigned link-local address; reason: %s", c.Reason)
	}
}

func describe(changes map[string]diff.Change) string {
	if len(changes) == 0 {
		return "none"
	}
	out := make([]string, 0, len(changes))
	for id, c := range changes {
		out = append(out, fmt.Sprintf("%s (current %s, desired %s, reason %s)",
			id, c.Current, c.Desired, c.Reason))
	}
	return strings.Join(out, "; ")
}
