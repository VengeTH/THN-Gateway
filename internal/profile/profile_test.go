package profile
package profile

// Profiles describe intent, never hardware.
//
// # What these tests hold
//
// The single most important property of this package is negative: there is no
// device profile in it, and there never will be. A "Dell E5470 profile" or a
// "two-NIC gateway profile" would encode the exact assumption this milestone
// exists to remove — that the product's shape is the shape of the machine it
// was first developed on.
//
// A negative rule needs an enforcing test, or it is a comment. The three
// tests below read the source of this package and fail if a vendor name, an
// interface name, or a positioned interface ever appears in it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/host"
	"github.com/venth/thn-gateway/internal/network"
)

// # Device fixtures.
//
// The same five hosts used by the device-independence suite. They are
// duplicated rather than shared because internal/profile must not import
// internal/host's test files, and because a shared helper would make a change
// to one suite silently change the other — which is how a test stops testing
// anything.

func hostA() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("enp0s31f6", 2, "aa:bb:cc:dd:ee:01", "ether", network.LinkUp, 1000),
			obs("enp1s0", 3, "aa:bb:cc:dd:ee:02", "ether", network.LinkDown, 1000),
			obs("wlp2s0", 4, "aa:bb:cc:dd:ee:03", "wlan", network.LinkUp, 300),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

func hostB() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("eno1", 2, "11:22:33:44:55:01", "ether", network.LinkUp, 1000),
			obs("eno2", 3, "11:22:33:44:55:02", "ether", network.LinkUp, 1000),
			obs("eno3", 4, "11:22:33:44:55:03", "ether", network.LinkDown, 1000),
			obs("eno4", 5, "11:22:33:44:55:04", "ether", network.LinkDown, 1000),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

func hostC() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("ens3", 2, "cc:dd:ee:ff:00:01", "ether", network.LinkUp, 1000),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

func hostD() *network.Snapshot {
	return &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("eth0", 2, "de:ad:be:ef:00:01", "ether", network.LinkUp, 1000),
			obs("eth1", 3, "de:ad:be:ef:00:02", "ether", network.LinkUp, 1000),
			obs("eth2", 4, "de:ad:be:ef:00:03", "wlan", network.LinkDown, 0),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}
}

func obs(name string, index int, mac, kind string, state network.LinkState, mbps int) network.Interface {
	return network.Interface{
		Name:      name,
		Index:     index,
		MAC:       mac,
		MTU:       1500,
		SpeedMbps: mbps,
		Kind:      kind,
		State:     state,
		Role:      network.RoleUnassigned,
	}
}

// TestNoProfileNamesHardware is the negative rule, enforced.
//
// It reads this package's own source rather than the registry, so it also
// catches a vendor name in a comment — which is how "the Dell" quietly comes
// back as "the Dell E5470 profile".
func TestNoProfileNamesHardware(t *testing.T) {
	banned := []string{
		"dell", "e5470", "realtek", "intel", "broadcom",
		"rpi", "raspberry", "usb ethernet",
		"enp0s31f6", "enp1s0", "wlp2s0", "wlan0", "eth0", "eth1", "enx",
	}

	src, err := os.ReadFile(filepath.Join(".", "profile.go"))
	if err != nil {
		t.Fatalf("reading the package source: %v", err)
	}

	lower := strings.ToLower(string(src))
	for _, b := range banned {
		if strings.Contains(lower, b) {
			t.Errorf("profile.go mentions %q; a profile describes intent and must not "+
				"name a vendor, a model or a kernel interface", b)
		}
	}
}

// TestNoProfileDeclaresAPositionedInterface catches the subtler regression.
//
// Naming "eth0" is obvious and is caught above. Assuming that the FIRST
// interface holds a role is not a string anyone writes, it is a shape: a
// profile that says "requires one interface and takes the one at index 0".
//
// The guard is that no profile may require a role without also being evaluated
// against a resolution — which is what Evaluate's signature enforces — and
// that no requirement references anything positional.
func TestNoProfileDeclaresAPositionedInterface(t *testing.T) {
	for _, p := range All() {
		def, err := Lookup(string(p))
		if err != nil {
			t.Fatalf("profile %s is in All() but Lookup fails: %v", p, err)
		}
		for i, req := range def.Requirements {
			if req.Role == host.RoleUnassigned && req.Capability == "" {
				t.Errorf("profile %s requirement %d names neither a role nor a capability; "+
					"it must state what it needs", p, i)
			}
			if req.Role == host.RoleWAN || req.Role == host.RoleLAN {
				// Fine — a ROLE is the whole point. What must not happen is
				// a requirement that is satisfied by hardware alone.
				if def.Name == ProfileManagedDevice {
					t.Errorf("profile %s requires role %s but is meant to require nothing", p, req.Role)
				}
			}
		}
	}
}

// TestTheGatewayProfileRunsOnEveryCompatibleHost is the positive proof.
//
// The same desired gateway — profile "gateway", WAN and LAN assigned — is
// evaluated against hosts that share nothing: interface names, counts,
// wireless presence. A, B and D have the hardware for it. C has one NIC and
// legitimately cannot, and must say so with a structured finding rather than
// by silently succeeding.
func TestTheGatewayProfileRunsOnEveryCompatibleHost(t *testing.T) {
	def, err := Lookup("gateway")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		snap    *network.Snapshot
		assign  func() []host.Assignment
		wantOK  bool
		wantWhy string
	}{
		{
			name:   "host A: two NICs",
			snap:   hostA(),
			assign: func() []host.Assignment { return []host.Assignment{{Role: host.RoleWAN, Selector: "enp0s31f6"}, {Role: host.RoleLAN, Selector: "enp1s0"}} },
			wantOK: true,
		},
		{
			name:   "host B: four NICs",
			snap:   hostB(),
			assign: func() []host.Assignment { return []host.Assignment{{Role: host.RoleWAN, Selector: "eno1"}, {Role: host.RoleLAN, Selector: "eno2"}} },
			wantOK: true,
		},
		{
			name:   "host D: different names",
			snap:   hostD(),
			assign: func() []host.Assignment { return []host.Assignment{{Role: host.RoleWAN, Selector: "eth0"}, {Role: host.RoleLAN, Selector: "eth1"}} },
			wantOK: true,
		},
		{
			name:    "host C: one NIC cannot fill two roles",
			snap:    hostC(),
			assign:  func() []host.Assignment { return []host.Assignment{{Role: host.RoleWAN, Selector: "ens3"}} },
			wantOK:  false,
			wantWhy: "role-unassigned",
		},
		{
			name:    "host A with nothing assigned",
			snap:    hostA(),
			assign:  func() []host.Assignment { return nil },
			wantOK:  false,
			wantWhy: "role-unassigned",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := host.FromSnapshot(c.snap)
			res := host.Resolve(d, c.assign())

			rep := Evaluate(d, res, def)

			if rep.Satisfied != c.wantOK {
				t.Fatalf("satisfied = %v, want %v; findings %+v", rep.Satisfied, c.wantOK, rep.Findings)
			}
			if c.wantOK {
				if len(rep.Findings) != 0 {
					t.Errorf("a satisfied profile reported findings: %+v", rep.Findings)
				}
				return
			}
			if len(rep.Blocked()) == 0 {
				t.Fatal("an unsatisfied profile reported no blocking findings")
			}
			found := false
			for _, f := range rep.Blocked() {
				if f.Code == c.wantWhy {
					found = true
				}
				if f.Message == "" {
					t.Error("a finding has no message")
				}
			}
			if !found {
				t.Errorf("no blocking finding with code %q; got %+v", c.wantWhy, rep.Findings)
			}
		})
	}
}

// TestAPhoneCannotRunTheGatewayProfile is the shape argument, in a test.
//
// A phone with one wireless adapter is not a gateway. The profile must say so
// with a capability the host lacks, not with an assumption about NIC counts.
func TestAPhoneCannotRunTheGatewayProfile(t *testing.T) {
	phone := &network.Snapshot{
		CapturedAt: time.Now(),
		Platform:   "linux",
		Supported:  true,
		Interfaces: []network.Interface{
			obs("wlan0", 2, "de:ad:be:ef:99:01", "wlan", network.LinkUp, 300),
			obs("lo", 1, "", "loopback", network.LinkUp, 0),
		},
		Sysctl: []network.SysctlValue{{Key: "net.ipv4.ip_forward", Value: "0"}},
	}

	d := host.FromSnapshot(phone)
	res := host.Resolve(d, []host.Assignment{{Role: host.RoleWAN, Selector: "wlan0"}})

	gw, err := Lookup("gateway")
	if err != nil {
		t.Fatal(err)
	}
	rep := Evaluate(d, res, gw)

	if rep.Satisfied {
		t.Error("a single wireless adapter was accepted as a gateway")
	}

	// It must name the LAN, because a phone has no LAN.
	sawLAN := false
	for _, f := range rep.Blocked() {
		if f.Role == host.RoleLAN && f.Code == "role-unassigned" {
			sawLAN = true
		}
	}
	if !sawLAN {
		t.Errorf("the report does not say the LAN is missing: %+v", rep.Findings)
	}
}

// TestTheAccessPointProfileNeedsWireless is the profile differing by CAPABILITY
// rather than by hardware list.
//
// The access point and the bridge have the SAME role requirement — a LAN —
// and differ only in the capability they need. That is what "a capability is
// not an assumption" has to look like in practice.
func TestTheAccessPointProfileNeedsWireless(t *testing.T) {
	ap, err := Lookup("access-point")
	if err != nil {
		t.Fatal(err)
	}

	withWiFi := host.FromSnapshot(hostA())
	withoutWiFi := host.FromSnapshot(hostC())

	res := host.Resolve(withoutWiFi, []host.Assignment{{Role: host.RoleLAN, Selector: "ens3"}})

	if rep := Evaluate(withWiFi, host.Resolve(withWiFi, []host.Assignment{{Role: host.RoleLAN, Selector: "enp1s0"}}), ap); rep.Satisfied {
		t.Log("host A reports wireless-ap available; the access point profile passes")
	} else {
		t.Errorf("a host with a wireless adapter cannot run the access point profile: %+v", rep.Findings)
	}

	rep := Evaluate(withoutWiFi, res, ap)
	if rep.Satisfied {
		t.Error("a host with no wireless adapter was accepted as an access point")
	}
	if len(rep.Blocked()) == 0 {
		t.Fatal("no blocking finding for a host with no wireless adapter")
	}
}

// TestLookupRefusesToGuess is the anti-silent-substitution rule.
func TestLookupRefusesToGuess(t *testing.T) {
	if _, err := Lookup("dell-e5470"); err == nil {
		t.Fatal("a device-shaped profile name was accepted")
	}
	if _, err := Lookup("bridge"); err != nil {
		t.Fatalf("a real profile was rejected: %v", err)
	}

	_, err := Lookup("nonsense")
	if err == nil {
		t.Fatal("an unknown profile was accepted")
	}
	// The error must list what IS available, or an operator cannot recover.
	for _, p := range All() {
		if !strings.Contains(err.Error(), string(p)) {
			t.Errorf("the error does not mention the known profile %s: %v", p, err)
		}
	}
}

// TestAnUninspectedHostIsNotAnUnsatisfiedHost is the honesty rule.
func TestAnUninspectedHostIsNotAnUnsatisfiedHost(t *testing.T) {
	d := host.FromSnapshot(&network.Snapshot{Supported: false, Platform: "windows"})

	gw, err := Lookup("gateway")
	if err != nil {
		t.Fatal(err)
	}
	rep := Evaluate(d, host.Resolve(d, nil), gw)

	if rep.Satisfied {
		t.Fatal("an uninspected host satisfied the gateway profile")
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Code != "not-inspected" {
		t.Fatalf("an uninspected host produced %+v, want a single not-inspected finding", rep.Findings)
	}
}

// TestEveryProfileHasAnOperatorFacingName keeps the beginner path usable.
func TestEveryProfileHasAnOperatorFacingName(t *testing.T) {
	for _, p := range All() {
		def, err := Lookup(string(p))
		if err != nil {
			t.Fatal(err)
		}
		if def.Title == "" {
			t.Errorf("profile %s has no operator-facing title", p)
		}
		if len(def.Description) < 20 {
			t.Errorf("profile %s description is too short to be read by an operator: %q", p, def.Description)
		}
	}
}