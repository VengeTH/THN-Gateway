package deployment

import (
	"strings"
	"testing"
)

// deployed is a host where every blocking signal is met: Linux, both
// configured interfaces present.
func deployed() Observation {
	return Observation{
		HostSupported: true,
		HostPlatform:  "linux",
		ConfiguredWAN: "enp0s31f6",
		ConfiguredLAN: "bond0",
		Interfaces:    []string{"bond0", "enp0s31f6", "lo"},
		GatewayName:   "site-001",
	}
}

// ----------------------------------------------------- failing closed

// Both blocking signals unmet. The verdict must be "not deployed", and the
// reason must name one concrete thing to go and look at rather than listing
// every signal — an operator needs the interface, not the report.
func TestBothInterfacesMissingIsNotADeployment(t *testing.T) {
	o := deployed()
	o.Interfaces = []string{"lo"}

	s := Detect(o)

	if s.Deployed {
		t.Fatal("a host with neither configured interface reported itself deployed")
	}
	if s.Reason == "" {
		t.Fatal("a non-deployment must carry a reason")
	}
	if !strings.Contains(s.Reason, "enp0s31f6") {
		t.Errorf("the reason does not name a missing interface: %q", s.Reason)
	}

	// Both must still be reported as evidence, even though only one is the
	// reason. A verdict that can be checked is worth more than a short one.
	for _, name := range []string{"wan-attached", "lan-attached"} {
		sig := signalFor(s, name)
		if sig.Met {
			t.Errorf("signal %q claims to be met on a host missing it", name)
		}
	}
}

// The configured interface is absent, and so are every interface the host
// reports. The evidence has to say so without inventing a list.
func TestAnEmptyInterfaceListIsReportedHonestly(t *testing.T) {
	o := deployed()
	o.Interfaces = nil

	s := Detect(o)

	if s.Deployed {
		t.Fatal("a host reporting no interfaces at all reported itself deployed")
	}
	wan := signalFor(s, "wan-attached")
	if !strings.Contains(wan.Detail, "Present: nothing") {
		t.Errorf("the evidence does not report the absence: %q", wan.Detail)
	}
}

// An interface that disappears between configuration and inspection must fail
// closed. This is the same call as the missing-uplink case reached from a
// different direction, and it is the one that matters: a gateway whose second
// NIC drops out must not be told it is a gateway.
func TestAnInterfaceThatDisappearsFailsClosed(t *testing.T) {
	before := Detect(deployed())
	if !before.Deployed {
		t.Fatal("precondition: the host should be a deployment before the interface goes")
	}

	o := deployed()
	o.Interfaces = []string{"enp0s31f6", "lo"} // bond0 has gone

	after := Detect(o)
	if after.Deployed {
		t.Fatal("a host that lost its configured LAN still reported itself deployed")
	}
	if !strings.Contains(after.Reason, "bond0") {
		t.Errorf("the reason does not name the interface that vanished: %q", after.Reason)
	}
}

// Interface names come from configuration, which is operator-supplied text, and
// from the host. A name that differs only by case or surrounding whitespace is
// a different name to the kernel, so it must not be silently reconciled into a
// match. Failing closed is correct; what matters is that it fails.
func TestAMismatchedInterfaceNameDoesNotCountAsAttached(t *testing.T) {
	for _, name := range []string{"ENP0S31F6", " enp0s31f6", "enp0s31f6 ", "enp0s31f"} {
		o := deployed()
		o.ConfiguredLAN = name

		if Detect(o).Deployed {
			t.Errorf("configured interface %q was treated as attached", name)
		}
	}
}

// Every signal must be answered, whatever the input. A verdict computed from a
// partial signal set is a verdict that can be wrong in the direction that
// permits something.
func TestEverySignalIsAlwaysAnswered(t *testing.T) {
	cases := map[string]Observation{
		"nothing set at all":       {},
		"empty host platform":      {HostSupported: true},
		"empty configured names":   {HostSupported: true, Interfaces: []string{"lo", ""}},
		"names with no interfaces": {HostSupported: true, ConfiguredWAN: "wan0", ConfiguredLAN: "lan0"},
	}

	for name, o := range cases {
		s := Detect(o)
		if s.Deployed {
			t.Errorf("%s: reported as a deployment", name)
		}
		if len(s.Signals) != 4 {
			t.Errorf("%s: got %d signals, want 4", name, len(s.Signals))
		}
		if s.Headline == "" {
			t.Errorf("%s: no headline for the verdict", name)
		}
	}
}

// ------------------------------------------------------ the laptop case

// The case this whole package exists for: a development machine must report
// itself as not deployed, and must say so in the operator's terms.
func TestALaptopIsNotADeployment(t *testing.T) {
	s := Detect(Observation{
		HostPlatform: "windows",
		GatewayName:  "thn-gateway",
	})

	if s.Deployed {
		t.Fatal("a Windows development machine reported itself as a deployment")
	}
	if s.Headline != "THN Gateway is not physically deployed." {
		t.Errorf("headline = %q", s.Headline)
	}
	if s.Reason == "" {
		t.Error("no reason was given")
	}
}

// A host that cannot be inspected is not a host with absent interfaces. It is
// a host nothing is known about, and the message must not conflate the two.
func TestAnUninspectableHostIsNotADeployment(t *testing.T) {
	s := Detect(Observation{HostPlatform: "windows"})

	if s.Deployed {
		t.Fatal("an uninspectable host reported itself as a deployment")
	}

	host := signalFor(s, "host-inspectable")
	if host.Met {
		t.Error("host-inspectable was met on a host that cannot be inspected")
	}
	// And it must be the reason: nothing below it was learned.
	if s.Reason != host.Detail {
		t.Errorf("the headline reason is not the inspectability one:\n  got  %q\n  want %q",
			s.Reason, host.Detail)
	}
}

// ------------------------------------------------------ the gateway case

// A real gateway must report itself deployed, or the refusal would tell an
// operator their working gateway is not deployed — the mirror image of the
// mistake this package exists to avoid.
func TestARealGatewayIsADeployment(t *testing.T) {
	s := Detect(deployed())

	if !s.Deployed {
		t.Fatalf("a gateway with both interfaces present was not recognised:\n%s", Render(s))
	}
	if s.Reason != "" {
		t.Errorf("a deployment carries a reason for not being one: %q", s.Reason)
	}
}

// An unattached uplink is exactly the development state on the gateway itself,
// and it must be reported as not deployed.
func TestAMissingWanIsNotADeployment(t *testing.T) {
	o := deployed()
	o.Interfaces = []string{"bond0", "lo"}

	s := Detect(o)
	if s.Deployed {
		t.Fatal("a host missing its configured uplink reported itself deployed")
	}

	wan := signalFor(s, "wan-attached")
	if !strings.Contains(s.Reason, "enp0s31f6") {
		t.Errorf("the reason does not name the interface that is missing: %q", s.Reason)
	}
	if strings.Contains(wan.Detail, "not on this host") == false {
		t.Errorf("the evidence does not say it is absent: %q", wan.Detail)
	}
}

// The development configuration leaves the LAN unset on purpose. That is not a
// fault, and it is a perfectly good reason not to call the box a gateway.
func TestAnUnsetLanIsNotADeploymentButNotAFault(t *testing.T) {
	o := deployed()
	o.ConfiguredLAN = ""

	s := Detect(o)
	if s.Deployed {
		t.Fatal("a host with no configured LAN reported itself deployed")
	}

	lan := signalFor(s, "lan-attached")
	if !strings.Contains(lan.Detail, "still being chosen") {
		t.Errorf("an unset LAN was reported as a fault rather than a stage: %q", lan.Detail)
	}
}

// A missing name is not hardware, and refusing to call a working gateway a
// deployment over its name would be pedantry.
func TestAnUnnamedGatewayIsStillADeployment(t *testing.T) {
	o := deployed()
	o.GatewayName = ""

	s := Detect(o)
	if !s.Deployed {
		t.Errorf("a gateway with no name was not recognised as a deployment:\n%s", Render(s))
	}

	named := signalFor(s, "named")
	if named.Met {
		t.Error("the named signal claims to be met with an empty name")
	}
	if named.Blocking {
		t.Error("the named signal is blocking; it should be informational")
	}
}

// ------------------------------------------------------ signals

func TestEverySignalIsReportedWithWhatItChecked(t *testing.T) {
	s := Detect(deployed())

	if len(s.Signals) < 4 {
		t.Fatalf("only %d signal(s) were reported: %+v", len(s.Signals), s.Signals)
	}
	for _, sig := range s.Signals {
		if sig.Name == "" {
			t.Error("a signal has no name")
		}
		if sig.WhatItChecks == "" {
			t.Errorf("%s does not say what it checks", sig.Name)
		}
		if sig.Detail == "" {
			t.Errorf("%s has no detail, so the verdict cannot be checked", sig.Name)
		}
	}
}

// A marker file would prove somebody ran a command; a flag would prove
// somebody typed something. Neither proves hardware is present, which is why
// the signals are interface presence rather than either.
func TestDetectionUsesHardwareNotConfiguration(t *testing.T) {
	// Two observations differing only in what is on the host.
	with := Detect(deployed())

	o := deployed()
	o.Interfaces = nil
	without := Detect(o)

	if with.Deployed == without.Deployed {
		t.Error("changing what is present on the host did not change the verdict; " +
			"the check is reading configuration rather than hardware")
	}
}

func TestBlockingListsOnlyUnmetBlockingSignals(t *testing.T) {
	o := deployed()
	o.Interfaces = []string{"lo"}

	s := Detect(o)
	blocking := s.Blocking()

	if len(blocking) != 2 {
		t.Fatalf("got %d blocking signal(s), want 2: %+v", len(blocking), blocking)
	}
	for _, sig := range blocking {
		if sig.Met {
			t.Errorf("%s is listed as blocking but is met", sig.Name)
		}
		if !sig.Blocking {
			t.Errorf("%s is listed as blocking but is not a blocking signal", sig.Name)
		}
	}
}

func TestRenderShowsEverySignal(t *testing.T) {
	out := Render(Detect(deployed()))
	for _, want := range []string{"host-inspectable", "wan-attached", "lan-attached", "named"} {
		if !strings.Contains(out, want) {
			t.Errorf("the rendering omits %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "yes") {
		t.Error("the rendering shows no evidence marks")
	}
}

func signalFor(s Status, name string) Signal {
	for _, sig := range s.Signals {
		if sig.Name == name {
			return sig
		}
	}
	return Signal{}
}
