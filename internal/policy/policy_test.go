package policy_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/identity"
	"github.com/VengeTH/THN-Gateway/internal/policy"
	"github.com/VengeTH/THN-Gateway/internal/qos"
	"github.com/VengeTH/THN-Gateway/internal/schedule"
)

var at = time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC) // a Saturday, midday

// guestMAC and consoleMAC are two devices with different profiles.
const (
	guestMAC   = "aa:bb:cc:dd:ee:01"
	consoleMAC = "aa:bb:cc:dd:ee:02"
)

// fixtureAddrs are the resolvers the fixture profiles name.
//
// They are parsed once at package initialisation rather than on every call, and
// a failure panics: they are compile-time constants, so a parse failure is a
// typo in the fixture, and there is nothing for a test to report that the
// panic would not say more clearly.
var (
	fixtureCloudflare = mustAddr("1.1.1.1")
	fixtureQuad9      = mustAddr("9.9.9.9")
	fixtureHostAddr   = netip.MustParseAddr("10.77.0.100")
)

// mustAddr parses a constant address or panics.
func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic("the policy fixture contains an unparseable address " + s + ": " + err.Error())
	}
	return a
}

// mustAddrs is the variadic form used by the fixture builders.
func mustAddrs(addrs ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, mustAddr(a))
	}
	return out
}

// clock builds a wall clock, panicking on an out-of-range pair. The pairs are
// literals in the fixtures, so a failure is a typo rather than a condition.
func clock(h, m int) schedule.WallClock {
	c, err := schedule.NewWallClock(h, m)
	if err != nil {
		panic("the policy fixture has an invalid wall clock: " + err.Error())
	}
	return c
}

// at2 builds a moment on the fixture's own date, at a given time of day.
func at2(h, m int) time.Time {
	return time.Date(2026, time.March, 14, h, m, 0, 0, time.UTC)
}

// device builds a registry entry for a MAC.
//
// It returns a pointer because Set.Resolve takes one: a nil device is a
// meaningful input there, and a helper that could not produce one would make it
// awkward to test.
func device(t *testing.T, mac, hostname string) *identity.Device {
	t.Helper()

	reg := identity.NewRegistry()
	if _, known := reg.Observe(identity.Observation{
		MAC: mac, Hostname: hostname, Address: fixtureHostAddr,
	}, at); known {
		t.Fatalf("a first sighting of %s reported the device as already known", mac)
	}

	got, ok := reg.ByMAC(mac)
	if !ok {
		t.Fatalf("the registry does not know %s", mac)
	}
	return &got
}

// set builds a policy document with a house default and two devices.
func set() policy.Set {
	return policy.Set{
		Bandwidth: map[string]policy.BandwidthProfile{
			"full": {
				Name: "full", Shaped: true,
				Rate:   qos.Bandwidth{DownloadKbps: 100_000, UploadKbps: 20_000, OverheadPercent: 10},
				Limits: qos.DefaultLimits(),
			},
			"guest": {
				Name: "guest", Shaped: true,
				Rate:   qos.Bandwidth{DownloadKbps: 10_000, UploadKbps: 2_000, OverheadPercent: 10},
				Limits: qos.DefaultLimits(),
			},
		},
		DNS: map[string]policy.DNSProfile{
			"unfiltered": {Name: "unfiltered", Upstreams: mustAddrs("1.1.1.1", "9.9.9.9")},
			"filtered": {
				Name:      "filtered",
				Upstreams: mustAddrs("9.9.9.9"),
				Blocked:   []string{"*.example.invalid"},
			},
		},
		Firewall: map[string]policy.FirewallProfile{
			"open":     {Name: "open", Default: policy.Allow},
			"isolated": {Name: "isolated", Default: policy.Deny, Isolate: true},
		},
		Devices: map[string]policy.DeviceProfile{
			"guest-console": {Name: "guest-console"},
			"kids-console":  {Name: "kids-console", DNS: "filtered", Firewall: "isolated"},
		},
		Schedules: map[string]schedule.Schedule{
			"daytime":   schedule.Daily("daytime", "UTC", clock(8, 0), clock(22, 0), 0),
			"overnight": schedule.Daily("overnight", "UTC", clock(22, 0), clock(7, 0), 0),
		},
		Bindings: []policy.Binding{
			{
				Kind: policy.KindBandwidth, Profile: "full",
				Subject: policy.Subject{}, // every device
			},
			{
				Kind: policy.KindBandwidth, Profile: "guest",
				Subject: policy.NewDeviceSubject(guestMAC),
			},
			{
				Kind: policy.KindDNS, Profile: "unfiltered",
				Subject: policy.Subject{},
			},
			{
				Kind: policy.KindFirewall, Profile: "open",
				Subject: policy.Subject{},
			},
		},
	}
}

// TestCatchAllAppliesWhenNothingMoreSpecificExists is the baseline: a device
// with no profile of its own gets the house default.
func TestCatchAllAppliesWhenNothingMoreSpecificExists(t *testing.T) {
	got := set().Resolve(policy.NewDeviceSubject(consoleMAC),
		device(t, consoleMAC, "console"), at)

	if got.Bandwidth == nil {
		t.Fatal("no bandwidth profile resolved for a device with no profile of its own")
	}
	if got.Bandwidth.Name != "full" {
		t.Errorf("bandwidth = %q, want the house default", got.Bandwidth.Name)
	}
	if got.Firewall == nil || got.Firewall.Name != "open" {
		t.Error("firewall did not resolve to the house default")
	}
	if len(got.Unresolved) != 0 {
		t.Errorf("unresolved = %v, want none", got.Unresolved)
	}
}

// TestAMoreSpecificSubjectWins is the property that makes per-device policy
// possible at all.
func TestAMoreSpecificSubjectWins(t *testing.T) {
	got := set().Resolve(policy.NewDeviceSubject(guestMAC), device(t, guestMAC, "laptop"), at)

	if got.Bandwidth == nil {
		t.Fatal("no bandwidth resolved")
	}
	if got.Bandwidth.Name != "guest" {
		t.Errorf("bandwidth = %q, want guest; the more specific binding did not win "+
			"over the house default", got.Bandwidth.Name)
	}
}

// TestTheLosingBindingIsReported is the property that makes a policy
// predictable.
//
// A binding that loses silently is how a guest quietly gets the full link: the
// document says one thing, the resolution does another, and nothing says which
// is which.
func TestTheLosingBindingIsReported(t *testing.T) {
	got := set().Resolve(policy.NewDeviceSubject(guestMAC), device(t, guestMAC, "laptop"), at)

	var sawWinner, sawLoser bool
	for _, r := range got.Reasons {
		if !strings.Contains(r.Explanation, "") {
			continue
		}
		if r.Selected {
			sawWinner = true
			continue
		}
		if r.Binding.Profile == "full" {
			sawLoser = true
			if !strings.Contains(r.Explanation, "less specific") {
				t.Errorf("the losing binding's explanation %q does not say why it "+
					"lost", r.Explanation)
			}
		}
	}
	if !sawLoser {
		t.Errorf("the house default is not among the reasons: %+v", got.Reasons)
	}
	_ = sawWinner
}

// TestAScheduleGatesABinding is the whole point of the time layer.
func TestAScheduleGatesABinding(t *testing.T) {
	s := set()
	s.Bindings = append(s.Bindings, policy.Binding{
		Kind:     policy.KindBandwidth,
		Profile:  "guest",
		Subject:  policy.NewDeviceSubject(consoleMAC),
		Schedule: "overnight",
	})
	s.Schedules["overnight"] = schedule.Daily("overnight", "UTC", clock(22, 0), clock(7, 0), 0)

	dev := device(t, consoleMAC, "console")

	// Midday: the overnight binding is scheduled out, so the house default wins.
	midday := s.Resolve(policy.NewDeviceSubject(consoleMAC), dev, at)
	if midday.Bandwidth.Name != "full" {
		t.Errorf("midday bandwidth = %q, want the house default", midday.Bandwidth.Name)
	}

	// 23:00: the scheduled binding applies and is more specific anyway.
	night := at2(23, 0)
	late := s.Resolve(policy.NewDeviceSubject(consoleMAC), dev, night)
	if late.Bandwidth.Name != "guest" {
		t.Errorf("23:00 bandwidth = %q, want guest", late.Bandwidth.Name)
	}
}

// TestAScheduleOutIsReportedWithItsReason: an operator debugging "why is my
// console not limited at midnight" needs the schedule's own words.
func TestAScheduleOutIsReportedWithItsReason(t *testing.T) {
	s := set()
	s.Bindings = append(s.Bindings, policy.Binding{
		Kind: policy.KindBandwidth, Profile: "guest",
		Subject: policy.NewDeviceSubject(consoleMAC), Schedule: "overnight",
	})

	got := s.Resolve(policy.NewDeviceSubject(consoleMAC), device(t, consoleMAC, "console"), at)

	var found bool
	for _, r := range got.Reasons {
		if r.Binding.Profile != "guest" {
			continue
		}
		if r.ScheduleResult != nil && r.ScheduleResult.Active {
			t.Error("the binding's schedule reports itself active at midday")
		}
		if !strings.Contains(r.Explanation, "scheduled out") {
			t.Errorf("explanation %q does not say the binding was scheduled out",
				r.Explanation)
		}
		found = true
	}
	if !found {
		t.Error("the scheduled binding is not among the reasons at all")
	}
}

// TestAnUndefinedScheduleFailsClosed: a binding naming a schedule that does
// not exist must not silently become always-on. That would turn a typo into a
// policy that applies at three in the morning.
func TestAnUndefinedScheduleFailsClosed(t *testing.T) {
	s := set()
	s.Bindings = append(s.Bindings, policy.Binding{
		Kind: policy.KindBandwidth, Profile: "guest",
		Subject: policy.NewDeviceSubject(consoleMAC), Schedule: "nonexistent",
	})

	got := s.Resolve(policy.NewDeviceSubject(consoleMAC), device(t, consoleMAC, "console"), at)

	if got.Bandwidth == nil || got.Bandwidth.Name != "full" {
		t.Errorf("bandwidth = %v, want the house default; a binding with an "+
			"undefined schedule must not apply", got.Bandwidth)
	}

	var reported bool
	for _, r := range got.Reasons {
		if r.Binding.Schedule == "nonexistent" &&
			strings.Contains(r.Explanation, "not defined") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the undefined schedule was not reported: %+v", got.Reasons)
	}
}

// TestAnUndefinedProfileIsReportedNotSilentlyDropped: the configuration is
// partly wrong, and resolving for the subjects it can is better than refusing
// to resolve at all — but the operator has to be told.
func TestAnUndefinedProfileIsReportedNotSilentlyDropped(t *testing.T) {
	s := set()
	s.Bindings = append(s.Bindings, policy.Binding{
		Kind: policy.KindFirewall, Profile: "nonexistent",
		Subject: policy.NewDeviceSubject(consoleMAC),
	})

	got := s.Resolve(policy.NewDeviceSubject(consoleMAC), device(t, consoleMAC, "console"), at)

	if len(got.Unresolved) == 0 {
		t.Fatal("a binding naming a profile that does not exist produced no report")
	}
	if !strings.Contains(strings.Join(got.Unresolved, " "), "nonexistent") {
		t.Errorf("unresolved = %v, want it to name the missing profile", got.Unresolved)
	}
}

// TestADeviceProfileSuppliesWhatNoBindingClaims is the indirection: a device
// profile names the other profiles, and that is how a device gets a coherent
// set without a binding per kind.
func TestADeviceProfileSuppliesWhatNoBindingClaims(t *testing.T) {
	s := set()
	// Remove the catch-all firewall and DNS bindings so only the device
	// profile can supply them.
	s.Bindings = []policy.Binding{
		{Kind: policy.KindBandwidth, Profile: "full", Subject: policy.Subject{}},
		{
			Kind: policy.KindDevice, Profile: "kids-console",
			Subject: policy.NewDeviceSubject(consoleMAC),
		},
	}

	got := s.Resolve(policy.NewDeviceSubject(consoleMAC), device(t, consoleMAC, "console"), at)

	if got.Device == nil {
		t.Fatal("the device profile did not resolve")
	}
	if got.DNS == nil || got.DNS.Name != "filtered" {
		t.Errorf("DNS = %v, want filtered via the device profile", got.DNS)
	}
	if got.Firewall == nil || !got.Firewall.Isolate {
		t.Errorf("firewall = %v, want the isolating profile via the device profile", got.Firewall)
	}
	if got.Bandwidth == nil || got.Bandwidth.Name != "full" {
		t.Error("bandwidth did not fall back to the house default")
	}
}

// TestAnExplicitBindingBeatsADeviceProfileReference is the precedence rule, and
// it is the one an operator is most likely to get wrong.
func TestAnExplicitBindingBeatsADeviceProfileReference(t *testing.T) {
	s := set()
	s.Devices["kids-console"] = policy.DeviceProfile{
		Name: "kids-console", DNS: "filtered", Firewall: "isolated",
	}
	s.Bindings = []policy.Binding{
		{Kind: policy.KindDevice, Profile: "kids-console",
			Subject: policy.NewDeviceSubject(consoleMAC)},
		// A direct statement about this device's DNS, which should win over
		// the indirect reference in the device profile.
		{Kind: policy.KindDNS, Profile: "unfiltered",
			Subject: policy.NewDeviceSubject(consoleMAC)},
	}

	got := s.Resolve(policy.NewDeviceSubject(consoleMAC), device(t, consoleMAC, "console"), at)

	if got.DNS == nil || got.DNS.Name != "unfiltered" {
		t.Errorf("DNS = %v, want unfiltered; an explicit binding must outrank an "+
			"indirect reference from the device profile", got.DNS)
	}
}

// TestASchedulePriorityOverridesSpecificity is the documented tie-break, and it
// has to be that way round: a deliberate priority should beat an accidental
// specificity match.
func TestASchedulePriorityOverridesSpecificity(t *testing.T) {
	s := set()
	s.Schedules["urgent"] = schedule.Daily("urgent", "UTC", clock(0, 0), clock(23, 59), 10)
	s.Bindings = append(s.Bindings, policy.Binding{
		// More specific, but no schedule, so priority zero.
		Kind: policy.KindBandwidth, Profile: "guest",
		Subject: policy.NewDeviceSubject(guestMAC),
	}, policy.Binding{
		// Less specific, but a high-priority schedule.
		Kind: policy.KindBandwidth, Profile: "full",
		Subject: policy.Subject{}, Schedule: "urgent",
	})

	got := s.Resolve(policy.NewDeviceSubject(guestMAC), device(t, guestMAC, "laptop"), at)

	if got.Bandwidth.Name != "full" {
		t.Errorf("bandwidth = %q, want full; schedule priority must outrank "+
			"subject specificity", got.Bandwidth.Name)
	}
}

// TestTwoSchedulesContestedAtTheSamePriorityResolveByDeclaration is the last
// resort, and it is reported as such because "the later one wins" is a rule an
// operator has to know rather than infer.
func TestTwoSchedulesContestedAtTheSamePriorityResolveByDeclaration(t *testing.T) {
	s := set()
	s.Bindings = append(s.Bindings, policy.Binding{
		Kind: policy.KindBandwidth, Profile: "guest",
		Subject: policy.NewDeviceSubject(guestMAC), Schedule: "daytime",
	})

	got := s.Resolve(policy.NewDeviceSubject(guestMAC), device(t, guestMAC, "laptop"), at)

	if got.Bandwidth.Name != "guest" {
		t.Errorf("bandwidth = %q, want guest; the later declaration wins at equal "+
			"priority and specificity", got.Bandwidth.Name)
	}
}

// TestResolutionWorksWithoutADevice: a policy document has to be checkable
// before anything has connected, and refusing to resolve for an unseen subject
// would make that impossible.
func TestResolutionWorksWithoutADevice(t *testing.T) {
	subject := policy.NewDeviceSubject(guestMAC)

	got := set().Resolve(subject, nil, at)

	if got.Bandwidth == nil {
		t.Fatal("no bandwidth resolved for a subject with no registry entry")
	}
	if got.Bandwidth.Name != "guest" {
		t.Errorf("bandwidth = %q, want guest; an exact subject match must work "+
			"without a device", got.Bandwidth.Name)
	}
}

// TestResolutionWorksForAnUnknownSubject: a subject naming nothing resolves
// against the catch-all bindings, which is the house default.
func TestResolutionWorksForAnUnknownSubject(t *testing.T) {
	got := set().Resolve(policy.Subject{}, nil, at)

	if got.Bandwidth == nil || got.Bandwidth.Name != "full" {
		t.Errorf("bandwidth = %v, want the house default", got.Bandwidth)
	}
}

// TestEveryReasonIsExplained is the general property: a reason with no
// explanation is not a reason.
func TestEveryReasonIsExplained(t *testing.T) {
	got := set().Resolve(policy.NewDeviceSubject(guestMAC), device(t, guestMAC, "laptop"), at)

	if len(got.Reasons) == 0 {
		t.Fatal("a resolution with three applicable bindings reported no reasons")
	}
	for _, r := range got.Reasons {
		if strings.TrimSpace(r.Explanation) == "" {
			t.Errorf("binding %s has no explanation", r.Binding)
		}
	}
}

// TestResolutionStringNamesWhatApplied, because a summary that says "3
// policies" tells an operator nothing about which.
func TestResolutionStringNamesWhatApplied(t *testing.T) {
	got := set().Resolve(policy.NewDeviceSubject(guestMAC), device(t, guestMAC, "laptop"), at)

	s := got.String()
	for _, want := range []string{"bandwidth", "guest"} {
		if !strings.Contains(s, want) {
			t.Errorf("resolution %q does not mention %q", s, want)
		}
	}
}

// TestAnUnconstrainedProfileSaysSo: a profile with no rate must not render as
// a rate of zero, which would read as an infinitely slow link.
func TestAnUnconstrainedProfileSaysSo(t *testing.T) {
	p := policy.BandwidthProfile{Name: "unconstrained"}
	if !strings.Contains(p.String(), "unconstrained") {
		t.Errorf("String = %q, want it to say the profile does not constrain anything", p)
	}
	if strings.Contains(p.String(), "0 kbit") {
		t.Errorf("String = %q, an unconstrained profile must not render as zero", p)
	}
}

// TestSubjectRendersTheMostSpecificIdentifier.
func TestSubjectRendersTheMostSpecificIdentifier(t *testing.T) {
	cases := []struct {
		s    policy.Subject
		want string
	}{
		{policy.NewDeviceSubject("AA:BB:CC:DD:EE:01"), "aa:bb:cc:dd:ee:01"},
		{policy.Subject{DeviceID: "dev_abc"}, "dev_abc"},
		{policy.Subject{Hostname: "laptop"}, "laptop"},
		{policy.Subject{}, "(any device)"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("String = %q, want %q", got, c.want)
		}
	}
}

// TestAMacIsNormalisedOnConstruction: a subject written with upper-case hex has
// to match the registry, which stores lower-case.
func TestAMacIsNormalisedOnConstruction(t *testing.T) {
	upper := policy.NewDeviceSubject("AA:BB:CC:DD:EE:01")
	lower := policy.NewDeviceSubject("aa:bb:cc:dd:ee:01")

	if upper.MAC != lower.MAC {
		t.Errorf("the same address produced two subjects: %q and %q", upper.MAC, lower.MAC)
	}
	if upper.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MAC = %q, want the lower-case form the registry uses", upper.MAC)
	}
}

// TestABindingWithNoProfileIsReported is the inert-line case: a binding that
// does nothing must be visible.
func TestABindingWithNoProfileIsReported(t *testing.T) {
	s := set()
	s.Bindings = append(s.Bindings, policy.Binding{
		Kind: policy.KindDNS, Profile: "", Subject: policy.NewDeviceSubject(consoleMAC),
	})

	got := s.Resolve(policy.NewDeviceSubject(consoleMAC), device(t, consoleMAC, "console"), at)

	var found bool
	for _, r := range got.Reasons {
		if r.Binding.Kind == policy.KindDNS && strings.Contains(r.Explanation, "no effect") {
			found = true
		}
	}
	if !found {
		t.Errorf("a binding naming no profile was not reported: %+v", got.Reasons)
	}
}
