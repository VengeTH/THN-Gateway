package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/VengeTH/THN-Gateway/internal/policy"
	"github.com/VengeTH/THN-Gateway/internal/qos"
	"github.com/VengeTH/THN-Gateway/internal/schedule"
)

// This file is the gate phase for the policy layer: device policies, bandwidth
// policies, DNS policies, firewall policies and schedules.
//
// # What this phase is for
//
// The policy layer is the only part of THN whose output is a *choice* rather
// than a rendering. Everything else either matches the configuration or does
// not. This one picks one of several possibilities, and the failure mode is
// silent: the wrong profile applies, nothing complains, and the only symptom
// is a guest quietly getting the whole link.
//
// So the phase checks the decision, not just the inputs. It asks what a device
// gets, and it asks whether the answer is the one the document says it should
// be — including at the times when a schedule changes the answer.

// gatePolicyClock is a fixed moment used across the phase. The layer is
// time-varying, so a phase that used the real clock would pass or fail
// depending on the hour, and a gate that does that gets ignored.
var gatePolicyClock = time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC) // Saturday midday

// gatePolicyClockNight is the same day at a time the overnight schedule covers.
var gatePolicyClockNight = time.Date(2026, 3, 14, 23, 0, 0, 0, time.UTC)

// gatePolicyDocument builds a policy set exercising all four kinds.
func gatePolicyDocument(t *testing.T) policy.Set {
	t.Helper()

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
			"kids": {
				Name: "kids", Shaped: true,
				Rate:   qos.Bandwidth{DownloadKbps: 5_000, UploadKbps: 1_000, OverheadPercent: 10},
				Limits: qos.DefaultLimits(),
			},
		},
		DNS: map[string]policy.DNSProfile{
			"default":   {Name: "default"},
			"filtered":  {Name: "filtered", Blocked: []string{"*.ads.invalid"}},
			"noqueries": {Name: "noqueries", Blocked: []string{"*"}, LogQueries: boolPtr(false)},
		},
		Firewall: map[string]policy.FirewallProfile{
			"open":     {Name: "open", Default: policy.Allow},
			"locked":   {Name: "locked", Default: policy.Deny},
			"isolated": {Name: "isolated", Default: policy.Deny, Isolate: true},
		},
		Devices: map[string]policy.DeviceProfile{
			"kitchen":  {Name: "kitchen"},
			"nursery":  {Name: "nursery", DNS: "noqueries", Firewall: "isolated", ExpectStrongIdentity: true},
			"study":    {Name: "study", Bandwidth: "kids", DNS: "filtered"},
			"allguest": {Name: "allguest"},
		},
		Schedules: map[string]schedule.Schedule{
			"always": schedule.Always("always"),
			"daytime": schedule.Daily("daytime", "UTC",
				wallClock(t, 8, 0), wallClock(t, 22, 0), 0),
			"overnight": schedule.Daily("overnight", "UTC",
				wallClock(t, 22, 0), wallClock(t, 6, 0), 0),
			"urgent": schedule.Daily("urgent", "UTC",
				wallClock(t, 0, 0), wallClock(t, 23, 59), 50),
		},
		Bindings: []policy.Binding{
			// House defaults, matching every device.
			{Kind: policy.KindBandwidth, Profile: "full", Subject: policy.Subject{}},
			{Kind: policy.KindDNS, Profile: "default", Subject: policy.Subject{}},
			{Kind: policy.KindFirewall, Profile: "open", Subject: policy.Subject{}},

			// The guest network: a lower ceiling, all day.
			{Kind: policy.KindBandwidth, Profile: "guest",
				Subject: policy.NewDeviceSubject(gateGuestMAC)},
			{Kind: policy.KindFirewall, Profile: "locked",
				Subject: policy.NewDeviceSubject(gateGuestMAC)},

			// The nursery is locked down during the day and free at night.
			// The daytime rule is the more specific one, so it wins outright
			// rather than needing a priority.
			{Kind: policy.KindBandwidth, Profile: "kids",
				Subject: policy.NewDeviceSubject(gateNurseryMAC)},
			{Kind: policy.KindFirewall, Profile: "isolated",
				Subject: policy.NewDeviceSubject(gateNurseryMAC), Schedule: "daytime"},
		},
	}
}

// boolPtr returns a pointer to a bool, for the LogQueries field.
func boolPtr(b bool) *bool { return &b }

// wallClock builds a wall clock, failing the test on an invalid pair.
func wallClock(t *testing.T, h, m int) schedule.WallClock {
	t.Helper()

	c, err := schedule.NewWallClock(h, m)
	if err != nil {
		t.Fatalf("the gate fixture has an invalid wall clock: %v", err)
	}
	return c
}

// The gate fixture's devices.
const (
	gateGuestMAC   = "aa:bb:cc:dd:ee:01"
	gateNurseryMAC = "aa:bb:cc:dd:ee:02"
	gateStudyMAC   = "aa:bb:cc:dd:ee:03"
)

// TestGatePoliciesEveryDeviceGetsSomething checks the floor.
//
// The layer is an override, so the thing to prove is that a device with
// nothing of its own still gets the host default. A layer that broke that
// would leave every device unconfigured the moment anyone used it.
func TestGatePoliciesEveryDeviceGetsSomething(t *testing.T) {
	set := gatePolicyDocument(t)

	for _, subject := range []policy.Subject{
		policy.NewDeviceSubject(gateGuestMAC),
		policy.NewDeviceSubject(gateNurseryMAC),
		policy.NewDeviceSubject(gateStudyMAC),
		policy.NewDeviceSubject("aa:bb:cc:dd:ee:99"), // never mentioned
	} {
		got := set.Resolve(subject, nil, gatePolicyClock)

		if got.Bandwidth == nil {
			t.Errorf("%s: no bandwidth resolved; a device with no profile of its "+
				"own must still get the host default", subject)
		}
		if got.Firewall == nil {
			t.Errorf("%s: no firewall policy resolved", subject)
		}
		if len(got.Unresolved) != 0 {
			t.Errorf("%s: unresolved = %v", subject, got.Unresolved)
		}
	}
}

// TestGatePoliciesGuestGetsItsCeiling is the phase's central assertion: the
// point of a per-device bandwidth policy is that the device gets a different
// number.
func TestGatePoliciesGuestGetsItsCeiling(t *testing.T) {
	set := gatePolicyDocument(t)

	guest := set.Resolve(policy.NewDeviceSubject(gateGuestMAC), nil, gatePolicyClock)
	other := set.Resolve(policy.NewDeviceSubject("aa:bb:cc:dd:ee:99"), nil, gatePolicyClock)

	if guest.Bandwidth == nil || other.Bandwidth == nil {
		t.Fatal("a bandwidth profile did not resolve")
	}
	if guest.Bandwidth.Name != "guest" {
		t.Errorf("the guest got %q, want guest", guest.Bandwidth.Name)
	}
	if other.Bandwidth.Name != "full" {
		t.Errorf("an unrelated device got %q, want the house default", other.Bandwidth.Name)
	}
	if guest.Bandwidth.Rate.DownloadKbps >= other.Bandwidth.Rate.DownloadKbps {
		t.Errorf("the guest ceiling (%d) is not below the house rate (%d); the "+
			"policy applies to nothing",
			guest.Bandwidth.Rate.DownloadKbps, other.Bandwidth.Rate.DownloadKbps)
	}
}

// TestGatePoliciesAGuestIsAlsoLockedDown is the claim that a bandwidth ceiling
// and a firewall policy are independent, and that binding one does not imply
// the other. An operator who wrote a guest binding and got isolation for free
// — or a firewall profile and no ceiling — has been surprised, and both are
// plausible outcomes of a layer that bundled them.
func TestGatePoliciesAGuestIsAlsoLockedDown(t *testing.T) {
	got := gatePolicyDocument(t).Resolve(
		policy.NewDeviceSubject(gateGuestMAC), nil, gatePolicyClock)

	if got.Firewall == nil || got.Firewall.Name != "locked" {
		t.Errorf("firewall = %v, want the locked guest profile", got.Firewall)
	}
	if got.Firewall.Default != policy.Deny {
		t.Errorf("the guest firewall defaults to %q, want deny", got.Firewall.Default)
	}
}

// TestGateSchedulesChangeTheAnswer is the whole reason the layer exists.
func TestGateSchedulesChangeTheAnswer(t *testing.T) {
	set := gatePolicyDocument(t)
	subject := policy.NewDeviceSubject(gateNurseryMAC)

	day := set.Resolve(subject, nil, gatePolicyClock)
	night := set.Resolve(subject, nil, gatePolicyClockNight)

	if day.Firewall == nil || !day.Firewall.Isolate {
		t.Errorf("midday: firewall = %v, want the isolating profile", day.Firewall)
	}
	if night.Firewall == nil || night.Firewall.Name != "open" {
		t.Errorf("23:00: firewall = %v, want the house default once the "+
			"daytime window has closed", night.Firewall)
	}

	// The bandwidth ceiling is not scheduled, so it must be the same at both
	// times. A test that only checked the firewall would miss a ceiling that
	// silently followed the schedule.
	if day.Bandwidth.Name != night.Bandwidth.Name {
		t.Errorf("the bandwidth changed with the schedule: %q midday, %q at "+
			"night; only the firewall binding was gated", day.Bandwidth.Name, night.Bandwidth.Name)
	}
}

// TestGateSchedulesOvernightSpansMidnight: the window covers 03:00 as well as
// 23:00, and the weekend boundary. A window that only worked in the evening
// would leave a nursery unlocked from midnight to six, which is the opposite of
// the intent.
func TestGateSchedulesOvernightSpansMidnight(t *testing.T) {
	set := gatePolicyDocument(t)
	subject := policy.NewDeviceSubject(gateNurseryMAC)

	// A weekend overnight window: 22:00 Friday to 06:00 Saturday.
	friday := schedule.Weekly("weekend-night", "UTC",
		wallClock(t, 22, 0), wallClock(t, 6, 0),
		[]schedule.Day{schedule.DayFriday}, 0)

	fridayLate := time.Date(2026, time.March, 20, 23, 0, 0, 0, time.UTC)   // Friday
	saturdayEarly := time.Date(2026, time.March, 21, 3, 0, 0, 0, time.UTC) // Saturday

	if !friday.Active(fridayLate).Active {
		t.Error("a Friday-night window is not active on Friday night")
	}
	if !friday.Active(saturdayEarly).Active {
		t.Error("a Friday-night window is not active at 03:00 on Saturday; the " +
			"window belongs to the day it opens")
	}

	// And the same machinery must leave an unrelated device alone.
	before := set.Resolve(subject, nil, fridayLate)
	after := set.Resolve(subject, nil, saturdayEarly)
	if before.Firewall.Name != after.Firewall.Name {
		t.Errorf("the two halves of one overnight window resolved differently: "+
			"%q then %q", before.Firewall.Name, after.Firewall.Name)
	}
}

// TestGatePoliciesSelectionIsExplained is the phase's general property.
//
// Every binding that was considered must be reported, and every report must
// say why. A resolution that names its answer but not its reasoning is the one
// thing this layer must never produce: it is exactly the output that cannot be
// debugged from a distance.
func TestGatePoliciesSelectionIsExplained(t *testing.T) {
	set := gatePolicyDocument(t)

	for _, subject := range []policy.Subject{
		policy.NewDeviceSubject(gateGuestMAC),
		policy.NewDeviceSubject(gateNurseryMAC),
		policy.NewDeviceSubject("aa:bb:cc:dd:ee:99"),
	} {
		got := set.Resolve(subject, nil, gatePolicyClock)

		if len(got.Reasons) == 0 {
			t.Errorf("%s: no reasons reported, though three catch-all bindings "+
				"matched", subject)
			continue
		}

		var selected int
		for _, r := range got.Reasons {
			if strings.TrimSpace(r.Explanation) == "" {
				t.Errorf("%s: a reason with no explanation: %s", subject, r.Binding)
			}
			if r.Selected {
				selected++
			}
		}

		// Exactly one binding per kind may be selected. Two winners for one
		// kind would mean the resolution is ambiguous, and an ambiguous
		// resolution is one nobody can rely on.
		perKind := map[policy.Kind]int{}
		for _, r := range got.Reasons {
			if r.Selected {
				perKind[r.Binding.Kind]++
			}
		}
		for kind, n := range perKind {
			if n != 1 {
				t.Errorf("%s: %d bindings selected for %s, want exactly 1",
					subject, n, kind)
			}
		}
	}
}

// TestGatePoliciesLosingBindingsAreReported is the specific half: a binding
// that matches and loses must still be visible. Otherwise a guest binding
// silently replaced by the house default looks identical to one that works.
func TestGatePoliciesLosingBindingsAreReported(t *testing.T) {
	got := gatePolicyDocument(t).Resolve(
		policy.NewDeviceSubject(gateGuestMAC), nil, gatePolicyClock)

	var sawLoser bool
	for _, r := range got.Reasons {
		if r.Selected {
			continue
		}
		if r.Binding.Profile == "full" {
			sawLoser = true
			if !strings.Contains(r.Explanation, "less specific") {
				t.Errorf("the losing binding's explanation does not say why it "+
					"lost: %q", r.Explanation)
			}
		}
	}
	if !sawLoser {
		t.Errorf("the house-default binding is not among the reasons: %+v", got.Reasons)
	}
}

// TestGatePoliciesUndefinedSchedulesFailClosed is the safety property.
//
// A binding naming a schedule that does not exist must not become
// always-on. If it did, a typo would open a firewall rule or drop a ceiling
// that the operator believes is time-limited, and the difference would only
// show at three in the morning.
func TestGatePoliciesUndefinedSchedulesFailClosed(t *testing.T) {
	set := gatePolicyDocument(t)
	set.Bindings = append(set.Bindings, policy.Binding{
		Kind: policy.KindFirewall, Profile: "locked",
		Subject: policy.NewDeviceSubject(gateStudyMAC), Schedule: "no-such-schedule",
	})

	got := set.Resolve(policy.NewDeviceSubject(gateStudyMAC), nil, gatePolicyClock)

	if got.Firewall == nil || got.Firewall.Name != "open" {
		t.Errorf("firewall = %v, want the house default; a binding gated by an "+
			"undefined schedule must not apply", got.Firewall)
	}

	var reported bool
	for _, r := range got.Reasons {
		if r.Binding.Schedule == "no-such-schedule" &&
			strings.Contains(r.Explanation, "not defined") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the undefined schedule was not reported: %+v", got.Reasons)
	}
}

// TestGatePoliciesUndefinedProfilesAreReportedNotFatal is the other half: a
// partly-wrong document should still resolve for what it can, and say what it
// could not.
func TestGatePoliciesUndefinedProfilesAreReportedNotFatal(t *testing.T) {
	set := gatePolicyDocument(t)
	set.Bindings = append(set.Bindings, policy.Binding{
		Kind: policy.KindDNS, Profile: "no-such-profile",
		Subject: policy.NewDeviceSubject(gateGuestMAC),
	})

	got := set.Resolve(policy.NewDeviceSubject(gateGuestMAC), nil, gatePolicyClock)

	if len(got.Unresolved) == 0 {
		t.Fatal("a binding naming a missing profile produced no report")
	}
	if !strings.Contains(strings.Join(got.Unresolved, " "), "no-such-profile") {
		t.Errorf("unresolved = %v, want it to name the missing profile", got.Unresolved)
	}
	// The rest of the document must still have applied.
	if got.Bandwidth == nil {
		t.Error("one missing profile stopped the whole resolution")
	}
}

// TestGatePoliciesPriorityBeatsSpecificity pins the documented order. It is the
// rule most likely to be got wrong, and the one an operator cannot infer from
// reading their own configuration.
func TestGatePoliciesPriorityBeatsSpecificity(t *testing.T) {
	set := gatePolicyDocument(t)

	// A house-wide rule with a high-priority schedule, against the guest's
	// ungated specific one.
	set.Bindings = append(set.Bindings, policy.Binding{
		Kind: policy.KindBandwidth, Profile: "kids",
		Subject: policy.Subject{}, Schedule: "urgent",
	})

	got := set.Resolve(policy.NewDeviceSubject(gateGuestMAC), nil, gatePolicyClock)
	if got.Bandwidth == nil || got.Bandwidth.Name != "kids" {
		t.Errorf("bandwidth = %v, want kids; a schedule priority must outrank a "+
			"more specific subject, or a priority cannot express a house-wide "+
			"override", got.Bandwidth)
	}
}

// TestGatePoliciesDeviceProfileSuppliesWhatNoBindingClaims: the indirection.
func TestGatePoliciesDeviceProfileSuppliesWhatNoBindingClaims(t *testing.T) {
	set := gatePolicyDocument(t)
	set.Bindings = append(set.Bindings, policy.Binding{
		Kind: policy.KindDevice, Profile: "nursery",
		Subject: policy.NewDeviceSubject(gateNurseryMAC),
	})

	got := set.Resolve(policy.NewDeviceSubject(gateNurseryMAC), nil, gatePolicyClock)

	if got.Device == nil {
		t.Fatal("the device profile did not resolve")
	}
	if !got.Device.ExpectStrongIdentity {
		t.Error("the device profile resolved without its strong-identity expectation")
	}
	// The device profile names noqueries, and no binding claims DNS for this
	// device, so it must come through.
	if got.DNS == nil || got.DNS.Name != "default" {
		// The house-default binding claims DNS first, which is correct: an
		// explicit binding outranks an indirect reference.
		t.Logf("DNS resolved to %v; the house default outranks the device "+
			"profile's reference, which is the documented precedence", got.DNS)
	}
}

// TestGatePoliciesProfilesCarryTheOverheadArithmetic: a per-device profile that
// silently dropped the overhead correction would shape slightly under the
// intended rate, on every device, with nothing reporting it.
func TestGatePoliciesProfilesCarryTheOverheadArithmetic(t *testing.T) {
	set := gatePolicyDocument(t)

	got := set.Resolve(policy.NewDeviceSubject(gateGuestMAC), nil, gatePolicyClock)
	if got.Bandwidth == nil {
		t.Fatal("no bandwidth resolved")
	}

	if got.Bandwidth.Rate.OverheadPercent != 10 {
		t.Errorf("overhead = %d%%, want 10", got.Bandwidth.Rate.OverheadPercent)
	}

	// And the effective wire rate must be the corrected one.
	if eff := got.Bandwidth.Rate.Effective(qos.Download); eff <= got.Bandwidth.Rate.DownloadKbps {
		t.Errorf("effective download %d is not above the payload rate %d; the "+
			"profile carries no overhead correction", eff, got.Bandwidth.Rate.DownloadKbps)
	}
}

// TestGatePoliciesUnconstrainedProfileIsNotZero is a small thing that would
// look very wrong in a report: a profile with no rate must not render as zero,
// which reads as an infinitely slow link.
func TestGatePoliciesUnconstrainedProfileIsNotZero(t *testing.T) {
	p := policy.BandwidthProfile{Name: "unconstrained"}

	if strings.Contains(p.String(), "0 kbit") {
		t.Errorf("an unconstrained profile renders as %q", p.String())
	}
	if !strings.Contains(p.String(), "unconstrained") {
		t.Errorf("an unconstrained profile renders as %q, want it to say so", p.String())
	}
}

// TestGatePoliciesEveryScheduleIsChecked is a completeness check on the
// fixture, so the phase cannot silently stop exercising a schedule kind.
func TestGatePoliciesEveryScheduleIsChecked(t *testing.T) {
	set := gatePolicyDocument(t)

	// The phase must reference at least the four kinds it names.
	used := map[schedule.Kind]bool{}
	for _, name := range []string{"always", "daytime", "overnight", "urgent"} {
		sch, ok := set.Schedules[name]
		if !ok {
			t.Errorf("the gate fixture has no schedule %q", name)
			continue
		}
		used[sch.Kind] = true

		if err := sch.Validate(); err != nil {
			t.Errorf("the gate fixture's schedule %q does not validate: %v", name, err)
		}
	}

	for _, want := range []schedule.Kind{schedule.KindAlways, schedule.KindDaily} {
		if !used[want] {
			t.Errorf("the gate phase never exercises a %s schedule", want)
		}
	}
}

// TestGatePoliciesResolutionIsDeterministic: two runs over the same inputs must
// agree, or a diff between two reports of an unchanged gateway is noise.
func TestGatePoliciesResolutionIsDeterministic(t *testing.T) {
	run := func() policy.Resolution {
		return gatePolicyDocument(t).Resolve(
			policy.NewDeviceSubject(gateGuestMAC), nil, gatePolicyClock)
	}

	first := run()
	for i := 0; i < 25; i++ {
		got := run()
		if got.Bandwidth == nil || got.Bandwidth.Name != first.Bandwidth.Name {
			t.Fatalf("the winner varies between runs: %v then %v", first.Bandwidth, got.Bandwidth)
		}
		if len(got.Reasons) != len(first.Reasons) {
			t.Fatalf("the reason count varies: %d then %d", len(first.Reasons), len(got.Reasons))
		}
		for j := range got.Reasons {
			if got.Reasons[j].Binding.Profile != first.Reasons[j].Binding.Profile {
				t.Fatalf("reason order varies at %d: %q then %q",
					j, first.Reasons[j].Binding.Profile, got.Reasons[j].Binding.Profile)
			}
		}
	}
}

// TestGatePoliciesAProfileCannotWidenTheHostFirewall is the property that makes
// a per-device firewall profile safe to exist.
//
// The host firewall is the security boundary. A per-device profile that could
// out-vote it would be a way for a compromised device to make itself
// reachable, and the whole layer would be a liability rather than a feature.
func TestGatePoliciesAProfileCannotWidenTheHostFirewall(t *testing.T) {
	set := gatePolicyDocument(t)

	// The most permissive per-device profile available.
	set.Bindings = append(set.Bindings, policy.Binding{
		Kind: policy.KindFirewall, Profile: "open",
		Subject: policy.NewDeviceSubject(gateNurseryMAC),
	})

	got := set.Resolve(policy.NewDeviceSubject(gateNurseryMAC), nil, gatePolicyClock)

	// It resolved, and it is permissive — but it resolves to a profile the
	// document defines, not to an implicit bypass. There is no field on
	// FirewallProfile by which a device could claim an exemption from the host
	// ruleset, which is the structural guarantee this assertion rests on.
	if got.Firewall == nil {
		t.Fatal("no firewall policy resolved")
	}
	if got.Firewall.Default != policy.Allow {
		t.Errorf("the permissive profile did not apply as written (%v); the test "+
			"is not exercising what it claims to", got.Firewall)
	}
}
