package schedule_test

import (
	"strings"
	"testing"
	"time"

	"github.com/venth/thn-gateway/internal/schedule"
)

// mustClock builds a wall clock or fails the test.
func mustClock(t *testing.T, h, m int) schedule.WallClock {
	t.Helper()

	c, err := schedule.NewWallClock(h, m)
	if err != nil {
		t.Fatalf("building %02d:%02d: %v", h, m, err)
	}
	return c
}

// at builds a moment in a zone.
func at(t *testing.T, zone string, y int, mo time.Month, d, h, mi int) time.Time {
	t.Helper()

	loc := time.UTC
	if zone != "" {
		l, err := time.LoadLocation(zone)
		if err != nil {
			t.Skipf("the %s timezone is not available in this environment: %v", zone, err)
		}
		loc = l
	}
	return time.Date(y, mo, d, h, mi, 0, 0, loc)
}

// TestOvernightWindowIsTheFirstTrap is the case a naive comparison gets wrong,
// and it is the case this package exists to be right about.
//
// A window from 22:00 to 06:00 has a start later than its end. Written as
// start <= t < end it never matches, and the schedule silently never applies —
// which is indistinguishable from a schedule that is working and has nothing to
// do.
func TestOvernightWindowIsTheFirstTrap(t *testing.T) {
	s := schedule.Daily("overnight", "UTC", mustClock(t, 22, 0), mustClock(t, 6, 0), 0)

	cases := []struct {
		name string
		when time.Time
		want bool
	}{
		{"21:59, just before", at(t, "", 2026, time.March, 14, 21, 59), false},
		{"22:00, at the start", at(t, "", 2026, time.March, 14, 22, 0), true},
		{"23:30, middle of the night", at(t, "", 2026, time.March, 14, 23, 30), true},
		{"00:00, after midnight", at(t, "", 2026, time.March, 15, 0, 0), true},
		{"05:59, just before the end", at(t, "", 2026, time.March, 15, 5, 59), true},
		{"06:00, at the end", at(t, "", 2026, time.March, 15, 6, 0), false},
		{"12:00, the gap during the day", at(t, "", 2026, time.March, 15, 12, 0), false},
		{"21:00, approaching again", at(t, "", 2026, time.March, 15, 21, 0), false},
	}

	for _, c := range cases {
		got := s.Active(c.when)
		if got.Active != c.want {
			t.Errorf("%s: active = %v, want %v (%s)", c.name, got.Active, c.want, got.Reason)
		}
	}
}

// TestDaytimeWindowDoesNotWrap is the control for the case above. A window that
// does not cross midnight must not become active during the small hours, which
// is what a comparison that ignores the direction of the window would do.
func TestDaytimeWindowDoesNotWrap(t *testing.T) {
	s := schedule.Daily("business", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0), 0)

	cases := []struct {
		when time.Time
		want bool
	}{
		{at(t, "", 2026, time.March, 14, 8, 59), false},
		{at(t, "", 2026, time.March, 14, 9, 0), true},
		{at(t, "", 2026, time.March, 14, 12, 0), true},
		{at(t, "", 2026, time.March, 14, 17, 0), false},
		{at(t, "", 2026, time.March, 14, 23, 0), false},
		{at(t, "", 2026, time.March, 15, 2, 0), false},
	}

	for _, c := range cases {
		if got := s.Active(c.when).Active; got != c.want {
			t.Errorf("%s: active = %v, want %v", c.when.Format("15:04"), got, c.want)
		}
	}
}

// TestBoundariesAreHalfOpen is the property that lets two back-to-back windows
// tile a day without a gap or an overlap. An inclusive end would make 09:00
// belong to both the 08:00-09:00 window and the 09:00-10:00 one, and an operator
// would see two policies apply at once.
func TestBoundariesAreHalfOpen(t *testing.T) {
	first := schedule.Daily("first", "UTC", mustClock(t, 8, 0), mustClock(t, 9, 0), 0)
	second := schedule.Daily("second", "UTC", mustClock(t, 9, 0), mustClock(t, 10, 0), 0)

	at9 := at(t, "", 2026, time.March, 14, 9, 0)

	if first.Active(at9).Active {
		t.Error("the 08:00-09:00 window is active at 09:00; the end is inclusive")
	}
	if !second.Active(at9).Active {
		t.Error("the 09:00-10:00 window is not active at 09:00; the start is exclusive")
	}
}

// TestTwoBackToBackWindowsTileADay: the consequence of half-open intervals,
// asserted directly because it is the property operators depend on.
func TestTwoBackToBackWindowsTileADay(t *testing.T) {
	first := schedule.Daily("morning", "UTC", mustClock(t, 8, 0), mustClock(t, 9, 0), 0)
	second := schedule.Daily("mid-morning", "UTC", mustClock(t, 9, 0), mustClock(t, 10, 0), 0)

	// Walk the span the two windows share, minute by minute, and assert
	// exactly one of them applies. The walk is bounded to 08:00-10:00: outside
	// that span neither window applies, and "exactly one" would be the wrong
	// claim there rather than a defect in the tiling.
	for m := 8 * 60; m < 10*60; m++ {
		moment := at(t, "", 2026, time.March, 14, m/60, m%60)

		a, b := first.Active(moment).Active, second.Active(moment).Active
		if a == b {
			t.Errorf("%s: both = %v, want exactly one; the windows leave a %s",
				moment.Format("15:04"), a, map[bool]string{false: "gap", true: "overlap"}[a])
		}
	}

	// And outside it, neither applies.
	for _, m := range []int{7 * 60, 7*60 + 59, 10 * 60, 23 * 60} {
		moment := at(t, "", 2026, time.March, 14, m/60, m%60)
		if first.Active(moment).Active || second.Active(moment).Active {
			t.Errorf("%s: a window is active outside 08:00-10:00",
				moment.Format("15:04"))
		}
	}
}

// TestNextChangeIsTheNextTransition is what lets a daemon sleep until the
// answer changes rather than polling. Without it, a caller either wakes far too
// often or sleeps through a change.
func TestNextChangeIsTheNextTransition(t *testing.T) {
	s := schedule.Daily("business", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0), 0)

	beforeOpen := at(t, "", 2026, time.March, 14, 8, 0)
	got := s.Active(beforeOpen)
	if got.Active {
		t.Fatal("the window is active before it opens")
	}
	if !got.NextChange.Equal(at(t, "", 2026, time.March, 14, 9, 0)) {
		t.Errorf("next change = %s, want 09:00 today", got.NextChange)
	}

	inside := s.Active(at(t, "", 2026, time.March, 14, 12, 0))
	if !inside.Active {
		t.Fatal("the window is not active at noon")
	}
	if !inside.NextChange.Equal(at(t, "", 2026, time.March, 14, 17, 0)) {
		t.Errorf("next change = %s, want 17:00 today", inside.NextChange)
	}

	afterClose := s.Active(at(t, "", 2026, time.March, 14, 18, 0))
	if afterClose.Active {
		t.Fatal("the window is active after it closes")
	}
	// Tomorrow morning, not tonight: the window closed rather than opening.
	want := at(t, "", 2026, time.March, 15, 9, 0)
	if !afterClose.NextChange.Equal(want) {
		t.Errorf("next change = %s, want %s", afterClose.NextChange, want)
	}
}

// TestNextChangeForAnOvernightWindow spans the midnight crossing, which is where
// a next-change calculation usually goes wrong.
func TestNextChangeForAnOvernightWindow(t *testing.T) {
	s := schedule.Daily("overnight", "UTC", mustClock(t, 22, 0), mustClock(t, 6, 0), 0)

	cases := []struct {
		name string
		when time.Time
		want time.Time
	}{
		{
			"before opening tonight",
			at(t, "", 2026, time.March, 14, 20, 0),
			at(t, "", 2026, time.March, 14, 22, 0),
		},
		{
			"inside, before midnight",
			at(t, "", 2026, time.March, 14, 23, 0),
			at(t, "", 2026, time.March, 15, 6, 0),
		},
		{
			"inside, after midnight",
			at(t, "", 2026, time.March, 15, 2, 0),
			at(t, "", 2026, time.March, 15, 6, 0),
		},
		{
			"in the daytime gap",
			at(t, "", 2026, time.March, 15, 12, 0),
			at(t, "", 2026, time.March, 15, 22, 0),
		},
	}

	for _, c := range cases {
		got := s.Active(c.when)
		if !got.NextChange.Equal(c.want) {
			t.Errorf("%s: next change = %s, want %s", c.name,
				got.NextChange.Format("2006-01-02 15:04"), c.want.Format("2006-01-02 15:04"))
		}
	}
}

// TestTimezoneIsTheSecondTrap: a window expressed in local time must stay at
// that local time across a daylight-saving change.
//
// The UTC offset of the zone moves; the wall clock the operator wrote does not.
// A window stored as a duration since midnight would be an hour wrong for half
// the year, and the symptom would be a bandwidth limit that applies at 10am in
// summer.
func TestTimezoneIsTheSecondTrap(t *testing.T) {
	// Europe/Madrid moves from UTC+1 to UTC+2 on 29 March 2026.
	zone := "Europe/Madrid"

	before := at(t, zone, 2026, time.March, 28, 12, 0)
	after := at(t, zone, 2026, time.March, 30, 12, 0)

	offsetBefore := before.Format("-07:00")
	offsetAfter := after.Format("-07:00")
	if offsetBefore == offsetAfter {
		t.Skipf("Europe/Madrid did not change offset across this date (%s)", offsetBefore)
	}

	s := schedule.Daily("local-nine", zone, mustClock(t, 9, 0), mustClock(t, 17, 0), 0)

	// 09:00 local is 09:00 local on both sides of the change, even though the
	// UTC instants differ by an hour.
	for _, moment := range []time.Time{before, after} {
		got := s.Active(moment)
		if !got.Active {
			t.Errorf("%s (%s): the 09:00-17:00 local window is not active at "+
				"09:00-17:00 local", moment.Format("2006-01-02 15:04"), moment.Format("-07:00"))
		}
	}

	// And the window must not drift: 08:30 local is still outside it.
	morning := time.Date(2026, time.March, 30, 8, 30, 0, 0, mustLoad(t, zone))
	if s.Active(morning).Active {
		t.Error("the window is active at 08:30 local; it drifted across the " +
			"daylight-saving change")
	}
}

// mustLoad loads a location or fails the test.
func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()

	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("the %s timezone is not available: %v", name, err)
	}
	return loc
}

// TestWeeklyRespectsNamedDays: a schedule that ignores its day list would apply
// every day, which is how a "weekend only" guest limit becomes a permanent one.
func TestWeeklyRespectsNamedDays(t *testing.T) {
	s := schedule.Weekly("weekend", "UTC", mustClock(t, 0, 0), mustClock(t, 23, 59),
		[]schedule.Day{schedule.DaySaturday, schedule.DaySunday}, 0)

	// 14 March 2026 is a Saturday.
	saturday := at(t, "", 2026, time.March, 14, 12, 0)
	if !s.Active(saturday).Active {
		t.Error("the weekend window is not active on a Saturday")
	}

	sunday := at(t, "", 2026, time.March, 15, 12, 0)
	if !s.Active(sunday).Active {
		t.Error("the weekend window is not active on a Sunday")
	}

	monday := at(t, "", 2026, time.March, 16, 12, 0)
	got := s.Active(monday)
	if got.Active {
		t.Error("the weekend window is active on a Monday")
	}
	if got.NextChange.IsZero() {
		t.Error("no next change on a day the window excludes; a caller would have " +
			"to poll to find out when the window returns")
	}
	if !got.NextChange.Equal(at(t, "", 2026, time.March, 21, 0, 0)) {
		t.Errorf("next change = %s, want Saturday 21 March", got.NextChange)
	}
}

// TestWeeklyOvernightAcrossMidnight: the day a window belongs to is the day it
// opens. A window from Friday 22:00 to Saturday 06:00 is still Friday's window
// at 03:00 on Saturday, and testing Saturday alone would get this wrong.
func TestWeeklyOvernightAcrossMidnight(t *testing.T) {
	// Friday 20:00 to Saturday 06:00, on Fridays only.
	s := schedule.Weekly("friday-night", "UTC", mustClock(t, 22, 0), mustClock(t, 6, 0),
		[]schedule.Day{schedule.DayFriday}, 0)

	// 20 March 2026 is a Friday.
	fridayLate := at(t, "", 2026, time.March, 20, 23, 0)
	if !s.Active(fridayLate).Active {
		t.Error("not active on Friday night")
	}

	// 03:00 on Saturday is still inside Friday's window.
	saturdayEarly := at(t, "", 2026, time.March, 21, 3, 0)
	if !s.Active(saturdayEarly).Active {
		t.Error("not active at 03:00 on Saturday; the window belongs to the day " +
			"it opens, not the day it is observed on")
	}

	// 23:00 on Saturday is not: Saturday is not a named day.
	saturdayNight := at(t, "", 2026, time.March, 21, 23, 0)
	if s.Active(saturdayNight).Active {
		t.Error("active on Saturday night, which is not a named day")
	}
}

// TestWeeklyDailyRespectsDayBeforeCheckingTheWindow: on a day the schedule
// excludes, the window is irrelevant however the clock falls.
func TestWeeklyDailyRespectsDayBeforeCheckingTheWindow(t *testing.T) {
	s := schedule.Weekly("weekdays", "UTC", mustClock(t, 0, 0), mustClock(t, 23, 59),
		[]schedule.Day{schedule.DayMonday, schedule.DayTuesday, schedule.DayWednesday,
			schedule.DayThursday, schedule.DayFriday}, 0)

	saturday := at(t, "", 2026, time.March, 14, 12, 0)
	if s.Active(saturday).Active {
		t.Error("a weekday-only window is active on a Saturday")
	}
}

// TestOnceWindowIsBounded: a maintenance window expressed once rather than
// weekly, which is the case where an end boundary actually matters.
func TestOnceWindowIsBounded(t *testing.T) {
	start := at(t, "", 2026, time.March, 21, 2, 0)
	end := at(t, "", 2026, time.March, 21, 4, 0)

	s := schedule.Schedule{
		Name: "maintenance", Kind: schedule.KindOnce,
		Start: start, End: end,
	}

	if s.Active(start.Add(-time.Hour)).Active {
		t.Error("active before the window opens")
	}
	if !s.Active(start).Active {
		t.Error("not active at the start")
	}
	if !s.Active(start.Add(time.Hour)).Active {
		t.Error("not active in the middle")
	}
	if s.Active(end).Active {
		t.Error("active at the end; the end is exclusive")
	}
	if s.Active(end.Add(time.Hour)).Active {
		t.Error("active after the window closed")
	}

	// A closed once window has no next change: the answer is permanent.
	closed := s.Active(end.Add(time.Hour))
	if !closed.NextChange.IsZero() {
		t.Errorf("a closed one-shot window reports a next change at %s", closed.NextChange)
	}
	if !strings.Contains(closed.Reason, "ago") {
		t.Errorf("reason %q does not say the window has passed", closed.Reason)
	}
}

// TestAlwaysAndNeverNeedNoBoundary: their answer is permanent, so reporting a
// next change would send a caller chasing a transition that never comes.
func TestAlwaysAndNeverNeedNoBoundary(t *testing.T) {
	moment := at(t, "", 2026, time.March, 14, 12, 0)

	if got := schedule.Always("on").Active(moment); !got.Active {
		t.Error("an always schedule is not active")
	} else if !got.NextChange.IsZero() {
		t.Errorf("an always schedule reports a next change at %s", got.NextChange)
	}

	if got := schedule.Never("off").Active(moment); got.Active {
		t.Error("a never schedule is active")
	} else if !got.NextChange.IsZero() {
		t.Errorf("a never schedule reports a next change at %s", got.NextChange)
	}
}

// TestEveryResultExplainsItself: a schedule that quietly does not apply is
// indistinguishable from a policy that was never bound.
func TestEveryResultExplainsItself(t *testing.T) {
	moment := at(t, "", 2026, time.March, 14, 12, 0)

	schedules := []schedule.Schedule{
		schedule.Always("on"),
		schedule.Never("off"),
		schedule.Daily("day", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0), 0),
		schedule.Daily("night", "UTC", mustClock(t, 22, 0), mustClock(t, 6, 0), 0),
		schedule.Weekly("weekend", "UTC", mustClock(t, 0, 0), mustClock(t, 23, 59),
			[]schedule.Day{schedule.DaySaturday}, 0),
		schedule.Schedule{
			Name: "once", Kind: schedule.KindOnce,
			Start: at(t, "", 2026, time.March, 21, 2, 0),
			End:   at(t, "", 2026, time.March, 21, 4, 0),
		},
		{Name: "nonsense", Kind: "whenever"},
	}

	for _, s := range schedules {
		got := s.Active(moment)
		if strings.TrimSpace(got.Reason) == "" {
			t.Errorf("schedule %q returned no reason", s.Name)
		}
		if !strings.Contains(got.Reason, s.Name) {
			t.Errorf("schedule %q reason %q does not name the schedule, so an "+
				"operator cannot tell which one was evaluated", s.Name, got.Reason)
		}
	}
}

// TestUnknownKindDoesNotApply is the fail-closed direction: an unrecognised
// schedule must not be treated as active, because applying an unknown policy is
// the worse failure.
func TestUnknownKindDoesNotApply(t *testing.T) {
	s := schedule.Schedule{Name: "mystery", Kind: "whenever"}

	got := s.Active(at(t, "", 2026, time.March, 14, 12, 0))
	if got.Active {
		t.Error("an unknown schedule kind is active; it should fail closed")
	}
	if !strings.Contains(got.Reason, "unknown kind") {
		t.Errorf("reason %q does not say the kind was unrecognised", got.Reason)
	}
}

// TestZeroTimeRefusesToConclude: a zero time is a caller bug, and treating it
// as a real moment would produce a confident answer about the year 1.
func TestZeroTimeRefusesToConclude(t *testing.T) {
	got := schedule.Always("on").Active(time.Time{})
	if got.Active {
		t.Error("a schedule evaluated at the zero time reported itself active")
	}
	if !strings.Contains(got.Reason, "zero time") {
		t.Errorf("reason %q does not identify the zero time as the problem", got.Reason)
	}
}

// TestValidateRejectsInertSchedules: each of these is a schedule that loads
// successfully and then never does anything, which is the worst kind of
// configuration error.
func TestValidateRejectsInertSchedules(t *testing.T) {
	cases := []struct {
		name string
		s    schedule.Schedule
	}{
		{"no name", schedule.Schedule{Kind: schedule.KindAlways}},
		{"unknown kind", schedule.Schedule{Name: "x", Kind: "sometimes"}},
		{
			"unresolvable location",
			schedule.Daily("x", "Mars/Olympus", mustClock(t, 9, 0), mustClock(t, 17, 0), 0),
		},
		{
			"not a weekday",
			schedule.Weekly("x", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0),
				[]schedule.Day{"caturday"}, 0),
		},
		{
			"once with no end",
			schedule.Schedule{Name: "x", Kind: schedule.KindOnce,
				Start: at(t, "", 2026, time.March, 21, 2, 0)},
		},
		{
			"once that ends before it starts",
			schedule.Schedule{Name: "x", Kind: schedule.KindOnce,
				Start: at(t, "", 2026, time.March, 21, 4, 0),
				End:   at(t, "", 2026, time.March, 21, 2, 0)},
		},
		{
			// Active at exactly one instant of the day, and therefore never
			// observed by anything that polls.
			"zero-length daily window",
			schedule.Daily("x", "UTC", mustClock(t, 0, 0), mustClock(t, 0, 0), 0),
		},
		{
			"weekly with no days",
			schedule.Weekly("x", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0), nil, 0),
		},
		{
			// A daily schedule that names days is a weekly schedule written as
			// a daily one, and would silently ignore the days.
			"daily naming days",
			schedule.Schedule{
				Name: "x", Kind: schedule.KindDaily,
				From: mustClock(t, 9, 0), To: mustClock(t, 17, 0),
				Days: []schedule.Day{schedule.DayMonday},
			},
		},
	}

	for _, c := range cases {
		if err := c.s.Validate(); err == nil {
			t.Errorf("%s: a schedule with %s validated", c.name, c.name)
		}
	}

	// And a well-formed schedule must pass, or the validation is useless.
	good := []schedule.Schedule{
		schedule.Always("on"),
		schedule.Never("off"),
		schedule.Daily("day", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0), 0),
		schedule.Daily("night", "UTC", mustClock(t, 22, 0), mustClock(t, 6, 0), 0),
		schedule.Weekly("weekend", "UTC", mustClock(t, 0, 0), mustClock(t, 23, 59),
			[]schedule.Day{schedule.DaySaturday, schedule.DaySunday}, 0),
	}

	for _, s := range good {
		if err := s.Validate(); err != nil {
			t.Errorf("schedule %q was rejected: %v", s.Name, err)
		}
	}
}

// TestStringRendersWhatWasConfigured: an operator checking a schedule against
// the configuration they wrote needs the same fields in the same words.
func TestStringRendersWhatWasConfigured(t *testing.T) {
	cases := []struct {
		s    schedule.Schedule
		want []string
	}{
		{schedule.Always("always-on"), []string{"always-on", "always"}},
		{schedule.Never("disabled"), []string{"disabled", "never"}},
		{
			schedule.Daily("business", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0), 0),
			[]string{"business", "09:00-17:00", "every day", "UTC"},
		},
		{
			schedule.Weekly("weekend", "UTC", mustClock(t, 0, 0), mustClock(t, 23, 59),
				[]schedule.Day{schedule.DaySunday, schedule.DaySaturday}, 0),
			[]string{"weekend", "saturday", "sunday"},
		},
	}

	for _, c := range cases {
		got := c.s.String()
		for _, want := range c.want {
			if !strings.Contains(got, want) {
				t.Errorf("String = %q, want it to contain %q", got, want)
			}
		}
	}
}

// TestDayOrderIsMondayFirstAndIndependent: the mapping from time.Weekday to
// Day is arithmetic, and arithmetic of this kind is wrong exactly once. It is
// checked against every day of a known week.
func TestDayOrderIsMondayFirstAndIndependent(t *testing.T) {
	// 16 March 2026 is a Monday.
	monday := at(t, "", 2026, time.March, 16, 12, 0)

	want := []schedule.Day{
		schedule.DayMonday, schedule.DayTuesday, schedule.DayWednesday,
		schedule.DayThursday, schedule.DayFriday, schedule.DaySaturday,
		schedule.DaySunday,
	}

	// Each weekday gets a schedule naming only that day, and must be active
	// exactly on that day of the week.
	for i, day := range want {
		s := schedule.Weekly("only-"+string(day), "UTC",
			mustClock(t, 0, 0), mustClock(t, 23, 59), []schedule.Day{day}, 0)

		moment := monday.AddDate(0, 0, i)
		if got := s.Active(moment); !got.Active {
			t.Errorf("a schedule naming only %s is not active on %s (%s)",
				day, moment.Weekday(), moment.Format("2006-01-02"))
		}

		// And on the following day it must not be.
		next := moment.AddDate(0, 0, 1)
		if s.Active(next).Active {
			t.Errorf("a schedule naming only %s is also active on %s",
				day, next.Weekday())
		}
	}
}

// TestEqualIgnoresDayOrderButNotContent: day order in the document is a
// formatting choice and must not register as a change, but a different day must.
func TestEqualIgnoresDayOrderButNotContent(t *testing.T) {
	a := schedule.Weekly("x", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0),
		[]schedule.Day{schedule.DayMonday, schedule.DayWednesday}, 0)
	b := schedule.Weekly("x", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0),
		[]schedule.Day{schedule.DayWednesday, schedule.DayMonday}, 0)
	if !a.Equal(b) {
		t.Error("two schedules differing only in day order are not equal; a " +
			"reformatted document would look like a policy change")
	}

	c := schedule.Weekly("x", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0),
		[]schedule.Day{schedule.DayMonday, schedule.DayThursday}, 0)
	if a.Equal(c) {
		t.Error("two schedules naming different days are equal")
	}

	d := schedule.Weekly("x", "UTC", mustClock(t, 9, 0), mustClock(t, 17, 0),
		[]schedule.Day{schedule.DayMonday, schedule.DayWednesday}, 5)
	if a.Equal(d) {
		t.Error("two schedules with different priorities are equal")
	}
}
