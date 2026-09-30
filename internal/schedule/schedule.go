// Package schedule expresses when a policy applies.
//
// # Why the time model comes first
//
// Every other thing in this layer — a device's bandwidth, its resolver, its
// access — can be made time-varying. So the time model is shared, and getting
// it subtly wrong would put the same subtle error in four places, each of
// which would be reported as a different symptom.
//
// A schedule that is off by an hour is not a scheduling bug that shows up as a
// scheduling bug. It is a bandwidth limit that applies at the wrong time, a
// firewall rule that opens when the owner expects it closed, a resolver that
// changes while somebody is working. The package exists to make that one class
// of error testable in isolation.
//
// # The three traps
//
// Overnight windows. A window from 22:00 to 06:00 has a start later than its
// end. Written as start <= t < end it never matches, and the schedule silently
// never applies — which looks exactly like a schedule that is working and has
// nothing to do.
//
// Timezone. A window expressed in local time must stay at 09:00 local across a
// daylight-saving change, which means the window cannot be a pair of absolute
// instants. It is a pair of wall-clock times, and they are resolved against the
// zone on the day in question.
//
// Boundaries. A window ending at 06:00 does not include 06:00, and a window
// starting at 22:00 does. Half-open intervals are the only choice that
// partitions a day without a gap or an overlap at the seam, and an inclusive
// end would make two back-to-back windows both apply at midnight.
//
// # NextChange
//
// Active now is half the question. The other half is when the answer changes,
// and a caller that has to poll to find out is a caller that either wakes too
// often or sleeps through a change. NextChange is what lets a daemon sleep
// until the next transition and no longer.
package schedule

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Kind is how a schedule recurs.
type Kind string

const (
	// KindAlways is active at every moment.
	KindAlways Kind = "always"

	// KindNever is never active. It exists so a schedule can be disabled
	// visibly rather than deleted: a deleted schedule leaves no trace, and a
	// policy that stopped applying because someone removed a line is the
	// hardest kind of outage to find.
	KindNever Kind = "never"

	// KindOnce applies between two absolute instants.
	//
	// It is the only kind that takes absolute times, and it exists for
	// "maintenance window on Saturday" expressed once rather than weekly.
	KindOnce Kind = "once"

	// KindDaily applies during a time-of-day window, every day.
	KindDaily Kind = "daily"

	// KindWeekly applies during a time-of-day window, on named days.
	KindWeekly Kind = "weekly"
)

// Valid reports whether the kind is one of the defined values.
func (k Kind) Valid() bool {
	switch k {
	case KindAlways, KindNever, KindOnce, KindDaily, KindWeekly:
		return true
	}
	return false
}

// WallClock is a time of day, with no date and no zone.
//
// It is deliberately not a time.Duration since midnight. A duration loses the
// distinction between 02:00 and 14:00, and that distinction is the whole
// content of a daily window.
type WallClock struct {
	Hour   int `json:"hour"`
	Minute int `json:"minute"`
}

// NewWallClock builds a wall-clock time, rejecting out-of-range values.
func NewWallClock(hour, minute int) (WallClock, error) {
	if hour < 0 || hour > 23 {
		return WallClock{}, fmt.Errorf("hour %d is outside 0-23", hour)
	}
	if minute < 0 || minute > 59 {
		return WallClock{}, fmt.Errorf("minute %d is outside 0-59", minute)
	}
	return WallClock{Hour: hour, Minute: minute}, nil
}

// Minutes returns the offset from midnight.
//
// It is used for comparison and for deciding whether a window is overnight,
// never for reconstructing a moment — that is what would break across a zone
// change.
func (w WallClock) Minutes() int { return w.Hour*60 + w.Minute }

// String renders the wall clock in 24-hour form.
func (w WallClock) String() string { return fmt.Sprintf("%02d:%02d", w.Hour, w.Minute) }

// Day is a weekday.
type Day string

const (
	DayMonday    Day = "monday"
	DayTuesday   Day = "tuesday"
	DayWednesday Day = "wednesday"
	DayThursday  Day = "thursday"
	DayFriday    Day = "friday"
	DaySaturday  Day = "saturday"
	DaySunday    Day = "sunday"
)

// Days is the set of weekdays, Monday first.
var Days = []Day{
	DayMonday, DayTuesday, DayWednesday, DayThursday,
	DayFriday, DaySaturday, DaySunday,
}

// Valid reports whether the day is one of the seven.
func (d Day) Valid() bool {
	for _, known := range Days {
		if d == known {
			return true
		}
	}
	return false
}

// dayOf maps a time.Weekday onto a Day.
//
// time.Weekday has Sunday as 0, so the mapping is arithmetic. Arithmetic of
// this kind is wrong exactly once and never again, and it is done here so
// there is one place for it to be wrong — and one test that checks all seven
// days against a known week.
func dayOf(w time.Weekday) Day {
	return Days[(int(w)+6)%7]
}

// Schedule is when something applies.
type Schedule struct {
	// Name identifies the schedule, in `thn policy resolve` output.
	Name string `json:"name"`

	// Kind is how it recurs.
	Kind Kind `json:"kind"`

	// Location names the timezone the daily and weekly windows are expressed
	// in. Empty means UTC.
	//
	// It is a string rather than a *time.Location because a schedule has to
	// survive a round trip through the configuration document, and because
	// "Europe/Madrid" is what an operator wrote. The location is loaded at
	// evaluation and a name that does not resolve is reported by Validate
	// rather than becoming a runtime surprise.
	Location string `json:"location,omitempty"`

	// Start and End bound a once schedule. Both are absolute.
	Start time.Time `json:"start,omitempty"`
	End   time.Time `json:"end,omitempty"`

	// From and To bound the time-of-day window for daily and weekly kinds.
	//
	// From may be later than To, which means the window crosses midnight. That
	// is the ordinary way to express "overnight" and it is the case a naive
	// comparison gets wrong.
	From WallClock `json:"from,omitempty"`
	To   WallClock `json:"to,omitempty"`

	// Days restricts a weekly schedule. Empty means every day.
	Days []Day `json:"days,omitempty"`

	// Priority breaks ties when two schedules for the same subject both match.
	//
	// Higher wins. It is an explicit integer rather than "most specific" or
	// "last declared" because those two orderings are surprising: an operator
	// who adds a rule at the bottom of a file and finds it ignored will not
	// work out why, and an operator who does not know about a conflict
	// resolution rule cannot predict their own configuration.
	Priority int `json:"priority,omitempty"`

	// Comments are emitted verbatim in rendered output.
	Comments []string `json:"comments,omitempty"`
}

// Result is what evaluating a schedule concluded.
type Result struct {
	// Active is whether the schedule applies at the evaluated moment.
	Active bool `json:"active"`

	// Reason explains the answer in a sentence.
	//
	// It is not decoration. A schedule that quietly does not apply looks
	// identical to a policy that was never bound, and an operator debugging
	// "why is my guest still getting full speed at midnight" needs the
	// difference.
	Reason string `json:"reason"`

	// NextChange is when the answer will next differ, if it will.
	//
	// A zero value means the answer is permanent: always-on, never-on, or a
	// once window with no end.
	NextChange time.Time `json:"next_change,omitempty"`
}

// Always returns a schedule that applies at every moment.
func Always(name string) Schedule {
	return Schedule{Name: name, Kind: KindAlways}
}

// Never returns a schedule that never applies.
func Never(name string) Schedule {
	return Schedule{Name: name, Kind: KindNever}
}

// Daily builds a schedule active during a window every day.
func Daily(name, location string, from, to WallClock, priority int) Schedule {
	return Schedule{
		Name: name, Kind: KindDaily,
		Location: location,
		From:     from, To: to,
		Priority: priority,
	}
}

// Weekly builds a schedule active during a window on the named days.
func Weekly(name, location string, from, to WallClock, days []Day, priority int) Schedule {
	return Schedule{
		Name: name, Kind: KindWeekly,
		Location: location,
		From:     from, To: to,
		Days:     days,
		Priority: priority,
	}
}

// location returns the schedule's zone, or UTC.
func (s Schedule) location() *time.Location {
	if s.Location == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(s.Location)
	if err != nil {
		// An unresolvable zone is caught by Validate. Falling back to UTC here
		// means a caller that skipped validation gets a defined answer rather
		// than a panic, and Validate's error is the one that gets reported.
		return time.UTC
	}
	return loc
}

// Validate checks a schedule for the mistakes that make it inert.
func (s Schedule) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("a schedule must have a name; `thn policy resolve` reports " +
			"schedules by name and an unnamed one cannot be identified")
	}
	if !s.Kind.Valid() {
		return fmt.Errorf("schedule %q has kind %q, which is not one of always, never, "+
			"once, daily or weekly", s.Name, s.Kind)
	}

	if s.Location != "" {
		if _, err := time.LoadLocation(s.Location); err != nil {
			return fmt.Errorf("schedule %q names location %q, which does not resolve: %v",
				s.Name, s.Location, err)
		}
	}

	for _, d := range s.Days {
		if !d.Valid() {
			return fmt.Errorf("schedule %q names day %q, which is not a weekday", s.Name, d)
		}
	}

	switch s.Kind {
	case KindOnce:
		if s.Start.IsZero() || s.End.IsZero() {
			return fmt.Errorf("schedule %q is a once window but has no start or end", s.Name)
		}
		if !s.End.After(s.Start) {
			return fmt.Errorf("schedule %q ends at %s, which is not after its start %s; "+
				"a window that does not move forward can never apply",
				s.Name, s.End, s.Start)
		}
		// A once schedule's wall clock and day list are ignored rather than
		// rejected. They are commonly left over from a daily schedule that was
		// changed to a bounded one, and refusing to load a configuration over an
		// ignored field would be worse than ignoring it.

	case KindDaily, KindWeekly:
		// A zero-length window is active at exactly one instant of the day, and
		// therefore is never observed by anything that polls. It is rejected
		// rather than silently accepted, because a schedule that is active at
		// one instant and never seen is indistinguishable from one that was
		// never configured.
		if s.From.Minutes() == s.To.Minutes() {
			return fmt.Errorf("schedule %q has from %s equal to to %s, so it is active "+
				"at one instant of the day and never observed; use kind always or "+
				"never if that was not meant", s.Name, s.From, s.To)
		}
		if s.Kind == KindWeekly && len(s.Days) == 0 {
			return fmt.Errorf("schedule %q is weekly but names no days; it would apply "+
				"on none", s.Name)
		}
		if s.Kind == KindDaily && len(s.Days) > 0 {
			return fmt.Errorf("schedule %q is daily but names days, which it would "+
				"ignore; use kind weekly if you want it restricted to particular "+
				"days", s.Name)
		}
	}

	return nil
}

// String renders the schedule in a form an operator can check against the
// configuration they wrote.
func (s Schedule) String() string {
	switch s.Kind {
	case KindAlways:
		return fmt.Sprintf("%s: always", s.Name)
	case KindNever:
		return fmt.Sprintf("%s: never", s.Name)
	case KindOnce:
		return fmt.Sprintf("%s: from %s until %s",
			s.Name, s.Start.UTC().Format(time.RFC3339), s.End.UTC().Format(time.RFC3339))
	case KindDaily, KindWeekly:
		days := "every day"
		if len(s.Days) > 0 {
			days = strings.Join(dayStrings(s.Days), ",")
		}
		return fmt.Sprintf("%s: %s-%s %s (%s)", s.Name, s.From, s.To, days, s.LocationLabel())
	}
	return fmt.Sprintf("%s: %s", s.Name, s.Kind)
}

// Active evaluates the schedule at a moment.
func (s Schedule) Active(now time.Time) Result {
	if now.IsZero() {
		// A zero time is a caller bug rather than a real moment, and treating
		// it as one would give a confident answer about the year 1.
		return Result{
			Reason: fmt.Sprintf("schedule %q was evaluated at the zero time; "+
				"no conclusion is possible", s.Name),
		}
	}

	switch s.Kind {
	case KindAlways:
		return Result{
			Active: true,
			Reason: fmt.Sprintf("schedule %q is always active", s.Name),
		}

	case KindNever:
		return Result{
			Active: false,
			Reason: fmt.Sprintf("schedule %q is disabled (kind never)", s.Name),
		}

	case KindOnce:
		return s.once(now)

	case KindDaily, KindWeekly:
		return s.recurring(now)

	default:
		return Result{
			Reason: fmt.Sprintf("schedule %q has unknown kind %q; it is treated as "+
				"not applying rather than as an error, because applying an "+
				"unrecognised policy is the worse failure", s.Name, s.Kind),
		}
	}
}

// once evaluates a bounded window.
func (s Schedule) once(now time.Time) Result {
	switch {
	case now.Before(s.Start):
		return Result{
			Active: false,
			Reason: fmt.Sprintf("schedule %q starts at %s, which is %s away",
				s.Name, s.Start.UTC().Format(time.RFC3339), roundDur(s.Start.Sub(now))),
			NextChange: s.Start,
		}
	case !now.Before(s.End):
		return Result{
			Active: false,
			Reason: fmt.Sprintf("schedule %q ended at %s, %s ago",
				s.Name, s.End.UTC().Format(time.RFC3339), roundDur(now.Sub(s.End))),
		}
	default:
		return Result{
			Active: true,
			Reason: fmt.Sprintf("schedule %q is active; it ends at %s, in %s",
				s.Name, s.End.UTC().Format(time.RFC3339), roundDur(s.End.Sub(now))),
			NextChange: s.End,
		}
	}
}

// recurring evaluates a daily or weekly window.
//
// The window is resolved in the schedule's own zone, using the date as it is in
// that zone. That is what keeps "09:00" at 09:00 local across a daylight-saving
// change: the window is a wall-clock fact about the day, not an offset from
// midnight.
func (s Schedule) recurring(now time.Time) Result {
	loc := s.location()
	local := now.In(loc)

	// A daily schedule names no days and so always passes. A weekly schedule
	// that names none is rejected by Validate rather than silently applying
	// every day, so the same test serves both.
	if !s.appliesOnDay(local) {
		next := s.nextDayStart(local, loc)
		return Result{
			Active: false,
			Reason: fmt.Sprintf("schedule %q applies on %s, and today is %s",
				s.Name, strings.Join(dayStrings(s.Days), "/"), local.Weekday()),
			NextChange: next,
		}
	}

	inWindow, boundary, boundaryIsStart := s.inWindow(local, loc)

	switch {
	case inWindow:
		return Result{
			Active: true,
			Reason: fmt.Sprintf("schedule %q is active (%s-%s %s)",
				s.Name, s.From, s.To, s.LocationLabel()),
			NextChange: boundary,
		}
	case boundaryIsStart:
		return Result{
			Active: false,
			Reason: fmt.Sprintf("schedule %q is outside its window; it starts at %s",
				s.Name, boundary.In(loc).Format("15:04 MST")),
			NextChange: boundary,
		}
	default:
		return Result{
			Active: false,
			Reason: fmt.Sprintf("schedule %q is outside its window; it ended at %s",
				s.Name, boundary.In(loc).Format("15:04 MST")),
			NextChange: boundary,
		}
	}
}

// overnight reports whether the window crosses midnight.
func (s Schedule) overnight() bool { return s.To.Minutes() < s.From.Minutes() }

// appliesOnDay reports whether the schedule's days include the day the current
// window belongs to.
//
// # The window belongs to the day it opens
//
// A weekly overnight window on Fridays, 22:00 to 06:00, is still applying at
// 03:00 on Saturday. Testing the observed weekday would report it inactive, so a
// "friday night only" limit would be off every Saturday morning — which is
// exactly the hours somebody is most likely to be using the network.
//
// So in the early-morning part of an overnight window, the day that matters is
// yesterday's.
func (s Schedule) appliesOnDay(local time.Time) bool {
	if s.includesDay(dayOf(local.Weekday())) {
		return true
	}

	// Only an overnight window can be observed on a day it did not open on.
	if !s.overnight() {
		return false
	}

	// Before the window's end time, the relevant window is yesterday's. At or
	// after it, the day's window is long finished and there is nothing to
	// attribute to yesterday.
	if local.Hour()*60+local.Minute() >= s.To.Minutes() {
		return false
	}

	return s.includesDay(dayOf(local.AddDate(0, 0, -1).Weekday()))
}

// inWindow reports whether the local moment is inside the schedule's window,
// and where the next boundary falls.
//
// The three-way return is because "not in the window" has two cases that mean
// different things to a caller: the window has not started, or it has already
// finished. Only the second can be an overnight window, where the relevant
// boundary is the start of the next instance rather than the end of this one.
//
// # The overnight case needs two candidate windows, not one
//
// An overnight window repeats daily, so at any moment two instances can be
// relevant: the one that opened yesterday and closes today, and the one opening
// today and closing tomorrow. At 03:00 the first applies; at 23:00 the second
// does. Collapsing them into a single interval gets exactly one of those two
// moments right, which is the bug this two-candidate form exists to avoid.
func (s Schedule) inWindow(local time.Time, loc *time.Location) (in bool, boundary time.Time, isStart bool) {
	if !s.overnight() {
		// A plain interval on today's date.
		startToday := s.at(local, s.From, loc)
		endToday := s.at(local, s.To, loc)

		switch {
		case local.Before(startToday):
			return false, startToday, true
		case local.Before(endToday):
			return true, endToday, false
		default:
			// Today's window is over. The next boundary is tomorrow's start.
			return false, s.at(local.AddDate(0, 0, 1), s.From, loc), true
		}
	}

	// Overnight: the instance that opened yesterday, and the one opening today.
	prevOpen := s.at(local.AddDate(0, 0, -1), s.From, loc)
	prevClose := s.at(local, s.To, loc)
	todayOpen := s.at(local, s.From, loc)
	todayClose := s.at(local.AddDate(0, 0, 1), s.To, loc)

	switch {
	case local.Before(prevOpen):
		// Last night's instance has not opened yet.
		return false, prevOpen, true

	case local.Before(prevClose):
		// Last night's instance, closing this morning.
		return true, prevClose, false

	case local.Before(todayOpen):
		// Tonight's instance closed earlier today and has not reopened. This is
		// the gap the naive comparison gets wrong.
		return false, todayOpen, true

	default:
		// Tonight's instance, closing tomorrow morning.
		return true, todayClose, false
	}
}

// at returns the moment on the given local date at the given wall clock.
func (s Schedule) at(local time.Time, clock WallClock, loc *time.Location) time.Time {
	return time.Date(
		local.Year(), local.Month(), local.Day(),
		clock.Hour, clock.Minute, 0, 0, loc,
	)
}

// includesDay reports whether the schedule names a weekday. An empty day list
// means every day.
func (s Schedule) includesDay(d Day) bool {
	if len(s.Days) == 0 {
		return true
	}
	for _, named := range s.Days {
		if named == d {
			return true
		}
	}
	return false
}

// nextDayStart returns the next moment a named day recurs, at the From time.
//
// It looks forward at most a week, which is enough for any non-empty day set,
// and returns a time a week out when the set is empty — for a schedule that
// never applies, a week out is indistinguishable from never.
func (s Schedule) nextDayStart(local time.Time, loc *time.Location) time.Time {
	for i := 1; i <= 7; i++ {
		candidate := local.AddDate(0, 0, i)
		if !s.includesDay(dayOf(candidate.Weekday())) {
			continue
		}
		return s.at(candidate, s.From, loc)
	}
	return local.AddDate(0, 0, 7)
}

// LocationLabel renders the zone for output.
func (s Schedule) LocationLabel() string {
	if s.Location == "" {
		return "UTC"
	}
	return s.Location
}

// Equal reports whether two schedules are the same.
//
// It is used to decide whether a set changed, and comparing field by field
// would mean maintaining the comparison in step with the struct forever.
func (s Schedule) Equal(other Schedule) bool {
	if s.Name != other.Name || s.Kind != other.Kind || s.Location != other.Location {
		return false
	}
	if s.Priority != other.Priority {
		return false
	}
	if !sameTime(s.Start, other.Start) || !sameTime(s.End, other.End) {
		return false
	}
	if s.From != other.From || s.To != other.To {
		return false
	}
	return sameDays(s.Days, other.Days)
}

func sameTime(a, b time.Time) bool {
	return a.Equal(b) || (a.IsZero() && b.IsZero())
}

func sameDays(a, b []Day) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]Day(nil), a...)
	bs := append([]Day(nil), b...)
	sort.Slice(as, func(i, j int) bool { return as[i] < as[j] })
	sort.Slice(bs, func(i, j int) bool { return bs[i] < bs[j] })
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// dayStrings renders a day set in canonical order, Monday first.
func dayStrings(days []Day) []string {
	order := map[Day]int{}
	for i, d := range Days {
		order[d] = i
	}

	sorted := append([]Day(nil), days...)
	sort.Slice(sorted, func(i, j int) bool { return order[sorted[i]] < order[sorted[j]] })

	out := make([]string, 0, len(sorted))
	for _, d := range sorted {
		out = append(out, string(d))
	}
	return out
}

// roundDur renders a duration at a resolution a person can read.
func roundDur(d time.Duration) time.Duration {
	switch {
	case d >= time.Hour:
		return d.Round(time.Minute)
	case d >= time.Minute:
		return d.Round(time.Second)
	default:
		return d
	}
}
