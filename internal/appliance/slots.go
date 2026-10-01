package appliance

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Slots: the A/B model an appliance needs in order to be updatable at all.
//
// # Why two slots
//
// A gateway is unattended. There is nobody to watch an upgrade, to notice it
// went wrong, or to interrupt it. That leaves exactly one workable shape: the
// upgrade is either complete or it did not happen, and the decision about
// which of those is true is made by something that can still run when the new
// image will not.
//
// The bootloader makes that decision, by counting boot attempts. This package
// does not touch the bootloader; it keeps the state the bootloader and the
// appliance agree on, and works out what the appliance should do about it.
//
// # The rule that matters
//
// A slot that has booted and then failed is never chosen again without being
// marked good first. Without that rule, a slot that fails immediately on every
// boot is retried forever, and an appliance with two slots is no better off
// than one with a corrupt filesystem.

const (
	// SlotA and SlotB are the conventional names.
	SlotA = "a"
	SlotB = "b"
)

// SlotState is where a slot is.
type SlotState string

const (
	// SlotEmpty is a slot with no image.
	SlotEmpty SlotState = "empty"

	// SlotStaged holds an image that has not been booted yet.
	SlotStaged SlotState = "staged"

	// SlotActive is the slot currently running.
	SlotActive SlotState = "active"

	// SlotInactive holds the image that should be run if the active one fails.
	SlotInactive SlotState = "inactive"

	// SlotFailed holds an image that booted and did not work.
	//
	// Terminal until someone stages a new image into it. An appliance that
	// retries a known-bad slot on every boot is not resilient, it is stuck in
	// a loop and burning its other slot's attempts.
	SlotFailed SlotState = "failed"
)

// Slot is one boot slot.
type Slot struct {
	// Name is "a" or "b".
	Name string `json:"name"`

	// State is where the slot is.
	State SlotState `json:"state"`

	// Image is the manifest digest of the image in the slot.
	Image string `json:"image,omitempty"`

	// Booted reports whether this slot has ever booted successfully.
	//
	// The distinction from State is what makes the boot count work: a slot can
	// be active and still never have completed a boot.
	Booted bool `json:"booted"`

	// Attempts is how many times the bootloader has tried this slot.
	Attempts int `json:"attempts"`

	// LastError is why the last attempt failed.
	LastError string `json:"last_error,omitempty"`

	// ActivatedAt is when it became active.
	ActivatedAt time.Time `json:"activated_at,omitempty"`
}

// MaxBootAttempts is how many times a slot is tried before it is failed.
//
// Three. One is a coincidence, two is a pattern, and a gateway that takes
// three attempts to boot has an update problem that an update is unlikely to
// fix.
const MaxBootAttempts = 3

// SlotTable is the pair of slots and the rules over them.
//
// Mutating methods are safe for concurrent use, because the thing that writes
// to it — a health reporter — and the thing that reads it — a boot decision —
// are rarely the same goroutine, and a table that races is a table that
// eventually reports a slot as failed for no reason.
type SlotTable struct {
	mu    sync.Mutex
	slots map[string]*Slot
}

// NewSlotTable returns a table with both slots empty.
func NewSlotTable() *SlotTable {
	return &SlotTable{slots: map[string]*Slot{
		SlotA: {Name: SlotA, State: SlotEmpty},
		SlotB: {Name: SlotB, State: SlotEmpty},
	}}
}

// Stage puts an image into the slot that is not running.
//
// Refuses to stage over the active slot. Overwriting the slot that is
// currently executing is how an upgrade bricks a device mid-write, and the
// guard is here rather than in the caller because every caller would need to
// remember it and one of them would not.
func (t *SlotTable) Stage(name, image string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.slots[name]
	if !ok {
		return fmt.Errorf("appliance: no slot named %q", name)
	}
	if s.State == SlotActive {
		return fmt.Errorf(
			"appliance: slot %s is active and cannot be staged over; the other slot must be used", name)
	}
	if image == "" {
		return fmt.Errorf("appliance: an image digest is required to stage a slot")
	}

	t.slots[name] = &Slot{
		Name:  name,
		State: SlotStaged,
		Image: image,
	}
	return nil
}

// Activate makes a slot the running one and demotes the other.
//
// The previously active slot becomes inactive rather than empty: it holds an
// image that worked, and that image is the fallback.
func (t *SlotTable) Activate(name string, at time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.slots[name]
	if !ok {
		return fmt.Errorf("appliance: no slot named %q", name)
	}
	if s.State == SlotEmpty {
		return fmt.Errorf("appliance: slot %s is empty", name)
	}
	if s.State == SlotFailed {
		return fmt.Errorf(
			"appliance: slot %s is failed and must not be activated; stage a new image into it", name)
	}

	other := t.other(name)
	if other != nil && other.State == SlotActive {
		other.State = SlotInactive
	}

	s.State = SlotActive
	s.ActivatedAt = at.UTC()
	s.Attempts = 0
	s.LastError = ""
	return nil
}

// other returns the slot that is not the named one.
//
// Declared to take no lock of its own because every caller already holds it;
// a method that locked again on a non-reentrant mutex would deadlock, which is
// a worse bug than the one a comment prevents.
func (t *SlotTable) other(name string) *Slot {
	for n, s := range t.slots {
		if n != name {
			return s
		}
	}
	return nil
}

// BootSucceeded records that the running slot came up.
//
// This is the call that makes a slot trustworthy. Until it is made, the slot
// is an image that has not yet proven it runs, and the boot count keeps
// counting against it.
func (t *SlotTable) BootSucceeded(name string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.slots[name]
	if !ok {
		return fmt.Errorf("appliance: no slot named %q", name)
	}
	s.Booted = true
	s.Attempts = 0
	s.LastError = ""
	return nil
}

// BootFailed records that the running slot did not come up, and fails the slot
// once it has been tried enough.
//
// Failing rather than retrying forever is the point of MaxBootAttempts. A
// slot that fails every boot and is retried forever consumes the other slot's
// attempts too, and turns one bad image into two unusable slots.
func (t *SlotTable) BootFailed(name, reason string, at time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.slots[name]
	if !ok {
		return fmt.Errorf("appliance: no slot named %q", name)
	}

	s.Attempts++
	s.LastError = reason

	if s.Attempts >= MaxBootAttempts {
		s.State = SlotFailed
		return fmt.Errorf(
			"appliance: slot %s failed %d times and has been marked failed; last error: %s",
			name, s.Attempts, reason)
	}
	return nil
}

// FallbackTo returns the slot to try if the given one will not run.
//
// A slot qualifies when it holds an image, is not the running slot, and has
// either booted successfully before or has never been tried. A slot that has
// already failed does not qualify however good its image looks.
//
// The preference order is deliberate: a slot that has booted before is a slot
// known to run on this hardware, and that is worth more than a slot that
// merely looks newer.
func (t *SlotTable) FallbackTo(from string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	candidates := make([]*Slot, 0, len(t.slots))
	for _, s := range t.slots {
		if s.Name == from || s.State == SlotEmpty || s.State == SlotFailed {
			continue
		}
		if s.State == SlotActive {
			continue
		}
		candidates = append(candidates, s)
	}
	if len(candidates) == 0 {
		return "", false
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Booted != candidates[j].Booted {
			return candidates[i].Booted // proven to boot, first
		}
		return candidates[i].Name < candidates[j].Name
	})

	return candidates[0].Name, true
}

// Get returns a copy of one slot.
func (t *SlotTable) Get(name string) (Slot, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.slots[name]
	if !ok {
		return Slot{}, false
	}
	return *s, true
}

// All returns a copy of every slot, ordered by name.
func (t *SlotTable) All() []Slot {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]Slot, 0, len(t.slots))
	for _, s := range t.slots {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Running returns the active slot.
func (t *SlotTable) Running() (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.slots {
		if s.State == SlotActive {
			return s.Name, true
		}
	}
	return "", false
}

// Usable reports whether a slot holds something the bootloader could run.
func (s Slot) Usable() bool {
	return s.State != SlotEmpty && s.State != SlotFailed
}

// String renders the table for a terminal.
func (t *SlotTable) String() string {
	var sb strings.Builder
	sb.WriteString("Slot  State      Booted  Attempts  Image\n")
	for _, s := range t.All() {
		image := s.Image
		if len(image) > 12 {
			image = image[:12]
		}
		if image == "" {
			image = "-"
		}
		fmt.Fprintf(&sb, "  %-4s %-10s %-6t  %-8d  %s\n",
			s.Name, s.State, s.Booted, s.Attempts, image)
	}
	return sb.String()
}
