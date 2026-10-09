package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeTcReader answers tc queries from fixed text, so a baseline can be built
// from output a real kernel produced rather than from hand-written fields.
type fakeTcReader struct {
	qdisc  string
	class  string
	filter string
	err    error
}

func (f fakeTcReader) RunTCOutput(ctx context.Context, args ...string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	switch {
	case strings.Contains(strings.Join(args, " "), "qdisc"):
		return f.qdisc, nil
	case strings.Contains(strings.Join(args, " "), "class"):
		return f.class, nil
	default:
		return f.filter, nil
	}
}

// vethNoqueueOutput is what `tc qdisc show dev <veth>` prints.
//
// Every veth pair — which is every interface the disposable lab and any
// virtualised gateway is built from — carries this. It is the kernel saying
// the device has no queueing, not a queue somebody configured.
const vethNoqueueOutput = "qdisc noqueue 0: root refcnt 2\n"

// TestAVethIsAdoptable is the regression test for the refusal that stopped
// every QoS scenario on the disposable lab.
//
// The capture was always faithful: it recorded `noqueue` exactly as tc printed
// it, and correctly preserved it as a restorable baseline. The bug was in what
// Foreign() called foreign. It enumerated one kernel default, pfifo_fast, and
// treated everything else as an operator's configuration — so `noqueue`, the
// absence of a queue, was refused as a hand-tuned hierarchy nobody had built.
//
// The safety property being tested is unchanged in spirit: a real discipline
// still has to be refused (see TestRealDisciplinesAreStillRefused). What
// changed is that a kernel-installed default is correctly recognised as
// something there is nothing to destroy.
func TestAVethIsAdoptable(t *testing.T) {
	b := CaptureTcBaseline(context.Background(), fakeTcReader{qdisc: vethNoqueueOutput}, "thnwan0")

	if !b.Captured {
		t.Fatalf("a readable veth must report Captured, got %+v", b)
	}
	if b.Foreign() {
		t.Errorf("noqueue reported as foreign configuration:\n  root: %s", b.Root)
	}
	if err := AdoptableRootQdisc(b); err != nil {
		t.Errorf("a veth must be adoptable, got: %v", err)
	}
}

// TestAKernelDefaultBaselineStillRollsBack guards the other half of the change.
//
// Exempting the kernel defaults from the refusal must not exempt them from
// rollback. Having replaced noqueue with CAKE, THN still has to be able to put
// noqueue back — that is the whole reason the baseline captured it.
func TestAKernelDefaultBaselineStillRollsBack(t *testing.T) {
	b := CaptureTcBaseline(context.Background(), fakeTcReader{qdisc: vethNoqueueOutput}, "thnwan0")

	replace, ok := b.RestoreOp().(OpQDiscReplace)
	if !ok {
		t.Fatalf("rollback of a captured noqueue should replace the root, got %T", b.RestoreOp())
	}
	if !strings.Contains(replace.Spec, "noqueue") {
		t.Errorf("rollback spec %q does not restore the observed discipline", replace.Spec)
	}
}

// TestKernelDefaultQdiscsAreNotForeign pins the set rather than one name.
//
// pfifo_fast is the default on a physical NIC, noqueue is the default on a
// virtual one, and pfifo is the plain FIFO the kernel falls back to. They are
// the same fact about three devices, and treating only one of them as a
// default is what made a veth look configured.
func TestKernelDefaultQdiscsAreNotForeign(t *testing.T) {
	for _, kind := range []string{"noqueue", "pfifo_fast", "pfifo"} {
		b := TcBaseline{
			Device:   "eth0",
			Captured: true,
			Root:     "qdisc replace dev eth0 root " + kind,
		}
		if b.Foreign() {
			t.Errorf("%q reported as foreign configuration; the kernel installs it for itself", kind)
		}
		if err := AdoptableRootQdisc(b); err != nil {
			t.Errorf("AdoptableRootQdisc(%s) = %v, want adoptable", kind, err)
		}
	}
}

// TestRealDisciplinesAreStillRefused is the half of the rule the fix must not
// have relaxed. A discipline that really is somebody's configuration is
// refused, and the refusal names the kind and the interface so an operator can
// act on it.
func TestRealDisciplinesAreStillRefused(t *testing.T) {
	for _, kind := range []string{"cake", "htb", "fq_codel", "codel", "mq"} {
		b := TcBaseline{
			Device:   "eth0",
			Captured: true,
			Root:     "qdisc replace dev eth0 root " + kind + " bandwidth 100Mbit",
		}
		if !b.Foreign() {
			t.Errorf("%q was treated as a kernel default; THN must not adopt a real discipline", kind)
		}

		err := AdoptableRootQdisc(b)
		if err == nil {
			t.Errorf("AdoptableRootQdisc(%s) = nil, want refusal", kind)
			continue
		}
		// The message has to identify what was found and where, or an operator
		// is left deciding what to remove without knowing which interface.
		for _, want := range []string{kind, "eth0"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal for %s does not name %q: %v", kind, want, err)
			}
		}
	}
}

// TestAnUnreadBaselineIsNeverAdoptable keeps "there was no qdisc here" and "THN
// did not look" distinct.
//
// Both produce an empty Root, and collapsing them would let THN destroy a
// hierarchy it never observed. A capture that failed refuses.
func TestAnUnreadBaselineIsNeverAdoptable(t *testing.T) {
	b := CaptureTcBaseline(context.Background(),
		fakeTcReader{err: errors.New("tc qdisc show failed: exit status 1")}, "eth0")

	if b.Captured {
		t.Fatal("a failed read must not report Captured")
	}
	if b.Foreign() {
		t.Error("an uncaptured baseline is not 'foreign'; it is unknown, which refuses separately")
	}
	if err := AdoptableRootQdisc(b); err == nil {
		t.Error("AdoptableRootQdisc on an uncaptured baseline = nil, want refusal")
	} else if !strings.Contains(err.Error(), "eth0") {
		t.Errorf("refusal does not name the interface: %v", err)
	}

	// And it must not fabricate a rollback either.
	if op := b.RestoreOp(); op != nil {
		t.Errorf("RestoreOp on an uncaptured baseline = %T, want nil so rollback refuses rather than guessing", op)
	}
}

// TestAMissingDeviceIsAnEmptyBaselineNotAFailure covers the third state.
//
// tc reports a device that is not there as an error. That is a fact about the
// interface — it carries no qdisc — rather than a failure to inspect one, so
// it is captured and empty, and rollback removes what THN installed.
func TestAMissingDeviceIsAnEmptyBaselineNotAFailure(t *testing.T) {
	b := CaptureTcBaseline(context.Background(),
		fakeTcReader{err: errors.New(`Cannot find device "eth0"`)}, "eth0")

	if !b.Captured {
		t.Fatalf("an absent device is a fact, not a failed read: %+v", b)
	}
	if err := AdoptableRootQdisc(b); err != nil {
		t.Errorf("an absent device carries nothing to protect: %v", err)
	}
	if _, ok := b.RestoreOp().(OpQDiscDelete); !ok {
		t.Errorf("rollback of an empty baseline should delete the root, got %T", b.RestoreOp())
	}
}
