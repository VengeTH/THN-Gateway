package cli

import (
	"strings"
	"testing"

	"github.com/venth/thn-gateway/internal/activation"
	"github.com/venth/thn-gateway/internal/deployment"
	"github.com/venth/thn-gateway/internal/network"
)

// This file is the gate phase for phases 1 to 3.
//
// # What is being held in place
//
// The project is at phase 3: a skeleton, a configuration and safety engine, and
// a read-only network abstraction. Nothing has touched the Internet, nothing
// has touched the host, and `thn activate` refuses.
//
// This file exists so that those facts stay true by assertion rather than by
// memory. A control plane, an appliance layer and a fleet authority all exist
// in the tree; none of them may become a way to change something, and the
// simplest way to check that is to look for writes and for a destructive
// tier.

// firstCommands are the commands a new operator is meant to reach for.
//
// Named explicitly rather than checked structurally, because the list is a
// product decision and a structural check would pass on a list that no longer
// matches what somebody was told to type.
var firstCommands = []string{
	"status", "diagnostics", "network", "config", "plan",
}

func TestGateFirstCommandsAllExist(t *testing.T) {
	for _, name := range firstCommands {
		if _, ok := commands[name]; !ok {
			t.Errorf("`thn %s` is not a command; it is one of the first ones an "+
				"operator is meant to reach for", name)
		}
	}
}

// `thn network inspect` is the read-only view of the host. It must be pure, and
// it must be honest about whether it managed to read anything.
//
// # What this used to assert, and why it failed on a real gateway
//
// It asserted `code == ExitOK` is a FAILURE — "exited zero on a host it
// cannot read". That was written when the suite only ever ran on a Windows
// developer machine, where `platform_other.go` reports `supported = false` and
// inspect legitimately exits non-zero.
//
// The assertion therefore encoded the ACCIDENT of the authoring platform as a
// product requirement. On the first real Linux host the inspector works,
// exits zero, and the test failed for being right.
//
// Nothing about the behaviour it guarded was wrong. What was wrong is that it
// only described half the contract, and the half it described happened to be
// the half no gateway ever exercises.
//
// The contract is symmetric, and both halves are now asserted:
//
//	host readable    → exit 0, and a real Interfaces report
//	host unreadable  → exit non-zero, and the reason stated
//
// The readable half is NEW. It was never checked before, and it is the half
// that matters on the machine THN is deployed to.
func TestGateNetworkInspectExistsAndIsPure(t *testing.T) {
	cmd, ok := commands["network"]
	if !ok {
		t.Fatal("there is no `thn network` command")
	}
	if cmd.Tier != TierPure {
		t.Errorf("`thn network` is %s; reading the host cannot change it", cmd.Tier)
	}

	env, out, errOut := newTestEnv("inspect")
	code := runNetwork(env, []string{"inspect"})
	combined := out.String() + errOut.String()

	// Decide, independently, which half of the contract applies here. Using
	// the same inspector the command uses is safe precisely because that
	// inspector is read-only; hardcoding a platform would reintroduce the
	// very assumption this test just had removed.
	snap, err := network.NewInspector().Inspect(cmdContext())
	if err != nil {
		t.Fatalf("could not determine whether this host is inspectable: %v", err)
	}

	if snap.Supported {
		if code != ExitOK {
			t.Errorf("`thn network inspect` exited %d on a host it CAN read:\n%s", code, combined)
		}
		if !strings.Contains(combined, "Interfaces") {
			t.Errorf("inspect reported success without reading any interfaces:\n%s", combined)
		}
		if len(snap.Interfaces) == 0 {
			t.Log("note: this host reported itself supported but found no interfaces")
		}
		return
	}

	if code == ExitOK {
		t.Errorf("`thn network inspect` exited zero on a host it cannot read:\n%s", combined)
	}
	if !strings.Contains(combined, "cannot inspect") {
		t.Errorf("inspect neither read the host nor said why it could not:\n%s", combined)
	}
}

// The refusal is the deliverable. Its sentences are asserted because they are
// what an operator reads at three in the morning, and a reworded refusal is a
// changed interface.
func TestGateActivateRefusesWithTheExpectedSentences(t *testing.T) {
	env, _, errOut := newTestEnv()
	code := runActivate(env, []string{})

	if code == ExitOK {
		t.Fatal("`thn activate` succeeded; it must refuse")
	}

	out := errOut.String()
	for _, want := range []string{
		"activation refused",
		"not physically deployed",
		"No approved physical deployment detected",
		"Current network remains untouched",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal is missing %q:\n%s", want, out)
		}
	}
}

// The untouched sentence is a contract. It appears in both branches — not
// deployed, and deployed but unable to apply — because the operator needs it
// whichever situation they are in.
func TestGateActivateAlwaysSaysTheNetworkIsUntouched(t *testing.T) {
	if !strings.Contains(refusalText(t), "Current network remains untouched") {
		t.Error("the refusal did not say the network is untouched")
	}
	if !strings.Contains(refusalText(t, "--yes"), "Current network remains untouched") {
		t.Error("--yes changed the refusal; it must not")
	}

	// The two branches are genuinely different sentences. A box that is not
	// a gateway must not be told about apply paths, and a gateway must not
	// be told it is not deployed.
	if r := deploymentReason(deployment.Status{Deployed: true}); !strings.Contains(r, "no apply path") {
		t.Errorf("a deployed host is not told the limitation is the software: %q", r)
	}
	notDeployed := deployment.Status{Reason: "the uplink is not attached"}
	if r := deploymentReason(notDeployed); !strings.Contains(r, "No approved physical deployment") {
		t.Errorf("an undeployed host is not told it is undeployed: %q", r)
	}
}

func TestGateActivateDidNotBecomeApplyable(t *testing.T) {
	if activation.CanApply() {
		t.Fatal("activation.CanApply() became true; phases 1-3 do not apply anything")
	}

	implemented := activation.ImplementedStages()
	for _, s := range activation.UnsupportedStages() {
		for _, got := range implemented {
			if got == s {
				t.Errorf("stage %s became implemented", s)
			}
		}
	}

	// And the refusal must not be something a flag turns off. --yes is
	// accepted for forward compatibility and changes nothing.
	if !strings.Contains(refusalText(t, "--yes"), "Current network remains untouched") {
		t.Error("--yes changed the refusal; it must not")
	}
}

// Nothing in the phase 1-3 command set may write.
func TestGatePhaseCommandsWriteNothing(t *testing.T) {
	for _, f := range []string{"network.go", "activate.go"} {
		source, err := readSource(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		for _, forbidden := range []string{
			"os.WriteFile", "os.Create", "os.Remove", "os.Rename",
			"os.Chmod", "os.Mkdir", "os.Truncate", "os.Symlink",
		} {
			if strings.Contains(source, forbidden) {
				t.Errorf("%s uses %s; phases 1-3 do not write to anything", f, forbidden)
			}
		}
	}
}

// There is still exactly one destructive command, and it still refuses.
func TestGateOneDestructiveCommandRemains(t *testing.T) {
	var destructive []string
	for name, cmd := range commands {
		if cmd.Tier == TierDestructive {
			destructive = append(destructive, name)
		}
	}
	if len(destructive) != 1 || destructive[0] != "activate" {
		t.Errorf("destructive commands are %v, want exactly [activate]", destructive)
	}
}

// Everything in the tree must be pure, live-read, or the single destructive
// command. A control plane and an appliance layer exist in packages; neither
// may have produced a way to act.
//
// Live is allowed because reading the host is what phases 2 and 3 are for.
// It is separated from pure so that the distinction stays visible: a command
// that touches the host is not the same kind of thing as one that does not,
// and `status` and `diagnostics` are the two that are live for exactly that
// reason.
func TestGateNoCommandBecameMutating(t *testing.T) {
	var destructive int
	for name, cmd := range commands {
		switch cmd.Tier {
		case TierPure, TierLive:
			// Fine.
		case TierDestructive:
			destructive++
			if name != "activate" {
				t.Errorf("%s is destructive; the only destructive command must be activate", name)
			}
		default:
			t.Errorf("%s has tier %q, which is not one this build uses", name, cmd.Tier)
		}
	}

	if destructive != 1 {
		t.Errorf("there are %d destructive commands, want exactly 1", destructive)
	}
}

func refusalText(t *testing.T, args ...string) string {
	t.Helper()
	env, _, errOut := newTestEnv(args...)
	runActivate(env, args)
	return errOut.String()
}
