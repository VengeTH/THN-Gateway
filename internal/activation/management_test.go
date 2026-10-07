package activation

import (
	"testing"
)

func TestManagementSafetyPassesCleanTopology(t *testing.T) {
	in := ManagementSafetyInput{
		TailscalePresent:    true,
		TailscaleInterface:  "tailscale0",
		ActiveSSHIP:         "192.168.1.50",
		ActiveSSHInterface:  "eth0",
		HasDefaultRoute:     true,
		PlannedDefaultRoute: true,
		TouchedInterfaces:   []string{"eth1", "eth2"},
	}

	rep := EvaluateManagementSafety(in)
	if !rep.Safe {
		t.Fatalf("expected clean topology to pass management safety, got reason: %s", rep.Reason)
	}
	if !rep.TailscalePreserved {
		t.Error("expected Tailscale to be preserved")
	}
	if !rep.SSHPathPreserved {
		t.Error("expected SSH path to be preserved")
	}
}

func TestManagementSafetyBlocksTouchingTailscale(t *testing.T) {
	in := ManagementSafetyInput{
		TailscalePresent:   true,
		TailscaleInterface: "tailscale0",
		TouchedInterfaces:  []string{"eth1", "tailscale0"},
	}

	rep := EvaluateManagementSafety(in)
	if rep.Safe {
		t.Fatal("expected touching tailscale0 to fail management safety")
	}
	if rep.TailscalePreserved {
		t.Error("expected TailscalePreserved to be false")
	}
}

func TestManagementSafetyBlocksSettingDownSSHInterface(t *testing.T) {
	in := ManagementSafetyInput{
		ActiveSSHIP:          "192.168.1.50",
		ActiveSSHInterface:   "eth0",
		HasDefaultRoute:      true,
		PlannedDefaultRoute:  true,
		InterfaceDownActions: []string{"eth0"},
	}

	rep := EvaluateManagementSafety(in)
	if rep.Safe {
		t.Fatal("expected setting down eth0 to fail management safety")
	}
	if rep.SSHPathPreserved {
		t.Error("expected SSHPathPreserved to be false")
	}
}

func TestManagementSafetyBlocksRemovingSSHAddress(t *testing.T) {
	in := ManagementSafetyInput{
		ActiveSSHIP:         "192.168.1.50",
		ActiveSSHInterface:  "eth0",
		HasDefaultRoute:     true,
		PlannedDefaultRoute: true,
		RemovedAddresses: map[string][]string{
			"eth0": {"192.168.1.50/24"},
		},
	}

	rep := EvaluateManagementSafety(in)
	if rep.Safe {
		t.Fatal("expected removing active SSH IP to fail management safety")
	}
}

func TestManagementSafetyBlocksEliminatingDefaultRoute(t *testing.T) {
	in := ManagementSafetyInput{
		HasDefaultRoute:     true,
		PlannedDefaultRoute: false,
	}

	rep := EvaluateManagementSafety(in)
	if rep.Safe {
		t.Fatal("expected eliminating default route to fail management safety")
	}
	if rep.DefaultRoutePreserved {
		t.Error("expected DefaultRoutePreserved to be false")
	}
}
