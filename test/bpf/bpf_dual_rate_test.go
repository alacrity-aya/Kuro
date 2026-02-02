//go:build bpf

package test

import (
	"kuro/internal/agent/bpf"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestDualRateEnforcement(t *testing.T) {
	cfg := TopologyConfig{
		NsName:    "test_dual_ns",
		HostVeth:  "veth_dual_host",
		PodVeth:   "veth_dual_pod",
		PodIP:     "10.50.1.2",
		HostIP:    "10.50.1.1",
		IperfPort: "5401",
	}

	rateSim := 200.0 * Mb
	rateSys := 20.0 * Mb

	SetupTopology(t, cfg)
	mgr := InitBPFManager(t)

	nsHandle, _ := netns.GetFromName(cfg.NsName)
	defer nsHandle.Close()
	hostLink, _ := netlink.LinkByName(cfg.HostVeth)

	if err := mgr.AddPod("dual-pod", hostLink.Attrs().Index, nsHandle); err != nil {
		t.Fatalf("AddPod failed: %v", err)
	}

	t.Logf("[Test] Setting Rates - Sim: %.0f Mbps, Sys: %.0f Mbps", rateSim/Mb, rateSys/Mb)
	err := mgr.UpdateRule(hostLink.Attrs().Index, uint64(rateSim), uint64(rateSim), uint64(rateSys), uint64(rateSys))
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	time.Sleep(1 * time.Second)

	// Scenario 1: Sys Traffic (Default - No Policy)
	t.Run("Sys_Traffic_Check", func(t *testing.T) {
		t.Log(">>> Scenario 1: System Traffic Enforcement")

		// Downstream
		bpsDown := RunIperf(t, "", cfg.PodIP, cfg.IperfPort, "4", false)
		ValidateTraffic(t, bpsDown, rateSys, "Sys-Down", 0.35)

		time.Sleep(1 * time.Second)

		// Upstream
		bpsUp := RunIperf(t, "", cfg.PodIP, cfg.IperfPort, "4", true)
		ValidateTraffic(t, bpsUp, rateSys, "Sys-Up", 0.35)
	})

	time.Sleep(2 * time.Second)

	// Scenario 2: Sim Traffic (With Policy)
	t.Run("Sim_Traffic_Check", func(t *testing.T) {
		t.Log(">>> Scenario 2: Simulation Traffic Enforcement")

		policy := &bpf.NetworkPolicyConfig{BandwidthLimit: 0}
		if err := mgr.SetPolicy(cfg.PodIP, cfg.HostIP, policy); err != nil {
			t.Fatalf("SetPolicy Upload failed: %v", err)
		}
		if err := mgr.SetPolicy(cfg.HostIP, cfg.PodIP, policy); err != nil {
			t.Fatalf("SetPolicy Download failed: %v", err)
		}

		time.Sleep(2 * time.Second)

		// Downstream
		bpsDown := RunIperf(t, "", cfg.PodIP, cfg.IperfPort, "4", false)
		ValidateTraffic(t, bpsDown, rateSim, "Sim-Down", 0.30)

		time.Sleep(1 * time.Second)

		// Upstream
		bpsUp := RunIperf(t, "", cfg.PodIP, cfg.IperfPort, "4", true)
		ValidateTraffic(t, bpsUp, rateSim, "Sim-Up", 0.30)
	})
}
