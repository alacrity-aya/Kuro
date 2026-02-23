package test

import (
	"testing"
	"time"

	"kuro/internal/agent/bpf"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestTrafficIsolation(t *testing.T) {
	cfg := TopologyConfig{
		NsName:    "test_iso_ns",
		HostVeth:  "veth_iso_host",
		PodVeth:   "veth_iso_pod",
		PodIP:     "10.30.1.2",
		HostIP:    "10.30.1.1",
		IperfPort: "5301",
	}

	SetupTopology(t, cfg)
	mgr := InitBPFManager(t)

	// BPF Specific Setup
	nsHandle, _ := netns.GetFromName(cfg.NsName)
	defer nsHandle.Close()
	hostLink, _ := netlink.LinkByName(cfg.HostVeth)

	t.Log("[Test] Attaching BPF programs to Pod...")
	if err := mgr.AddPod("iso-pod", hostLink.Attrs().Index, nsHandle); err != nil {
		t.Fatalf("AddPod failed: %v", err)
	}

	simRate := 10.0 * Mb
	sysRate := 50.0 * Mb

	// [UPDATED] Set both rates
	t.Logf("[Test] Configuring Rates - Sim: %.0f Mbps, Sys: %.0f Mbps", simRate/Mb, sysRate/Mb)
	err := mgr.UpdateRule(hostLink.Attrs().Index, uint64(simRate), uint64(simRate), uint64(sysRate), uint64(sysRate))
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	// --- Phase 1: Default System Traffic ---
	t.Run("Phase1_SysDefault", func(t *testing.T) {
		t.Log(">>> Testing Phase 1: Default System Traffic (Expected High Speed)")
		// Reverse=true means Server(Pod) sends to Client(Host), testing Upload/Egress from Pod
		bps := RunIperf(t, "", cfg.PodIP, cfg.IperfPort, "4", true)
		ValidateTraffic(t, bps, sysRate, "Sys-Default", 0.3)
	})

	// --- Phase 2: Promote to Simulation Traffic ---
	t.Run("Phase2_SimPromoted", func(t *testing.T) {
		t.Log(">>> Testing Phase 2: Applying Policy (Sim Traffic - Expected Low Speed)")
		err := mgr.SetPolicy(cfg.PodIP, cfg.HostIP, &bpf.NetworkPolicyConfig{BandwidthLimit: 0})
		if err != nil {
			t.Fatalf("SetPolicy failed: %v", err)
		}

		// Wait for map update
		time.Sleep(500 * time.Millisecond)

		bps := RunIperf(t, "", cfg.PodIP, cfg.IperfPort, "4", true)
		ValidateTraffic(t, bps, simRate, "Sim-Active", 0.3)
	})

	// --- Phase 3: Revert to System Traffic ---
	t.Run("Phase3_SysReverted", func(t *testing.T) {
		t.Log(">>> Testing Phase 3: Removing Policy (Revert to Sys - Expected High Speed)")
		err := mgr.SetPolicy(cfg.PodIP, cfg.HostIP, nil)
		if err != nil {
			t.Fatalf("Failed to remove policy: %v", err)
		}

		time.Sleep(500 * time.Millisecond)

		bps := RunIperf(t, "", cfg.PodIP, cfg.IperfPort, "4", true)
		ValidateTraffic(t, bps, sysRate, "Sys-Restored", 0.3)
	})
}
