//go:build bpf

package test

import (
	"kuro/internal/agent/bpf"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestDualDirectionTC(t *testing.T) {
	cfg := TopologyConfig{
		NsName:    "test_tc_ns",
		HostVeth:  "veth_tc_host",
		PodVeth:   "veth_tc_pod",
		PodIP:     "10.20.99.2",
		HostIP:    "10.20.99.1",
		IperfPort: "5202",
	}

	limitRate := 100.0 * Mb // 100 Mbps
	sysRate := 1.0 * Gb     // 1 Gbps

	SetupTopology(t, cfg)
	mgr := InitBPFManager(t)

	nsHandle, err := netns.GetFromName(cfg.NsName)
	if err != nil {
		t.Fatalf("Failed to get ns handle: %v", err)
	}
	defer nsHandle.Close()

	hostLink, _ := netlink.LinkByName(cfg.HostVeth)
	t.Log("[Test] Adding Pod to BPF Manager...")
	if err := mgr.AddPod("test-pod", hostLink.Attrs().Index, nsHandle); err != nil {
		t.Fatalf("AddPod failed: %v", err)
	}

	t.Logf("[Test] Updating Rules: Limit=%.0f Mbps", limitRate/Mb)
	err = mgr.UpdateRule(hostLink.Attrs().Index, uint64(limitRate), uint64(limitRate), uint64(sysRate), uint64(sysRate))
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	t.Log("[Test] Applying bidirectional Sim Policy...")
	if err := mgr.SetPolicy(cfg.PodIP, cfg.HostIP, &bpf.TcLinkPolicy{BandwidthLimit: 0}); err != nil {
		t.Fatalf("SetPolicy Upload failed: %v", err)
	}
	if err := mgr.SetPolicy(cfg.HostIP, cfg.PodIP, &bpf.TcLinkPolicy{BandwidthLimit: 0}); err != nil {
		t.Fatalf("SetPolicy Download failed: %v", err)
	}

	// Wait for EDT horizon + safety buffer
	t.Log("Waiting for TCP congestion control stabilization...")
	time.Sleep(3 * time.Second)

	// --- Test A: Download (Host -> Pod) ---
	t.Run("Download_HostToPod", func(t *testing.T) {
		// Client (Host) -> Server (Pod). Normal iperf (reverse=false)
		bps := RunIperf(t, "", cfg.PodIP, cfg.IperfPort, "5", false)
		ValidateTraffic(t, bps, limitRate, "Download", 0.3)
	})

	time.Sleep(2 * time.Second)

	// --- Test B: Upload (Pod -> Host) ---
	t.Run("Upload_PodToHost", func(t *testing.T) {
		// Client (Host) -> Server (Pod). Reverse mode (Server sends data)
		bps := RunIperf(t, "", cfg.PodIP, cfg.IperfPort, "5", true)
		ValidateTraffic(t, bps, limitRate, "Upload", 0.3)
	})
}
