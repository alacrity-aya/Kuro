//go:build bpf

package test

import (
	"encoding/json"
	"fmt"
	"kuro/internal/agent/bpf"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	dualNsName    = "test_dual_ns"
	dualHostVeth  = "veth_dual_host"
	dualPodVeth   = "veth_dual_pod"
	dualPodIP     = "10.50.1.2"
	dualHostIP    = "10.50.1.1"
	dualIperfPort = "5401"

	// Define clearly distinguishable rates
	// Sim: High Bandwidth (e.g., 200 Mbps)
	// Sys: Low Bandwidth (e.g., 20 Mbps)
	rateSimBits = 200 * 1000 * 1000
	rateSysBits = 20 * 1000 * 1000
)

func TestDualRateEnforcement(t *testing.T) {
	// 1. Setup
	setupCmd := exec.Command("./test/setup_topology.sh", dualNsName, dualHostVeth, dualPodVeth, dualPodIP+"/24", dualHostIP+"/24", dualIperfPort)
	if out, err := setupCmd.CombinedOutput(); err != nil {
		t.Fatalf("Setup failed: %s", string(out))
	}
	defer func() {
		exec.Command("./test/cleanup_topology.sh", dualNsName, dualHostVeth).Run()
		os.Remove(fmt.Sprintf("/tmp/iperf_server_%s.log", dualNsName))
	}()

	// 2. Init BPF
	mgr, err := bpf.NewBpfManager()
	if err != nil {
		t.Fatalf("NewBpfManager: %v", err)
	}
	defer mgr.Close()

	linkObj, _ := netlink.LinkByName(dualHostVeth)
	nsHandle, _ := netns.GetFromPath("/var/run/netns/" + dualNsName)
	defer nsHandle.Close()

	if err := mgr.AddPod(dualNsName, linkObj.Attrs().Index, nsHandle); err != nil {
		t.Fatalf("AddPod: %v", err)
	}

	// 3. Configure Rules
	// Sim = 200 Mbps, Sys = 20 Mbps
	t.Logf("Configuring: Sim=%f Mbps, Sys=%f Mbps", rateSimBits/1e6, rateSysBits/1e6)
	err = mgr.UpdateRule(linkObj.Attrs().Index, uint64(rateSimBits), uint64(rateSimBits), uint64(rateSysBits), uint64(rateSysBits))
	if err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	time.Sleep(1 * time.Second)

	// ==========================================
	// Scenario 1: Sys Traffic (Default)
	// ==========================================
	t.Run("Sys_Traffic_Check", func(t *testing.T) {
		// Verify Whitelist Empty
		p, _ := mgr.GetPeers()
		if len(p) != 0 {
			t.Fatalf("Whitelist not empty")
		}

		// Run Download (Host->Pod)
		bps := runDualIperf(t, false)
		validateDualSpeed(t, bps, rateSysBits, "Sys-Down")

		// Run Upload (Pod->Host)
		bps = runDualIperf(t, true)
		validateDualSpeed(t, bps, rateSysBits, "Sys-Up")
	})

	time.Sleep(2 * time.Second)

	// ==========================================
	// Scenario 2: Sim Traffic (Whitelisted)
	// ==========================================
	t.Run("Sim_Traffic_Check", func(t *testing.T) {
		t.Logf("Whitelisting IPs...")
		mgr.AddPeer(dualPodIP)
		mgr.AddPeer(dualHostIP)

		// Run Download
		bps := runDualIperf(t, false)
		validateDualSpeed(t, bps, rateSimBits, "Sim-Down")

		// Run Upload
		bps = runDualIperf(t, true)
		validateDualSpeed(t, bps, rateSimBits, "Sim-Up")
	})
}

func runDualIperf(t *testing.T, reverse bool) float64 {
	args := []string{"-c", dualPodIP, "-p", dualIperfPort, "-t", "4", "-J"}
	if reverse {
		args = append(args, "-R")
	}
	cmd := exec.Command("iperf3", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("iperf3 error: %v, out: %s", err, string(out))
	}
	var res IperfResult
	json.Unmarshal(out, &res)
	if res.End.SumSent.BitsPerSecond > res.End.SumReceived.BitsPerSecond {
		return res.End.SumSent.BitsPerSecond
	}
	return res.End.SumReceived.BitsPerSecond
}

func validateDualSpeed(t *testing.T, actual float64, target uint64, tag string) {
	mbps := actual / 1e6
	tMb := float64(target) / 1e6
	t.Logf("[%s] Got %.2f Mbps (Target %.2f)", tag, mbps, tMb)

	if actual > float64(target)*1.35 {
		t.Errorf("[%s] FAILED: Speed too high", tag)
	} else if actual < float64(target)*0.65 {
		t.Errorf("[%s] FAILED: Speed too low", tag)
	}
}
