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
	isoNsName    = "test_iso_ns"
	isoHostVeth  = "veth_iso_host"
	isoPodVeth   = "veth_iso_pod"
	isoPodIP     = "10.30.1.2"
	isoHostIP    = "10.30.1.1"
	isoIperfPort = "5301"

	// Define distinct rates to verify isolation
	simLimitRateBits = 10 * 1000 * 1000 // 10 Mbps
	sysLimitRateBits = 50 * 1000 * 1000 // 50 Mbps (Different from Sim to distinguish)
)

type IperfResultIso struct {
	End struct {
		SumSent struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_sent"`
		SumReceived struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_received"`
	} `json:"end"`
}

func TestTrafficIsolation(t *testing.T) {
	setupCmd := exec.Command("./test/bpf/setup_topology.sh", isoNsName, isoHostVeth, isoPodVeth, isoPodIP+"/24", isoHostIP+"/24", isoIperfPort)
	if out, err := setupCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to setup topology: %v\nOutput: %s", err, string(out))
	}
	defer cleanupIso()

	t.Logf("Topology %s created.", isoNsName)

	mgr, err := bpf.NewBpfManager()
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer mgr.Close()

	linkObj, err := netlink.LinkByName(isoHostVeth)
	if err != nil {
		t.Fatalf("Failed to find host veth: %v", err)
	}
	hostIfIndex := linkObj.Attrs().Index

	nsHandle, err := netns.GetFromPath("/var/run/netns/" + isoNsName)
	if err != nil {
		t.Fatalf("Failed to get netns handle: %v", err)
	}
	defer nsHandle.Close()

	if err := mgr.AddPod(isoNsName, hostIfIndex, nsHandle); err != nil {
		t.Fatalf("AddPod failed: %v", err)
	}

	// [UPDATE] Configure Dual Rates
	// Sim: 10Mbps, Sys: 50Mbps
	if err := mgr.UpdateRule(hostIfIndex, uint64(simLimitRateBits), uint64(simLimitRateBits), uint64(sysLimitRateBits), uint64(sysLimitRateBits)); err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}
	t.Logf("Configured Rates: Sim=10Mbps, Sys=50Mbps")

	time.Sleep(1 * time.Second)

	// Phase A: Sys Traffic (Host IP NOT whitelisted)
	// Expectation: Should match Sys Limit (50Mbps)
	t.Run("Phase_A_Sys_Traffic_Limit", func(t *testing.T) {
		t.Log("Testing Sys Traffic (Whitelist Empty)...")
		// Verify whitelist is empty
		peers, _ := mgr.GetPeers()
		if len(peers) != 0 {
			t.Fatalf("Expected empty whitelist, got: %v", peers)
		}

		bps := runIperfIso(t, true) // Upload (Pod->Host)
		validateSpeedIso(t, bps, sysLimitRateBits, "Sys")
	})

	time.Sleep(2 * time.Second)

	// Phase B: Sim Traffic (Host IP Whitelisted)
	// Expectation: Should match Sim Limit (10Mbps)
	t.Run("Phase_B_Sim_Traffic_Limit", func(t *testing.T) {
		t.Logf("Adding HOST IP %s to Whitelist (Switching to Sim Mode)...", isoHostIP)
		if err := mgr.AddPeer(isoHostIP); err != nil {
			t.Fatalf("Failed to add peer: %v", err)
		}

		bps := runIperfIso(t, true)
		validateSpeedIso(t, bps, simLimitRateBits, "Sim")
	})

	time.Sleep(2 * time.Second)

	// Phase C: Sys Traffic Restored
	// Expectation: Should return to Sys Limit (50Mbps)
	t.Run("Phase_C_Sys_Traffic_Restored", func(t *testing.T) {
		t.Logf("Removing HOST IP %s from Whitelist (Switching back to Sys Mode)...", isoHostIP)
		if err := mgr.RemovePeer(isoHostIP); err != nil {
			t.Fatalf("Failed to remove peer: %v", err)
		}

		bps := runIperfIso(t, true)
		validateSpeedIso(t, bps, sysLimitRateBits, "Sys-Restored")
	})
}

func runIperfIso(t *testing.T, reverse bool) float64 {
	args := []string{
		"-c", isoPodIP,
		"-p", isoIperfPort,
		"-t", "5",
		"-J",
	}
	if reverse {
		args = append(args, "-R")
	}

	cmd := exec.Command("iperf3", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("iperf3 failed: %v, Output: %s", err, string(out))
	}

	var result IperfResultIso
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("Failed to parse iperf output: %v", err)
	}

	bpsSent := result.End.SumSent.BitsPerSecond
	bpsRecv := result.End.SumReceived.BitsPerSecond
	if bpsSent > bpsRecv {
		return bpsSent
	}
	return bpsRecv
}

func validateSpeedIso(t *testing.T, actualBps float64, targetBps float64, mode string) {
	mbps := actualBps / 1000000.0
	t.Logf("[%s] Actual Speed: %.2f Mbps, Target: %.2f Mbps", mode, mbps, targetBps/1000000.0)

	// Tolerance
	upperLimit := targetBps * 1.3
	lowerLimit := targetBps * 0.7

	if actualBps > upperLimit {
		t.Errorf("[%s] FAILED: Speed too high! Got: %.2f Mbps", mode, mbps)
	} else if actualBps < lowerLimit {
		t.Errorf("[%s] FAILED: Speed too low! Got: %.2f Mbps", mode, mbps)
	} else {
		t.Logf("[%s] PASS: Speed accurate.", mode)
	}
}

func cleanupIso() {
	exec.Command("./test/bpf/cleanup_topology.sh", isoNsName, isoHostVeth).Run()
	os.Remove(fmt.Sprintf("/tmp/iperf_server_%s.log", isoNsName))
}
