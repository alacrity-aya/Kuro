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
	// Define test parameters
	isoNsName    = "test_iso_ns"
	isoHostVeth  = "veth_iso_host"
	isoPodVeth   = "veth_iso_pod"
	isoPodIP     = "10.30.1.2"
	isoHostIP    = "10.30.1.1"
	isoIperfPort = "5301"

	// Simulation rate limit: 10 Mbps
	simLimitRateBits = 10 * 1000 * 1000

	// Expected Sys rate (should be much larger than 10Mbps, e.g., > 100Mbps)
	sysThresholdBits = 100 * 1000 * 1000
)

// Reuse previous IperfResult structure
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
	// 1. Setup topology environment
	setupCmd := exec.Command("./test/setup_topology.sh", isoNsName, isoHostVeth, isoPodVeth, isoPodIP+"/24", isoHostIP+"/24", isoIperfPort)
	if out, err := setupCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to setup topology: %v\nOutput: %s", err, string(out))
	}
	defer cleanupIso()

	t.Logf("Topology %s created. Pod IP: %s", isoNsName, isoPodIP)

	// 2. Initialize BPF Manager
	mgr, err := bpf.NewBpfManager()
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer mgr.Close()

	// 3. Get interface index and load BPF program
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

	// 4. Configure rate limiting rules (set to 10Mbps)
	// Note: This rule is written to rate_map, but in tc.c, only Sim traffic reads this limit
	if err := mgr.UpdateRule(hostIfIndex, uint64(simLimitRateBits), uint64(simLimitRateBits)); err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}
	t.Logf("Configured Rate Limit to 10 Mbps (Sim Only)")

	// Wait for BPF to take effect
	time.Sleep(1 * time.Second)

	// ========================================================================
	// Phase A: Default State (Not in whitelist) -> Treated as Sys traffic -> Expected: No rate limit
	// ========================================================================
	t.Run("Phase_A_Sys_Traffic_Bypass", func(t *testing.T) {
		t.Log("Testing Sys Traffic (Not in whitelist)...")

		// Verify whitelist is empty (for rigor)
		peers, _ := mgr.GetPeers()
		if len(peers) != 0 {
			t.Fatalf("Expected empty whitelist, got: %v", peers)
		}

		// Run iperf (Pod -> Host uplink)
		bps := runIperfIso(t, true)

		// Verify: Speed should be significantly higher than 10Mbps
		mbps := bps / 1000000.0
		t.Logf("[Sys] Measured Speed: %.2f Mbps", mbps)

		if bps < float64(sysThresholdBits) {
			t.Errorf("[Sys] FAILED: Traffic was limited! Got %.2f Mbps, Expected > %.2f Mbps. Is the whitelist logic broken?", mbps, float64(sysThresholdBits)/1e6)
		} else {
			t.Logf("[Sys] PASS: Traffic bypassed limit successfully.")
		}
	})

	time.Sleep(2 * time.Second)

	// ========================================================================
	// Phase B: Added to Whitelist -> Treated as Sim traffic -> Expected: Throttled to 10Mbps
	// ========================================================================
	t.Run("Phase_B_Sim_Traffic_Throttled", func(t *testing.T) {
		t.Logf("Adding Pod IP %s to Whitelist (Sim Mode)...", isoPodIP)

		// Key action: Add IP to whitelist
		if err := mgr.AddPeer(isoPodIP); err != nil {
			t.Fatalf("Failed to add peer: %v", err)
		}

		// Verify if write was successful
		peers, _ := mgr.GetPeers()
		t.Logf("Current Whitelist: %v", peers)

		// Run iperf
		bps := runIperfIso(t, true)

		// Verify: Speed should be around 10Mbps
		validateSpeedIso(t, bps, simLimitRateBits, "Sim")
	})

	time.Sleep(2 * time.Second)

	// ========================================================================
	// Phase C: Removed from Whitelist -> Revert to Sys traffic -> Expected: No rate limit
	// ========================================================================
	t.Run("Phase_C_Sys_Traffic_Restored", func(t *testing.T) {
		t.Logf("Removing Pod IP %s from Whitelist...", isoPodIP)

		if err := mgr.RemovePeer(isoPodIP); err != nil {
			t.Fatalf("Failed to remove peer: %v", err)
		}

		// Run iperf
		bps := runIperfIso(t, true)

		mbps := bps / 1000000.0
		t.Logf("[Sys-Restored] Measured Speed: %.2f Mbps", mbps)

		if bps < float64(sysThresholdBits) {
			t.Errorf("[Sys-Restored] FAILED: Traffic still limited after removal! Speed: %.2f Mbps", mbps)
		} else {
			t.Logf("[Sys-Restored] PASS: Traffic restored to full speed.")
		}
	})
}

// Helper function: Run iperf3 client
func runIperfIso(t *testing.T, reverse bool) float64 {
	args := []string{
		"-c", isoPodIP,
		"-p", isoIperfPort,
		"-t", "10", // Run for 10 seconds
		"-J", // JSON output
	}
	if reverse {
		args = append(args, "-R") // Reverse mode (Server sends, Client receives) - Testing Download mostly
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

	// Take the larger value between Sent and Received (usually closest to link rate)
	bpsSent := result.End.SumSent.BitsPerSecond
	bpsRecv := result.End.SumReceived.BitsPerSecond
	if bpsSent > bpsRecv {
		return bpsSent
	}
	return bpsRecv
}

// Helper function: Verify if rate limiting is accurate
func validateSpeedIso(t *testing.T, actualBps float64, targetBps float64, mode string) {
	mbps := actualBps / 1000000.0
	t.Logf("[%s] Actual Speed: %.2f Mbps, Target: %.2f Mbps", mode, mbps, targetBps/1000000.0)

	// Allow 20% error margin
	upperLimit := targetBps * 1.2
	lowerLimit := targetBps * 0.8

	if actualBps > upperLimit {
		t.Errorf("[%s] FAILED: Speed too high! Limit broken. Got: %.2f Mbps", mode, mbps)
	} else if actualBps < lowerLimit {
		t.Errorf("[%s] FAILED: Speed too low! Over-throttled. Got: %.2f Mbps", mode, mbps)
	} else {
		t.Logf("[%s] PASS: Speed accurate.", mode)
	}
}

func cleanupIso() {
	exec.Command("./test/cleanup_topology.sh", isoNsName, isoHostVeth).Run()
	// Remove temporary logs
	os.Remove(fmt.Sprintf("/tmp/iperf_server_%s.log", isoNsName))
}
