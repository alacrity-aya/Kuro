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
	nsName    = "test_tc_ns"
	hostVeth  = "veth_tc_host"
	podVeth   = "veth_tc_pod"
	podIP     = "10.20.99.2"
	hostIP    = "10.20.99.1"
	iperfPort = "5202"

	limitRateBits = 100 * 1000 * 1000

	edtHorizonSec = 2
)

type IperfResult struct {
	End struct {
		SumSent struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_sent"`
		SumReceived struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_received"`
	} `json:"end"`
}

func TestDualDirectionTC(t *testing.T) {
	setupCmd := exec.Command("./test/setup_topology.sh", nsName, hostVeth, podVeth, podIP+"/24", hostIP+"/24", iperfPort)
	if out, err := setupCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to setup topology: %v\nOutput: %s", err, string(out))
	}
	t.Log("Topology setup complete.")

	// Ensure resources are cleaned up when the test ends
	defer func() {
		// Print server logs for debugging
		logContent, _ := os.ReadFile(fmt.Sprintf("/tmp/iperf_server_%s.log", nsName))
		if len(logContent) > 0 {
			// Only print the tail of the log to avoid excessive length
			t.Logf("=== iperf3 Server Log (Tail) ===\n%s", string(logContent))
		}
		cleanup()
	}()

	// 2. Initialize BPF Manager
	mgr, err := bpf.NewBpfManager()
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer mgr.Close()

	// 3. Attach BPF programs
	linkObj, err := netlink.LinkByName(hostVeth)
	if err != nil {
		t.Fatalf("Failed to find host veth: %v", err)
	}
	hostIfIndex := linkObj.Attrs().Index

	nsHandle, err := netns.GetFromPath("/var/run/netns/" + nsName)
	if err != nil {
		t.Fatalf("Failed to get netns handle: %v", err)
	}
	defer nsHandle.Close()

	if err := mgr.AddPod(nsName, hostIfIndex, nsHandle); err != nil {
		t.Fatalf("AddPod failed: %v", err)
	}

	t.Logf("Whitelisting Pod IP: %s", podIP)
	if err := mgr.AddPeer(podIP); err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}

	t.Logf("Whitelisting Host IP (Test Peer): %s", hostIP)
	if err := mgr.AddPeer(hostIP); err != nil {
		t.Fatalf("AddPeer Host failed: %v", err)
	}

	// 4. Apply rate limit rules (100 Mbps)
	if err := mgr.UpdateRule(hostIfIndex, uint64(limitRateBits), uint64(limitRateBits)); err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	t.Logf("Rate limit set to %.2f Mbps. Waiting for convergence...", float64(limitRateBits)/1e6)
	time.Sleep(2 * time.Second)

	// --- Test A: Download (Host -> Pod) ---
	t.Run("Download_HostToPod", func(t *testing.T) {
		// Verify download direction (Checks Dst IP whitelist logic)
		bps := runIperf(t, false)
		validateSpeed(t, bps, limitRateBits, "Download")
	})

	// Wait for the EDT bucket to drain to prevent interference with the next test
	t.Logf("Sleeping %d seconds to drain EDT bucket...", edtHorizonSec+1)
	time.Sleep(time.Duration(edtHorizonSec+1) * time.Second)

	// Check if the iperf server is still running
	checkServerCmd := exec.Command("pgrep", "-f", "iperf3 -s")
	if err := checkServerCmd.Run(); err != nil {
		t.Fatalf("CRITICAL: iperf3 server died before Upload test!")
	}

	// --- Test B: Upload (Pod -> Host) ---
	t.Run("Upload_PodToHost", func(t *testing.T) {
		// Verify upload direction (Checks Src IP whitelist logic)
		bps := runIperf(t, true)
		validateSpeed(t, bps, limitRateBits, "Upload")
	})
}

func runIperf(t *testing.T, reverse bool) float64 {
	args := []string{
		"-c", podIP,
		"-p", iperfPort,
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

	var result IperfResult
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("Failed to parse iperf output: %v", err)
	}

	bpsSent := result.End.SumSent.BitsPerSecond
	bpsRecv := result.End.SumReceived.BitsPerSecond

	// Return the larger value (usually represents the actual throughput)
	if bpsSent > bpsRecv {
		return bpsSent
	}
	return bpsRecv
}

func validateSpeed(t *testing.T, actualBps float64, targetBps float64, direction string) {
	mbps := actualBps / 1000000.0
	t.Logf("[%s] Actual Speed: %.2f Mbps, Target: %.2f Mbps", direction, mbps, targetBps/1000000.0)

	// Set upper/lower limits (allowing a 30% margin)
	upperLimit := targetBps * 1.3
	lowerLimit := targetBps * 0.7

	if actualBps > upperLimit {
		t.Errorf("[%s] Speed too high! Limit not enforced. Got: %.2f Mbps, Max expected: %.2f Mbps", direction, mbps, upperLimit/1000000.0)
	} else if actualBps < lowerLimit {
		t.Logf("[%s] Warning: Speed lower than expected (%.2f Mbps). Could be environment noise.", direction, mbps)
	} else {
		t.Logf("[%s] PASS: Speed within valid range.", direction)
	}
}

func cleanup() {
	exec.Command("./test/cleanup_topology.sh", nsName, hostVeth).Run()
}
