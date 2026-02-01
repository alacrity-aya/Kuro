//go:build bpf

package test

import (
	"encoding/json"
	"fmt"
	"kuro/internal/agent/bpf"
	"os"
	"os/exec"
	"testing"
)

// Common constants
const (
	Mb = 1000 * 1000
	Gb = 1000 * 1000 * 1000
)

// IperfResult matches the JSON output of iperf3 -J
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

// TopologyConfig holds configuration for the shell script setup
type TopologyConfig struct {
	NsName    string
	HostVeth  string
	PodVeth   string
	PodIP     string
	HostIP    string
	IperfPort string
}

// SetupTopology executes the shell script and registers cleanup
func SetupTopology(t *testing.T, cfg TopologyConfig) {
	t.Logf("[Setup] Initializing topology for Namespace: %s", cfg.NsName)
	cmd := exec.Command("./test/bpf/setup_topology.sh",
		cfg.NsName, cfg.HostVeth, cfg.PodVeth,
		cfg.PodIP+"/24", cfg.HostIP+"/24", cfg.IperfPort)

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("[Setup] Failed to execute setup script: %v\nOutput: %s", err, string(out))
	}
	t.Log("[Setup] Topology created successfully.")

	// Register cleanup automatically
	t.Cleanup(func() {
		if os.Getenv("KEEP_NS") != "" {
			t.Logf("[Cleanup] KEEP_NS set, skipping cleanup for %s", cfg.NsName)
			return
		}
		t.Logf("[Cleanup] Removing topology for %s...", cfg.NsName)
		// Try to run the cleanup script first for graceful shutdown
		cleanupCmd := exec.Command("./test/bpf/cleanup_topology.sh", cfg.NsName, cfg.HostVeth)
		if out, err := cleanupCmd.CombinedOutput(); err != nil {
			t.Logf("[Cleanup] Warning: Cleanup script error: %s", string(out))
			// Fallback force delete
			exec.Command("ip", "netns", "del", cfg.NsName).Run()
			exec.Command("ip", "link", "del", cfg.HostVeth).Run()
		}
	})
}

// InitBPFManager creates a manager and ensures it's closed
func InitBPFManager(t *testing.T) *bpf.BpfManager {
	t.Log("[BPF] Initializing BPF Manager...")
	mgr, err := bpf.NewBpfManager()
	if err != nil {
		t.Fatalf("[BPF] Failed to create manager: %v", err)
	}
	t.Cleanup(func() {
		t.Log("[BPF] Closing Manager...")
		mgr.Close()
	})
	return mgr
}

// RunIperf executes iperf3 client.
// If clientNs is empty, it runs on Host. If set, it runs inside `ip netns exec`.
func RunIperf(t *testing.T, clientNs string, targetIP string, port string, durationSec string, reverse bool) float64 {
	var args []string

	// Construct the command prefix if inside a namespace
	if clientNs != "" {
		args = append(args, "ip", "netns", "exec", clientNs)
	}

	args = append(args, "iperf3", "-c", targetIP, "-p", port, "-t", durationSec, "-J")
	if reverse {
		args = append(args, "-R")
	}

	cmdStr := fmt.Sprintf("%v", args)
	t.Logf("[Test] Running Iperf: %s", cmdStr)

	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("[Test] Iperf failed: %v\nOutput: %s", err, string(out))
	}

	var res IperfResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("[Test] Failed to parse JSON: %v. Raw Output: %s", err, string(out))
	}

	// For TCP, we usually care about the Receiver's throughput, but take the max to be safe/fair
	bpsSent := res.End.SumSent.BitsPerSecond
	bpsRecv := res.End.SumReceived.BitsPerSecond

	actual := bpsRecv
	if bpsSent > bpsRecv {
		actual = bpsSent
	}

	t.Logf("[Test] Iperf Result - Sent: %.2f Mbps, Recv: %.2f Mbps", bpsSent/Mb, bpsRecv/Mb)
	return actual
}

// ValidateTraffic checks if the speed is within a tolerance range
func ValidateTraffic(t *testing.T, actualBps float64, expectedBps float64, testName string, tolerancePercent float64) {
	actualMbps := actualBps / Mb
	expectedMbps := expectedBps / Mb

	lowerBound := expectedBps * (1 - tolerancePercent)
	upperBound := expectedBps * (1 + tolerancePercent)

	t.Logf("[%s] Validation: %.2f Mbps (Target: %.2f Mbps, Range: %.2f - %.2f)",
		testName, actualMbps, expectedMbps, lowerBound/Mb, upperBound/Mb)

	if actualBps < lowerBound || actualBps > upperBound {
		t.Errorf("[%s] FAILED: Speed %.2f Mbps is out of tolerance (%.0f%%) for target %.2f Mbps",
			testName, actualMbps, tolerancePercent*100, expectedMbps)
	} else {
		t.Logf("[%s] PASSED", testName)
	}
}

// RunShellHelper is a wrapper for raw exec commands
func RunShellHelper(t *testing.T, command string, args ...string) {
	t.Logf("[Shell] Executing: %s %v", command, args)
	if err := exec.Command(command, args...).Run(); err != nil {
		t.Fatalf("[Shell] Command failed: %s %v, error: %v", command, args, err)
	}
}
