//go:build bpf

package test

import (
	"encoding/json"
	"fmt"
	"kuro/internal/agent/bpf"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// NetEmTestConfig defines the topology for simulation tests
var NetEmTestConfig = TopologyConfig{
	NsName:    "test_netem_ns",
	HostVeth:  "veth_netem_host",
	PodVeth:   "veth_netem_pod",
	PodIP:     "10.60.1.2",
	HostIP:    "10.60.1.1",
	IperfPort: "8080", // Standard port
}

const SystemPort = "9100"

func TestNetworkEmulation(t *testing.T) {
	SetupTopology(t, NetEmTestConfig)
	mgr := InitBPFManager(t)

	nsHandle, _ := netns.GetFromName(NetEmTestConfig.NsName)
	defer nsHandle.Close()
	hostLink, _ := netlink.LinkByName(NetEmTestConfig.HostVeth)

	if err := mgr.AddPod("netem-pod", hostLink.Attrs().Index, nsHandle); err != nil {
		t.Fatalf("AddPod failed: %v", err)
	}

	sysRate := 1.0 * Gb
	simRate := 100.0 * Mb
	err := mgr.UpdateRule(hostLink.Attrs().Index, uint64(simRate), uint64(simRate), uint64(sysRate), uint64(sysRate))
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	time.Sleep(1 * time.Second)

	// =========================================================================
	// Test 1: Latency Simulation (Using Ping)
	// =========================================================================
	t.Run("Sim_Latency_Injection", func(t *testing.T) {
		targetLatencyMs := 50
		targetLatencyNs := uint64(targetLatencyMs * 1000 * 1000)

		t.Logf(">>> Applying Latency Policy: %d ms", targetLatencyMs)
		policy := &bpf.NetworkPolicyConfig{
			BandwidthLimit: 0,
			BaseLatencyNs:  targetLatencyNs,
		}

		if err := mgr.SetPolicy(NetEmTestConfig.PodIP, NetEmTestConfig.HostIP, policy); err != nil {
			t.Fatalf("SetPolicy failed: %v", err)
		}

		// Use Ping for latency as it measures RTT effectively
		stats := RunPing(t, NetEmTestConfig.NsName, NetEmTestConfig.HostIP, 10)

		tolerance := 0.15
		minAcceptable := float64(targetLatencyMs) * (1.0 - tolerance)
		maxAcceptable := float64(targetLatencyMs) * (1.0 + tolerance)

		if stats.Avg < minAcceptable || stats.Avg > maxAcceptable {
			t.Errorf("Latency Test Failed! Target: %dms, Got avg: %.2fms (Acceptable: %.1f-%.1f)",
				targetLatencyMs, stats.Avg, minAcceptable, maxAcceptable)
		} else {
			t.Logf("[PASS] Latency Verified. Avg: %.2fms", stats.Avg)
		}
	})

	// =========================================================================
	// Test 2: Packet Loss Simulation (Using Iperf3 UDP)
	// =========================================================================
	t.Run("Sim_Packet_Loss", func(t *testing.T) {
		lossPpm := uint32(200000) // 20% Packet Loss
		expectedLossPercent := 20.0

		t.Logf(">>> Applying Loss Policy: %d ppm (%.0f%%)", lossPpm, expectedLossPercent)
		policy := &bpf.NetworkPolicyConfig{
			BandwidthLimit:    0,
			CorruptionRatePpm: lossPpm,
		}

		if err := mgr.SetPolicy(NetEmTestConfig.PodIP, NetEmTestConfig.HostIP, policy); err != nil {
			t.Fatalf("SetPolicy failed: %v", err)
		}

		stats := RunPing(t, NetEmTestConfig.NsName, NetEmTestConfig.HostIP, 200)
		t.Logf(">>> Ping Loss Result: %.1f%%", stats.LossPct)

		if math.Abs(stats.LossPct-expectedLossPercent) > 7.0 {
			t.Errorf("Loss Test Failed! Expected ~%.1f%%, Got %.1f%%", expectedLossPercent, stats.LossPct)
		} else {
			t.Logf("[PASS] Loss Verified. Got %.1f%% loss", stats.LossPct)
		}
	})

	// =========================================================================
	// Test 3: System Port Bypass (Using Iperf3 UDP Bandwidth)
	// =========================================================================
	t.Run("Sys_Port_Bypass", func(t *testing.T) {
		// 1. Strangle the Sim Traffic to 1Mbps
		strangleRate := 1.0 * Mb
		t.Log(">>> Updating Sim Rate to 1Mbps (Stranglehold)")
		err := mgr.UpdateRule(hostLink.Attrs().Index, uint64(strangleRate), uint64(strangleRate), uint64(sysRate), uint64(sysRate))
		if err != nil {
			t.Fatalf("UpdateRule failed: %v", err)
		}

		// 2. Start Server on Protected Port
		stopServer := startIperfServer(t, SystemPort)
		defer stopServer()

		// 3. Run UDP Client targeting System Port. Request 50Mbps.
		// If bypassed (System Lane), it should get ~50Mbps (since SysRate is 1Gbps).
		// If NOT bypassed (Sim Lane), it will be capped at 1Mbps -> 98% loss.
		targetBw := 50.0 // Mbps
		stats := RunIperfUDP(t, NetEmTestConfig.NsName, NetEmTestConfig.HostIP, SystemPort, fmt.Sprintf("%.0fM", targetBw))

		// Check Throughput (Mbps)
		// UDP Throughput = (Total Bytes / Time) or (BitsPerSecond from JSON)
		// If we got > 20Mbps, we definitely bypassed the 1Mbps limit.
		if stats.Mbps < 20.0 {
			t.Errorf("Bypass Failed! Traffic was throttled to %.2f Mbps (Expected > 20Mbps)", stats.Mbps)
		} else {
			t.Logf("[PASS] Port %s Bypassed Sim limits. Speed: %.2f Mbps", SystemPort, stats.Mbps)
		}
	})
}

// ============================================================================
// Enhanced Helpers
// ============================================================================

type UDPStats struct {
	Mbps        float64
	LostPercent float64
	JitterMs    float64
	Packets     int
	Lost        int
}

// RunIperfUDP runs iperf3 in UDP mode to measure Loss and Jitter
func RunIperfUDP(t *testing.T, clientNs string, targetIP string, port string, bandwidth string) UDPStats {
	var args []string
	if clientNs != "" {
		args = append(args, "ip", "netns", "exec", clientNs)
	}
	// -u: UDP, -b: Bandwidth, -l: Length (small packet to simulate generic traffic), -J: JSON
	args = append(args, "iperf3", "-c", targetIP, "-p", port, "-u", "-b", bandwidth, "-t", "2", "-J")

	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Iperf UDP failed: %v\nOutput: %s", err, string(out))
	}

	var res struct {
		End struct {
			Sum struct {
				BitsPerSecond float64 `json:"bits_per_second"`
				JitterMs      float64 `json:"jitter_ms"`
				LostPercent   float64 `json:"lost_percent"`
				Packets       int     `json:"packets"`
				LostPackets   int     `json:"lost_packets"`
			} `json:"sum"`
		} `json:"end"`
	}

	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("Failed to parse Iperf JSON: %v", err)
	}

	return UDPStats{
		Mbps:        res.End.Sum.BitsPerSecond / 1e6,
		LostPercent: res.End.Sum.LostPercent,
		JitterMs:    res.End.Sum.JitterMs,
		Packets:     res.End.Sum.Packets,
		Lost:        res.End.Sum.LostPackets,
	}
}

func startIperfServer(t *testing.T, port string) func() {
	cmd := exec.Command("iperf3", "-s", "-p", port)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start iperf server: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	return func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}
}

// Keep the Ping helper but use it only for Latency
type PingStats struct {
	Avg     float64
	LossPct float64
}

func RunPing(t *testing.T, nsName string, targetIP string, count int) PingStats {
	cmd := exec.Command("ip", "netns", "exec", nsName, "ping", "-c", strconv.Itoa(count), "-i", "0.01", "-q", targetIP)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Ping command had error (expected for loss test, unexpected for latency): %v", err)
	}

	output := string(out)
	stats := PingStats{}
	reRtt := regexp.MustCompile(`rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms`)
	matches := reRtt.FindStringSubmatch(output)
	if len(matches) == 5 {
		stats.Avg, _ = strconv.ParseFloat(matches[2], 64)
	}

	reLoss := regexp.MustCompile(`(\d+)% packet loss`)
	if matches := reLoss.FindStringSubmatch(output); len(matches) == 2 {
		stats.LossPct, _ = strconv.ParseFloat(matches[1], 64)
	}

	return stats
}
