//go:build benchmark

package test

import (
	"encoding/json"
	"fmt"
	"kuro/internal/agent/bpf"
	"os/exec"
	"testing"
	"time"
)

const (
	XdpBenchNs    = "bench_xdp_ns"
	XdpHostVeth   = "veth_xdp_host"
	XdpPodVeth    = "veth_xdp_pod"
	XdpPodIP      = "10.40.1.2"
	XdpHostIP     = "10.40.1.1"
	XdpServerPort = "7001"
)

// Define rate limit cases
var ingressTestCases = []benchCase{
	{"100Mbps", 100 * 1000 * 1000},
	{"500Mbps", 500 * 1000 * 1000},
	{"1Gbps", 1 * 1000 * 1000 * 1000},
}

// Benchmark_TC_Ingress_Police tests standard Linux TC policing
func Benchmark_TC_Ingress_Police(b *testing.B) {
	for _, tc := range ingressTestCases {
		b.Run(tc.name, func(b *testing.B) {
			setupXdpBenchEnv(b)
			defer teardownXdpBenchEnv()

			// Add standard TC ingress policing
			cmd := exec.Command("tc", "qdisc", "add", "dev", XdpHostVeth, "handle", "ffff:", "ingress")
			if err := cmd.Run(); err != nil {
				b.Fatalf("Failed to add ingress qdisc: %v", err)
			}

			// [FIXED] Burst adjusted.
			// TC 'burst' unit is bytes. A safe rule of thumb for TCP is rate / 1000 * buffer_ms.
			// Ideally for 1Gbps, we want > 1MB burst to be nice to TCP, but for UDP test 100KB is acceptable.
			// We increase it slightly to 200k to ensure stability.
			rateKbps := tc.rate / 1000
			cmd = exec.Command("tc", "filter", "add", "dev", XdpHostVeth, "parent", "ffff:", "protocol", "ip", "u32", "match", "u32", "0", "0", "police", "rate", fmt.Sprintf("%dkbit", rateKbps), "burst", "200k", "drop", "flowid", ":1")
			if err := cmd.Run(); err != nil {
				b.Fatalf("Failed to add police filter: %v", err)
			}

			stopServer := startIperfServerXdp(b)
			defer stopServer()

			b.ResetTimer()
			// [FIXED] Use UDP
			res := runXdpBenchIperfUDP(b, tc.rate)
			b.StopTimer()

			reportMetrics(b, "TC-Police", res, tc.rate)
		})
	}
}

// Benchmark_XDP_Drop tests our eBPF XDP rate limiter
func Benchmark_XDP_Drop(b *testing.B) {
	for _, tc := range ingressTestCases {
		b.Run(tc.name, func(b *testing.B) {
			setupXdpBenchEnv(b)
			defer teardownXdpBenchEnv()

			mgr, err := bpf.NewBpfManager(false)
			if err != nil {
				b.Fatalf("NewBpfManager failed: %v", err)
			}
			defer mgr.Close()

			// [FIXED] Increase Burst for XDP
			// 100KB is too small for 1Gbps (0.8ms).
			// We set burst to ~2ms worth of data or min 200KB.
			// 1Gbps = 125MB/s. 2ms = 250KB.
			burstBytes := uint64(256 * 1024)

			err = mgr.AttachIngressProtection(XdpHostVeth, tc.rate, burstBytes)
			if err != nil {
				b.Fatalf("AttachIngressProtection failed: %v", err)
			}

			stopServer := startIperfServerXdp(b)
			defer stopServer()

			b.ResetTimer()
			// [FIXED] Use UDP
			res := runXdpBenchIperfUDP(b, tc.rate)
			b.StopTimer()

			reportMetrics(b, "XDP-Drop", res, tc.rate)
		})
	}
}

// --- Helpers ---

func setupXdpBenchEnv(b *testing.B) {
	exec.Command("ip", "netns", "add", XdpBenchNs).Run()
	exec.Command("ip", "link", "add", XdpHostVeth, "type", "veth", "peer", "name", XdpPodVeth).Run()
	exec.Command("ip", "link", "set", XdpPodVeth, "netns", XdpBenchNs).Run()

	exec.Command("ip", "addr", "add", XdpHostIP+"/24", "dev", XdpHostVeth).Run()
	exec.Command("ip", "link", "set", XdpHostVeth, "up").Run()
	// Disable Offloading for accurate XDP testing
	exec.Command("ethtool", "-K", XdpHostVeth, "gso", "off", "gro", "off").Run()

	exec.Command("ip", "netns", "exec", XdpBenchNs, "ip", "addr", "add", XdpPodIP+"/24", "dev", XdpPodVeth).Run()
	exec.Command("ip", "netns", "exec", XdpBenchNs, "ip", "link", "set", XdpPodVeth, "up").Run()
	exec.Command("ip", "netns", "exec", XdpBenchNs, "ethtool", "-K", XdpPodVeth, "gso", "off", "gro", "off").Run()
}

func teardownXdpBenchEnv() {
	exec.Command("ip", "netns", "del", XdpBenchNs).Run()
	exec.Command("ip", "link", "del", XdpHostVeth).Run()
}

func startIperfServerXdp(b *testing.B) func() {
	cmd := exec.Command("iperf3", "-s", "-p", XdpServerPort)
	if err := cmd.Start(); err != nil {
		b.Fatalf("Failed to start iperf server: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	return func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}
}

// [NEW] Helper for UDP Benchmark
func runXdpBenchIperfUDP(b *testing.B, targetRate uint64) BenchResult {
	// Push 1.2x traffic to force dropping
	sendRateBps := float64(targetRate) * 1.2
	sendRateStr := fmt.Sprintf("%.0f", sendRateBps)

	// -u: UDP
	// -b: Bandwidth
	// -R: Reverse? No, Client(Pod) -> Host(Ingress). Normal mode.
	cmd := exec.Command("ip", "netns", "exec", XdpBenchNs, "iperf3", "-c", XdpHostIP, "-p", XdpServerPort, "-u", "-b", sendRateStr, "-t", "5", "-J", "-P", "4")
	out, err := cmd.Output()
	if err != nil {
		b.Logf("iperf3 UDP failed: %v", err)
	}

	var res struct {
		End struct {
			Sum struct {
				// For UDP, Sum contains the aggregated stats
				BitsPerSecond float64 `json:"bits_per_second"`
				LostPercent   float64 `json:"lost_percent"`
			} `json:"sum"`
			CpuUtilizationPercent struct {
				HostTotal float64 `json:"host_total"`
			} `json:"cpu_utilization_percent"`
		} `json:"end"`
	}

	if err := json.Unmarshal(out, &res); err != nil {
		b.Fatalf("json parse error: %v, output: %s", err, string(out))
	}

	// For UDP, bits_per_second in 'sum' is the received bandwidth (Goodput)
	return BenchResult{
		Bps:      res.End.Sum.BitsPerSecond,
		Retrans:  0, // UDP has no retransmits
		CpuUsage: res.End.CpuUtilizationPercent.HostTotal,
	}
}
