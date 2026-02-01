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

			// Add standard TC ingress policing on Host Veth
			// NOTE: Policing on Ingress is supported by default in recent kernels
			cmd := exec.Command("tc", "qdisc", "add", "dev", XdpHostVeth, "handle", "ffff:", "ingress")
			if err := cmd.Run(); err != nil {
				b.Fatalf("Failed to add ingress qdisc: %v", err)
			}

			// rate X kbit burst 100k
			rateKbps := tc.rate / 1000
			cmd = exec.Command("tc", "filter", "add", "dev", XdpHostVeth, "parent", "ffff:", "protocol", "ip", "u32", "match", "u32", "0", "0", "police", "rate", fmt.Sprintf("%dkbit", rateKbps), "burst", "100k", "drop", "flowid", ":1")
			if err := cmd.Run(); err != nil {
				b.Fatalf("Failed to add police filter: %v", err)
			}

			stopServer := startIperfServerXdp(b)
			defer stopServer()

			b.ResetTimer()
			res := runXdpBenchIperf(b)
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

			mgr, err := bpf.NewBpfManager()
			if err != nil {
				b.Fatalf("NewBpfManager failed: %v", err)
			}
			defer mgr.Close()

			// Attach XDP to Host Veth
			// Burst = 100KB approx
			err = mgr.AttachIngressProtection(XdpHostVeth, tc.rate, 100*1024)
			if err != nil {
				b.Fatalf("AttachIngressProtection failed: %v", err)
			}

			// We DO NOT set any policy here.
			// By default, traffic will be "System Traffic" and hit the XDP limiter.

			stopServer := startIperfServerXdp(b)
			defer stopServer()

			b.ResetTimer()
			res := runXdpBenchIperf(b)
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

	// Host Side
	exec.Command("ip", "addr", "add", XdpHostIP+"/24", "dev", XdpHostVeth).Run()
	exec.Command("ip", "link", "set", XdpHostVeth, "up").Run()

	// Ensure GSO/GRO is off to stress packet processing
	exec.Command("ethtool", "-K", XdpHostVeth, "gso", "off", "gro", "off").Run()

	// Pod Side
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

func runXdpBenchIperf(b *testing.B) BenchResult {
	// Client runs in NS (Pod), sending to Host
	// We want to test INGRESS on Host Veth
	cmd := exec.Command("ip", "netns", "exec", XdpBenchNs, "iperf3", "-c", XdpHostIP, "-p", XdpServerPort, "-t", "10", "-J", "-P", "8", "-Z")
	out, err := cmd.Output()
	if err != nil {
		b.Logf("iperf3 failed (expected if drops are too high?): %v", err)
	}

	var res struct {
		End struct {
			SumSent struct {
				BitsPerSecond float64 `json:"bits_per_second"`
				Retransmits   int     `json:"retransmits"`
			} `json:"sum_sent"`
			CpuUtilizationPercent struct {
				HostTotal float64 `json:"host_total"`
			} `json:"cpu_utilization_percent"`
		} `json:"end"`
	}

	if err := json.Unmarshal(out, &res); err != nil {
		// Just return zero result if parse fails (likely connection reset due to drop)
		return BenchResult{}
	}

	// For XDP limit, we check the *Received* rate usually, or Sent rate to see how much TCP backed off.
	// Since iperf report is from client side (Sender), SumSent shows what it *tried* to push (and successfully acked?).
	// Actually, TCP will backoff.
	return BenchResult{
		Bps:      res.End.SumSent.BitsPerSecond,
		Retrans:  res.End.SumSent.Retransmits,
		CpuUsage: res.End.CpuUtilizationPercent.HostTotal,
	}
}
