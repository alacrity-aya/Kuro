//go:build benchmark

package test

import (
	"encoding/json"
	"fmt"
	"kuro/internal/agent/bpf"
	"os/exec"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
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

			stopServer := startIperfServerXdp(b)
			defer stopServer()

			b.Logf("[TC] Applying Ingress Police rules for %s...", tc.name)

			rateBits := tc.rate

			// [FIX]: Increase Burst to allow TCP to function correctly.
			// Recommendation: At least 100ms of buffer for policing.
			// Burst (bytes) = (Rate (bps) * 0.1 sec) / 8
			burstBytes := rateBits / 8 / 10

			// Ensure a healthy minimum burst (e.g., 2MB) for high-speed veth
			if burstBytes < 2*1024*1024 {
				burstBytes = 2 * 1024 * 1024
			}

			// TC Command:
			// tc filter add ... police rate X burst Y mtu 64kb drop
			cmds := [][]string{
				{"tc", "qdisc", "add", "dev", XdpHostVeth, "handle", "ffff:", "ingress"},
				{
					"tc", "filter", "add", "dev", XdpHostVeth, "parent", "ffff:", "protocol", "ip",
					"u32", "match", "u32", "0", "0",
					"police", "rate", fmt.Sprintf("%dbit", rateBits),
					"burst", fmt.Sprintf("%d", burstBytes),
					// "limit" removed
					"drop", "flowid", ":1",
				},
			}

			for _, c := range cmds {
				if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
					b.Fatalf("Failed to setup TC Police: %v, %s", err, string(out))
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result := runXdpBenchIperf(b)
				reportMetrics(b, "TC-Police-"+tc.name, result, tc.rate)
			}
		})
	}
}

// Benchmark_XDP_TokenBucket tests our custom eBPF XDP implementation
func Benchmark_XDP_TokenBucket(b *testing.B) {
	for _, tc := range ingressTestCases {
		b.Run(tc.name, func(b *testing.B) {
			setupXdpBenchEnv(b)
			defer teardownXdpBenchEnv()

			stopServer := startIperfServerXdp(b)
			defer stopServer()

			mgr, err := bpf.NewBpfManager()
			if err != nil {
				b.Fatalf("NewBpfManager failed: %v", err)
			}
			defer mgr.Close()

			linkObj, _ := netlink.LinkByName(XdpHostVeth)

			// [FIX]: Increase Burst for XDP as well.
			// Same logic: 100ms burst to accommodate TCP
			burstBytes := uint64(tc.rate / 8 / 10)
			if burstBytes < 2*1024*1024 {
				burstBytes = 2 * 1024 * 1024
			}

			b.Logf("[XDP] Attaching Ingress Protection for %s (Burst: %d bytes)...", tc.name, burstBytes)

			if err := mgr.AttachIngressProtection(linkObj.Attrs().Name, tc.rate, burstBytes); err != nil {
				b.Fatalf("Failed to attach XDP: %v", err)
			}

			time.Sleep(1 * time.Second)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result := runXdpBenchIperf(b)
				reportMetrics(b, "XDP-Token-"+tc.name, result, tc.rate)
			}
		})
	}
}

// --- Helpers ---

func setupXdpBenchEnv(b *testing.B) {
	cmd := exec.Command("./test/bpf/setup_topology.sh", XdpBenchNs, XdpHostVeth, XdpPodVeth, XdpPodIP+"/24", XdpHostIP+"/24", XdpServerPort)
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("Setup failed: %v, %s", err, string(out))
	}
	// [CRITICAL] Disable offloading!
	// In veth pairs, TSO/GRO creates super-packets (up to 64KB).
	// If the policer sees one 64KB packet and the token bucket only has 10KB left, it drops the WHOLE 64KB.
	// This causes massive throughput fluctuations.
	exec.Command("ethtool", "-K", XdpHostVeth, "tso", "off", "gso", "off", "gro", "off").Run()
	exec.Command("ip", "netns", "exec", XdpBenchNs, "ethtool", "-K", "eth0", "tso", "off", "gso", "off", "gro", "off").Run()
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
	// [ADJUSTMENT] Increase TCP parallel streams slightly to help saturate link despite drops
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

	if len(out) > 0 {
		if err := json.Unmarshal(out, &res); err != nil {
			b.Fatalf("json parse error: %v, output: %s", err, string(out))
		}
	}

	return BenchResult{
		Bps:      res.End.SumSent.BitsPerSecond,
		Retrans:  res.End.SumSent.Retransmits,
		CpuUsage: res.End.CpuUtilizationPercent.HostTotal,
	}
}
