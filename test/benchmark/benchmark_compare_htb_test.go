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
	"github.com/vishvananda/netns"
)

const (
	BenchNsName   = "bench_ns"
	BenchHostVeth = "veth_bench_host"
	BenchPodVeth  = "veth_bench_pod"
	BenchPodIP    = "10.20.1.2"
	BenchHostIP   = "10.20.1.1" // Explicitly define Host IP
)

// Define the test case structure
type benchCase struct {
	name string
	rate uint64 // bps
}

// Define the list of bandwidths to be tested
var testCases = []benchCase{
	{"100Mbps", 100 * 1000 * 1000},
	{"1Gbps", 1 * 1000 * 1000 * 1000},
	{"5Gbps", 5 * 1000 * 1000 * 1000},
}

// Benchmark_Classic_HTB tests the performance of the standard Linux TC HTB qdisc.
func Benchmark_Classic_HTB(b *testing.B) {
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			setupBenchmarkEnv(b)
			defer teardownBenchmarkEnv()

			// 1. Setup HTB on Host Veth (Ingress from Pod perspective, but we shape on XDP or Egress usually)
			// Here we verify Upload (Pod -> Host), so we shape on Pod Veth Egress?
			// Standard K8s CNI shapes on Host Veth Egress (Download) and Pod Veth Egress (Upload).
			// Let's shape Pod Veth Egress for Upload test.
			// But for simplicity in script-free setup, we run commands:

			// Apply HTB to Pod Veth (inside NS)
			cmd := exec.Command("ip", "netns", "exec", BenchNsName, "tc", "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "htb", "default", "1")
			if err := cmd.Run(); err != nil {
				b.Fatalf("Failed to add HTB root: %v", err)
			}
			rateStr := fmt.Sprintf("%dbit", tc.rate)
			cmd = exec.Command("ip", "netns", "exec", BenchNsName, "tc", "class", "add", "dev", "eth0", "parent", "1:", "classid", "1:1", "htb", "rate", rateStr)
			if err := cmd.Run(); err != nil {
				b.Fatalf("Failed to add HTB class: %v", err)
			}

			stopServer := startIperfServerHost(b)
			defer stopServer()

			b.ResetTimer()
			res := runBenchIperf(b)
			b.StopTimer()

			reportMetrics(b, "Classic-HTB", res, tc.rate)
		})
	}
}

// Benchmark_EDT_BPF tests the performance of our eBPF-based EDT implementation.
func Benchmark_EDT_BPF(b *testing.B) {
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			setupBenchmarkEnv(b)
			defer teardownBenchmarkEnv()

			mgr, err := bpf.NewBpfManager()
			if err != nil {
				b.Fatalf("NewBpfManager failed: %v", err)
			}
			defer mgr.Close()

			hostLink, _ := netlink.LinkByName(BenchHostVeth)
			nsHandle, _ := netns.GetFromName(BenchNsName)
			defer nsHandle.Close()

			if err := mgr.AddPod("bench-pod", hostLink.Attrs().Index, nsHandle); err != nil {
				b.Fatalf("AddPod failed: %v", err)
			}

			// [UPDATED] 1. Configure Rates (Sim & Sys)
			// We set both to the benchmark target rate.
			err = mgr.UpdateRule(hostLink.Attrs().Index, tc.rate, tc.rate, tc.rate, tc.rate)
			if err != nil {
				b.Fatalf("UpdateRule failed: %v", err)
			}

			// [UPDATED] 2. Set Policy to promote traffic to "Simulation Lane"
			// If we don't do this, traffic is treated as "System" and gets a 3ms latency penalty (offset),
			// which might unfairly skew throughput/latency metrics compared to raw HTB.
			// BandwidthLimit: 0 means "Use Default Sim Rate" (which we set above).
			policy := &bpf.NetworkPolicyConfig{BandwidthLimit: 0}

			// Upload: Pod -> Host
			if err := mgr.SetPolicy(BenchPodIP, BenchHostIP, policy); err != nil {
				b.Fatalf("SetPolicy Upload failed: %v", err)
			}

			// Wait for map sync
			time.Sleep(500 * time.Millisecond)

			stopServer := startIperfServerHost(b)
			defer stopServer()

			b.ResetTimer()
			res := runBenchIperf(b)
			b.StopTimer()

			reportMetrics(b, "EDT-BPF", res, tc.rate)
		})
	}
}

// --- Helpers ---

func setupBenchmarkEnv(b *testing.B) {
	exec.Command("ip", "netns", "add", BenchNsName).Run()
	exec.Command("ip", "link", "add", BenchHostVeth, "type", "veth", "peer", "name", BenchPodVeth).Run()
	exec.Command("ip", "link", "set", BenchPodVeth, "netns", BenchNsName).Run()

	// Host Side
	exec.Command("ip", "addr", "add", BenchHostIP+"/24", "dev", BenchHostVeth).Run()
	exec.Command("ip", "link", "set", BenchHostVeth, "up").Run()
	exec.Command("ip", "link", "set", "lo", "up").Run()

	// Pod Side
	// Rename veth to eth0 inside NS for consistency with BPF logic looking for "eth0"
	exec.Command("ip", "netns", "exec", BenchNsName, "ip", "link", "set", BenchPodVeth, "name", "eth0").Run()
	exec.Command("ip", "netns", "exec", BenchNsName, "ip", "addr", "add", BenchPodIP+"/24", "dev", "eth0").Run()
	exec.Command("ip", "netns", "exec", BenchNsName, "ip", "link", "set", "eth0", "up").Run()
	exec.Command("ip", "netns", "exec", BenchNsName, "ip", "link", "set", "lo", "up").Run()

	// Turn off offloading to test pure software performance (optional, but fair for comparison)
	exec.Command("ethtool", "-K", BenchHostVeth, "gso", "off", "tso", "off", "gro", "off").Run()
	exec.Command("ip", "netns", "exec", BenchNsName, "ethtool", "-K", "eth0", "gso", "off", "tso", "off", "gro", "off").Run()
}

func teardownBenchmarkEnv() {
	exec.Command("ip", "netns", "del", BenchNsName).Run()
	exec.Command("ip", "link", "del", BenchHostVeth).Run()
}

func startIperfServerHost(b *testing.B) func() {
	cmd := exec.Command("iperf3", "-s", "-p", "7001")
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

type BenchResult struct {
	Bps      float64
	Retrans  int
	CpuUsage float64
}

func runBenchIperf(b *testing.B) BenchResult {
	// Client in Pod -> Server on Host (Upload)
	// -Z: Zero Copy (reduces client CPU load to focus on network)
	// -P 4: Parallel streams to saturate link
	cmd := exec.Command("ip", "netns", "exec", BenchNsName, "iperf3", "-c", BenchHostIP, "-p", "7001", "-t", "10", "-J", "-P", "4", "-Z")
	out, err := cmd.Output()
	if err != nil {
		b.Logf("iperf3 failed: %v", err)
		return BenchResult{}
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
		b.Fatalf("json parse error: %v, output: %s", err, string(out))
	}

	return BenchResult{
		Bps:      res.End.SumSent.BitsPerSecond,
		Retrans:  res.End.SumSent.Retransmits,
		CpuUsage: res.End.CpuUtilizationPercent.HostTotal,
	}
}

func reportMetrics(b *testing.B, method string, r BenchResult, targetRate uint64) {
	mbps := r.Bps / 1e6
	b.ReportMetric(mbps, "Mbps")
	b.ReportMetric(float64(r.Retrans), "Retrans")
	b.ReportMetric(r.CpuUsage, "CPU%")

	targetMbps := float64(targetRate) / 1e6
	if mbps > targetMbps*1.15 || mbps < targetMbps*0.85 {
		b.Logf("[%s] WARNING: Rate unstable. Got %.2f Mbps, Target %.2f Mbps", method, mbps, targetMbps)
	} else {
		b.Logf("[%s] PASS: Rate stable. Got %.2f Mbps", method, mbps)
	}
}
