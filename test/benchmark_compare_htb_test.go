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

			b.Logf("[HTB] Applying rules for %s...", tc.name)
			cmds := [][]string{
				{"tc", "qdisc", "add", "dev", BenchHostVeth, "root", "handle", "1:", "htb", "default", "10"},
				{"tc", "class", "add", "dev", BenchHostVeth, "parent", "1:", "classid", "1:10", "htb", "rate", fmt.Sprintf("%dbit", tc.rate)},
			}
			for _, c := range cmds {
				if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
					b.Fatalf("Failed to setup HTB: %v, %s", err, string(out))
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result := runBenchIperf(b)
				reportMetrics(b, "HTB-"+tc.name, result, tc.rate)
			}
		})
	}
}

// Benchmark_Ebpf_EDT tests the performance of our custom eBPF EDT limiter.
func Benchmark_Ebpf_EDT(b *testing.B) {
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			setupBenchmarkEnv(b)
			defer teardownBenchmarkEnv()

			mgr, err := bpf.NewBpfManager()
			if err != nil {
				b.Fatalf("Failed to create BPF manager: %v", err)
			}
			defer mgr.Close()

			linkHost, err := netlink.LinkByName(BenchHostVeth)
			if err != nil {
				b.Fatalf("Cannot find host veth: %v", err)
			}

			nsHandle, err := netns.GetFromPath("/var/run/netns/" + BenchNsName)
			if err != nil {
				b.Fatalf("Cannot get ns handle: %v", err)
			}
			defer nsHandle.Close()

			time.Sleep(1 * time.Second)

			b.Logf("[eBPF] Attaching EDT programs for %s...", tc.name)
			if err := mgr.AddPod("bench-pod", linkHost.Attrs().Index, nsHandle); err != nil {
				b.Fatalf("AddPod failed: %v", err)
			}

			// [FIX]: Add BOTH Pod IP and Host IP to whitelist.
			// Since we test Download (Host->Pod), eBPF checks Src IP (Host).
			// We must simulate that the Host is a trusted Sim Peer.
			b.Logf("[eBPF] Whitelisting Peers (Pod: %s, Host: %s)...", BenchPodIP, BenchHostIP)
			if err := mgr.AddPeer(BenchPodIP); err != nil {
				b.Fatalf("AddPeer Pod failed: %v", err)
			}
			if err := mgr.AddPeer(BenchHostIP); err != nil {
				b.Fatalf("AddPeer Host failed: %v", err)
			}

			b.Logf("[eBPF] Applying EDT rules (%s)...", tc.name)
			if err := mgr.UpdateRule(linkHost.Attrs().Index, tc.rate, tc.rate); err != nil {
				b.Fatalf("UpdateRule failed: %v", err)
			}

			time.Sleep(1 * time.Second)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result := runBenchIperf(b)
				reportMetrics(b, "eBPF-"+tc.name, result, tc.rate)
			}
		})
	}
}

type BenchResult struct {
	Bps      float64
	Retrans  int
	CpuUsage float64
}

func runBenchIperf(b *testing.B) BenchResult {
	// Targeting BenchPodIP
	cmd := exec.Command("iperf3", "-c", BenchPodIP, "-t", "10", "-J", "-Z", "-P", "8")
	out, err := cmd.Output()
	if err != nil {
		b.Fatalf("iperf3 failed: %v", err)
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

func setupBenchmarkEnv(b *testing.B) {
	// Use BenchPodIP and BenchHostIP constants
	cmd := exec.Command("./test/setup_topology.sh", BenchNsName, BenchHostVeth, BenchPodVeth, BenchPodIP+"/24", BenchHostIP+"/24", "5201")
	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("Setup failed: %v, %s", err, string(out))
	}
}

func teardownBenchmarkEnv() {
	exec.Command("ip", "netns", "del", BenchNsName).Run()
	exec.Command("ip", "link", "del", BenchHostVeth).Run()
}
