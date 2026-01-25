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
	BenchNsName    = "bench_ns"
	BenchHostVeth  = "veth_bench_host"
	BenchPodVeth   = "veth_bench_pod"
	BenchLimitRate = 1 * 1000 * 1000 * 1000 // New: 1 Gbps
)

func Benchmark_Classic_HTB(b *testing.B) {
	setupBenchmarkEnv(b)
	defer teardownBenchmarkEnv()

	// tc qdisc add dev veth_bench_host root handle 1: htb default 10
	// tc class add dev veth_bench_host parent 1: classid 1:10 htb rate 100mbit
	b.Logf("Applying Classic HTB rules (%.0f Mbps)...", BenchLimitRate/1e6)
	cmds := [][]string{
		{"tc", "qdisc", "add", "dev", BenchHostVeth, "root", "handle", "1:", "htb", "default", "10"},
		{"tc", "class", "add", "dev", BenchHostVeth, "parent", "1:", "classid", "1:10", "htb", "rate", fmt.Sprintf("%dbit", BenchLimitRate)},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			b.Fatalf("Failed to setup HTB: %v, %s", err, string(out))
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := runBenchIperf(b)
		reportMetrics(b, "HTB", result)
	}
}

func Benchmark_Ebpf_EDT(b *testing.B) {
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

	time.Sleep(2 * time.Second)

	b.Logf("Attaching eBPF EDT programs...")
	if err := mgr.AddPod("bench-pod", linkHost.Attrs().Index, nsHandle); err != nil {
		b.Fatalf("AddPod failed: %v", err)
	}

	b.Logf("Applying eBPF EDT rules (%.0f Mbps)...", BenchLimitRate/1e6)

	if err := mgr.UpdateRule(linkHost.Attrs().Index, BenchLimitRate, BenchLimitRate); err != nil {
		b.Fatalf("UpdateRule failed: %v", err)
	}

	time.Sleep(1 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := runBenchIperf(b)
		reportMetrics(b, "eBPF-EDT", result)
	}
}

type BenchResult struct {
	Bps      float64
	Retrans  int
	CpuUsage float64
}

func runBenchIperf(b *testing.B) BenchResult {
	cmd := exec.Command("iperf3", "-c", "10.20.1.2", "-t", "5", "-J", "-Z", "-P", "16")
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
		b.Fatalf("json parse error: %v", err)
	}

	return BenchResult{
		Bps:      res.End.SumSent.BitsPerSecond,
		Retrans:  res.End.SumSent.Retransmits,
		CpuUsage: res.End.CpuUtilizationPercent.HostTotal,
	}
}

func reportMetrics(b *testing.B, method string, r BenchResult) {
	mbps := r.Bps / 1e6
	b.ReportMetric(mbps, "Mbps")
	b.ReportMetric(float64(r.Retrans), "Retrans")
	b.ReportMetric(r.CpuUsage, "CPU%")

	targetMbps := float64(BenchLimitRate) / 1e6
	if mbps > targetMbps*1.1 || mbps < targetMbps*0.9 {
		b.Logf("[%s] WARNING: Rate unstable. Got %.2f Mbps, Target %.2f Mbps", method, mbps, targetMbps)
	}
}

func setupBenchmarkEnv(b *testing.B) {
	cmd := exec.Command("./setup_topology.sh", BenchNsName, BenchHostVeth, BenchPodVeth, "10.20.1.2/24", "10.20.1.1/24", "5201")

	if out, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("Setup failed: %v, %s", err, string(out))
	}
}

func teardownBenchmarkEnv() {
	exec.Command("ip", "netns", "del", BenchNsName).Run()
	exec.Command("ip", "link", "del", BenchHostVeth).Run()
}
