package test

import (
	"os/exec"
	"testing"
	"time"

	"kuro/internal/agent/bpf"
)

// Specific constants for Eth0 test
const (
	Eth0NsName     = "test_eth0_ns"
	FakeHostIface  = "veth_fake_host"
	FakeWorldIface = "veth_fake_world"
	Eth0HostIP     = "192.168.50.1"
	Eth0WorldIP    = "192.168.50.2"
	Eth0Port       = "6001"
)

func TestEth0Protection(t *testing.T) {
	setupEth0Topology(t)
	mgr := InitBPFManager(t) // Uses shared cleanup

	limitIngress := 5.0 * Mb

	// 3. Attach Ingress Protection to "Fake Host"
	t.Logf("[Test] Attaching Ingress Protection Limit: %.2f Mbps", limitIngress/Mb)
	err := mgr.AttachIngressProtection(FakeHostIface, uint64(limitIngress), 10*1024)
	if err != nil {
		t.Fatalf("AttachIngressProtection failed: %v", err)
	}

	// Start iperf Server in Root NS (Simulating Host App)
	stopServer := startIperfServerInRoot(t)
	defer stopServer()

	// ==========================================
	// Test A: System Traffic (Blocked by XDP)
	// ==========================================
	// Client runs in NS (World), targeting Host IP
	t.Run("Sys_Traffic_Dropped", func(t *testing.T) {
		t.Log(">>> Testing System Traffic (Expect XDP Drop/Limit)...")

		// Using RunIperf helper with clientNs set
		bps := RunIperf(t, Eth0NsName, Eth0HostIP, Eth0Port, "3", false)

		// XDP enforcement is strict, usually well below limit or exactly at it
		ValidateTraffic(t, bps, limitIngress, "Sys-XDP", 1.0) // 100% tolerance up, but mainly checking it doesn't exceed massively

		if bps > limitIngress*2 {
			t.Errorf("Traffic exceeded safety limit! Got %.2f Mbps", bps/Mb)
		}
	})

	time.Sleep(2 * time.Second)

	// ==========================================
	// Test B: Simulation Traffic (Bypass XDP)
	// ==========================================
	t.Run("Sim_Traffic_Bypass", func(t *testing.T) {
		t.Log(">>> Applying Policy (Expect Bypass / No Limit)...")

		policy := &bpf.NetworkPolicyConfig{BandwidthLimit: 0}
		if err := mgr.SetPolicy(Eth0WorldIP, Eth0HostIP, policy); err != nil {
			t.Fatalf("SetPolicy failed: %v", err)
		}

		bps := RunIperf(t, Eth0NsName, Eth0HostIP, Eth0Port, "3", false)

		// Expect > 50Mbps (veth speed is usually very fast)
		if bps < 50*Mb {
			t.Errorf("Sim Traffic did not bypass XDP! Speed: %.2f Mbps (Expected > 50)", bps/Mb)
		} else {
			t.Logf("[Pass] Sim Traffic Bypassed: %.2f Mbps", bps/Mb)
		}
	})
}

// Helper specific to Eth0 topology construction
func setupEth0Topology(t *testing.T) {
	t.Log("[Setup] Creating Fake Eth0 Topology...")

	exec.Command("ip", "netns", "del", Eth0NsName).Run()

	exec.Command("ip", "link", "del", FakeHostIface).Run()

	RunShellHelper(t, "ip", "netns", "add", Eth0NsName)
	RunShellHelper(t, "ip", "link", "add", FakeHostIface, "type", "veth", "peer", "name", FakeWorldIface)
	RunShellHelper(t, "ip", "link", "set", FakeWorldIface, "netns", Eth0NsName)

	// Configure Host
	RunShellHelper(t, "ip", "addr", "add", Eth0HostIP+"/24", "dev", FakeHostIface)
	RunShellHelper(t, "ip", "link", "set", FakeHostIface, "up")
	RunShellHelper(t, "ip", "link", "set", "lo", "up")

	// Configure World (NS) using helper wrapper
	runInNs(t, Eth0NsName, "ip", "addr", "add", Eth0WorldIP+"/24", "dev", FakeWorldIface)
	runInNs(t, Eth0NsName, "ip", "link", "set", FakeWorldIface, "up")
	runInNs(t, Eth0NsName, "sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=0")

	// Cleanup
	t.Cleanup(func() {
		t.Log("[Cleanup] Removing Eth0 Topology...")
		exec.Command("ip", "netns", "del", Eth0NsName).Run()
		exec.Command("ip", "link", "del", FakeHostIface).Run()
	})
}

func startIperfServerInRoot(t *testing.T) func() {
	t.Logf("[Setup] Starting background iperf3 server on port %s...", Eth0Port)
	cmd := exec.Command("iperf3", "-s", "-p", Eth0Port)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start iperf server: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // warm up
	return func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}
}

func runInNs(t *testing.T, ns string, command ...string) {
	args := append([]string{"netns", "exec", ns}, command...)
	RunShellHelper(t, "ip", args...)
}
