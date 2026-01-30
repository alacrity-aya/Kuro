//go:build bpf

package test

import (
	"encoding/json"
	"kuro/internal/agent/bpf"
	"os/exec"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	Eth0NsName     = "test_eth0_ns"
	FakeHostIface  = "veth_fake_host"
	FakeWorldIface = "veth_fake_world"
	HostIP         = "192.168.50.1"
	WorldIP        = "192.168.50.2"
	IperfPort      = "6001"

	// Set a very low limit for testing to easily verify XDP DROP
	TestIngressLimit = 5 * 1000 * 1000 // 5 Mbps
)

// Reusing IperfResult struct from previous tests
type IperfResultEth0 struct {
	End struct {
		SumReceived struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_received"`
	} `json:"end"`
}

func TestEth0Protection(t *testing.T) {
	// 1. Setup Environment (Fake Host <-> Fake World)
	setupEth0Topology(t)
	defer cleanupEth0Topology()

	t.Log("Fake Eth0 Topology Created.")

	// 2. Initialize BPF Manager on the Fake Host Interface
	// This will attach:
	// - TC Egress (Global Scheduling)
	// - XDP Ingress (DDoS Protection)
	mgr, err := bpf.NewBpfManager()
	if err != nil {
		t.Fatalf("NewBpfManager failed: %v", err)
	}
	defer mgr.Close()

	// 3. Manually override Ingress Limit for testing
	// The default init might set it to 900Mbps (based on 1Gbps default), which is too high to test locally.
	// We set it to 5Mbps to verify the XDP DROP logic.
	linkObj, _ := netlink.LinkByName(FakeHostIface)
	if err := mgr.AttachIngressProtection(linkObj.Attrs().Name, uint64(TestIngressLimit), 64*1024); err != nil {
		t.Fatalf("Failed to update ingress limit: %v", err)
	}
	t.Logf("Ingress Protection enforced: Limit = %f Mbps", TestIngressLimit/1e6)

	// ========================================================================
	// Phase A: Sys Traffic (Not Whitelisted) -> Should be Throttled by XDP
	// ========================================================================
	t.Run("Phase_A_Sys_Ingress_Throttled", func(t *testing.T) {
		t.Log("Testing Sys Ingress (World -> Host)...")

		// Ensure whitelist is empty
		peers, _ := mgr.GetPeers()
		if len(peers) > 0 {
			t.Fatalf("Expected empty whitelist, got: %v", peers)
		}

		// Run iperf Server on Host (Current NS)
		stopServer := startIperfServer(t)
		defer stopServer()

		// Run iperf Client in World NS
		bps := runIperfClientInNs(t, Eth0NsName, HostIP)

		// Validate
		validateEth0Speed(t, bps, float64(TestIngressLimit), "Sys Ingress")
	})

	time.Sleep(1 * time.Second)

	// ========================================================================
	// Phase B: Sim Traffic (Whitelisted) -> Should Bypass XDP Limit
	// ========================================================================
	t.Run("Phase_B_Sim_Ingress_Bypass", func(t *testing.T) {
		t.Logf("Whitelisting World IP: %s", WorldIP)
		if err := mgr.AddPeer(WorldIP); err != nil {
			t.Fatalf("Failed to add peer: %v", err)
		}

		// Run iperf Server on Host
		stopServer := startIperfServer(t)
		defer stopServer()

		// Run iperf Client in World NS
		bps := runIperfClientInNs(t, Eth0NsName, HostIP)

		// Validate
		// Veth pair speed is virtual (usually > 10Gbps).
		// We expect it to be significantly higher than our 5Mbps limit.
		if bps < 50*1000*1000 {
			t.Errorf("[Sim Ingress] FAILED: Speed too low (%.2f Mbps). Bypass might have failed.", bps/1e6)
		} else {
			t.Logf("[Sim Ingress] PASS: Bypass successful. Speed: %.2f Mbps", bps/1e6)
		}
	})
}

// --- Helpers ---

func setupEth0Topology(t *testing.T) {
	// Cleanup old
	exec.Command("ip", "netns", "del", Eth0NsName).Run()
	exec.Command("ip", "link", "del", FakeHostIface).Run()

	// Create Namespace
	if err := exec.Command("ip", "netns", "add", Eth0NsName).Run(); err != nil {
		t.Fatalf("Failed to add ns: %v", err)
	}

	// Create Veth Pair
	if err := exec.Command("ip", "link", "add", FakeHostIface, "type", "veth", "peer", "name", FakeWorldIface).Run(); err != nil {
		t.Fatalf("Failed to create veth: %v", err)
	}

	// Move Peer to NS
	if err := exec.Command("ip", "link", "set", FakeWorldIface, "netns", Eth0NsName).Run(); err != nil {
		t.Fatalf("Failed to move iface: %v", err)
	}

	// Configure Host IP
	if err := exec.Command("ip", "addr", "add", HostIP+"/24", "dev", FakeHostIface).Run(); err != nil {
		t.Fatalf("Failed to add host ip: %v", err)
	}
	exec.Command("ip", "link", "set", FakeHostIface, "up").Run()

	// Configure World IP (Inside NS)
	runInNs(t, Eth0NsName, "ip", "addr", "add", WorldIP+"/24", "dev", FakeWorldIface)
	runInNs(t, Eth0NsName, "ip", "link", "set", FakeWorldIface, "up")
	runInNs(t, Eth0NsName, "ip", "link", "set", "lo", "up")

	// Disable Offloading on Veth to verify XDP properly (sometimes needed for Generic XDP accuracy)
	exec.Command("ethtool", "-K", FakeHostIface, "tso", "off", "gso", "off", "gro", "off").Run()
}

func cleanupEth0Topology() {
	exec.Command("ip", "netns", "del", Eth0NsName).Run()
	exec.Command("ip", "link", "del", FakeHostIface).Run()
}

func startIperfServer(t *testing.T) func() {
	// Start iperf3 server in one-off mode
	cmd := exec.Command("iperf3", "-s", "-p", IperfPort, "--one-off")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start iperf server: %v", err)
	}

	// Allow startup time
	time.Sleep(500 * time.Millisecond)

	return func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}
}

func runIperfClientInNs(t *testing.T, ns, targetIP string) float64 {
	// Run client inside the namespace, targeting the host
	cmdStr := []string{"ip", "netns", "exec", ns, "iperf3", "-c", targetIP, "-p", IperfPort, "-t", "5", "-J", "-Z"}
	cmd := exec.Command(cmdStr[0], cmdStr[1:]...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("iperf client failed: %v, Output: %s", err, string(out))
	}

	var res IperfResultEth0
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("json parse failed: %v", err)
	}

	return res.End.SumReceived.BitsPerSecond
}

func runInNs(t *testing.T, ns string, command ...string) {
	args := append([]string{"netns", "exec", ns}, command...)
	if err := exec.Command("ip", args...).Run(); err != nil {
		t.Fatalf("Failed to run in ns %s: %v", ns, err)
	}
}

func validateEth0Speed(t *testing.T, actualBps float64, limitBps float64, name string) {
	mbps := actualBps / 1e6
	targetMbps := limitBps / 1e6

	t.Logf("[%s] Actual: %.2f Mbps, Limit: %.2f Mbps", name, mbps, targetMbps)

	// Allow some burst margin for XDP (it's not a shaper, it's a policer)
	// Policers are harsh, but token bucket allows bursts.
	if actualBps > limitBps*1.3 {
		t.Errorf("[%s] FAIL: Speed exceeded limit! Got %.2f Mbps", name, mbps)
	} else {
		t.Logf("[%s] PASS: Speed successfully throttled.", name)
	}
}
