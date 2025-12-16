package config

import (
	"os"
	"testing"
)

const testToml = `
[[host]]
name = "hostA"

[host.vxlan]
id = 42
iface = "vxlan42"
port = 4789
remote = "192.168.1.10"

[[host.node]]
name = "node1"
type = "container"
container = "sim-node-1"
image = "ubuntu:latest"
ip = "10.10.0.1/24"

[host.node.traffic_shaping]
rate_bps = 12500000
burst_bytes = 80000000

[host.node.netem]
loss = 0.1
jitter_ms = 1000
delay_ms = 10

[[host.node]]
name = "server"
type = "exec"
exec = "iperf3"
args = ["-s"]
cwd = "/workspace"
ip = "10.10.0.2/24"

[[host.route]]
dest_ip = "10.10.0.1"
out_node = "node1"
`

func TestLoadHostConfig_Fields(t *testing.T) {
	tmpFile := "test_config.toml"
	if err := os.WriteFile(tmpFile, []byte(testToml), 0o644); err != nil {
		t.Fatalf("failed to write test toml: %v", err)
	}
	defer os.Remove(tmpFile)

	hc, err := LoadConfig(tmpFile, "hostA")
	if err != nil {
		t.Fatalf("LoadHostConfig failed: %v", err)
	}

	if hc.Name != "hostA" {
		t.Errorf("expected host name 'hostA', got %s", hc.Name)
	}

	if hc.Vxlan == nil {
		t.Fatal("expected vxlan config to be non-nil")
	}
	if hc.Vxlan.ID != 42 || hc.Vxlan.Iface != "vxlan42" || hc.Vxlan.Port != 4789 || hc.Vxlan.Remote != "192.168.1.10" {
		t.Errorf("vxlan fields mismatch: %+v", hc.Vxlan)
	}

	if len(hc.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(hc.Nodes))
	}

	node1 := hc.Nodes[0]
	if node1.Name != "node1" || node1.Type != "container" || node1.Container != "sim-node-1" || node1.Image != "ubuntu:latest" || node1.IP != "10.10.0.1/24" {
		t.Errorf("node1 fields mismatch: %+v", node1)
	}
	if node1.TrafficShaping == nil || node1.TrafficShaping.RateBps != 12500000 || node1.TrafficShaping.BurstBytes != 80000000 {
		t.Errorf("node1 traffic shaping mismatch: %+v", node1.TrafficShaping)
	}
	if node1.Netem == nil || node1.Netem.DelayMs != 10 || node1.Netem.JitterMs != 1000 || node1.Netem.LossPct != 0.1 {
		t.Errorf("node1 netem mismatch: %+v", node1.Netem)
	}

	node2 := hc.Nodes[1]
	if node2.Name != "server" || node2.Type != "exec" || node2.Exec != "iperf3" || node2.IP != "10.10.0.2/24" || node2.Cwd != "/workspace" {
		t.Errorf("node2 fields mismatch: %+v", node2)
	}
	if len(node2.Args) != 1 || node2.Args[0] != "-s" {
		t.Errorf("node2 args mismatch: %+v", node2.Args)
	}
}
