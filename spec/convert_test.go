package spec_test

import (
	"testing"

	"kuro/proto"
	"kuro/spec"
)

func TestBuildSpecs(t *testing.T) {
	config := &proto.ApplyNodeConfig{
		Vxlan: &proto.VxlanConfig{
			Vni:      100,
			Port:     4789,
			Iface:    "eth0",
			RemoteIp: "192.168.1.1",
		},
		Nodes: []*proto.NodeConfig{
			{
				Name: "node1",
				Ip:   "10.0.0.1",
				Type: proto.NodeType_EXEC,
				Runtime: &proto.NodeConfig_Exec{
					Exec: &proto.ExecNodeConfig{
						Exec: "/bin/sh",
						Args: []string{"-c", "ls"},
					},
				},
				TrafficShaping: &proto.TrafficShaping{
					RateBps:    5000,
					BurstBytes: 1000,
				},
				Netem: &proto.Netem{
					DelayMs: 20.5,
				},
			},
		},
	}

	res, err := spec.BuildSpecs(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.TopoSpec.Vxlan == nil || res.TopoSpec.Vxlan.ID != 100 {
		t.Errorf("vxlan id mismatch: expected 100")
	}

	if len(res.TopoSpec.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(res.TopoSpec.Nodes))
	}

	node := res.TopoSpec.Nodes[0]
	if node.Name != "node1" || node.Exec != "/bin/sh" {
		t.Errorf("node info mismatch: %+v", node)
	}

	if len(res.ProgramSpecs) != 1 {
		t.Fatalf("expected 1 program spec")
	}
	if res.ProgramSpecs[0].RateLimit.RateBytes != 5000 {
		t.Errorf("rate limit mismatch: %d", res.ProgramSpecs[0].RateLimit.RateBytes)
	}

	if len(res.NetemSpecs) != 1 {
		t.Fatalf("expected 1 netem spec")
	}
	if res.NetemSpecs[0].LatencyMs != 20.5 {
		t.Errorf("netem spec values mismatch")
	}

	if len(res.RouteSpecs) != 1 || res.RouteSpecs[0].DestIP != "10.0.0.1" {
		t.Errorf("route spec mismatch")
	}
}

func TestBuildSpecs_UnsupportedRuntime(t *testing.T) {
	config := &proto.ApplyNodeConfig{
		Nodes: []*proto.NodeConfig{
			{
				Name: "node3",
				Type: proto.NodeType_CONTAINER,
				Runtime: &proto.NodeConfig_Container{
					Container: &proto.ContainerNodeConfig{},
				},
			},
		},
	}

	_, err := spec.BuildSpecs(config)
	if err == nil {
		t.Error("expected error for unsupported container runtime, got nil")
	}
}
