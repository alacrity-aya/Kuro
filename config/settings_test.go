package config

import (
	"testing"
)

func TestValidateHost(t *testing.T) {
	tests := []struct {
		name    string
		host    HostConfig
		wantErr bool
	}{
		{
			name: "Valid config with VXLAN and Nodes",
			host: HostConfig{
				Name: "host1",
				Vxlan: &VxlanConfig{
					ID:    100,
					Iface: "eth0",
					Group: "239.1.1.1",
					Port:  4789,
					Src:   "127.0.0.1",
				},
				Nodes: []NodeConfig{
					{Name: "n1", IP: "10.0.0.1/24"},
					{Name: "n2", IP: "10.0.0.2/24"},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid VXLAN Remote (not multicast)",
			host: HostConfig{
				Vxlan: &VxlanConfig{
					Iface: "eth0",
					Group: "1.1.1.1",
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid IP format (missing mask)",
			host: HostConfig{
				Nodes: []NodeConfig{
					{Name: "n1", IP: "10.0.0.1"},
				},
			},
			wantErr: true,
		},
		{
			name: "IP conflict between nodes",
			host: HostConfig{
				Nodes: []NodeConfig{
					{Name: "n1", IP: "10.10.0.1/24"},
					{Name: "n2", IP: "10.10.0.1/24"},
				},
			},
			wantErr: true,
		},
		{
			name: "Node name too long",
			host: HostConfig{
				Nodes: []NodeConfig{
					{Name: "verylongnodename", IP: "10.0.0.1/24"},
				},
			},
			wantErr: true,
		},
		{
			name: "Node name illegal characters",
			host: HostConfig{
				Nodes: []NodeConfig{
					{Name: "n-1", IP: "10.0.0.1/24"},
				},
			},
			wantErr: true,
		},
		{
			name: "Empty node IP",
			host: HostConfig{
				Nodes: []NodeConfig{
					{Name: "n1", IP: ""},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.host.validateHost()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHost() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildApplyNodeConfigs(t *testing.T) {
	cfg := &SimulationConfig{
		Hosts: []HostConfig{
			{
				Name: "h1",
				Vxlan: &VxlanConfig{
					ID:    42,
					Group: "239.1.1.1",
					Iface: "eth0",
				},
				Nodes: []NodeConfig{
					{Name: "n1", IP: "192.168.1.1/24", Type: "exec", Exec: "ls"},
				},
			},
		},
	}

	res := BuildApplyNodeConfigs(cfg)

	if len(res) != 1 {
		t.Fatalf("expected 1 host config, got %d", len(res))
	}

	h1, ok := res["h1"]
	if !ok {
		t.Fatal("host h1 not found in result")
	}

	if h1.Vxlan.Vni != 42 {
		t.Errorf("expected VNI 42, got %d", h1.Vxlan.Vni)
	}

	if len(h1.Nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(h1.Nodes))
	}
}
