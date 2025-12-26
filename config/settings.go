// Package config is used to parsed config file
package config

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"unicode"

	pb "kuro/proto"

	"github.com/BurntSushi/toml"
)

type SimulationConfig struct {
	Hosts []HostConfig `toml:"host"`
}

type HostConfig struct {
	Name  string       `toml:"name"`
	Vxlan *VxlanConfig `toml:"vxlan,omitempty"`
	Nodes []NodeConfig `toml:"node"`
	// Routes []RouteConfig `toml:"route,omitempty"`
}

type VxlanConfig struct {
	ID    uint32 `toml:"vni"`
	Iface string `toml:"iface"`
	Port  uint32 `toml:"port"`
	Group string `toml:"group"`
	Src   string `toml:"src"`
}

type NodeConfig struct {
	Name           string          `toml:"name"` // Will be used as Interface Name usually
	Type           string          `toml:"type"` // container | exec
	Container      string          `toml:"container,omitempty"`
	Image          string          `toml:"image,omitempty"`
	Exec           string          `toml:"exec,omitempty"`
	Args           []string        `toml:"args,omitempty"`
	Cwd            string          `toml:"cwd,omitempty"`
	IP             string          `toml:"ip"`
	TrafficShaping *TrafficShaping `toml:"traffic_shaping,omitempty"`
	Netem          *Netem          `toml:"netem,omitempty"`
}

type TrafficShaping struct {
	RateBps    uint64 `toml:"rate_bps"`    // bytes per second
	BurstBytes uint64 `toml:"burst_bytes"` // bytes
}

type Netem struct {
	DelayMs  float64 `toml:"delay_ms,omitempty"`
	JitterMs float64 `toml:"jitter_ms,omitempty"`
	LossPct  float64 `toml:"loss,omitempty"`
}

type RouteConfig struct {
	DestIP  string `toml:"dest_ip"`
	OutNode string `toml:"out_node"` // This refers to the node name (interface name)
}

// LoadConfig parses the TOML and returns the config for the specific hostName
func LoadConfig(path string) (*SimulationConfig, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	var simCfg SimulationConfig
	if _, err := toml.DecodeFile(path, &simCfg); err != nil {
		return nil, fmt.Errorf("failed to parse TOML: %w", err)
	}

	for i, host := range simCfg.Hosts {
		if err := host.validateHost(); err != nil {
			return nil, fmt.Errorf("host[%d] error: %w", i, err)
		}
	}

	slog.Debug("LoadConfig", "simulation config", simCfg)

	return &simCfg, nil
}

func validateNodeName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("node name cannot be empty")
	}
	if len(name) > 8 {
		return fmt.Errorf("node name %q too long (max 8 chars)", name)
	}

	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			return fmt.Errorf("node name %q contains illegal character %q", name, c)
		}
	}
	return nil
}

// validate current host config here
func (h *HostConfig) validateHost() error {
	if h.Vxlan != nil {
		if h.Vxlan.Iface == "" {
			return fmt.Errorf("vxlan.iface cannot be empty")
		}

		if h.Vxlan.Group == "" {
			return fmt.Errorf("vxlan.remote cannot be empty")
		}

		if ip := net.ParseIP(h.Vxlan.Group); ip == nil || !ip.IsMulticast() {
			return fmt.Errorf("vxlan.group should be valid multicast ip: %s", h.Vxlan.Group)
		}

		if ip := net.ParseIP(h.Vxlan.Src); ip == nil {
			return fmt.Errorf("vxlan.src should be valid: %s", h.Vxlan.Src)
		}
	}

	usedIPs := make(map[string]string)
	for i, n := range h.Nodes {
		if err := validateNodeName(n.Name); err != nil {
			return err
		}
		if n.IP == "" {
			return fmt.Errorf("node[%d] (%s) IP cannot be empty", i, n.Name)
		}

		ip, _, err := net.ParseCIDR(n.IP)
		if err != nil {
			return fmt.Errorf("node[%d] (%s) has invalid CIDR format: %s (example: 192.168.1.1/24)", i, n.Name, n.IP)
		}

		ipStr := ip.String()
		if existingNode, found := usedIPs[ipStr]; found {
			return fmt.Errorf("IP conflict: node '%s' and node '%s' both use the same IP %s", existingNode, n.Name, ipStr)
		}

		usedIPs[ipStr] = n.Name
	}
	return nil
}

func BuildApplyNodeConfigs(cfg *SimulationConfig) map[string]*pb.ApplyNodeConfig {
	ret := make(map[string]*pb.ApplyNodeConfig)

	for _, host := range cfg.Hosts {
		req := &pb.ApplyNodeConfig{
			HostName: host.Name,
		}

		if host.Vxlan != nil {
			req.Vxlan = &pb.VxlanConfig{
				Vni:     uint32(host.Vxlan.ID),
				Port:    uint32(host.Vxlan.Port),
				Iface:   host.Vxlan.Iface,
				GroupIp: host.Vxlan.Group,
				Src:     host.Vxlan.Src,
			}
		}

		for _, node := range host.Nodes {
			req.Nodes = append(req.Nodes, buildNodeConfig(node))
		}

		ret[host.Name] = req
	}

	slog.Debug("BuildApplyNodeConfigs", "return", ret)

	return ret
}

func buildNodeConfig(n NodeConfig) *pb.NodeConfig {
	nodeType := pb.NodeType_NODE_TYPE_UNSPECIFIED

	switch n.Type {
	case "exec":
		nodeType = pb.NodeType_EXEC
	case "container":
		nodeType = pb.NodeType_CONTAINER
	}

	pbNode := &pb.NodeConfig{
		Name: n.Name,
		Type: nodeType,
		Ip:   n.IP,
	}

	// exec / container → oneof
	if n.Type == "exec" {
		pbNode.Runtime = &pb.NodeConfig_Exec{
			Exec: &pb.ExecNodeConfig{
				Exec: n.Exec,
				Args: n.Args,
				Cwd:  n.Cwd,
			},
		}
	}

	// traffic shaping
	if n.TrafficShaping != nil {
		pbNode.TrafficShaping = &pb.TrafficShaping{
			RateBps:    n.TrafficShaping.RateBps,
			BurstBytes: n.TrafficShaping.BurstBytes,
		}
	}

	// netem
	if n.Netem != nil {
		pbNode.Netem = &pb.Netem{
			Loss:     n.Netem.LossPct,
			JitterMs: n.Netem.JitterMs,
			DelayMs:  n.Netem.DelayMs,
		}
	}

	return pbNode
}
