package config

import (
	"fmt"
	"os"
	"unicode"

	"github.com/BurntSushi/toml"
)

type SimulationConfig struct {
	Hosts []HostConfig `toml:"host"`
}

type HostConfig struct {
	Name   string        `toml:"name"`
	Vxlan  *VxlanConfig  `toml:"vxlan,omitempty"`
	Nodes  []NodeConfig  `toml:"node"`
	Routes []RouteConfig `toml:"route"`
}

type VxlanConfig struct {
	ID     int    `toml:"id"`
	Iface  string `toml:"iface"`
	Port   int    `toml:"port"`
	Remote string `toml:"remote"`
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
	DelayMs  uint32  `toml:"delay_ms,omitempty"`
	JitterMs uint32  `toml:"jitter_ms,omitempty"`
	LossPct  float64 `toml:"loss,omitempty"`
}

type RouteConfig struct {
	DestIP  string `toml:"dest_ip"`
	OutNode string `toml:"out_node"` // This refers to the node name (interface name)
}

// LoadHostConfig parses the TOML and returns the config for the specific hostName
func LoadHostConfig(path string, hostName string) (*HostConfig, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	var simCfg SimulationConfig
	if _, err := toml.DecodeFile(path, &simCfg); err != nil {
		return nil, fmt.Errorf("failed to parse TOML: %w", err)
	}

	for _, h := range simCfg.Hosts {
		if h.Name == hostName {
			// Found the target host
			if err := h.validateHost(); err != nil {
				return nil, err
			}
			return &h, nil
		}
	}

	return nil, fmt.Errorf("host '%s' not found in config file", hostName)
}

func ValidateNodeName(name string) error {
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
	}

	for i, n := range h.Nodes {
		if err := ValidateNodeName(n.Name); err != nil {
			return err
		}
		if n.IP == "" {
			return fmt.Errorf("node[%d] (%s) IP cannot be empty", i, n.Name)
		}
	}
	return nil
}
