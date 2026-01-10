// Package config is used to parse config file
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type EmulationConfig struct {
	ConfigVersion string            `yaml:"config_version"`
	Workloads     []*WorkloadConfig `yaml:"workloads"`
}

type WorkloadConfig struct {
	PodName   string           `yaml:"pod_name"`
	RateLimit *RateLimitConfig `yaml:"rate_limit"`
	Netem     *NetemConfig     `yaml:"netem"`
}

type RateLimitConfig struct {
	RateBps    uint64 `yaml:"rate_bps"`
	BurstBytes uint64 `yaml:"burst_bytes"`
}

type NetemConfig struct {
	DelayMs  uint32 `yaml:"delay_ms"`
	JitterMs uint32 `yaml:"jitter_ms"`
	LossPpm  uint32 `yaml:"loss_ppm"`
}

func LoadConfig(path string) (*EmulationConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg EmulationConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	return &cfg, nil
}
