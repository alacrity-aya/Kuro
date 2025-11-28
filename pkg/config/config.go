package config

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

type LoggerConfig struct {
	Level string `toml:"level"`
}

type RuleConfig struct {
	Gress     string `toml:"gress"`
	Rate      string `toml:"rate"`
	TimeScale string `toml:"time_scale"`
	IfaceName string `toml:"iface_name"`
	Port      []int  `toml:"port"`
}

type GlobalConfig struct {
	Log  LoggerConfig `toml:"log"`
	Rule RuleConfig   `toml:"rule"`
}

var C GlobalConfig

func LoadConfig(configPath string) error {
	_, err := toml.DecodeFile(configPath, &C)
	if err != nil {
		return fmt.Errorf("failed to decode config file %s: %w", configPath, err)
	}
	return nil
}
