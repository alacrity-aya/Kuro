package config

import (
	"log"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Rules []Rule `toml:"rule"`
}

type Rule struct {
	Ifacename string     `toml:"ifacename"`
	Gress     string     `toml:"gress"`
	RateLimit *RateLimit `toml:"rate_limit,omitempty"`
	NetQoS    *NetQoS    `toml:"net_qos,omitempty"`
}

type RateLimit struct {
	Algo  string `toml:"algo,omitempty"`
	Rate  int    `toml:"rate,omitempty"`  // bytes
	Burst int    `toml:"burst,omitempty"` // bytes
}

type NetQoS struct {
	DelayMs  int     `toml:"delay_ms,omitempty"`
	JitterMs int     `toml:"jitter_ms,omitempty"`
	LossPct  float64 `toml:"loss_pct,omitempty"`
}

var C Config

func LoadConfig(path string) {
	if _, err := os.Stat(path); err != nil {
		log.Fatalf("failed to find config file, path: %s", path)
	}

	if _, err := toml.DecodeFile(path, &C); err != nil {
		log.Fatalf("Failed to parse TOML: %v", err)
	}
	checkConfig(C)
}

func checkConfig(cfg Config) {
	for i, r := range cfg.Rules {
		if r.Ifacename == "" {
			log.Fatalf("rule[%d]: iface cannot be empty", i)
		}
		if r.Gress == "" {
			log.Fatalf("rule[%d]: gress cannot be empty", i)
		}

		if r.RateLimit == nil && r.NetQoS == nil {
			log.Fatalf("rule[%d]: either rate_limit or net_qos must be specified", i)
		}

		if _, err := net.InterfaceByName(r.Ifacename); err != nil {
			log.Fatalf("rule[%d]: failed to find eth: %s, %v", i, r.Ifacename, err)
		}
	}
}
