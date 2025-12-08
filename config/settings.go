package config

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Rules []Rule `toml:"rule"`
}

type Rule struct {
	IfaceName string     `toml:"ifacename"`
	Gress     string     `toml:"gress"`
	RateLimit *RateLimit `toml:"rate_limit,omitempty"`
	NetQoS    *NetQoS    `toml:"net_qos,omitempty"`
}

type RateLimit struct {
	Algo  string `toml:"algo,omitempty"`
	Rate  uint64 `toml:"rate,omitempty"`  // bytes
	Burst uint64 `toml:"burst,omitempty"` // bytes
}

func (r *RateLimit) String() string {
	if r == nil {
		return "nil"
	}
	return fmt.Sprintf("{algo=%s rate=%d burst=%d}", r.Algo, r.Rate, r.Burst)
}

func (q *NetQoS) String() string {
	if q == nil {
		return "nil"
	}
	return fmt.Sprintf("{delay=%dms jitter=%dms loss=%.3f%%}", q.DelayMs, q.JitterMs, q.LossPct)
}

type NetQoS struct {
	DelayMs  int     `toml:"delay_ms,omitempty"`
	JitterMs int     `toml:"jitter_ms,omitempty"`
	LossPct  float64 `toml:"loss_pct,omitempty"`
}

var C Config

func (cfg *Config) LoadConfig(path string) {
	if _, err := os.Stat(path); err != nil {
		log.Fatalf("failed to find config file, path: %s", path)
	}

	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		log.Fatalf("Failed to parse TOML: %v", err)
	}
	cfg.checkConfig()
}

func (cfg *Config) checkConfig() {
	for i, r := range cfg.Rules {
		if r.IfaceName == "" {
			log.Fatalf("rule[%d]: iface cannot be empty", i)
		}
		if r.Gress == "" {
			log.Fatalf("rule[%d]: gress cannot be empty", i)
		}

		if r.Gress != "both" && r.Gress != "ingress" && r.Gress != "egress" {
			log.Fatalf("rule[%d]: gress = %v, expected 'both', 'ingress' or 'egress'", i, r.Gress)
		}

		if r.RateLimit == nil && r.NetQoS == nil {
			log.Fatalf("rule[%d]: either rate_limit or net_qos must be specified", i)
		}

		if _, err := net.InterfaceByName(r.IfaceName); err != nil {
			log.Fatalf("rule[%d]: failed to find eth: %s, %v", i, r.IfaceName, err)
		}

		if r.RateLimit != nil {
			if r.RateLimit.Rate == 0 || r.RateLimit.Burst == 0 {
				log.Fatalf("rule[%d]: rate or burst equals to zero, rate = %d, burst = %d", i, r.RateLimit.Rate, r.RateLimit.Burst)
			}
		}
	}
}
