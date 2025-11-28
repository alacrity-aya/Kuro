package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// =====================
// Raw TOML structs
// =====================

type LoggerConfig struct {
	Level string `toml:"level"`
}

type TargetConfig struct {
	Ports   []int  `toml:"ports"`      // required
	RateStr string `toml:"rate"`       // required
	TimeStr string `toml:"time_scale"` // required
}

type OtherConfig struct {
	RateStr string `toml:"rate"`       // required
	TimeStr string `toml:"time_scale"` // optional
}

type RuleConfig struct {
	Iface  string       `toml:"iface"` // required
	Gress  string       `toml:"gress"` // required
	Target TargetConfig `toml:"target"`
	Other  OtherConfig  `toml:"other"`
}

type GlobalConfig struct {
	Log  LoggerConfig `toml:"log"`
	Rule RuleConfig   `toml:"rule"`

	// Parsed values (converted)
	TargetRateBps uint64
	TargetTimeMs  uint64
	OtherRateBps  uint64
	OtherTimeMs   uint64
	TargetGress   uint8
}

var C GlobalConfig

// =====================
// Parsing helpers
// =====================

func parseRate(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, errors.New("rate cannot be empty")
	}

	multiplier := uint64(1)

	switch {
	case strings.HasSuffix(s, "K"):
		multiplier = 1000
		s = strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		multiplier = 1000 * 1000
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		multiplier = 1000 * 1000 * 1000
		s = strings.TrimSuffix(s, "G")
	}

	var base uint64
	_, err := fmt.Sscanf(s, "%d", &base)
	if err != nil {
		return 0, fmt.Errorf("invalid rate format: %s", s)
	}

	return base * multiplier, nil
}

// Convert "200ms", "1s", "2s" → milliseconds
func parseTimeScale(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, errors.New("time_scale cannot be empty")
	}

	// Let Go's duration parser handle it
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid time_scale: %s", s)
	}

	return uint64(d.Milliseconds()), nil
}

// =====================
// Required field checker
// =====================

func validateRequiredFields() error {
	r := C.Rule

	if r.Iface == "" {
		return errors.New("[rule.iface] is required")
	}

	if r.Gress == "" {
		return errors.New("[rule.gress] is required")
	}

	// Target required
	if len(r.Target.Ports) == 0 {
		return errors.New("[rule.target.ports] cannot be empty")
	}
	if r.Target.RateStr == "" {
		return errors.New("[rule.target.rate] is required")
	}
	if r.Target.TimeStr == "" {
		return errors.New("[rule.target.time_scale] is required")
	}

	// Other traffic required only for rate
	if r.Other.RateStr == "" {
		return errors.New("[rule.other.rate] is required")
	}

	return nil
}

// =====================
// LoadConfig
// =====================

func LoadConfig(configPath string) error {
	_, err := toml.DecodeFile(configPath, &C)
	if err != nil {
		return fmt.Errorf("failed to decode config file %s: %w", configPath, err)
	}

	// Validate required fields
	if err := validateRequiredFields(); err != nil {
		return err
	}

	// Parse target values
	C.TargetRateBps, err = parseRate(C.Rule.Target.RateStr)
	if err != nil {
		return err
	}
	C.TargetTimeMs, err = parseTimeScale(C.Rule.Target.TimeStr)
	if err != nil {
		return err
	}

	// tc.bpf.c:
	// #define INGRESS 0
	// #define EGRESS 1
	switch C.Rule.Gress {
	case "egress":
		C.TargetGress = 1
	case "ingress":
		C.TargetGress = 0
	default:
		return errors.New("config.C.Rule.Gress != egress/ingress")
	}

	// Parse other values
	C.OtherRateBps, err = parseRate(C.Rule.Other.RateStr)
	if err != nil {
		return err
	}

	// time_scale optional for other
	if C.Rule.Other.TimeStr != "" {
		C.OtherTimeMs, err = parseTimeScale(C.Rule.Other.TimeStr)
		if err != nil {
			return err
		}
	} else {
		C.OtherTimeMs = 100 // default 100ms
	}

	return nil
}
