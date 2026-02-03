package k8s

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"kuro/internal/domain"

	"k8s.io/apimachinery/pkg/api/resource"
)

// ParseLinkPolicy converts string configurations from the CRD into the domain's integer-based configurations.
func ParseLinkPolicy(specBandwidth, specLatency, specJitter, specLoss string) (domain.LinkPolicy, error) {
	p := domain.LinkPolicy{}

	// 1. Bandwidth (bps)
	if specBandwidth != "" {
		normalized := specBandwidth
		// 1. Remove "bps" suffix (case-insensitive)
		if strings.HasSuffix(strings.ToLower(specBandwidth), "bps") {
			normalized = specBandwidth[:len(specBandwidth)-3]
		}

		// 2. Correct unit casing (K8s recognizes k, M, G, T; it does not recognize lowercase m, g, t for bandwidth)
		// If the user writes "10mbps" -> "10m" (interpreted as milli, which is incorrect) -> needs correction to "10M"
		// If the user writes "10gbps" -> "10g" (invalid) -> needs correction to "10G"
		if len(normalized) > 0 {
			lastChar := normalized[len(normalized)-1]
			switch lastChar {
			case 'm': // milli -> Mega
				normalized = normalized[:len(normalized)-1] + "M"
			case 'g': // invalid -> Giga
				normalized = normalized[:len(normalized)-1] + "G"
			case 'k', 'K': // kilo (K8s standard uses lowercase 'k')
				normalized = normalized[:len(normalized)-1] + "k"
			}
		}

		q, err := resource.ParseQuantity(normalized)
		if err != nil {
			return p, fmt.Errorf("invalid bandwidth %s (normalized: %s): %w", specBandwidth, normalized, err)
		}

		// q.Value() returns the int64 value (e.g., if the unit is M/G/k).
		// Since our context is bits (as the input is bps), the value parsed by ParseQuantity is used directly.
		// For example, "10M" -> 10,000,000, which represents bits/sec.
		p.BandwidthBps = uint64(q.Value())
	}

	// 2. Latency
	if specLatency != "" {
		d, err := time.ParseDuration(specLatency)
		if err != nil {
			return p, fmt.Errorf("invalid latency %s: %w", specLatency, err)
		}
		p.BaseLatencyNs = uint64(d.Nanoseconds())
	}

	// 3. Jitter
	if specJitter != "" {
		d, err := time.ParseDuration(specJitter)
		if err != nil {
			return p, fmt.Errorf("invalid jitter %s: %w", specJitter, err)
		}
		p.JitterNs = uint64(d.Nanoseconds())
	}

	// 4. Packet Loss (e.g., "0.5%") -> Convert to PPM (Parts Per Million)
	if specLoss != "" {
		s := strings.TrimSuffix(specLoss, "%")
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return p, fmt.Errorf("invalid packet loss %s: %w", specLoss, err)
		}
		// 1% = 10,000 PPM
		p.CorruptionRatePpm = uint32(f * 10000)
	}

	return p, nil
}
