package k8s

import (
	"testing"

	"kuro/internal/domain"

	"github.com/stretchr/testify/assert"
)

func TestParseLinkPolicy_Bandwidth(t *testing.T) {
	tests := []struct {
		name      string
		bandwidth string
		expected  uint64
	}{
		{
			name:      "10Mbps",
			bandwidth: "10Mbps",
			expected:  10_000_000,
		},
		{
			name:      "100Mbps",
			bandwidth: "100Mbps",
			expected:  100_000_000,
		},
		{
			name:      "1Gbps",
			bandwidth: "1Gbps",
			expected:  1_000_000_000,
		},
		{
			name:      "10kbps",
			bandwidth: "10kbps",
			expected:  10_000,
		},
		{
			name:      "10Kbps uppercase K",
			bandwidth: "10Kbps",
			expected:  10_000,
		},
		{
			name:      "without bps suffix",
			bandwidth: "10M",
			expected:  10_000_000,
		},
		{
			name:      "500kbps lowercase",
			bandwidth: "500kbps",
			expected:  500_000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseLinkPolicy(tt.bandwidth, "", "", "")
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, p.BandwidthBps)
		})
	}
}

func TestParseLinkPolicy_Latency(t *testing.T) {
	tests := []struct {
		name     string
		latency  string
		expected uint64
	}{
		{
			name:     "50ms",
			latency:  "50ms",
			expected: 50_000_000, // 50ms in nanoseconds
		},
		{
			name:     "100ms",
			latency:  "100ms",
			expected: 100_000_000,
		},
		{
			name:     "1s",
			latency:  "1s",
			expected: 1_000_000_000,
		},
		{
			name:     "500us",
			latency:  "500us",
			expected: 500_000,
		},
		{
			name:     "1.5s",
			latency:  "1.5s",
			expected: 1_500_000_000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseLinkPolicy("", tt.latency, "", "")
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, p.BaseLatencyNs)
		})
	}
}

func TestParseLinkPolicy_Jitter(t *testing.T) {
	tests := []struct {
		name     string
		jitter   string
		expected uint64
	}{
		{
			name:     "10ms",
			jitter:   "10ms",
			expected: 10_000_000,
		},
		{
			name:     "5ms",
			jitter:   "5ms",
			expected: 5_000_000,
		},
		{
			name:     "100us",
			jitter:   "100us",
			expected: 100_000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseLinkPolicy("", "", tt.jitter, "")
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, p.JitterNs)
		})
	}
}

func TestParseLinkPolicy_PacketLoss(t *testing.T) {
	tests := []struct {
		name     string
		loss     string
		expected uint32
	}{
		{
			name:     "0.5%",
			loss:     "0.5%",
			expected: 5000, // 0.5% = 5000 PPM
		},
		{
			name:     "1%",
			loss:     "1%",
			expected: 10000, // 1% = 10000 PPM
		},
		{
			name:     "0.1%",
			loss:     "0.1%",
			expected: 1000, // 0.1% = 1000 PPM
		},
		{
			name:     "10%",
			loss:     "10%",
			expected: 100000, // 10% = 100000 PPM
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseLinkPolicy("", "", "", tt.loss)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, p.CorruptionRatePpm)
		})
	}
}

func TestParseLinkPolicy_AllFields(t *testing.T) {
	p, err := ParseLinkPolicy("10Mbps", "50ms", "10ms", "0.5%")
	assert.NoError(t, err)

	assert.Equal(t, uint64(10_000_000), p.BandwidthBps)
	assert.Equal(t, uint64(50_000_000), p.BaseLatencyNs)
	assert.Equal(t, uint64(10_000_000), p.JitterNs)
	assert.Equal(t, uint32(5000), p.CorruptionRatePpm)
}

func TestParseLinkPolicy_EmptyFields(t *testing.T) {
	p, err := ParseLinkPolicy("", "", "", "")
	assert.NoError(t, err)

	// Should return zero values
	assert.Equal(t, domain.LinkPolicy{}, p)
}

func TestParseLinkPolicy_InvalidBandwidth(t *testing.T) {
	_, err := ParseLinkPolicy("invalid", "", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid bandwidth")
}

func TestParseLinkPolicy_InvalidLatency(t *testing.T) {
	_, err := ParseLinkPolicy("", "invalid", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid latency")
}

func TestParseLinkPolicy_InvalidJitter(t *testing.T) {
	_, err := ParseLinkPolicy("", "", "invalid", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid jitter")
}

func TestParseLinkPolicy_InvalidPacketLoss(t *testing.T) {
	_, err := ParseLinkPolicy("", "", "", "invalid%")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid packet loss")
}
