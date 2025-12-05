package loader

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"kuro/config"
	"kuro/gen"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("Failed to remove memlock", "error", err)
	}
}

type TrafficStats struct {
	TotalAcceptedBytes   uint64
	TotalDroppedBytes    uint64
	TotalAcceptedPackets uint64
	TotalDroppedPackets  uint64

	// Calculated rates (based on AcceptedBytes)
	InstantRateBps float64 // Bytes per second (Instantaneous)
	SmoothRateBps  float64 // Bytes per second (Smoothed/EMA)
}

type EbpfProgram struct {
	links []link.Link
	objs  *gen.TcObjects

	loaded bool

	// Field for rate cauculation
	lastCheck   time.Time
	lastBytes   uint64
	smoothRate  float64
	firstSample bool
	statsMu     sync.Mutex
}

func NewEbpfProgram() *EbpfProgram {
	return &EbpfProgram{
		objs:        &gen.TcObjects{},
		links:       make([]link.Link, 0),
		firstSample: true,
	}
}

func (p *EbpfProgram) Load() error {
	if p.loaded {
		return nil
	}

	if err := gen.LoadTcObjects(p.objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}

	p.loaded = true
	return nil
}

func (p *EbpfProgram) Detach() error {
	var errs []error
	for _, l := range p.links {
		if l != nil {
			if err := l.Close(); err != nil {
				errs = append(errs, err)
				slog.Error("Failed to close link", "error", err)
			}
		}
	}
	p.links = nil
	if len(errs) > 0 {
		return fmt.Errorf("errors occurred during detach: %v", errs)
	}
	return nil
}

func (p *EbpfProgram) Attach(ifaceName string, gress string) error {
	if !p.loaded {
		return fmt.Errorf("program not loaded, call Load() first")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifaceName, err)
	}

	// Detach existing links before attaching new ones
	_ = p.Detach()

	var newLinks []link.Link

	attachDir := func(attachType ebpf.AttachType) error {
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   p.objs.Gress,
			Attach:    attachType,
		})
		if err != nil {
			return err
		}
		newLinks = append(newLinks, l)
		return nil
	}

	// Attach logic based on direction
	switch gress {
	case "ingress":
		if err := attachDir(ebpf.AttachTCXIngress); err != nil {
			return err
		}
	case "egress":
		if err := attachDir(ebpf.AttachTCXEgress); err != nil {
			return err
		}
	case "both":
		if err := attachDir(ebpf.AttachTCXEgress); err != nil {
			return err
		}
		if err := attachDir(ebpf.AttachTCXIngress); err != nil {
			for _, l := range newLinks {
				l.Close()
			}
			return err
		}
	default:
		// Default to egress
		if err := attachDir(ebpf.AttachTCXEgress); err != nil {
			return err
		}
	}

	p.links = newLinks
	// Reset stats baseline on re-attach
	p.firstSample = true
	p.lastCheck = time.Now()

	slog.Info("Attached eBPF program", "iface", ifaceName, "gress", gress)
	return nil
}

func (p *EbpfProgram) Close() {
	slog.Info("Closing eBPF program resources...")
	_ = p.Detach()

	if p.loaded && p.objs != nil {
		if err := p.objs.Close(); err != nil {
			slog.Error("Failed to close eBPF objects", "error", err)
		}
		p.loaded = false
	}
}

func (p *EbpfProgram) UpdateRateLimit(rate, burst uint64) error {
	if !p.loaded {
		return fmt.Errorf("program not loaded")
	}

	rule := gen.TcBucketRule{
		RateBytes:  rate,
		BurstBytes: burst,
	}

	// Key is always 0 based on map definition
	var key uint32 = 0

	slog.Debug("Updating BucketRuleMap", "rate", rate, "burst", burst)
	if err := p.objs.BucketRuleMap.Update(key, rule, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update rate limit map: %w", err)
	}

	return nil
}

func (p *EbpfProgram) GetStats() (TrafficStats, error) {
	p.statsMu.Lock() // TODO: why need lock here?
	defer p.statsMu.Unlock()

	var stats TrafficStats
	if !p.loaded {
		return stats, fmt.Errorf("program not loaded")
	}

	// FlowCounterMap is a PERCPU_ARRAY. Lookup returns a slice of values (one per CPU).
	var values []gen.TcFlowCounter
	var key uint32 = 0

	// Note: objs.FlowCounterMap needs to be available in gen.TcObjects
	if err := p.objs.FlowCounterMap.Lookup(key, &values); err != nil {
		return stats, fmt.Errorf("failed to lookup flow counter map: %w", err)
	}

	// Aggregate values from all CPUs
	for _, v := range values {
		stats.TotalAcceptedBytes += v.AcceptedBytes
		stats.TotalDroppedBytes += v.DroppedBytes
		stats.TotalAcceptedPackets += v.AcceptedPackets
		stats.TotalDroppedPackets += v.DroppedPackets
	}

	// Calculate Rates
	now := time.Now()

	if p.firstSample {
		// First run: just initialize baseline, rate is 0
		p.lastBytes = stats.TotalAcceptedBytes
		p.lastCheck = now
		p.smoothRate = 0
		p.firstSample = false
		return stats, nil
	}

	duration := now.Sub(p.lastCheck).Seconds()

	// Avoid division by zero
	if duration > 0 {
		// Calculate delta
		deltaBytes := float64(stats.TotalAcceptedBytes - p.lastBytes)

		// Instantaneous Rate
		stats.InstantRateBps = deltaBytes / duration

		// Smooth Rate using Exponential Moving Average (EMA)
		// Alpha factor determines weight of new data (e.g., 0.2 means 20% new, 80% history)
		alpha := 0.2
		if p.smoothRate == 0 {
			p.smoothRate = stats.InstantRateBps
		} else {
			p.smoothRate = (alpha * stats.InstantRateBps) + ((1 - alpha) * p.smoothRate)
		}
		stats.SmoothRateBps = p.smoothRate
	}

	// Update state for next calculation
	p.lastBytes = stats.TotalAcceptedBytes
	p.lastCheck = now

	return stats, nil
}

type EbpfManager struct {
	mu       sync.RWMutex
	programs map[string]*EbpfProgram // key: ifaceName
}

func NewEbpfManager() *EbpfManager {
	return &EbpfManager{
		programs: make(map[string]*EbpfProgram),
	}
}

func (m *EbpfManager) Load(cfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rule := range cfg.Rules {
		if rule.RateLimit == nil {
			continue
		}

		if _, exists := m.programs[rule.Ifacename]; exists {
			slog.Info("Interface already managed, skipping load", "iface", rule.Ifacename)
			continue
		}

		prog := NewEbpfProgram()
		if err := prog.Load(); err != nil {
			slog.Error("Failed to load BPF objects", "iface", rule.Ifacename, "error", err)
			continue
		}

		if err := prog.Attach(rule.Ifacename, rule.Gress); err != nil {
			slog.Error("Failed to attach BPF program", "iface", rule.Ifacename, "error", err)
			prog.Close()
			continue
		}

		if err := prog.UpdateRateLimit(rule.RateLimit.Rate, rule.RateLimit.Burst); err != nil {
			slog.Error("Failed to update rate limit", "iface", rule.Ifacename, "error", err)
			prog.Close()
			continue
		}

		m.programs[rule.Ifacename] = prog
	}

	return nil
}

func (m *EbpfManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, prog := range m.programs {
		prog.Close()
		delete(m.programs, name)
	}
	return nil
}

func (m *EbpfManager) GetIfaceStats(ifaceName string) (TrafficStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	prog, exists := m.programs[ifaceName]
	if !exists {
		return TrafficStats{}, fmt.Errorf("interface %s not managed", ifaceName)
	}

	return prog.GetStats()
}

func (m *EbpfManager) Reload(ifaceName string, rateLimit config.RateLimit) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	slog.Info("Reloading rate limits...", "ifaceName", ifaceName)

	prog, exists := m.programs[ifaceName]

	if !exists {
		return fmt.Errorf("interface %s not managed", ifaceName)
	}

	err := prog.UpdateRateLimit(rateLimit.Rate, rateLimit.Burst)
	if err != nil {
		slog.Error("Failed to reload rule", "iface", ifaceName, "error", err)
	} else {
		slog.Debug("Successfully reloaded rule", "iface", ifaceName)
	}

	return nil
}
