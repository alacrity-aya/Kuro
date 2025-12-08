package loader

import (
	"encoding/binary"
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

	ifaceIndex uint32

	// Field for rate cauculation
	lastCheck   time.Time
	lastBytes   uint64
	smoothRate  float64
	firstSample bool
	statsMu     sync.Mutex
}

func NewEbpfProgram(objs *gen.TcObjects) *EbpfProgram {
	loaded := objs != nil && objs.Gress != nil

	return &EbpfProgram{
		objs:        objs,
		links:       make([]link.Link, 0),
		firstSample: true,
		loaded:      loaded,
	}
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
	if p.objs == nil || p.objs.Gress == nil {
		return fmt.Errorf("ebpf objects or program not loaded")
	}
	if !p.loaded {
		return fmt.Errorf("program not loaded, call Load() first")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifaceName, err)
	}

	// 2. Store the interface index for map keys
	p.ifaceIndex = uint32(iface.Index)

	// Detach existing links
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
		if err := attachDir(ebpf.AttachTCXEgress); err != nil {
			return err
		}
	}

	p.links = newLinks
	p.firstSample = true
	p.lastCheck = time.Now()

	slog.Info("Attached eBPF program", "iface", ifaceName, "index", p.ifaceIndex, "gress", gress)
	return nil
}

func (p *EbpfProgram) UpdateRateLimit(rate, burst uint64) error {
	if !p.loaded {
		return fmt.Errorf("program not loaded")
	}

	// Ensure State Map entry exists (needed for HASH maps with spinlocks)
	// We must initialize the bucket state if it doesn't exist
	newState := gen.TcBucketState{
		Tokens: burst, // Give full burst initially
		LastNs: uint64(time.Now().UnixNano()),
	}
	if err := p.objs.BucketStateMap.Update(p.ifaceIndex, newState, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to init bucket state: %w", err)
	}
	slog.Debug("Initialized bucket state", "state", newState)

	rule := gen.TcBucketRule{
		RateBytes:  rate,
		BurstBytes: burst,
	}

	slog.Debug("Updating BucketRuleMap", "ifaceIdx", p.ifaceIndex, "rate", rate, "burst", burst)

	if err := p.objs.BucketRuleMap.Update(p.ifaceIndex, rule, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update rate limit map: %w", err)
	}

	return nil
}

func (p *EbpfProgram) UpdateloaRedirectRule(dstIPStr string, targetIfaceName string) error {
	if !p.loaded {
		return fmt.Errorf("program not loaded")
	}

	// Parse IP
	ip := net.ParseIP(dstIPStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", dstIPStr)
	}

	// Ensure IPv4 and get 4 bytes
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("not an ipv4 address: %s", dstIPStr)
	}

	// Convert to __be32 (Big Endian uint32)
	// net.IP is already a byte slice, but we need it as a uint32 for the map key
	ipKey := binary.BigEndian.Uint32(v4)
	slog.Debug("IP str to be32", "dstIPStr", dstIPStr, "rawIP", ipKey, "targetIfaceName", targetIfaceName)

	// Get target interface index
	targetIface, err := net.InterfaceByName(targetIfaceName)
	if err != nil {
		return fmt.Errorf("target interface not found: %w", err)
	}
	targetIdx := uint32(targetIface.Index)

	if err := p.objs.RedirectMap.Update(ipKey, targetIdx, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update redirect map: %w", err)
	}

	slog.Debug("Updating RedirectMap", "ip", dstIPStr, "ip_be32", ipKey, "target", targetIfaceName, "idx", targetIdx)

	var key uint32
	var val uint32
	it := p.objs.RedirectMap.Iterate()
	for it.Next(&key, &val) {
		fmt.Printf("===map entry: key=%d (0x%x) -> val=%d===\n", key, key, val)
	}

	return nil
}

func (p *EbpfProgram) GetStats() (TrafficStats, error) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()

	var stats TrafficStats
	if !p.loaded {
		return stats, fmt.Errorf("program not loaded")
	}

	var values []gen.TcFlowCounter

	if err := p.objs.FlowCounterMap.Lookup(p.ifaceIndex, &values); err != nil {
		return stats, nil
	}

	for _, v := range values {
		stats.TotalAcceptedBytes += v.AcceptedBytes
		stats.TotalDroppedBytes += v.DroppedBytes
		stats.TotalAcceptedPackets += v.AcceptedPackets
		stats.TotalDroppedPackets += v.DroppedPackets
	}

	now := time.Now()

	if p.firstSample {
		p.lastBytes = stats.TotalAcceptedBytes
		p.lastCheck = now
		p.smoothRate = 0
		p.firstSample = false
		return stats, nil
	}

	duration := now.Sub(p.lastCheck).Seconds()

	if duration > 0 {
		deltaBytes := float64(stats.TotalAcceptedBytes - p.lastBytes)
		stats.InstantRateBps = deltaBytes / duration

		alpha := 0.2
		if p.smoothRate == 0 {
			p.smoothRate = stats.InstantRateBps
		} else {
			p.smoothRate = (alpha * stats.InstantRateBps) + ((1 - alpha) * p.smoothRate)
		}
		stats.SmoothRateBps = p.smoothRate
	}

	p.lastBytes = stats.TotalAcceptedBytes
	p.lastCheck = now

	return stats, nil
}

type EbpfManager struct {
	mu       sync.RWMutex
	programs map[string]*EbpfProgram

	objs *gen.TcObjects
}

func NewEbpfManager() *EbpfManager {
	return &EbpfManager{
		programs: make(map[string]*EbpfProgram),
	}
}

func (m *EbpfManager) Load(cfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Load objects once (shared among all interfaces)
	if m.objs == nil {
		m.objs = &gen.TcObjects{}
		if err := gen.LoadTcObjects(m.objs, nil); err != nil {
			slog.Error("Failed to load tc objects", "error", err)
			return err
		}
		slog.Debug("successed to load tc objects")
	}

	for _, rule := range cfg.Rules {
		if _, exists := m.programs[rule.IfaceName]; exists {
			continue
		}

		// Create program that references the shared objs
		prog := NewEbpfProgram(m.objs)

		slog.Debug("Attach tc hook...")

		// Attach sets the p.ifaceIndex
		if err := prog.Attach(rule.IfaceName, rule.Gress); err != nil {
			slog.Error("Failed to attach BPF program", "iface", rule.IfaceName, "error", err)
			prog.Detach()
			continue
		}

		if rule.RateLimit != nil {
			if err := prog.UpdateRateLimit(rule.RateLimit.Rate, rule.RateLimit.Burst); err != nil {
				slog.Error("Failed to update rate limit", "iface", rule.IfaceName, "error", err)
				prog.Detach()
				continue
			}

			prog.UpdateloaRedirectRule("10.10.0.2", "veth-b")
		} else {
			prog.UpdateloaRedirectRule("10.10.0.1", "veth-a")
		}

		m.programs[rule.IfaceName] = prog
	}

	return nil
}

func (m *EbpfManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	slog.Info("clear bpf resource...")

	for name, prog := range m.programs {
		if err := prog.Detach(); err != nil {
			slog.Warn("Failed to detach program", "error", err)
		}
		delete(m.programs, name)
	}

	if m.objs != nil {
		if err := m.objs.Close(); err != nil {
			return err
		}
		m.objs = nil
	}

	return nil
}

func initFlowCounterMap(prog *EbpfProgram) error {
	if prog.firstSample {
		var counterVals []gen.TcFlowCounter
		key := prog.ifaceIndex
		if err := prog.objs.FlowCounterMap.Update(key, counterVals, ebpf.UpdateNoExist); err != nil {
			return fmt.Errorf("init flow counter failed: %w", err)
		}
		slog.Debug("Initialized flow counter entry", "ifaceIdx", key)
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

	// initialize flow counter map
	if err := initFlowCounterMap(prog); err != nil {
		return TrafficStats{}, err
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
