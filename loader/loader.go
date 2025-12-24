// Package loader is used to load ebpf program
package loader

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"kuro/gen"
	"kuro/spec"
	"kuro/utils"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("Failed to remove memlock", "error", err)
	}
}

type IfaceStats struct {
	IfaceName string
	Stat      TrafficStats
}

type TrafficStats struct {
	TotalAcceptedBytes   uint64
	TotalDroppedBytes    uint64
	TotalAcceptedPackets uint64
	TotalDroppedPackets  uint64

	// Calculated rates (based on AcceptedBytes)
	InstantRateBps float64 // Bytes per second (Instantaneous)
	SmoothRateBps  float64 // Bytes per second (Smoothed/EMA)

	TimeStamp time.Time
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

// Attach I think attaching ingress only is enough
func (p *EbpfProgram) Attach(ifaceName string) error {
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

	p.ifaceIndex = uint32(iface.Index)

	// Detach existing links
	_ = p.Detach()

	var newLinks []link.Link

	// TODO: remove this in future
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

	if err := attachDir(ebpf.AttachTCXIngress); err != nil {
		return err
	}

	p.links = newLinks
	p.firstSample = true
	p.lastCheck = time.Now()

	slog.Info("Attached eBPF program", "iface", ifaceName, "index", p.ifaceIndex, "gress", "ingress")
	return nil
}

func (p *EbpfProgram) UpdateNetem(delayMs, jitterMs, loss float64) error {
	if !p.loaded {
		return fmt.Errorf("program not loaded")
	}

	rule := gen.TcNetemRule{
		Loss:     uint64(loss),
		JitterMs: uint64(jitterMs),
		DelayMs:  uint64(delayMs),
	}

	slog.Debug("Updating NetemRuleMap",
		"ifaceIdx", p.ifaceIndex,
		"delay", rule.DelayMs,
		"jitter", rule.JitterMs,
		"loss", rule.Loss)

	if err := p.objs.NetemRuleMap.Update(p.ifaceIndex, rule, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update netem map: %w", err)
	}

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

	rule := gen.TcTrafficRule{
		RateBytes:  rate,
		BurstBytes: burst,
	}

	slog.Debug("Updating BucketRuleMap", "ifaceIdx", p.ifaceIndex, "rate", rate, "burst", burst)

	if err := p.objs.TrafficRuleMap.Update(p.ifaceIndex, rule, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update rate limit map: %w", err)
	}

	return nil
}

func (m *EbpfManager) updateGlobalRedirect(dstIPStr string, targetIfaceName string) error {
	slog.Debug("updateGlobalRedirect", "dstIPStr", dstIPStr, "targetIfaceName", targetIfaceName)

	ip := net.ParseIP(dstIPStr)
	if ip == nil {
		return fmt.Errorf("invalid ip: %s", dstIPStr)
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("not ipv4: %s", dstIPStr)
	}

	ipKey := binary.NativeEndian.Uint32(v4)

	targetIface, err := net.InterfaceByName(targetIfaceName)
	if err != nil {
		return fmt.Errorf("target iface %s not found: %w", targetIfaceName, err)
	}
	targetIdx := uint32(targetIface.Index)

	if err := m.objs.RedirectMap.Update(ipKey, targetIdx, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("map update failed: %w", err)
	}

	slog.Debug("Route Updated", "ip", dstIPStr, "target", targetIfaceName, "idx", targetIdx)
	return nil
}

func (p *EbpfProgram) GetStats() (TrafficStats, error) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()

	var stats TrafficStats
	if !p.loaded {
		return stats, fmt.Errorf("program not loaded")
	}

	// initialize flow counter map
	if p.firstSample {
		if err := initFlowCounterMap(p); err != nil {
			return TrafficStats{}, err
		}
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
	stats.TimeStamp = now

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

func (m *EbpfManager) Sync(programs []spec.ProgramSpec, routes []spec.RouteSpec, netems []spec.NetemSpec) error {
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

	// Attach Tc and update rate limit rules
	for _, program := range programs {
		if _, exists := m.programs[program.IfaceName]; exists {
			continue
		}

		// Create program that references the shared objs
		prog := NewEbpfProgram(m.objs)

		slog.Debug("Attach tc hook...")

		// Attach sets the p.ifaceIndex
		if err := prog.Attach(program.IfaceName); err != nil {
			slog.Error("Failed to attach BPF program", "iface", program.IfaceName, "error", err)
			prog.Detach()
			continue
		}

		if program.RateLimit != nil {
			if err := prog.UpdateRateLimit(program.RateLimit.RateBytes, program.RateLimit.BurstBytes); err != nil {
				slog.Error("Failed to update rate limit", "iface", program.IfaceName, "error", err)
				prog.Detach()
				continue
			}
		}

		m.programs[program.IfaceName] = prog
	}

	// Update netem rules
	for _, netem := range netems {
		// BUG: netem.IfaceName and program.IfaceName is different
		prog, exists := m.programs[netem.IfaceName]
		if !exists {
			slog.Warn("Netem rule target interface not managed by eBPF, skipping", "iface", netem.IfaceName)
			continue
		}

		if err := prog.UpdateNetem(netem.LatencyMs, netem.JitterMs, netem.LossPercent); err != nil {
			slog.Error("Failed to update netem rule", "iface", netem.IfaceName, "error", err)
		}
	}

	// Update Redirect Map
	for _, route := range routes {
		if err := m.updateGlobalRedirect(route.DestIP, utils.EthName(route.TargetNode)); err != nil {
			slog.Error("Failed to update route", "dest", route.DestIP, "target", route.TargetNode, "err", err)
		}
	}

	return nil
}

func (m *EbpfManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	slog.Info("clear bpf resource...")

	var errs []error

	for name, prog := range m.programs {
		if err := prog.Detach(); err != nil {
			slog.Warn("Failed to detach program", "error", err)
			errs = append(errs, err)
		}
		delete(m.programs, name)
	}

	if m.objs != nil {
		if err := m.objs.Close(); err != nil {
			errs = append(errs, err)
		}
		m.objs = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("close encountered multiple errors: %v", errs)
	}

	return nil
}

func initFlowCounterMap(prog *EbpfProgram) error {
	var counterVals []gen.TcFlowCounter
	key := prog.ifaceIndex
	if err := prog.objs.FlowCounterMap.Update(key, counterVals, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("init flow counter failed: %w", err)
	}
	slog.Debug("Initialized flow counter entry", "ifaceIdx", key)

	return nil
}

func (m *EbpfManager) CollectStats() []IfaceStats {
	// create snapshot
	m.mu.RLock()
	total := len(m.programs)
	progs := make([]*EbpfProgram, 0, total)
	names := make([]string, 0, total)

	for name, prog := range m.programs {
		progs = append(progs, prog)
		names = append(names, name)
	}
	m.mu.RUnlock()

	if total == 0 {
		return []IfaceStats{}
	}

	resultChan := make(chan IfaceStats, total)
	wg := &sync.WaitGroup{}

	for i, prog := range progs {
		wg.Add(1)

		go func(p *EbpfProgram, name string) {
			defer wg.Done()

			trafficStats, err := p.GetStats()
			if err != nil {
				slog.Warn("get traffic stat failed", "ifaceName", name, "error", err)
			}

			resultChan <- IfaceStats{IfaceName: name, Stat: trafficStats}
		}(prog, names[i])
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	ifaceStats := make([]IfaceStats, 0, total)
	for res := range resultChan {
		ifaceStats = append(ifaceStats, res)
	}

	return ifaceStats
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

func (m *EbpfManager) Reload(ifaceName string, rateLimit spec.RateLimitSpec) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	slog.Info("Reloading rate limits...", "ifaceName", ifaceName)

	prog, exists := m.programs[ifaceName]

	if !exists {
		return fmt.Errorf("interface %s not managed", ifaceName)
	}

	err := prog.UpdateRateLimit(rateLimit.RateBytes, rateLimit.BurstBytes)
	if err != nil {
		slog.Error("Failed to reload rule", "iface", ifaceName, "error", err)
	} else {
		slog.Debug("Successfully reloaded rule", "iface", ifaceName)
	}

	return nil
}
