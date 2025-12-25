package loader

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"kuro/gen"
	"kuro/spec"
	"kuro/utils"

	"github.com/cilium/ebpf"
)

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
