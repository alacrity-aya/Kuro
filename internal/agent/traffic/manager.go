package traffic

import (
	"fmt"
	"log/slog"
	"sync"
)

type BpfManager struct {
	mu       sync.RWMutex
	programs map[int]*BpfProgram
}

func NewBpfManager() *BpfManager {
	return &BpfManager{
		programs: make(map[int]*BpfProgram),
	}
}

func (m *BpfManager) Apply(specs ...Spec) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for _, sp := range specs {
		prog, exists := m.programs[sp.IfaceIndex]
		if !exists {
			slog.Info("Initializing new BpfProgram", "pod", sp.PodName, "ifIndex", sp.IfaceIndex)
			prog = &BpfProgram{
				podName:    sp.PodName,
				ifaceIndex: uint32(sp.IfaceIndex),
			}
			m.programs[sp.IfaceIndex] = prog
		}

		if err := prog.apply(sp); err != nil {
			errs = append(errs, fmt.Errorf("pod %s (idx %d): %w", sp.PodName, sp.IfaceIndex, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

func (m *BpfManager) CollectStats() []TrafficStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var stats []TrafficStats

	for _, prog := range m.programs {
		stats = append(stats, prog.getStats())
	}

	return stats
}

func (m *BpfManager) CleanUp(ifaceIndex ...int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error

	for _, index := range ifaceIndex {
		prog, exists := m.programs[index]
		if !exists {
			continue
		}

		slog.Info("Cleaning up BpfProgram", "ifIndex", index)
		if err := prog.cleanUp(); err != nil {
			errs = append(errs, err)
		}
		delete(m.programs, index)
	}

	if len(errs) != 0 {
		return fmt.Errorf("CleanUp tc rule failed, errors: %v", errs)
	}
	return nil
}

func (m *BpfManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	slog.Info("Shutting down BpfManager, cleaning up all rules...")

	var errs []error
	for ifIndex, prog := range m.programs {
		if err := prog.cleanUp(); err != nil {
			slog.Error("Failed to clean up program", "ifIndex", ifIndex, "err", err)
			errs = append(errs, err)
		}
		delete(m.programs, ifIndex)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during manager shutdown: %v", errs)
	}
	return nil
}
