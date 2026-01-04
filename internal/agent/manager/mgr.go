// Package manager is used to manage ebpf programs.
package manager

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/alacrity-aya/Kuro/internal/spec"
)

type BpfManager struct {
	mu sync.RWMutex
	// ifaceIndex -> *TcProgram
	programs map[int]*BpfProgram
}

func NewBpfManager() *BpfManager {
	return &BpfManager{
		programs: make(map[int]*BpfProgram),
	}
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

// Apply is used to apply rules. If program not exists, initialize it
func (m *BpfManager) Apply(specs ...spec.Spec) error {
	slog.Debug("BpfManager Apply", "specs_count", len(specs))

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
			errs = append(errs, fmt.Errorf("failed to apply rule for ifIndex %d: %w", sp.IfaceIndex, err))
		}
	}

	if len(errs) != 0 {
		return fmt.Errorf("Apply tc rule failed, errors: %v", errs)
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
