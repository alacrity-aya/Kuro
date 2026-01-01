// Package manager is used to manage ebpf programs.
package manager

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/alacrity-aya/Kuro/internal/spec"
)

type BpfManager struct {
	// ifaceIndex -> *TcProgram
	programs map[int]*BpfProgram
}

func NewBpfManager() *BpfManager {
	return &BpfManager{
		programs: make(map[int]*BpfProgram),
	}
}

func (m *BpfManager) CleanUp(ifaceIndex ...int) error {
	var errs []error

	for _, index := range ifaceIndex {
		err := m.programs[index].cleanUp()
		errs = append(errs, err)
	}

	if len(errs) != 0 {
		return fmt.Errorf("CleanUp tc rule failed, errors: %v", errs)
	}
	return nil
}

// Apply is used to update or load traffic control rule
func (m *BpfManager) Apply(specs ...spec.Spec) error {
	slog.Debug("BpfManager Apply", "specs", specs)

	var errs []error

	for _, spec := range specs {
		prog := m.programs[spec.IfaceIndex]
		err := prog.apply(spec)
		errs = append(errs, err)
	}

	if len(errs) != 0 {
		return fmt.Errorf("Apply tc rule failed, errors: %v", errs)
	}
	return nil
}

func (m *BpfManager) CollectStats() []TrafficStats {
	wg := &sync.WaitGroup{}

	total := len(m.programs)
	resultChan := make(chan TrafficStats, total)

	for _, prog := range m.programs {
		wg.Add(1)

		go func(p *BpfProgram) {
			defer wg.Done()
			resultChan <- p.getStats()
		}(prog)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	trafficStats := make([]TrafficStats, 0, total)
	for res := range resultChan {
		trafficStats = append(trafficStats, res)
	}

	return trafficStats
}
