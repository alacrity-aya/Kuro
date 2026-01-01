// Package manager is used to manage ebpf programs.
package manager

type BpfManager struct {
	programs map[int]*TcProgram
}

func NewBpfManager() *BpfManager {
	return &BpfManager{
		programs: make(map[int]*TcProgram),
	}
}

func (b *BpfManager) CleanUp(ifaceIndex int) error {
	return nil
}

// Attach is used to update or load traffic control rule
func (b *BpfManager) Attach(ifaceIndex int) error {
	return nil
}
