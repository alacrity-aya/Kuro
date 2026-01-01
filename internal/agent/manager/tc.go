package manager

import (
	"fmt"

	"github.com/alacrity-aya/Kuro/internal/ebpf"
	"github.com/alacrity-aya/Kuro/internal/spec"
	"github.com/cilium/ebpf/link"
)

type BpfProgram struct {
	podName string

	links []link.Link
	objs  *ebpf.TcObjects

	loaded bool

	ifaceIndex uint32
}

func (p *BpfProgram) apply(spec spec.Spec) error {
	return fmt.Errorf("not implemented")
}

func (p *BpfProgram) cleanUp() error {
	return fmt.Errorf("not implemented")
}

func (p *BpfProgram) getStats() TrafficStats {
	return TrafficStats{}
}
