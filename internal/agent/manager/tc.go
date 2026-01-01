package manager

import (
	"github.com/alacrity-aya/Kuro/internal/ebpf"
	"github.com/cilium/ebpf/link"
)

type TcProgram struct {
	links []link.Link
	objs  *ebpf.TcObjects

	loaded bool

	ifaceIndex uint32
}
