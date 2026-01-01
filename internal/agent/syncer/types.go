package syncer

import (
	"github.com/alacrity-aya/Kuro/internal/spec"
	"github.com/vishvananda/netns"
)

type TaskExecutor interface {
	GetPodMetadata(podName string) (ifIndex int, handle netns.NsHandle, exists bool)
	GetPodNameByIface(ifaceName string) (string, bool)
	ApplyRules(specs []spec.Spec) error
	// CollectAllStats() []loader.IfaceStats
}
