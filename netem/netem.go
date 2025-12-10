// Package netem is used to apply tc netem
package netem

import (
	"fmt"
	"log/slog"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type NetemSpec struct {
	NsName      string
	IfaceName   string
	LatencyMs   uint32
	JitterMs    uint32
	LossPercent float64
}

func SetNetems(specs ...NetemSpec) error {
	for _, spec := range specs {
		if err := setNetem(spec); err != nil {
			return fmt.Errorf("IfaceName %s: %v", spec.IfaceName, err)
		}
	}

	slog.Info("set netem rules completed")

	return nil
}

func setNetem(spec NetemSpec) error {
	originNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current ns: %v", err)
	}
	defer originNs.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer netns.Set(originNs)

	targetNsHandle, err := netns.GetFromName(spec.NsName)
	if err != nil {
		return fmt.Errorf("failed to get netns %s: %v", spec.NsName, err)
	}
	defer targetNsHandle.Close()

	if err = netns.Set(targetNsHandle); err != nil {
		return fmt.Errorf("failed to enter netns: %v", err)
	}

	link, err := netlink.LinkByName(spec.IfaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found in ns %s: %v",
			spec.IfaceName, spec.NsName, err)
	}

	qdisc := &netlink.Netem{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		Latency: spec.LatencyMs * 1000,
		Jitter:  spec.JitterMs * 1000,
		Loss:    uint32(spec.LossPercent * 100),
	}

	// ensure idempotent behavior
	_ = netlink.QdiscDel(qdisc)

	// there is no need to clear this qdisc, because we'll delete all netns in topo.teardown()
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("failed to add netem qdisc: %v", err)
	}

	return nil
}
