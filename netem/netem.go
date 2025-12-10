// Package netem is used to apply tc netem
package netem

import (
	"fmt"
	"log/slog"
	"math"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type NetemSpec struct {
	NsName      string
	IfaceName   string
	LatencyMs   float64
	JitterMs    float64
	LossPercent float64
	Limit       uint32
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

	if _, err = netlink.LinkList(); err != nil {
		slog.Warn("failed to warm up netlink clock", "error", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer netns.Set(originNs)

	targetNsHandle, err := netns.GetFromName(spec.NsName)
	slog.Debug("GetFromName", "namespace", spec.NsName)
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

	// --- Remove any existing root qdisc (netem or other) ---
	cleanup := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
	}
	_ = netlink.QdiscDel(cleanup)

	qdisc := &netlink.Netem{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		// NOTE: https://github.com/vishvananda/netlink/issues/480
		Latency: uint32(spec.LatencyMs * 1_000 * netlink.TickInUsec()), // ms → us
		Jitter:  uint32(spec.JitterMs * 1_000 * netlink.TickInUsec()),  // ms → us
		Limit:   spec.Limit,
		Loss:    uint32(spec.LossPercent * float64(math.MaxUint32)),
	}

	// there is no need to clear this qdisc, because we'll delete all netns in topo.teardown()
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("failed to add netem qdisc: %v", err)
	}

	return nil
}
