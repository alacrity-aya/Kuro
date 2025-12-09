// Package netem is used to apply tc netem
package netem

import (
	"fmt"
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

func SetNetemConfig(nsName string, ifaceName string, latencyMs uint32, jitterMs uint32, lossPercent float32) error {
	originNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current ns: %v", err)
	}
	defer originNs.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer netns.Set(originNs)

	targetNsHandle, err := netns.GetFromName(nsName)
	if err != nil {
		return fmt.Errorf("failed to get netns %s: %v", nsName, err)
	}
	defer targetNsHandle.Close()

	err = netns.Set(targetNsHandle)
	if err != nil {
		return fmt.Errorf("failed to enter netns: %v", err)
	}

	// --- Now we are in other netns  ---

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found in ns %s: %v", ifaceName, nsName, err)
	}

	// tc qdisc add dev eth0 root netem delay 100ms 10ms loss 1%
	qdisc := &netlink.Netem{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		Latency: latencyMs * 1000,
		Jitter:  jitterMs * 1000,
		Limit:   1000,
	}

	_ = netlink.QdiscDel(qdisc)

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("failed to add netem qdisc: %v", err)
	}

	return nil
}
