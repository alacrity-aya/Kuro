// Package netem is used to apply tc netem
package netem

import (
	"fmt"
	"log/slog"
	"math"
	"runtime"

	"kuro/spec"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type NetemManager struct {
	specs []spec.NetemSpec
}

// NewNetemManager creates a new manager with the provided specs.
func NewNetemManager(specs []spec.NetemSpec) *NetemManager {
	return &NetemManager{
		specs: specs,
	}
}

func (m *NetemManager) Apply() error {
	for _, s := range m.specs {
		if err := applySingle(s); err != nil {
			return fmt.Errorf("interface %s in ns %s: %w", s.IfaceName, s.NsName, err)
		}
	}
	slog.Info("All netem rules applied successfully", "count", len(m.specs))
	return nil
}

func applySingle(spec spec.NetemSpec) error {
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

// Inspect queries the current qdisc information from the OS and prints it.
func (m *NetemManager) Inspect() {
	fmt.Println("--- Netem Runtime Inspection ---")

	for _, s := range m.specs {
		info, err := m.getLiveQdiscInfo(s)
		if err != nil {
			slog.Error("Failed to inspect interface", "ns", s.NsName, "iface", s.IfaceName, "error", err)
			continue
		}
		fmt.Printf("[NS: %s | Iface: %s] %s\n", s.NsName, s.IfaceName, info)
	}
}

func (m *NetemManager) getLiveQdiscInfo(s spec.NetemSpec) (string, error) {
	originNs, _ := netns.Get()
	defer originNs.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer netns.Set(originNs)

	targetNs, err := netns.GetFromName(s.NsName)
	if err != nil {
		return "", err
	}
	defer targetNs.Close()

	netns.Set(targetNs)

	link, err := netlink.LinkByName(s.IfaceName)
	if err != nil {
		return "", err
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return "", err
	}

	for _, q := range qdiscs {
		if q.Type() == "netem" {
			// Type assertion to get specific netem details if needed
			if n, ok := q.(*netlink.Netem); ok {
				return fmt.Sprintf("Type: netem, Latency: %v, Loss: %v, Limit: %d",
					n.Latency, n.Loss, n.Limit), nil
			}
		}
	}
	return "No netem qdisc found", nil
}
