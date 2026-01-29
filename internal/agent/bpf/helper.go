package bpf

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
)

// ================= Helpers =================

// ensureFQ checks and sets the fq qdisc on the given interface index.
// This function operates in the CURRENT namespace context.
func (m *BpfManager) ensureFQ(ifaceIndex int, packetLimit uint32) error {
	linkObj, err := netlink.LinkByIndex(ifaceIndex)
	if err != nil {
		return fmt.Errorf("get link: %w", err)
	}

	qdiscs, err := netlink.QdiscList(linkObj)
	if err != nil {
		return fmt.Errorf("list qdiscs: %w", err)
	}

	// Check existing root qdisc
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_ROOT {
			if q.Type() == "fq" {
				return nil // Already fq
			}
			// Delete non-fq qdisc
			if err := netlink.QdiscDel(q); err != nil {
				// Check for "file not exist" in case it was auto-removed
				if !os.IsNotExist(err) && !strings.Contains(err.Error(), "no such file") {
					return fmt.Errorf("del qdisc: %w", err)
				}
			}
			break
		}
	}

	const safeLimit = 20000

	// Add fq qdisc
	fq := netlink.NewFq(netlink.QdiscAttrs{
		LinkIndex: linkObj.Attrs().Index,
		Parent:    netlink.HANDLE_ROOT,
		Handle:    netlink.MakeHandle(1, 0),
	})
	fq.Pacing = 1 // Crucial for EDT

	fq.PacketLimit = safeLimit // TODO: In fact this is not safe
	if packetLimit != 0 {
		fq.PacketLimit = packetLimit
	}
	fq.FlowMaxRate = math.MaxUint32

	if err := netlink.QdiscAdd(fq); err != nil {
		return fmt.Errorf("add fq: %w", err)
	}
	return nil
}

// ipToUint32 converts an IP string to a uint32 that, when stored in memory
// on a Little Endian machine, matches the Network Byte Order layout.
func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid ip format: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an ipv4 address: %s", ipStr)
	}

	return binary.LittleEndian.Uint32(ipv4), nil
}

// uint32ToIP converts the raw map key back to net.IP
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

// getInterfaceSpeed return Mbps
func getInterfaceSpeed(ifaceName string) (uint64, error) {
	path := fmt.Sprintf("/sys/class/net/%s/speed", ifaceName)
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	speedStr := strings.TrimSpace(string(content))
	speedMbps, err := strconv.ParseUint(speedStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse speed: %w", err)
	}

	return speedMbps, nil
}

func bpsToScaledCost(bps uint64) uint64 {
	if bps == 0 {
		return 0
	}
	return uint64((float64(8*NsecPerSec) * float64(ScaleFactor)) / float64(bps))
}
