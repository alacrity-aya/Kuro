package traffic

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
)

// ResolvePodInterface find iface index according to pod ip
func ResolvePodInterface(podIP string) (int, string, error) {
	ip := net.ParseIP(podIP)
	if ip == nil {
		return 0, "", fmt.Errorf("invalid pod ip: %s", podIP)
	}

	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return 0, "", fmt.Errorf("failed to get route for pod ip %s: %w", podIP, err)
	}

	if len(routes) == 0 {
		return 0, "", fmt.Errorf("no route found for pod ip %s", podIP)
	}

	linkIndex := routes[0].LinkIndex
	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return 0, "", fmt.Errorf("failed to get link by index %d: %w", linkIndex, err)
	}

	if link.Type() != "veth" {
		// NOTE: For overlay networks (VXLAN), this might be flannel.1 or cni0
		// For Kind environments, it's usually veth
		// We can add a log warning, but not force an error, because bridge mode also supports TC
		slog.Warn("Pod interface is not veth", "type", link.Type(), "name", link.Attrs().Name)
	}

	return linkIndex, link.Attrs().Name, nil
}

func PortToUint16(port uint32) uint16 {
	//  BUG: maybe endian issue here
	return uint16((port >> 8) | (port << 8))
}

func ProtoToUint8(p string) uint8 {
	switch p {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	default:
		return 0
	}
}

func IPToUint32(ipStr string) (uint32, error) {
	//  BUG: maybe endian issue here
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid ip")
	}
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not ipv4")
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func Uint32ToIP(n uint32) string {
	if n == 0 {
		return "0.0.0.0" // Default Rule
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip.String()
}
