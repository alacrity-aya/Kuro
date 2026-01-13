package traffic

import (
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
