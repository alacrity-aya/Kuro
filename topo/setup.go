// Package topo implements the network topology and node management for the kuro simulation.
package topo

import (
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"

	"kuro/config"
	"kuro/utils"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type RuntimeNode struct {
	Name string
	Ip   string
}

type Vxlan struct {
	ID     int
	Iface  string
	Port   int
	Remote string
}

type RuntimeTopo struct {
	Nodes  []RuntimeNode
	Vxlan  *Vxlan
	origns netns.NsHandle // host netns

	// track network resource
	createdNs    []string
	createdLinks []string // Host side link names (veths, vxlan)
}

func NewRuntimeTopo(cfg config.HostConfig) *RuntimeTopo {
	var vxlan *Vxlan = nil
	if cfg.Vxlan != nil {
		vxlan = &Vxlan{
			ID:     cfg.Vxlan.ID,
			Iface:  cfg.Vxlan.Iface,
			Port:   cfg.Vxlan.Port,
			Remote: cfg.Vxlan.Remote,
		}
	}

	var nodes []RuntimeNode

	for _, node := range cfg.Nodes {
		node := RuntimeNode{Name: node.Name, Ip: node.IP}
		nodes = append(nodes, node)
	}

	topo := &RuntimeTopo{
		Vxlan:        vxlan,
		Nodes:        nodes,
		createdNs:    make([]string, 0),
		createdLinks: make([]string, 0),
	}

	slog.Debug("ConvertToRuntimeTopo", "runtime topology", topo)
	return topo
}

func (topo *RuntimeTopo) initOrigNs() error {
	origns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current netns handle, error: %v", err)
	}
	topo.origns = origns
	return nil
}

func (topo *RuntimeTopo) Setup() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := topo.initOrigNs(); err != nil {
		return err
	}

	for _, node := range topo.Nodes {
		if err := topo.createNodeNetwork(node); err != nil {
			return fmt.Errorf("failed to setup node %s: %w", node.Name, err)
		}
	}

	if err := topo.createVxlan(); err != nil {
		return fmt.Errorf("failed to setup vxlan: %w", err)
	}

	return nil
}

// create netns, veth Pair and config ip addr for each node
func (topo *RuntimeTopo) createNodeNetwork(node RuntimeNode) error {
	nsName := utils.NetnsName(node.Name)
	hostEth := utils.EthName(node.Name)
	peerEth := utils.PeerEthName(node.Name)

	slog.Info("Setting up node", "node", node.Name, "ns", nsName, "ip", node.Ip)

	// A. 创建 Netns
	// NewNamed 会自动创建一个新的命名空间并在 /var/run/netns/ 下挂载
	// 注意：这会自动将当前线程切换到新的 netns，所以我们需要切回来
	newNs, err := netns.NewNamed(nsName)
	if err != nil {
		return fmt.Errorf("failed to create netns %s: %w", nsName, err)
	}
	defer newNs.Close()
	topo.createdNs = append(topo.createdNs, nsName)

	// 恢复到 Host Netns 以创建 veth pair
	if err := netns.Set(topo.origns); err != nil {
		return fmt.Errorf("failed to set original netns: %w", err)
	}

	// B. 创建 Veth Pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostEth,
		},
		PeerName: peerEth,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair %s <-> %s: %w", hostEth, peerEth, err)
	}
	topo.createdLinks = append(topo.createdLinks, hostEth)

	// C. 将 Peer 端移动到新的 Netns
	peerLink, err := netlink.LinkByName(peerEth)
	if err != nil {
		return fmt.Errorf("failed to find peer link %s: %w", peerEth, err)
	}

	if err := netlink.LinkSetNsFd(peerLink, int(newNs)); err != nil {
		return fmt.Errorf("failed to move peer link to ns: %w", err)
	}

	// D. 启动 Host 端 Veth
	hostLink, err := netlink.LinkByName(hostEth)
	if err != nil {
		return fmt.Errorf("failed to find host link %s: %w", hostEth, err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("failed to set host link up: %w", err)
	}

	// E. 进入新的 Netns 配置 IP 和 Lo
	if err := netns.Set(newNs); err != nil {
		return fmt.Errorf("failed to switch to netns %s: %w", nsName, err)
	}

	// E.1 启动 lo (Loopback) - 对网络栈很重要
	loLink, err := netlink.LinkByName("lo")
	if err == nil {
		_ = netlink.LinkSetUp(loLink)
	}

	// E.2 配置 Peer Veth IP
	peerLinkInNs, err := netlink.LinkByName(peerEth)
	if err != nil {
		return fmt.Errorf("failed to find peer link inside ns: %w", err)
	}

	addr, err := netlink.ParseAddr(node.Ip)
	if err != nil {
		return fmt.Errorf("invalid ip address %s: %w", node.Ip, err)
	}

	if err := netlink.AddrAdd(peerLinkInNs, addr); err != nil {
		return fmt.Errorf("failed to add ip %s to interface: %w", node.Ip, err)
	}

	if err := netlink.LinkSetUp(peerLinkInNs); err != nil {
		return fmt.Errorf("failed to set peer link up: %w", err)
	}

	// F. 恢复到 Host Netns
	if err := netns.Set(topo.origns); err != nil {
		return fmt.Errorf("failed to restore original netns: %w", err)
	}

	return nil
}

// createVxlan 创建 VXLAN 接口
func (topo *RuntimeTopo) createVxlan() error {
	if topo.Vxlan == nil {
		slog.Info("No VXLAN config found, skipping VXLAN setup")
		return nil
	}

	if topo.Vxlan.Iface == "" {
		slog.Info("No parent interface specified for VXLAN, skipping or creating standalone")
		// 实际上通常需要物理接口作为 VTEP，这里假设必须存在
		return nil
	}

	parentLink, err := netlink.LinkByName(topo.Vxlan.Iface)
	if err != nil {
		return fmt.Errorf("failed to find parent interface %s for vxlan: %w", topo.Vxlan.Iface, err)
	}

	vxlanName := fmt.Sprintf("vxlan%d", topo.Vxlan.ID)
	slog.Info("Setting up Vxlan", "name", vxlanName, "id", topo.Vxlan.ID, "remote", topo.Vxlan.Remote)

	vxlan := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: vxlanName,
		},
		VxlanId:      topo.Vxlan.ID,
		VtepDevIndex: parentLink.Attrs().Index,
		Port:         topo.Vxlan.Port,
	}

	// 如果配置了 Remote IP，通常设置为 Group (组播) 或直接 Remote (如果是单播)
	// 这里简单处理：如果 Remote 是有效 IP，将其设为 Group 以支持简单的点对点或组播发现
	if topo.Vxlan.Remote != "" {
		ip := net.ParseIP(topo.Vxlan.Remote)
		if ip != nil {
			vxlan.Group = ip
		}
	}

	if err := netlink.LinkAdd(vxlan); err != nil {
		return fmt.Errorf("failed to create vxlan interface: %w", err)
	}
	topo.createdLinks = append(topo.createdLinks, vxlanName)

	// 启动接口
	vxlanLink, err := netlink.LinkByName(vxlanName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(vxlanLink); err != nil {
		return err
	}

	return nil
}

// TearDown 清理所有创建的资源
func (topo *RuntimeTopo) TearDown() {
	slog.Info("Tearing down topology...")

	// 1. 删除 VXLAN 接口 (Link)
	// 注意：我们在 createdLinks 里记录了所有的 Host 侧接口
	// 删除 Netns 时，Veth 的 Host 端会自动删除，所以这里主要为了删除 VXLAN
	// 为了安全起见，尝试删除记录的所有 link，忽略 "not found" 错误
	for _, linkName := range topo.createdLinks {
		if strings.HasPrefix(linkName, "v-") {
			// Veth pair 的 host 端通常随 netns 删除而消失，
			// 但如果 netns 删除失败，这里可以作为兜底
			if link, err := netlink.LinkByName(linkName); err == nil {
				_ = netlink.LinkDel(link)
			}
		} else {
			// VXLAN 等其他接口
			if link, err := netlink.LinkByName(linkName); err == nil {
				slog.Info("Deleting interface", "name", linkName)
				if err := netlink.LinkDel(link); err != nil {
					slog.Warn("Failed to delete link", "name", linkName, "error", err)
				}
			}
		}
	}

	// 2. 删除 Netns
	// 这会自动清理 namespace 里面的所有接口
	for _, nsName := range topo.createdNs {
		slog.Info("Deleting netns", "name", nsName)
		if err := netns.DeleteNamed(nsName); err != nil {
			slog.Warn("Failed to delete netns", "name", nsName, "error", err)
		}
	}

	// 清空列表
	topo.createdNs = nil
	topo.createdLinks = nil

	// 关闭 host 句柄
	if topo.origns.IsOpen() {
		topo.origns.Close()
	}
}

// PrintTopology 打印当前创建的网络拓扑结构
func (topo *RuntimeTopo) PrintTopology() {
	fmt.Println("====== Network Topology ======")

	// 打印 VXLAN 信息

	if topo.Vxlan != nil {
		vxlanName := fmt.Sprintf("vxlan%d", topo.Vxlan.ID)
		fmt.Printf("[Host] --- (vxlan: %s, VNI: %d, Remote: %s) ---> External\n",
			vxlanName, topo.Vxlan.ID, topo.Vxlan.Remote)
	}

	// 打印节点信息
	for _, node := range topo.Nodes {
		hostEth := utils.EthName(node.Name)
		peerEth := utils.PeerEthName(node.Name)
		nsName := utils.NetnsName(node.Name)

		fmt.Printf("[Host] %s <===> [Netns: %s] %s (IP: %s)\n",
			hostEth, nsName, peerEth, node.Ip)
	}
	fmt.Println("==============================")
}
