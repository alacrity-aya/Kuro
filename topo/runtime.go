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

type Vxlan struct {
	ID     int
	Iface  string
	Port   int
	Remote string
}

type RuntimeTopo struct {
	Nodes  []RuntimeNode
	Vxlan  *Vxlan
	origns netns.NsHandle // original host network namespace

	// Track resources created during setup
	createdNs    []string
	createdLinks []string // host-side links (veths, vxlan)
}

func buildRuntimeNode(cfg config.NodeConfig) RuntimeNode {
	base := baseNode{name: cfg.Name, ip: cfg.IP, nodeType: cfg.Type}
	switch cfg.Type {

	case "container":
		return &ContainerNode{baseNode: base, image: cfg.Image, container: cfg.Container}
	case "exec":
		return &ExecNode{baseNode: base, exec: cfg.Exec, args: cfg.Args, cwd: cfg.Cwd, cmd: nil, pid: -1}

	default:
		panic(fmt.Sprintf("should be unreachable! cfg.Type: %s", cfg.Type))
	}
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

	nodes := make([]RuntimeNode, 0, len(cfg.Nodes))

	for _, node := range cfg.Nodes {
		nodes = append(nodes, buildRuntimeNode(node))
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

func (topo *RuntimeTopo) GetRuntimeNode(name string) RuntimeNode {
	for _, node := range topo.Nodes {
		if name == node.Name() {
			return node
		}
	}
	return nil
}

func (topo *RuntimeTopo) initOrigNs() error {
	// Save the current host network namespace handle
	origns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get current netns handle: %v", err)
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
		if err := topo.setupNodeNetwork(node); err != nil {
			return fmt.Errorf("failed to setup node %s: %w", node.Name(), err)
		}

		// Start node
		if err := node.Run(); err != nil {
			return err
		}
	}

	if err := topo.createVxlan(); err != nil {
		return fmt.Errorf("failed to setup vxlan: %w", err)
	}

	slog.Info("Setup topology completed")

	return nil
}

// setupNodeNetwork creates a netns, veth pair, and configures IP for the node.
func (topo *RuntimeTopo) setupNodeNetwork(node RuntimeNode) error {
	nodeName := node.Name()
	nsName := utils.NetnsName(nodeName)
	hostEth := utils.EthName(nodeName)
	peerEth := utils.PeerEthName(nodeName)

	slog.Info("Setting up node", "node", nodeName, "ns", nsName, "ip", node.IP)

	// add network devices

	// A. Create a new named network namespace.
	// netns.NewNamed automatically switches the current thread into the new ns.
	newNs, err := netns.NewNamed(nsName)
	if err != nil {
		return fmt.Errorf("failed to create netns %s: %w", nsName, err)
	}
	defer newNs.Close()
	topo.createdNs = append(topo.createdNs, nsName)

	// Switch back to the host ns before creating the veth pair.
	if err = netns.Set(topo.origns); err != nil {
		return fmt.Errorf("failed to set original netns: %w", err)
	}

	// B. Create a veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostEth,
		},
		PeerName: peerEth,
	}

	if err = netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair %s <-> %s: %w", hostEth, peerEth, err)
	}
	topo.createdLinks = append(topo.createdLinks, hostEth)

	// C. Move the peer veth into the new netns.
	peerLink, err := netlink.LinkByName(peerEth)
	if err != nil {
		return fmt.Errorf("failed to find peer link %s: %w", peerEth, err)
	}

	if err = netlink.LinkSetNsFd(peerLink, int(newNs)); err != nil {
		return fmt.Errorf("failed to move peer link to ns: %w", err)
	}

	// D. Bring up host-side veth.
	hostLink, err := netlink.LinkByName(hostEth)
	if err != nil {
		return fmt.Errorf("failed to find host link %s: %w", hostEth, err)
	}
	if err = netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("failed to set host link up: %w", err)
	}

	// E. Enter the node namespace to configure IP and loopback.
	if err = netns.Set(newNs); err != nil {
		return fmt.Errorf("failed to switch to netns %s: %w", nsName, err)
	}

	// E.1 Bring up loopback interface.
	loLink, err := netlink.LinkByName("lo")
	if err == nil {
		_ = netlink.LinkSetUp(loLink)
	}

	// E.2 Configure peer veth IP inside the namespace.
	peerLinkInNs, err := netlink.LinkByName(peerEth)
	if err != nil {
		return fmt.Errorf("failed to find peer link inside ns: %w", err)
	}

	addr, err := netlink.ParseAddr(node.IP())
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", node.IP(), err)
	}

	if err = netlink.AddrAdd(peerLinkInNs, addr); err != nil {
		return fmt.Errorf("failed to add IP %s to interface: %w", node.IP(), err)
	}

	if err = netlink.LinkSetUp(peerLinkInNs); err != nil {
		return fmt.Errorf("failed to set peer link up: %w", err)
	}

	if err := netns.Set(topo.origns); err != nil {
		return fmt.Errorf("failed to restore original netns: %w", err)
	}

	return nil
}

// createVxlan creates the VXLAN interface on the host.
func (topo *RuntimeTopo) createVxlan() error {
	if topo.Vxlan == nil {
		slog.Info("No VXLAN config found, skipping setup")
		return nil
	}

	if topo.Vxlan.Iface == "" {
		slog.Error("No parent interface specified for VXLAN; skipping")
		return nil
	}

	parentLink, err := netlink.LinkByName(topo.Vxlan.Iface)
	if err != nil {
		return fmt.Errorf("failed to find parent interface %s: %w", topo.Vxlan.Iface, err)
	}

	vxlanName := fmt.Sprintf("vxlan%d", topo.Vxlan.ID)
	slog.Info("Setting up VXLAN", "name", vxlanName, "id", topo.Vxlan.ID, "remote", topo.Vxlan.Remote)

	vx := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: vxlanName,
		},
		VxlanId:      topo.Vxlan.ID,
		VtepDevIndex: parentLink.Attrs().Index,
		Port:         topo.Vxlan.Port,
	}

	// If Remote is set, treat it as the group/multicast/remote endpoint.
	if topo.Vxlan.Remote != "" {
		ip := net.ParseIP(topo.Vxlan.Remote)
		if ip != nil {
			vx.Group = ip
		}
	}

	err = netlink.LinkAdd(vx)
	if err != nil {
		return fmt.Errorf("failed to create vxlan interface: %w", err)
	}
	topo.createdLinks = append(topo.createdLinks, vxlanName)

	vxlanLink, err := netlink.LinkByName(vxlanName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(vxlanLink); err != nil {
		return err
	}

	return nil
}

// TearDown removes all created resources.
func (topo *RuntimeTopo) TearDown() {
	slog.Info("Tearing down topology...")

	for _, node := range topo.Nodes {
		if err := node.Stop(); err != nil {
			slog.Warn("Failed to stop node", "error", err)
		}
	}

	// Remove all created interfaces.
	for _, linkName := range topo.createdLinks {
		if strings.HasPrefix(linkName, "v-") {
			// veth host side normally disappears with namespace deletion,
			// but delete here as fallback.
			if link, err := netlink.LinkByName(linkName); err == nil {
				_ = netlink.LinkDel(link)
			}
		} else {
			if link, err := netlink.LinkByName(linkName); err == nil {
				slog.Info("Deleting interface", "name", linkName)
				_ = netlink.LinkDel(link)
			}
		}
	}

	// Remove namespaces (removes node-side interfaces automatically).
	for _, ns := range topo.createdNs {
		slog.Info("Deleting netns", "name", ns)
		_ = netns.DeleteNamed(ns)
	}

	topo.createdNs = nil
	topo.createdLinks = nil

	if topo.origns.IsOpen() {
		topo.origns.Close()
	}
}

func (topo *RuntimeTopo) PrintTopology() {
	fmt.Println("====== Network Topology ======")

	if topo.Vxlan != nil {
		vxlanName := fmt.Sprintf("vxlan%d", topo.Vxlan.ID)
		fmt.Printf("[Host] --- (VXLAN: %s, VNI: %d, Remote: %s) ---> External\n",
			vxlanName, topo.Vxlan.ID, topo.Vxlan.Remote)
	}

	for _, node := range topo.Nodes {

		hostEth := utils.EthName(node.Name())
		peerEth := utils.PeerEthName(node.Name())
		nsName := utils.NetnsName(node.Name())

		fmt.Printf("[Host] %s <===> [Netns: %s] %s (IP: %s)\n",
			hostEth, nsName, peerEth, node.IP())
	}

	fmt.Println("==============================")
}
