// Package topo implements the network topology and node management for the kuro simulation.
package topo

import (
	"fmt"
	"log/slog"
	"net"
	"runtime"

	"kuro/spec"
	"kuro/utils"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type RuntimeTopo struct {
	Nodes  []RuntimeNode
	Vxlan  *spec.Vxlan
	origns netns.NsHandle // original host network namespace

	// Track resources created during setup
	createdNs    []string
	createdLinks []string // host-side links (veths, vxlan)
}

func buildRuntimeNode(node spec.TopoNode) RuntimeNode {
	base := baseNode{name: node.Name, ip: node.IP, nodeType: node.Type}
	switch node.Type {
	case "container":
		slog.Error("container is still todo")
		return &ContainerNode{baseNode: base, image: node.Image, container: node.Container}
	case "exec":
		return &ExecNode{baseNode: base, exec: node.Exec, args: node.Args, cwd: node.Cwd, cmd: nil, pid: -1}

	default:
		panic(fmt.Sprintf("should be unreachable! cfg.Type: %s", node.Type))
	}
}

func NewRuntimeTopo(topoSpec spec.TopoSpec) *RuntimeTopo {
	var topo RuntimeTopo
	topo.Vxlan = topoSpec.Vxlan

	for _, node := range topoSpec.Nodes {
		topo.Nodes = append(topo.Nodes, buildRuntimeNode(node))
	}

	topo.createdLinks = make([]string, 0)
	topo.createdNs = make([]string, 0)

	slog.Debug("ConvertToRuntimeTopo", "runtime topology", topo)
	return &topo
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

// Setup It's no need to use goroutin in this function because of runtime.LockOSThread
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
			MTU:  parentLink.Attrs().MTU - 50, // UDP + VXLAN + Outer IP + Ethernet = 50
		},
		VxlanId:      int(topo.Vxlan.ID),
		VtepDevIndex: parentLink.Attrs().Index,
		Port:         int(topo.Vxlan.Port),
		Learning:     true,
	}

	ip := net.ParseIP(topo.Vxlan.Remote)

	if ip == nil || !ip.IsMulticast() {
		return fmt.Errorf("ip == nil || !ip.IsMulticast(). ip address shoule be checked in config module")
	}
	vx.Group = ip

	// TODO: add vx.SrcAddr
	vx.SrcAddr = net.ParseIP("10.20.0.1")

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
func (topo *RuntimeTopo) TearDown() error {
	slog.Info("Tearing down topology...")
	var errs []error

	// Stop Nodes
	for _, node := range topo.Nodes {
		if err := node.Stop(); err != nil {
			slog.Warn("Failed to stop node", "error", err)
			errs = append(errs, fmt.Errorf("stop node failed: %w", err))
		}
	}

	// Remove Links
	for _, linkName := range topo.createdLinks {
		if link, err := netlink.LinkByName(linkName); err == nil {
			slog.Info("Deleting interface", "name", linkName)
			if delErr := netlink.LinkDel(link); delErr != nil {
				errs = append(errs, fmt.Errorf("delete link %s failed: %w", linkName, delErr))
			}
		}
	}

	// Remove Namespaces
	for _, ns := range topo.createdNs {
		slog.Info("Deleting netns", "name", ns)
		if delErr := netns.DeleteNamed(ns); delErr != nil {
			errs = append(errs, fmt.Errorf("delete ns %s failed: %w", ns, delErr))
		}
	}

	// Reset state
	topo.createdNs = nil
	topo.createdLinks = nil

	if topo.origns.IsOpen() {
		topo.origns.Close()
	}

	// Return aggregated errors
	if len(errs) > 0 {
		return fmt.Errorf("teardown encountered multiple errors: %v", errs)
	}
	return nil
}

func (topo *RuntimeTopo) InspectTopology(hostName string) {
	fmt.Println("\n--- Network Topology ---")

	if topo.Vxlan != nil {
		vxlanName := fmt.Sprintf("vxlan%d", topo.Vxlan.ID)
		fmt.Printf("[%s] --- (VXLAN: %s, VNI: %d, Remote: %s) ---> External\n",
			hostName, vxlanName, topo.Vxlan.ID, topo.Vxlan.Remote)

		fmt.Println("------------------------------")
	}

	for _, node := range topo.Nodes {

		hostEth := utils.EthName(node.Name())
		peerEth := utils.PeerEthName(node.Name())
		nsName := utils.NetnsName(node.Name())

		fmt.Printf("[%s] %s: %s\n", hostName, node.Name(), node.Info())
		fmt.Printf("[%s] %s <===> [Netns: %s] %s (IP: %s)\n",
			hostName, hostEth, nsName, peerEth, node.IP())

		fmt.Println("------------------------------")

	}

	fmt.Println("==============================")
	fmt.Println()
}
