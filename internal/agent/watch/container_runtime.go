package watch

import (
	"context"
	"fmt"
	"runtime"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/vishvananda/netlink"
	nt "github.com/vishvananda/netns"
)

type ContainerRuntime struct {
	client *containerd.Client
}

func NewContainerRuntime(socketPath string) (*ContainerRuntime, error) {
	client, err := containerd.New(socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to containerd: %w", err)
	}

	return &ContainerRuntime{client: client}, nil
}

func (c *ContainerRuntime) CleanUp() error {
	if c.client == nil {
		return nil
	}

	err := c.client.Close()
	if err != nil {
		return err
	}
	return nil
}

func (c *ContainerRuntime) GetNsByContainerID(ctx context.Context, containerID string) (nt.NsHandle, error) {
	ctx = namespaces.WithNamespace(ctx, "k8s.io")

	container, err := c.client.LoadContainer(ctx, containerID)
	if err != nil {
		return 0, fmt.Errorf("failed to load container %s: %w", containerID, err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to get task for container %s: %w", containerID, err)
	}

	pid := task.Pid()
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d for container %s", pid, containerID)
	}

	nsHandler, err := nt.GetFromPid(int(pid))
	if err != nil {
		return -1, fmt.Errorf("failed to get netns handler from pid %d: %w", pid, err)
	}

	return nsHandler, nil
}

func (c *ContainerRuntime) GetHostVethPair(podNsHandle nt.NsHandle) (string, int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNs, err := nt.Get()
	if err != nil {
		return "", 0, fmt.Errorf("failed to get host netns: %w", err)
	}
	defer hostNs.Close()

	defer func() {
		if err = nt.Set(hostNs); err != nil {
			fmt.Printf("CRITICAL: Failed to restore host netns: %v\n", err)
		}
	}()

	if err = nt.Set(podNsHandle); err != nil {
		return "", 0, fmt.Errorf("failed to enter pod netns: %w", err)
	}

	link, err := netlink.LinkByName("eth0")
	if err != nil {
		return "", 0, fmt.Errorf("failed to find eth0 in pod netns: %w", err)
	}

	peerIndex := link.Attrs().ParentIndex
	if peerIndex <= 0 {
		return "", 0, fmt.Errorf("invalid peer index for eth0")
	}

	if err = nt.Set(hostNs); err != nil {
		return "", 0, fmt.Errorf("failed to switch back to host netns: %w", err)
	}

	hostLink, err := netlink.LinkByIndex(peerIndex)
	if err != nil {
		return "", 0, fmt.Errorf("failed to find host link with index %d: %w", peerIndex, err)
	}

	return hostLink.Attrs().Name, peerIndex, nil
}
