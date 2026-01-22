package netns

import (
	"context"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
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
