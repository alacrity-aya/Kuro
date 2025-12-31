// Package discovery send pods information to agent
package discovery

// TODO: migrate watcher to informer

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const ContainerIface = "eth0"

type TargetPod struct {
	PodName     string
	ExpID       string
	HostIfIndex int
	NetnsHandle netns.NsHandle
}

type Event struct {
	Type   watch.EventType
	Target TargetPod
}

type PodWatcher struct {
	k8sClient *kubernetes.Clientset
	criClient runtimeapi.RuntimeServiceClient
	criConn   *grpc.ClientConn
	labelKey  string
}

func NewPodWatcher(k *kubernetes.Clientset, criSocketPath string, label string) (*PodWatcher, error) {
	// establish rpc connection
	conn, err := grpc.NewClient(criSocketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CRI socket %s: %w", criSocketPath, err)
	}

	return &PodWatcher{
		k8sClient: k,
		criClient: runtimeapi.NewRuntimeServiceClient(conn),
		criConn:   conn,
		labelKey:  label,
	}, nil
}

func (w *PodWatcher) Close() {
	if w.criConn != nil {
		w.criConn.Close()
	}
}

func (w *PodWatcher) Watch(ctx context.Context) <-chan Event {
	out := make(chan Event)

	go func() {
		defer close(out)
		watcher, _ := w.k8sClient.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{
			LabelSelector: w.labelKey,
		})

		for event := range watcher.ResultChan() {
			pod, ok := event.Object.(*v1.Pod)

			if !ok {
				continue
			}

			// inform agent remove pod
			if event.Type == watch.Deleted {
				out <- Event{
					Type: watch.Deleted,
					Target: TargetPod{
						PodName: pod.Name,
					},
				}
				continue
			}

			// only handle running pod with assigned ip
			if pod.Status.Phase == v1.PodRunning && pod.Status.PodIP != "" {
				go w.probePod(pod, out)
			}
		}
	}()

	return out
}

func (w *PodWatcher) probePod(pod *v1.Pod, out chan<- Event) {
	var cID string
	for _, s := range pod.Status.ContainerStatuses {
		if s.ContainerID != "" && s.State.Running != nil {
			cID = strings.TrimPrefix(s.ContainerID, "containerd://")
			break
		}
	}
	if cID == "" {
		return
	}

	var pid int
	for i := range 5 {
		resp, err := w.criClient.ContainerStatus(context.Background(), &runtimeapi.ContainerStatusRequest{
			ContainerId: cID,
			Verbose:     true,
		})
		if err == nil {
			var info struct {
				Pid int `json:"pid"`
			}
			json.Unmarshal([]byte(resp.Info["info"]), &info)
			pid = info.Pid
			break
		}
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
	}
	if pid == 0 {
		return
	}

	hostIdx, handle, err := w.getNetworkMetadata(pid)
	if err != nil {
		return
	}

	out <- Event{
		Type: watch.Added,
		Target: TargetPod{
			PodName:     pod.Name,
			ExpID:       pod.Labels[w.labelKey],
			HostIfIndex: hostIdx,
			NetnsHandle: handle,
		},
	}
}

func (w *PodWatcher) getNetworkMetadata(pid int) (int, netns.NsHandle, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hNS, _ := netns.Get()
	defer hNS.Close()

	cNS, err := netns.GetFromPid(pid)
	if err != nil {
		return 0, 0, err
	}

	netns.Set(cNS)
	link, err := netlink.LinkByName("eth0")
	netns.Set(hNS)

	if err != nil {
		cNS.Close()
		return 0, 0, err
	}
	return link.Attrs().ParentIndex, cNS, nil
}
