// Package discovery discovers pod adding and pod deleting
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
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
	k8sClient    *kubernetes.Clientset
	criClient    runtimeapi.RuntimeServiceClient
	criConn      *grpc.ClientConn
	k8sNamespace string
}

func NewPodWatcher(k *kubernetes.Clientset, criSocketPath string, k8sNamespace string) (*PodWatcher, error) {
	conn, err := grpc.NewClient(criSocketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CRI socket %s: %w", criSocketPath, err)
	}

	if k8sNamespace == "" {
		slog.Warn("watcher: k8sNamespace is empty, watch all namespaces")
	}

	return &PodWatcher{
		k8sClient:    k,
		criClient:    runtimeapi.NewRuntimeServiceClient(conn),
		criConn:      conn,
		k8sNamespace: k8sNamespace,
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

		nodeName := os.Getenv("NODE_NAME")
		opts := metav1.ListOptions{
			FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
		}

		slog.Info("Starting K8s Watch", "selector: nodeName", nodeName, "selector: namespace", w.k8sNamespace)
		watcher, err := w.k8sClient.CoreV1().Pods(w.k8sNamespace).Watch(ctx, opts)
		if err != nil {
			slog.Error("K8s Watch failed", "error", err)
			return
		}

		for event := range watcher.ResultChan() {
			pod, ok := event.Object.(*v1.Pod)
			if !ok {
				continue
			}

			if pod.Namespace == "kube-system" || pod.Namespace == "kuro-system" {
				continue
			}

			slog.Debug("Watch Event Received",
				"type", event.Type,
				"pod", pod.Name,
				"phase", pod.Status.Phase,
				"hasIP", pod.Status.PodIP != "",
				"namespace", pod.Namespace)

			// inform agent remove pod
			if event.Type == watch.Deleted {
				out <- Event{
					Type:   watch.Deleted,
					Target: TargetPod{PodName: pod.Name},
				}
				continue
			}

			if pod.Status.Phase == v1.PodRunning && pod.Status.PodIP != "" {
				slog.Debug("Pod is ready, starting probe", "pod", pod.Name)
				go w.probePod(pod, out)
			} else {
				slog.Debug("Ignoring Pod (not ready)", "pod", pod.Name, "phase", pod.Status.Phase)
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
		slog.Warn("Probe failed: No running container ID found", "pod", pod.Name)
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
			if parseErr := json.Unmarshal([]byte(resp.Info["info"]), &info); parseErr != nil {
				slog.Warn("CRI Info parse error", "pod", pod.Name, "err", parseErr)
			} else {
				pid = info.Pid
				if pid != 0 {
					break
				}
			}
		} else {
			slog.Debug("CRI Lookup retry", "pod", pod.Name, "attempt", i, "err", err)
		}
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
	}

	if pid == 0 {
		slog.Error("Probe failed: Could not resolve PID from CRI", "pod", pod.Name, "cid", cID)
		return
	}

	hostIdx, handle, err := w.getNetworkMetadata(pid)
	if err != nil {
		slog.Error("Probe failed: Netns lookup error", "pod", pod.Name, "pid", pid, "err", err)
		return
	}

	slog.Info("Pod Discovered", "pod", pod.Name, "ifIndex", hostIdx, "expID", pod.Namespace)

	out <- Event{
		Type: watch.Added,
		Target: TargetPod{
			PodName:     pod.Name,
			ExpID:       pod.Namespace,
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
		return 0, 0, fmt.Errorf("failed to get ns from pid %d: %w", pid, err)
	}

	if err = netns.Set(cNS); err != nil {
		cNS.Close()
		return 0, 0, fmt.Errorf("failed to enter netns: %w", err)
	}

	link, err := netlink.LinkByName("eth0")
	netns.Set(hNS)

	if err != nil {
		cNS.Close()
		return 0, 0, fmt.Errorf("failed to find eth0: %w", err)
	}

	return link.Attrs().ParentIndex, cNS, nil
}
