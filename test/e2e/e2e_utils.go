package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	TargetNamespace = "kuro-experiment"
	AgentNamespace  = "kuro-system"
	ServerPodName   = "iperf-server"
	ClientPodName   = "iperf-client"
	IperfImage      = "nicolaka/netshoot"
	LimitTolerance  = 0.3
)

// --- Structs ---

type PodContext struct {
	Info struct {
		Name        string `json:"Name"`
		Namespace   string `json:"Namespace"`
		ContainerID string `json:"ContainerID"`
		NodeName    string `json:"NodeName"`
		IP          string `json:"IP"`
	} `json:"Info"`
}

type IperfJSONOutput struct {
	End struct {
		SumSent struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_sent"`
		SumReceived struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_received"`
	} `json:"end"`
}

// --- Debug Helpers ---

func DumpAgentLogs(t *testing.T, namespace string) {
	out, err := exec.Command("kubectl", "logs", "-n", namespace, "-l", "app=kuro-agent", "--tail=50").CombinedOutput()
	if err == nil {
		t.Logf(">>> Agent Logs:\n%s", string(out))
	}
}

// --- K8s Helpers ---

func CleanupAndWait(t *testing.T, clientset *kubernetes.Clientset) {
	t.Logf(">>> [Utils] Cleaning up resources...")
	ctx := context.Background()
	_ = clientset.CoreV1().Namespaces().Delete(ctx, TargetNamespace, metav1.DeleteOptions{})

	WaitFor(t, 120*time.Second, func() bool {
		_, err := clientset.CoreV1().Namespaces().Get(ctx, TargetNamespace, metav1.GetOptions{})
		return err != nil
	})

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: TargetNamespace}}
	if _, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		t.Logf("Namespace creation warning: %v", err)
	}
}

func GetAgentPodOnNode(ctx context.Context, clientset *kubernetes.Clientset, nodeName string) (string, error) {
	pods, err := clientset.CoreV1().Pods(AgentNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=kuro-agent",
	})
	if err != nil {
		return "", err
	}
	for _, p := range pods.Items {
		if p.Spec.NodeName == nodeName {
			return p.Name, nil
		}
	}
	return "", fmt.Errorf("no agent found on node %s", nodeName)
}

func WaitPodRunning(t *testing.T, clientset *kubernetes.Clientset, podName string, ns ...string) {
	targetNs := TargetNamespace
	if len(ns) > 0 {
		targetNs = ns[0]
	}

	t.Logf(">>> [Utils] Waiting for pod %s/%s to be RUNNING...", targetNs, podName)
	ctx := context.Background()

	err := WaitForError(120*time.Second, func() error {
		p, err := clientset.CoreV1().Pods(targetNs).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if p.Status.Phase == corev1.PodRunning {
			return nil
		}
		for _, cs := range p.Status.ContainerStatuses {
			if cs.State.Waiting != nil && cs.State.Waiting.Reason == "ErrImagePull" {
				return fmt.Errorf("image pull failed")
			}
		}
		return fmt.Errorf("status: %s", p.Status.Phase)
	})
	if err != nil {
		events, _ := exec.Command("kubectl", "get", "events", "-n", targetNs, "--field-selector", "involvedObject.name="+podName).CombinedOutput()
		t.Logf(">>> Pod Events:\n%s", string(events))
		t.Fatalf("Timeout waiting for Pod %s to run: %v", podName, err)
	}
}

// --- Iperf Helpers ---

func RunIperfRemote(t *testing.T, clientPodName, serverIP string, reverse bool) float64 {
	cmdArgs := []string{
		"exec", "-n", TargetNamespace, clientPodName, "--",
		"iperf3", "-c", serverIP, "-t", "5", "-J", "--connect-timeout", "2000",
	}
	if reverse {
		cmdArgs = append(cmdArgs, "-R")
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		out, err := exec.Command("kubectl", cmdArgs...).CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("exec failed: %w, out: %s", err, string(out))
			time.Sleep(2 * time.Second)
			continue
		}

		var result IperfJSONOutput
		if err := json.Unmarshal(out, &result); err != nil {
			lastErr = fmt.Errorf("json parse error: %w", err)
			continue
		}
		bps := result.End.SumReceived.BitsPerSecond
		if bps == 0 {
			bps = result.End.SumSent.BitsPerSecond
		}
		return bps
	}
	t.Fatalf("RunIperfRemote failed: %v", lastErr)
	return 0
}

func VerifySpeed(t *testing.T, actualBps float64, targetBps float64, tag string) {
	mbps := actualBps / 1e6
	targetMbps := targetBps / 1e6
	t.Logf("[%s] Measured: %.2f Mbps | Target: %.2f Mbps", tag, mbps, targetMbps)

	if actualBps > targetBps*(1+LimitTolerance) {
		DumpAgentLogs(t, AgentNamespace)
		t.Errorf("FAIL: [%s] Limit Exceeded! Got %.2f Mbps > Limit %.2f Mbps", tag, mbps, targetMbps)
	} else {
		t.Logf("PASS: [%s] Traffic shaped correctly.", tag)
	}
}

func WaitFor(t *testing.T, timeout time.Duration, condition func() bool) bool {
	start := time.Now()
	for {
		if condition() {
			return true
		}
		if time.Since(start) > timeout {
			return false
		}
		time.Sleep(1 * time.Second)
	}
}

func WaitForError(timeout time.Duration, op func() error) error {
	start := time.Now()
	var err error
	for {
		if err = op(); err == nil {
			return nil
		}
		if time.Since(start) > timeout {
			return err
		}
		time.Sleep(2 * time.Second)
	}
}
