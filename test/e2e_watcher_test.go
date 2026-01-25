//go:build k8s

package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	TargetNamespace = "kuro-experiment"
	AgentNamespace  = "kuro-system"
	TestPodName     = "e2e-verify-pod"
	AgentLabel      = "app=kuro-agent"
)

// PodContext matches the structure returned by /debug/pods
type PodContext struct {
	Info struct {
		Name        string `json:"Name"`
		Namespace   string `json:"Namespace"`
		ContainerID string `json:"ContainerID"`
		NodeName    string `json:"NodeName"`
		IP          string `json:"IP"`
	} `json:"Info"`
}

func TestAgentE2E(t *testing.T) {
	// 1. K8s Client Setup
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("Failed to build kubeconfig: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("Failed to create clientset: %v", err)
	}
	ctx := context.Background()

	// 2. Pre-Test Cleanup (Ensure clean state)
	t.Log(">>> [Setup] ensuring environment is clean...")
	if err := ensurePodDeleted(ctx, clientset, TestPodName); err != nil {
		t.Fatalf("Failed to cleanup previous pod: %v", err)
	}

	// 3. Create Pod
	t.Logf(">>> [Setup] Creating testing pod: %s", TestPodName)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      TestPodName,
			Namespace: TargetNamespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:alpine",
				},
			},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}

	_, err = clientset.CoreV1().Pods(TargetNamespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create pod: %v", err)
	}

	// Ensure cleanup happens even if test fails later
	t.Cleanup(func() {
		t.Log(">>> [Cleanup] Deleting testing pod...")
		_ = clientset.CoreV1().Pods(TargetNamespace).Delete(context.Background(), TestPodName, metav1.DeleteOptions{})
	})

	// 4. Wait for Pod Running
	t.Log(">>> [Setup] Waiting for pod to be running and scheduled...")
	var targetNodeName string
	var targetPodIP string

	waitFor(t, 90*time.Second, func() bool {
		p, err := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, TestPodName, metav1.GetOptions{})
		if err == nil && p.Status.Phase == corev1.PodRunning && p.Spec.NodeName != "" && p.Status.PodIP != "" {
			targetNodeName = p.Spec.NodeName
			targetPodIP = p.Status.PodIP
			return true
		}
		return false
	})
	t.Logf("Pod is ready on Node: %s, IP: %s", targetNodeName, targetPodIP)

	// 5. Connect to Agent
	agentPodName, err := getAgentPodOnNode(ctx, clientset, targetNodeName)
	if err != nil {
		t.Fatalf("Failed to find agent on node %s: %v", targetNodeName, err)
	}

	localPort := "18080"
	t.Logf(">>> [Setup] Port-forwarding to agent %s on port %s", agentPodName, localPort)
	cmd := exec.Command("kubectl", "port-forward", "-n", AgentNamespace, agentPodName, fmt.Sprintf("%s:8080", localPort))
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start port-forward: %v", err)
	}
	// Ensure port-forward process is killed
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	time.Sleep(2 * time.Second) // Give port-forward a moment to establish

	// ================= TEST PHASE 1: ADDITION =================
	t.Run("Verify Pod Addition", func(t *testing.T) {
		// Test 1: Local Watcher (Metadata & Netns)
		t.Log("Check 1: Local Watcher should track the pod")
		waitFor(t, 10*time.Second, func() bool {
			pods, err := getAgentPods(localPort)
			if err != nil {
				return false
			}
			for _, p := range pods {
				if p.Info.Name == TestPodName {
					if p.Info.IP != targetPodIP {
						t.Logf("Warning: IP mismatch in agent. Expected %s, got %s", targetPodIP, p.Info.IP)
					}
					return true
				}
			}
			return false
		})

		// Test 2: Peer Watcher (IP Whitelist)
		t.Log("Check 2: Peer Watcher should verify IP in BPF Map")
		waitFor(t, 10*time.Second, func() bool {
			peers, err := getAgentPeers(localPort)
			if err != nil {
				return false
			}
			for _, ip := range peers {
				if ip == targetPodIP {
					return true
				}
			}
			return false
		})
	})

	// ================= TEST PHASE 2: DELETION =================
	t.Log(">>> [Action] Deleting pod to test cleanup logic...")
	err = clientset.CoreV1().Pods(TargetNamespace).Delete(ctx, TestPodName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete pod: %v", err)
	}

	// Wait for K8s to fully remove it first
	if err := ensurePodDeleted(ctx, clientset, TestPodName); err != nil {
		t.Fatalf("Pod stuck in terminating state: %v", err)
	}

	t.Run("Verify Pod Removal", func(t *testing.T) {
		// Test 3: Peer Watcher Removal (IP Removal)
		t.Log("Check 3: Peer Watcher should remove IP from BPF Map")
		waitFor(t, 20*time.Second, func() bool {
			peers, err := getAgentPeers(localPort)
			if err != nil {
				return false // Network error, retry
			}
			for _, ip := range peers {
				if ip == targetPodIP {
					return false // Still exists, keep waiting
				}
			}
			return true // Gone
		})

		// Test 4: Local Watcher Removal (Netns Handle Cleanup) -> 这一步是你要求的关键补充
		t.Log("Check 4: Local Watcher should remove Pod from memory (Close Netns)")
		waitFor(t, 20*time.Second, func() bool {
			pods, err := getAgentPods(localPort)
			if err != nil {
				return false
			}
			for _, p := range pods {
				if p.Info.Name == TestPodName {
					return false // Still exists in memory, keep waiting
				}
			}
			return true // Gone
		})
	})

	t.Log(">>> All Systems Go! E2E Test Passed.")
}

// ... [Helper Functions] ...

func ensurePodDeleted(ctx context.Context, client *kubernetes.Clientset, podName string) error {
	grace := int64(0)
	err := client.CoreV1().Pods(TargetNamespace).Delete(ctx, podName, metav1.DeleteOptions{
		GracePeriodSeconds: &grace,
	})

	if err != nil && errors.IsNotFound(err) {
		return nil // Already gone
	}

	// Poll until it's really gone
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	timeout := time.After(30 * time.Second)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for pod %s deletion", podName)
		case <-ticker.C:
			_, err := client.CoreV1().Pods(TargetNamespace).Get(ctx, podName, metav1.GetOptions{})
			if err != nil && errors.IsNotFound(err) {
				return nil // Success
			}
		}
	}
}

func getAgentPodOnNode(ctx context.Context, client *kubernetes.Clientset, nodeName string) (string, error) {
	pods, err := client.CoreV1().Pods(AgentNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: AgentLabel,
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no agent pod found on node %s", nodeName)
	}
	return pods.Items[0].Name, nil
}

func getAgentPods(port string) ([]PodContext, error) {
	url := fmt.Sprintf("http://127.0.0.1:%s/debug/pods", port)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	var pods []PodContext
	if err := json.NewDecoder(resp.Body).Decode(&pods); err != nil {
		return nil, err
	}
	return pods, nil
}

func getAgentPeers(port string) ([]string, error) {
	url := fmt.Sprintf("http://127.0.0.1:%s/debug/peers", port)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	var peers []string
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, err
	}
	return peers, nil
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	start := time.Now()
	for {
		if condition() {
			return
		}
		if time.Since(start) > timeout {
			t.Fatalf("Timeout waiting for condition")
		}
		time.Sleep(1 * time.Second)
	}
}
