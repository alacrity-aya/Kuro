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
		IP          string `json:"IP"` // Ensure IP is included in PodInfo definition in watcher.go if not already
	} `json:"Info"`
}

func TestAgentE2E(t *testing.T) {
	// ... [Standard K8s Setup Code - Same as before] ...
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

	gracePeriod := int64(0)
	err = clientset.CoreV1().Pods(TargetNamespace).Delete(ctx, TestPodName, metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod,
	})

	t.Logf("cleanup previous pod error: %v", err)

	// if err != nil && !errors.IsNotFound(err) {
	// 	t.Fatalf("Failed to cleanup previous pod: %v", err)
	// }

	t.Log("Waiting for previous pod to be fully deleted...")
	time.Sleep(5 * time.Second)

	t.Logf("Creating testing pod: %s", TestPodName)
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

	t.Log("Waiting for pod to be running and scheduled...")
	var targetNodeName string
	var targetPodIP string // We need the IP to verify PeerWatcher

	waitFor(t, 90*time.Second, func() bool {
		p, err := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, TestPodName, metav1.GetOptions{})
		if err == nil && p.Status.Phase == corev1.PodRunning && p.Spec.NodeName != "" && p.Status.PodIP != "" {
			targetNodeName = p.Spec.NodeName
			targetPodIP = p.Status.PodIP
			return true
		}
		return false
	})
	t.Logf("Test pod is running on node: %s with IP: %s", targetNodeName, targetPodIP)

	agentPodName, err := getAgentPodOnNode(ctx, clientset, targetNodeName)
	if err != nil {
		t.Fatalf("Failed to find agent on node %s: %v", targetNodeName, err)
	}
	t.Logf("Target Agent Pod is: %s", agentPodName)

	localPort := "18080"
	cmd := exec.Command("kubectl", "port-forward", "-n", AgentNamespace, agentPodName, fmt.Sprintf("%s:8080", localPort))
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start port-forward: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
	}()

	time.Sleep(2 * time.Second)

	// --- Test 1: Local Watcher (Existing) ---
	t.Log("Assertion 1: Checking if Local Watcher has detected the pod...")
	waitFor(t, 10*time.Second, func() bool {
		pods, err := getAgentPods(localPort)
		if err != nil {
			t.Logf("Error querying agent pods: %v", err)
			return false
		}
		for _, p := range pods {
			if p.Info.Name == TestPodName {
				t.Logf("SUCCESS: Local Agent is tracking pod %s", p.Info.Name)
				return true
			}
		}
		return false
	})

	// --- Test 2: Peer Watcher (New) ---
	t.Log("Assertion 2: Checking if Peer Watcher has added IP to BPF Map...")
	waitFor(t, 10*time.Second, func() bool {
		peers, err := getAgentPeers(localPort)
		if err != nil {
			t.Logf("Error querying agent peers: %v", err)
			return false
		}
		for _, ip := range peers {
			if ip == targetPodIP {
				t.Logf("SUCCESS: PeerWatcher synced IP %s to BPF Map", ip)
				return true
			}
		}
		return false
	})

	// --- Clean Up ---
	t.Log("Deleting testing pod...")
	err = clientset.CoreV1().Pods(TargetNamespace).Delete(ctx, TestPodName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete pod: %v", err)
	}

	// --- Test 3: Verify Removal ---
	t.Log("Assertion 3: Checking if IP is removed from BPF Map...")
	waitFor(t, 20*time.Second, func() bool {
		peers, err := getAgentPeers(localPort)
		if err != nil {
			return false
		}
		for _, ip := range peers {
			if ip == targetPodIP {
				// Should NOT find it
				return false
			}
		}
		t.Log("SUCCESS: IP removed from BPF Map.")
		return true
	})
}

// ... [Helper Functions] ...

func getAgentPodOnNode(ctx context.Context, client *kubernetes.Clientset, nodeName string) (string, error) {
	// (Keep existing implementation)
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
	// (Keep existing implementation)
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

// [New Helper]
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
