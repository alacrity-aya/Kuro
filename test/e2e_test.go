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

type PodContext struct {
	Info struct {
		Name        string `json:"Name"`
		Namespace   string `json:"Namespace"`
		ContainerID string `json:"ContainerID"`
		NodeName    string `json:"NodeName"`
	} `json:"Info"`
}

func TestAgentE2E(t *testing.T) {
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

	t.Log("Cleaning up previous test pods...")
	_ = clientset.CoreV1().Pods(TargetNamespace).Delete(ctx, TestPodName, metav1.DeleteOptions{})

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
	waitFor(t, 60*time.Second, func() bool {
		p, err := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, TestPodName, metav1.GetOptions{})
		if err == nil && p.Status.Phase == corev1.PodRunning && p.Spec.NodeName != "" {
			targetNodeName = p.Spec.NodeName
			return true
		}
		return false
	})
	t.Logf("Test pod is running on node: %s", targetNodeName)

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

	t.Log("Assertion: Checking if Agent has detected the pod...")
	waitFor(t, 10*time.Second, func() bool {
		pods, err := getAgentPods(localPort)
		if err != nil {
			t.Logf("Error querying agent: %v", err)
			return false
		}
		for _, p := range pods {
			if p.Info.Name == TestPodName {
				t.Logf("SUCCESS: Agent is tracking pod %s (ContainerID: %s)", p.Info.Name, p.Info.ContainerID)
				return true
			}
		}
		return false
	})

	t.Log("Deleting testing pod...")
	err = clientset.CoreV1().Pods(TargetNamespace).Delete(ctx, TestPodName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete pod: %v", err)
	}

	t.Log("Assertion: Checking if Agent has cleaned up the pod...")
	waitFor(t, 20*time.Second, func() bool {
		pods, err := getAgentPods(localPort)
		if err != nil {
			return false
		}
		for _, p := range pods {
			if p.Info.Name == TestPodName {
				return false
			}
		}
		t.Log("SUCCESS: Pod removed from Agent memory.")
		return true
	})
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
