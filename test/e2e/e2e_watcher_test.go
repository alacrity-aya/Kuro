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

func TestAgentWatcherE2E(t *testing.T) {
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	CleanupAndWait(t, clientset)
	defer CleanupAndWait(t, clientset)

	testPodName := "e2e-verify-pod"
	t.Logf(">>> Creating pod: %s", testPodName)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: testPodName, Namespace: TargetNamespace},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nginx", Image: "nginx:alpine"}}},
	}
	clientset.CoreV1().Pods(TargetNamespace).Create(ctx, pod, metav1.CreateOptions{})

	WaitPodRunning(t, clientset, testPodName)
	targetPod, _ := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, testPodName, metav1.GetOptions{})

	// Port Forward
	agentPod, err := GetAgentPodOnNode(ctx, clientset, targetPod.Spec.NodeName)
	if err != nil {
		t.Fatal(err)
	}
	localPort := "18080"
	cmd := exec.Command("kubectl", "port-forward", "-n", AgentNamespace, agentPod, fmt.Sprintf("%s:8080", localPort))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	time.Sleep(2 * time.Second)

	// Verify Local Watcher
	t.Run("Verify Pod Addition", func(t *testing.T) {
		if !WaitFor(t, 20*time.Second, func() bool {
			// This relies on the /debug/pods endpoint in http_service.go
			pods, err := GetAgentPods(localPort)
			if err != nil {
				return false
			}
			for _, p := range pods {
				if p.Info.Name == testPodName {
					return true
				}
			}
			return false
		}) {
			DumpAgentLogs(t, AgentNamespace)
			t.Fatalf("Timeout waiting for Agent to discover pod %s", testPodName)
		}
	})

	// Verify Deletion
	clientset.CoreV1().Pods(TargetNamespace).Delete(ctx, testPodName, metav1.DeleteOptions{})
	WaitFor(t, 30*time.Second, func() bool {
		_, err := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, testPodName, metav1.GetOptions{})
		return err != nil
	})

	t.Run("Verify Pod Deletion", func(t *testing.T) {
		if !WaitFor(t, 20*time.Second, func() bool {
			pods, err := GetAgentPods(localPort)
			if err != nil {
				return false
			}
			for _, p := range pods {
				if p.Info.Name == testPodName {
					return false // Still exists
				}
			}
			return true // Gone
		}) {
			t.Fatalf("Timeout waiting for Agent to remove pod %s", testPodName)
		}
	})
}

// Helper specific to this test
type DebugPod struct {
	Info struct {
		Name string `json:"Name"`
	} `json:"Info"`
}

func GetAgentPods(port string) ([]DebugPod, error) {
	resp, err := http.Get(fmt.Sprintf("http://localhost:%s/debug/pods", port))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var pods []DebugPod
	if err := json.NewDecoder(resp.Body).Decode(&pods); err != nil {
		return nil, err
	}
	return pods, nil
}
