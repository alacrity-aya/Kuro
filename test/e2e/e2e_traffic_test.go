//go:build k8s

package test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestTrafficShapingHTTP(t *testing.T) {
	// 1. Setup
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

	// 2. Deploy
	t.Log(">>> Deploying Workloads...")
	// Server
	serverPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ServerPodName, Labels: map[string]string{"app": "iperf-server"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "s", Image: IperfImage, Command: []string{"iperf3", "-s"}}}},
	}
	clientset.CoreV1().Pods(TargetNamespace).Create(ctx, serverPod, metav1.CreateOptions{})
	// Service
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "iperf-service"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "iperf-server"}, Ports: []corev1.ServicePort{{Port: 5201}}},
	}
	if _, err := clientset.CoreV1().Services(TargetNamespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatal(err)
		}
	}
	// Client
	clientPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ClientPodName},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: IperfImage, Command: []string{"sleep", "3600"}}}},
	}
	clientset.CoreV1().Pods(TargetNamespace).Create(ctx, clientPod, metav1.CreateOptions{})

	WaitPodRunning(t, clientset, ServerPodName)
	WaitPodRunning(t, clientset, ClientPodName)

	// 3. Port Forward Agent
	cp, _ := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, ClientPodName, metav1.GetOptions{})
	agentPod, err := GetAgentPodOnNode(ctx, clientset, cp.Spec.NodeName)
	if err != nil {
		t.Fatal(err)
	}

	localPort := "28080"
	pfCmd := exec.Command("kubectl", "port-forward", "-n", AgentNamespace, agentPod, fmt.Sprintf("%s:8080", localPort))
	if err := pfCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pfCmd.Process.Kill() }()
	time.Sleep(2 * time.Second)

	// 4. Set Limit via HTTP

	limit := 50 * 1000 * 1000 // 50 Mbps
	t.Logf(">>> Applying Limit: %d bps", limit)

	url := fmt.Sprintf("http://127.0.0.1:%s/ops/limit?sim_up=%d&sim_down=%d&sys_up=%d&sys_down=%d",
		localPort, limit, limit, limit, limit)

	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("Failed to call agent API: %v", err)
	}
	resp.Body.Close()
	time.Sleep(1 * time.Second)

	// 5. Verify
	t.Run("Upload", func(t *testing.T) {
		bps := RunIperfRemote(t, ClientPodName, "iperf-service", false)
		VerifySpeed(t, bps, float64(limit), "HTTP Upload")
	})
}
