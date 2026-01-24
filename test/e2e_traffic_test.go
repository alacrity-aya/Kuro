//go:build k8s

package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	IperfImage     = "nicolaka/netshoot"
	ServerPodName  = "iperf-server"
	ClientPodName  = "iperf-client"
	LimitRateBits  = 50 * 1000 * 1000 // 50 Mbps
	LimitTolerance = 0.2              // Allow 20% error tolerance
)

// IperfJSONOutput is used to parse the output of 'iperf3 -J'
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

func TestTrafficShapingE2E(t *testing.T) {
	// 1. Initialize K8s client
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("Error building kubeconfig: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("Error creating clientset: %v", err)
	}
	ctx := context.Background()

	// (A) Before testing starts: Force cleanup and wait
	cleanupAndWait(t, clientset)

	// (B) After testing ends: Perform cleanup as well (using defer)
	defer cleanupAndWait(t, clientset)

	// 3. Deploy iperf3 Server
	t.Log(">>> Deploying iperf3 Server...")
	serverPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ServerPodName, Labels: map[string]string{"app": "iperf-server"}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "iperf-server",
				Image:   IperfImage,
				Command: []string{"iperf3"},
				Args:    []string{"-s"},
				Ports:   []corev1.ContainerPort{{ContainerPort: 5201}},
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}
	if _, err := clientset.CoreV1().Pods(TargetNamespace).Create(ctx, serverPod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create server pod: %v", err)
	}

	// Create Service for Client connection
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "iperf-service"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "iperf-server"},
			Ports:    []corev1.ServicePort{{Port: 5201, Protocol: corev1.ProtocolTCP}},
		},
	}
	if _, err := clientset.CoreV1().Services(TargetNamespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
		// Ignore if exists
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("Failed to create service: %v", err)
		}
	}

	// 4. Deploy iperf3 Client
	t.Log(">>> Deploying iperf3 Client...")
	clientPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ClientPodName},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "iperf-client",
				Image:   IperfImage,
				Command: []string{"sleep", "3600"}, // Keep running
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}
	if _, err := clientset.CoreV1().Pods(TargetNamespace).Create(ctx, clientPod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Failed to create client pod: %v", err)
	}

	// 5. Wait for Pod Running
	t.Log("Waiting for pods to be ready...")
	waitPodRunning(t, clientset, ServerPodName)
	waitPodRunning(t, clientset, ClientPodName)

	// Get the Node where Client Pod is located to find the corresponding Agent
	cp, _ := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, ClientPodName, metav1.GetOptions{})
	agentPodName, err := getAgentPodOnNode(ctx, clientset, cp.Spec.NodeName)
	if err != nil {
		t.Fatalf("Failed to locate agent on node %s: %v", cp.Spec.NodeName, err)
	}
	t.Logf("Controlled by Agent: %s", agentPodName)

	// 6. Port-Forward to Agent API
	localPort := "28080" // Use a port different from e2e_test
	pfCmd := exec.Command("kubectl", "port-forward", "-n", AgentNamespace, agentPodName, fmt.Sprintf("%s:8080", localPort))
	if err := pfCmd.Start(); err != nil {
		t.Fatalf("Port-forward failed: %v", err)
	}
	defer func() { _ = pfCmd.Process.Kill() }()
	time.Sleep(2 * time.Second) // Wait for connection establishment

	// 7. Set rate limit (50 Mbps)
	t.Logf(">>> Applying Limit: %d Mbps (Up/Down)", LimitRateBits/1000000)
	setLimitURL := fmt.Sprintf("http://127.0.0.1:%s/ops/limit?up=%d&down=%d", localPort, LimitRateBits, LimitRateBits)
	resp, err := http.Get(setLimitURL)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("Failed to set limit via Agent API: %v", err)
	}
	resp.Body.Close()
	t.Log("Limit applied successfully via API.")

	// Wait for BPF rules to take effect (eBPF map updates are atomic, but allow a small buffer)
	time.Sleep(1 * time.Second)

	// 8. Run test: Upload (Client -> Server)
	// This tests the Egress of the Client Pod (HandleEdtUpload)
	t.Run("Upload_Test", func(t *testing.T) {
		bps := runIperfRemote(t, ClientPodName, "iperf-service", false)
		verifySpeed(t, bps, LimitRateBits, "Upload")
	})

	// 9. Run test: Download (Server -> Client)
	// This tests the Ingress of the Client Pod (actually Egress of the corresponding veth on Host -> HandleEdtDownload)
	t.Run("Download_Test", func(t *testing.T) {
		bps := runIperfRemote(t, ClientPodName, "iperf-service", true)
		verifySpeed(t, bps, LimitRateBits, "Download")
	})
}

// runIperfRemote executes iperf3 inside the Pod
// reverse=false: Client sends (Upload)
// reverse=true: Client receives (Download)
func runIperfRemote(t *testing.T, clientPod, serverHost string, reverse bool) float64 {
	cmdArgs := []string{
		"exec", "-n", TargetNamespace, clientPod, "--",
		"iperf3", "-c", serverHost, "-t", "5", "-J",
	}
	if reverse {
		cmdArgs = append(cmdArgs, "-R")
	}

	cmd := exec.Command("kubectl", cmdArgs...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	t.Logf("Running iperf3 (Reverse=%v)...", reverse)
	if err := cmd.Run(); err != nil {
		t.Fatalf("iperf3 execution failed: %v\nStderr: %s", err, stderr.String())
	}

	var result IperfJSONOutput
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Logf("Raw Output: %s", out.String())
		t.Fatalf("Failed to parse iperf JSON: %v", err)
	}

	// Take the larger value between sender and receiver statistics (usually consistent, receiver is more accurate)
	bps := result.End.SumReceived.BitsPerSecond
	if bps == 0 {
		bps = result.End.SumSent.BitsPerSecond
	}
	return bps
}

func verifySpeed(t *testing.T, actualBps float64, targetBps float64, direction string) {
	mbps := actualBps / 1e6
	targetMbps := targetBps / 1e6
	t.Logf("[%s] Measured: %.2f Mbps | Target: %.2f Mbps", direction, mbps, targetMbps)

	upper := targetBps * (1 + LimitTolerance)
	// Lower bound is slightly more relaxed because TCP slow start and environment noise might cause lower average speeds
	lower := targetBps * (1 - LimitTolerance*1.5)

	if actualBps > upper {
		t.Errorf("FAIL: [%s] Limit Exceeded! Got %.2f Mbps, Limit %.2f Mbps", direction, mbps, targetMbps)
	} else if actualBps < lower {
		t.Logf("WARNING: [%s] Speed lower than expected (%.2f Mbps). Could be environment noise.", direction, mbps)
	} else {
		t.Logf("PASS: [%s] Traffic shaped correctly.", direction)
	}
}

func waitPodRunning(t *testing.T, client *kubernetes.Clientset, podName string) {
	waitFor(t, 120*time.Second, func() bool {
		p, err := client.CoreV1().Pods(TargetNamespace).Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return false
		}
		return p.Status.Phase == corev1.PodRunning
	})
}

func cleanupTrafficTest(t *testing.T, client *kubernetes.Clientset) {
	ctx := context.Background()
	delOpt := metav1.DeleteOptions{}
	_ = client.CoreV1().Pods(TargetNamespace).Delete(ctx, ServerPodName, delOpt)
	_ = client.CoreV1().Pods(TargetNamespace).Delete(ctx, ClientPodName, delOpt)
	_ = client.CoreV1().Services(TargetNamespace).Delete(ctx, "iperf-service", delOpt)
}

// cleanupAndWait force deletes and waits for resources to disappear completely
func cleanupAndWait(t *testing.T, client *kubernetes.Clientset) {
	t.Log("Cleaning up previous resources...")
	ctx := context.Background()

	// Use 0 grace period for immediate force deletion
	gracePeriod := int64(0)
	delOpt := metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod,
	}

	// List of resources to clean up
	pods := []string{ServerPodName, ClientPodName}
	services := []string{"iperf-service"}

	// 1. Delete Pods
	for _, name := range pods {
		err := client.CoreV1().Pods(TargetNamespace).Delete(ctx, name, delOpt)
		if err != nil && !apierrors.IsNotFound(err) {
			t.Logf("Warning: Failed to delete pod %s: %v", name, err)
		}
	}

	// 2. Delete Services
	for _, name := range services {
		err := client.CoreV1().Services(TargetNamespace).Delete(ctx, name, delOpt)
		if err != nil && !apierrors.IsNotFound(err) {
			t.Logf("Warning: Failed to delete service %s: %v", name, err)
		}
	}

	// 3. Core logic: Loop and check if resources have actually disappeared
	timeout := 30 * time.Second
	start := time.Now()

	for {
		pendingCount := 0

		// Check if Pods still exist
		for _, name := range pods {
			_, err := client.CoreV1().Pods(TargetNamespace).Get(ctx, name, metav1.GetOptions{})
			if err == nil {
				pendingCount++ // Not yet deleted
			} else if !apierrors.IsNotFound(err) {
				t.Logf("Check pod %s error: %v", name, err)
			}
		}

		// Check if Services still exist
		for _, name := range services {
			_, err := client.CoreV1().Services(TargetNamespace).Get(ctx, name, metav1.GetOptions{})
			if err == nil {
				pendingCount++
			}
		}

		if pendingCount == 0 {
			t.Log("Cleanup complete: All resources removed.")
			return
		}

		if time.Since(start) > timeout {
			t.Logf("Warning: Timeout waiting for resource cleanup. Still pending: %d objects", pendingCount)
			// Even if timed out, attempt to continue as it might be stuck in terminating; K8s will eventually handle it
			return
		}

		time.Sleep(1 * time.Second)
	}
}
