//go:build k8s

package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	ControllerService = "kuro-controller.kuro-system.svc:9090"
	LocalHttpPort     = "18080"          // Local port mapped to Controller's 8080
	TestLimitRate     = 30 * 1000 * 1000 // 30 Mbps
)

func TestHTTPAndTrafficControl(t *testing.T) {
	// 1. K8s Config
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

	// 2. Deploy & Setup Controller in Cluster
	t.Log(">>> [Setup] Deploying Real Controller to kuro-system...")

	// Ensure image exists (assuming you've run 'make images' and loaded them)
	// Apply Controller Deployment
	cmd := exec.Command("kubectl", "apply", "-f", "../../deploy/controller.yaml")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to deploy controller: %v, out: %s", err, string(out))
	}

	// Wait for Controller to be Ready
	t.Log(">>> [Setup] Waiting for Controller Pod...")
	WaitDeployment(t, clientset, AgentNamespace, "kuro-controller")

	pods, err := clientset.CoreV1().Pods(AgentNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=kuro-controller",
	})
	if err != nil || len(pods.Items) == 0 {
		t.Fatalf("Failed to find controller pod: %v", err)
	}
	controllerIP := pods.Items[0].Status.PodIP
	if controllerIP == "" {
		t.Fatal("Controller Pod has no IP yet")
	}
	controllerAddr := fmt.Sprintf("%s:9090", controllerIP)
	t.Logf(">>> [Setup] Resolved Controller IP: %s (Bypassing DNS)", controllerAddr)

	// 3. Configure Agent to Connect to In-Cluster Controller
	t.Logf(">>> [Setup] Pointing Agent to %s...", ControllerService)

	// Restart Agent to apply configuration
	t.Log(">>> [Setup] Rolling out Agent...")
	exec.Command("kubectl", "rollout", "restart", "daemonset/kuro-agent", "-n", AgentNamespace).Run()
	exec.Command("kubectl", "rollout", "status", "daemonset/kuro-agent", "-n", AgentNamespace, "--timeout=60s").Run()

	// 4. Start Port-Forward for HTTP API
	t.Logf(">>> [Setup] Port-forwarding Controller :8080 -> :%s", LocalHttpPort)
	pfCmd := exec.Command("kubectl", "port-forward", "svc/kuro-controller", fmt.Sprintf("%s:8080", LocalHttpPort), "-n", AgentNamespace)
	if err := pfCmd.Start(); err != nil {
		t.Fatalf("Failed to start port-forward: %v", err)
	}
	defer func() {
		if pfCmd.Process != nil {
			pfCmd.Process.Kill()
		}
	}()

	// Wait for Port-Forward to take effect and wait for Agent to come online
	baseUrl := fmt.Sprintf("http://127.0.0.1:%s", LocalHttpPort)
	t.Log(">>> [Wait] Waiting for Agent to register via HTTP API...")

	var targetNodeName string
	WaitFor(t, 60*time.Second, func() bool {
		// Call GET /api/v1/agents to check for connected Agents
		resp, err := http.Get(baseUrl + "/api/v1/agents")
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		var res struct {
			Count int      `json:"count"`
			Nodes []string `json:"nodes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return false
		}

		if res.Count > 0 {
			targetNodeName = res.Nodes[0]
			t.Logf("PASS: Found connected agent node: %s", targetNodeName)
			return true
		}
		return false
	})

	if targetNodeName == "" {
		DumpAgentLogs(t, AgentNamespace)
		// Also print Controller logs
		out, _ := exec.Command("kubectl", "logs", "-n", AgentNamespace, "-l", "app=kuro-controller").CombinedOutput()
		t.Logf("Controller Logs:\n%s", string(out))
		t.Fatal("Timeout waiting for agent connection via HTTP API")
	}

	// 5. Deploy Workloads (Client/Server)
	CleanupAndWait(t, clientset) // From e2e_utils.go
	defer CleanupAndWait(t, clientset)

	t.Log(">>> Deploying iperf workloads...")
	serverPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ServerPodName, Labels: map[string]string{"app": "iperf-server"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "s", Image: IperfImage, Command: []string{"iperf3", "-s"}}}},
	}
	clientset.CoreV1().Pods(TargetNamespace).Create(ctx, serverPod, metav1.CreateOptions{})

	clientPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ClientPodName},
		Spec: corev1.PodSpec{
			NodeName:   targetNodeName, // Scheduled to the same Node for convenience (or different Node depending on CNI)
			Containers: []corev1.Container{{Name: "c", Image: IperfImage, Command: []string{"sleep", "3600"}}},
		},
	}
	clientset.CoreV1().Pods(TargetNamespace).Create(ctx, clientPod, metav1.CreateOptions{})

	WaitPodRunning(t, clientset, ServerPodName)
	WaitPodRunning(t, clientset, ClientPodName)

	srvPod, _ := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, ServerPodName, metav1.GetOptions{})
	srvIP := srvPod.Status.PodIP

	// 6. Test Logic using HTTP API

	// Step 6.1: Whitelist (POST /api/v1/whitelist)
	t.Logf(">>> [HTTP] Whitelisting IP: %s", srvIP)
	whitelistPayload := map[string]interface{}{
		"node_name": targetNodeName,
		"ips":       []string{srvIP},
	}
	mustSendHTTP(t, "POST", baseUrl+"/api/v1/whitelist", whitelistPayload)

	// Step 6.2: Apply Rate Limit (POST /api/v1/policy/pod)
	t.Logf(">>> [HTTP] Limiting Pod %s to 30Mbps...", ClientPodName)
	policyPayload := map[string]interface{}{
		"node_name": targetNodeName,
		"pod_name":  ClientPodName,
		"namespace": TargetNamespace,
		"sim_rate": map[string]int{
			"upload":   TestLimitRate,
			"download": TestLimitRate,
		},
		"sys_rate": map[string]int{ // System rate is usually set to a large value or unlimited
			"upload":   1000 * 1000 * 1000,
			"download": 1000 * 1000 * 1000,
		},
	}
	mustSendHTTP(t, "POST", baseUrl+"/api/v1/policy/pod", policyPayload)

	// Allow some time for the Agent to process and apply the eBPF Map
	time.Sleep(2 * time.Second)

	// Step 6.3: Verify Speed
	bps := RunIperfRemote(t, ClientPodName, srvIP, false)
	VerifySpeed(t, bps, float64(TestLimitRate), "HTTP Controlled Upload")
}

// --- Helpers ---

func mustSendHTTP(t *testing.T, method, url string, payload interface{}) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP Request Failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP Error %d: %s", resp.StatusCode, string(respBody))
	}
	t.Logf("HTTP OK: %s", string(respBody))
}

func WaitDeployment(t *testing.T, client *kubernetes.Clientset, ns, name string) {
	WaitFor(t, 120*time.Second, func() bool {
		dep, err := client.AppsV1().Deployments(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		return dep.Status.ReadyReplicas > 0
	})
}
