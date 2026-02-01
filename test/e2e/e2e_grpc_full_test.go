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
	LocalHttpPort     = "18080"
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

	// 2. Check Controller
	t.Log(">>> [Setup] Waiting for Controller Pod...")

	var controllerPodName string
	ns := "kuro-system"

	// Added retry logic to find the Pod, in case the Deployment hasn't created the Pod yet
	WaitFor(t, 60*time.Second, func() bool {
		pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=kuro-controller", // Ensure this matches your Deployment Label
		})
		if err != nil || len(pods.Items) == 0 {
			return false
		}
		// Pick the first Pod
		controllerPodName = pods.Items[0].Name
		return true
	})

	if controllerPodName == "" {
		t.Fatal("Timeout: Could not find any pod with label app=kuro-controller")
	}

	t.Logf(">>> Found Controller Pod: %s", controllerPodName)
	WaitPodRunning(t, clientset, controllerPodName, ns)

	// 3. Configure Agent to point to Controller
	controllerPods, _ := clientset.CoreV1().Pods("kuro-system").List(ctx, metav1.ListOptions{LabelSelector: "app=kuro-controller"})
	if len(controllerPods.Items) == 0 {
		t.Fatal("No controller pod found")
	}
	controllerPodName = controllerPods.Items[0].Name

	t.Log(">>> [Setup] Port-forwarding Controller :8080 -> :18080")
	pfCmd := exec_portforward("kuro-system", controllerPodName, "8080", LocalHttpPort)
	if err := pfCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pfCmd.Process.Kill() }()

	baseUrl := "http://localhost:" + LocalHttpPort

	t.Log(">>> [Wait] Waiting for Agent to register via HTTP API...")
	var agentNodeName string
	WaitFor(t, 60*time.Second, func() bool {
		resp, err := http.Get(baseUrl + "/api/v1/agents")
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		var res struct {
			Nodes []string `json:"nodes"`
		}
		json.NewDecoder(resp.Body).Decode(&res)
		if len(res.Nodes) > 0 {
			agentNodeName = res.Nodes[0]
			return true
		}
		return false
	})

	if agentNodeName == "" {
		t.Fatal("No agent registered with Controller")
	}
	t.Logf("PASS: Found connected agent node: %s", agentNodeName)

	// 4. Deploy Workloads
	CleanupAndWait(t, clientset)
	defer CleanupAndWait(t, clientset)

	t.Log(">>> Deploying iperf workloads...")

	serverPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ServerPodName, Labels: map[string]string{"app": "iperf-server"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "s", Image: IperfImage, Command: []string{"iperf3", "-s"}}}},
	}
	clientPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ClientPodName, Labels: map[string]string{"app": "iperf-client"}},
		Spec: corev1.PodSpec{
			NodeName:   agentNodeName,
			Containers: []corev1.Container{{Name: "c", Image: IperfImage, Command: []string{"sleep", "3600"}}},
		},
	}

	clientset.CoreV1().Pods(TargetNamespace).Create(ctx, serverPod, metav1.CreateOptions{})
	clientset.CoreV1().Pods(TargetNamespace).Create(ctx, clientPod, metav1.CreateOptions{})

	WaitPodRunning(t, clientset, ServerPodName)
	WaitPodRunning(t, clientset, ClientPodName)

	srv, _ := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, ServerPodName, metav1.GetOptions{})
	cli, _ := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, ClientPodName, metav1.GetOptions{})
	srvIP := srv.Status.PodIP
	cliIP := cli.Status.PodIP

	// 5. Apply Policies
	t.Logf(">>> Applying Policies via Controller for Pod %s...", ClientPodName)

	// Step 5.1: Pod Limits
	podPolicyPayload := map[string]interface{}{
		"node_name": agentNodeName,
		"pod_name":  ClientPodName,
		"sim_rate": map[string]int{
			"upload":   TestLimitRate,
			"download": TestLimitRate,
		},
		"sys_rate": map[string]int{
			"upload":   1000 * 1000 * 1000,
			"download": 1000 * 1000 * 1000,
		},
	}
	mustSendHTTP(t, "POST", baseUrl+"/api/v1/policy/pod", podPolicyPayload)

	// Step 5.2: Link Policy (Promote to Sim Lane)
	linkPolicyPayload := map[string]interface{}{
		"node_name": agentNodeName,
		"src_ip":    cliIP,
		"dst_ip":    srvIP,
		"policy": map[string]interface{}{
			"bandwidth_limit": 0,
		},
	}
	mustSendHTTP(t, "POST", baseUrl+"/api/v1/policy/link", linkPolicyPayload)

	time.Sleep(3 * time.Second)

	// 6. Verify Speed
	bps := RunIperfRemote(t, ClientPodName, srvIP, false)
	VerifySpeed(t, bps, float64(TestLimitRate), "HTTP Controlled Upload")
}

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

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("API Error %d: %s", resp.StatusCode, string(respBody))
	}
}

func exec_portforward(ns, pod, remotePort, localPort string) *exec.Cmd {
	return exec.Command("kubectl", "port-forward", "-n", ns, pod, fmt.Sprintf("%s:%s", localPort, remotePort))
}
