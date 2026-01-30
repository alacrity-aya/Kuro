//go:build k8s

package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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
	t.Logf(">>> [Debug] Dumping logs for Agent in namespace %s...", namespace)
	cmd := exec.Command("kubectl", "logs", "-n", namespace, "-l", "app=kuro-agent", "--tail=100")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Failed to get logs: %v", err)
	} else {
		t.Logf("\n=== AGENT LOGS START ===\n%s\n=== AGENT LOGS END ===", string(out))
	}
}

// --- Helpers ---

func CleanupAndWait(t *testing.T, client *kubernetes.Clientset) {
	t.Logf(">>> [Utils] Cleaning up resources...")
	ctx := context.Background()
	grace := int64(0)
	delOpt := metav1.DeleteOptions{GracePeriodSeconds: &grace}

	resources := []string{ServerPodName, ClientPodName, "e2e-verify-pod"}
	for _, name := range resources {
		_ = client.CoreV1().Pods(TargetNamespace).Delete(ctx, name, delOpt)
	}
	_ = client.CoreV1().Services(TargetNamespace).Delete(ctx, "iperf-service", delOpt)

	WaitFor(t, 60*time.Second, func() bool {
		pending := 0
		for _, name := range resources {
			if _, err := client.CoreV1().Pods(TargetNamespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
				pending++
			}
		}
		return pending == 0
	})
}

func WaitPodRunning(t *testing.T, client *kubernetes.Clientset, podName string) {
	t.Logf(">>> [Utils] Waiting for pod %s to be RUNNING...", podName)
	if !WaitFor(t, 120*time.Second, func() bool {
		p, err := client.CoreV1().Pods(TargetNamespace).Get(context.Background(), podName, metav1.GetOptions{})
		if err != nil {
			return false
		}
		return p.Status.Phase == corev1.PodRunning && p.Status.PodIP != ""
	}) {
		t.Fatalf("Timeout waiting for Pod %s to run. Check 'kubectl describe pod %s -n %s'", podName, podName, TargetNamespace)
	}
}

func GetAgentPodOnNode(ctx context.Context, client *kubernetes.Clientset, nodeName string) (string, error) {
	var podName string
	err := WaitForError(10*time.Second, func() error {
		pods, err := client.CoreV1().Pods(AgentNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app=kuro-agent",
			FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
		})
		if err != nil {
			return err
		}
		if len(pods.Items) == 0 {
			return fmt.Errorf("no agent pod found")
		}

		p := pods.Items[0]
		if p.Status.Phase != corev1.PodRunning {
			return fmt.Errorf("agent pod %s is %s", p.Name, p.Status.Phase)
		}
		podName = p.Name
		return nil
	})
	return podName, err
}

func GetAgentPods(port string) ([]PodContext, error) {
	url := fmt.Sprintf("http://127.0.0.1:%s/debug/pods", port)
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	var pods []PodContext
	if err := json.NewDecoder(resp.Body).Decode(&pods); err != nil {
		return nil, err
	}
	return pods, nil
}

func RunIperfRemote(t *testing.T, clientPod, serverHost string, reverse bool) float64 {
	cmdArgs := []string{
		"exec", "-n", TargetNamespace, clientPod, "--",
		"iperf3", "-c", serverHost, "-t", "5", "-J", "--connect-timeout", "5000",
	}
	if reverse {
		cmdArgs = append(cmdArgs, "-R")
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		cmd := exec.Command("kubectl", cmdArgs...)
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		t.Logf("Running iperf3 (Attempt %d)...", i+1)
		if err := cmd.Run(); err != nil {
			lastErr = fmt.Errorf("iperf3 error: %v | stderr: %s", err, stderr.String())
			time.Sleep(2 * time.Second)
			continue
		}

		var result IperfJSONOutput
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			lastErr = fmt.Errorf("json parse error: %v | raw: %s", err, out.String())
			time.Sleep(1 * time.Second)
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
		time.Sleep(1 * time.Second)
	}
}

func GetHostLANIP(t *testing.T) string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		t.Logf("Warning: No internet connection to determine LAN IP: %v", err)
		return "172.18.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP.String()

	t.Logf(">>> Detected Host LAN IP: %s", ip)
	return ip
}
