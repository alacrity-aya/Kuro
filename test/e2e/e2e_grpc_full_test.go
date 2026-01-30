//go:build k8s_failed

package test

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "kuro/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type MockController struct {
	pb.UnimplementedSimulationAgentServiceServer
	mu           sync.Mutex
	connected    map[string]pb.SimulationAgentService_ControlStreamServer
	events       chan *pb.AgentMsg
	cmdResponses chan *pb.CommandAck
}

func NewMockController() *MockController {
	return &MockController{
		connected:    make(map[string]pb.SimulationAgentService_ControlStreamServer),
		events:       make(chan *pb.AgentMsg, 100),
		cmdResponses: make(chan *pb.CommandAck, 100),
	}
}

func (s *MockController) ControlStream(stream pb.SimulationAgentService_ControlStreamServer) error {
	firstMsg, err := stream.Recv()
	if err != nil {
		return err
	}

	hb := firstMsg.GetHeartbeat()
	if hb == nil {
		return fmt.Errorf("first message was not heartbeat")
	}

	nodeName := hb.NodeName
	log.Printf("[MockServer] Agent connected from Node: %s", nodeName)

	s.mu.Lock()
	s.connected[nodeName] = stream
	s.mu.Unlock()

	s.events <- firstMsg // Send Heartbeat as event

	for {
		msg, err := stream.Recv()
		if err != nil {
			s.mu.Lock()
			delete(s.connected, nodeName)
			s.mu.Unlock()
			return err
		}
		if ack := msg.GetAck(); ack != nil {
			s.cmdResponses <- ack
		} else {
			s.events <- msg
		}
	}
}

func (s *MockController) SendCommand(nodeName string, cmd *pb.ControllerCmd) error {
	s.mu.Lock()
	stream, ok := s.connected[nodeName]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("agent %s not connected", nodeName)
	}
	return stream.Send(cmd)
}

// ================= E2E Test =================

const (
	TestLimitRate = 30 * 1000 * 1000 // 30 Mbps
	HostGrpcPort  = "9090"
)

func TestGRPCAndTrafficControl(t *testing.T) {
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

	// 2. Start Mock Controller
	mockCtrl := NewMockController()
	lis, err := net.Listen("tcp", "0.0.0.0:"+HostGrpcPort)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterSimulationAgentServiceServer(grpcServer, mockCtrl)
	reflection.Register(grpcServer)

	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	// 3. Patch Agent Config
	hostIP := GetHostLANIP(t)
	t.Logf(">>> Mock Server at %s:%s", hostIP, HostGrpcPort)

	t.Log("!!! IMPORTANT: Ensure Host Firewall allows port 9090 from Docker Bridge !!!")
	t.Logf("!!! Run: sudo ufw allow 9090/tcp || sudo iptables -I INPUT -p tcp --dport 9090 -j ACCEPT")

	patchCmd := exec.Command("kubectl", "set", "env", "daemonset/kuro-agent", "-n", AgentNamespace,
		fmt.Sprintf("CONTROLLER_ADDR=%s:%s", hostIP, HostGrpcPort),
		fmt.Sprintf("NO_PROXY=%s,localhost,127.0.0.1,.svc,.cluster.local", hostIP),
	)
	if err := patchCmd.Run(); err != nil {
		t.Fatal("Failed to patch agent env")
	}

	t.Log(">>> Waiting for Agent rollout...")
	exec.Command("kubectl", "rollout", "status", "daemonset/kuro-agent", "-n", AgentNamespace, "--timeout=60s").Run()

	t.Log(">>> Waiting for Agent Heartbeat...")
	var targetAgentNode string
	select {
	case msg := <-mockCtrl.events:
		if hb := msg.GetHeartbeat(); hb != nil {
			targetAgentNode = hb.NodeName
			t.Logf("PASS: Agent connected from %s", targetAgentNode)
		}
	case <-time.After(60 * time.Second):

		DumpAgentLogs(t, AgentNamespace)
		t.Fatal("Timeout waiting for agent connection. (Likely Firewall or Config Issue)")
	}

	// 4. Deploy Workloads (Utils)
	CleanupAndWait(t, clientset)
	defer CleanupAndWait(t, clientset)

	t.Log(">>> Deploying iperf...")
	serverPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ServerPodName, Labels: map[string]string{"app": "iperf-server"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "s", Image: IperfImage, Command: []string{"iperf3", "-s"}}}},
	}
	clientset.CoreV1().Pods(TargetNamespace).Create(ctx, serverPod, metav1.CreateOptions{})

	clientPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ClientPodName},
		Spec: corev1.PodSpec{
			NodeName:   targetAgentNode,
			Containers: []corev1.Container{{Name: "c", Image: IperfImage, Command: []string{"sleep", "3600"}}},
		},
	}
	clientset.CoreV1().Pods(TargetNamespace).Create(ctx, clientPod, metav1.CreateOptions{})

	WaitPodRunning(t, clientset, ServerPodName)
	WaitPodRunning(t, clientset, ClientPodName)

	// 5. Test Traffic
	srvPod, _ := clientset.CoreV1().Pods(TargetNamespace).Get(ctx, ServerPodName, metav1.GetOptions{})
	srvIP := srvPod.Status.PodIP

	// Step 5.1: Whitelist Server IP (Mock Controller -> Agent)
	t.Logf(">>> Whitelisting Server IP: %s", srvIP)
	syncCmd := &pb.ControllerCmd{
		CommandId: "sync-1",
		Payload: &pb.ControllerCmd_SyncPeers{
			SyncPeers: &pb.SyncPeerWhitelist{PeerIps: []string{srvIP}},
		},
	}
	mockCtrl.SendCommand(targetAgentNode, syncCmd)

	select {
	case ack := <-mockCtrl.cmdResponses:
		if !ack.Success {
			t.Fatalf("Whitelist failed: %s", ack.Message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for Whitelist ACK")
	}

	// Step 5.2: Apply Rate Limit
	t.Log(">>> Applying Rate Limit...")
	limitCmd := &pb.ControllerCmd{
		CommandId: "limit-1",
		Payload: &pb.ControllerCmd_ApplyPolicy{
			ApplyPolicy: &pb.ApplyPodPolicy{
				PodName: ClientPodName,
				SimRate: &pb.RateLimit{UploadBps: TestLimitRate, DownloadBps: TestLimitRate},
			},
		},
	}
	mockCtrl.SendCommand(targetAgentNode, limitCmd)
	select {
	case ack := <-mockCtrl.cmdResponses:
		if !ack.Success {
			t.Fatalf("Limit failed: %s", ack.Message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for Limit ACK")
	}

	// Step 5.3: Verify
	bps := RunIperfRemote(t, ClientPodName, srvIP, false)
	VerifySpeed(t, bps, TestLimitRate, "gRPC Upload")
}
