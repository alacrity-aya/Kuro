package remote

import (
	"context"
	"log"
	"net"
	"testing"
	"time"

	pb "kuro/api/v1"
	"kuro/internal/domain"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// --- Mocks ---

// MockAgentHandler simulates the Agent's business logic using DOMAIN types
type MockAgentHandler struct {
	LastPodPolicy  domain.PodPolicy
	LastLinkPolicy domain.LinkPolicy
	LastNodePolicy domain.NodePolicy

	PolicyApplied     bool
	LinkPolicyApplied bool
}

// [UPDATED] Interface Implementation using Domain
func (m *MockAgentHandler) GetAgentStatus() domain.Heartbeat {
	return domain.Heartbeat{
		NodeName:        "test-node",
		ManagedPodCount: 10,
	}
}

// [UPDATED] Interface Implementation using Domain
func (m *MockAgentHandler) ApplyPolicy(cmd domain.PodPolicy) error {
	m.LastPodPolicy = cmd
	m.PolicyApplied = true
	return nil
}

// [UPDATED] Interface Implementation using Domain
func (m *MockAgentHandler) ApplyNodePolicy(cmd domain.NodePolicy) error {
	m.LastNodePolicy = cmd
	return nil
}

// [UPDATED] Interface Implementation using Domain
func (m *MockAgentHandler) ApplyLinkPolicy(cmd domain.LinkPolicy) error {
	m.LastLinkPolicy = cmd
	m.LinkPolicyApplied = true
	return nil
}

// MockControllerServer simulates the Controller's gRPC service (Wire Level - Still PB)
type MockControllerServer struct {
	pb.UnimplementedSimulationAgentServiceServer
	cmdCh chan *pb.ControllerCmd
	msgCh chan *pb.AgentMsg
}

func (s *MockControllerServer) ControlStream(stream pb.SimulationAgentService_ControlStreamServer) error {
	go func() {
		for cmd := range s.cmdCh {
			if err := stream.Send(cmd); err != nil {
				return
			}
		}
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		s.msgCh <- msg
	}
}

// --- Test Setup ---

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	lis = bufconn.Listen(bufSize)
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func TestClientCommunication(t *testing.T) {
	// 1. Setup Mock Controller (Wire Level)
	s := grpc.NewServer()
	mockController := &MockControllerServer{
		cmdCh: make(chan *pb.ControllerCmd, 10),
		msgCh: make(chan *pb.AgentMsg, 10),
	}
	pb.RegisterSimulationAgentServiceServer(s, mockController)

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	// 2. Setup Agent Client with Mock Domain Handler
	mockAgent := &MockAgentHandler{}
	client, err := NewClient("bufnet", "test-node", mockAgent)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	client.conn = conn

	cl := pb.NewSimulationAgentServiceClient(conn)
	stream, err := cl.ControlStream(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	client.stream = stream

	go client.recvLoop(stream)
	go client.sendLoop(ctx, stream)

	// --- Test Case 1: Heartbeat (Agent -> Controller) ---
	// Assert that the domain heartbeat from MockAgent was converted to PB correctly
	select {
	case msg := <-mockController.msgCh:
		if hb := msg.GetHeartbeat(); hb == nil {
			t.Error("Expected Heartbeat message, got something else")
		} else {
			if hb.ManagedPodCount != 10 {
				t.Errorf("Expected 10 pods, got %d", hb.ManagedPodCount)
			}
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for heartbeat")
	}

	// --- Test Case 2: Send Event (Agent -> Controller) ---
	// Input: Domain Object
	event := domain.PodEvent{
		Type:      domain.EventAdd,
		PodName:   "pod-1",
		PodIP:     "10.0.0.1",
		Namespace: "default",
	}
	client.EnqueueEvent(event)

	// Output: PB Object (Verification)
	select {
	case msg := <-mockController.msgCh:
		if podEv := msg.GetPodEvent(); podEv != nil {
			if podEv.PodName != "pod-1" {
				t.Errorf("Expected pod-1, got %s", podEv.PodName)
			}
			if podEv.Type != pb.PodLifecycleEvent_ADDED {
				t.Errorf("Expected ADDED event type")
			}
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for event")
	}

	// --- Test Case 3: Receive ApplyPolicy Command (Controller -> Agent) ---
	// Input: PB Object (Network)
	cmd := &pb.ControllerCmd{
		CommandId: "cmd-1",
		Payload: &pb.ControllerCmd_ApplyPolicy{
			ApplyPolicy: &pb.ApplyPodPolicy{
				PodName: "pod-1",
				SimRate: &pb.RateLimit{UploadBps: 1000},
			},
		},
	}
	mockController.cmdCh <- cmd

	time.Sleep(100 * time.Millisecond)

	// Verification: Domain Object (Business Logic)
	if !mockAgent.PolicyApplied {
		t.Error("AgentHandler.ApplyPolicy was not called")
	}
	if mockAgent.LastPodPolicy.PodName != "pod-1" {
		t.Errorf("Expected PodName pod-1, got %s", mockAgent.LastPodPolicy.PodName)
	}
	if mockAgent.LastPodPolicy.SimRate.UploadBps != 1000 {
		t.Errorf("Expected UploadBps 1000, got %d", mockAgent.LastPodPolicy.SimRate.UploadBps)
	}

	// --- Test Case 4: Verify ACK (Agent -> Controller) ---
	select {
	case msg := <-mockController.msgCh:
		if ack := msg.GetAck(); ack != nil {
			if ack.CommandId != "cmd-1" || !ack.Success {
				t.Errorf("Invalid ACK received: %v", ack)
			}
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for ACK")
	}

	// --- Test Case 5: Receive ApplyLinkPolicy Command (Controller -> Agent) ---
	// Input: PB Object
	cmdLink := &pb.ControllerCmd{
		CommandId: "cmd-2",
		Payload: &pb.ControllerCmd_ApplyLinkPolicy{
			ApplyLinkPolicy: &pb.ApplyLinkPolicy{
				SrcIp: "10.0.0.1",
				DstIp: "10.0.0.2",
				Policy: &pb.LinkPolicy{
					BandwidthBps: 1000000,
				},
			},
		},
	}
	mockController.cmdCh <- cmdLink

	time.Sleep(100 * time.Millisecond)

	// Verification: Domain Object
	if !mockAgent.LinkPolicyApplied {
		t.Error("AgentHandler.ApplyLinkPolicy was not called")
	}
	if mockAgent.LastLinkPolicy.SrcIP != "10.0.0.1" {
		t.Errorf("Expected SrcIP 10.0.0.1, got %s", mockAgent.LastLinkPolicy.SrcIP)
	}
	if mockAgent.LastLinkPolicy.BandwidthBps != 1000000 {
		t.Errorf("Expected Bandwidth 1M, got %d", mockAgent.LastLinkPolicy.BandwidthBps)
	}
}
