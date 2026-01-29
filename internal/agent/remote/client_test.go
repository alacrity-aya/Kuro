package remote

import (
	"context"
	"log"
	"net"
	"testing"
	"time"

	pb "kuro/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// --- Mocks ---

// MockAgentHandler simulates the Agent's business logic
type MockAgentHandler struct {
	PolicyApplied     bool
	WhitelistSynced   bool
	LastHeartbeatSent *pb.Heartbeat
}

func (m *MockAgentHandler) GetAgentStatus() *pb.Heartbeat {
	return &pb.Heartbeat{ManagedPodCount: 10}
}

func (m *MockAgentHandler) ApplyPolicy(cmd *pb.ApplyPodPolicy) error {
	m.PolicyApplied = true
	return nil
}

func (m *MockAgentHandler) ApplyNodePolicy(cmd *pb.ApplyNodePolicy) error {
	return nil
}

func (m *MockAgentHandler) SyncWhitelist(cmd *pb.SyncPeerWhitelist) error {
	m.WhitelistSynced = true
	return nil
}

// MockControllerServer simulates the Controller's gRPC service
type MockControllerServer struct {
	pb.UnimplementedSimulationAgentServiceServer
	cmdCh chan *pb.ControllerCmd
	msgCh chan *pb.AgentMsg
}

func (s *MockControllerServer) ControlStream(stream pb.SimulationAgentService_ControlStreamServer) error {
	// Sending goroutine: Reads commands from the channel and sends them to the Agent
	go func() {
		for cmd := range s.cmdCh {
			if err := stream.Send(cmd); err != nil {
				return
			}
		}
	}()

	// Receiving loop: Reads messages sent by the Agent
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
	// 1. Setup Mock Controller
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

	// 2. Setup Agent Client
	mockAgent := &MockAgentHandler{}
	client, err := NewClient("bufnet", "test-node", mockAgent)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use NewClient with the passthrough scheme to bypass DNS resolution for bufconn
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	client.conn = conn

	// Manually start the Stream for testing
	cl := pb.NewSimulationAgentServiceClient(conn)
	stream, err := cl.ControlStream(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	client.stream = stream

	// Start internal processing loops
	go client.recvLoop(stream)
	go client.sendLoop(ctx, stream)

	// --- Test Case 1: Heartbeat (Agent -> Controller) ---
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
	event := &pb.PodLifecycleEvent{
		Type:    pb.PodLifecycleEvent_ADDED,
		PodName: "pod-1",
		PodIp:   "10.0.0.1",
	}
	client.EnqueueEvent(event)

	select {
	case msg := <-mockController.msgCh:
		// Note: Heartbeats may arrive before the event; in a production test,
		// you might want to filter messages. For this test, we assume order.
		if podEv := msg.GetPodEvent(); podEv != nil {
			if podEv.PodName != "pod-1" {
				t.Errorf("Expected pod-1, got %s", podEv.PodName)
			}
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for event")
	}

	// --- Test Case 3: Receive Command (Controller -> Agent) ---
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

	// Allow a brief moment for goroutines to process
	time.Sleep(100 * time.Millisecond)

	if !mockAgent.PolicyApplied {
		t.Error("AgentHandler.ApplyPolicy was not called")
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
}

