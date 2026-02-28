package remote

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	pb "kuro/api/proto/v1"
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

func (m *MockAgentHandler) GetAgentStatus() domain.Heartbeat {
	return domain.Heartbeat{
		NodeName:        "test-node",
		ManagedPodCount: 10,
	}
}

func (m *MockAgentHandler) ApplyPolicy(cmd domain.PodPolicy) error {
	m.LastPodPolicy = cmd
	m.PolicyApplied = true
	return nil
}

func (m *MockAgentHandler) ApplyNodePolicy(cmd domain.NodePolicy) error {
	m.LastNodePolicy = cmd
	return nil
}

func (m *MockAgentHandler) ApplyLinkPolicy(cmd domain.LinkPolicy) error {
	m.LastLinkPolicy = cmd
	m.LinkPolicyApplied = true
	return nil
}

func (m *MockAgentHandler) ApplyProbeTask(task domain.ProbeTask) error {
	return nil
}

func (m *MockAgentHandler) RemoveProbeTask(removal domain.ProbeTaskRemoval) error {
	return nil
}

// MockControllerServer simulates the Controller's gRPC service
type MockControllerServer struct {
	pb.UnimplementedSimulationAgentServiceServer
	receivedMsgs chan *pb.AgentMsg
	cmdCh        chan *pb.ControllerCmd
}

func NewMockControllerServer() *MockControllerServer {
	return &MockControllerServer{
		receivedMsgs: make(chan *pb.AgentMsg, 100),
		cmdCh:        make(chan *pb.ControllerCmd, 100),
	}
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
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		s.receivedMsgs <- msg
	}
}

// --- Test Setup ---

const bufSize = 1024 * 1024

func TestClientCommunication(t *testing.T) {
	// 1. Setup InMemory Listener
	lis := bufconn.Listen(bufSize)
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	// 2. Setup Mock Controller Server
	s := grpc.NewServer()
	mockController := NewMockControllerServer()
	pb.RegisterSimulationAgentServiceServer(s, mockController)

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Printf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	// 3. Setup Agent Client with Mock Domain Handler
	mockAgent := &MockAgentHandler{}

	// Create Client but DON'T Start yet
	// Note: NewClient doesn't dial, Start() does.
	client, err := NewClient("passthrough:///bufnet", "test-node", mockAgent)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// 4. Inject Custom Dialer into the Client (Advanced)
	// Since NewClient uses grpc.NewClient internally with default options,
	// we need to override the connection creation logic OR allow NewClient to accept options.
	// However, for this test, we can manually overwrite the internal client.conn
	// IF we modify Client struct to allow injection, OR we can just use the address.
	// BUT `grpc.NewClient` creates the connection.
	// To make `client.go` testable with bufconn, we usually need to pass `grpc.DialOption`.

	// hack: We will manually Dial here and replace the conn in client struct
	// IF client.Start() allows it. But client.Start() creates its own conn.
	// SOLUTION: Modify NewClient to accept opts or just Re-implement Start logic for test.

	// A cleaner way without changing production code too much:
	// Let's manually overwrite the `conn` in the struct and call `connectionManager` directly
	// instead of `Start`. This is a "white-box" test approach.

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	client.conn = conn // Inject our bufconn connection

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the connection manager logic directly (white-box testing)
	go client.connectionManager(ctx)

	// --- Wait for Connection ---
	// Since connectionManager runs in a loop, we wait a bit for the stream to be established
	time.Sleep(500 * time.Millisecond)

	// --- Test Case 1: Heartbeat (Agent -> Controller) ---
	// connectionManager calls sendLoop which sends an initial heartbeat
	select {
	case msg := <-mockController.receivedMsgs:
		if hb := msg.GetHeartbeat(); hb != nil {
			if hb.ManagedPodCount != 10 {
				t.Errorf("Expected 10 pods, got %d", hb.ManagedPodCount)
			}
			t.Log("✓ Initial Heartbeat received")
		} else {
			// It might be possible we get something else first if events were queued,
			// but here heartbeat is the first thing sent.
			t.Logf("Received message type: %T", msg.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for initial heartbeat")
	}

	// --- Test Case 2: Send Event (Agent -> Controller) ---
	event := domain.PodEvent{
		Type:      domain.EventAdd,
		PodName:   "pod-1",
		PodIP:     "10.0.0.1",
		Namespace: "default",
	}
	client.EnqueueEvent(event)

	select {
	case msg := <-mockController.receivedMsgs:
		// Drain potential heartbeats if they came fast
		if msg.GetHeartbeat() != nil {
			// grab next
			msg = <-mockController.receivedMsgs
		}

		if podEv := msg.GetPodEvent(); podEv != nil {
			if podEv.PodName != "pod-1" {
				t.Errorf("Expected pod-1, got %s", podEv.PodName)
			}
			if podEv.Type != pb.PodLifecycleEvent_ADDED {
				t.Errorf("Expected ADDED event type")
			}
			t.Log("✓ Pod Event received")
		} else {
			t.Errorf("Expected PodEvent, got %v", msg.Payload)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for event")
	}

	// --- Test Case 3: Receive ApplyPolicy Command (Controller -> Agent) ---
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

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	if !mockAgent.PolicyApplied {
		t.Error("AgentHandler.ApplyPolicy was not called")
	} else {
		t.Log("✓ ApplyPolicy handled locally")
	}
	if mockAgent.LastPodPolicy.SimRate.UploadBps != 1000 {
		t.Errorf("Expected UploadBps 1000, got %d", mockAgent.LastPodPolicy.SimRate.UploadBps)
	}

	// --- Test Case 4: Verify ACK (Agent -> Controller) ---
	// The client should have sent an ACK back
	select {
	case msg := <-mockController.receivedMsgs:
		// Drain heartbeats
		for msg.GetHeartbeat() != nil {
			msg = <-mockController.receivedMsgs
		}

		if ack := msg.GetAck(); ack != nil {
			if ack.CommandId != "cmd-1" || !ack.Success {
				t.Errorf("Invalid ACK received: %v", ack)
			}
			t.Log("✓ ACK received")
		} else {
			t.Errorf("Expected ACK, got %v", msg.Payload)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for ACK")
	}

	// Stop client
	client.Stop()
}
