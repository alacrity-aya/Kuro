package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	pb "kuro/api/v1"
	"kuro/internal/controller"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Free ports for testing to avoid conflicts
const (
	testGrpcPort = 50051
	testHTTPPort = 50052
	testNodeName = "test-worker-node"
)

// TestControllerFlow performs a full integration test:
// 1. Starts Controller Server
// 2. Simulates an Agent connecting (gRPC)
// 3. Sends an HTTP Command to Controller
// 4. Verifies Agent receives the command via gRPC
func TestControllerFlow(t *testing.T) {
	// --- Step 1: Start Controller ---
	mgr := controller.NewControllerManager(testGrpcPort, testHTTPPort)

	// Run controller in a goroutine
	go func() {
		if err := mgr.Run(); err != nil {
			// It might fail if ports are taken, but for test logic we assume success
			t.Logf("Controller stopped: %v", err)
		}
	}()
	// Give it a moment to bind ports
	time.Sleep(100 * time.Millisecond)

	// --- Step 2: Simulate Agent Connection (gRPC) ---
	conn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", testGrpcPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to connect to controller: %v", err)
	}
	defer conn.Close()

	client := pb.NewSimulationAgentServiceClient(conn)
	stream, err := client.ControlStream(context.Background())
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}

	// Send Initial Heartbeat (Registration)
	initHb := &pb.AgentMsg{
		Timestamp: time.Now().UnixNano(),
		Payload: &pb.AgentMsg_Heartbeat{
			Heartbeat: &pb.Heartbeat{
				NodeName:        testNodeName, // CRITICAL: Identifies the stream
				NodeIp:          "127.0.0.1",
				ManagedPodCount: 5,
			},
		},
	}
	if err = stream.Send(initHb); err != nil {
		t.Fatalf("Failed to send handshake: %v", err)
	}

	// Channel to capture commands received by the Fake Agent
	commandCh := make(chan *pb.ControllerCmd, 1)

	// Start a goroutine to listen for commands from Controller
	go func() {
		for {
			cmd, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Logf("Stream recv error: %v", err)
				return
			}
			commandCh <- cmd
		}
	}()

	// Wait briefly to ensure registration is processed
	time.Sleep(100 * time.Millisecond)

	// --- Step 3: Trigger Command via HTTP ---

	// API Payload: Apply Pod Policy
	apiPayload := map[string]any{
		"node_name": testNodeName,
		"pod_name":  "nginx-pod",
		"namespace": "default",
		"sim_rate": map[string]int{
			"upload":   1024,
			"download": 2048,
		},
		"sys_rate": map[string]int{
			"upload":   1000000,
			"download": 1000000,
		},
	}
	body, _ := json.Marshal(apiPayload)

	resp, err := http.Post(
		fmt.Sprintf("http://localhost:%d/api/v1/policy/pod", testHTTPPort),
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("HTTP Error %d: %s", resp.StatusCode, string(bodyBytes))
	}
	resp.Body.Close()

	// --- Step 4: Verify Reception ---
	select {
	case cmd := <-commandCh:
		// Validate the command is what we expected
		payload, ok := cmd.Payload.(*pb.ControllerCmd_ApplyPolicy)
		if !ok {
			t.Fatalf("Received wrong command type: %T", cmd.Payload)
		}

		policy := payload.ApplyPolicy
		if policy.PodName != "nginx-pod" {
			t.Errorf("Expected PodName 'nginx-pod', got '%s'", policy.PodName)
		}
		if policy.SimRate.DownloadBps != 2048 {
			t.Errorf("Expected Download 2048, got %d", policy.SimRate.DownloadBps)
		}
		t.Logf("Success! Received command ID: %s", cmd.CommandId)

	case <-time.After(2 * time.Second):
		t.Fatal("Timeout: Fake Agent did not receive command from Controller")
	}
}

// TestWhitelistBroadcast verifies that a whitelist update without a node_name
// is broadcast to all connected agents.
func TestWhitelistBroadcast(t *testing.T) {
	// Re-init controller for clean state (using different ports to avoid TIME_WAIT issues)
	grpcPort := 50053
	httpPort := 50054
	mgr := controller.NewControllerManager(grpcPort, httpPort)
	go mgr.Run()
	time.Sleep(100 * time.Millisecond)

	// Helper to create a fake agent
	createAgent := func(name string) (pb.SimulationAgentService_ControlStreamClient, chan *pb.ControllerCmd) {
		conn, _ := grpc.NewClient(
			fmt.Sprintf("localhost:%d", grpcPort),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		client := pb.NewSimulationAgentServiceClient(conn)
		stream, _ := client.ControlStream(context.Background())

		// Handshake
		stream.Send(&pb.AgentMsg{
			Payload: &pb.AgentMsg_Heartbeat{
				Heartbeat: &pb.Heartbeat{NodeName: name},
			},
		})

		ch := make(chan *pb.ControllerCmd, 10)
		go func() {
			for {
				cmd, err := stream.Recv()
				if err != nil {
					return
				}
				ch <- cmd
			}
		}()
		return stream, ch
	}

	// Create 2 agents
	_, ch1 := createAgent("worker-1")
	_, ch2 := createAgent("worker-2")
	time.Sleep(100 * time.Millisecond) // Allow registration

	// Send Broadcast HTTP Request (no node_name)
	payload := map[string]any{
		"ips": []string{"10.0.0.1", "10.0.0.2"},
	}
	body, _ := json.Marshal(payload)
	http.Post(
		fmt.Sprintf("http://localhost:%d/api/v1/whitelist", httpPort),
		"application/json",
		bytes.NewBuffer(body),
	)

	// Verify both received it
	timeout := time.After(1 * time.Second)

	check := func(ch chan *pb.ControllerCmd, name string) {
		select {
		case cmd := <-ch:
			if _, ok := cmd.Payload.(*pb.ControllerCmd_SyncPeers); !ok {
				t.Errorf("%s received wrong command", name)
			}
		case <-timeout:
			t.Errorf("%s did not receive broadcast", name)
		}
	}

	check(ch1, "worker-1")
	check(ch2, "worker-2")
}
