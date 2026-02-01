package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	pb "kuro/api/v1"
	"kuro/internal/controller"
	"kuro/internal/controller/api"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	testGrpcPort = 50051
	testHTTPPort = 50052
	testNodeName = "test-worker-node"
)

func TestControllerLinkPolicyFlow(t *testing.T) {
	// 1. Start Controller (RPC Server)
	// no longer responsible for starting HTTP.
	mgr := controller.NewControllerManager(testGrpcPort)
	go func() {
		if err := mgr.RunAgentServer(); err != nil {
			t.Errorf("AgentServer failed: %v", err)
		}
	}()

	// 2. Start HTTP Server (API Layer)
	// [UPDATED] Start HTTP Server independently and inject the Manager dependency.
	httpServer := api.NewHTTPServer(mgr, testHTTPPort)
	go func() {
		if err := httpServer.Run(); err != nil {
			t.Errorf("HTTPServer failed: %v", err)
		}
	}()

	// Wait for services to start
	time.Sleep(100 * time.Millisecond)

	// 3. Simulate Agent (Real gRPC Client)
	// We still use the Protobuf (PB) client here because we are testing
	// whether the Wire Protocol issued by the Controller is correct.
	conn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", testGrpcPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to dial grpc: %v", err)
	}
	defer conn.Close()

	client := pb.NewSimulationAgentServiceClient(conn)
	stream, err := client.ControlStream(context.Background())
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}

	// Handshake
	stream.Send(&pb.AgentMsg{
		Payload: &pb.AgentMsg_Heartbeat{
			Heartbeat: &pb.Heartbeat{NodeName: testNodeName},
		},
	})

	// Command Listener (Async)
	cmdCh := make(chan *pb.ControllerCmd, 1)
	go func() {
		for {
			cmd, err := stream.Recv()
			if err != nil {
				return
			}
			cmdCh <- cmd
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// 4. Trigger Link Policy via HTTP
	// [UPDATED] JSON Payload must match the flattened structure in api/server.go
	payload := map[string]any{
		"node_name":       testNodeName,
		"src_ip":          "10.0.0.1",
		"dst_ip":          "10.0.0.2",
		"bandwidth_limit": 5000000,
		"base_latency_ns": 10000000,
		// "is_delete": false, // Optional, defaults to false
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(
		fmt.Sprintf("http://localhost:%d/api/v1/policy/link", testHTTPPort),
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP Error: %d", resp.StatusCode)
	}

	// 5. Verify Reception (Wire Protocol Check)
	select {
	case cmd := <-cmdCh:
		// Verify if the Controller correctly converted the Domain object back to a Proto object
		pl, ok := cmd.Payload.(*pb.ControllerCmd_ApplyLinkPolicy)
		if !ok {
			t.Fatalf("Wrong command type received: %T", cmd.Payload)
		}

		linkPl := pl.ApplyLinkPolicy
		if linkPl.SrcIp != "10.0.0.1" {
			t.Errorf("Expected SrcIP 10.0.0.1, got %s", linkPl.SrcIp)
		}

		// Check Policy details
		if linkPl.Policy == nil {
			t.Fatal("Expected Policy struct, got nil (Deletion?)")
		}
		if linkPl.Policy.BandwidthBps != 5000000 {
			t.Errorf("Expected BW 5Mbps, got %d", linkPl.Policy.BandwidthBps)
		}
		if linkPl.Policy.BaseLatencyNs != 10000000 {
			t.Errorf("Expected Latency 10ms, got %d", linkPl.Policy.BaseLatencyNs)
		}

	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for command")
	}
}
