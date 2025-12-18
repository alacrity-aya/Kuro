package control

import (
	"context"
	"net"
	"testing"
	"time"

	pb "kuro/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestAgentServer_ControlStream(t *testing.T) {
	testHost := "test-host"

	configs := map[string]*pb.ApplyNodeConfig{
		testHost: {
			HostName: testHost,
			Vxlan:    &pb.VxlanConfig{Vni: 100},
		},
	}
	server := NewAgentServer(configs)

	// start server
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterAgentServiceServer(s, server)
	go s.Serve(lis)
	defer s.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewAgentServiceClient(conn)

	stream, err := client.ControlStream(context.Background())
	if err != nil {
		t.Fatalf("open stream error: %v", err)
	}

	err = stream.Send(&pb.ClientMessage{
		Payload: &pb.ClientMessage_Hello{
			Hello: &pb.Hello{Ip: testHost, AgentVersion: "v1.0.0"},
		},
	})
	if err != nil {
		t.Fatal("send hello error: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}

	config := resp.GetApplyConfig()

	if config == nil || config.GetHostName() != "test-host" {
		t.Errorf("expected config for %s, got %v", testHost, config)
	}

	// --- 步骤 3: 发送 Ack ---
	err = stream.Send(&pb.ClientMessage{
		Payload: &pb.ClientMessage_Ack{
			Ack: &pb.Ack{Ok: true},
		},
	})
	if err != nil {
		t.Fatalf("send ack error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if !server.registry.h[testHost].online {
		t.Errorf("node should be online after ack")
	}

	// --- 步骤 4: 发送心跳 ---
	err = stream.Send(&pb.ClientMessage{
		Payload: &pb.ClientMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
		},
	})
	if err != nil {
		t.Fatalf("send heartbeat error: %v", err)
	}

	// 接收心跳回包
	heartbeatResp, err := stream.Recv()
	if err != nil || heartbeatResp.GetHeartbeat() == nil {
		t.Errorf("expected heartbeat response, got %v", heartbeatResp)
	}
}
