package control

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	pb "kuro/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type testEnv struct {
	server *AgentServer
	grpcS  *grpc.Server
	conn   *grpc.ClientConn
	client pb.AgentServiceClient
	addr   string
}

func setupTestEnv(t *testing.T, configs map[string]*pb.ApplyNodeConfig) *testEnv {
	s := NewAgentServer(configs)

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	grpcS := grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcS, s)
	go grpcS.Serve(lis)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}

	return &testEnv{
		server: s,
		grpcS:  grpcS,
		conn:   conn,
		client: pb.NewAgentServiceClient(conn),
		addr:   lis.Addr().String(),
	}
}

func setupTestEnvWithTimeout(t *testing.T, configs map[string]*pb.ApplyNodeConfig, time time.Duration) *testEnv {
	ss := &AgentServer{registry: NewMemRegistry(configs), heartbeatTimeout: time}

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	grpcS := grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcS, ss)
	go grpcS.Serve(lis)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}

	return &testEnv{
		server: ss,
		grpcS:  grpcS,
		conn:   conn,
		client: pb.NewAgentServiceClient(conn),
		addr:   lis.Addr().String(),
	}
}

func (e *testEnv) teardown() {
	e.conn.Close()
	e.grpcS.Stop()
}

func TestControlStream(t *testing.T) {
	t.Parallel()
	slog.SetLogLoggerLevel(slog.LevelDebug)
	testHost := "test-host"
	defaultConfigs := map[string]*pb.ApplyNodeConfig{
		testHost: {HostName: testHost, Vxlan: &pb.VxlanConfig{Vni: 100}},
	}

	t.Run("Success", func(t *testing.T) {
		env := setupTestEnv(t, defaultConfigs)
		defer env.teardown()

		stream, _ := env.client.ControlStream(context.Background())

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
			Hello: &pb.Hello{HostName: testHost, AgentVersion: "v1.0.0"},
		}})
		resp, _ := stream.Recv()
		if resp.GetApplyConfig() == nil {
			t.Fatal("expected config")
		}

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{Ack: &pb.Ack{Ok: true}}})

		time.Sleep(100 * time.Millisecond)
		info, _ := env.server.registry.GetInfo(testHost)
		if !info.online {
			t.Error("should be online")
		}

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
		}})
		hResp, err := stream.Recv()
		if err != nil || hResp.GetHeartbeat() == nil {
			t.Errorf("heartbeat failed: %v", err)
		}
	})

	t.Run("WrongFirstMessage", func(t *testing.T) {
		env := setupTestEnv(t, defaultConfigs)
		defer env.teardown()

		stream, _ := env.client.ControlStream(context.Background())

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{Ack: &pb.Ack{Ok: true}}})
		msg, _ := stream.Recv()
		if msg.GetError().GetCode() != 401 {
			t.Fatal("expected 401")
		}

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
		}})
		msg, _ = stream.Recv()
		if msg.GetError().GetCode() != 401 {
			t.Fatal("expected 401 again")
		}
	})

	t.Run("NoAckReplyViolation", func(t *testing.T) {
		env := setupTestEnv(t, defaultConfigs)
		defer env.teardown()

		stream, _ := env.client.ControlStream(context.Background())

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
			Hello: &pb.Hello{HostName: testHost, AgentVersion: "v1.0.0"},
		}})
		stream.Recv() // consume config

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
		}})

		_, err := stream.Recv()
		if err == nil {
			t.Fatal("should fail due to protocol violation (missing ACK)")
		}
	})

	t.Run("AckReplyTimeout", func(t *testing.T) {
		env := setupTestEnv(t, defaultConfigs)
		defer env.teardown()

		stream, _ := env.client.ControlStream(context.Background())

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
			Hello: &pb.Hello{HostName: testHost, AgentVersion: "v1.0.0"},
		}})
		stream.Recv() // consume config

		time.Sleep(7 * time.Second)

		_, err := stream.Recv()
		if err == nil {
			t.Fatal("expected timeout error")
		}
	})

	t.Run("HeartbeatTimeout", func(t *testing.T) {
		env := setupTestEnvWithTimeout(t, defaultConfigs, time.Second*1)
		defer env.teardown()

		stream, _ := env.client.ControlStream(context.Background())

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
			Hello: &pb.Hello{HostName: testHost, AgentVersion: "v1.0.0"},
		}})
		resp, _ := stream.Recv()
		if resp.GetApplyConfig() == nil {
			t.Fatal("expected config")
		}

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{Ack: &pb.Ack{Ok: true}}})

		time.Sleep(100 * time.Millisecond)
		info, _ := env.server.registry.GetInfo(testHost)
		if !info.online {
			t.Error("should be online")
		}

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
		}})
		hResp, err := stream.Recv()
		if err != nil || hResp.GetHeartbeat() == nil {
			t.Errorf("heartbeat failed: %v", err)
		}

		time.Sleep(2 * time.Second)

		_, err = stream.Recv()
		slog.Info("stream.Recv()", "error", err)
		if err == nil {
			t.Fatal("expected timeout error")
		}
	})
}
