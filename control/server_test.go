package control

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	pb "kuro/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type testEnv struct {
	server *AgentServer
	grpcS  *grpc.Server
	conn   *grpc.ClientConn
	client pb.AgentServiceClient
	addr   string
}

// setupTestEnvWithConfig helper creates a server with custom timeouts for faster testing
func setupTestEnvWithConfig(t *testing.T, configs map[string]*pb.ApplyNodeConfig, hbTimeout, ackTimeout time.Duration) *testEnv {
	ss := NewAgentServer(configs)
	// Override defaults for testing
	if hbTimeout > 0 {
		ss.heartbeatTimeout = hbTimeout
	}
	if ackTimeout > 0 {
		ss.ackTimeout = ackTimeout
	}

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
	// t.Parallel() // Optional: enable if logs don't get mixed up too badly
	slog.SetLogLoggerLevel(slog.LevelDebug)

	testHost := "test-host"
	defaultConfigs := map[string]*pb.ApplyNodeConfig{
		testHost: {HostName: testHost, Vxlan: &pb.VxlanConfig{Vni: 100}},
	}

	t.Run("Success", func(t *testing.T) {
		env := setupTestEnvWithConfig(t, defaultConfigs, 0, 0)
		defer env.teardown()

		stream, err := env.client.ControlStream(context.Background())
		if err != nil {
			t.Fatalf("failed to open stream: %v", err)
		}

		// 1. Send Hello
		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
			Hello: &pb.Hello{HostName: testHost, AgentVersion: "v1.0.0"},
		}})

		// 2. Expect Config
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("recv failed: %v", err)
		}
		if resp.GetApplyConfig() == nil {
			t.Fatal("expected config")
		}

		// 3. Send ACK
		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{Ack: &pb.Ack{Ok: true}}})

		// 4. Verification: Node should be online
		time.Sleep(50 * time.Millisecond) // wait for server to process
		info, exists := env.server.registry.GetInfo(testHost)
		if !exists || !info.online {
			t.Error("should be online after ACK")
		}

		// 5. Send Heartbeat
		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
		}})
		hResp, err := stream.Recv()
		if err != nil || hResp.GetHeartbeat() == nil {
			t.Errorf("heartbeat failed: %v", err)
		}
	})

	t.Run("WrongFirstMessage", func(t *testing.T) {
		env := setupTestEnvWithConfig(t, defaultConfigs, 0, 0)
		defer env.teardown()

		stream, _ := env.client.ControlStream(context.Background())

		// 1. Send Ack instead of Hello
		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{Ack: &pb.Ack{Ok: true}}})

		// 2. Expect immediate error (Stream closed)
		_, err := stream.Recv()

		// 3. Verify Error Code
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated error, got: %v", err)
		}
	})

	t.Run("NoAckReplyViolation", func(t *testing.T) {
		env := setupTestEnvWithConfig(t, defaultConfigs, 0, 0)
		defer env.teardown()

		stream, _ := env.client.ControlStream(context.Background())

		// 1. Send Hello
		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
			Hello: &pb.Hello{HostName: testHost, AgentVersion: "v1.0.0"},
		}})
		stream.Recv() // consume config

		// 2. Send Heartbeat instead of Ack
		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
		}})

		// 3. Expect FailedPrecondition error
		_, err := stream.Recv()
		if err == nil {
			t.Fatal("should fail due to protocol violation (missing ACK)")
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.FailedPrecondition {
			t.Errorf("expected FailedPrecondition error, got: %v", err)
		}
	})

	t.Run("AckReplyTimeout", func(t *testing.T) {
		// Set ACK timeout to 200ms
		env := setupTestEnvWithConfig(t, defaultConfigs, time.Second, 200*time.Millisecond)
		defer env.teardown()

		stream, _ := env.client.ControlStream(context.Background())

		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
			Hello: &pb.Hello{HostName: testHost, AgentVersion: "v1.0.0"},
		}})
		stream.Recv() // consume config

		// Wait longer than ackTimeout (200ms)
		time.Sleep(300 * time.Millisecond)

		// Try to read, should get DeadlineExceeded
		_, err := stream.Recv()
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if status.Code(err) != codes.DeadlineExceeded {
			t.Errorf("expected DeadlineExceeded, got: %v", err)
		}
	})

	t.Run("HeartbeatTimeout", func(t *testing.T) {
		// Set Heartbeat timeout to 500ms
		env := setupTestEnvWithConfig(t, defaultConfigs, 500*time.Millisecond, time.Second)
		defer env.teardown()

		stream, _ := env.client.ControlStream(context.Background())

		// Perform handshake
		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
			Hello: &pb.Hello{HostName: testHost, AgentVersion: "v1.0.0"},
		}})
		stream.Recv()
		stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{Ack: &pb.Ack{Ok: true}}})

		// Wait for heartbeat timeout
		time.Sleep(600 * time.Millisecond)

		_, err := stream.Recv()
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if status.Code(err) != codes.DeadlineExceeded {
			t.Errorf("expected DeadlineExceeded, got: %v", err)
		}
	})

	// New Test: Concurrent Clients
	t.Run("Concurrency", func(t *testing.T) {
		clientCount := 10
		// Generate config for multiple hosts
		configs := make(map[string]*pb.ApplyNodeConfig)
		for i := range clientCount {
			host := fmt.Sprintf("host-%d", i)
			configs[host] = &pb.ApplyNodeConfig{HostName: host, Vxlan: &pb.VxlanConfig{Vni: uint32(100 + i)}}
		}

		env := setupTestEnvWithConfig(t, configs, 2*time.Second, 2*time.Second)
		defer env.teardown()

		var wg sync.WaitGroup
		wg.Add(clientCount)

		for i := range clientCount {
			go func(id int) {
				defer wg.Done()
				host := fmt.Sprintf("host-%d", id)

				// Create a new client for each goroutine (simulating distinct agents)
				// NOTE: In real world, we would dial a new connection, but sharing conn is okay for multiplexing testing
				stream, err := env.client.ControlStream(context.Background())
				if err != nil {
					t.Errorf("client %d failed to open stream: %v", id, err)
					return
				}

				// Handshake
				stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Hello{
					Hello: &pb.Hello{HostName: host},
				}})

				resp, err := stream.Recv()
				if err != nil || resp.GetApplyConfig().HostName != host {
					t.Errorf("client %d config mismatch or error: %v", id, err)
					return
				}

				stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Ack{Ack: &pb.Ack{Ok: true}}})

				// Send a heartbeat
				stream.Send(&pb.ClientMessage{Payload: &pb.ClientMessage_Heartbeat{
					Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
				}})

				_, err = stream.Recv() // expect heartbeat ack
				if err != nil {
					t.Errorf("client %d heartbeat failed: %v", id, err)
				}
			}(i)
		}

		wg.Wait()

		// Verify all are online
		for i := range clientCount {
			host := fmt.Sprintf("host-%d", i)
			info, exists := env.server.registry.GetInfo(host)
			if !exists || !info.online {
				t.Errorf("host %s should be online", host)
			}
		}
	})
}
