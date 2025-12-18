// Package control is kuro's control panel.
// It can control network topology, receives data from data panels and persists / aggregates them.
package control

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	pb "kuro/proto"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AgentServer struct { // heartbeat timeout 10s, ack timeout 10s
	pb.UnimplementedAgentServiceServer
	registry *MemRegistry

	heartbeatTimeout time.Duration

	// inject DB / aggregator / TSDB writer
}

func NewAgentServer(config map[string]*pb.ApplyNodeConfig) *AgentServer {
	return &AgentServer{registry: NewMemRegistry(config), heartbeatTimeout: 10 * time.Second}
}

// TODO: Implement dynamic push via channel
// FIXME: the following function is completely awful, refactor it

// ControlStream registers host
func (s *AgentServer) ControlStream(stream pb.AgentService_ControlStreamServer) error {
	ctx := stream.Context()
	var registeredHost string
	var isPendingAck bool // state flag: is waiting ApplyNodeConfig ack

	timer := time.NewTimer(s.heartbeatTimeout)
	defer timer.Stop()

	defer func() {
		if registeredHost != "" {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.registry.UpdateHostState(cleanupCtx, registeredHost, false)
			slog.Info("agent connection closed", "host", registeredHost)
		}
	}()

	for {
		type recvMsg struct {
			msg *pb.ClientMessage
			err error
		}
		msgChan := make(chan recvMsg, 1)

		go func() {
			m, e := stream.Recv()
			msgChan <- recvMsg{m, e}
		}()

		select {
		case <-ctx.Done():
			return ctx.Err()

		case res := <-msgChan:
			if res.err == io.EOF {
				return nil
			}
			if res.err != nil {
				return res.err
			}

			// reset heartbeat timer
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(s.heartbeatTimeout)

			in := res.msg

			// --- scene A: new connection without hello ---
			if registeredHost == "" {
				hello := in.GetHello()
				if hello == nil {
					_ = stream.Send(&pb.ServerMessage{Payload: &pb.ServerMessage_Error{
						Error: &pb.Error{Code: 401, Message: "Please send Hello first"},
					}})
					continue
				}

				config, err := s.registry.RegisterHost(ctx, hello)
				if err != nil {
					_ = stream.Send(&pb.ServerMessage{Payload: &pb.ServerMessage_Error{
						Error: &pb.Error{Code: 402, Message: err.Error()},
					}})
					continue
				}

				if err := stream.Send(&pb.ServerMessage{
					Payload: &pb.ServerMessage_ApplyConfig{ApplyConfig: config},
				}); err != nil {
					return err
				}

				// enter wait ack state
				registeredHost = hello.GetHostName()
				isPendingAck = true
				timer.Reset(10 * time.Second) // change to ack timeout
				continue
			}

			// --- scene B: received hello，waiting ACK ---
			if isPendingAck {
				ack := in.GetAck()
				if ack == nil {
					// protocol violation: must be ack
					return status.Error(codes.FailedPrecondition, "expected ACK after config")
				}
				if !ack.Ok {
					return fmt.Errorf("client failed to apply config: %s", ack.Message)
				}

				// success, online
				if err := s.registry.UpdateHostState(ctx, registeredHost, true); err != nil {
					return err
				}
				isPendingAck = false
				timer.Reset(s.heartbeatTimeout) // change to heartbeat timeout
				slog.Info("node is now online", "host", registeredHost)
				continue
			}

			// --- scene C: Heartbeat, etc. ---
			switch in.Payload.(type) {
			case *pb.ClientMessage_Heartbeat:
				_ = stream.Send(&pb.ServerMessage{
					Payload: &pb.ServerMessage_Heartbeat{
						Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
					},
				})
			case *pb.ClientMessage_Hello:
				slog.Warn("duplicate hello", "host", registeredHost)
			}

		case <-timer.C:
			// wait ack timeout
			if isPendingAck {
				return status.Error(codes.DeadlineExceeded, "timeout waiting for ACK")
			}
			// heartbeat timeout
			return status.Error(codes.DeadlineExceeded, "heartbeat timeout")
		}
	}
}

func (s *AgentServer) ReportTraffic(stream pb.AgentService_ReportTrafficServer) error {
	return nil
}
