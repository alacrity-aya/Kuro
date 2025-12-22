// Package control is kuro's control panel.
// It can control network topology, receives data from data panels and persists / aggregates them.
package control

import (
	"context"
	"io"
	"log/slog"
	"time"

	pb "kuro/proto"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ControlStream handles the bidirectional stream for agent registration and heartbeats.
// It acts as a state machine: Unregistered -> WaitingAck -> Online.
func (s *AgentServer) ControlStream(stream pb.AgentService_ControlStreamServer) error {
	ctx := stream.Context()
	var registeredHost string
	var isPendingAck bool // state flag: is waiting ApplyNodeConfig ack

	// Initialize timer with heartbeat timeout.
	timer := time.NewTimer(s.heartbeatTimeout)
	defer timer.Stop()

	// Ensure cleanup happens when the stream closes (error or EOF).
	defer func() {
		if registeredHost != "" {
			// Use a detached context for cleanup to ensure it runs even if stream context is cancelled.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.registry.UpdateHostState(cleanupCtx, registeredHost, false)
			slog.Info("agent connection closed", "host", registeredHost)
		}
	}()

	for {
		// Create a channel to receive messages from the blocking stream.Recv()
		type recvMsg struct {
			msg *pb.ClientMessage
			err error
		}
		msgChan := make(chan recvMsg, 1)

		// Launch a goroutine to read the next message.
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

			// Safely reset the timer
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(s.heartbeatTimeout)

			in := res.msg

			// --- Scene A: New connection (expecting Hello) ---
			if registeredHost == "" {
				hello := in.GetHello()
				if hello == nil {
					slog.Warn("protocol violation: expected Hello", "payload", in.Payload)
					return status.Error(codes.Unauthenticated, "protocol violation: expected Hello first")
				}

				config, err := s.registry.RegisterHost(ctx, hello)
				if err != nil {
					slog.Warn("registration failed", "host", hello.HostName, "err", err)
					// Using Internal or NotFound depending on logic, Internal is safer for generic errors.
					return status.Errorf(codes.Internal, "registration failed: %v", err)
				}

				if err := stream.Send(&pb.ServerMessage{
					Payload: &pb.ServerMessage_ApplyConfig{ApplyConfig: config},
				}); err != nil {
					return err
				}

				// Transition state: Wait for ACK
				registeredHost = hello.GetHostName()
				isPendingAck = true

				// Reset timer to a shorter duration specifically for ACK waiting
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(s.ackTimeout)

				continue
			}

			// --- Scene B: Received Hello, Waiting for ACK ---
			if isPendingAck {
				ack := in.GetAck()
				if ack == nil {
					// Protocol violation: Sending Heartbeat or Hello while Server expects ACK
					slog.Warn("protocol violation: expected Ack", "host", registeredHost, "payload", in.Payload)
					return status.Error(codes.FailedPrecondition, "expected ACK after config")
				}
				if !ack.Ok {
					return status.Errorf(codes.Internal, "client failed to apply config: %s", ack.Message)
				}

				// Success: Mark node as Online
				if err := s.registry.UpdateHostState(ctx, registeredHost, true); err != nil {
					return status.Errorf(codes.Internal, "failed to update state: %v", err)
				}

				isPendingAck = false
				// Timer was already reset to heartbeatTimeout at the start of select case
				slog.Info("node is now online", "host", registeredHost)
				continue
			}

			// --- Scene C: Normal Operation (Heartbeat) ---
			switch in.Payload.(type) {
			case *pb.ClientMessage_Heartbeat:
				// Respond to heartbeat
				err := stream.Send(&pb.ServerMessage{
					Payload: &pb.ServerMessage_Heartbeat{
						Heartbeat: &pb.Heartbeat{Timestamp: time.Now().UnixMilli()},
					},
				})
				if err != nil {
					return err
				}
			case *pb.ClientMessage_Hello:
				slog.Warn("duplicate hello received", "host", registeredHost)
			// TODO: Handle duplicate hello here
			default:
				// ignore other messages
			}

		case <-timer.C:
			// Differentiate timeout reasons based on state
			if isPendingAck {
				slog.Warn("ack timeout", "host", registeredHost)
				return status.Error(codes.DeadlineExceeded, "timeout waiting for ACK")
			}
			slog.Warn("heartbeat timeout", "host", registeredHost)
			return status.Error(codes.DeadlineExceeded, "heartbeat timeout")
		}
	}
}
