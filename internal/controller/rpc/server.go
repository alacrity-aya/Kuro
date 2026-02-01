package rpc

import (
	"fmt"
	"io"
	"log"
	"sync"

	pb "kuro/api/v1"
	"kuro/internal/domain"
)

// AgentManager defines the business interface for the Controller layer (Pure Domain)
type AgentManager interface {
	RegisterAgent(nodeName string, sender domain.AgentSender)
	UnregisterAgent(nodeName string)
	HandleHeartbeat(nodeName string, hb domain.Heartbeat)
	HandlePodEvent(nodeName string, event domain.PodEvent)
	HandleAck(nodeName string, ack domain.CommandAck)
}

// =============================================================
// gRPC Stream Adapter (Implements domain.AgentSender)
// =============================================================

// GrpcStreamSender wraps the gRPC stream, implements the domain.AgentSender interface,
// and handles concurrent write safety.
type GrpcStreamSender struct {
	stream pb.SimulationAgentService_ControlStreamServer
	mu     sync.Mutex
}

func (s *GrpcStreamSender) Send(cmd domain.ControllerCommand) error {
	// 1. Domain -> Proto
	pbCmd := ToProtoCommand(cmd)

	// 2. Thread-safe Send
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(pbCmd)
}

func (s *GrpcStreamSender) Close() {
	// The gRPC server stream ends when the context is cancelled;
	// no manual close is required here, so this is left empty.
}

// =============================================================
// Server Implementation
// =============================================================

type Server struct {
	pb.UnimplementedSimulationAgentServiceServer
	manager AgentManager
}

func NewServer(manager AgentManager) *Server {
	return &Server{
		manager: manager,
	}
}

func (s *Server) ControlStream(stream pb.SimulationAgentService_ControlStreamServer) error {
	// 1. Initial Handshake (Wait for Heartbeat)
	firstMsg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive initial heartbeat: %w", err)
	}

	pbHb := firstMsg.GetHeartbeat()
	if pbHb == nil {
		return fmt.Errorf("protocol violation: first message must be Heartbeat")
	}

	nodeName := pbHb.NodeName
	if nodeName == "" {
		return fmt.Errorf("protocol violation: node name cannot be empty")
	}

	log.Printf("[RPC] Node connected: %s (IP: %s)", nodeName, pbHb.NodeIp)

	// 2. Create Sender Adapter and Register
	sender := &GrpcStreamSender{stream: stream}
	s.manager.RegisterAgent(nodeName, sender)

	defer func() {
		log.Printf("[RPC] Node disconnected: %s", nodeName)
		s.manager.UnregisterAgent(nodeName)
	}()

	// Process Initial Heartbeat (Proto -> Domain)
	s.manager.HandleHeartbeat(nodeName, FromProtoHeartbeat(pbHb))

	// 3. Receive Loop
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Printf("[RPC] Stream error for %s: %v", nodeName, err)
			return err
		}

		// Dispatch (Proto -> Domain)
		switch payload := msg.Payload.(type) {
		case *pb.AgentMsg_Heartbeat:
			s.manager.HandleHeartbeat(nodeName, FromProtoHeartbeat(payload.Heartbeat))
		case *pb.AgentMsg_PodEvent:
			s.manager.HandlePodEvent(nodeName, FromProtoPodEvent(payload.PodEvent))
		case *pb.AgentMsg_Ack:
			s.manager.HandleAck(nodeName, FromProtoAck(payload.Ack))
		default:
			log.Printf("[RPC] Unknown message type from %s", nodeName)
		}
	}
}
