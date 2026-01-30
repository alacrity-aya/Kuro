package rpc

import (
	"fmt"
	"io"
	"log"

	pb "kuro/api/v1"
)

// AgentManager defines the methods the gRPC server needs to interact with the Controller logic.
type AgentManager interface {
	// RegisterAgent stores the active stream for a node.
	RegisterAgent(nodeName string, stream pb.SimulationAgentService_ControlStreamServer)
	// UnregisterAgent removes the stream when disconnected.
	UnregisterAgent(nodeName string)
	// HandleHeartbeat processes status updates from agents.
	HandleHeartbeat(nodeName string, hb *pb.Heartbeat)
	// HandlePodEvent processes topology changes detected by agents.
	HandlePodEvent(nodeName string, event *pb.PodLifecycleEvent)
	// HandleAck processes command acknowledgements.
	HandleAck(nodeName string, ack *pb.CommandAck)
}

// Server implements the gRPC SimulationAgentService.
type Server struct {
	pb.UnimplementedSimulationAgentServiceServer
	manager AgentManager
}

// NewServer creates a new gRPC server instance.
func NewServer(manager AgentManager) *Server {
	return &Server{
		manager: manager,
	}
}

// ControlStream handles the bidirectional stream between Agent and Controller.
func (s *Server) ControlStream(stream pb.SimulationAgentService_ControlStreamServer) error {
	// 1. Wait for the initial Heartbeat to register the node.
	// We expect the first message to be a Heartbeat containing the NodeName.
	firstMsg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive initial heartbeat: %w", err)
	}

	hb := firstMsg.GetHeartbeat()
	if hb == nil {
		return fmt.Errorf("protocol violation: first message must be Heartbeat")
	}

	nodeName := hb.NodeName
	if nodeName == "" {
		return fmt.Errorf("protocol violation: node name cannot be empty")
	}

	log.Printf("[RPC] Node connected: %s (IP: %s)", nodeName, hb.NodeIp)

	// 2. Register the stream in the manager
	s.manager.RegisterAgent(nodeName, stream)

	// Ensure cleanup on disconnect
	defer func() {
		log.Printf("[RPC] Node disconnected: %s", nodeName)
		s.manager.UnregisterAgent(nodeName)
	}()

	// Process the initial heartbeat
	s.manager.HandleHeartbeat(nodeName, hb)

	// 3. Start the Receive Loop
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Printf("[RPC] Stream error for %s: %v", nodeName, err)
			return err
		}

		// Dispatch based on payload type
		switch payload := msg.Payload.(type) {
		case *pb.AgentMsg_Heartbeat:
			s.manager.HandleHeartbeat(nodeName, payload.Heartbeat)
		case *pb.AgentMsg_PodEvent:
			s.manager.HandlePodEvent(nodeName, payload.PodEvent)
		case *pb.AgentMsg_Ack:
			s.manager.HandleAck(nodeName, payload.Ack)
		default:
			log.Printf("[RPC] Unknown message type from %s", nodeName)
		}
	}
}
