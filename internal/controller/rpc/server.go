package rpc

import (
	"io"
	"log"
	"sync"

	pb "kuro/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ControllerServer struct {
	pb.UnimplementedSimulationAgentServiceServer

	// Map: NodeName -> Stream
	agents sync.Map
}

func (s *ControllerServer) ControlStream(stream pb.SimulationAgentService_ControlStreamServer) error {
	// 1. Wait for the first heartbeat packet for registration
	firstMsg, err := stream.Recv()
	if err != nil {
		return err
	}
	hb := firstMsg.GetHeartbeat()
	if hb == nil {
		return status.Errorf(codes.InvalidArgument, "first message must be a heartbeat")
	}

	nodeName := hb.NodeName
	log.Printf("[Controller] Agent connected: %s", nodeName)

	// Register Stream
	s.agents.Store(nodeName, stream)
	defer s.agents.Delete(nodeName)

	// 2. Receiving Loop
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Printf("[Controller] Error receiving from %s: %v", nodeName, err)
			return err
		}

		switch payload := msg.Payload.(type) {
		case *pb.AgentMsg_Heartbeat:
			// Update status
		case *pb.AgentMsg_PodEvent:
			// Handle Pod changes -> Update Global Map -> Trigger SyncPeerWhitelist
			log.Printf("Pod Event from %s: %v", nodeName, payload.PodEvent)
		case *pb.AgentMsg_Ack:
			// Handle command acknowledgment (ACK)
		}
	}
}

// SendCommand Example method: To be called by other Controller components
func (s *ControllerServer) SendCommand(nodeName string, cmd *pb.ControllerCmd) {
	val, ok := s.agents.Load(nodeName)
	if !ok {
		return
	}
	stream := val.(pb.SimulationAgentService_ControlStreamServer)
	if err := stream.Send(cmd); err != nil {
		log.Printf("[Controller] Failed to send command to %s: %v", nodeName, err)
	}
}

