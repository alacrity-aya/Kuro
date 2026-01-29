package controller

import (
	"io"
	"log"
	"sync"

	kurov1 "kuro/api/v1"

	"google.golang.org/grpc"
)

// SimulationServer implements the gRPC server for agents.
type SimulationServer struct {
	kurov1.UnimplementedSimulationAgentServiceServer

	// Thread-safe map to store connected agents
	// Key: NodeName, Value: Stream
	mu     sync.RWMutex
	agents map[string]kurov1.SimulationAgentService_ControlStreamServer
}

func NewSimulationServer() *SimulationServer {
	return &SimulationServer{
		agents: make(map[string]kurov1.SimulationAgentService_ControlStreamServer),
	}
}

// ControlStream handles the bidirectional streaming.
func (s *SimulationServer) ControlStream(stream kurov1.SimulationAgentService_ControlStreamServer) error {
	var nodeName string

	log.Println("[Controller] New connection attempt...")

	for {
		// 1. Receive message from Agent
		msg, err := stream.Recv()
		if err == io.EOF {
			log.Printf("[Controller] Agent %s disconnected (EOF)", nodeName)
			return nil
		}
		if err != nil {
			log.Printf("[Controller] Stream error from %s: %v", nodeName, err)
			s.removeAgent(nodeName)
			return err
		}

		// 2. Handle Payload
		switch payload := msg.Payload.(type) {
		case *kurov1.AgentMsg_Heartbeat:
			hb := payload.Heartbeat
			// Register connection on first heartbeat
			if nodeName == "" {
				nodeName = hb.NodeName
				s.registerAgent(nodeName, stream)
				log.Printf("[Controller] Agent Registered: %s (IP: %s, Pods: %d)", hb.NodeName, hb.NodeIp, hb.ManagedPodCount)
			}
			// Update liveness status (logic to be added)

		case *kurov1.AgentMsg_PodEvent:
			event := payload.PodEvent
			log.Printf("[Controller] Pod Event from %s: %s %s/%s IP=%s",
				nodeName, event.Type, event.Namespace, event.PodName, event.PodIp)
			// TODO: Update global topology cache
		}
	}
}

func (s *SimulationServer) registerAgent(name string, stream kurov1.SimulationAgentService_ControlStreamServer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[name] = stream
}

func (s *SimulationServer) removeAgent(name string) {
	if name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.agents, name)
	log.Printf("[Controller] Removed agent session: %s", name)
}

// RegisterGRPC registers this server with a grpc.Server instance
func (s *SimulationServer) RegisterGRPC(grpcServer *grpc.Server) {
	kurov1.RegisterSimulationAgentServiceServer(grpcServer, s)
}
