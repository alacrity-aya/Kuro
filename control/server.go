// Package control is kuro's control panel.
// It can control network topology, receives data from data panels and persists / aggregates them.
package control

import (
	"sync"

	pb "kuro/proto"
)

type AgentServer struct {
	pb.UnimplementedAgentServiceServer
	config map[string]*pb.ApplyNodeConfig

	mu sync.RWMutex
	// inject DB / aggregator / TSDB writer
}

func NewAgentServer(config map[string]*pb.ApplyNodeConfig) *AgentServer {
	return &AgentServer{config: config}
}

func ControlStream(stream pb.AgentService_ControlStreamServer) error {
	return nil
}

func ReportTraffic(stream pb.AgentService_ReportTrafficServer) error {
	return nil
}
