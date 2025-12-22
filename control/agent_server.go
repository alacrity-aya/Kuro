package control

import (
	"time"

	pb "kuro/proto"
)

// AgentServer handles gRPC connections from agents.
type AgentServer struct {
	pb.UnimplementedAgentServiceServer
	registry *MemRegistry

	heartbeatTimeout time.Duration
	ackTimeout       time.Duration

	// channel to send traffic stats
	statsChan chan *ReportedStat

	// inject DB / aggregator / TSDB writer
}

type ReportedStat struct {
	HostName string
	Stats    *pb.TrafficStats
}

// NewAgentServer creates a new server with default timeouts.
func NewAgentServer(config map[string]*pb.ApplyNodeConfig) *AgentServer {
	return &AgentServer{
		registry:         NewMemRegistry(config),
		heartbeatTimeout: 30 * time.Second, // Standard heartbeat interval
		ackTimeout:       5 * time.Second,  // Time to wait for config ACK

		statsChan: make(chan *ReportedStat, 10000),
	}
}
