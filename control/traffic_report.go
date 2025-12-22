package control

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "kuro/proto"
)

// ReportTraffic placeholder
func (s *AgentServer) ReportTraffic(stream pb.AgentService_ReportTrafficServer) error {
	return status.Error(codes.Unimplemented, "not implemented yet")
}
