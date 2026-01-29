package remote

import (
	pb "kuro/api/v1"
)

// AgentHandler defines the interface for the Client to call Agent business logic.
// This design ensures the "remote" package does not need to import "kuro/internal/agent",
// effectively avoiding circular dependencies.
type AgentHandler interface {
	// GetAgentStatus retrieves the current status of the Agent (used to construct heartbeats).
	GetAgentStatus() *pb.Heartbeat

	// ApplyPolicy handles Pod-level policies (e.g., Rate Limiting) received from the Controller.
	ApplyPolicy(cmd *pb.ApplyPodPolicy) error

	// ApplyNodePolicy handles Node-level policies (e.g., Ingress Protection) received from the Controller.
	ApplyNodePolicy(cmd *pb.ApplyNodePolicy) error

	// SyncWhitelist handles peer whitelist synchronization issued by the Controller.
	SyncWhitelist(cmd *pb.SyncPeerWhitelist) error
}
