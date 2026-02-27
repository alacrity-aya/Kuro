package remote

import (
	"kuro/internal/domain"
)

// AgentHandler defines the interface for the Client to call Agent business logic.
// NOW: Completely decoupled from Protobuf.
type AgentHandler interface {
	// GetAgentStatus retrieves the current status of the Agent.
	GetAgentStatus() domain.Heartbeat

	// ApplyPolicy handles Pod-level policies.
	ApplyPolicy(cmd domain.PodPolicy) error

	// ApplyNodePolicy handles Node-level policies.
	ApplyNodePolicy(cmd domain.NodePolicy) error

	// ApplyLinkPolicy handles specific point-to-point link physics.
	ApplyLinkPolicy(cmd domain.LinkPolicy) error
	// ApplyProbeTask handles probe task assignments for RTT detection.
	ApplyProbeTask(task domain.ProbeTask) error

	// RemoveProbeTask handles probe task removal.
	RemoveProbeTask(removal domain.ProbeTaskRemoval) error
}
