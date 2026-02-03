package domain

import "time"

// =======================
// Enums
// =======================

type EventType int

const (
	EventAdd EventType = iota
	EventModify
	EventDelete
)

// =======================
// Core Entities
// =======================

type Heartbeat struct {
	NodeName        string
	NodeIP          string
	ManagedPodCount int
	Timestamp       time.Time
}

type PodEvent struct {
	Type        EventType
	PodName     string
	Namespace   string
	PodIP       string
	ContainerID string
	HostIfIndex int32
	Timestamp   time.Time
}

type CommandAck struct {
	CommandID string
	Success   bool
	Message   string
	Timestamp time.Time
}

// =======================
// Policies
// =======================

type LinkPolicy struct {
	SrcIP             string
	DstIP             string
	BandwidthBps      uint64
	BaseLatencyNs     uint64
	JitterNs          uint64
	CorruptionRatePpm uint32
	QueueDepthNs      uint64
	IsDelete          bool // Helper flag to indicate deletion (policy == nil in proto)
}

type PodPolicy struct {
	PodName   string
	Namespace string
	SimRate   *RateLimit
	SysRate   *RateLimit
}

type RateLimit struct {
	UploadBps   uint64
	DownloadBps uint64
}

type NodePolicy struct {
	IngressLimitBps   uint64
	IngressBurstBytes uint64
}

// =======================
// Controller Commands
// =======================

// ControllerCommand represents a generic instruction sent from the Controller to an Agent.
type ControllerCommand struct {
	ID      string
	Payload any // Can be LinkPolicy, PodPolicy, or NodePolicy
}

// AgentSender defines the abstract interface for sending data to an Agent.
// This allows the Controller to remain agnostic of the underlying transport layer
// (e.g., whether it is a gRPC stream or a WebSocket).
type AgentSender interface {
	Send(cmd ControllerCommand) error
	Close() // Optional, used for resource cleanup
}
