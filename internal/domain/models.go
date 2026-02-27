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
// Probe (RTT Detection)
// =======================

type ProbeType int

const (
	ProbeTypeSIM ProbeType = iota
	ProbeTypeSYS
)

func (p ProbeType) String() string {
	switch p {
	case ProbeTypeSIM:
		return "sim"
	case ProbeTypeSYS:
		return "sys"
	default:
		return "unknown"
	}
}

// ProbeTask defines a periodic RTT probe between two Pods.
type ProbeTask struct {
	TaskID          string
	SrcPod          string
	SrcIP           string
	DstPod          string
	DstIP           string
	Type            ProbeType
	IntervalSeconds int32
	TargetPort      int32 // 9090 for SIM, 9100 for SYS
}

// ProbeTaskRemoval identifies a probe task to remove.
type ProbeTaskRemoval struct {
	TaskID string
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

// TopologyResponse defines the response structure for GET /api/v1/topology
type TopologyResponse struct {
	Nodes []TopologyNode `json:"nodes"`
}

type TopologyNode struct {
	Name      string `json:"name"`      // Pod name (e.g., drone-group-hash-x5a)
	Group     string `json:"group"`     // Target group (e.g., drone)
	Namespace string `json:"namespace"` // Kubernetes namespace
	IP        string `json:"ip"`        // Pod IP address
	Status    string `json:"status"`    // Current phase: Running, Pending, etc.
}

// =======================
// API Response Types
// =======================

// ApiResponse wraps all API responses with success/error status
type ApiResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ListResult wraps paginated list responses
type ListResult struct {
	Items         any    `json:"items"`
	TotalCount    int    `json:"totalCount"`
	ContinueToken string `json:"continueToken,omitempty"`
}

// TopologyNodeViz represents a node for visualization
type TopologyNodeViz struct {
	ID      string            `json:"id"`      // Pod UID
	Name    string            `json:"name"`    // Pod name
	Role    string            `json:"role"`    // Node role: drone, gateway, etc.
	IP      string            `json:"ip"`      // Pod IP
	Labels  map[string]string `json:"labels"`
	Status  string            `json:"status"`  // running, pending, failed
	GroupID string            `json:"groupId"` // NodeGroup name
	X       *int              `json:"x,omitempty"`
	Y       *int              `json:"y,omitempty"`
}

// TopologyLink represents a link between two nodes
type TopologyLink struct {
	ID       string         `json:"id"`
	SourceID string         `json:"sourceId"`
	TargetID string         `json:"targetId"`
	Policy   *LinkPolicyViz `json:"policy,omitempty"`
	Status   string         `json:"status"` // active, inactive, pending
	Metrics  *LinkMetrics   `json:"metrics,omitempty"`
}

// LinkPolicyViz represents policy for visualization
type LinkPolicyViz struct {
	Bandwidth  string `json:"bandwidth"`  // e.g., "10Mbps"
	Latency    string `json:"latency"`    // e.g., "50ms"
	Jitter     string `json:"jitter"`     // e.g., "10ms"
	PacketLoss string `json:"packetLoss"` // e.g., "0.5%"
}

// LinkMetrics contains current metrics for a link
type LinkMetrics struct {
	BandwidthUsage   float64 `json:"bandwidthUsage"`   // 0-100
	CurrentLatency   float64 `json:"currentLatency"`   // ms
	CurrentJitter    float64 `json:"currentJitter"`    // ms
	PacketLossRate   float64 `json:"packetLossRate"`   // 0-100
	BytesPerSecond   float64 `json:"bytesPerSecond"`
	PacketsPerSecond float64 `json:"packetsPerSecond"`
}
