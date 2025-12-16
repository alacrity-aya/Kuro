package spec

// RateLimitSpec defines the parameters for Token Bucket
type RateLimitSpec struct {
	RateBytes  uint64
	BurstBytes uint64
}

// ProgramSpec defines how an interface should be managed
type ProgramSpec struct {
	IfaceName string
	RateLimit *RateLimitSpec
}

// RouteSpec defines a redirect rule: DestIP -> Target Interface Name
type RouteSpec struct {
	DestIP     string // e.g. "10.10.0.1" (Single IP for exact match map)
	TargetNode string // The interface name to redirect to
}

type Vxlan struct {
	ID     uint32
	Iface  string
	Port   uint32
	Remote string
}

type Node struct {
	name     string
	nodetype string
	ip       string

	// exec
	exec string
	args []string
	cwd  string

	// container
	image     string
	container string
}

type TopoSpec struct {
	Vxlan *Vxlan
	nodes []Node
}

type NetemSpec struct {
	NsName      string
	IfaceName   string
	LatencyMs   float64
	JitterMs    float64
	LossPercent float64
	Limit       uint32
}
