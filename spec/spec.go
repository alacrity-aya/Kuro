package spec

type Specs struct {
	ProgramSpecs []ProgramSpec
	RouteSpecs   []RouteSpec
	NetemSpecs   []NetemSpec
	TopoSpec     TopoSpec
}

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

type TopoNode struct {
	Name string
	Type string
	IP   string

	// Exec
	Exec string
	Args []string
	Cwd  string

	// container
	Image     string
	Container string
}

type TopoSpec struct {
	Vxlan *Vxlan
	Nodes []TopoNode
}

type NetemSpec struct {
	NsName      string
	IfaceName   string
	LatencyMs   float64
	JitterMs    float64
	LossPercent float64
}
