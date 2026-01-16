package traffic

type Spec struct {
	PodName    string
	IfaceIndex int
	IfaceName  string

	Rules       []Rule
	DefaultRule Rule
}

type Rule struct {
	TargetIP string // e.g. 10.244.0.9
	Rate     RateLimitSpec
	Netem    NetemSpec
}
type RateLimitSpec struct {
	RateBytes  uint64
	BurstBytes uint64
}

type NetemSpec struct {
	LatencyMs   uint32
	JitterMs    uint32
	LossPercent float64 // 0.0 - 100.0
}

type DirectionStats struct {
	TotalBytes     uint64
	TotalPackets   uint64
	DroppedBytes   uint64
	DroppedPackets uint64

	InstantRateBps float64
	SmoothRateBps  float64
}

type LinkStats struct {
	RemoteIP string // e.g. 10.244.0.5
	Ingress  DirectionStats
	Egress   DirectionStats
}

type TrafficStats struct {
	PodName     string
	IfaceName   string
	CurrentSpec *Spec

	// ip address -> LinkStats
	Stats map[string]*LinkStats
}
