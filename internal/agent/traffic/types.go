package traffic

type Spec struct {
	PodName    string
	IfaceIndex int
	IfaceName  string
	RateLimit  RateLimitSpec
	Netem      NetemSpec
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

type TrafficStats struct {
	PodName     string
	IfaceName   string
	CurrentSpec *Spec

	Ingress DirectionStats
	Egress  DirectionStats
}
