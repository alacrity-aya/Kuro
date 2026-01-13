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

type TrafficStats struct {
	PodName              string
	TotalAcceptedBytes   uint64
	TotalDroppedBytes    uint64
	TotalAcceptedPackets uint64
	TotalDroppedPackets  uint64
	InstantRateBps       float64
	SmoothRateBps        float64

	// for WatchStatus
	IfaceName   string
	CurrentSpec *Spec
}
