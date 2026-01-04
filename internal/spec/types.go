// Package spec provides spec for tc rule
package spec

import "github.com/vishvananda/netns"

type Spec struct {
	RateLimit RateLimitSpec
	Netem     NetemSpec

	NsHandle   netns.NsHandle
	IfaceIndex int
	PodName    string
}

type RateLimitSpec struct {
	RateBytes  uint64
	BurstBytes uint64
}

type NetemSpec struct {
	LatencyMs   float64
	JitterMs    float64
	LossPercent float64
}
