package utils

import (
	"fmt"
	"strings"

	"kuro/config"
	"kuro/manager"
	"kuro/netem"
)

func NetnsName(nodeName string) string {
	return "ns-" + nodeName
}

func NodeNameFromNetns(netns string) (string, error) {
	const prefix = "ns-"
	if !strings.HasPrefix(netns, prefix) {
		return "", fmt.Errorf("invalid netns name: %s", netns)
	}
	return netns[len(prefix):], nil
}

// EthName eth in host
func EthName(nodeName string) string {
	return "v-" + nodeName
}

func NodeNameFromEth(eth string) (string, error) {
	const prefix = "v-"
	if !strings.HasPrefix(eth, prefix) {
		return "", fmt.Errorf("invalid eth name: %s", eth)
	}
	return eth[len(prefix):], nil
}

// PeerEthName eth in node ns
func PeerEthName(nodeName string) string {
	return "p-" + nodeName
}

func NodeNameFromPeerEth(eth string) (string, error) {
	const prefix = "p-"
	if !strings.HasPrefix(eth, prefix) {
		return "", fmt.Errorf("invalid eth name: %s", eth)
	}
	return eth[len(prefix):], nil
}

func ConvertToSpecs(cfg config.HostConfig) ([]manager.ProgramSpec, []manager.RouteSpec, []netem.NetemSpec) {
	// TODO: parse vxlan
	var progSpecs []manager.ProgramSpec
	var netemSpecs []netem.NetemSpec

	for _, node := range cfg.Nodes {
		progSpec := manager.ProgramSpec{
			IfaceName: EthName(node.Name), // Assuming Node Name matches Host Interface Name
		}

		if node.TrafficShaping != nil {
			progSpec.RateLimit = &manager.RateLimitSpec{
				RateBytes:  node.TrafficShaping.RateBps,
				BurstBytes: node.TrafficShaping.BurstBytes,
			}
		}

		progSpecs = append(progSpecs, progSpec)

		if node.Netem != nil {
			netemSpec := netem.NetemSpec{
				NsName:      NetnsName(node.Name),
				IfaceName:   PeerEthName(node.Name),
				LatencyMs:   node.Netem.DelayMs,
				JitterMs:    node.Netem.JitterMs,
				LossPercent: node.Netem.LossPct,
			}

			netemSpecs = append(netemSpecs, netemSpec)
		}

	}

	var routeSpecs []manager.RouteSpec
	for _, r := range cfg.Routes {
		routeSpecs = append(routeSpecs, manager.RouteSpec{
			DestIP:     r.DestIP,
			TargetNode: r.OutNode,
		})
	}

	return progSpecs, routeSpecs, netemSpecs
}
