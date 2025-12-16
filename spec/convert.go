// Package spec convert pb.ApplyNodeConfig to local spec
package spec

import (
	"fmt"

	pb "kuro/proto"
	"kuro/utils"
)

// BuildSpecs trusts the arguments passed from control panel.
func BuildSpecs(config *pb.ApplyNodeConfig) (*Specs, error) {
	var progSpecs []ProgramSpec
	var netemSpecs []NetemSpec
	var routeSpecs []RouteSpec
	var topoSpec TopoSpec

	if config.Vxlan != nil {
		topoSpec.Vxlan.ID = config.Vxlan.GetId()
		topoSpec.Vxlan.Iface = config.Vxlan.GetIface()
		topoSpec.Vxlan.Port = config.Vxlan.GetPort()
		topoSpec.Vxlan.Remote = config.Vxlan.GetRemoteIp()
	}

	for _, node := range config.GetNodes() {

		// TopoSpec
		topoNode := TopoNode{Name: node.GetName(), Type: node.GetType(), IP: node.GetIp()}

		if node.GetType() == "exec" {
			topoNode.Exec = node.GetExec().GetExec()
			topoNode.Args = node.GetExec().GetArgs()
			topoNode.Cwd = node.GetExec().GetCwd()
		} else if node.GetType() == "container" {
			return nil, fmt.Errorf("node type container is not implemented")
		} else {
			return nil, fmt.Errorf("should be unreachable")
		}

		topoSpec.Nodes = append(topoSpec.Nodes, topoNode)

		// progSpecs
		progSpec := ProgramSpec{
			IfaceName: utils.EthName(node.Name),
		}

		if node.TrafficShaping != nil {
			progSpec.RateLimit = &RateLimitSpec{
				RateBytes:  node.TrafficShaping.RateBps,
				BurstBytes: node.TrafficShaping.BurstBytes,
			}
		}

		progSpecs = append(progSpecs, progSpec)

		// netemSpecs
		if node.Netem != nil {
			limit := node.Netem.Limit
			if limit == 0 {
				limit = 1000
			}

			netemSpec := NetemSpec{
				NsName:      utils.NetnsName(node.Name),
				IfaceName:   utils.PeerEthName(node.Name),
				LatencyMs:   node.Netem.DelayMs,
				JitterMs:    node.Netem.JitterMs,
				LossPercent: node.Netem.Loss,
				Limit:       limit,
			}

			netemSpecs = append(netemSpecs, netemSpec)
		}

		// routeSpecs
		routeSpec := RouteSpec{DestIP: node.Ip, TargetNode: node.Name}
		routeSpecs = append(routeSpecs, routeSpec)

	}

	return &Specs{progSpecs, routeSpecs, netemSpecs, topoSpec}, nil
}
