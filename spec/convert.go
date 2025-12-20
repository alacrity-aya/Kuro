// Package spec convert pb.ApplyNodeConfig to local spec
package spec

import (
	"fmt"
	"log/slog"
	"strings"

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
		topoSpec.Vxlan = &Vxlan{
			ID:     config.Vxlan.GetVni(),
			Iface:  config.Vxlan.GetIface(),
			Port:   config.Vxlan.GetPort(),
			Remote: config.Vxlan.GetRemoteIp(),
		}
	}

	for _, node := range config.GetNodes() {

		// TopoSpec

		slog.Debug("GetNodeType", "type", strings.ToLower(node.GetType().String()))
		topoNode := TopoNode{Name: node.GetName(), IP: node.GetIp(), Type: strings.ToLower(node.GetType().String())}

		// TODO: support container
		switch v := node.Runtime.(type) {
		case *pb.NodeConfig_Exec:
			topoNode.Exec = v.Exec.GetExec()
			topoNode.Args = v.Exec.GetArgs()
			topoNode.Cwd = v.Exec.GetCwd()

		default:
			return nil, fmt.Errorf("node type: %s not supported yet", node.GetType().String())
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
