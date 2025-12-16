// Package spec convert pb.ApplyNodeConfig to local spec
package spec

import (
	"fmt"

	pb "kuro/proto"
)

func BuildTopoSpec(config *pb.ApplyNodeConfig) (*TopoSpec, error) {
	var spec TopoSpec

	var nodes []Node

	if config.Vxlan != nil {
		spec.Vxlan.ID = config.Vxlan.GetId()
		spec.Vxlan.Iface = config.Vxlan.GetIface()
		spec.Vxlan.Port = config.Vxlan.GetPort()
		spec.Vxlan.Remote = config.Vxlan.GetRemoteIp()
	}

	for _, n := range config.Nodes {
		node := Node{name: n.GetName(), nodetype: n.GetType(), ip: n.GetIp()}

		if n.GetType() == "exec" {
			node.exec = n.GetExec().GetExec()
			node.args = n.GetExec().GetArgs()
			node.cwd = n.GetExec().GetCwd()
		} else if n.GetType() == "container" {
			return nil, fmt.Errorf("node type container is not implemented")
		} else {
			return nil, fmt.Errorf("should be unreachable")
		}

		nodes = append(nodes, node)

	}

	spec.nodes = nodes

	return &spec, nil
}
