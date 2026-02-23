package api

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ==================
// NetworkTopology
// ==================

// NetworkTopologyCreateRequest is the request body for creating a NetworkTopology
type NetworkTopologyCreateRequest struct {
	Name   string                     `json:"name"`
	Labels map[string]string          `json:"labels,omitempty"`
	Spec   NetworkTopologySpecRequest `json:"spec"`
}

// NetworkTopologySpecRequest is the spec portion of create request
type NetworkTopologySpecRequest struct {
	NodeGroups []NodeGroupRequest `json:"nodeGroups"`
}

// NodeGroupRequest represents a node group in the request
type NodeGroupRequest struct {
	Name     string            `json:"name"`
	Replicas int32             `json:"replicas"`
	Image    string            `json:"image"`
	Command  []string          `json:"command,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// ==================
// TrafficControl
// ==================

// TrafficControlCreateRequest is the request body for creating a TrafficControl
type TrafficControlCreateRequest struct {
	Name   string                    `json:"name"`
	Labels map[string]string         `json:"labels,omitempty"`
	Spec   TrafficControlSpecRequest `json:"spec"`
}

// TrafficControlUpdateRequest is the request body for updating a TrafficControl
type TrafficControlUpdateRequest struct {
	Spec TrafficControlSpecRequest `json:"spec"`
}

// TrafficControlSpecRequest is the spec portion of TrafficControl request
type TrafficControlSpecRequest struct {
	Source      metav1.LabelSelector `json:"source"`
	Destination metav1.LabelSelector `json:"destination"`
	Policy      LinkPolicyRequest    `json:"policy"`
}

// LinkPolicyRequest represents link policy in the request
type LinkPolicyRequest struct {
	Bandwidth  string `json:"bandwidth"`
	Latency    string `json:"latency"`
	Jitter     string `json:"jitter"`
	PacketLoss string `json:"packetLoss"`
}
