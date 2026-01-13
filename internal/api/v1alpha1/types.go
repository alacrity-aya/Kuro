package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ==========================================
// ExperimentWorkload - kuro-workload.yaml
// ==========================================

type ExperimentWorkload struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec WorkloadSpec `json:"spec"`
}

type WorkloadSpec struct {
	Components []Component `json:"components"`
}

type Component struct {
	Name      string            `json:"name"`
	Replicas  int32             `json:"replicas"`
	Image     string            `json:"image"`
	Command   []string          `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Resources ResourceReqs      `json:"resources"`
}

type ResourceReqs struct {
	Limits   map[string]string `json:"limits,omitempty"`
	Requests map[string]string `json:"requests,omitempty"`
}

// ==========================================
// NetworkTopology - kuro-emulation.yaml
// ==========================================

type NetworkTopology struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec TopologySpec `json:"spec"`
}

type TopologySpec struct {
	Defaults GlobalDefaults `json:"defaults"`
	Nodes    []Node         `json:"nodes"`
	Links    []Link         `json:"links"`
}

type GlobalDefaults struct {
	PhysicalCapacity string `json:"physical_capacity"`
	BackgroundRate   string `json:"background_rate"`
	BackgroundBurst  string `json:"background_burst"`
}

type Node struct {
	Name   string      `json:"name"`
	Config *NodeConfig `json:"config,omitempty"`
}

type NodeConfig struct {
	PhysicalCapacity string `json:"physical_capacity,omitempty"`
	BackgroundRate   string `json:"background_rate,omitempty"`
}

type Link struct {
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Selector Selector `json:"selector"`
	QoS      QoS      `json:"qos"`
}

type Selector struct {
	Mode     string `json:"mode"`               // "topology_aware" or "manual"
	Protocol string `json:"protocol,omitempty"` // TCP, UDP, etc.
	DestPort int32  `json:"dest_port,omitempty"`
}

type QoS struct {
	Bandwidth   string `json:"bandwidth"`
	Burst       string `json:"burst"`
	ShapingType string `json:"shaping_type,omitempty"` // tbf, htb
	Latency     string `json:"latency,omitempty"`
	Jitter      string `json:"jitter,omitempty"`
	Loss        string `json:"loss,omitempty"`
}
