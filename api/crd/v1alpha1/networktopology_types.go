package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// UserProgram defines the code logic injected by the user
type UserProgram struct {
	// Source is the specific content of the code
	Source string `json:"source,omitempty"`
	// MountPath is the absolute path where the code is mounted inside the container
	MountPath string `json:"mountPath,omitempty"`
	// Filename is the name of the mounted file, e.g., "algo.py"
	Filename string `json:"filename,omitempty"`
}

type NodeGroup struct {
	Name     string            `json:"name"`
	Replicas int32             `json:"replicas"`
	Image    string            `json:"image"`
	Command  []string          `json:"command,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	// UserProgram allows users to inject code
	UserProgram *UserProgram `json:"userProgram,omitempty"`
}

// NetworkTopologySpec defines the desired state of NetworkTopology
type NetworkTopologySpec struct {
	NodeGroups []NodeGroup `json:"nodeGroups,omitempty"`
}

// NetworkTopologyStatus defines the observed state of NetworkTopology
type NetworkTopologyStatus struct {
	ReadyNodes int32 `json:"readyNodes"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NetworkTopology is the Schema for the networktopologies API
type NetworkTopology struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkTopologySpec   `json:"spec,omitempty"`
	Status NetworkTopologyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkTopologyList contains a list of NetworkTopology
type NetworkTopologyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkTopology `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkTopology{}, &NetworkTopologyList{})
}
