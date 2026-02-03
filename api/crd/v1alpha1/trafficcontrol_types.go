package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LinkPolicySpec struct {
	// e.g. "10Mbps"
	Bandwidth string `json:"bandwidth,omitempty"`
	// e.g. "50ms"
	Latency string `json:"latency,omitempty"`
	// e.g. "10ms"
	Jitter string `json:"jitter,omitempty"`
	// e.g. "0.5%"
	PacketLoss string `json:"packetLoss,omitempty"`
}

// TrafficControlSpec defines the desired state of TrafficControl
type TrafficControlSpec struct {
	Priority    int32                `json:"priority,omitempty"`
	Source      metav1.LabelSelector `json:"source"`
	Destination metav1.LabelSelector `json:"destination"`
	Policy      LinkPolicySpec       `json:"policy"`
}

// TrafficControlStatus defines the observed state of TrafficControl
type TrafficControlStatus struct {
	ActiveLinks int32 `json:"activeLinks"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// TrafficControl is the Schema for the trafficcontrols API
type TrafficControl struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TrafficControlSpec   `json:"spec,omitempty"`
	Status TrafficControlStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TrafficControlList contains a list of TrafficControl
type TrafficControlList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrafficControl `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TrafficControl{}, &TrafficControlList{})
}
