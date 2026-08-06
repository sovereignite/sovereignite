package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AgentMode is the ADK collaboration mode for an agent.
// +kubebuilder:validation:Enum=chat;task;single_turn
type AgentMode string

const (
	ModeChat       AgentMode = "chat"
	ModeTask       AgentMode = "task"
	ModeSingleTurn AgentMode = "single_turn"
)

// CrewMember defines an agent in the crew.
type CrewMember struct {
	// Name is the agent name (e.g. "scout", "builder").
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Mode is the ADK collaboration mode.
	// +kubebuilder:validation:Required
	Mode AgentMode `json:"mode"`

	// Description is a short description of the agent's role.
	// +optional
	Description string `json:"description,omitempty"`

	// Instruction is the agent's system prompt.
	// +optional
	Instruction string `json:"instruction,omitempty"`

	// Tools is a list of tool names exposed to this agent.
	// +optional
	Tools []string `json:"tools,omitempty"`
}

// CrewSpec defines the desired state of a Crew.
type CrewSpec struct {
	// ModelRef references a ModelBackend resource.
	// +kubebuilder:validation:Required
	ModelRef string `json:"modelRef"`

	// Members defines the agents in the crew.
	// +kubebuilder:validation:MinItems=1
	Members []CrewMember `json:"members"`

	// RemoteWorkers references optional A2A remote agent endpoints.
	// +optional
	RemoteWorkers []RemoteWorkerRef `json:"remoteWorkers,omitempty"`
}

// RemoteWorkerRef describes an A2A remote agent.
type RemoteWorkerRef struct {
	// Name is the remote agent name.
	Name string `json:"name"`
	// Description is what the remote agent does.
	Description string `json:"description,omitempty"`
	// AgentCardURL is the A2A agent card source URL.
	AgentCardURL string `json:"agentCardURL"`
}

// CrewStatus is the observed state of a Crew.
type CrewStatus struct {
	// Ready indicates whether the crew is fully configured and operational.
	Ready bool `json:"ready,omitempty"`

	// ActiveRunID is the current or most recent run identifier.
	// +optional
	ActiveRunID string `json:"activeRunID,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.modelRef`
// +kubebuilder:printcolumn:name="Members",type=integer,JSONPath=`.spec.members`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`

// Crew describes a team of ADK agents.
type Crew struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CrewSpec   `json:"spec"`
	Status CrewStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CrewList contains a list of Crew.
type CrewList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Crew `json:"items"`
}
