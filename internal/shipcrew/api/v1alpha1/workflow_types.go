package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NodeType identifies the kind of workflow node.
// +kubebuilder:validation:Enum=agent;function;hitl;route;join
type NodeType string

const (
	NodeTypeAgent    NodeType = "agent"
	NodeTypeFunction NodeType = "function"
	NodeTypeHITL     NodeType = "hitl"
	NodeTypeRoute    NodeType = "route"
	NodeTypeJoin     NodeType = "join"
)

// WorkflowSpec defines a graph-based workflow of agents and nodes.
type WorkflowSpec struct {
	// Nodes defines the execution nodes in the workflow graph.
	// +kubebuilder:validation:MinItems=1
	Nodes []WorkflowNode `json:"nodes"`

	// Edges defines the connections between nodes.
	// +kubebuilder:validation:MinItems=1
	Edges []WorkflowEdge `json:"edges"`

	// ModelRef references a ModelBackend for agent nodes that don't specify one.
	// +optional
	ModelRef string `json:"modelRef,omitempty"`
}

// WorkflowNode is a single node in the workflow graph.
type WorkflowNode struct {
	// Name uniquely identifies this node.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Type is the node type.
	// +kubebuilder:validation:Required
	Type NodeType `json:"type"`

	// AgentRef references a CrewMember by name (for agent nodes).
	// +optional
	AgentRef string `json:"agentRef,omitempty"`

	// Function is the function name to call (for function nodes).
	// +optional
	Function string `json:"function,omitempty"`

	// HITL configures human-in-the-loop behavior (for hitl nodes).
	// +optional
	HITL *HITLConfig `json:"hitl,omitempty"`

	// Route configures conditional routing (for route nodes).
	// +optional
	Route *RouteConfig `json:"route,omitempty"`
}

// HITLConfig configures a human-in-the-loop node.
type HITLConfig struct {
	// Message is the prompt displayed to the user.
	Message string `json:"message,omitempty"`

	// InterruptID identifies this HITL pause point.
	InterruptID string `json:"interruptID,omitempty"`
}

// RouteConfig configures conditional routing from a node.
type RouteConfig struct {
	// Field is the output field to route on.
	Field string `json:"field,omitempty"`
}

// WorkflowEdge connects two nodes in the workflow graph.
type WorkflowEdge struct {
	// From is the source node name. Use "START" for the entry point.
	From string `json:"from"`

	// To is the destination node name.
	To string `json:"to"`

	// Condition is an optional routing condition (for route nodes).
	// +optional
	Condition string `json:"condition,omitempty"`
}

// WorkflowStatus is the observed state of a Workflow.
type WorkflowStatus struct {
	// Ready indicates whether the workflow is valid and can execute.
	Ready bool `json:"ready,omitempty"`

	// NodeCount is the number of nodes in the workflow.
	NodeCount int `json:"nodeCount,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Nodes",type=integer,JSONPath=`.status.nodeCount`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:resource:shortName=wf

// Workflow describes a graph-based workflow of agents and execution nodes.
type Workflow struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WorkflowSpec   `json:"spec"`
	Status WorkflowStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WorkflowList contains a list of Workflow.
type WorkflowList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Workflow `json:"items"`
}
