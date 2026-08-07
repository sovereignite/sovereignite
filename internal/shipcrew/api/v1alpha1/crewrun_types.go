package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StreamingMode controls how the runner streams responses. Maps to
// agent.StreamingMode.
// +kubebuilder:validation:Enum=none;sse
type StreamingMode string

const (
	// StreamingModeNone indicates no streaming.
	StreamingModeNone StreamingMode = "none"
	// StreamingModeSSE enables server-sent events streaming.
	StreamingModeSSE StreamingMode = "sse"
)

// CrewRunSpec defines a single execution request against a Crew.
// Maps to a runner.Run() invocation.
type CrewRunSpec struct {
	// CrewRef references the Crew resource to execute.
	// +kubebuilder:validation:Required
	CrewRef string `json:"crewRef"`

	// UserID identifies the user making this request. Used for session
	// namespacing and memory scoping.
	// +kubebuilder:validation:Required
	UserID string `json:"userID"`

	// SessionID identifies the conversation session. If empty, the
	// controller generates one. Sessions persist across CrewRun
	// invocations sharing the same sessionID.
	// +optional
	SessionID string `json:"sessionID,omitempty"`

	// Message is the user's input content. Maps to genai.Content.
	// The controller converts this to *genai.Content for runner.Run().
	// +kubebuilder:validation:Required
	Message MessageContent `json:"message"`

	// StreamingMode controls response streaming behavior.
	// +optional
	StreamingMode *StreamingMode `json:"streamingMode,omitempty"`

	// SaveInputBlobsAsArtifacts, when true, saves each part of the user
	// input that is a blob (e.g. images, files) as an artifact.
	// +optional
	SaveInputBlobsAsArtifacts *bool `json:"saveInputBlobsAsArtifacts,omitempty"`
}

// MessageContent represents user input content. Maps to genai.Content.
type MessageContent struct {
	// Text is the plain text content.
	// +optional
	Text string `json:"text,omitempty"`

	// Parts is raw JSON for complex content (multipart with inline data,
	// function calls, etc). When set, Text is ignored.
	// +optional
	// +kubebuilder:validation:Type=object
	// +kubebuilder:pruning:PreserveUnknownFields
	Parts *apiextensionsv1.JSON `json:"parts,omitempty"`
}

// CrewRunPhase represents the current phase of a CrewRun.
// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed
type CrewRunPhase string

const (
	CrewRunPhasePending   CrewRunPhase = "Pending"
	CrewRunPhaseRunning   CrewRunPhase = "Running"
	CrewRunPhaseSucceeded CrewRunPhase = "Succeeded"
	CrewRunPhaseFailed    CrewRunPhase = "Failed"
)

// CrewRunStatus is the observed state of a CrewRun.
type CrewRunStatus struct {
	// Phase is the current lifecycle phase.
	// +optional
	Phase CrewRunPhase `json:"phase,omitempty"`

	// SessionID is the resolved session ID used for this run.
	// +optional
	SessionID string `json:"sessionID,omitempty"`

	// Events contains the events emitted during the run. Each event
	// is the raw session.Event JSON.
	// +optional
	Events []apiextensionsv1.JSON `json:"events,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Crew",type=string,JSONPath=`.spec.crewRef`
// +kubebuilder:printcolumn:name="User",type=string,JSONPath=`.spec.userID`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:resource:shortName=crun

// CrewRun represents a single execution request against a Crew.
type CrewRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CrewRunSpec   `json:"spec"`
	Status CrewRunStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CrewRunList contains a list of CrewRun.
type CrewRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CrewRun `json:"items"`
}
