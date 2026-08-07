package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AgentMode is the ADK delegation mode for an LlmAgent.
// Maps to llmagent.Mode.
// +kubebuilder:validation:Enum=chat;task;single_turn
type AgentMode string

const (
	// ModeChat is the standard chat agent reachable via transfer_to_agent.
	ModeChat AgentMode = "chat"
	// ModeTask is a task agent that chats with the user to accomplish a task.
	ModeTask AgentMode = "task"
	// ModeSingleTurn is an agent that completes a task without chatting with
	// the user.
	ModeSingleTurn AgentMode = "single_turn"
)

// IncludeContents controls what parts of prior conversation history is
// received by the agent. Maps to llmagent.IncludeContents.
// +kubebuilder:validation:Enum=default;none
type IncludeContents string

const (
	// IncludeContentsDefault sends relevant conversation history to the agent.
	IncludeContentsDefault IncludeContents = "default"
	// IncludeContentsNone makes the agent operate solely on its current turn.
	IncludeContentsNone IncludeContents = "none"
)

// CrewMember defines an LlmAgent within a Crew. Maps to llmagent.Config.
type CrewMember struct {
	// Name must be unique within the crew. Cannot be "user".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Description of the agent's capability. The LLM uses this to determine
	// whether to delegate control. One-line is enough and preferred.
	// +optional
	Description string `json:"description,omitempty"`

	// Mode is the ADK delegation mode.
	// +kubebuilder:validation:Required
	Mode AgentMode `json:"mode"`

	// ModelRef references a ModelBackend resource for this agent.
	// If unset, falls back to the Crew-level modelRef.
	// +optional
	ModelRef string `json:"modelRef,omitempty"`

	// Instruction is the agent's system prompt. Supports {key} template
	// placeholders resolved from session state at runtime.
	// +optional
	Instruction string `json:"instruction,omitempty"`

	// SubAgents lists agent names within this crew that this agent can
	// delegate to. ADK auto-generates delegation tools for each.
	// +optional
	SubAgents []string `json:"subAgents,omitempty"`

	// Tools lists tool names available to this agent. When combined with
	// Toolsets, these are added alongside tools discovered from toolsets.
	// +optional
	Tools []string `json:"tools,omitempty"`

	// Toolsets lists MCPServer resource names whose tools are exposed to
	// this agent. The controller resolves each to a tool.Toolset.
	// +optional
	Toolsets []string `json:"toolsets,omitempty"`

	// OutputKey, when set, saves the agent's text reply to session state
	// under this key. Used to connect agents via shared state.
	// +optional
	OutputKey string `json:"outputKey,omitempty"`

	// GenerateContentConfig is the raw genai.GenerateContentConfig JSON
	// for model tuning (temperature, topP, maxOutputTokens, etc.).
	// +optional
	// +kubebuilder:validation:Type=object
	// +kubebuilder:pruning:PreserveUnknownFields
	GenerateContentConfig *apiextensionsv1.JSON `json:"generateContentConfig,omitempty"`

	// InputSchema is the JSON Schema for the agent's input when used as a tool.
	// +optional
	// +kubebuilder:validation:Type=object
	// +kubebuilder:pruning:PreserveUnknownFields
	InputSchema *apiextensionsv1.JSON `json:"inputSchema,omitempty"`

	// OutputSchema is the JSON Schema for the agent's output. When set,
	// the agent can only reply and cannot use tools or transfer.
	// +optional
	// +kubebuilder:validation:Type=object
	// +kubebuilder:pruning:PreserveUnknownFields
	OutputSchema *apiextensionsv1.JSON `json:"outputSchema,omitempty"`

	// IncludeContents controls what conversation history the agent receives.
	// +optional
	IncludeContents *IncludeContents `json:"includeContents,omitempty"`

	// DisallowTransferToParent prevents transferring to parent agent.
	// +optional
	DisallowTransferToParent *bool `json:"disallowTransferToParent,omitempty"`

	// DisallowTransferToPeers prevents transferring to peer agents.
	// +optional
	DisallowTransferToPeers *bool `json:"disallowTransferToPeers,omitempty"`
}

// CrewSpec defines the desired state of a Crew. Maps to runner.Config.
type CrewSpec struct {
	// AppName identifies this application. Used for session namespacing.
	// Defaults to the Crew resource name if unset.
	// +optional
	AppName string `json:"appName,omitempty"`

	// ModelRef references a ModelBackend resource. Used as the default
	// model for all members that don't specify their own modelRef.
	// +kubebuilder:validation:Required
	ModelRef string `json:"modelRef"`

	// Members defines the LlmAgents in this crew.
	// +kubebuilder:validation:MinItems=1
	Members []CrewMember `json:"members"`
}

// CrewStatus is the observed state of a Crew.
type CrewStatus struct {
	// Ready indicates whether the crew is fully configured and all
	// referenced ModelBackends and MCPServers are available.
	Ready bool `json:"ready,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.modelRef`
// +kubebuilder:printcolumn:name="Members",type=integer,JSONPath=`.spec.members`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`

// Crew describes a team of ADK LlmAgents backed by a runner.
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
