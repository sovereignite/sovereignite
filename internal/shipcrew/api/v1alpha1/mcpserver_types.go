package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MCPTransport is the transport type for connecting to an MCP server.
// Maps to mcp.Transport implementations in mcptoolset.
// +kubebuilder:validation:Enum=stdio;streamable-http;sse
type MCPTransport string

const (
	// MCPTransportStdio runs a command and communicates via stdin/stdout.
	// Maps to mcp.CommandTransport.
	MCPTransportStdio MCPTransport = "stdio"
	// MCPTransportStreamableHTTP connects via streamable HTTP.
	// Maps to mcp.StreamableClientTransport.
	MCPTransportStreamableHTTP MCPTransport = "streamable-http"
	// MCPTransportSSE connects via server-sent events.
	// Maps to mcp.SSEClientTransport.
	MCPTransportSSE MCPTransport = "sse"
)

// MCPServerSpec defines an MCP server connection. Maps to mcptoolset.Config.
type MCPServerSpec struct {
	// Transport is the MCP transport type.
	// +kubebuilder:validation:Required
	Transport MCPTransport `json:"transport"`

	// Command is the binary and arguments for stdio transport.
	// First element is the binary path, rest are arguments.
	// +optional
	Command []string `json:"command,omitempty"`

	// Endpoint is the server URL for streamable-http or sse transport.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// Env is a list of environment variable references for the stdio
	// transport command process.
	// +optional
	Env []EnvVar `json:"env,omitempty"`

	// ToolFilter optionally restricts which tools are exposed from
	// this server. Maps to tool.AllowedToolsPredicate (allow) or
	// a deny predicate (deny).
	// +optional
	ToolFilter *ToolFilter `json:"toolFilter,omitempty"`

	// RequireConfirmation flags whether tools from this server must
	// always ask for user confirmation before execution.
	// +optional
	RequireConfirmation *bool `json:"requireConfirmation,omitempty"`
}

// EnvVar references an environment variable, optionally from a Secret.
type EnvVar struct {
	// Name is the environment variable name.
	Name string `json:"name"`
	// Value is a direct value. Mutually exclusive with ValueFrom.
	// +optional
	Value string `json:"value,omitempty"`
	// ValueFrom references a Secret key for the value.
	// +optional
	ValueFrom *EnvVarSource `json:"valueFrom,omitempty"`
}

// EnvVarSource references a Secret key.
type EnvVarSource struct {
	// SecretRef references a Secret key.
	SecretRef SecretKeyRef `json:"secretRef"`
}

// SecretKeyRef references a key in a Kubernetes Secret.
type SecretKeyRef struct {
	// Name is the secret name.
	Name string `json:"name"`
	// Key is the key within the secret.
	Key string `json:"key"`
}

// ToolFilter restricts which tools are exposed from an MCP server.
type ToolFilter struct {
	// Allow is an explicit allowlist of tool names. If set, only these
	// tools are exposed. Maps to tool.AllowedToolsPredicate.
	// +optional
	Allow []string `json:"allow,omitempty"`
	// Deny is a denylist of tool names. Ignored if Allow is set.
	// +optional
	Deny []string `json:"deny,omitempty"`
}

// MCPServerStatus is the observed state of an MCPServer.
type MCPServerStatus struct {
	// Ready indicates whether the server is reachable and tools have
	// been discovered.
	Ready bool `json:"ready,omitempty"`

	// DiscoveredTools is the list of tool names discovered from the server.
	// +optional
	DiscoveredTools []string `json:"discoveredTools,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Transport",type=string,JSONPath=`.spec.transport`
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.spec.endpoint`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:resource:shortName=mcp

// MCPServer describes an MCP server connection for ADK agents.
type MCPServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MCPServerSpec   `json:"spec"`
	Status MCPServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MCPServerList contains a list of MCPServer.
type MCPServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MCPServer `json:"items"`
}
