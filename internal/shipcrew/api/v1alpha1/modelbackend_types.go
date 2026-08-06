// Package v1alpha1 contains the CRD types for the Sovereignite ADK agent
// platform under adk.sovereignite.net/v1alpha1.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Provider identifies the model backend type.
// +kubebuilder:validation:Enum=gemini;openai;ollama
type Provider string

const (
	ProviderGemini Provider = "gemini"
	ProviderOpenAI Provider = "openai"
	ProviderOllama Provider = "ollama"
)

// ModelBackendSpec defines a model backend connection.
type ModelBackendSpec struct {
	// Provider is the model backend type.
	// +kubebuilder:validation:Required
	Provider Provider `json:"provider"`

	// Model is the model identifier (e.g. "gemini-2.0-flash", "gpt-4o", "llama3.1").
	// +kubebuilder:validation:Required
	Model string `json:"model"`

	// BaseURL overrides the default endpoint (required for ollama, optional for openai).
	// +optional
	BaseURL string `json:"baseURL,omitempty"`

	// APIKeyRef references a Kubernetes secret containing the API key.
	// +optional
	APIKeyRef *SecretKeyRef `json:"apiKeyRef,omitempty"`
}

// SecretKeyRef references a key in a Kubernetes Secret.
type SecretKeyRef struct {
	// Name is the secret name.
	Name string `json:"name"`
	// Key is the key within the secret.
	Key string `json:"key"`
}

// ModelBackendStatus is the observed state of a ModelBackend.
type ModelBackendStatus struct {
	// Ready indicates whether the backend is reachable and configured.
	Ready bool `json:"ready,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.provider`
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.model`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:resource:shortName=mb

// ModelBackend describes a model backend for ADK agents.
type ModelBackend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ModelBackendSpec   `json:"spec"`
	Status ModelBackendStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ModelBackendList contains a list of ModelBackend.
type ModelBackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ModelBackend `json:"items"`
}
