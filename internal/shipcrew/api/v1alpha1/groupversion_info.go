// Package v1alpha1 contains API Schema definitions for adk.sovereignite.net v1alpha1.
//
// +kubebuilder:object:generate=true
// +groupName=adk.sovereignite.net
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the API group and version for this package.
	GroupVersion = schema.GroupVersion{Group: "adk.sovereignite.net", Version: "v1alpha1"}

	// SchemeBuilder is used to add Go types to the GroupVersionResource scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(&ModelBackend{}, &ModelBackendList{})
	SchemeBuilder.Register(&Crew{}, &CrewList{})
}
