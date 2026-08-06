// Package v1alpha1 contains API Schema definitions for adk.sovereignite.net v1alpha1.
//
// +kubebuilder:object:generate=true
// +groupName=adk.sovereignite.net
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the API group and version for this package.
	GroupVersion = schema.GroupVersion{Group: "adk.sovereignite.net", Version: "v1alpha1"}

	// SchemeBuilder is used to add Go types to the runtime scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&ModelBackend{},
		&ModelBackendList{},
		&Crew{},
		&CrewList{},
		&CrewRun{},
		&CrewRunList{},
		&MCPServer{},
		&MCPServerList{},
		&Workflow{},
		&WorkflowList{},
	)
	return nil
}
