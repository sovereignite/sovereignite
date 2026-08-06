package v1alpha1

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// --- ModelBackend ---

func (in *ModelBackend) DeepCopyInto(out *ModelBackend) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *ModelBackend) DeepCopy() *ModelBackend {
	if in == nil {
		return nil
	}
	out := new(ModelBackend)
	in.DeepCopyInto(out)
	return out
}

func (in *ModelBackend) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *ModelBackendSpec) DeepCopyInto(out *ModelBackendSpec) {
	*out = *in
	if in.APIKeyRef != nil {
		in, out := &in.APIKeyRef, &out.APIKeyRef
		*out = new(SecretKeyRef)
		**out = **in
	}
}

func (in *ModelBackendStatus) DeepCopyInto(out *ModelBackendStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *ModelBackendList) DeepCopyInto(out *ModelBackendList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ModelBackend, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *ModelBackendList) DeepCopy() *ModelBackendList {
	if in == nil {
		return nil
	}
	out := new(ModelBackendList)
	in.DeepCopyInto(out)
	return out
}

func (in *ModelBackendList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// --- Crew ---

func (in *Crew) DeepCopyInto(out *Crew) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *Crew) DeepCopy() *Crew {
	if in == nil {
		return nil
	}
	out := new(Crew)
	in.DeepCopyInto(out)
	return out
}

func (in *Crew) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *CrewSpec) DeepCopyInto(out *CrewSpec) {
	*out = *in
	if in.Members != nil {
		in, out := &in.Members, &out.Members
		*out = make([]CrewMember, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *CrewMember) DeepCopyInto(out *CrewMember) {
	*out = *in
	if in.SubAgents != nil {
		in, out := &in.SubAgents, &out.SubAgents
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Tools != nil {
		in, out := &in.Tools, &out.Tools
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Toolsets != nil {
		in, out := &in.Toolsets, &out.Toolsets
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.GenerateContentConfig != nil {
		in, out := &in.GenerateContentConfig, &out.GenerateContentConfig
		*out = new(apiextensionsv1.JSON)
		(*in).DeepCopyInto(*out)
	}
	if in.InputSchema != nil {
		in, out := &in.InputSchema, &out.InputSchema
		*out = new(apiextensionsv1.JSON)
		(*in).DeepCopyInto(*out)
	}
	if in.OutputSchema != nil {
		in, out := &in.OutputSchema, &out.OutputSchema
		*out = new(apiextensionsv1.JSON)
		(*in).DeepCopyInto(*out)
	}
	if in.IncludeContents != nil {
		in, out := &in.IncludeContents, &out.IncludeContents
		*out = new(IncludeContents)
		**out = **in
	}
	if in.DisallowTransferToParent != nil {
		in, out := &in.DisallowTransferToParent, &out.DisallowTransferToParent
		*out = new(bool)
		**out = **in
	}
	if in.DisallowTransferToPeers != nil {
		in, out := &in.DisallowTransferToPeers, &out.DisallowTransferToPeers
		*out = new(bool)
		**out = **in
	}
}

func (in *CrewStatus) DeepCopyInto(out *CrewStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *CrewList) DeepCopyInto(out *CrewList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Crew, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *CrewList) DeepCopy() *CrewList {
	if in == nil {
		return nil
	}
	out := new(CrewList)
	in.DeepCopyInto(out)
	return out
}

func (in *CrewList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// --- CrewRun ---

func (in *CrewRun) DeepCopyInto(out *CrewRun) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *CrewRun) DeepCopy() *CrewRun {
	if in == nil {
		return nil
	}
	out := new(CrewRun)
	in.DeepCopyInto(out)
	return out
}

func (in *CrewRun) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *CrewRunSpec) DeepCopyInto(out *CrewRunSpec) {
	*out = *in
	in.Message.DeepCopyInto(&out.Message)
	if in.StreamingMode != nil {
		in, out := &in.StreamingMode, &out.StreamingMode
		*out = new(StreamingMode)
		**out = **in
	}
	if in.SaveInputBlobsAsArtifacts != nil {
		in, out := &in.SaveInputBlobsAsArtifacts, &out.SaveInputBlobsAsArtifacts
		*out = new(bool)
		**out = **in
	}
}

func (in *MessageContent) DeepCopyInto(out *MessageContent) {
	*out = *in
	if in.Parts != nil {
		in, out := &in.Parts, &out.Parts
		*out = new(apiextensionsv1.JSON)
		(*in).DeepCopyInto(*out)
	}
}

func (in *CrewRunStatus) DeepCopyInto(out *CrewRunStatus) {
	*out = *in
	if in.Events != nil {
		in, out := &in.Events, &out.Events
		*out = make([]apiextensionsv1.JSON, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *CrewRunList) DeepCopyInto(out *CrewRunList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CrewRun, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *CrewRunList) DeepCopy() *CrewRunList {
	if in == nil {
		return nil
	}
	out := new(CrewRunList)
	in.DeepCopyInto(out)
	return out
}

func (in *CrewRunList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// --- MCPServer ---

func (in *MCPServer) DeepCopyInto(out *MCPServer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *MCPServer) DeepCopy() *MCPServer {
	if in == nil {
		return nil
	}
	out := new(MCPServer)
	in.DeepCopyInto(out)
	return out
}

func (in *MCPServer) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *MCPServerSpec) DeepCopyInto(out *MCPServerSpec) {
	*out = *in
	if in.Command != nil {
		in, out := &in.Command, &out.Command
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Env != nil {
		in, out := &in.Env, &out.Env
		*out = make([]EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.ToolFilter != nil {
		in, out := &in.ToolFilter, &out.ToolFilter
		*out = new(ToolFilter)
		(*in).DeepCopyInto(*out)
	}
	if in.RequireConfirmation != nil {
		in, out := &in.RequireConfirmation, &out.RequireConfirmation
		*out = new(bool)
		**out = **in
	}
}

func (in *EnvVar) DeepCopyInto(out *EnvVar) {
	*out = *in
	if in.ValueFrom != nil {
		in, out := &in.ValueFrom, &out.ValueFrom
		*out = new(EnvVarSource)
		**out = **in
	}
}

func (in *EnvVarSource) DeepCopyInto(out *EnvVarSource) {
	*out = *in
	out.SecretRef = in.SecretRef
}

func (in *SecretKeyRef) DeepCopyInto(out *SecretKeyRef) {
	*out = *in
}

func (in *ToolFilter) DeepCopyInto(out *ToolFilter) {
	*out = *in
	if in.Allow != nil {
		in, out := &in.Allow, &out.Allow
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Deny != nil {
		in, out := &in.Deny, &out.Deny
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

func (in *MCPServerStatus) DeepCopyInto(out *MCPServerStatus) {
	*out = *in
	if in.DiscoveredTools != nil {
		in, out := &in.DiscoveredTools, &out.DiscoveredTools
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *MCPServerList) DeepCopyInto(out *MCPServerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]MCPServer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *MCPServerList) DeepCopy() *MCPServerList {
	if in == nil {
		return nil
	}
	out := new(MCPServerList)
	in.DeepCopyInto(out)
	return out
}

func (in *MCPServerList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// --- Workflow ---

func (in *Workflow) DeepCopyInto(out *Workflow) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *Workflow) DeepCopy() *Workflow {
	if in == nil {
		return nil
	}
	out := new(Workflow)
	in.DeepCopyInto(out)
	return out
}

func (in *Workflow) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *WorkflowSpec) DeepCopyInto(out *WorkflowSpec) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make([]WorkflowNode, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Edges != nil {
		in, out := &in.Edges, &out.Edges
		*out = make([]WorkflowEdge, len(*in))
		copy(*out, *in)
	}
}

func (in *WorkflowNode) DeepCopyInto(out *WorkflowNode) {
	*out = *in
	if in.HITL != nil {
		in, out := &in.HITL, &out.HITL
		*out = new(HITLConfig)
		**out = **in
	}
	if in.Route != nil {
		in, out := &in.Route, &out.Route
		*out = new(RouteConfig)
		**out = **in
	}
}

func (in *WorkflowStatus) DeepCopyInto(out *WorkflowStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *WorkflowList) DeepCopyInto(out *WorkflowList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Workflow, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *WorkflowList) DeepCopy() *WorkflowList {
	if in == nil {
		return nil
	}
	out := new(WorkflowList)
	in.DeepCopyInto(out)
	return out
}

func (in *WorkflowList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}
