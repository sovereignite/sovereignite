package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto copies all properties into another ModelBackend.
func (in *ModelBackend) DeepCopyInto(out *ModelBackend) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a deep copy of the ModelBackend.
func (in *ModelBackend) DeepCopy() *ModelBackend {
	if in == nil {
		return nil
	}
	out := new(ModelBackend)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy as runtime.Object.
func (in *ModelBackend) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// DeepCopyInto copies all properties into another ModelBackendSpec.
func (in *ModelBackendSpec) DeepCopyInto(out *ModelBackendSpec) {
	*out = *in
	if in.APIKeyRef != nil {
		in, out := &in.APIKeyRef, &out.APIKeyRef
		*out = new(SecretKeyRef)
		**out = **in
	}
}

// DeepCopyInto copies all properties into another ModelBackendStatus.
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

// DeepCopyInto copies all properties into another ModelBackendList.
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

// DeepCopy returns a deep copy of the ModelBackendList.
func (in *ModelBackendList) DeepCopy() *ModelBackendList {
	if in == nil {
		return nil
	}
	out := new(ModelBackendList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy as runtime.Object.
func (in *ModelBackendList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// DeepCopyInto copies all properties into another Crew.
func (in *Crew) DeepCopyInto(out *Crew) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a deep copy of the Crew.
func (in *Crew) DeepCopy() *Crew {
	if in == nil {
		return nil
	}
	out := new(Crew)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy as runtime.Object.
func (in *Crew) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

// DeepCopyInto copies all properties into another CrewSpec.
func (in *CrewSpec) DeepCopyInto(out *CrewSpec) {
	*out = *in
	if in.Members != nil {
		in, out := &in.Members, &out.Members
		*out = make([]CrewMember, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.RemoteWorkers != nil {
		in, out := &in.RemoteWorkers, &out.RemoteWorkers
		*out = make([]RemoteWorkerRef, len(*in))
		copy(*out, *in)
	}
}

// DeepCopyInto copies all properties into another CrewMember.
func (in *CrewMember) DeepCopyInto(out *CrewMember) {
	*out = *in
	if in.Tools != nil {
		in, out := &in.Tools, &out.Tools
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopyInto copies all properties into another CrewStatus.
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

// DeepCopyInto copies all properties into another CrewList.
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

// DeepCopy returns a deep copy of the CrewList.
func (in *CrewList) DeepCopy() *CrewList {
	if in == nil {
		return nil
	}
	out := new(CrewList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a deep copy as runtime.Object.
func (in *CrewList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}
