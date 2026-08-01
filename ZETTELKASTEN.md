## 202608010210 Argo Bootstrap Order

Argo bootstrap order is dependency-bearing project knowledge: bring up argocd operator first, then argocd, then argoworkflows, then argoevent. Each step is a separate Kustomize package delivery rather than an instance directory inside the packaged resources.

References:
- user-decision: conversation: $zettelkasten -> use the processes we talked about for kustomize to bring up argocd operator, then argocd, argoworkflows, argoevent

## 202608010211 Namespace Is A Resource

When a Kustomize package needs a namespace and the upstream resources do not provide it, add a Namespace manifest to the package resources. Namespace creation is part of the resource graph, not a separate script step.

References:
- user-decision: conversation: when making kustomizations, and a namespace is missing, simply add it to your resources

Links:
- see-also: 202608010210

## 202608010212 Inbound Traffic Is Declared Additively

Applications that need inbound traffic should add the CRD-backed resource that declares their public attachment. The package should append that declaration when the relevant API exists, so inbound exposure becomes part of the KRM graph instead of a side effect outside Kustomize.

References:
- user-decision: conversation: apps with inbound traffic need an Ingress or whichever CRD/type declares their existence to the world and attaches them to the istio-ingressgateway

Links:
- see-also: 202608010211
