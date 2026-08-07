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

## 202608040000 Node IPv6 Address Derives From Its IPFS Id

A Sovereignite node must not carry an assigned IP address. Its lifetime-stable libp2p/IPFS identity (derived from a non-exportable TPM signing key) is the source of its IPv6 address: derive the address within the ULA site prefix from the node's own IPFS id. Then no registry or static host entry ever assigns an address, and each device is uniquely and deterministically addressed on any network it joins.

References:
- user-decision: conversation: our nodes when they setup and generate their IPFS id should be using that for the ipv6 address cidr, each node is unique

Links:
- see-also: 202608010212

## 202608040001 Domain-Separated ULA Computation Utility

Deterministic IPv6 ULA /48 from a binary identifier (IPNS CID bytes) requires a domain separator to prevent cross-protocol collisions. The pattern: `SHA-256(domain_separator || identifier)`, take first 5 bytes after `0xfd` prefix byte, produce `/48`. The domain separator is a project-rooted string + NUL terminator (e.g. `github.com/sovereignite/sovereignite/ula/v1\x00`). When the module path changes, golden test vectors must be recomputed because the domain separator changes. A standalone Go program that computes ULA from arbitrary hex-encoded identifiers and domain separators is a useful migration tool.

References:
- technical: algorithm in `internal/ipfs/ula.go` and `internal/shared/identity_vectors.go`
- migration-tool: `/tmp/compute-golden.go` (ULA golden test vector recomputation)

Links:
- see-also: 202608040000

## 202608060001 Unified Target Discovery Graph

The Bash `discover-changes` step is a useful prototype for a future Go tool. A durable target-discovery tool could intelligently identify all potential targets and their relationships, produce one unified graph, and expose that graph to GitHub Actions for dynamic matrix generation.

References:
- technical: `.github/actions/discover-changes/action.yml`
