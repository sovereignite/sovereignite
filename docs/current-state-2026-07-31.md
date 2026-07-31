# Current State - 2026-07-31

This document preserves the working state before the next cleanup/fix pass.

## Committed Baseline

- `f2f070d` switches libvirt nodes to the Fedora CoreOS installer path.
- `2b53e5f` bootstraps kubeadm with external TPM PKI.

## Live Cluster State

- Kubeconfig: `build/kubeconfig/admin.conf`
- API endpoint: `https://10.10.10.10:6443`
- Kubernetes nodes reached `Ready` across 3 control-plane nodes and 5 workers.
- The full SPIRE, Istio, and Knative integration is not verified healthy.

## Known Live Drift

- `spire/spire-agent-bundle` was refreshed from the current SPIRE server bundle.
- `spire-agent` DaemonSet was restarted after the bundle refresh; agents recovered to `Running`.
- One SPIRE entry was created directly with `spire-server entry create`:
  - Entry ID: `dae267aa-b0da-4207-a36a-23c5bff05d52`
  - SPIFFE ID: `spiffe://sovereignite.local/ns/knative-serving/sa/knative-private-istio-private`
  - Parent ID: `spiffe://sovereignite.local/spire/agent/tpm_devid/2ee741b3b00c9d43aa2a06ac07e1bb3e9e254e95`
  - Selectors: `k8s:ns:knative-serving`, `k8s:sa:knative-private-istio-private`
- `spire-tpm-attestor-ca` was updated live to include the host `swtpm-localca` public CA bundle.

## Known Issues

- SPIRE server startup in `k8s/components/spire/base/resources/50-server.yaml` still contains inline TPM2-PKCS#11 token/PIN initialization. That lifecycle should move into TPM integration management and use Kubernetes Secrets for PIN consumption.
- SPIRE controller-manager watches `ClusterSPIFFEID` and `ClusterStaticEntry` resources but did not create registration entries during observed runs.
- Istio gateway pods are configured with `CA_ADDR=spire-server.spire.svc:8081`, which causes TLS verification failure against SPIRE server certificate identity.
- Knative cert-manager config references missing `ClusterIssuer/knative-selfsigned-issuer`; certificates remain unissued until the issuer config is corrected.
- `kubectl logs` and `kubectl exec` through kubelet returned `remote error: tls: internal error`; node-side logs were read over SSH.

## Worktree Buckets

- Controller/runtime changes: TPM issuer, Kubernetes CSR signer, SPIRE TPM keymanager, Dockerfiles, `go.mod`, and `go.sum`.
- SPIRE manifests: server/agent config, controller-manager CRDs/config, RBAC, and node alias resources.
- Knative Eventing vendor/materialization: large deterministic file-numbering churn after adding in-memory channel upstream material.
- New source/scripts: `cmd/tpm-devid-provisioner/main.go`, `scripts/provision-spire-tpm-devid.sh`, and `scripts/import-controller-images-to-nodes.sh`.

## Do Not Commit

- Root `tpm-devid-provisioner` is a generated local ELF binary. Its source is `cmd/tpm-devid-provisioner/main.go`.
