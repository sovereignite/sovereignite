# Sovereignite

`tpm-cluster-issuer` installs the API and controller for the TPM-backed
cert-manager external issuer. `tpm-cluster-issuers` creates the project issuer
resources and grants cert-manager permission to approve their requests. Deploy
the controller before the issuer resources.

`k8s-tpm-csr-signer` installs the TPM-backed Kubernetes CSR signer and the
kubelet client and serving certificate policies.

`spire-tpm-keymanager` installs the SPIRE TPM key manager API and controller
together with the key manager resource consumed by SPIRE.
