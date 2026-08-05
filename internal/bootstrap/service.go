// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	// JournalVersion is the only durable bootstrap-journal schema understood
	// by this implementation.
	JournalVersion uint32 = 1

	maxArtifactBytes = 16 << 20
	maxIdentifierSize = 256
)

// Step is one of the nine, and only nine, v5 bootstrap steps.
type Step string

const (
	StepTPMKeyManagerCASigning Step = "TPM-keymanager CA signing"
	StepKubeletConfig          Step = "kubelet config"
	StepCalicoIPv6             Step = "Calico IPv6 using injected ULA"
	StepIstioIngress           Step = "Istio ingress"
	StepSPIRETPMConfig         Step = "SPIRE TPM plugin/TPM Device Key config"
	StepInitializeAPIServer    Step = "initialize Kubernetes API server"
	StepWaitControlPlane       Step = "wait control plane"
	StepApplyClusterConfigs    Step = "apply cluster configs"
	StepMarkComplete           Step = "mark complete"
)

var orderedSteps = [...]Step{
	StepTPMKeyManagerCASigning,
	StepKubeletConfig,
	StepCalicoIPv6,
	StepIstioIngress,
	StepSPIRETPMConfig,
	StepInitializeAPIServer,
	StepWaitControlPlane,
	StepApplyClusterConfigs,
	StepMarkComplete,
}

// Steps returns a copy of the exact v5 bootstrap order.
func Steps() []Step {
	return slices.Clone(orderedSteps[:])
}

func stepIndex(step Step) int {
	for index, candidate := range orderedSteps {
		if candidate == step {
			return index
		}
	}
	return -1
}

// StatusState mirrors the committed BootstrapState surface without pretending
// to be generated protobuf or gRPC code.
type StatusState string

const (
	StatusNotStarted StatusState = "not_started"
	StatusInProgress StatusState = "in_progress"
	StatusComplete   StatusState = "complete"
	StatusFailed     StatusState = "failed"
)

// Status contains exactly the domain values needed by the committed
// Bootstrap.GetStatus response. A future generated transport performs the
// protobuf enum and timestamp conversion.
type Status struct {
	State       StatusState
	CurrentStep Step
	Message     string
	UpdatedAt   time.Time
}

// Component identifies one named upstream boundary. These are not resource
// APIs and do not authorize Sovereignite CRDs.
type Component string

const (
	ComponentKeyManager Component = "keymanager"
	ComponentKubernetes Component = "kubernetes"
	ComponentCalico     Component = "calico"
	ComponentIstio      Component = "istio"
	ComponentSPIRE      Component = "spire"
	ComponentDex        Component = "dex"
)

// PinnedVersions contains authority-selected versions. There are intentionally
// no defaults, moving tags, or compatibility guesses.
type PinnedVersions struct {
	Kubernetes string
	Calico     string
	Istio      string
	SPIRE      string
	Dex        string
}

// Artifact is an already rendered, public configuration input bound to an
// authority-selected version and exact SHA-256 digest. Component adapters must
// atomically write and validate it before activation.
type Artifact struct {
	Name   string
	Version string
	SHA256 string
	Content []byte
}

const (
	ArtifactCARequest          = "tpm-ca-signing-request"
	ArtifactKubelet            = "kubelet-configuration"
	ArtifactCalico             = "calico-ipv6-configuration"
	ArtifactIstio              = "istio-ingress-configuration"
	ArtifactSPIRE              = "spire-tpm-device-key-configuration"
	ArtifactDex                = "dex-configuration"
	ArtifactControlPlane       = "kubernetes-control-plane-configuration"
	ArtifactCluster            = "kubernetes-cluster-configuration"
	ArtifactTopologyContract   = "kubernetes-topology-contract"
	ArtifactKeyInventory       = "tpm-key-inventory-contract"
	ArtifactIssuerHierarchy    = "issuer-hierarchy-contract"
	ArtifactIngressTokenFlow   = "ingress-token-flow-contract"
	ArtifactCompatibility      = "upstream-compatibility-contract"
)

// Artifacts is the closed bootstrap artifact inventory. Adding another entry
// requires a v5 scope decision rather than an unreviewed resource abstraction.
type Artifacts struct {
	CARequest    Artifact
	Kubelet     Artifact
	Calico      Artifact
	Istio       Artifact
	SPIRE       Artifact
	Dex         Artifact
	ControlPlane Artifact
	Cluster     Artifact
}

// AuthorityContracts holds the decisions that v5 leaves materially open.
// Bootstrap refuses to start unless exact, pinned documents are injected.
type AuthorityContracts struct {
	KubernetesTopology Artifact
	TPMKeyInventory     Artifact
	IssuerHierarchy     Artifact
	IngressTokenFlow    Artifact
	Compatibility       Artifact
}

// Configuration is immutable after NewCoordinator succeeds.
type Configuration struct {
	BootstrapVersion     string
	Versions             PinnedVersions
	ULA                  netip.Prefix
	TPMDeviceKeyReference string
	Artifacts            Artifacts
	Authority            AuthorityContracts
}

// Operation is a stable idempotency identity for one journaled step. An
// adapter must use IdempotencyKey to reopen or verify a prior result after a
// crash; it must never rotate a completed key or recreate a completed resource.
type Operation struct {
	TransactionID      string
	IdempotencyKey     string
	BootstrapVersion   string
	ConfigurationSHA256 string
	Step               Step
	FieldManager       string
	ForceOwnership     bool
	Compatibility      Artifact
}

const bootstrapFieldManager = "sovereignite-bootstrap"

// Observation is public-only evidence returned by an injected adapter. It
// records hashes, never private material or cluster secrets.
type Observation struct {
	Component      Component `json:"component"`
	Version        string    `json:"version"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	ResourceSHA256 string    `json:"resource_sha256"`
	Ready          bool      `json:"ready"`
}

// Evidence is the complete, ordered observation set for one step.
type Evidence struct {
	Observations []Observation `json:"observations"`
}

func (a Artifact) validate(expectedName, expectedVersion string) error {
	if a.Name != expectedName {
		return fmt.Errorf("artifact name %q, expected %q", a.Name, expectedName)
	}
	if err := validatePinnedIdentifier("artifact version", a.Version); err != nil {
		return fmt.Errorf("%s: %w", a.Name, err)
	}
	if expectedVersion != "" && a.Version != expectedVersion {
		return fmt.Errorf(
			"artifact %q version %q does not match selected version %q",
			a.Name,
			a.Version,
			expectedVersion,
		)
	}
	if len(a.Content) == 0 || len(a.Content) > maxArtifactBytes {
		return fmt.Errorf(
			"artifact %q must contain between 1 and %d bytes",
			a.Name,
			maxArtifactBytes,
		)
	}
	if bytes.IndexByte(a.Content, 0) >= 0 {
		return fmt.Errorf("artifact %q contains a NUL byte", a.Name)
	}
	if !validSHA256(a.SHA256) {
		return fmt.Errorf("artifact %q has a non-canonical SHA-256 digest", a.Name)
	}
	sum := sha256.Sum256(a.Content)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return fmt.Errorf("artifact %q SHA-256 digest does not match its content", a.Name)
	}
	if containsPrivateKey(a.Content) {
		return fmt.Errorf("artifact %q contains private-key material", a.Name)
	}
	return nil
}

func validateOperationalArtifact(a Artifact) error {
	lower := bytes.ToLower(a.Content)
	if bytes.Contains(lower, []byte("kubeadm")) {
		return fmt.Errorf("artifact %q invokes or references forbidden kubeadm", a.Name)
	}
	compact := removeASCIIWhitespace(lower)
	customResourceDefinition := bytes.Contains(
		compact,
		[]byte("kind:customresourcedefinition"),
	) || bytes.Contains(
		compact,
		[]byte(`"kind":"customresourcedefinition"`),
	)
	if customResourceDefinition && bytes.Contains(lower, []byte("sovereignite")) {
		return fmt.Errorf("artifact %q defines a forbidden Sovereignite CRD", a.Name)
	}
	return nil
}

func removeASCIIWhitespace(content []byte) []byte {
	result := make([]byte, 0, len(content))
	for _, character := range content {
		switch character {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			result = append(result, character)
		}
	}
	return result
}

func (c Configuration) validate() (string, error) {
	if err := validatePinnedIdentifier("bootstrap version", c.BootstrapVersion); err != nil {
		return "", err
	}
	selected := []struct {
		name  string
		value string
	}{
		{name: "Kubernetes version", value: c.Versions.Kubernetes},
		{name: "Calico version", value: c.Versions.Calico},
		{name: "Istio version", value: c.Versions.Istio},
		{name: "SPIRE version", value: c.Versions.SPIRE},
		{name: "Dex version", value: c.Versions.Dex},
	}
	for _, version := range selected {
		if err := validatePinnedIdentifier(version.name, version.value); err != nil {
			return "", err
		}
	}
	if !c.ULA.IsValid() || !c.ULA.Addr().Is6() || c.ULA.Bits() != 48 ||
		c.ULA != c.ULA.Masked() || c.ULA.Addr().As16()[0] != 0xfd {
		return "", errors.New("injected ULA must be a canonical fd00::/8 IPv6 /48")
	}
	if err := validateRequiredIdentifier(
		"TPM Device Key reference",
		c.TPMDeviceKeyReference,
	); err != nil {
		return "", err
	}

	artifacts := []struct {
		artifact Artifact
		name     string
		version  string
	}{
		{artifact: c.Artifacts.CARequest, name: ArtifactCARequest, version: c.BootstrapVersion},
		{artifact: c.Artifacts.Kubelet, name: ArtifactKubelet, version: c.Versions.Kubernetes},
		{artifact: c.Artifacts.Calico, name: ArtifactCalico, version: c.Versions.Calico},
		{artifact: c.Artifacts.Istio, name: ArtifactIstio, version: c.Versions.Istio},
		{artifact: c.Artifacts.SPIRE, name: ArtifactSPIRE, version: c.Versions.SPIRE},
		{artifact: c.Artifacts.Dex, name: ArtifactDex, version: c.Versions.Dex},
		{
			artifact: c.Artifacts.ControlPlane,
			name:     ArtifactControlPlane,
			version:  c.Versions.Kubernetes,
		},
		{artifact: c.Artifacts.Cluster, name: ArtifactCluster, version: c.Versions.Kubernetes},
	}
	for _, candidate := range artifacts {
		if err := candidate.artifact.validate(candidate.name, candidate.version); err != nil {
			return "", err
		}
		if err := validateOperationalArtifact(candidate.artifact); err != nil {
			return "", err
		}
	}
	if !bytes.Contains(
		c.Artifacts.SPIRE.Content,
		[]byte(c.TPMDeviceKeyReference),
	) {
		return "", errors.New(
			"SPIRE artifact does not contain the injected TPM Device Key reference",
		)
	}

	contracts := []struct {
		artifact Artifact
		name     string
	}{
		{artifact: c.Authority.KubernetesTopology, name: ArtifactTopologyContract},
		{artifact: c.Authority.TPMKeyInventory, name: ArtifactKeyInventory},
		{artifact: c.Authority.IssuerHierarchy, name: ArtifactIssuerHierarchy},
		{artifact: c.Authority.IngressTokenFlow, name: ArtifactIngressTokenFlow},
		{artifact: c.Authority.Compatibility, name: ArtifactCompatibility},
	}
	for _, contract := range contracts {
		if err := contract.artifact.validate(contract.name, ""); err != nil {
			return "", fmt.Errorf("authority contract: %w", err)
		}
		if err := validateOperationalArtifact(contract.artifact); err != nil {
			return "", fmt.Errorf("authority contract: %w", err)
		}
	}
	return configurationDigest(c)
}

func configurationDigest(c Configuration) (string, error) {
	type artifactIdentity struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	}
	identity := func(artifact Artifact) artifactIdentity {
		return artifactIdentity{
			Name:    artifact.Name,
			Version: artifact.Version,
			SHA256:  artifact.SHA256,
		}
	}
	envelope := struct {
		Version      string             `json:"bootstrap_version"`
		Versions     PinnedVersions     `json:"versions"`
		ULA          string             `json:"ula"`
		TPMReference string             `json:"tpm_device_key_reference"`
		Artifacts    []artifactIdentity `json:"artifacts"`
		Authority    []artifactIdentity `json:"authority"`
	}{
		Version:      c.BootstrapVersion,
		Versions:     c.Versions,
		ULA:          c.ULA.String(),
		TPMReference: c.TPMDeviceKeyReference,
		Artifacts: []artifactIdentity{
			identity(c.Artifacts.CARequest),
			identity(c.Artifacts.Kubelet),
			identity(c.Artifacts.Calico),
			identity(c.Artifacts.Istio),
			identity(c.Artifacts.SPIRE),
			identity(c.Artifacts.Dex),
			identity(c.Artifacts.ControlPlane),
			identity(c.Artifacts.Cluster),
		},
		Authority: []artifactIdentity{
			identity(c.Authority.KubernetesTopology),
			identity(c.Authority.TPMKeyInventory),
			identity(c.Authority.IssuerHierarchy),
			identity(c.Authority.IngressTokenFlow),
			identity(c.Authority.Compatibility),
		},
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("encode configuration identity: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func cloneConfiguration(c Configuration) Configuration {
	c.Artifacts.CARequest = copyArtifact(c.Artifacts.CARequest)
	c.Artifacts.Kubelet = copyArtifact(c.Artifacts.Kubelet)
	c.Artifacts.Calico = copyArtifact(c.Artifacts.Calico)
	c.Artifacts.Istio = copyArtifact(c.Artifacts.Istio)
	c.Artifacts.SPIRE = copyArtifact(c.Artifacts.SPIRE)
	c.Artifacts.Dex = copyArtifact(c.Artifacts.Dex)
	c.Artifacts.ControlPlane = copyArtifact(c.Artifacts.ControlPlane)
	c.Artifacts.Cluster = copyArtifact(c.Artifacts.Cluster)
	c.Authority.KubernetesTopology = copyArtifact(c.Authority.KubernetesTopology)
	c.Authority.TPMKeyInventory = copyArtifact(c.Authority.TPMKeyInventory)
	c.Authority.IssuerHierarchy = copyArtifact(c.Authority.IssuerHierarchy)
	c.Authority.IngressTokenFlow = copyArtifact(c.Authority.IngressTokenFlow)
	c.Authority.Compatibility = copyArtifact(c.Authority.Compatibility)
	return c
}

func copyArtifact(artifact Artifact) Artifact {
	artifact.Content = bytes.Clone(artifact.Content)
	return artifact
}

func validatePinnedIdentifier(name, value string) error {
	if err := validateRequiredIdentifier(name, value); err != nil {
		return err
	}
	switch strings.ToLower(value) {
	case "latest", "main", "master", "head", "stable", "nightly":
		return fmt.Errorf("%s must not use moving identifier %q", name, value)
	}
	return nil
}

func validateRequiredIdentifier(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > maxIdentifierSize {
		return fmt.Errorf("%s exceeds %d bytes", name, maxIdentifierSize)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s has surrounding whitespace", name)
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("%s must contain only printable ASCII without spaces", name)
		}
	}
	return nil
}

func containsPrivateKey(content []byte) bool {
	upper := bytes.ToUpper(content)
	return bytes.Contains(upper, []byte("-----BEGIN PRIVATE KEY-----")) ||
		bytes.Contains(upper, []byte("-----BEGIN RSA PRIVATE KEY-----")) ||
		bytes.Contains(upper, []byte("-----BEGIN EC PRIVATE KEY-----")) ||
		bytes.Contains(upper, []byte("-----BEGIN OPENSSH PRIVATE KEY-----"))
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func idempotencyKey(transactionID string, step Step) string {
	sum := sha256.Sum256([]byte(transactionID + "\x00" + string(step)))
	return hex.EncodeToString(sum[:])
}
