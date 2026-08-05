// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

const testTransactionID = "00112233445566778899aabbccddeeff"

func secureTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testArtifact(name, version, content string) Artifact {
	sum := sha256.Sum256([]byte(content))
	return Artifact{
		Name:    name,
		Version: version,
		SHA256:  hex.EncodeToString(sum[:]),
		Content: []byte(content),
	}
}

func validTestConfiguration() Configuration {
	const tpmReference = "tpm-device-key:0x81010040"
	return Configuration{
		BootstrapVersion: "bootstrap-v5.0.0",
		Versions: PinnedVersions{
			Kubernetes: "v1.35.1",
			Calico:     "v3.31.2",
			Istio:      "v1.29.3",
			SPIRE:      "v1.14.1",
			Dex:        "v2.45.1",
		},
		ULA:                   netip.MustParsePrefix("fd18:4f1c:14d::/48"),
		TPMDeviceKeyReference: tpmReference,
		Artifacts: Artifacts{
			CARequest: testArtifact(
				ArtifactCARequest,
				"bootstrap-v5.0.0",
				"public certificate request",
			),
			Kubelet: testArtifact(
				ArtifactKubelet,
				"v1.35.1",
				"apiVersion: kubelet.config.k8s.io/v1beta1\n",
			),
			Calico: testArtifact(
				ArtifactCalico,
				"v3.31.2",
				"calico IPv6 desired configuration\n",
			),
			Istio: testArtifact(
				ArtifactIstio,
				"v1.29.3",
				"istio ingress desired configuration\n",
			),
			SPIRE: testArtifact(
				ArtifactSPIRE,
				"v1.14.1",
				"plugin = tpm_devid\nreference = "+tpmReference+"\n",
			),
			Dex: testArtifact(
				ArtifactDex,
				"v2.45.1",
				"dex desired configuration\n",
			),
			ControlPlane: testArtifact(
				ArtifactControlPlane,
				"v1.35.1",
				"complete authorized control plane inputs\n",
			),
			Cluster: testArtifact(
				ArtifactCluster,
				"v1.35.1",
				"kubernetes cluster desired configuration\n",
			),
		},
		Authority: AuthorityContracts{
			KubernetesTopology: testArtifact(
				ArtifactTopologyContract,
				"decision-006-r1",
				"complete topology and component inventory\n",
			),
			TPMKeyInventory: testArtifact(
				ArtifactKeyInventory,
				"decision-001-014-r1",
				"authorized TPM role inventory and policy\n",
			),
			IssuerHierarchy: testArtifact(
				ArtifactIssuerHierarchy,
				"decision-004-r1",
				"authorized issuer hierarchy\n",
			),
			IngressTokenFlow: testArtifact(
				ArtifactIngressTokenFlow,
				"decision-007-r1",
				"authorized ingress and token flow\n",
			),
			Compatibility: testArtifact(
				ArtifactCompatibility,
				"compatibility-r1",
				"pinned upstream compatibility matrix\n",
			),
		},
	}
}

type testClock struct {
	mu   sync.Mutex
	next time.Time
}

var sharedTestClock = newTestClock()

func newTestClock() *testClock {
	return &testClock{
		next: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	value := c.next
	c.next = c.next.Add(time.Millisecond)
	return value
}

type fakePreparedPublisher struct {
	mu           sync.Mutex
	publishCalls int
	verifyCalls  int
	publishErr   error
	verifyErr    error
}

func (p *fakePreparedPublisher) Publish(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.publishCalls++
	return p.publishErr
}

func (p *fakePreparedPublisher) Verify(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verifyCalls++
	return p.verifyErr
}

func (p *fakePreparedPublisher) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.publishCalls, p.verifyCalls
}

type fakeUpstreams struct {
	mu sync.Mutex

	config Configuration

	actionCalls   map[string]int
	creationCalls map[string]int
	resources     map[string]string
	verifyCalls   map[string]int
	failOnce      map[string]error
	verifyFailure map[string]error
}

func newFakeUpstreams(config Configuration) *fakeUpstreams {
	return &fakeUpstreams{
		config:        cloneConfiguration(config),
		actionCalls:   make(map[string]int),
		creationCalls: make(map[string]int),
		resources:     make(map[string]string),
		verifyCalls:   make(map[string]int),
		failOnce:      make(map[string]error),
		verifyFailure: make(map[string]error),
	}
}

func (f *fakeUpstreams) ensure(
	operation Operation,
	action string,
	component Component,
	artifact Artifact,
	ready bool,
) (Observation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if operation.FieldManager != bootstrapFieldManager ||
		operation.ForceOwnership ||
		operation.Compatibility.SHA256 !=
			f.config.Authority.Compatibility.SHA256 {
		return Observation{}, errors.New("unsafe fake apply ownership policy")
	}
	f.actionCalls[action]++
	resourceKey := operation.IdempotencyKey + "/" + action
	resourceSHA, exists := f.resources[resourceKey]
	if !exists {
		sum := sha256.Sum256([]byte(resourceKey))
		resourceSHA = hex.EncodeToString(sum[:])
		f.resources[resourceKey] = resourceSHA
		f.creationCalls[action]++
	}
	if err := f.failOnce[action]; err != nil {
		delete(f.failOnce, action)
		return Observation{}, err
	}
	return Observation{
		Component:      component,
		Version:        artifact.Version,
		ArtifactSHA256: artifact.SHA256,
		ResourceSHA256: resourceSHA,
		Ready:          ready,
	}, nil
}

func (f *fakeUpstreams) verify(
	operation Operation,
	action string,
	component Component,
	artifact Artifact,
	observation Observation,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if operation.FieldManager != bootstrapFieldManager ||
		operation.ForceOwnership ||
		operation.Compatibility.SHA256 !=
			f.config.Authority.Compatibility.SHA256 {
		return errors.New("unsafe fake verify ownership policy")
	}
	f.verifyCalls[action]++
	if err := f.verifyFailure[action]; err != nil {
		return err
	}
	resourceKey := operation.IdempotencyKey + "/" + action
	resourceSHA, exists := f.resources[resourceKey]
	if !exists {
		return errors.New("fake resource is absent")
	}
	if observation.Component != component ||
		observation.Version != artifact.Version ||
		observation.ArtifactSHA256 != artifact.SHA256 ||
		observation.ResourceSHA256 != resourceSHA {
		return errors.New("fake observation does not match resource")
	}
	return nil
}

func (f *fakeUpstreams) ready(
	operation Operation,
	action string,
	component Component,
	artifact Artifact,
) (Observation, error) {
	return f.ensure(operation, action, component, artifact, true)
}

func (f *fakeUpstreams) EnsureSigning(
	_ context.Context,
	operation Operation,
	request CARequest,
) (Observation, error) {
	if request.Purpose != SigningPurposeBootstrapCA {
		return Observation{}, errors.New("unexpected signing purpose")
	}
	return f.ensure(
		operation,
		"ca-signing",
		ComponentKeyManager,
		request.Artifact,
		true,
	)
}

func (f *fakeUpstreams) VerifySigning(
	_ context.Context,
	operation Operation,
	request CARequest,
	observation Observation,
) error {
	if request.Purpose != SigningPurposeBootstrapCA {
		return errors.New("unexpected signing purpose")
	}
	return f.verify(
		operation,
		"ca-signing",
		ComponentKeyManager,
		request.Artifact,
		observation,
	)
}

func (f *fakeUpstreams) PrepareKubelet(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	_ Artifact,
) (Observation, error) {
	return f.ensure(
		operation,
		"kubelet",
		ComponentKubernetes,
		artifact,
		false,
	)
}

func (f *fakeUpstreams) VerifyKubelet(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	_ Artifact,
	observation Observation,
) error {
	return f.verify(
		operation,
		"kubelet",
		ComponentKubernetes,
		artifact,
		observation,
	)
}

func (f *fakeUpstreams) InitializeAPIServer(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	_ Artifact,
) (Observation, error) {
	return f.ensure(
		operation,
		"api-server",
		ComponentKubernetes,
		artifact,
		false,
	)
}

func (f *fakeUpstreams) VerifyAPIServer(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	_ Artifact,
	observation Observation,
) error {
	return f.verify(
		operation,
		"api-server",
		ComponentKubernetes,
		artifact,
		observation,
	)
}

func (f *fakeUpstreams) WaitControlPlane(
	_ context.Context,
	operation Operation,
	artifact Artifact,
) (Observation, error) {
	return f.ensure(
		operation,
		"control-plane",
		ComponentKubernetes,
		artifact,
		true,
	)
}

func (f *fakeUpstreams) VerifyControlPlane(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	observation Observation,
) error {
	return f.verify(
		operation,
		"control-plane",
		ComponentKubernetes,
		artifact,
		observation,
	)
}

func (f *fakeUpstreams) Reconcile(
	_ context.Context,
	operation Operation,
	artifact Artifact,
) (Observation, error) {
	return f.ensure(
		operation,
		"kubernetes-reconcile",
		ComponentKubernetes,
		artifact,
		true,
	)
}

func (f *fakeUpstreams) VerifyReconciled(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	observation Observation,
) error {
	return f.verify(
		operation,
		"kubernetes-reconcile",
		ComponentKubernetes,
		artifact,
		observation,
	)
}

func (f *fakeUpstreams) CheckReady(
	_ context.Context,
	operation Operation,
) (Observation, error) {
	return f.ready(
		operation,
		"kubernetes-ready",
		ComponentKubernetes,
		f.config.Artifacts.Cluster,
	)
}

func (f *fakeUpstreams) VerifyReady(
	_ context.Context,
	operation Operation,
	observation Observation,
) error {
	return f.verify(
		operation,
		"kubernetes-ready",
		ComponentKubernetes,
		f.config.Artifacts.Cluster,
		observation,
	)
}

func (f *fakeUpstreams) PrepareIPv6(
	_ context.Context,
	operation Operation,
	ula netip.Prefix,
	artifact Artifact,
) (Observation, error) {
	if ula != f.config.ULA {
		return Observation{}, errors.New("unexpected ULA")
	}
	return f.ensure(
		operation,
		"calico-ipv6",
		ComponentCalico,
		artifact,
		false,
	)
}

func (f *fakeUpstreams) VerifyIPv6(
	_ context.Context,
	operation Operation,
	ula netip.Prefix,
	artifact Artifact,
	observation Observation,
) error {
	if ula != f.config.ULA {
		return errors.New("unexpected ULA")
	}
	return f.verify(
		operation,
		"calico-ipv6",
		ComponentCalico,
		artifact,
		observation,
	)
}

func (f *fakeUpstreams) PrepareIngress(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	_ Artifact,
) (Observation, error) {
	return f.ensure(
		operation,
		"istio-ingress",
		ComponentIstio,
		artifact,
		false,
	)
}

func (f *fakeUpstreams) VerifyIngress(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	_ Artifact,
	observation Observation,
) error {
	return f.verify(
		operation,
		"istio-ingress",
		ComponentIstio,
		artifact,
		observation,
	)
}

func (f *fakeUpstreams) PrepareTPM(
	_ context.Context,
	operation Operation,
	request SPIRERequest,
) (Observation, error) {
	if request.TPMDeviceKeyReference != f.config.TPMDeviceKeyReference {
		return Observation{}, errors.New("unexpected TPM Device Key reference")
	}
	return f.ensure(
		operation,
		"spire-tpm",
		ComponentSPIRE,
		request.Artifact,
		false,
	)
}

func (f *fakeUpstreams) VerifyTPM(
	_ context.Context,
	operation Operation,
	request SPIRERequest,
	observation Observation,
) error {
	return f.verify(
		operation,
		"spire-tpm",
		ComponentSPIRE,
		request.Artifact,
		observation,
	)
}

func (f *fakeUpstreams) reconcileNamed(
	operation Operation,
	action string,
	component Component,
	artifact Artifact,
) (Observation, error) {
	return f.ensure(operation, action, component, artifact, true)
}

type fakeCalico struct {
	environment *fakeUpstreams
}

func (f fakeCalico) PrepareIPv6(
	ctx context.Context,
	operation Operation,
	ula netip.Prefix,
	artifact Artifact,
) (Observation, error) {
	return f.environment.PrepareIPv6(ctx, operation, ula, artifact)
}

func (f fakeCalico) VerifyIPv6(
	ctx context.Context,
	operation Operation,
	ula netip.Prefix,
	artifact Artifact,
	observation Observation,
) error {
	return f.environment.VerifyIPv6(ctx, operation, ula, artifact, observation)
}

func (f fakeCalico) Reconcile(
	_ context.Context,
	operation Operation,
	artifact Artifact,
) (Observation, error) {
	return f.environment.reconcileNamed(
		operation,
		"calico-reconcile",
		ComponentCalico,
		artifact,
	)
}

func (f fakeCalico) VerifyReconciled(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	observation Observation,
) error {
	return f.environment.verify(
		operation,
		"calico-reconcile",
		ComponentCalico,
		artifact,
		observation,
	)
}

func (f fakeCalico) CheckReady(
	_ context.Context,
	operation Operation,
) (Observation, error) {
	return f.environment.ready(
		operation,
		"calico-ready",
		ComponentCalico,
		f.environment.config.Artifacts.Calico,
	)
}

func (f fakeCalico) VerifyReady(
	_ context.Context,
	operation Operation,
	observation Observation,
) error {
	return f.environment.verify(
		operation,
		"calico-ready",
		ComponentCalico,
		f.environment.config.Artifacts.Calico,
		observation,
	)
}

type fakeIstio struct {
	environment *fakeUpstreams
}

func (f fakeIstio) PrepareIngress(
	ctx context.Context,
	operation Operation,
	artifact Artifact,
	contract Artifact,
) (Observation, error) {
	return f.environment.PrepareIngress(
		ctx,
		operation,
		artifact,
		contract,
	)
}

func (f fakeIstio) VerifyIngress(
	ctx context.Context,
	operation Operation,
	artifact Artifact,
	contract Artifact,
	observation Observation,
) error {
	return f.environment.VerifyIngress(
		ctx,
		operation,
		artifact,
		contract,
		observation,
	)
}

func (f fakeIstio) Reconcile(
	_ context.Context,
	operation Operation,
	artifact Artifact,
) (Observation, error) {
	return f.environment.reconcileNamed(
		operation,
		"istio-reconcile",
		ComponentIstio,
		artifact,
	)
}

func (f fakeIstio) VerifyReconciled(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	observation Observation,
) error {
	return f.environment.verify(
		operation,
		"istio-reconcile",
		ComponentIstio,
		artifact,
		observation,
	)
}

func (f fakeIstio) CheckReady(
	_ context.Context,
	operation Operation,
) (Observation, error) {
	return f.environment.ready(
		operation,
		"istio-ready",
		ComponentIstio,
		f.environment.config.Artifacts.Istio,
	)
}

func (f fakeIstio) VerifyReady(
	_ context.Context,
	operation Operation,
	observation Observation,
) error {
	return f.environment.verify(
		operation,
		"istio-ready",
		ComponentIstio,
		f.environment.config.Artifacts.Istio,
		observation,
	)
}

type fakeSPIRE struct {
	environment *fakeUpstreams
}

func (f fakeSPIRE) PrepareTPM(
	ctx context.Context,
	operation Operation,
	request SPIRERequest,
) (Observation, error) {
	return f.environment.PrepareTPM(ctx, operation, request)
}

func (f fakeSPIRE) VerifyTPM(
	ctx context.Context,
	operation Operation,
	request SPIRERequest,
	observation Observation,
) error {
	return f.environment.VerifyTPM(
		ctx,
		operation,
		request,
		observation,
	)
}

func (f fakeSPIRE) Reconcile(
	_ context.Context,
	operation Operation,
	artifact Artifact,
) (Observation, error) {
	return f.environment.reconcileNamed(
		operation,
		"spire-reconcile",
		ComponentSPIRE,
		artifact,
	)
}

func (f fakeSPIRE) VerifyReconciled(
	_ context.Context,
	operation Operation,
	artifact Artifact,
	observation Observation,
) error {
	return f.environment.verify(
		operation,
		"spire-reconcile",
		ComponentSPIRE,
		artifact,
		observation,
	)
}

func (f fakeSPIRE) CheckReady(
	_ context.Context,
	operation Operation,
) (Observation, error) {
	return f.environment.ready(
		operation,
		"spire-ready",
		ComponentSPIRE,
		f.environment.config.Artifacts.SPIRE,
	)
}

func (f fakeSPIRE) VerifyReady(
	_ context.Context,
	operation Operation,
	observation Observation,
) error {
	return f.environment.verify(
		operation,
		"spire-ready",
		ComponentSPIRE,
		f.environment.config.Artifacts.SPIRE,
		observation,
	)
}

type fakeDex struct {
	environment *fakeUpstreams
}

func (f fakeDex) Reconcile(
	_ context.Context,
	operation Operation,
	request DexRequest,
) (Observation, error) {
	return f.environment.reconcileNamed(
		operation,
		"dex-reconcile",
		ComponentDex,
		request.Artifact,
	)
}

func (f fakeDex) VerifyReconciled(
	_ context.Context,
	operation Operation,
	request DexRequest,
	observation Observation,
) error {
	return f.environment.verify(
		operation,
		"dex-reconcile",
		ComponentDex,
		request.Artifact,
		observation,
	)
}

func (f fakeDex) CheckReady(
	_ context.Context,
	operation Operation,
) (Observation, error) {
	return f.environment.ready(
		operation,
		"dex-ready",
		ComponentDex,
		f.environment.config.Artifacts.Dex,
	)
}

func (f fakeDex) VerifyReady(
	_ context.Context,
	operation Operation,
	observation Observation,
) error {
	return f.environment.verify(
		operation,
		"dex-ready",
		ComponentDex,
		f.environment.config.Artifacts.Dex,
		observation,
	)
}

func completeFakeDependencies(
	environment *fakeUpstreams,
	prepared PreparedPublisher,
) Dependencies {
	return Dependencies{
		CA:         environment,
		Kubernetes: environment,
		Calico:     fakeCalico{environment: environment},
		Istio:      fakeIstio{environment: environment},
		SPIRE:      fakeSPIRE{environment: environment},
		Dex:        fakeDex{environment: environment},
		Prepared:   prepared,
	}
}

func newTestCoordinator(
	t *testing.T,
	config Configuration,
	store JournalStore,
	environment *fakeUpstreams,
	prepared PreparedPublisher,
	hooks coordinatorHooks,
) *Coordinator {
	t.Helper()
	coordinator, err := newCoordinator(
		config,
		store,
		completeFakeDependencies(environment, prepared),
		coordinatorOptions{
			clock: sharedTestClock,
			newID: func() (string, error) {
				return testTransactionID, nil
			},
			hooks: hooks,
		},
	)
	if err != nil {
		t.Fatalf("create coordinator: %v", err)
	}
	return coordinator
}

func resourceCreations(environment *fakeUpstreams) map[string]int {
	environment.mu.Lock()
	defer environment.mu.Unlock()
	copyOfCounts := make(map[string]int, len(environment.creationCalls))
	for action, count := range environment.creationCalls {
		copyOfCounts[action] = count
	}
	return copyOfCounts
}

func actionCalls(environment *fakeUpstreams) map[string]int {
	environment.mu.Lock()
	defer environment.mu.Unlock()
	copyOfCounts := make(map[string]int, len(environment.actionCalls))
	for action, count := range environment.actionCalls {
		copyOfCounts[action] = count
	}
	return copyOfCounts
}

func setFailOnce(
	environment *fakeUpstreams,
	action string,
	err error,
) {
	environment.mu.Lock()
	defer environment.mu.Unlock()
	environment.failOnce[action] = err
}

func setVerificationFailure(
	environment *fakeUpstreams,
	action string,
	err error,
) {
	environment.mu.Lock()
	defer environment.mu.Unlock()
	environment.verifyFailure[action] = err
}

func assertAllCreationsAtMostOnce(
	t *testing.T,
	environment *fakeUpstreams,
) {
	t.Helper()
	for action, count := range resourceCreations(environment) {
		if count != 1 {
			t.Fatalf("resource %q creation count = %d, want 1", action, count)
		}
	}
}

func testResourceDigest(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func mustDigest(t *testing.T, config Configuration) string {
	t.Helper()
	digest, err := config.validate()
	if err != nil {
		t.Fatalf("validate test configuration: %v", err)
	}
	return digest
}

func initialTestJournal(config Configuration) Journal {
	digest, err := config.validate()
	if err != nil {
		panic(fmt.Sprintf("invalid test configuration: %v", err))
	}
	return Journal{
		Version:             JournalVersion,
		Revision:            1,
		TransactionID:       testTransactionID,
		BootstrapVersion:    config.BootstrapVersion,
		ConfigurationSHA256: digest,
		State:               JournalInProgress,
		Steps:               []StepRecord{},
		UpdatedAt: time.Date(
			2026,
			7,
			28,
			12,
			0,
			0,
			0,
			time.UTC,
		),
	}
}
