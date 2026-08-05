// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	bootstrap "github.com/sovereignite/sovereignite/internal/bootstrap"
	"google.golang.org/grpc"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil &&
		!errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf(
			"sovereignite-bootstrap accepts no command-line operations; got %d arguments",
			len(args),
		)
	}

	coordinator, err := newStubCoordinator()
	if err != nil {
		return fmt.Errorf("create bootstrap coordinator: %w", err)
	}

	server, err := bootstrap.NewServer(coordinator)
	if err != nil {
		return fmt.Errorf("create bootstrap server: %w", err)
	}

	grpcServer := grpc.NewServer()
	server.RegisterGrpcServer(grpcServer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("create gRPC listener: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcServer.Serve(listener)
	}()

	log.Printf("bootstrap gRPC server listening on %s", listener.Addr().String())

	select {
	case <-ctx.Done():
		grpcServer.GracefulStop()
		return <-errCh
	case err := <-errCh:
		return err
	}
}

func newStubCoordinator() (*bootstrap.Coordinator, error) {
	config := stubConfiguration()
	store := &memoryJournalStore{}
	deps := bootstrap.Dependencies{
		CA:         &stubCASigner{},
		Kubernetes: &stubKubernetesInstaller{},
		Calico:     &stubCalicoInstaller{},
		Istio:      &stubIstioInstaller{},
		SPIRE:      &stubSPIREInstaller{},
		Dex:        &stubDexInstaller{},
		Prepared:   &stubPreparedPublisher{},
	}
	return bootstrap.NewCoordinator(config, store, deps)
}

var errStubDependencyUnavailable = errors.New(
	"stub dependency unavailable; production wiring required",
)

type memoryJournalStore struct {
	journal bootstrap.Journal
}

func (m *memoryJournalStore) Load() (bootstrap.Journal, error) {
	return m.journal, nil
}

func (m *memoryJournalStore) Save(
	_ uint64,
	journal bootstrap.Journal,
) error {
	m.journal = journal
	return nil
}

type stubCASigner struct{}

func (stubCASigner) EnsureSigning(
	context.Context,
	bootstrap.Operation,
	bootstrap.CARequest,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubCASigner) VerifySigning(
	context.Context,
	bootstrap.Operation,
	bootstrap.CARequest,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

type stubKubernetesInstaller struct{}

func (stubKubernetesInstaller) PrepareKubelet(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Artifact,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubKubernetesInstaller) VerifyKubelet(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Artifact,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubKubernetesInstaller) InitializeAPIServer(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Artifact,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubKubernetesInstaller) VerifyAPIServer(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Artifact,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubKubernetesInstaller) WaitControlPlane(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubKubernetesInstaller) VerifyControlPlane(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubKubernetesInstaller) Reconcile(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubKubernetesInstaller) VerifyReconciled(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubKubernetesInstaller) CheckReady(
	context.Context,
	bootstrap.Operation,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubKubernetesInstaller) VerifyReady(
	context.Context,
	bootstrap.Operation,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

type stubCalicoInstaller struct{}

func (stubCalicoInstaller) PrepareIPv6(
	context.Context,
	bootstrap.Operation,
	netip.Prefix,
	bootstrap.Artifact,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubCalicoInstaller) VerifyIPv6(
	context.Context,
	bootstrap.Operation,
	netip.Prefix,
	bootstrap.Artifact,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubCalicoInstaller) Reconcile(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubCalicoInstaller) VerifyReconciled(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubCalicoInstaller) CheckReady(
	context.Context,
	bootstrap.Operation,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubCalicoInstaller) VerifyReady(
	context.Context,
	bootstrap.Operation,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

type stubIstioInstaller struct{}

func (stubIstioInstaller) PrepareIngress(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Artifact,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubIstioInstaller) VerifyIngress(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Artifact,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubIstioInstaller) Reconcile(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubIstioInstaller) VerifyReconciled(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubIstioInstaller) CheckReady(
	context.Context,
	bootstrap.Operation,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubIstioInstaller) VerifyReady(
	context.Context,
	bootstrap.Operation,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

type stubSPIREInstaller struct{}

func (stubSPIREInstaller) PrepareTPM(
	context.Context,
	bootstrap.Operation,
	bootstrap.SPIRERequest,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubSPIREInstaller) VerifyTPM(
	context.Context,
	bootstrap.Operation,
	bootstrap.SPIRERequest,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubSPIREInstaller) Reconcile(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubSPIREInstaller) VerifyReconciled(
	context.Context,
	bootstrap.Operation,
	bootstrap.Artifact,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubSPIREInstaller) CheckReady(
	context.Context,
	bootstrap.Operation,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubSPIREInstaller) VerifyReady(
	context.Context,
	bootstrap.Operation,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

type stubDexInstaller struct{}

func (stubDexInstaller) Reconcile(
	context.Context,
	bootstrap.Operation,
	bootstrap.DexRequest,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubDexInstaller) VerifyReconciled(
	context.Context,
	bootstrap.Operation,
	bootstrap.DexRequest,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

func (stubDexInstaller) CheckReady(
	context.Context,
	bootstrap.Operation,
) (bootstrap.Observation, error) {
	return bootstrap.Observation{}, errStubDependencyUnavailable
}

func (stubDexInstaller) VerifyReady(
	context.Context,
	bootstrap.Operation,
	bootstrap.Observation,
) error {
	return errStubDependencyUnavailable
}

type stubPreparedPublisher struct{}

func (stubPreparedPublisher) Publish(context.Context) error {
	return errStubDependencyUnavailable
}

func (stubPreparedPublisher) Verify(context.Context) error {
	return errStubDependencyUnavailable
}

func stubArtifact(name, version, content string) bootstrap.Artifact {
	sum := sha256.Sum256([]byte(content))
	return bootstrap.Artifact{
		Name:    name,
		Version: version,
		SHA256:  hex.EncodeToString(sum[:]),
		Content: []byte(content),
	}
}

func stubConfiguration() bootstrap.Configuration {
	const tpmReference = "tpm-device-key:0x81010040"
	return bootstrap.Configuration{
		BootstrapVersion: "bootstrap-v5.0.0",
		Versions: bootstrap.PinnedVersions{
			Kubernetes: "v1.35.1",
			Calico:     "v3.31.2",
			Istio:      "v1.29.3",
			SPIRE:      "v1.14.1",
			Dex:        "v2.45.1",
		},
		ULA:                   netip.MustParsePrefix("fd18:4f1c:14d::/48"),
		TPMDeviceKeyReference: tpmReference,
		Artifacts: bootstrap.Artifacts{
			CARequest: stubArtifact(
				bootstrap.ArtifactCARequest,
				"bootstrap-v5.0.0",
				"public certificate request",
			),
			Kubelet: stubArtifact(
				bootstrap.ArtifactKubelet,
				"v1.35.1",
				"apiVersion: kubelet.config.k8s.io/v1beta1\n",
			),
			Calico: stubArtifact(
				bootstrap.ArtifactCalico,
				"v3.31.2",
				"calico IPv6 desired configuration\n",
			),
			Istio: stubArtifact(
				bootstrap.ArtifactIstio,
				"v1.29.3",
				"istio ingress desired configuration\n",
			),
			SPIRE: stubArtifact(
				bootstrap.ArtifactSPIRE,
				"v1.14.1",
				"plugin = tpm_devid\nreference = "+tpmReference+"\n",
			),
			Dex: stubArtifact(
				bootstrap.ArtifactDex,
				"v2.45.1",
				"dex desired configuration\n",
			),
			ControlPlane: stubArtifact(
				bootstrap.ArtifactControlPlane,
				"v1.35.1",
				"complete authorized control plane inputs\n",
			),
			Cluster: stubArtifact(
				bootstrap.ArtifactCluster,
				"v1.35.1",
				"kubernetes cluster desired configuration\n",
			),
		},
		Authority: bootstrap.AuthorityContracts{
			KubernetesTopology: stubArtifact(
				bootstrap.ArtifactTopologyContract,
				"decision-006-r1",
				"complete topology and component inventory\n",
			),
			TPMKeyInventory: stubArtifact(
				bootstrap.ArtifactKeyInventory,
				"decision-001-014-r1",
				"authorized TPM role inventory and policy\n",
			),
			IssuerHierarchy: stubArtifact(
				bootstrap.ArtifactIssuerHierarchy,
				"decision-004-r1",
				"authorized issuer hierarchy\n",
			),
			IngressTokenFlow: stubArtifact(
				bootstrap.ArtifactIngressTokenFlow,
				"decision-007-r1",
				"authorized ingress and token flow\n",
			),
			Compatibility: stubArtifact(
				bootstrap.ArtifactCompatibility,
				"compatibility-r1",
				"pinned upstream compatibility matrix\n",
			),
		},
	}
}
