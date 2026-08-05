// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"

	"github.com/sovereignite/sovereignite/internal/keymanager"
	"github.com/sovereignite/sovereignite/internal/tpm"
	"github.com/sovereignite/sovereignite/internal/trust"
)

var (
	openTPM     = tpm.OpenGoTPM
	newKeyStore = keymanager.NewFileStore
	newManager  = keymanager.NewManager
)

// systemClock satisfies trust.Clock without exporting the internal type.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func main() {
	if err := run(os.Args[1:], nil); err != nil {
		slog.Error("trust service stopped", "error", err)
		os.Exit(1)
	}
}

// run starts the sovereignite.v1 Trust gRPC service on a loopback port. All
// unresolved D-series dependencies are wired as fail-closed stubs that deny
// every mutation. The server shuts down when the process receives SIGINT or
// SIGTERM, or when the optional context is cancelled.
//
// Identity is read from SOVEREIGNITE_CANONICAL_IPNS and
// SOVEREIGNITE_PEER_ID environment variables. If both are empty, the
// service starts with a generated ephemeral identity for testing.
func run(arguments []string, testCtx context.Context) error {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	tpmDevice := fs.String("tpm-device", "/dev/tpmrm0", "Linux TPM resource-manager device")
	metadataPath := fs.String("metadata-path", "/var/lib/sovereignite/keymanager/metadata.json", "key-manager public-metadata path")
	if err := fs.Parse(arguments); err != nil {
		return err
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if testCtx != nil {
		ctx, cancel = context.WithCancel(testCtx)
	} else {
		ctx, cancel = signal.NotifyContext(
			context.Background(),
			syscall.SIGINT,
			syscall.SIGTERM,
		)
	}
	defer cancel()

	canonicalIPNS := os.Getenv("SOVEREIGNITE_CANONICAL_IPNS")
	peerID := os.Getenv("SOVEREIGNITE_PEER_ID")

	var identity trust.DeviceIdentity
	if canonicalIPNS != "" && peerID != "" {
		var err error
		identity, err = trust.DeriveDeviceIdentity(canonicalIPNS, peerID)
		if err != nil {
			slog.Error("configure trust identity from environment", "error", err)
			return err
		}
	} else {
		slog.Warn("no identity configured, using ephemeral test identity")
		identity = trust.DeviceIdentity{
			CanonicalIPNS: "k2k4r8juhvoclkyr8tep6jfbl13v3fm8bxv8e5s84v9669rjx9iogc80",
			PeerID:        "12D3KooWDpJ7As7HWAwsi8HqjThL0jzRT7rXt3jHkRQdRGaGR1ka",
			TrustDomain:   "k2k4r8juhvoclkyr8tep6jfbl13v3fm8bxv8e5s84v9669rjx9iogc80",
			SPIFFEID:      "spiffe://k2k4r8juhvoclkyr8tep6jfbl13v3fm8bxv8e5s84v9669rjx9iogc80/device/12D3KooWDpJ7As7HWAwsi8HqjThL0jzRT7rXt3jHkRQdRGaGR1ka",
		}
	}

	stateDir, err := os.MkdirTemp("", "sovereignite-trust-state-*")
	if err != nil {
		slog.Error("create trust state directory", "error", err)
		return err
	}
	defer func() { _ = os.RemoveAll(stateDir) }()

	store, err := trust.NewFileStore(stateDir + "/state.json")
	if err != nil {
		slog.Error("configure trust state store", "error", err)
		return err
	}

	backend, err := openTPM(tpm.GoTPMConfig{
		DevicePath: strings.TrimSpace(*tpmDevice),
	})
	if err != nil {
		return err
	}
	defer func() { _ = backend.Close() }()

	metadataPathClean := strings.TrimSpace(*metadataPath)
	kms, err := newKeyStore(metadataPathClean)
	if err != nil {
		return err
	}
	km, err := newManager(
		backend,
		kms,
		keymanager.DefaultPolicies(),
		nil,
		nil,
	)
	if err != nil {
		return err
	}
	if err := km.Open(ctx); err != nil {
		return err
	}

	svc, err := trust.NewService(trust.ServiceConfig{
		Identity:                   identity,
		Store:                      store,
		KeyManager:                 km,
		Policy:                     trust.AuthorizationPolicyFunc(nil),
		FederationMaterial:         nil,
		PublicSnapshotBuilder:      nil,
		Publisher:                  nil,
		Clock:                      systemClock{},
		MaximumGrantLifetime:       10 * time.Minute,
		MaximumCertificateLifetime: 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	if err := svc.Open(ctx); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	pb.RegisterTrustServer(grpcServer, trust.NewTrustServer(svc))

	go func() {
		slog.Info("trust gRPC server listening", "address", listener.Addr().String())
		if err := grpcServer.Serve(listener); err != nil {
			slog.Error("trust gRPC server failed", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		slog.Info("trust gRPC server shutting down")
		grpcServer.GracefulStop()
	}()

	go func() {
		if err := svc.DrainOutbox(context.Background()); err != nil {
			slog.Error("trust outbox drain failed", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("trust service stopped")
	return nil
}
