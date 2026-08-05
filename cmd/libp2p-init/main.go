// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	identity "github.com/sovereignite/sovereignite/internal/libp2p"
	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"
	"google.golang.org/grpc"
)

var errTPMProviderUnavailable = errors.New(
	"TPM key provider is unavailable; software-key fallback is prohibited",
)

type dependencies struct {
	openKey        func(context.Context) (identity.TPMSigningKey, error)
	hostLauncher   identity.HostLauncher
	hostnameSetter identity.HostnameSetter
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if err := run(ctx, os.Args[1:], defaultDependencies()); err != nil {
		slog.Error("libp2p identity service stopped", "error", err)
		os.Exit(1)
	}
}

func defaultDependencies() dependencies {
	return dependencies{
		openKey: func(context.Context) (identity.TPMSigningKey, error) {
			return nil, errTPMProviderUnavailable
		},
		hostnameSetter: identity.DBusHostnameSetter{},
	}
}

func run(ctx context.Context, args []string, deps dependencies) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	config := identity.DefaultConfig()
	flags := flag.NewFlagSet("libp2p-init", flag.ContinueOnError)
	flags.StringVar(
		&config.StateRoot,
		"state-root",
		config.StateRoot,
		"absolute lifetime-stable public identity directory",
	)
	flags.StringVar(
		&config.RuntimeRoot,
		"runtime-root",
		config.RuntimeRoot,
		"absolute boot-scoped endpoint directory",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deps.openKey == nil {
		return errTPMProviderUnavailable
	}
	if deps.hostnameSetter == nil {
		return errors.New("hostname setter is required")
	}
	key, err := deps.openKey(ctx)
	if err != nil {
		return fmt.Errorf("open lifetime TPM identity key: %w", err)
	}
	if key == nil {
		return errors.New("TPM key provider returned no key")
	}
	service, err := identity.Start(
		ctx,
		config,
		key,
		deps.hostLauncher,
		deps.hostnameSetter,
	)
	if err != nil {
		return err
	}
	slog.Info(
		"libp2p identity core initialized",
		"identity",
		service.Identity().Name,
		"readiness_seam",
		fmt.Sprintf(
			"%s:%d",
			service.Endpoint().Address,
			service.Endpoint().Port,
		),
	)

	go func() {
		if err := service.Run(ctx); err != nil {
			slog.Error("readiness listener stopped", "error", err)
		}
	}()

	grpcServer := grpc.NewServer()
	pb.RegisterIdentityServer(grpcServer, identity.NewIdentityServer(service))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = service.Close()
		return fmt.Errorf("bind gRPC endpoint: %w", err)
	}

	slog.Info("gRPC server listening", "address", lis.Addr().String())

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	serveErr := grpcServer.Serve(lis)
	closeErr := service.Close()
	return errors.Join(serveErr, closeErr)
}
