// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sovereignite/sovereignite/internal/ipfs"
)

type dependencies struct {
	openSigner func(context.Context) (*ipfs.TPMIPNSSigner, error)
	openNode   func(
		context.Context,
		ipfs.Config,
		*ipfs.TPMIPNSSigner,
	) (ipfs.FullKuboNode, error)
	clock ipfs.Clock
}

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	if err := run(
		ctx,
		os.Args[1:],
		defaultDependencies(),
		os.Stderr,
	); err != nil {
		slog.Error("IPFS service stopped", "error", err)
		os.Exit(1)
	}
}

func defaultDependencies() dependencies {
	return dependencies{
		openSigner: func(context.Context) (*ipfs.TPMIPNSSigner, error) {
			return nil, ipfs.ErrKeyManagerSignerUnavailable
		},
		openNode: func(
			context.Context,
			ipfs.Config,
			*ipfs.TPMIPNSSigner,
		) (ipfs.FullKuboNode, error) {
			return nil, fmt.Errorf(
				"%w: D-003 requires an authorized maintained full-Kubo injection",
				ipfs.ErrFullKuboIntegrationUnavailable,
			)
		},
	}
}

func run(
	ctx context.Context,
	args []string,
	deps dependencies,
	errorOutput io.Writer,
) error {
	return runWithConfig(
		ctx,
		args,
		deps,
		errorOutput,
		ipfs.DefaultConfig(),
	)
}

func runWithConfig(
	ctx context.Context,
	args []string,
	deps dependencies,
	errorOutput io.Writer,
	config ipfs.Config,
) error {
	if ctx == nil {
		return errors.New("run context is required")
	}
	if errorOutput == nil {
		return errors.New("flag error output is required")
	}
	flags := flag.NewFlagSet("sovereignite-ipfs", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf(
			"unexpected positional arguments: %s",
			strings.Join(flags.Args(), " "),
		)
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deps.openSigner == nil {
		return ipfs.ErrKeyManagerSignerUnavailable
	}
	signer, err := deps.openSigner(ctx)
	if err != nil {
		return fmt.Errorf("open Key Manager IPNS signer: %w", err)
	}
	if signer == nil {
		return errors.New("Key Manager returned no IPNS signer")
	}
	if deps.openNode == nil {
		return ipfs.ErrFullKuboIntegrationUnavailable
	}
	node, err := deps.openNode(ctx, config, signer)
	if err != nil {
		return fmt.Errorf("open full Kubo node: %w", err)
	}
	if node == nil {
		return errors.New("full Kubo factory returned no node")
	}
	service, err := ipfs.StartService(ctx, config, signer, node, deps.clock)
	if err != nil {
		return err
	}
	slog.Info(
		"full Kubo IPFS service ready",
		"ipns_name",
		service.Readiness().IPNSName,
		"ula",
		service.Readiness().ULA,
	)
	return service.Run(ctx)
}
