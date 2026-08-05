// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import "context"

// SPIRERequest binds SPIRE's TPM plugin/TPM Device Key configuration to the
// explicit key inventory and issuer hierarchy. Node attestation is not treated
// as CA key management.
type SPIRERequest struct {
	Artifact              Artifact
	TPMDeviceKeyReference string
	KeyInventory          Artifact
	IssuerHierarchy       Artifact
}

// SPIREInstaller validates static configuration before API activation and
// installs/reconciles pinned upstream SPIRE resources afterward.
type SPIREInstaller interface {
	PrepareTPM(
		context.Context,
		Operation,
		SPIRERequest,
	) (Observation, error)
	VerifyTPM(
		context.Context,
		Operation,
		SPIRERequest,
		Observation,
	) error
	Reconcile(context.Context, Operation, Artifact) (Observation, error)
	VerifyReconciled(
		context.Context,
		Operation,
		Artifact,
		Observation,
	) error
	CheckReady(context.Context, Operation) (Observation, error)
	VerifyReady(context.Context, Operation, Observation) error
}
