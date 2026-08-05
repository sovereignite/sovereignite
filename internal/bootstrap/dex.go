// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import "context"

// DexRequest binds static Dex configuration to the authority-approved issuer
// hierarchy and ingress/token flow. It does not authorize token issuance.
type DexRequest struct {
	Artifact          Artifact
	IssuerHierarchy   Artifact
	IngressTokenFlow  Artifact
}

// DexInstaller installs and reconciles pinned upstream Dex configuration only
// during the existing "apply cluster configs" step.
type DexInstaller interface {
	Reconcile(context.Context, Operation, DexRequest) (Observation, error)
	VerifyReconciled(
		context.Context,
		Operation,
		DexRequest,
		Observation,
	) error
	CheckReady(context.Context, Operation) (Observation, error)
	VerifyReady(context.Context, Operation, Observation) error
}
