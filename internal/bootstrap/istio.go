// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import "context"

// IstioInstaller validates ingress configuration before API activation and
// installs/reconciles only pinned upstream Istio resources afterward.
type IstioInstaller interface {
	PrepareIngress(
		context.Context,
		Operation,
		Artifact,
		Artifact,
	) (Observation, error)
	VerifyIngress(
		context.Context,
		Operation,
		Artifact,
		Artifact,
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
