// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import "context"

// KubernetesInstaller owns only the initial Kubernetes actions required by the
// nine bootstrap steps. The topology document is opaque to this package and
// must describe the complete authority-approved kubeadm replacement.
type KubernetesInstaller interface {
	PrepareKubelet(
		context.Context,
		Operation,
		Artifact,
		Artifact,
	) (Observation, error)
	VerifyKubelet(
		context.Context,
		Operation,
		Artifact,
		Artifact,
		Observation,
	) error
	InitializeAPIServer(
		context.Context,
		Operation,
		Artifact,
		Artifact,
	) (Observation, error)
	VerifyAPIServer(
		context.Context,
		Operation,
		Artifact,
		Artifact,
		Observation,
	) error
	WaitControlPlane(
		context.Context,
		Operation,
		Artifact,
	) (Observation, error)
	VerifyControlPlane(
		context.Context,
		Operation,
		Artifact,
		Observation,
	) error
	Reconcile(
		context.Context,
		Operation,
		Artifact,
	) (Observation, error)
	VerifyReconciled(
		context.Context,
		Operation,
		Artifact,
		Observation,
	) error
	CheckReady(context.Context, Operation) (Observation, error)
	VerifyReady(context.Context, Operation, Observation) error
}
