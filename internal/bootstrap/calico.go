// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"context"
	"net/netip"
)

// CalicoInstaller renders and validates the injected ULA before API
// activation, then installs/reconciles pinned upstream Calico resources after
// the control plane is ready. It must not invent another CIDR.
type CalicoInstaller interface {
	PrepareIPv6(
		context.Context,
		Operation,
		netip.Prefix,
		Artifact,
	) (Observation, error)
	VerifyIPv6(
		context.Context,
		Operation,
		netip.Prefix,
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
