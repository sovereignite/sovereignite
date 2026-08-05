// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import "context"

// SigningPurpose is closed to the one Key Manager operation authorized by the
// first bootstrap step.
type SigningPurpose string

const (
	// SigningPurposeBootstrapCA prevents the bootstrap adapter from becoming a
	// general-purpose TPM signing oracle.
	SigningPurposeBootstrapCA SigningPurpose = "bootstrap-ca-signing"
)

// CARequest binds the public signing request to the authority-approved key
// inventory and issuer hierarchy. It contains no private key material.
type CARequest struct {
	Purpose         SigningPurpose
	Artifact        Artifact
	KeyInventory    Artifact
	IssuerHierarchy Artifact
}

// CASigner is the narrow Key Manager boundary used by bootstrap. EnsureSigning
// must create or reopen the same TPM-backed CA result for an idempotency key;
// it must not allocate, rotate, export, or replace a key on retry.
type CASigner interface {
	EnsureSigning(context.Context, Operation, CARequest) (Observation, error)
	VerifySigning(context.Context, Operation, CARequest, Observation) error
}
