// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"context"
	"errors"
	"regexp"
	"time"
)

// Operation identifies one mutation that requires an explicit authorization
// decision. It is an internal domain value and does not add a public RPC.
type Operation string

const (
	OperationAdopt                Operation = "adopt"
	OperationRevokeRelationship   Operation = "revoke-relationship"
	OperationInitializeCA         Operation = "initialize-ca"
	OperationIssueMTLSCertificate Operation = "issue-mtls-certificate"
	OperationRevokeCertificate    Operation = "revoke-certificate"
	OperationFederate             Operation = "federate"
)

// OwnershipRole is the explicit authority held by one adopted principal.
type OwnershipRole string

const (
	OwnershipRoleOwner       OwnershipRole = "owner"
	OwnershipRoleBackupAdmin OwnershipRole = "backup-admin"
)

// RelationshipPhase is the durable adoption/ownership state.
type RelationshipPhase string

const (
	RelationshipPhaseProvisional RelationshipPhase = "provisional"
	RelationshipPhaseAuthorized  RelationshipPhase = "authorized"
	RelationshipPhaseRevoked     RelationshipPhase = "revoked"
)

// FederationRole records explicit hub-and-spoke membership. A directed edge is
// still required; membership never implies a reverse or spoke-to-spoke edge.
type FederationRole string

const (
	FederationRoleHub   FederationRole = "hub"
	FederationRoleSpoke FederationRole = "spoke"
)

// AuthorizationIntent is public-only input to the injected policy. The policy
// must bind any external approval transcript and proof of possession to this
// authenticated peer and the exact current revision.
type AuthorizationIntent struct {
	Operation         Operation
	Peer              VerifiedMTLSPeer
	LocalIdentity     DeviceIdentity
	TargetPeerID      string
	RelationshipID    string
	CertificateID     string
	RemoteTrustDomain string
	CurrentRevision   uint64
}

// AuthorizationGrant is the smallest fail-closed result consumed by the
// domain core. GrantID is treated as sensitive approval material: only its
// domain-separated digest is persisted.
type AuthorizationGrant struct {
	GrantID              string
	ExpectedRevision     uint64
	ExpiresAt            time.Time
	OwnershipRole        OwnershipRole
	RelationshipPhase    RelationshipPhase
	RelatedRelationship  string
	LocalFederationRole  FederationRole
	RemoteFederationRole FederationRole
	SourceGeneration     uint64
	CertificateNotBefore time.Time
	CertificateNotAfter  time.Time
}

// AuthorizationPolicy supplies first-trust and all subsequent mutation
// authorization. A nil or typed-nil policy always denies every mutation.
//
// The unresolved v5 first-trust transcript, issuer hierarchy, and federation
// topology decisions belong behind this boundary; implementations must never
// weaken mTLS to satisfy them.
type AuthorizationPolicy interface {
	Authorize(context.Context, AuthorizationIntent) (AuthorizationGrant, error)
}

// AuthorizationPolicyFunc adapts a function to AuthorizationPolicy.
type AuthorizationPolicyFunc func(
	context.Context,
	AuthorizationIntent,
) (AuthorizationGrant, error)

// Authorize implements AuthorizationPolicy.
func (f AuthorizationPolicyFunc) Authorize(
	ctx context.Context,
	intent AuthorizationIntent,
) (AuthorizationGrant, error) {
	if f == nil {
		return AuthorizationGrant{}, ErrAuthorizationUnavailable
	}
	return f(ctx, intent)
}

var grantIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func validateGrant(
	grant AuthorizationGrant,
	expectedRevision uint64,
	now time.Time,
	maximumLifetime time.Duration,
) error {
	if !grantIDPattern.MatchString(grant.GrantID) {
		return errors.New("authorization grant ID is invalid")
	}
	if grant.ExpectedRevision != expectedRevision {
		return ErrStaleGeneration
	}
	if grant.ExpiresAt.IsZero() || !grant.ExpiresAt.After(now) {
		return errors.New("authorization grant is expired")
	}
	if maximumLifetime <= 0 ||
		grant.ExpiresAt.After(now.Add(maximumLifetime)) {
		return errors.New("authorization grant exceeds the configured lifetime")
	}
	return nil
}
