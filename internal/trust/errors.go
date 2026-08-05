// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import "errors"

var (
	// ErrAuthorizationUnavailable means no authority-approved policy was
	// injected. The operation must remain disabled.
	ErrAuthorizationUnavailable = errors.New("trust authorization policy is unavailable")
	// ErrPublicationUnavailable means no public-only publication boundary was
	// injected.
	ErrPublicationUnavailable = errors.New("public trust-state publisher is unavailable")
	// ErrPublicationSchemaUnavailable means authoritative public protocol
	// document rendering remains unresolved.
	ErrPublicationSchemaUnavailable = errors.New("public trust-state schema builder is unavailable")
	// ErrRevisionConflict means another writer committed state first.
	ErrRevisionConflict = errors.New("trust state revision conflict")
	// ErrStateRollback means durable state predates or differs from its
	// monotonic revision anchor.
	ErrStateRollback = errors.New("trust state rollback detected")
	// ErrStaleGeneration means a caller or policy acted on older state.
	ErrStaleGeneration = errors.New("stale trust state generation")
	// ErrReplay means an authorization grant or publication was already used.
	ErrReplay = errors.New("trust operation replay rejected")
	// ErrNotAuthorized means the authenticated peer has no current authority.
	ErrNotAuthorized = errors.New("authenticated peer is not authorized")
	// ErrUnsupportedStateVersion means durable state was written by an
	// unsupported schema version.
	ErrUnsupportedStateVersion = errors.New("unsupported trust state version")
	// ErrMismatchedPublicKey means the supplied public key does not derive
	// the expected peer ID.
	ErrMismatchedPublicKey = errors.New("public key does not match the expected peer ID")
	// ErrMismatchedPeerID means the record peer ID does not match the local
	// device peer ID.
	ErrMismatchedPeerID = errors.New("identity record peer ID does not match the local device")
	// ErrMismatchedSPIFFEID means the SPIFFE ID is not correctly derived from
	// the trust domain and peer ID.
	ErrMismatchedSPIFFEID = errors.New("SPIFFE ID does not match the expected derivation")
	// ErrUnknownHandle means the TPM persistent handle is not a locally-known
	// handle.
	ErrUnknownHandle = errors.New("TPM persistent handle is unknown or foreign")
	// ErrInvalidPhaseTransition means the requested identity phase transition
	// is not permitted.
	ErrInvalidPhaseTransition = errors.New("identity phase transition is not permitted")
	// ErrIdentityAlreadyRevoked means the identity is already in the revoked
	// phase.
	ErrIdentityAlreadyRevoked = errors.New("identity is already revoked")
	// ErrStalePeerRecordEnvelope means the peer record envelope sequence is
	// older than the current record.
	ErrStalePeerRecordEnvelope = errors.New("peer record envelope sequence is stale")
)
