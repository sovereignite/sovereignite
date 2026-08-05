// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/sovereignite/sovereignite/internal/keymanager"
)

const (
	grantDigestDomain               = "github.com/sovereignite/sovereignite/trust-authorization-grant/v1\x00"
	relationshipDigestDomain        = "github.com/sovereignite/sovereignite/trust-relationship/v1\x00"
	uncertainRevocationDigestDomain = "github.com/sovereignite/sovereignite/trust-uncertain-revocation/v1\x00"
)

// Clock makes persisted transition times deterministic in tests.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now()
}

// ServiceConfig contains only internal dependencies and fixed limits. It does
// not define a listener or extend the sovereignite.v1 API.
type ServiceConfig struct {
	Identity                   DeviceIdentity
	Store                      Store
	KeyManager                 CertificateKeyManager
	Policy                     AuthorizationPolicy
	FederationMaterial         FederationMaterialProvider
	PublicSnapshotBuilder      PublicSnapshotBuilder
	Publisher                  Publisher
	Clock                      Clock
	MaximumGrantLifetime       time.Duration
	MaximumCertificateLifetime time.Duration
}

// Service owns the durable Trust domain core.
type Service struct {
	openMu    sync.Mutex
	mu        sync.Mutex
	publishMu sync.Mutex
	issueMu   sync.Mutex

	config   ServiceConfig
	opened   bool
	snapshot Snapshot
}

// NewService validates immutable identity and safety bounds without performing
// I/O. Missing policy/builder/publisher/issuer seams are retained so read-only
// startup can explain the exact fail-closed gate.
func NewService(config ServiceConfig) (*Service, error) {
	identity, err := DeriveDeviceIdentity(
		config.Identity.CanonicalIPNS,
		config.Identity.PeerID,
	)
	if err != nil {
		return nil, fmt.Errorf("configure trust identity: %w", err)
	}
	if identity != config.Identity {
		return nil, errors.New("configured trust identity fields are inconsistent")
	}
	if isNil(config.Store) {
		return nil, errors.New("trust state store is required")
	}
	if config.Clock == nil {
		config.Clock = systemClock{}
	}
	if config.MaximumGrantLifetime <= 0 {
		return nil, errors.New("maximum authorization grant lifetime is required")
	}
	if config.MaximumCertificateLifetime <= 0 {
		return nil, errors.New("maximum certificate lifetime is required")
	}
	return &Service{config: config}, nil
}

// Open loads and validates durable state. First open atomically binds the
// state root to the configured lifetime identity.
func (s *Service) Open(ctx context.Context) error {
	if ctx == nil {
		return errors.New("trust open context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.openMu.Lock()
	defer s.openMu.Unlock()
	s.mu.Lock()
	if s.opened {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	snapshot, err := s.config.Store.Load()
	if err != nil {
		return fmt.Errorf("load trust state: %w", err)
	}
	for attempt := 0; attempt < 8; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateSnapshot(snapshot); err != nil {
			return fmt.Errorf("validate loaded trust state: %w", err)
		}
		if snapshot.Revision == 0 {
			next := cloneSnapshot(snapshot)
			next.Identity = s.config.Identity
			next.Revision = 1
			if err := s.config.Store.Commit(0, next); err != nil {
				if !errors.Is(err, ErrRevisionConflict) {
					return fmt.Errorf("initialize trust state: %w", err)
				}
				snapshot, err = s.config.Store.Load()
				if err != nil {
					return fmt.Errorf("reload initialized trust state: %w", err)
				}
				continue
			}
			snapshot = next
		} else if snapshot.Identity != s.config.Identity {
			return errors.New("durable trust identity does not match configured identity")
		}
		if len(snapshot.PendingCertificates) != 0 {
			now := s.config.Clock.Now().UTC()
			if now.IsZero() {
				return errors.New("trust clock returned zero time during issuance recovery")
			}
			next := cloneSnapshot(snapshot)
			next.Revision++
			for id, pending := range next.PendingCertificates {
				next.BurnedSerials[pending.Serial] = now
				delete(next.PendingCertificates, id)
			}
			if err := s.attachPublicOutbox(ctx, &next, now); err != nil {
				return fmt.Errorf("publish uncertain certificate serials: %w", err)
			}
			if err := s.config.Store.Commit(snapshot.Revision, next); err != nil {
				if !errors.Is(err, ErrRevisionConflict) {
					return fmt.Errorf("burn uncertain certificate serials: %w", err)
				}
				snapshot, err = s.config.Store.Load()
				if err != nil {
					return fmt.Errorf("reload recovered trust state: %w", err)
				}
				continue
			}
			snapshot = next
		}
		s.mu.Lock()
		s.snapshot = cloneSnapshot(snapshot)
		s.opened = true
		s.mu.Unlock()
		return nil
	}
	return ErrRevisionConflict
}

// Snapshot returns a validated deep copy for internal inspection and tests.
func (s *Service) Snapshot() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.opened {
		return Snapshot{}, errors.New("trust service is not open")
	}
	return cloneSnapshot(s.snapshot), nil
}

// GetTrustRelationships returns only currently authorized relationships.
// Provisional and revoked records remain internal because the committed proto
// has no phase field for them.
func (s *Service) GetTrustRelationships() ([]RelationshipRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.opened {
		return nil, errors.New("trust service is not open")
	}
	return sortedRelationshipRecords(s.snapshot.Relationships), nil
}

// GetFederations returns explicit directed edges sorted by target domain.
func (s *Service) GetFederations() ([]FederationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.opened {
		return nil, errors.New("trust service is not open")
	}
	result := make([]FederationRecord, 0, len(s.snapshot.Federations))
	for _, federation := range s.snapshot.Federations {
		federation.RemoteCACertificate = slices.Clone(federation.RemoteCACertificate)
		federation.CrossCertificate = slices.Clone(federation.CrossCertificate)
		result = append(result, federation)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].TargetDomain < result[right].TargetDomain
	})
	return result, nil
}

// AdoptDevice applies an injected authorization grant to the exact local
// target selected by the committed RPC. The caller is derived exclusively from
// a verified mutual-TLS client certificate.
func (s *Service) AdoptDevice(
	ctx context.Context,
	state tls.ConnectionState,
	targetPeerID string,
) (RelationshipRecord, error) {
	peer, current, now, err := s.authorizedInput(
		ctx,
		state,
		OperationAdopt,
		targetPeerID,
		"",
		"",
	)
	if err != nil {
		return RelationshipRecord{}, err
	}
	if targetPeerID != s.config.Identity.PeerID {
		return RelationshipRecord{}, errors.New("adoption target is not the local device")
	}
	grant, err := s.callPolicy(ctx, AuthorizationIntent{
		Operation:       OperationAdopt,
		Peer:            peer,
		LocalIdentity:   s.config.Identity,
		TargetPeerID:    targetPeerID,
		CurrentRevision: current.Revision,
	}, current, now)
	if err != nil {
		return RelationshipRecord{}, err
	}

	next := cloneSnapshot(current)
	next.Revision++
	relationship, err := applyAdoption(
		&next,
		peer,
		grant,
		now,
	)
	if err != nil {
		return RelationshipRecord{}, err
	}
	recordAppliedGrant(&next, grant, OperationAdopt, now)
	if err := s.attachPublicOutbox(ctx, &next, now); err != nil {
		return RelationshipRecord{}, err
	}
	if err := s.commitCandidate(current.Revision, next); err != nil {
		return RelationshipRecord{}, err
	}
	return relationship, nil
}

// RevokeTrust atomically revokes one relationship and every certificate bound
// to it before public publication is attempted.
func (s *Service) RevokeTrust(
	ctx context.Context,
	state tls.ConnectionState,
	relationshipID string,
) error {
	peer, current, now, err := s.authorizedInput(
		ctx,
		state,
		OperationRevokeRelationship,
		"",
		relationshipID,
		"",
	)
	if err != nil {
		return err
	}
	if !certificateIDPattern.MatchString(relationshipID) {
		return errors.New("relationship ID is invalid")
	}
	if _, err := requireAuthorizedPrincipal(current, peer, true); err != nil {
		return err
	}
	relationship, exists := current.Relationships[relationshipID]
	if !exists || relationship.Phase == RelationshipPhaseRevoked {
		return ErrNotAuthorized
	}
	grant, err := s.callPolicy(ctx, AuthorizationIntent{
		Operation:       OperationRevokeRelationship,
		Peer:            peer,
		LocalIdentity:   s.config.Identity,
		RelationshipID:  relationshipID,
		CurrentRevision: current.Revision,
	}, current, now)
	if err != nil {
		return err
	}

	next := cloneSnapshot(current)
	next.Revision++
	relationship.Phase = RelationshipPhaseRevoked
	relationship.Generation++
	relationship.UpdatedAt = now
	next.Relationships[relationshipID] = relationship
	for id, certificate := range next.Certificates {
		if certificate.RelationshipID != relationshipID ||
			certificate.Status == CertificateStatusRevoked {
			continue
		}
		certificate.Status = CertificateStatusRevoked
		certificate.RevokedAt = now
		next.Certificates[id] = certificate
		next.Revocations[id] = RevocationRecord{
			CertificateID:  id,
			Serial:         certificate.Serial,
			Kind:           RevocationKindMTLS,
			CertificateDER: slices.Clone(certificate.DER),
			RevokedAt:      now,
		}
	}
	recordAppliedGrant(&next, grant, OperationRevokeRelationship, now)
	if err := s.attachPublicOutbox(ctx, &next, now); err != nil {
		return err
	}
	return s.commitCandidate(current.Revision, next)
}

// InitializeLocalCA creates the device-local CA only through the TPM-backed
// Key Manager boundary. It remains disabled unless the injected policy and
// public schema builder authorize the unresolved production hierarchy.
func (s *Service) InitializeLocalCA(ctx context.Context) ([]byte, error) {
	s.issueMu.Lock()
	defer s.issueMu.Unlock()
	current, now, err := s.currentState(ctx)
	if err != nil {
		return nil, err
	}
	if len(current.PendingCertificates) != 0 {
		return nil, errors.New("uncertain certificate issuance requires recovery")
	}
	if len(current.ActiveCACertificate) != 0 {
		return nil, errors.New("device-local CA is already initialized")
	}
	grant, err := s.callPolicy(ctx, AuthorizationIntent{
		Operation:       OperationInitializeCA,
		LocalIdentity:   s.config.Identity,
		CurrentRevision: current.Revision,
	}, current, now)
	if err != nil {
		return nil, err
	}
	if err := s.validateCertificateGrant(grant, now); err != nil {
		return nil, err
	}
	publicKey, err := caPublicKey(ctx, s.config.KeyManager)
	if err != nil {
		return nil, err
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal TPM CA public key: %w", err)
	}
	pending, err := s.reserveCertificate(
		current,
		grant,
		OperationInitializeCA,
		"",
		"",
		s.config.Identity.SPIFFEID,
		publicKeyDER,
		now,
	)
	if err != nil {
		return nil, err
	}
	serial, _ := new(big.Int).SetString(pending.Serial, 10)
	encoded, err := issueLocalCA(
		ctx,
		s.config.KeyManager,
		s.config.Identity,
		serial,
		pending.NotBefore,
		pending.NotAfter,
	)
	if err != nil {
		return nil, s.burnPending(context.WithoutCancel(ctx), pending.ID, err)
	}

	bookkeepingCtx := context.WithoutCancel(ctx)
	err = s.finalizePending(
		bookkeepingCtx,
		pending.ID,
		func(next *Snapshot, _ PendingCertificate, completedAt time.Time) error {
			if len(next.ActiveCACertificate) != 0 {
				return errors.New("device-local CA was initialized concurrently")
			}
			next.ActiveCACertificate = slices.Clone(encoded)
			next.ActiveCAID = certificateID(encoded)
			next.Bundles[s.config.Identity.TrustDomain] = TrustBundleRecord{
				TrustDomain:    s.config.Identity.TrustDomain,
				Generation:     1,
				CACertificates: [][]byte{slices.Clone(encoded)},
				UpdatedAt:      completedAt,
			}
			return nil
		},
	)
	if err != nil {
		return nil, s.burnPending(bookkeepingCtx, pending.ID, err)
	}
	return slices.Clone(encoded), nil
}

// IssueLocalMTLSCertificate issues only the canonical local device identity.
// Mobile/client subject namespaces and enrollment remain blocked by D-004 and
// are not generalized here.
func (s *Service) IssueLocalMTLSCertificate(ctx context.Context) ([]byte, error) {
	s.issueMu.Lock()
	defer s.issueMu.Unlock()
	current, now, err := s.currentState(ctx)
	if err != nil {
		return nil, err
	}
	if len(current.PendingCertificates) != 0 {
		return nil, errors.New("uncertain certificate issuance requires recovery")
	}
	if len(current.ActiveCACertificate) == 0 {
		return nil, errors.New("device-local CA is not initialized")
	}
	if isNil(s.config.KeyManager) {
		return nil, errors.New("TPM-backed certificate key manager is unavailable")
	}
	grant, err := s.callPolicy(ctx, AuthorizationIntent{
		Operation:       OperationIssueMTLSCertificate,
		LocalIdentity:   s.config.Identity,
		CurrentRevision: current.Revision,
	}, current, now)
	if err != nil {
		return nil, err
	}
	if err := s.validateCertificateGrant(grant, now); err != nil {
		return nil, err
	}
	metadata, err := s.config.KeyManager.Metadata(
		ctx,
		keymanager.RoleDeviceIPNSIdentity,
	)
	if err != nil {
		return nil, fmt.Errorf("load local device public key: %w", err)
	}
	if metadata.Role != keymanager.RoleDeviceIPNSIdentity ||
		metadata.Purpose != keymanager.PurposeDeviceIPNSIdentity {
		return nil, errors.New("local device public key has an invalid role or purpose")
	}
	publicKey, err := x509.ParsePKIXPublicKey(metadata.PublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse local device public key: %w", err)
	}
	parent, err := x509.ParseCertificate(current.ActiveCACertificate)
	if err != nil {
		return nil, fmt.Errorf("parse active CA: %w", err)
	}
	subjectPublicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal local device public key: %w", err)
	}
	pending, err := s.reserveCertificate(
		current,
		grant,
		OperationIssueMTLSCertificate,
		"",
		"",
		s.config.Identity.SPIFFEID,
		subjectPublicKeyDER,
		now,
	)
	if err != nil {
		return nil, err
	}
	serial, _ := new(big.Int).SetString(pending.Serial, 10)
	encoded, err := issueMTLSLeaf(
		ctx,
		s.config.KeyManager,
		parent,
		s.config.Identity,
		serial,
		publicKey,
		pending.NotBefore,
		pending.NotAfter,
	)
	if err != nil {
		return nil, s.burnPending(context.WithoutCancel(ctx), pending.ID, err)
	}
	certificate, _ := x509.ParseCertificate(encoded)
	record := CertificateRecord{
		ID:                  certificateID(encoded),
		SPIFFEID:            s.config.Identity.SPIFFEID,
		Serial:              serial.String(),
		DER:                 slices.Clone(encoded),
		SubjectPublicKeyDER: slices.Clone(certificate.RawSubjectPublicKeyInfo),
		NotBefore:           certificate.NotBefore.UTC(),
		NotAfter:            certificate.NotAfter.UTC(),
		Status:              CertificateStatusActive,
		IssuedAt:            pending.CreatedAt,
	}
	bookkeepingCtx := context.WithoutCancel(ctx)
	err = s.finalizePending(
		bookkeepingCtx,
		pending.ID,
		func(next *Snapshot, _ PendingCertificate, completedAt time.Time) error {
			record.IssuedAt = completedAt
			if _, exists := next.Certificates[record.ID]; exists {
				return errors.New("issued certificate already exists")
			}
			next.Certificates[record.ID] = record
			return nil
		},
	)
	if err != nil {
		return nil, s.burnPending(bookkeepingCtx, pending.ID, err)
	}
	return slices.Clone(encoded), nil
}

// Federate creates exactly one directed local-to-remote hub/spoke edge and a
// TPM-signed cross-certificate. No reverse, transitive, authorization, or route
// edge is inferred.
func (s *Service) Federate(
	ctx context.Context,
	state tls.ConnectionState,
	remoteTrustDomain string,
) (FederationRecord, error) {
	s.issueMu.Lock()
	defer s.issueMu.Unlock()
	if _, err := TrustDomainFromIPNS(remoteTrustDomain); err != nil {
		return FederationRecord{}, err
	}
	if remoteTrustDomain == s.config.Identity.TrustDomain {
		return FederationRecord{}, errors.New("federation self-edge is prohibited")
	}
	peer, current, now, err := s.authorizedInput(
		ctx,
		state,
		OperationFederate,
		"",
		"",
		remoteTrustDomain,
	)
	if err != nil {
		return FederationRecord{}, err
	}
	if _, err := requireAuthorizedPrincipal(current, peer, true); err != nil {
		return FederationRecord{}, err
	}
	if len(current.PendingCertificates) != 0 {
		return FederationRecord{}, errors.New(
			"uncertain certificate issuance requires recovery",
		)
	}
	if len(current.ActiveCACertificate) == 0 {
		return FederationRecord{}, errors.New("device-local CA is not initialized")
	}
	if isNil(s.config.KeyManager) {
		return FederationRecord{}, errors.New(
			"TPM-backed certificate key manager is unavailable",
		)
	}
	grant, err := s.callPolicy(ctx, AuthorizationIntent{
		Operation:         OperationFederate,
		Peer:              peer,
		LocalIdentity:     s.config.Identity,
		RemoteTrustDomain: remoteTrustDomain,
		CurrentRevision:   current.Revision,
	}, current, now)
	if err != nil {
		return FederationRecord{}, err
	}
	if !complementaryFederationRoles(
		grant.LocalFederationRole,
		grant.RemoteFederationRole,
	) {
		return FederationRecord{}, errors.New(
			"federation policy did not authorize explicit hub-and-spoke roles",
		)
	}
	if err := s.validateCertificateGrant(grant, now); err != nil {
		return FederationRecord{}, err
	}
	if isNil(s.config.FederationMaterial) {
		return FederationRecord{}, errors.New(
			"federation public material provider is unavailable",
		)
	}
	material, err := s.config.FederationMaterial.Fetch(
		ctx,
		s.config.Identity,
		remoteTrustDomain,
		peer,
	)
	if err != nil {
		return FederationRecord{}, fmt.Errorf("fetch federation material: %w", err)
	}
	if material.SourceGeneration == 0 ||
		material.SourceGeneration != grant.SourceGeneration {
		return FederationRecord{}, ErrStaleGeneration
	}
	if existing, exists := current.Federations[remoteTrustDomain]; exists &&
		material.SourceGeneration <= existing.SourceGeneration {
		return FederationRecord{}, ErrStaleGeneration
	}
	remoteCADER := slices.Clone(material.RemoteCACertificateDER)
	remoteCA, err := x509.ParseCertificate(remoteCADER)
	if err != nil {
		return FederationRecord{}, fmt.Errorf("parse remote federation CA: %w", err)
	}
	if err := validateCACertificate(remoteCADER); err != nil {
		return FederationRecord{}, err
	}
	if remoteCA.Subject.CommonName != remoteTrustDomain {
		return FederationRecord{}, errors.New(
			"remote federation CA is bound to a different trust domain",
		)
	}
	parent, err := x509.ParseCertificate(current.ActiveCACertificate)
	if err != nil {
		return FederationRecord{}, fmt.Errorf("parse local federation CA: %w", err)
	}
	remotePublicKeyDER, err := x509.MarshalPKIXPublicKey(remoteCA.PublicKey)
	if err != nil {
		return FederationRecord{}, fmt.Errorf("marshal remote federation CA public key: %w", err)
	}
	pending, err := s.reserveCertificate(
		current,
		grant,
		OperationFederate,
		"",
		remoteTrustDomain,
		s.config.Identity.SPIFFEID,
		remotePublicKeyDER,
		now,
	)
	if err != nil {
		return FederationRecord{}, err
	}
	serial, _ := new(big.Int).SetString(pending.Serial, 10)
	crossCertificate, err := issueCrossCertificate(
		ctx,
		s.config.KeyManager,
		parent,
		remoteCA,
		serial,
		pending.NotBefore,
		pending.NotAfter,
	)
	if err != nil {
		return FederationRecord{}, s.burnPending(
			context.WithoutCancel(ctx),
			pending.ID,
			err,
		)
	}
	record := FederationRecord{
		SourceDomain:           s.config.Identity.TrustDomain,
		TargetDomain:           remoteTrustDomain,
		LocalRole:              grant.LocalFederationRole,
		RemoteRole:             grant.RemoteFederationRole,
		SourceGeneration:       material.SourceGeneration,
		RemoteCACertificate:    remoteCADER,
		CrossCertificate:       slices.Clone(crossCertificate),
		CrossCertificateID:     certificateID(crossCertificate),
		CrossCertificateSerial: pending.Serial,
		EstablishedAt:          now,
		UpdatedAt:              now,
	}
	bookkeepingCtx := context.WithoutCancel(ctx)
	err = s.finalizePending(
		bookkeepingCtx,
		pending.ID,
		func(next *Snapshot, _ PendingCertificate, completedAt time.Time) error {
			if existing, exists := next.Federations[remoteTrustDomain]; exists {
				if material.SourceGeneration <= existing.SourceGeneration {
					return ErrStaleGeneration
				}
				next.Revocations[existing.CrossCertificateID] = RevocationRecord{
					CertificateID:  existing.CrossCertificateID,
					Serial:         existing.CrossCertificateSerial,
					Kind:           RevocationKindCross,
					CertificateDER: slices.Clone(existing.CrossCertificate),
					RevokedAt:      completedAt,
				}
				record.EstablishedAt = existing.EstablishedAt
			}
			record.UpdatedAt = completedAt
			next.Federations[remoteTrustDomain] = record
			next.Bundles[remoteTrustDomain] = TrustBundleRecord{
				TrustDomain: remoteTrustDomain,
				Generation:  material.SourceGeneration,
				CACertificates: [][]byte{
					slices.Clone(remoteCADER),
				},
				UpdatedAt: completedAt,
			}
			return nil
		},
	)
	if err != nil {
		return FederationRecord{}, s.burnPending(bookkeepingCtx, pending.ID, err)
	}
	return record, nil
}

// RevokeCertificate enforces local revocation before its outbox is drained.
func (s *Service) RevokeCertificate(
	ctx context.Context,
	state tls.ConnectionState,
	certificateID string,
) error {
	peer, current, now, err := s.authorizedInput(
		ctx,
		state,
		OperationRevokeCertificate,
		"",
		"",
		"",
	)
	if err != nil {
		return err
	}
	if _, err := requireAuthorizedPrincipal(current, peer, true); err != nil {
		return err
	}
	certificate, exists := current.Certificates[certificateID]
	if !exists || certificate.Status != CertificateStatusActive {
		return ErrNotAuthorized
	}
	grant, err := s.callPolicy(ctx, AuthorizationIntent{
		Operation:       OperationRevokeCertificate,
		Peer:            peer,
		LocalIdentity:   s.config.Identity,
		CertificateID:   certificateID,
		CurrentRevision: current.Revision,
	}, current, now)
	if err != nil {
		return err
	}
	next := cloneSnapshot(current)
	next.Revision++
	certificate.Status = CertificateStatusRevoked
	certificate.RevokedAt = now
	next.Certificates[certificateID] = certificate
	next.Revocations[certificateID] = RevocationRecord{
		CertificateID:  certificateID,
		Serial:         certificate.Serial,
		Kind:           RevocationKindMTLS,
		CertificateDER: slices.Clone(certificate.DER),
		RevokedAt:      now,
	}
	recordAppliedGrant(&next, grant, OperationRevokeCertificate, now)
	if err := s.attachPublicOutbox(ctx, &next, now); err != nil {
		return err
	}
	return s.commitCandidate(current.Revision, next)
}

// DrainOutbox publishes pending immutable snapshots serially. A publisher
// failure leaves the item durable; a post-publish commit failure causes replay
// of the same ID and digest, which Publisher must handle idempotently.
func (s *Service) DrainOutbox(ctx context.Context) error {
	if ctx == nil {
		return errors.New("publication context is required")
	}
	if isNil(s.config.Publisher) {
		return ErrPublicationUnavailable
	}
	s.publishMu.Lock()
	defer s.publishMu.Unlock()

	for {
		current, _, err := s.currentState(ctx)
		if err != nil {
			return err
		}
		if len(current.Outbox) == 0 {
			return nil
		}
		ids := make([]string, 0, len(current.Outbox))
		for id := range current.Outbox {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(left, right int) bool {
			leftPublication := current.Outbox[ids[left]]
			rightPublication := current.Outbox[ids[right]]
			if leftPublication.StateRevision != rightPublication.StateRevision {
				return leftPublication.StateRevision < rightPublication.StateRevision
			}
			return ids[left] < ids[right]
		})
		publication := current.Outbox[ids[0]].Clone()
		receipt, err := s.config.Publisher.Publish(ctx, publication.Clone())
		if err != nil {
			return fmt.Errorf("publish public trust state %q: %w", publication.ID, err)
		}
		if err := validatePublicationReceipt(
			receipt,
			publication,
			current.LastIPNSSequence,
		); err != nil {
			return fmt.Errorf("validate public trust-state receipt: %w", err)
		}
		next := cloneSnapshot(current)
		next.Revision++
		delete(next.Outbox, publication.ID)
		if len(next.Published) >= maximumPublishedItems {
			pruneOldestPublished(next.Published)
		}
		next.Published[publication.ID] = PublishedRecord{
			Digest:       publication.Digest,
			RootCID:      receipt.RootCID,
			IPNSSequence: receipt.IPNSSequence,
			CompletedAt:  s.config.Clock.Now().UTC(),
		}
		next.LastIPNSSequence = receipt.IPNSSequence
		next.LastPublishedRoot = receipt.RootCID
		if err := s.commitCandidate(current.Revision, next); err != nil {
			return err
		}
	}
}

func pruneOldestPublished(records map[string]PublishedRecord) {
	var (
		oldestID       string
		oldestSequence uint64
	)
	for id, record := range records {
		if oldestID == "" || record.IPNSSequence < oldestSequence {
			oldestID = id
			oldestSequence = record.IPNSSequence
		}
	}
	if oldestID != "" {
		delete(records, oldestID)
	}
}

func (s *Service) authorizedInput(
	ctx context.Context,
	state tls.ConnectionState,
	_ Operation,
	_ string,
	_ string,
	_ string,
) (VerifiedMTLSPeer, Snapshot, time.Time, error) {
	current, now, err := s.currentState(ctx)
	if err != nil {
		return VerifiedMTLSPeer{}, Snapshot{}, time.Time{}, err
	}
	peer, err := VerifyMutualTLSPeer(state, now)
	if err != nil {
		return VerifiedMTLSPeer{}, Snapshot{}, time.Time{}, err
	}
	return peer, current, now, nil
}

func (s *Service) currentState(
	ctx context.Context,
) (Snapshot, time.Time, error) {
	if ctx == nil {
		return Snapshot{}, time.Time{}, errors.New("trust operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, time.Time{}, err
	}
	now := s.config.Clock.Now().UTC()
	if now.IsZero() {
		return Snapshot{}, time.Time{}, errors.New("trust clock returned zero time")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.opened {
		return Snapshot{}, time.Time{}, errors.New("trust service is not open")
	}
	return cloneSnapshot(s.snapshot), now, nil
}

func (s *Service) callPolicy(
	ctx context.Context,
	intent AuthorizationIntent,
	current Snapshot,
	now time.Time,
) (AuthorizationGrant, error) {
	if isNil(s.config.Policy) {
		return AuthorizationGrant{}, ErrAuthorizationUnavailable
	}
	grant, err := s.config.Policy.Authorize(ctx, intent)
	if err != nil {
		return AuthorizationGrant{}, fmt.Errorf("authorize %s: %w", intent.Operation, err)
	}
	if err := validateGrant(
		grant,
		current.Revision,
		now,
		s.config.MaximumGrantLifetime,
	); err != nil {
		return AuthorizationGrant{}, err
	}
	digest := grantDigest(grant.GrantID)
	if _, replay := current.AppliedGrants[digest]; replay {
		return AuthorizationGrant{}, ErrReplay
	}
	return grant, nil
}

func (s *Service) validateCertificateGrant(
	grant AuthorizationGrant,
	now time.Time,
) error {
	if grant.CertificateNotBefore.IsZero() ||
		grant.CertificateNotAfter.IsZero() ||
		!grant.CertificateNotAfter.After(grant.CertificateNotBefore) ||
		!grant.CertificateNotAfter.After(now) {
		return errors.New("certificate grant validity is invalid")
	}
	if grant.CertificateNotAfter.Sub(grant.CertificateNotBefore) >
		s.config.MaximumCertificateLifetime {
		return errors.New("certificate grant exceeds the configured lifetime")
	}
	return nil
}

func (s *Service) reserveCertificate(
	current Snapshot,
	grant AuthorizationGrant,
	operation Operation,
	relationshipID string,
	remoteTrustDomain string,
	spiffeID string,
	subjectPublicKeyDER []byte,
	now time.Time,
) (PendingCertificate, error) {
	if current.NextSerial == ^uint64(0) {
		return PendingCertificate{}, errors.New("certificate serial space is exhausted")
	}
	pending := PendingCertificate{
		ID:                  grantDigest(grant.GrantID),
		GrantDigest:         grantDigest(grant.GrantID),
		Operation:           operation,
		RelationshipID:      relationshipID,
		RemoteTrustDomain:   remoteTrustDomain,
		SPIFFEID:            spiffeID,
		Serial:              new(big.Int).SetUint64(current.NextSerial).String(),
		SubjectPublicKeyDER: slices.Clone(subjectPublicKeyDER),
		NotBefore:           grant.CertificateNotBefore.UTC(),
		NotAfter:            grant.CertificateNotAfter.UTC(),
		CreatedAt:           now,
	}
	next := cloneSnapshot(current)
	next.Revision++
	next.NextSerial++
	next.PendingCertificates[pending.ID] = pending
	recordAppliedGrant(&next, grant, operation, now)
	if err := s.commitCandidate(current.Revision, next); err != nil {
		return PendingCertificate{}, err
	}
	return pending, nil
}

func (s *Service) finalizePending(
	ctx context.Context,
	pendingID string,
	apply func(*Snapshot, PendingCertificate, time.Time) error,
) error {
	if apply == nil {
		return errors.New("certificate finalizer is required")
	}
	for attempt := 0; attempt < 8; attempt++ {
		current, now, err := s.currentState(ctx)
		if err != nil {
			return err
		}
		pending, exists := current.PendingCertificates[pendingID]
		if !exists {
			return errors.New("reserved certificate intent is unavailable")
		}
		next := cloneSnapshot(current)
		next.Revision++
		delete(next.PendingCertificates, pendingID)
		if err := apply(&next, pending, now); err != nil {
			return err
		}
		if err := s.attachPublicOutbox(ctx, &next, now); err != nil {
			return err
		}
		err = s.commitCandidate(current.Revision, next)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrRevisionConflict) {
			return err
		}
	}
	return ErrRevisionConflict
}

func (s *Service) burnPending(
	ctx context.Context,
	pendingID string,
	operationErr error,
) error {
	for attempt := 0; attempt < 8; attempt++ {
		current, now, err := s.currentState(ctx)
		if err != nil {
			return errors.Join(operationErr, err)
		}
		pending, exists := current.PendingCertificates[pendingID]
		if !exists {
			return operationErr
		}
		next := cloneSnapshot(current)
		next.Revision++
		delete(next.PendingCertificates, pendingID)
		next.BurnedSerials[pending.Serial] = now
		if err := s.attachPublicOutbox(ctx, &next, now); err != nil {
			return errors.Join(operationErr, err)
		}
		err = s.commitCandidate(current.Revision, next)
		if err == nil {
			return operationErr
		}
		if !errors.Is(err, ErrRevisionConflict) {
			return errors.Join(operationErr, err)
		}
	}
	return errors.Join(operationErr, ErrRevisionConflict)
}

func (s *Service) attachPublicOutbox(
	ctx context.Context,
	next *Snapshot,
	now time.Time,
) error {
	if isNil(s.config.PublicSnapshotBuilder) {
		return ErrPublicationSchemaUnavailable
	}
	view, err := publicStateView(*next)
	if err != nil {
		return err
	}
	documents, err := s.config.PublicSnapshotBuilder.Build(ctx, view)
	if err != nil {
		return fmt.Errorf("build public trust-state snapshot: %w", err)
	}
	publication, err := newPublication(
		s.config.Identity,
		next.Revision,
		documents,
		now,
	)
	if err != nil {
		return err
	}
	if _, exists := next.Published[publication.ID]; exists {
		return ErrReplay
	}
	// Every item is a complete immutable snapshot, so the newest local
	// transaction safely supersedes older pending snapshots. This keeps WAN or
	// DHT failure from exhausting a bound and blocking local revocation.
	next.Outbox = make(map[string]Publication, 1)
	next.Outbox[publication.ID] = publication
	return nil
}

func (s *Service) commitCandidate(
	expectedRevision uint64,
	next Snapshot,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.opened {
		return errors.New("trust service is not open")
	}
	if s.snapshot.Revision != expectedRevision {
		return errors.Join(ErrRevisionConflict, s.reloadSnapshotLocked())
	}
	if err := s.config.Store.Commit(expectedRevision, next); err != nil {
		reloadErr := s.reloadSnapshotLocked()
		if errors.Is(err, ErrRevisionConflict) && reloadErr != nil {
			return errors.Join(err, reloadErr)
		}
		return err
	}
	s.snapshot = cloneSnapshot(next)
	return nil
}

func (s *Service) reloadSnapshotLocked() error {
	reloaded, err := s.config.Store.Load()
	if err != nil {
		return fmt.Errorf("reload durable trust state: %w", err)
	}
	if err := validateSnapshot(reloaded); err != nil {
		return fmt.Errorf("validate reloaded durable trust state: %w", err)
	}
	if reloaded.Revision == 0 ||
		reloaded.Identity != s.config.Identity ||
		reloaded.Revision < s.snapshot.Revision {
		return errors.New("reloaded durable trust state is inconsistent")
	}
	s.snapshot = cloneSnapshot(reloaded)
	return nil
}

func applyAdoption(
	next *Snapshot,
	peer VerifiedMTLSPeer,
	grant AuthorizationGrant,
	now time.Time,
) (RelationshipRecord, error) {
	if grant.OwnershipRole != OwnershipRoleOwner &&
		grant.OwnershipRole != OwnershipRoleBackupAdmin {
		return RelationshipRecord{}, errors.New("authorization grant has an invalid ownership role")
	}
	if grant.RelationshipPhase != RelationshipPhaseProvisional &&
		grant.RelationshipPhase != RelationshipPhaseAuthorized {
		return RelationshipRecord{}, errors.New("authorization grant has an invalid adoption phase")
	}
	peerIdentity := peer.Identity()
	if grant.RelatedRelationship != "" {
		relationship, exists := next.Relationships[grant.RelatedRelationship]
		if !exists ||
			relationship.Phase != RelationshipPhaseProvisional ||
			relationship.PrincipalSPIFFEID != peerIdentity.SPIFFEID ||
			relationship.Role != grant.OwnershipRole ||
			grant.RelationshipPhase != RelationshipPhaseAuthorized {
			return RelationshipRecord{}, errors.New("provisional authorization transition is invalid")
		}
		relationship.Phase = RelationshipPhaseAuthorized
		relationship.Generation++
		relationship.UpdatedAt = now
		next.Relationships[relationship.ID] = relationship
		return relationship, nil
	}
	for _, relationship := range next.Relationships {
		if relationship.Phase != RelationshipPhaseRevoked &&
			relationship.PrincipalSPIFFEID == peerIdentity.SPIFFEID {
			return RelationshipRecord{}, errors.New("principal already has an active relationship")
		}
	}
	hasActiveOwner, hasAuthorizedOwner := ownerState(next.Relationships)
	switch {
	case grant.RelationshipPhase == RelationshipPhaseProvisional:
		if grant.OwnershipRole != OwnershipRoleOwner || hasActiveOwner {
			return RelationshipRecord{}, errors.New("provisional relationship must be the sole owner")
		}
	case grant.OwnershipRole == OwnershipRoleOwner:
		if hasActiveOwner {
			return RelationshipRecord{}, errors.New("an active owner already exists")
		}
	case grant.OwnershipRole == OwnershipRoleBackupAdmin:
		if !hasAuthorizedOwner {
			return RelationshipRecord{}, errors.New(
				"backup administrator requires an authorized owner",
			)
		}
	}
	certificateHash := peer.CertificateSHA256()
	id := relationshipID(
		grant.GrantID,
		next.Identity.PeerID,
		peerIdentity.SPIFFEID,
	)
	relationship := RelationshipRecord{
		ID:                       id,
		TargetPeerID:             next.Identity.PeerID,
		PrincipalSPIFFEID:        peerIdentity.SPIFFEID,
		PrincipalCertificateHash: hex.EncodeToString(certificateHash[:]),
		Role:                     grant.OwnershipRole,
		Phase:                    grant.RelationshipPhase,
		Generation:               1,
		EstablishedAt:            now,
		UpdatedAt:                now,
	}
	next.Relationships[id] = relationship
	return relationship, nil
}

func ownerState(
	relationships map[string]RelationshipRecord,
) (bool, bool) {
	var active, authorized bool
	for _, relationship := range relationships {
		if relationship.Role != OwnershipRoleOwner ||
			relationship.Phase == RelationshipPhaseRevoked {
			continue
		}
		active = true
		if relationship.Phase == RelationshipPhaseAuthorized {
			authorized = true
		}
	}
	return active, authorized
}

func requireAuthorizedPrincipal(
	snapshot Snapshot,
	peer VerifiedMTLSPeer,
	requireOwner bool,
) (RelationshipRecord, error) {
	for _, relationship := range snapshot.Relationships {
		if relationship.PrincipalSPIFFEID != peer.Identity().SPIFFEID ||
			relationship.Phase != RelationshipPhaseAuthorized {
			continue
		}
		fingerprint := peer.CertificateSHA256()
		if relationship.PrincipalCertificateHash != hex.EncodeToString(fingerprint[:]) {
			return RelationshipRecord{}, ErrNotAuthorized
		}
		if requireOwner && relationship.Role != OwnershipRoleOwner {
			return RelationshipRecord{}, ErrNotAuthorized
		}
		return relationship, nil
	}
	return RelationshipRecord{}, ErrNotAuthorized
}

func recordAppliedGrant(
	snapshot *Snapshot,
	grant AuthorizationGrant,
	operation Operation,
	now time.Time,
) {
	digest := grantDigest(grant.GrantID)
	snapshot.AppliedGrants[digest] = AppliedGrant{
		Digest:    digest,
		Operation: operation,
		AppliedAt: now,
	}
}

func grantDigest(grantID string) string {
	digest := sha256.Sum256(append([]byte(grantDigestDomain), []byte(grantID)...))
	return hex.EncodeToString(digest[:])
}

func relationshipID(grantID, peerID, principalSPIFFEID string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(relationshipDigestDomain))
	writeDigestField(digest, []byte(grantID))
	writeDigestField(digest, []byte(peerID))
	writeDigestField(digest, []byte(principalSPIFFEID))
	return hex.EncodeToString(digest.Sum(nil))
}

func publicStateView(snapshot Snapshot) (PublicStateView, error) {
	view := PublicStateView{
		Revision:               snapshot.Revision,
		LocalIdentity:          snapshot.Identity,
		ActiveCACertificateDER: slices.Clone(snapshot.ActiveCACertificate),
		Certificates:           make([]PublicCertificate, 0, len(snapshot.Certificates)),
		Revocations:            make([]PublicRevocation, 0, len(snapshot.Revocations)+len(snapshot.BurnedSerials)),
		Federations:            make([]PublicFederation, 0, len(snapshot.Federations)),
	}
	for _, certificate := range snapshot.Certificates {
		view.Certificates = append(view.Certificates, PublicCertificate{
			ID:        certificate.ID,
			SPIFFEID:  certificate.SPIFFEID,
			Serial:    certificate.Serial,
			DER:       slices.Clone(certificate.DER),
			NotBefore: certificate.NotBefore,
			NotAfter:  certificate.NotAfter,
			Status:    certificate.Status,
		})
	}
	statusIDs := make(map[string]struct{}, len(snapshot.Revocations)+len(snapshot.BurnedSerials))
	for _, revocation := range snapshot.Revocations {
		if _, duplicate := statusIDs[revocation.CertificateID]; duplicate {
			return PublicStateView{}, errors.New("public revocation status ID is reused")
		}
		statusIDs[revocation.CertificateID] = struct{}{}
		view.Revocations = append(view.Revocations, PublicRevocation{
			StatusID:       revocation.CertificateID,
			CertificateID:  revocation.CertificateID,
			Serial:         revocation.Serial,
			Kind:           revocation.Kind,
			CertificateDER: slices.Clone(revocation.CertificateDER),
			RevokedAt:      revocation.RevokedAt,
		})
	}
	for serial, revokedAt := range snapshot.BurnedSerials {
		statusID := uncertainRevocationID(snapshot.Identity.TrustDomain, serial)
		if _, duplicate := statusIDs[statusID]; duplicate {
			return PublicStateView{}, errors.New("public revocation status ID is reused")
		}
		statusIDs[statusID] = struct{}{}
		view.Revocations = append(view.Revocations, PublicRevocation{
			StatusID:  statusID,
			Serial:    serial,
			Kind:      RevocationKindUncertain,
			RevokedAt: revokedAt,
		})
	}
	for _, federation := range snapshot.Federations {
		view.Federations = append(view.Federations, PublicFederation{
			SourceDomain:           federation.SourceDomain,
			TargetDomain:           federation.TargetDomain,
			SourceGeneration:       federation.SourceGeneration,
			RemoteCACertificateDER: slices.Clone(federation.RemoteCACertificate),
			CrossCertificateDER:    slices.Clone(federation.CrossCertificate),
			EstablishedAt:          federation.EstablishedAt,
		})
	}
	sort.Slice(view.Certificates, func(left, right int) bool {
		return view.Certificates[left].ID < view.Certificates[right].ID
	})
	sort.Slice(view.Revocations, func(left, right int) bool {
		return view.Revocations[left].StatusID <
			view.Revocations[right].StatusID
	})
	sort.Slice(view.Federations, func(left, right int) bool {
		return view.Federations[left].TargetDomain <
			view.Federations[right].TargetDomain
	})
	return view, nil
}

func uncertainRevocationID(trustDomain, serial string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(uncertainRevocationDigestDomain))
	writeDigestField(digest, []byte(trustDomain))
	writeDigestField(digest, []byte(serial))
	return hex.EncodeToString(digest.Sum(nil))
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan,
		reflect.Func,
		reflect.Interface,
		reflect.Map,
		reflect.Pointer,
		reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
