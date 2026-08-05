// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sort"
	"time"

	"github.com/ipfs/go-cid"
)

const (
	// StateVersion is the sole durable trust-state schema understood here.
	StateVersion = 1

	maximumRelationships       = 1024
	maximumCertificates        = 4096
	maximumPendingCertificates = 64
	maximumRevocations         = 4096
	maximumFederations         = 128
	maximumBundles             = 128
	maximumAppliedGrants       = 4096
	maximumOutboxItems         = 256
	maximumPublishedItems      = 4096
	maximumCertificateDERBytes = 64 * 1024
)

// CertificateStatus is the local enforcement status of a public certificate.
type CertificateStatus string

const (
	CertificateStatusActive  CertificateStatus = "active"
	CertificateStatusRevoked CertificateStatus = "revoked"
)

// RevocationKind distinguishes issued leaf certificates, retired federation
// cross-certificates, and serials whose post-sign outcome is uncertain.
type RevocationKind string

const (
	RevocationKindMTLS      RevocationKind = "mtls"
	RevocationKindCross     RevocationKind = "cross-certificate"
	RevocationKindUncertain RevocationKind = "uncertain-serial"
)

// RelationshipRecord is a durable ownership/adoption relationship. Approval
// protocol material is not persisted.
type RelationshipRecord struct {
	ID                       string            `json:"id"`
	TargetPeerID             string            `json:"target_peer_id"`
	PrincipalSPIFFEID        string            `json:"principal_spiffe_id"`
	PrincipalCertificateHash string            `json:"principal_certificate_sha256"`
	Role                     OwnershipRole     `json:"role"`
	Phase                    RelationshipPhase `json:"phase"`
	Generation               uint64            `json:"generation"`
	EstablishedAt            time.Time         `json:"established_at"`
	UpdatedAt                time.Time         `json:"updated_at"`
}

// CertificateRecord contains a public certificate and its local status.
type CertificateRecord struct {
	ID                  string            `json:"id"`
	RelationshipID      string            `json:"relationship_id,omitempty"`
	SPIFFEID            string            `json:"spiffe_id"`
	Serial              string            `json:"serial"`
	DER                 []byte            `json:"der"`
	SubjectPublicKeyDER []byte            `json:"subject_public_key_der"`
	NotBefore           time.Time         `json:"not_before"`
	NotAfter            time.Time         `json:"not_after"`
	Status              CertificateStatus `json:"status"`
	IssuedAt            time.Time         `json:"issued_at"`
	RevokedAt           time.Time         `json:"revoked_at,omitempty"`
}

// PendingCertificate reserves a serial before the TPM-backed issuer is called.
// A failed or uncertain operation is removed only after its serial is burned.
type PendingCertificate struct {
	ID                  string    `json:"id"`
	GrantDigest         string    `json:"grant_digest"`
	Operation           Operation `json:"operation"`
	RelationshipID      string    `json:"relationship_id,omitempty"`
	RemoteTrustDomain   string    `json:"remote_trust_domain,omitempty"`
	SPIFFEID            string    `json:"spiffe_id"`
	Serial              string    `json:"serial"`
	SubjectPublicKeyDER []byte    `json:"subject_public_key_der"`
	NotBefore           time.Time `json:"not_before"`
	NotAfter            time.Time `json:"not_after"`
	CreatedAt           time.Time `json:"created_at"`
}

// RevocationRecord contains only public local revocation status.
type RevocationRecord struct {
	CertificateID  string         `json:"certificate_id"`
	Serial         string         `json:"serial"`
	Kind           RevocationKind `json:"kind"`
	CertificateDER []byte         `json:"certificate_der"`
	RevokedAt      time.Time      `json:"revoked_at"`
}

// FederationRecord is one explicit directed edge. It never implies a reverse,
// transitive, or spoke-to-spoke edge.
type FederationRecord struct {
	SourceDomain           string         `json:"source_domain"`
	TargetDomain           string         `json:"target_domain"`
	LocalRole              FederationRole `json:"local_role"`
	RemoteRole             FederationRole `json:"remote_role"`
	SourceGeneration       uint64         `json:"source_generation"`
	RemoteCACertificate    []byte         `json:"remote_ca_certificate"`
	CrossCertificate       []byte         `json:"cross_certificate,omitempty"`
	CrossCertificateID     string         `json:"cross_certificate_id,omitempty"`
	CrossCertificateSerial string         `json:"cross_certificate_serial,omitempty"`
	EstablishedAt          time.Time      `json:"established_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
}

// TrustBundleRecord keeps every authority keyed by its trust domain. Bundles
// are never merged into an undifferentiated CA pool.
type TrustBundleRecord struct {
	TrustDomain    string    `json:"trust_domain"`
	Generation     uint64    `json:"generation"`
	CACertificates [][]byte  `json:"ca_certificates"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AppliedGrant retains only a domain-separated digest for replay rejection.
type AppliedGrant struct {
	Digest    string    `json:"digest"`
	Operation Operation `json:"operation"`
	AppliedAt time.Time `json:"applied_at"`
}

// PublishedRecord binds a completed outbox item to its immutable CID and
// monotonic IPNS sequence.
type PublishedRecord struct {
	Digest       string    `json:"digest"`
	RootCID      string    `json:"root_cid"`
	IPNSSequence uint64    `json:"ipns_sequence"`
	CompletedAt  time.Time `json:"completed_at"`
}

// Snapshot is the complete public/state-only durable trust document.
type Snapshot struct {
	Version             int                           `json:"version"`
	Revision            uint64                        `json:"revision"`
	Identity            DeviceIdentity                `json:"identity"`
	NextSerial          uint64                        `json:"next_serial"`
	ActiveCACertificate []byte                        `json:"active_ca_certificate,omitempty"`
	ActiveCAID          string                        `json:"active_ca_id,omitempty"`
	Relationships       map[string]RelationshipRecord `json:"relationships"`
	Certificates        map[string]CertificateRecord  `json:"certificates"`
	PendingCertificates map[string]PendingCertificate `json:"pending_certificates"`
	BurnedSerials       map[string]time.Time           `json:"burned_serials"`
	Revocations         map[string]RevocationRecord   `json:"revocations"`
	Federations         map[string]FederationRecord   `json:"federations"`
	Bundles             map[string]TrustBundleRecord  `json:"bundles"`
	AppliedGrants       map[string]AppliedGrant        `json:"applied_grants"`
	Outbox              map[string]Publication         `json:"outbox"`
	Published           map[string]PublishedRecord     `json:"published"`
	LastIPNSSequence    uint64                         `json:"last_ipns_sequence"`
	LastPublishedRoot   string                         `json:"last_published_root,omitempty"`
}

func emptySnapshot() Snapshot {
	return Snapshot{
		Version:             StateVersion,
		NextSerial:          1,
		Relationships:       make(map[string]RelationshipRecord),
		Certificates:        make(map[string]CertificateRecord),
		PendingCertificates: make(map[string]PendingCertificate),
		BurnedSerials:       make(map[string]time.Time),
		Revocations:         make(map[string]RevocationRecord),
		Federations:         make(map[string]FederationRecord),
		Bundles:             make(map[string]TrustBundleRecord),
		AppliedGrants:       make(map[string]AppliedGrant),
		Outbox:              make(map[string]Publication),
		Published:           make(map[string]PublishedRecord),
	}
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.Version != StateVersion {
		return fmt.Errorf(
			"%w: %d",
			ErrUnsupportedStateVersion,
			snapshot.Version,
		)
	}
	if snapshot.NextSerial == 0 {
		return errors.New("next certificate serial must be positive")
	}
	if err := validateSnapshotMaps(snapshot); err != nil {
		return err
	}
	if snapshot.Revision == 0 {
		if snapshot.Identity != (DeviceIdentity{}) ||
			snapshot.NextSerial != 1 ||
			len(snapshot.ActiveCACertificate) != 0 ||
			snapshot.ActiveCAID != "" ||
			len(snapshot.Relationships) != 0 ||
			len(snapshot.Certificates) != 0 ||
			len(snapshot.PendingCertificates) != 0 ||
			len(snapshot.BurnedSerials) != 0 ||
			len(snapshot.Revocations) != 0 ||
			len(snapshot.Federations) != 0 ||
			len(snapshot.Bundles) != 0 ||
			len(snapshot.AppliedGrants) != 0 ||
			len(snapshot.Outbox) != 0 ||
			len(snapshot.Published) != 0 ||
			snapshot.LastIPNSSequence != 0 ||
			snapshot.LastPublishedRoot != "" {
			return errors.New("revision-zero trust state is not empty")
		}
		return nil
	}
	identity, err := DeriveDeviceIdentity(
		snapshot.Identity.CanonicalIPNS,
		snapshot.Identity.PeerID,
	)
	if err != nil {
		return fmt.Errorf("durable local identity: %w", err)
	}
	if identity != snapshot.Identity {
		return errors.New("durable local identity fields are inconsistent")
	}
	if err := validateCA(snapshot); err != nil {
		return err
	}
	if err := validateRelationships(snapshot); err != nil {
		return err
	}
	if err := validateCertificates(snapshot); err != nil {
		return err
	}
	if err := validateFederationsAndBundles(snapshot); err != nil {
		return err
	}
	if err := validateReplayAndPublicationState(snapshot); err != nil {
		return err
	}
	return nil
}

func validateSnapshotMaps(snapshot Snapshot) error {
	mapsPresent := snapshot.Relationships != nil &&
		snapshot.Certificates != nil &&
		snapshot.PendingCertificates != nil &&
		snapshot.BurnedSerials != nil &&
		snapshot.Revocations != nil &&
		snapshot.Federations != nil &&
		snapshot.Bundles != nil &&
		snapshot.AppliedGrants != nil &&
		snapshot.Outbox != nil &&
		snapshot.Published != nil
	if !mapsPresent {
		return errors.New("trust state map is missing")
	}
	if len(snapshot.Relationships) > maximumRelationships ||
		len(snapshot.Certificates) > maximumCertificates ||
		len(snapshot.PendingCertificates) > maximumPendingCertificates ||
		len(snapshot.BurnedSerials) > maximumCertificates ||
		len(snapshot.Revocations) > maximumRevocations ||
		len(snapshot.Federations) > maximumFederations ||
		len(snapshot.Bundles) > maximumBundles ||
		len(snapshot.AppliedGrants) > maximumAppliedGrants ||
		len(snapshot.Outbox) > maximumOutboxItems ||
		len(snapshot.Published) > maximumPublishedItems {
		return errors.New("trust state exceeds a collection bound")
	}
	return nil
}

func validateCA(snapshot Snapshot) error {
	if len(snapshot.ActiveCACertificate) == 0 {
		if snapshot.ActiveCAID != "" {
			return errors.New("active CA ID exists without a certificate")
		}
		if _, exists := snapshot.Bundles[snapshot.Identity.TrustDomain]; exists {
			return errors.New("local trust bundle exists without an active CA")
		}
		return nil
	}
	if len(snapshot.ActiveCACertificate) > maximumCertificateDERBytes {
		return errors.New("active CA certificate exceeds 64 KiB")
	}
	certificate, err := x509.ParseCertificate(snapshot.ActiveCACertificate)
	if err != nil {
		return fmt.Errorf("parse active CA certificate: %w", err)
	}
	if !certificate.BasicConstraintsValid ||
		!certificate.IsCA ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("active CA certificate is not a certificate authority")
	}
	if certificate.Subject.CommonName != snapshot.Identity.TrustDomain {
		return errors.New("active CA certificate is bound to a different trust domain")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return fmt.Errorf("verify active CA self-signature: %w", err)
	}
	if certificateID(snapshot.ActiveCACertificate) != snapshot.ActiveCAID {
		return errors.New("active CA certificate ID is inconsistent")
	}
	localBundle, exists := snapshot.Bundles[snapshot.Identity.TrustDomain]
	if !exists ||
		len(localBundle.CACertificates) == 0 ||
		!bytes.Equal(localBundle.CACertificates[0], snapshot.ActiveCACertificate) {
		return errors.New("active CA certificate is missing from its domain-keyed bundle")
	}
	return nil
}

func validateRelationships(snapshot Snapshot) error {
	activeOwners := 0
	authorizedOwner := false
	activePrincipals := make(map[string]struct{})
	for key, relationship := range snapshot.Relationships {
		if key != relationship.ID || !certificateIDPattern.MatchString(key) {
			return errors.New("relationship key or ID is invalid")
		}
		if relationship.TargetPeerID != snapshot.Identity.PeerID {
			return errors.New("relationship targets an unknown device")
		}
		if _, err := ParseDeviceSPIFFEID(relationship.PrincipalSPIFFEID); err != nil {
			return fmt.Errorf("relationship principal: %w", err)
		}
		if !certificateIDPattern.MatchString(relationship.PrincipalCertificateHash) {
			return errors.New("relationship principal certificate hash is invalid")
		}
		if relationship.Role != OwnershipRoleOwner &&
			relationship.Role != OwnershipRoleBackupAdmin {
			return errors.New("relationship ownership role is invalid")
		}
		if relationship.Phase != RelationshipPhaseProvisional &&
			relationship.Phase != RelationshipPhaseAuthorized &&
			relationship.Phase != RelationshipPhaseRevoked {
			return errors.New("relationship phase is invalid")
		}
		if relationship.Generation == 0 ||
			relationship.EstablishedAt.IsZero() ||
			relationship.UpdatedAt.Before(relationship.EstablishedAt) {
			return errors.New("relationship generation or timestamps are invalid")
		}
		if relationship.Phase != RelationshipPhaseRevoked {
			if _, exists := activePrincipals[relationship.PrincipalSPIFFEID]; exists {
				return errors.New("principal has multiple active relationships")
			}
			activePrincipals[relationship.PrincipalSPIFFEID] = struct{}{}
			if relationship.Role == OwnershipRoleOwner {
				activeOwners++
				if relationship.Phase == RelationshipPhaseAuthorized {
					authorizedOwner = true
				}
			}
		}
	}
	if activeOwners > 1 {
		return errors.New("trust state has multiple active owners")
	}
	for _, relationship := range snapshot.Relationships {
		if relationship.Role == OwnershipRoleBackupAdmin &&
			relationship.Phase != RelationshipPhaseRevoked &&
			!authorizedOwner {
			return errors.New("active backup administrator has no authorized owner")
		}
	}
	return nil
}

func validateCertificates(snapshot Snapshot) error {
	serials := make(map[string]struct{})
	if len(snapshot.ActiveCACertificate) != 0 {
		activeCA, _ := x509.ParseCertificate(snapshot.ActiveCACertificate)
		serial := activeCA.SerialNumber.String()
		if err := validateSerial(serial); err != nil {
			return err
		}
		serials[serial] = struct{}{}
	}
	for key, certificate := range snapshot.Certificates {
		if key != certificate.ID ||
			certificateID(certificate.DER) != certificate.ID ||
			len(certificate.DER) == 0 ||
			len(certificate.DER) > maximumCertificateDERBytes {
			return errors.New("certificate key or ID is inconsistent")
		}
		if err := validateSerial(certificate.Serial); err != nil {
			return err
		}
		if _, duplicate := serials[certificate.Serial]; duplicate {
			return errors.New("certificate serial is reused")
		}
		serials[certificate.Serial] = struct{}{}
		parsed, err := x509.ParseCertificate(certificate.DER)
		if err != nil {
			return fmt.Errorf("parse durable certificate: %w", err)
		}
		if parsed.SerialNumber.String() != certificate.Serial ||
			!bytes.Equal(parsed.RawSubjectPublicKeyInfo, certificate.SubjectPublicKeyDER) ||
			!parsed.NotBefore.Equal(certificate.NotBefore) ||
			!parsed.NotAfter.Equal(certificate.NotAfter) ||
			certificate.IssuedAt.IsZero() {
			return errors.New("durable certificate metadata is inconsistent")
		}
		if certificate.SPIFFEID != snapshot.Identity.SPIFFEID ||
			len(parsed.URIs) != 1 ||
			parsed.URIs[0] == nil ||
			parsed.URIs[0].String() != certificate.SPIFFEID ||
			parsed.IsCA ||
			!parsed.BasicConstraintsValid ||
			parsed.KeyUsage != x509.KeyUsageDigitalSignature ||
			!containsUsage(parsed.ExtKeyUsage, x509.ExtKeyUsageClientAuth) ||
			!containsUsage(parsed.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			return errors.New("durable mTLS certificate profile is invalid")
		}
		if len(snapshot.ActiveCACertificate) == 0 {
			return errors.New("mTLS certificate exists without an active CA")
		}
		parent, _ := x509.ParseCertificate(snapshot.ActiveCACertificate)
		if err := parsed.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("verify durable mTLS certificate: %w", err)
		}
		if certificate.Status != CertificateStatusActive &&
			certificate.Status != CertificateStatusRevoked {
			return errors.New("certificate status is invalid")
		}
		if certificate.Status == CertificateStatusRevoked &&
			certificate.RevokedAt.IsZero() {
			return errors.New("revoked certificate has no revocation time")
		}
		if certificate.Status == CertificateStatusRevoked {
			if _, exists := snapshot.Revocations[key]; !exists {
				return errors.New("revoked certificate has no public revocation record")
			}
		}
		if certificate.RelationshipID != "" {
			if _, exists := snapshot.Relationships[certificate.RelationshipID]; !exists {
				return errors.New("certificate refers to an unknown relationship")
			}
		}
	}
	for key, pending := range snapshot.PendingCertificates {
		if key != pending.ID || !certificateIDPattern.MatchString(key) {
			return errors.New("pending certificate ID is invalid")
		}
		if !certificateIDPattern.MatchString(pending.GrantDigest) ||
			(pending.Operation != OperationInitializeCA &&
				pending.Operation != OperationIssueMTLSCertificate &&
				pending.Operation != OperationFederate) {
			return errors.New("pending certificate authorization is invalid")
		}
		if err := validateSerial(pending.Serial); err != nil {
			return err
		}
		if _, duplicate := serials[pending.Serial]; duplicate {
			return errors.New("pending certificate serial is reused")
		}
		serials[pending.Serial] = struct{}{}
		if pending.CreatedAt.IsZero() ||
			pending.NotAfter.Before(pending.NotBefore) ||
			len(pending.SubjectPublicKeyDER) == 0 {
			return errors.New("pending certificate is invalid")
		}
		if _, err := x509.ParsePKIXPublicKey(pending.SubjectPublicKeyDER); err != nil {
			return errors.New("pending certificate public key is invalid")
		}
	}
	for serial, burnedAt := range snapshot.BurnedSerials {
		if err := validateSerial(serial); err != nil {
			return err
		}
		if _, duplicate := serials[serial]; duplicate {
			return errors.New("burned certificate serial is reused")
		}
		if burnedAt.IsZero() {
			return errors.New("burned serial has no timestamp")
		}
		serials[serial] = struct{}{}
	}
	activeCrossCertificates := make(map[string]struct{}, len(snapshot.Federations))
	for _, federation := range snapshot.Federations {
		if federation.CrossCertificateSerial == "" {
			continue
		}
		if !certificateIDPattern.MatchString(federation.CrossCertificateID) {
			return errors.New("federation cross-certificate ID is invalid")
		}
		if _, duplicate := activeCrossCertificates[federation.CrossCertificateID]; duplicate {
			return errors.New("federation cross-certificate is reused")
		}
		activeCrossCertificates[federation.CrossCertificateID] = struct{}{}
		if err := validateSerial(federation.CrossCertificateSerial); err != nil {
			return err
		}
		if _, duplicate := serials[federation.CrossCertificateSerial]; duplicate {
			return errors.New("federation cross-certificate serial is reused")
		}
		serials[federation.CrossCertificateSerial] = struct{}{}
	}
	for key, revocation := range snapshot.Revocations {
		if key != revocation.CertificateID ||
			!certificateIDPattern.MatchString(key) ||
			revocation.RevokedAt.IsZero() ||
			len(revocation.CertificateDER) == 0 ||
			len(revocation.CertificateDER) > maximumCertificateDERBytes ||
			certificateID(revocation.CertificateDER) != key {
			return errors.New("revocation record identity is inconsistent")
		}
		if err := validateSerial(revocation.Serial); err != nil {
			return err
		}
		switch revocation.Kind {
		case RevocationKindMTLS:
			certificate, exists := snapshot.Certificates[key]
			if !exists ||
				certificate.Serial != revocation.Serial ||
				!bytes.Equal(certificate.DER, revocation.CertificateDER) ||
				certificate.Status != CertificateStatusRevoked ||
				!certificate.RevokedAt.Equal(revocation.RevokedAt) {
				return errors.New("mTLS revocation record is inconsistent")
			}
		case RevocationKindCross:
			if _, active := activeCrossCertificates[key]; active {
				return errors.New("active federation cross-certificate is revoked")
			}
			if _, leaf := snapshot.Certificates[key]; leaf {
				return errors.New("cross-certificate revocation collides with an mTLS certificate")
			}
			if err := validateCACertificate(revocation.CertificateDER); err != nil {
				return fmt.Errorf("revoked federation cross-certificate: %w", err)
			}
			crossCertificate, _ := x509.ParseCertificate(revocation.CertificateDER)
			if crossCertificate.SerialNumber.String() != revocation.Serial {
				return errors.New("revoked federation cross-certificate serial is inconsistent")
			}
			if _, err := TrustDomainFromIPNS(crossCertificate.Subject.CommonName); err != nil {
				return errors.New("revoked federation cross-certificate domain is invalid")
			}
			if len(snapshot.ActiveCACertificate) == 0 {
				return errors.New("revoked federation cross-certificate has no local CA")
			}
			localCA, _ := x509.ParseCertificate(snapshot.ActiveCACertificate)
			if err := crossCertificate.CheckSignatureFrom(localCA); err != nil {
				return fmt.Errorf("verify revoked federation cross-certificate: %w", err)
			}
			if _, duplicate := serials[revocation.Serial]; duplicate {
				return errors.New("revoked federation cross-certificate serial is reused")
			}
			serials[revocation.Serial] = struct{}{}
		default:
			return errors.New("revocation kind is invalid")
		}
	}
	nextSerial := new(big.Int).SetUint64(snapshot.NextSerial)
	for serial := range serials {
		value, _ := new(big.Int).SetString(serial, 10)
		if value.Cmp(nextSerial) >= 0 {
			return errors.New("next certificate serial does not exceed every reserved serial")
		}
	}
	return nil
}

func validateFederationsAndBundles(snapshot Snapshot) error {
	for domain, federation := range snapshot.Federations {
		if domain != federation.TargetDomain ||
			federation.SourceDomain != snapshot.Identity.TrustDomain ||
			federation.TargetDomain == federation.SourceDomain {
			return errors.New("federation edge key or direction is invalid")
		}
		if _, err := TrustDomainFromIPNS(federation.TargetDomain); err != nil {
			return fmt.Errorf("federation target domain: %w", err)
		}
		if !complementaryFederationRoles(federation.LocalRole, federation.RemoteRole) {
			return errors.New("federation edge is not explicit hub-and-spoke")
		}
		if federation.SourceGeneration == 0 ||
			federation.EstablishedAt.IsZero() ||
			federation.UpdatedAt.Before(federation.EstablishedAt) {
			return errors.New("federation generation or timestamps are invalid")
		}
		if err := validateCACertificate(federation.RemoteCACertificate); err != nil {
			return fmt.Errorf("federation remote CA: %w", err)
		}
		remoteCA, _ := x509.ParseCertificate(federation.RemoteCACertificate)
		if remoteCA.Subject.CommonName != federation.TargetDomain {
			return errors.New("federation remote CA is bound to a different domain")
		}
		if err := validateCACertificate(federation.CrossCertificate); err != nil {
			return fmt.Errorf("federation cross-certificate: %w", err)
		}
		crossCertificate, _ := x509.ParseCertificate(federation.CrossCertificate)
		if federation.CrossCertificateID != certificateID(federation.CrossCertificate) ||
			federation.CrossCertificateSerial != crossCertificate.SerialNumber.String() {
			return errors.New("federation cross-certificate metadata is inconsistent")
		}
		if crossCertificate.Subject.CommonName != federation.TargetDomain {
			return errors.New("federation cross-certificate has the wrong subject domain")
		}
		if len(snapshot.ActiveCACertificate) == 0 {
			return errors.New("federation exists without a local CA")
		}
		localCA, _ := x509.ParseCertificate(snapshot.ActiveCACertificate)
		if err := crossCertificate.CheckSignatureFrom(localCA); err != nil {
			return fmt.Errorf("verify federation cross-certificate: %w", err)
		}
	}
	for domain, bundle := range snapshot.Bundles {
		if domain != bundle.TrustDomain {
			return errors.New("trust bundle is stored under the wrong domain")
		}
		if _, err := TrustDomainFromIPNS(domain); err != nil {
			return fmt.Errorf("trust bundle domain: %w", err)
		}
		if bundle.Generation == 0 ||
			bundle.UpdatedAt.IsZero() ||
			len(bundle.CACertificates) == 0 ||
			len(bundle.CACertificates) > 16 {
			return errors.New("trust bundle generation or certificate count is invalid")
		}
		for _, encoded := range bundle.CACertificates {
			if err := validateCACertificate(encoded); err != nil {
				return fmt.Errorf("trust bundle certificate: %w", err)
			}
			certificate, _ := x509.ParseCertificate(encoded)
			if certificate.Subject.CommonName != domain {
				return errors.New("trust bundle contains a CA for a different domain")
			}
		}
	}
	return nil
}

func validateReplayAndPublicationState(snapshot Snapshot) error {
	for digest, grant := range snapshot.AppliedGrants {
		if digest != grant.Digest ||
			!certificateIDPattern.MatchString(digest) ||
			grant.Operation == "" ||
			grant.AppliedAt.IsZero() {
			return errors.New("applied authorization grant is invalid")
		}
	}
	for id, publication := range snapshot.Outbox {
		if id != publication.ID {
			return errors.New("outbox item is stored under the wrong ID")
		}
		if publication.StateRevision > snapshot.Revision {
			return errors.New("outbox item refers to a future trust-state revision")
		}
		if err := validatePublication(publication, snapshot.Identity); err != nil {
			return fmt.Errorf("outbox publication: %w", err)
		}
	}
	var (
		maximumSequence uint64
		maximumRoot     string
		sequences       = make(map[uint64]struct{}, len(snapshot.Published))
	)
	for id, published := range snapshot.Published {
		if !certificateIDPattern.MatchString(id) ||
			published.Digest != id ||
			published.IPNSSequence == 0 ||
			published.CompletedAt.IsZero() {
			return errors.New("completed publication record is invalid")
		}
		root, err := cid.Decode(published.RootCID)
		if err != nil || !root.Defined() {
			return errors.New("completed publication root CID is invalid")
		}
		if _, duplicate := sequences[published.IPNSSequence]; duplicate {
			return errors.New("completed publication reuses an IPNS sequence")
		}
		sequences[published.IPNSSequence] = struct{}{}
		if published.IPNSSequence > maximumSequence {
			maximumSequence = published.IPNSSequence
			maximumRoot = published.RootCID
		}
	}
	if maximumSequence != snapshot.LastIPNSSequence {
		return errors.New("last IPNS sequence does not match completed publications")
	}
	if maximumRoot != snapshot.LastPublishedRoot {
		return errors.New("last published root does not match completed publications")
	}
	return nil
}

func validateSerial(serial string) error {
	value := new(big.Int)
	if serial == "" {
		return errors.New("certificate serial is required")
	}
	if _, ok := value.SetString(serial, 10); !ok ||
		value.Sign() <= 0 ||
		value.String() != serial {
		return errors.New("certificate serial is not canonical positive decimal")
	}
	return nil
}

func validateCACertificate(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > maximumCertificateDERBytes {
		return errors.New("CA certificate has an invalid size")
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		return err
	}
	if !certificate.BasicConstraintsValid ||
		!certificate.IsCA ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("certificate is not a signing CA")
	}
	return nil
}

func complementaryFederationRoles(local, remote FederationRole) bool {
	return (local == FederationRoleHub && remote == FederationRoleSpoke) ||
		(local == FederationRoleSpoke && remote == FederationRoleHub)
}

func certificateID(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	cloned := snapshot
	cloned.ActiveCACertificate = slices.Clone(snapshot.ActiveCACertificate)
	cloned.Relationships = cloneMap(snapshot.Relationships)
	cloned.Certificates = make(map[string]CertificateRecord, len(snapshot.Certificates))
	for key, record := range snapshot.Certificates {
		record.DER = slices.Clone(record.DER)
		record.SubjectPublicKeyDER = slices.Clone(record.SubjectPublicKeyDER)
		cloned.Certificates[key] = record
	}
	cloned.PendingCertificates = make(
		map[string]PendingCertificate,
		len(snapshot.PendingCertificates),
	)
	for key, record := range snapshot.PendingCertificates {
		record.SubjectPublicKeyDER = slices.Clone(record.SubjectPublicKeyDER)
		cloned.PendingCertificates[key] = record
	}
	cloned.BurnedSerials = cloneMap(snapshot.BurnedSerials)
	cloned.Revocations = make(map[string]RevocationRecord, len(snapshot.Revocations))
	for key, record := range snapshot.Revocations {
		record.CertificateDER = slices.Clone(record.CertificateDER)
		cloned.Revocations[key] = record
	}
	cloned.Federations = make(map[string]FederationRecord, len(snapshot.Federations))
	for key, record := range snapshot.Federations {
		record.RemoteCACertificate = slices.Clone(record.RemoteCACertificate)
		record.CrossCertificate = slices.Clone(record.CrossCertificate)
		cloned.Federations[key] = record
	}
	cloned.Bundles = make(map[string]TrustBundleRecord, len(snapshot.Bundles))
	for key, record := range snapshot.Bundles {
		record.CACertificates = cloneByteSlices(record.CACertificates)
		cloned.Bundles[key] = record
	}
	cloned.AppliedGrants = cloneMap(snapshot.AppliedGrants)
	cloned.Outbox = make(map[string]Publication, len(snapshot.Outbox))
	for key, publication := range snapshot.Outbox {
		cloned.Outbox[key] = publication.Clone()
	}
	cloned.Published = cloneMap(snapshot.Published)
	return cloned
}

func cloneMap[K comparable, V any](input map[K]V) map[K]V {
	if input == nil {
		return nil
	}
	cloned := make(map[K]V, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	cloned := make([][]byte, len(values))
	for index, value := range values {
		cloned[index] = slices.Clone(value)
	}
	return cloned
}

func sortedRelationshipRecords(
	relationships map[string]RelationshipRecord,
) []RelationshipRecord {
	result := make([]RelationshipRecord, 0, len(relationships))
	for _, relationship := range relationships {
		if relationship.Phase == RelationshipPhaseAuthorized {
			result = append(result, relationship)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].ID < result[right].ID
	})
	return result
}
