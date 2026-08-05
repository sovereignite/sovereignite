// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/sovereignite/sovereignite/internal/keymanager"
	sovereignlibp2p "github.com/sovereignite/sovereignite/internal/libp2p"
)

var testNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

func testIdentity(t *testing.T) (DeviceIdentity, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	libp2pPublic, err := libp2pcrypto.UnmarshalEd25519PublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := sovereignlibp2p.DerivePublicIdentity(
		0x81000011,
		libp2pPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(
		derived.Name,
		derived.PeerID.String(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return identity, private
}

func testTLSState(
	t *testing.T,
	identity DeviceIdentity,
	subjectPrivate ed25519.PrivateKey,
) tls.ConnectionState {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test adoption root"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(
		rand.Reader,
		caTemplate,
		caTemplate,
		caPublic,
		caPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	spiffeURI, err := url.Parse(identity.SPIFFEID)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: identity.SPIFFEID},
		NotBefore:             testNow.Add(-time.Minute),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{spiffeURI},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		leafTemplate,
		ca,
		subjectPrivate.Public(),
		caPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{
		Version:          tls.VersionTLS13,
		HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{leaf, ca},
		VerifiedChains:   [][]*x509.Certificate{{leaf, ca}},
	}
}

type memoryStore struct {
	mu       sync.Mutex
	snapshot Snapshot
}

func newMemoryStore() *memoryStore {
	return &memoryStore{snapshot: emptySnapshot()}
}

func (s *memoryStore) Load() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSnapshot(s.snapshot), nil
}

func (s *memoryStore) Commit(expected uint64, next Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot.Revision != expected {
		return ErrRevisionConflict
	}
	if next.Revision != expected+1 {
		return errors.New("invalid next revision")
	}
	if err := validateSnapshot(next); err != nil {
		return err
	}
	s.snapshot = cloneSnapshot(next)
	return nil
}

type testBuilder struct {
	mu    sync.Mutex
	views []PublicStateView
	err   error
}

func (b *testBuilder) Build(
	_ context.Context,
	view PublicStateView,
) ([]PublicDocument, error) {
	b.mu.Lock()
	b.views = append(b.views, view)
	err := b.err
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	document, buildErr := NewPublicDocument(
		PathDeviceDocument,
		mediaTypeJSON,
		[]byte(`{"schema_version":1,"public":true}`),
	)
	if buildErr != nil {
		return nil, buildErr
	}
	documents := []PublicDocument{document}
	if len(view.Revocations) == 0 {
		return documents, nil
	}
	crlPath, err := CRLPath(view.Revocations[0].RevokedAt.UTC())
	if err != nil {
		return nil, err
	}
	crl, err := NewPublicDocument(
		crlPath,
		mediaTypeCRL,
		[]byte{0x30, 0x00},
	)
	if err != nil {
		return nil, err
	}
	documents = append(documents, crl)
	for _, revocation := range view.Revocations {
		path, err := OCSPPath(revocation.StatusID)
		if err != nil {
			return nil, err
		}
		response, err := NewPublicDocument(
			path,
			mediaTypeOCSP,
			[]byte{0x30, 0x00},
		)
		if err != nil {
			return nil, err
		}
		documents = append(documents, response)
	}
	return documents, nil
}

type testPublisher struct {
	mu           sync.Mutex
	publications []Publication
	nextSequence uint64
	rootCID      string
	err          error
}

func (p *testPublisher) Publish(
	_ context.Context,
	publication Publication,
) (PublicationReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.publications = append(p.publications, publication.Clone())
	if p.err != nil {
		return PublicationReceipt{}, p.err
	}
	p.nextSequence++
	return PublicationReceipt{
		PublicationID: publication.ID,
		Digest:        publication.Digest,
		IPNSName:      publication.IPNSName,
		RootCID:       p.rootCID,
		IPNSSequence:  p.nextSequence,
	}, nil
}

type softwareKeyManager struct {
	caPublic       ed25519.PublicKey
	caPrivate      ed25519.PrivateKey
	devicePublic   ed25519.PublicKey
	requests       []keymanager.CertificateRequest
	issueErr       error
	customRole     keymanager.Role
	customPurpose  keymanager.KeyPurpose
	mu             sync.Mutex
}

func newSoftwareKeyManager(
	t *testing.T,
	devicePrivate ed25519.PrivateKey,
) *softwareKeyManager {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &softwareKeyManager{
		caPublic:     caPublic,
		caPrivate:    caPrivate,
		devicePublic: devicePrivate.Public().(ed25519.PublicKey),
	}
}

func (m *softwareKeyManager) Metadata(
	_ context.Context,
	role keymanager.Role,
) (keymanager.KeyMetadata, error) {
	var (
		public  crypto.PublicKey
		purpose keymanager.KeyPurpose
	)
	switch {
	case role == keymanager.RoleDeviceRootCA && m.customRole == role:
		public = m.caPublic
		purpose = m.customPurpose
	case role == keymanager.RoleDeviceRootCA:
		public = m.caPublic
		purpose = keymanager.PurposeCertificateAuthority
	case role == keymanager.RoleDeviceIPNSIdentity:
		public = m.devicePublic
		purpose = keymanager.PurposeDeviceIPNSIdentity
	default:
		return keymanager.KeyMetadata{}, errors.New("unknown role")
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return keymanager.KeyMetadata{}, err
	}
	return keymanager.KeyMetadata{
		Role:         role,
		Purpose:      purpose,
		PublicKeyDER: der,
	}, nil
}

func (m *softwareKeyManager) IssueCertificate(
	_ context.Context,
	request keymanager.CertificateRequest,
) ([]byte, error) {
	m.mu.Lock()
	m.requests = append(m.requests, request)
	issueErr := m.issueErr
	m.mu.Unlock()
	if issueErr != nil {
		return nil, issueErr
	}
	return x509.CreateCertificate(
		rand.Reader,
		request.Template,
		request.Parent,
		request.SubjectPublicKey,
		m.caPrivate,
	)
}

func newTestService(
	t *testing.T,
	identity DeviceIdentity,
	manager CertificateKeyManager,
	policy AuthorizationPolicy,
	material FederationMaterialProvider,
) (*Service, *memoryStore, *testBuilder, *testPublisher) {
	t.Helper()
	store := newMemoryStore()
	service, builder, publisher := newTestServiceOnStore(
		t,
		identity,
		store,
		manager,
		policy,
		material,
	)
	return service, store, builder, publisher
}

func newTestServiceOnStore(
	t *testing.T,
	identity DeviceIdentity,
	store Store,
	manager CertificateKeyManager,
	policy AuthorizationPolicy,
	material FederationMaterialProvider,
) (*Service, *testBuilder, *testPublisher) {
	t.Helper()
	builder := &testBuilder{}
	publisher := &testPublisher{rootCID: identity.CanonicalIPNS}
	service, err := NewService(ServiceConfig{
		Identity:                   identity,
		Store:                      store,
		KeyManager:                 manager,
		Policy:                     policy,
		FederationMaterial:         material,
		PublicSnapshotBuilder:      builder,
		Publisher:                  publisher,
		Clock:                      fixedClock{now: testNow},
		MaximumGrantLifetime:       time.Hour,
		MaximumCertificateLifetime: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	return service, builder, publisher
}

func grantFor(
	intent AuthorizationIntent,
	id string,
) AuthorizationGrant {
	return AuthorizationGrant{
		GrantID:              id,
		ExpectedRevision:     intent.CurrentRevision,
		ExpiresAt:            testNow.Add(30 * time.Minute),
		CertificateNotBefore: testNow.Add(-time.Minute),
		CertificateNotAfter:  testNow.Add(12 * time.Hour),
	}
}
