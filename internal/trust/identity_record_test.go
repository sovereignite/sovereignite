// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	sovereignlibp2p "github.com/sovereignite/sovereignite/internal/libp2p"
)

const testHandle uint32 = 0x81000011

func testKeyPair(t *testing.T) (libp2pcrypto.PubKey, ed25519.PrivateKey, peer.ID) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	libp2pPublic, err := libp2pcrypto.UnmarshalEd25519PublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPublicKey(libp2pPublic)
	if err != nil {
		t.Fatal(err)
	}
	return libp2pPublic, private, peerID
}

func testAddrInfo(t *testing.T, pid peer.ID) peer.AddrInfo {
	t.Helper()
	maddr1, err := multiaddr.NewMultiaddr("/ip4/192.168.1.1/tcp/4001")
	if err != nil {
		t.Fatal(err)
	}
	maddr2, err := multiaddr.NewMultiaddr("/ip4/10.0.0.1/tcp/4001")
	if err != nil {
		t.Fatal(err)
	}
	return peer.AddrInfo{
		ID:    pid,
		Addrs: []multiaddr.Multiaddr{maddr1, maddr2},
	}
}

func TestMapAddrInfoToIdentityRecordBindsPeerIDAndAddresses(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.PeerID != derived.PeerID.String() {
		t.Fatalf("PeerID = %q, want %q", record.PeerID, derived.PeerID.String())
	}
	if len(record.Addrs) != 2 {
		t.Fatalf("Addrs count = %d, want 2", len(record.Addrs))
	}
	if record.Phase != IdentityPhasePending {
		t.Fatalf("Phase = %q, want %q", record.Phase, IdentityPhasePending)
	}
}

func TestMapAddrInfoToIdentityRecordPublicKeyMapping(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Keys) != 1 {
		t.Fatalf("Keys count = %d, want 1", len(record.Keys))
	}
	key := record.Keys[0]
	if key.Type != "Ed25519" {
		t.Fatalf("Key type = %q, want %q", key.Type, "Ed25519")
	}
	if key.RawBase64 == "" {
		t.Fatal("Key raw base64 is empty")
	}
	decoded, err := decodeBase64(t, key.RawBase64)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) == 0 {
		t.Fatal("decoded key bytes are empty")
	}
	if key.TPMHandle != formatTPMHandle(testHandle) {
		t.Fatalf("TPM handle = %q, want %q", key.TPMHandle, formatTPMHandle(testHandle))
	}
}

func TestMapAddrInfoToIdentityRecordNoPrivateKey(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range record.Keys {
		if key.RawBase64 == "" {
			continue
		}
		decoded, err := decodeBase64(t, key.RawBase64)
		if err != nil {
			t.Fatal(err)
		}
		_, err = libp2pcrypto.UnmarshalPublicKey(decoded)
		if err != nil {
			t.Fatalf("key raw bytes are not a valid libp2p public key: %v", err)
		}
	}
}

func TestMapAddrInfoToIdentityRecordTPMHandleReference(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.Handle != testHandle {
		t.Fatalf("Handle = 0x%08x, want 0x%08x", record.Handle, testHandle)
	}
	if record.Keys[0].TPMHandle != formatTPMHandle(testHandle) {
		t.Fatalf("Key TPMHandle = %q, want %q", record.Keys[0].TPMHandle, formatTPMHandle(testHandle))
	}
}

func TestMapAddrInfoToIdentityRecordRejectsInvalidHandle(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	_, err = MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		0x00000001,
		identity.SPIFFEID,
	)
	if err == nil {
		t.Fatal("MapAddrInfoToIdentityRecord accepted invalid handle")
	}
}

func TestMapAddrInfoToIdentityRecordSPIFFEDerivation(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.SPIFFEID != identity.SPIFFEID {
		t.Fatalf("SPIFFEID = %q, want %q", record.SPIFFEID, identity.SPIFFEID)
	}
	if err := ValidateSPIFFEDerivation(record); err != nil {
		t.Fatalf("ValidateSPIFFEDerivation: %v", err)
	}
}

func TestMapPeerRecordToIdentityRecordUpdatesSequence(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.PeerRecordSequence != 0 {
		t.Fatalf("initial PeerRecordSequence = %d, want 0", record.PeerRecordSequence)
	}

	envelope := IdentityEnvelope{
		AddrInfo: addrInfo,
		Sequence: 5,
	}
	updated, err := MapPeerRecordToIdentityRecord(record, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if updated.PeerRecordSequence != 5 {
		t.Fatalf("PeerRecordSequence = %d, want 5", updated.PeerRecordSequence)
	}
}

func TestMapPeerRecordToIdentityRecordRejectsStaleEnvelope(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.PeerRecordSequence = 10

	envelope := IdentityEnvelope{
		AddrInfo: addrInfo,
		Sequence: 5,
	}
	_, err = MapPeerRecordToIdentityRecord(record, envelope)
	if err == nil {
		t.Fatal("MapPeerRecordToIdentityRecord accepted stale envelope")
	}
}

func TestX509SVIDMapping(t *testing.T) {
	t.Parallel()

	public, private, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}

	spiffeURI, _ := url.Parse(identity.SPIFFEID)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: identity.SPIFFEID},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{spiffeURI},
	}
	caPublic, caPrivate, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	ca, _ := x509.ParseCertificate(caDER)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, ca, private.Public(), caPrivate)

	updated, err := ValidateX509SVID(record, [][]byte{certDER})
	if err != nil {
		t.Fatal(err)
	}
	if updated.X509SVID == nil {
		t.Fatal("X509SVID is nil after mapping")
	}
	if len(updated.X509SVID.CertificateChain) != 1 {
		t.Fatalf("SVID chain length = %d, want 1", len(updated.X509SVID.CertificateChain))
	}
	if updated.X509SVID.Expiry.IsZero() {
		t.Fatal("SVID expiry is zero")
	}
}

func TestPhaseTransitionPendingToActive(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.Phase != IdentityPhasePending {
		t.Fatalf("initial Phase = %q, want %q", record.Phase, IdentityPhasePending)
	}

	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	activated, err := TransitionIdentityPhase(record, IdentityPhaseActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if activated.Phase != IdentityPhaseActive {
		t.Fatalf("Phase after transition = %q, want %q", activated.Phase, IdentityPhaseActive)
	}
	if activated.Generation != 1 {
		t.Fatalf("Generation = %d, want 1", activated.Generation)
	}
	if len(activated.Conditions) != 1 {
		t.Fatalf("Conditions count = %d, want 1", len(activated.Conditions))
	}
	cond := activated.Conditions[0]
	if cond.Type != "PhaseTransition" {
		t.Fatalf("Condition type = %q, want %q", cond.Type, "PhaseTransition")
	}
	if cond.Reason != "pending→active" {
		t.Fatalf("Condition reason = %q, want %q", cond.Reason, "pending→active")
	}
}

func TestPhaseTransitionActiveToRevoked(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	activated, err := TransitionIdentityPhase(record, IdentityPhaseActive, now)
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := TransitionIdentityPhase(activated, IdentityPhaseRevoked, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Phase != IdentityPhaseRevoked {
		t.Fatalf("Phase = %q, want %q", revoked.Phase, IdentityPhaseRevoked)
	}
	if revoked.Generation != 2 {
		t.Fatalf("Generation = %d, want 2", revoked.Generation)
	}
}

func TestPhaseTransitionRejectsInvalidTransitions(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	_, err = TransitionIdentityPhase(record, IdentityPhaseRevoked, now)
	if err == nil {
		t.Fatal("TransitionIdentityPhase accepted pending→revoked")
	}

	activated, err := TransitionIdentityPhase(record, IdentityPhaseActive, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = TransitionIdentityPhase(activated, IdentityPhasePending, now)
	if err == nil {
		t.Fatal("TransitionIdentityPhase accepted active→pending")
	}

	revoked, err := TransitionIdentityPhase(activated, IdentityPhaseRevoked, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = TransitionIdentityPhase(revoked, IdentityPhaseActive, now)
	if err == nil {
		t.Fatal("TransitionIdentityPhase accepted revoked→active")
	}
}

func TestGenerationTracking(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.Generation != 0 {
		t.Fatalf("initial Generation = %d, want 0", record.Generation)
	}

	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	activated, err := TransitionIdentityPhase(record, IdentityPhaseActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if activated.Generation != 1 {
		t.Fatalf("Generation after activation = %d, want 1", activated.Generation)
	}
	if activated.ObservedGeneration != 0 {
		t.Fatalf("ObservedGeneration = %d, want 0", activated.ObservedGeneration)
	}

	revoked, err := TransitionIdentityPhase(activated, IdentityPhaseRevoked, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Generation != 2 {
		t.Fatalf("Generation after revocation = %d, want 2", revoked.Generation)
	}
}

func TestValidateIdentityRecordRejectsMismatchedPeerID(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, _, otherPeerID := testKeyPair(t)
	err = ValidateIdentityRecord(record, otherPeerID.String())
	if err == nil {
		t.Fatal("ValidateIdentityRecord accepted mismatched peer ID")
	}
}

func TestValidatePublicKeyPeerIDConsistencyRejectsMismatch(t *testing.T) {
	t.Parallel()

	public, _, peerID := testKeyPair(t)
	_, _, otherPeerID := testKeyPair(t)

	err := ValidatePublicKeyPeerIDConsistency(public, otherPeerID.String())
	if err == nil {
		t.Fatal("ValidatePublicKeyPeerIDConsistency accepted mismatched key/peerID")
	}

	err = ValidatePublicKeyPeerIDConsistency(public, peerID.String())
	if err != nil {
		t.Fatalf("ValidatePublicKeyPeerIDConsistency rejected matching key/peerID: %v", err)
	}
}

func TestValidateHandleOwnershipRejectsForeignHandle(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}

	err = ValidateHandleOwnership(record, 0x81000099)
	if err == nil {
		t.Fatal("ValidateHandleOwnership accepted foreign handle")
	}

	err = ValidateHandleOwnership(record, testHandle)
	if err != nil {
		t.Fatalf("ValidateHandleOwnership rejected matching handle: %v", err)
	}
}

func TestValidateIdentityRecordRejectsStaleGeneration(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.Generation = 5
	record.ObservedGeneration = 10

	err = ValidateIdentityRecord(record, record.PeerID)
	if err == nil {
		t.Fatal("ValidateIdentityRecord accepted stale generation")
	}
}

func TestValidateIdentityRecordAcceptsValidRecord(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}

	err = ValidateIdentityRecord(record, record.PeerID)
	if err != nil {
		t.Fatalf("ValidateIdentityRecord rejected valid record: %v", err)
	}
}

func TestIdentityRecordToProtoMapping(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}

	proto := IdentityRecordToProto(record)
	if proto["peer_id"] != record.PeerID {
		t.Fatalf("proto peer_id = %q, want %q", proto["peer_id"], record.PeerID)
	}
	if proto["phase"] != "IDENTITY_PHASE_PENDING" {
		t.Fatalf("proto phase = %q, want %q", proto["phase"], "IDENTITY_PHASE_PENDING")
	}
	if proto["spiffe_id"] != record.SPIFFEID {
		t.Fatalf("proto spiffe_id = %q, want %q", proto["spiffe_id"], record.SPIFFEID)
	}
}

func TestRoundTripFromLibp2pToRecordAndBack(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateIdentityRecord(record, record.PeerID); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicKeyPeerIDConsistency(public, record.PeerID); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHandleOwnership(record, testHandle); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSPIFFEDerivation(record); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	activated, err := TransitionIdentityPhase(record, IdentityPhaseActive, now)
	if err != nil {
		t.Fatal(err)
	}
	proto := IdentityRecordToProto(activated)
	if proto["phase"] != "IDENTITY_PHASE_ACTIVE" {
		t.Fatalf("activated proto phase = %q, want %q", proto["phase"], "IDENTITY_PHASE_ACTIVE")
	}
}

func TestMapAddrInfoToIdentityRecordPopulatesAddrs(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Addrs) != len(addrInfo.Addrs) {
		t.Fatalf("Addrs count = %d, want %d", len(record.Addrs), len(addrInfo.Addrs))
	}
	for i, addr := range record.Addrs {
		_, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			t.Fatalf("Addrs[%d] = %q is not a valid multiaddr: %v", i, addr, err)
		}
		expected := addrInfo.Addrs[i].String()
		if addr != expected {
			t.Fatalf("Addrs[%d] = %q, want %q", i, addr, expected)
		}
	}
}

func TestMapPeerRecordToIdentityRecordSetsPeerRecordSequence(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.PeerRecordSequence != 0 {
		t.Fatalf("initial PeerRecordSequence = %d, want 0", record.PeerRecordSequence)
	}

	envelope := IdentityEnvelope{
		AddrInfo: addrInfo,
		Sequence: 42,
	}
	updated, err := MapPeerRecordToIdentityRecord(record, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if updated.PeerRecordSequence != 42 {
		t.Fatalf("PeerRecordSequence = %d, want 42", updated.PeerRecordSequence)
	}
}

func TestValidateIdentityRecordRejectsEmptyAddrs(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.Addrs = nil

	err = ValidateIdentityRecord(record, record.PeerID)
	if err == nil {
		t.Fatal("ValidateIdentityRecord accepted record with empty Addrs")
	}
}

func TestValidateIdentityRecordRejectsInvalidMultiaddr(t *testing.T) {
	t.Parallel()

	public, _, _ := testKeyPair(t)
	derived, err := sovereignlibp2p.DerivePublicIdentity(testHandle, public)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := DeriveDeviceIdentity(derived.Name, derived.PeerID.String())
	if err != nil {
		t.Fatal(err)
	}
	addrInfo := testAddrInfo(t, derived.PeerID)

	record, err := MapAddrInfoToIdentityRecord(
		addrInfo,
		public,
		testHandle,
		identity.SPIFFEID,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.Addrs = []string{"not-a-valid-multiaddr"}

	err = ValidateIdentityRecord(record, record.PeerID)
	if err == nil {
		t.Fatal("ValidateIdentityRecord accepted record with invalid multiaddr")
	}
}

func decodeBase64(t *testing.T, encoded string) ([]byte, error) {
	t.Helper()
	return base64.StdEncoding.DecodeString(encoded)
}
