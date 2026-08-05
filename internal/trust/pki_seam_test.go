// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/sovereignite/sovereignite/internal/keymanager"
)

// --- Acceptance 1: Canonical IDs / trust domain ---

func TestSPIFFEDerivationFromCanonicalIPNSName(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	spiffeID, err := url.Parse(identity.SPIFFEID)
	if err != nil {
		t.Fatal(err)
	}
	if spiffeID.Scheme != "spiffe" {
		t.Fatalf("scheme = %q, want spiffe", spiffeID.Scheme)
	}
	if spiffeID.Host != identity.CanonicalIPNS {
		t.Fatalf(
			"trust domain = %q, want canonical IPNS %q",
			spiffeID.Host,
			identity.CanonicalIPNS,
		)
	}
	if !strings.HasPrefix(spiffeID.Path, DeviceSPIFFEPathPrefix) {
		t.Fatalf("SPIFFE path = %q, want prefix %q", spiffeID.Path, DeviceSPIFFEPathPrefix)
	}
	peerSegment := strings.TrimPrefix(spiffeID.Path, DeviceSPIFFEPathPrefix)
	if peerSegment != identity.PeerID {
		t.Fatalf("peer segment = %q, want %q", peerSegment, identity.PeerID)
	}
}

func TestTrustDomainMatchesCanonicalIPNS(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	domain, err := TrustDomainFromIPNS(identity.CanonicalIPNS)
	if err != nil {
		t.Fatal(err)
	}
	if domain != identity.CanonicalIPNS {
		t.Fatalf("trust domain = %q, want %q", domain, identity.CanonicalIPNS)
	}
	if domain != identity.TrustDomain {
		t.Fatalf("trust domain = %q, want identity trust domain %q", domain, identity.TrustDomain)
	}
}

func TestDeriveDeviceIdentityRejectsEmptyAndMutatedInputs(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	if _, err := DeriveDeviceIdentity("", identity.PeerID); err == nil {
		t.Fatal("DeriveDeviceIdentity accepted empty IPNS")
	}
	if _, err := DeriveDeviceIdentity(identity.CanonicalIPNS, ""); err == nil {
		t.Fatal("DeriveDeviceIdentity accepted empty peer ID")
	}
	if _, err := DeriveDeviceIdentity(
		" "+identity.CanonicalIPNS,
		identity.PeerID,
	); err == nil {
		t.Fatal("DeriveDeviceIdentity accepted leading whitespace")
	}
	if _, err := DeriveDeviceIdentity(
		identity.CanonicalIPNS+"\t",
		identity.PeerID,
	); err == nil {
		t.Fatal("DeriveDeviceIdentity accepted trailing tab")
	}
}

func TestParseDeviceSPIFFEIDRequiresCanonicalForm(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	if _, err := ParseDeviceSPIFFEID(""); err == nil {
		t.Fatal("ParseDeviceSPIFFEID accepted empty string")
	}
	lower := strings.ToLower(identity.SPIFFEID)
	if lower != identity.SPIFFEID {
		if _, err := ParseDeviceSPIFFEID(lower); err == nil {
			t.Fatal("ParseDeviceSPIFFEID accepted lowercase mutation")
		}
	}
	upper := strings.ToUpper(identity.SPIFFEID)
	if _, err := ParseDeviceSPIFFEID(upper); err == nil {
		t.Fatal("ParseDeviceSPIFFEID accepted uppercase mutation")
	}
}

// --- Acceptance 2: Purpose-authorized TPM signer ---

func TestCertificateIssuanceGoesThroughTPMBoundary(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	manager := newSoftwareKeyManager(t, localPrivate)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationInitializeCA:
			return grantFor(intent, "tpm_boundary_ca_grant01"), nil
		case OperationIssueMTLSCertificate:
			return grantFor(intent, "tpm_boundary_leaf01"), nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	service, _, _, _ := newTestService(t, local, manager, policy, nil)
	caDER, err := service.InitializeLocalCA(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("CA is not a signing authority: KeyUsage=0x%x IsCA=%v", ca.KeyUsage, ca.IsCA)
	}
	if ca.Subject.CommonName != local.TrustDomain {
		t.Fatalf("CA CN = %q, want trust domain %q", ca.Subject.CommonName, local.TrustDomain)
	}
	leafDER, err := service.IssueLocalMTLSCertificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("leaf not signed by CA: %v", err)
	}
	if leaf.IsCA {
		t.Fatal("leaf certificate is marked CA")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != local.SPIFFEID {
		t.Fatalf("leaf URI SANs = %v, want %q", leaf.URIs, local.SPIFFEID)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.requests) != 2 {
		t.Fatalf("key manager requests = %d, want 2", len(manager.requests))
	}
	if manager.requests[0].Role != keymanager.RoleDeviceRootCA {
		t.Fatalf("CA request role = %q, want RoleDeviceRootCA", manager.requests[0].Role)
	}
	if manager.requests[1].Role != keymanager.RoleDeviceRootCA {
		t.Fatalf("leaf request role = %q, want RoleDeviceRootCA", manager.requests[1].Role)
	}
}

func TestTPMKeyManagerRejectsNonCertificatePurpose(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	manager := newSoftwareKeyManagerWithPurpose(
		t,
		localPrivate,
		keymanager.RoleDeviceRootCA,
		keymanager.KeyPurpose("non-certificate"),
	)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		return grantFor(intent, "tpm_wrong_purpose_gr01"), nil
	})
	service, _, _, _ := newTestService(t, local, manager, policy, nil)
	if _, err := service.InitializeLocalCA(context.Background()); err == nil {
		t.Fatal("InitializeLocalCA succeeded with non-certificate purpose TPM key")
	}
}

func TestLocalCARequiresPolicyGrant(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	service, _, _, _ := newTestService(t, local, nil, nil, nil)
	if _, err := service.InitializeLocalCA(context.Background()); err == nil {
		t.Fatal("InitializeLocalCA succeeded without policy")
	}
}

func TestMTLSIssuanceRequiresActiveCA(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		return grantFor(intent, "mtls_no_ca_grant00001"), nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	if _, err := service.IssueLocalMTLSCertificate(context.Background()); err == nil {
		t.Fatal("IssueLocalMTLSCertificate succeeded without active CA")
	}
}

// --- Acceptance 3: Directed domain-keyed edges ---

func TestFederationEdgeIsDirectedLocalToRemoteOnly(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	generation := uint64(10)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "directed_edge_owner1")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "directed_edge_ca0001"), nil
		case OperationFederate:
			grant := grantFor(intent, "directed_edge_fed001")
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = generation
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		return FederationMaterial{
			RemoteCACertificateDER: remoteCA,
			SourceGeneration:       generation,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	edge, err := service.Federate(context.Background(), state, remote.TrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	if edge.SourceDomain != local.TrustDomain {
		t.Fatalf("source domain = %q, want %q", edge.SourceDomain, local.TrustDomain)
	}
	if edge.TargetDomain != remote.TrustDomain {
		t.Fatalf("target domain = %q, want %q", edge.TargetDomain, remote.TrustDomain)
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, reverse := snapshot.Federations[local.TrustDomain]; reverse {
		t.Fatal("federation created a reverse edge under the local trust domain")
	}
	bundle, exists := snapshot.Bundles[remote.TrustDomain]
	if !exists {
		t.Fatal("remote trust bundle missing")
	}
	if bundle.TrustDomain != remote.TrustDomain {
		t.Fatalf(
			"remote bundle trust domain = %q, want %q",
			bundle.TrustDomain,
			remote.TrustDomain,
		)
	}
	if len(bundle.CACertificates) != 1 {
		t.Fatalf("remote bundle CA count = %d, want 1", len(bundle.CACertificates))
	}
}

func TestFederationRejectsNonHubSpokeRoles(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	generation := uint64(11)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "bad_role_owner_001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "bad_role_ca_00001"), nil
		case OperationFederate:
			grant := grantFor(intent, "bad_role_fed_001")
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleHub
			grant.SourceGeneration = generation
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		return FederationMaterial{
			RemoteCACertificateDER: remoteCA,
			SourceGeneration:       generation,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(context.Background(), state, remote.TrustDomain); err == nil {
		t.Fatal("Federate accepted non-hub-spoke roles")
	}
}

// --- Acceptance 4: Cross-certificate / revocation inputs ---

func TestFederationCrossCertificateIssuanceAndRevocation(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	gen1 := uint64(20)
	gen2 := uint64(21)
	var currentGen uint64 = gen1
	var callCount int
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "xcert_owner_000001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "xcert_init_ca_001"), nil
		case OperationFederate:
			callCount++
			id := "xcert_fed_000001"
			if callCount == 2 {
				id = "xcert_fed_000002"
			}
			grant := grantFor(intent, id)
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = currentGen
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		return FederationMaterial{
			RemoteCACertificateDER: remoteCA,
			SourceGeneration:       currentGen,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	edge1, err := service.Federate(context.Background(), state, remote.TrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	if len(edge1.CrossCertificate) == 0 {
		t.Fatal("first federation edge has no cross-certificate")
	}
	if edge1.CrossCertificateID == "" || edge1.CrossCertificateSerial == "" {
		t.Fatalf("first edge cross-cert metadata: id=%q serial=%q",
			edge1.CrossCertificateID, edge1.CrossCertificateSerial)
	}
	x509Cross, err := x509.ParseCertificate(edge1.CrossCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if !x509Cross.IsCA || x509Cross.MaxPathLen != 0 {
		t.Fatalf("cross-cert: IsCA=%v MaxPathLen=%d, want IsCA=true MaxPathLen=0",
			x509Cross.IsCA, x509Cross.MaxPathLen)
	}
	if x509Cross.Subject.CommonName != remote.TrustDomain {
		t.Fatalf("cross-cert CN = %q, want %q", x509Cross.Subject.CommonName, remote.TrustDomain)
	}
	currentGen = gen2
	edge2, err := service.Federate(context.Background(), state, remote.TrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	if edge2.CrossCertificateID == edge1.CrossCertificateID {
		t.Fatal("replacement edge reuses the same cross-certificate ID")
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	retired, exists := snapshot.Revocations[edge1.CrossCertificateID]
	if !exists {
		t.Fatal("first cross-certificate was not revoked")
	}
	if retired.Kind != RevocationKindCross {
		t.Fatalf("revocation kind = %q, want %q", retired.Kind, RevocationKindCross)
	}
	if !bytes.Equal(retired.CertificateDER, edge1.CrossCertificate) {
		t.Fatal("revoked cross-certificate DER does not match original")
	}
}

func TestCertificateRevocationIsAtomicBeforePublication(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "revoke_atomic_own01")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "revoke_atomic_ca01"), nil
		case OperationIssueMTLSCertificate:
			return grantFor(intent, "revoke_atomic_leaf1"), nil
		case OperationRevokeCertificate:
			return grantFor(intent, "revoke_atomic_rev1"), nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, publisher := newTestService(t, local, manager, policy, nil)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	leafDER, err := service.IssueLocalMTLSCertificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	certID := certificateID(leafDER)
	publisher.err = errors.New("IPFS unavailable")
	if err := service.RevokeCertificate(context.Background(), state, certID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Certificates[certID].Status != CertificateStatusRevoked {
		t.Fatalf("cert status = %q, want revoked", snapshot.Certificates[certID].Status)
	}
	revocation, exists := snapshot.Revocations[certID]
	if !exists {
		t.Fatal("revocation record missing after local revocation")
	}
	if revocation.Kind != RevocationKindMTLS {
		t.Fatalf("revocation kind = %q, want %q", revocation.Kind, RevocationKindMTLS)
	}
	if len(snapshot.Outbox) == 0 {
		t.Fatal("revocation did not produce an outbox item")
	}
}

// --- Acceptance 5: Reject invalid namespace / handle / stale source ---

func TestRejectSPIFFEWithUnauthorizedSubjectNamespace(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	candidates := []string{
		"spiffe://" + identity.TrustDomain + "/workload/" + identity.PeerID,
		"spiffe://" + identity.TrustDomain + "/service/web",
		"spiffe://" + identity.TrustDomain + "/node/" + identity.PeerID,
		"spiffe://" + identity.TrustDomain + "/agent/" + identity.PeerID,
		"spiffe://" + identity.TrustDomain + "/pods/" + identity.PeerID,
	}
	for _, candidate := range candidates {
		if _, err := ParseDeviceSPIFFEID(candidate); err == nil {
			t.Fatalf("ParseDeviceSPIFFEID accepted unauthorized namespace: %q", candidate)
		}
	}
}

func TestRejectInvalidPeerIDInSPIFFEPath(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	badHandles := []string{
		"",
		"not-a-valid-peer-id",
		identity.PeerID + "/extra",
		"/" + identity.PeerID,
		identity.PeerID + "?query",
		identity.PeerID + "#fragment",
	}
	for _, handle := range badHandles {
		spiffe := "spiffe://" + identity.TrustDomain + DeviceSPIFFEPathPrefix + handle
		if _, err := ParseDeviceSPIFFEID(spiffe); err == nil {
			t.Fatalf("ParseDeviceSPIFFEID accepted invalid handle: %q", handle)
		}
	}
}

func TestFederateRejectsStaleMaterialGeneration(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	gen := uint64(30)
	callCount := 0
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "stale_mat_owner0001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "stale_mat_ca_0001"), nil
		case OperationFederate:
			callCount++
			id := "stale_mat_fed_0001"
			if callCount == 2 {
				id = "stale_mat_fed_0002"
			}
			grant := grantFor(intent, id)
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = gen
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		materialGen := gen
		if callCount == 2 {
			materialGen = gen - 5
		}
		return FederationMaterial{
			RemoteCACertificateDER: remoteCA,
			SourceGeneration:       materialGen,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(context.Background(), state, remote.TrustDomain); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(context.Background(), state, remote.TrustDomain); err == nil {
		t.Fatal("Federate accepted stale material generation")
	}
}

func TestFederateRejectsZeroGeneration(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "zero_gen_owner_001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "zero_gen_ca_00001"), nil
		case OperationFederate:
			grant := grantFor(intent, "zero_gen_fed_001")
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = 0
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		return FederationMaterial{
			RemoteCACertificateDER: remoteCA,
			SourceGeneration:       0,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(context.Background(), state, remote.TrustDomain); err == nil {
		t.Fatal("Federate accepted zero generation")
	}
}

// --- Acceptance 6: Reject reverse / spoke inference and CA merging ---

func TestNoReverseTrustEdgeIsInferred(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	generation := uint64(40)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "no_reverse_owner_01")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "no_reverse_ca_0001"), nil
		case OperationFederate:
			grant := grantFor(intent, "no_reverse_fed_01")
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = generation
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		return FederationMaterial{
			RemoteCACertificateDER: remoteCA,
			SourceGeneration:       generation,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(context.Background(), state, remote.TrustDomain); err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for domain, federation := range snapshot.Federations {
		if domain == local.TrustDomain {
			t.Fatal("reverse edge found under local trust domain")
		}
		if federation.SourceDomain != local.TrustDomain {
			t.Fatalf(
				"federation %q has source domain %q, want %q",
				domain,
				federation.SourceDomain,
				local.TrustDomain,
			)
		}
	}
}

func TestTrustBundlesAreDomainKeyedNeverMerged(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remoteA, _ := testIdentity(t)
	remoteB, _ := testIdentity(t)
	remoteACA := testCertificateAuthority(t, remoteA.TrustDomain)
	remoteBCA := testCertificateAuthority(t, remoteB.TrustDomain)
	genA := uint64(50)
	genB := uint64(51)
	var currentGen uint64 = genA
	callCount := 0
	var mu sync.Mutex
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "bundle_merge_owner_1")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "bundle_merge_ca_0001"), nil
		case OperationFederate:
			mu.Lock()
			callCount++
			count := callCount
			mu.Unlock()
			id := "bundle_merge_fed_01"
			if count == 2 {
				id = "bundle_merge_fed_02"
			}
			grant := grantFor(intent, id)
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = currentGen
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		if domain == remoteA.TrustDomain {
			return FederationMaterial{
				RemoteCACertificateDER: remoteACA,
				SourceGeneration:       currentGen,
			}, nil
		}
		return FederationMaterial{
			RemoteCACertificateDER: remoteBCA,
			SourceGeneration:       currentGen,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(context.Background(), state, remoteA.TrustDomain); err != nil {
		t.Fatal(err)
	}
	currentGen = genB
	if _, err := service.Federate(context.Background(), state, remoteB.TrustDomain); err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Bundles) != 3 {
		t.Fatalf("bundle count = %d, want 3 (local + 2 remote)", len(snapshot.Bundles))
	}
	for domain, bundle := range snapshot.Bundles {
		for _, caDER := range bundle.CACertificates {
			ca, err := x509.ParseCertificate(caDER)
			if err != nil {
				t.Fatalf("bundle %q: parse CA: %v", domain, err)
			}
			if ca.Subject.CommonName != domain {
				t.Fatalf(
					"bundle %q contains CA with CN %q",
					domain,
					ca.Subject.CommonName,
				)
			}
		}
	}
	localBundle := snapshot.Bundles[local.TrustDomain]
	if !bytes.Equal(localBundle.CACertificates[0], snapshot.ActiveCACertificate) {
		t.Fatal("local bundle does not contain the active CA")
	}
	remoteABundle := snapshot.Bundles[remoteA.TrustDomain]
	if !bytes.Equal(remoteABundle.CACertificates[0], remoteACA) {
		t.Fatal("remote A bundle CA does not match the supplied remote CA")
	}
	remoteBBundle := snapshot.Bundles[remoteB.TrustDomain]
	if !bytes.Equal(remoteBBundle.CACertificates[0], remoteBCA) {
		t.Fatal("remote B bundle CA does not match the supplied remote CA")
	}
}

func TestFederateRejectsRemoteCABoundToWrongDomain(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	wrongDomainCA := testCertificateAuthority(t, "some-other-trust-domain")
	generation := uint64(60)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "wrong_cn_owner_0001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "wrong_cn_ca_00001"), nil
		case OperationFederate:
			grant := grantFor(intent, "wrong_cn_fed_001")
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = generation
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		return FederationMaterial{
			RemoteCACertificateDER: wrongDomainCA,
			SourceGeneration:       generation,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(context.Background(), state, remote.TrustDomain); err == nil {
		t.Fatal("Federate accepted remote CA bound to wrong domain")
	}
}

func TestFederateRejectsWhenFederationMaterialUnavailable(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	generation := uint64(70)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "no_material_own_001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "no_material_ca_001"), nil
		case OperationFederate:
			grant := grantFor(intent, "no_material_fed_01")
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = generation
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, nil)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(context.Background(), state, remote.TrustDomain); err == nil {
		t.Fatal("Federate succeeded without federation material provider")
	}
}

func TestFederateRequiresCAInitializedBeforeFederation(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	generation := uint64(80)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "fed_no_ca_own_001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationFederate:
			grant := grantFor(intent, "fed_no_ca_fed_001")
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = generation
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		return FederationMaterial{
			RemoteCACertificateDER: remoteCA,
			SourceGeneration:       generation,
		}, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(context.Background(), state, remote.TrustDomain); err == nil {
		t.Fatal("Federate succeeded without initializing local CA")
	}
}

// --- Additional negative vectors ---

func TestRejectSPIFFEIDOverMaximumLength(t *testing.T) {
	t.Parallel()

	longPeer := strings.Repeat("a", 2048)
	spiffe := "spiffe://trust-domain" + DeviceSPIFFEPathPrefix + longPeer
	if _, err := ParseDeviceSPIFFEID(spiffe); err == nil {
		t.Fatal("ParseDeviceSPIFFEID accepted SPIFFE ID exceeding 2048 bytes")
	}
}

func TestRejectSPIFFEIDWithPercentEncoding(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	encoded := "spiffe://" + identity.TrustDomain + DeviceSPIFFEPathPrefix + "%61"
	if _, err := ParseDeviceSPIFFEID(encoded); err == nil {
		t.Fatal("ParseDeviceSPIFFEID accepted percent-encoded ID")
	}
}

func TestRejectTrustDomainWithIPNSPrefix(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	if _, err := TrustDomainFromIPNS("/ipns/" + identity.CanonicalIPNS); err == nil {
		t.Fatal("TrustDomainFromIPNS accepted /ipns/ prefix")
	}
}

func TestRejectTrustDomainWithUppercaseMutation(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	upper := strings.ToUpper(identity.CanonicalIPNS)
	if _, err := TrustDomainFromIPNS(upper); err == nil {
		t.Fatal("TrustDomainFromIPNS accepted uppercase mutation")
	}
}

func TestRejectTrustDomainWithWhitespace(t *testing.T) {
	t.Parallel()

	identity, _ := testIdentity(t)
	if _, err := TrustDomainFromIPNS(" " + identity.CanonicalIPNS); err == nil {
		t.Fatal("TrustDomainFromIPNS accepted leading whitespace")
	}
	if _, err := TrustDomainFromIPNS(identity.CanonicalIPNS + " "); err == nil {
		t.Fatal("TrustDomainFromIPNS accepted trailing whitespace")
	}
}

func TestCrossCertificateHasMaxPathLenZero(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	generation := uint64(90)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "xcert_pathlen_own1")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "xcert_pathlen_ca1"), nil
		case OperationFederate:
			grant := grantFor(intent, "xcert_pathlen_fed1")
			grant.LocalFederationRole = FederationRoleHub
			grant.RemoteFederationRole = FederationRoleSpoke
			grant.SourceGeneration = generation
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	material := FederationMaterialProviderFunc(func(
		_ context.Context,
		_ DeviceIdentity,
		domain string,
		_ VerifiedMTLSPeer,
	) (FederationMaterial, error) {
		return FederationMaterial{
			RemoteCACertificateDER: remoteCA,
			SourceGeneration:       generation,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, _, _ := newTestService(t, local, manager, policy, material)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	edge, err := service.Federate(context.Background(), state, remote.TrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	cross, err := x509.ParseCertificate(edge.CrossCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if !cross.MaxPathLenZero {
		t.Fatal("cross-certificate MaxPathLenZero is false")
	}
	if cross.MaxPathLen != 0 {
		t.Fatalf("cross-certificate MaxPathLen = %d, want 0", cross.MaxPathLen)
	}
}

func TestFederateRejectsSelfFederationEdge(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "self_fed_own_0001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(
		context.Background(),
		state,
		local.TrustDomain,
	); err == nil {
		t.Fatal("Federate accepted self-edge")
	}
}

func TestFederateRejectsNonCanonicalTrustDomain(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "noncan_fed_own_01")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(context.Background(), state, local.PeerID); err != nil {
		t.Fatal(err)
	}
	candidates := []string{
		"",
		"not-a-valid-ipns-name",
		"/ipns/" + local.CanonicalIPNS,
		strings.ToUpper(local.CanonicalIPNS),
	}
	for _, domain := range candidates {
		if _, err := service.Federate(context.Background(), state, domain); err == nil {
			t.Fatalf("Federate accepted non-canonical domain: %q", domain)
		}
	}
}

// --- Helper for custom purpose TPM ---

func newSoftwareKeyManagerWithPurpose(
	t *testing.T,
	devicePrivate ed25519.PrivateKey,
	role keymanager.Role,
	purpose keymanager.KeyPurpose,
) *softwareKeyManager {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &softwareKeyManager{
		caPublic:      caPublic,
		caPrivate:     caPrivate,
		devicePublic:  devicePrivate.Public().(ed25519.PublicKey),
		customRole:    role,
		customPurpose: purpose,
	}
}
