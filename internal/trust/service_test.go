// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"
)

func TestAdoptionRequiresMTLSAndInjectedAuthorization(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	remote, remotePrivate := testIdentity(t)
	_ = localPrivate
	var (
		mu          sync.Mutex
		policyCalls int
	)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		mu.Lock()
		policyCalls++
		mu.Unlock()
		grant := grantFor(intent, "authorized_grant_0001")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, publisher := newTestService(
		t,
		local,
		nil,
		policy,
		nil,
	)

	if _, err := service.AdoptDevice(
		context.Background(),
		tls.ConnectionState{},
		local.PeerID,
	); err == nil {
		t.Fatal("AdoptDevice accepted plaintext/server-auth-only input")
	}
	mu.Lock()
	if policyCalls != 0 {
		t.Fatalf("policy calls = %d before verified mTLS, want 0", policyCalls)
	}
	mu.Unlock()

	relationship, err := service.AdoptDevice(
		context.Background(),
		testTLSState(t, remote, remotePrivate),
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if relationship.Role != OwnershipRoleOwner ||
		relationship.Phase != RelationshipPhaseAuthorized ||
		relationship.PrincipalSPIFFEID != remote.SPIFFEID {
		t.Fatalf("relationship = %#v", relationship)
	}
	relationships, err := service.GetTrustRelationships()
	if err != nil {
		t.Fatal(err)
	}
	if len(relationships) != 1 || relationships[0].ID != relationship.ID {
		t.Fatalf("authorized relationships = %#v", relationships)
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Outbox) != 1 {
		t.Fatalf("outbox count = %d, want 1", len(snapshot.Outbox))
	}
	if err := service.DrainOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	publisher.mu.Lock()
	if len(publisher.publications) != 1 {
		t.Fatalf("publisher calls = %d, want 1", len(publisher.publications))
	}
	publisher.mu.Unlock()
}

func TestAdoptionSupportsExplicitProvisionalAuthorizationTransition(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	remote, remotePrivate := testIdentity(t)
	var (
		mu                 sync.Mutex
		provisionalID      string
		authorizationCalls int
	)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		mu.Lock()
		defer mu.Unlock()
		authorizationCalls++
		grant := grantFor(
			intent,
			[]string{"provisional_grant_01", "authorized_grant_0002"}[authorizationCalls-1],
		)
		grant.OwnershipRole = OwnershipRoleOwner
		if authorizationCalls == 1 {
			grant.RelationshipPhase = RelationshipPhaseProvisional
		} else {
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			grant.RelatedRelationship = provisionalID
		}
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, remote, remotePrivate)
	provisional, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	provisionalID = provisional.ID
	relationships, err := service.GetTrustRelationships()
	if err != nil {
		t.Fatal(err)
	}
	if len(relationships) != 0 {
		t.Fatal("provisional relationship leaked through authorized list")
	}
	authorized, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.ID != provisional.ID ||
		authorized.Phase != RelationshipPhaseAuthorized ||
		authorized.Generation != 2 {
		t.Fatalf("authorized transition = %#v", authorized)
	}
}

func TestRevocationIsLocalBeforePublisherSuccess(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	var relationshipID string
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "authorized_grant_0003")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationRevokeRelationship:
			if intent.RelationshipID != relationshipID {
				return AuthorizationGrant{}, errors.New("wrong relationship")
			}
			return grantFor(intent, "revocation_grant_0001"), nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	service, _, _, publisher := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, owner, ownerPrivate)
	relationship, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	relationshipID = relationship.ID
	publisher.err = errors.New("IPFS unavailable")
	if err := service.RevokeTrust(
		context.Background(),
		state,
		relationship.ID,
	); err != nil {
		t.Fatal(err)
	}
	relationships, err := service.GetTrustRelationships()
	if err != nil {
		t.Fatal(err)
	}
	if len(relationships) != 0 {
		t.Fatal("revoked relationship remains authorized")
	}
	if err := service.DrainOutbox(context.Background()); err == nil {
		t.Fatal("DrainOutbox succeeded while publisher was unavailable")
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Relationships[relationship.ID].Phase != RelationshipPhaseRevoked ||
		len(snapshot.Outbox) == 0 {
		t.Fatal("publication failure rolled back local revocation or outbox")
	}
}

func TestAuthorizationGrantReplayIsRejected(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	first, firstPrivate := testIdentity(t)
	second, secondPrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "replayed_grant_0001")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	if _, err := service.AdoptDevice(
		context.Background(),
		testTLSState(t, first, firstPrivate),
		local.PeerID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AdoptDevice(
		context.Background(),
		testTLSState(t, second, secondPrivate),
		local.PeerID,
	); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed adoption error = %v, want %v", err, ErrReplay)
	}
}

func TestLocalCAAndMTLSIssuanceUseOnlyKeyManagerBoundary(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	manager := newSoftwareKeyManager(t, localPrivate)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationInitializeCA:
			return grantFor(intent, "initialize_ca_grant_01"), nil
		case OperationIssueMTLSCertificate:
			return grantFor(intent, "issue_mtls_grant_0001"), nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	service, _, _, _ := newTestService(
		t,
		local,
		manager,
		policy,
		nil,
	)
	caDER, err := service.InitializeLocalCA(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || ca.Subject.CommonName != local.TrustDomain {
		t.Fatalf("local CA = %#v", ca)
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
		t.Fatal(err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != local.SPIFFEID {
		t.Fatalf("leaf URI SANs = %#v, want %q", leaf.URIs, local.SPIFFEID)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.requests) != 2 ||
		manager.requests[0].Profile != profileDeviceCA ||
		manager.requests[1].Profile != profileMTLSLeaf {
		t.Fatalf("key-manager requests = %#v", manager.requests)
	}
}

func TestFailedTPMIssuanceBurnsDurablyReservedSerial(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	manager := newSoftwareKeyManager(t, localPrivate)
	manager.issueErr = errors.New("TPM policy denied")
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		return grantFor(intent, "failed_issuance_grant1"), nil
	})
	service, _, builder, publisher := newTestService(
		t,
		local,
		manager,
		policy,
		nil,
	)
	if _, err := service.InitializeLocalCA(context.Background()); err == nil {
		t.Fatal("InitializeLocalCA succeeded after TPM failure")
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.NextSerial != 2 ||
		len(snapshot.PendingCertificates) != 0 ||
		len(snapshot.BurnedSerials) != 1 {
		t.Fatalf(
			"failed issuance state: next=%d pending=%d burned=%d",
			snapshot.NextSerial,
			len(snapshot.PendingCertificates),
			len(snapshot.BurnedSerials),
		)
	}
	if _, burned := snapshot.BurnedSerials["1"]; !burned {
		t.Fatal("failed issuance did not burn reserved serial 1")
	}
	if len(snapshot.Outbox) != 1 {
		t.Fatalf("failed issuance outbox count = %d, want 1", len(snapshot.Outbox))
	}
	builder.mu.Lock()
	views := append([]PublicStateView(nil), builder.views...)
	builder.mu.Unlock()
	if len(views) != 1 || len(views[0].Revocations) != 1 {
		t.Fatalf("failed issuance public views = %#v", views)
	}
	revocation := views[0].Revocations[0]
	if revocation.StatusID != uncertainRevocationID(local.TrustDomain, "1") ||
		revocation.CertificateID != "" ||
		revocation.Serial != "1" ||
		revocation.Kind != RevocationKindUncertain ||
		len(revocation.CertificateDER) != 0 {
		t.Fatalf("failed issuance public revocation = %#v", revocation)
	}
	statusPath, err := OCSPPath(revocation.StatusID)
	if err != nil {
		t.Fatal(err)
	}
	if !publicationContainsPath(snapshot.Outbox, statusPath) {
		t.Fatalf("failed issuance publication omitted %q", statusPath)
	}
	if err := service.DrainOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	publisher.mu.Lock()
	published := len(publisher.publications)
	publisher.mu.Unlock()
	if published != 1 {
		t.Fatalf("failed issuance publication attempts = %d, want 1", published)
	}
}

func TestOpenPublishesCrashRecoveredPendingSerialAsUncertain(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(localPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	pendingID := grantDigest("crash_recovery_01")
	snapshot := emptySnapshot()
	snapshot.Identity = local
	snapshot.Revision = 2
	snapshot.NextSerial = 2
	snapshot.PendingCertificates[pendingID] = PendingCertificate{
		ID:                  pendingID,
		GrantDigest:         pendingID,
		Operation:           OperationInitializeCA,
		SPIFFEID:            local.SPIFFEID,
		Serial:              "1",
		SubjectPublicKeyDER: publicKeyDER,
		NotBefore:           testNow.Add(-time.Minute),
		NotAfter:            testNow.Add(12 * time.Hour),
		CreatedAt:           testNow,
	}
	snapshot.AppliedGrants[pendingID] = AppliedGrant{
		Digest:    pendingID,
		Operation: OperationInitializeCA,
		AppliedAt: testNow,
	}
	if err := validateSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	store := newMemoryStore()
	store.snapshot = cloneSnapshot(snapshot)
	service, builder, _ := newTestServiceOnStore(
		t,
		local,
		store,
		nil,
		nil,
		nil,
	)
	recovered, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Revision != 3 ||
		len(recovered.PendingCertificates) != 0 ||
		len(recovered.BurnedSerials) != 1 ||
		len(recovered.Outbox) != 1 {
		t.Fatalf("crash-recovered state = %#v", recovered)
	}
	builder.mu.Lock()
	views := append([]PublicStateView(nil), builder.views...)
	builder.mu.Unlock()
	if len(views) != 1 || len(views[0].Revocations) != 1 {
		t.Fatalf("crash-recovery public views = %#v", views)
	}
	revocation := views[0].Revocations[0]
	if revocation.Serial != "1" ||
		revocation.Kind != RevocationKindUncertain ||
		revocation.StatusID != uncertainRevocationID(local.TrustDomain, "1") {
		t.Fatalf("crash-recovery public revocation = %#v", revocation)
	}
	statusPath, err := OCSPPath(revocation.StatusID)
	if err != nil {
		t.Fatal(err)
	}
	if !publicationContainsPath(recovered.Outbox, statusPath) {
		t.Fatalf("crash-recovery publication omitted %q", statusPath)
	}
}

func TestFederationCreatesOnlyExplicitDirectedHubSpokeEdge(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	generation := uint64(7)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "federation_owner_0001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "federation_ca_grant1"), nil
		case OperationFederate:
			grantID := "federation_edge_0001"
			if generation == 8 {
				grantID = "federation_edge_0002"
			}
			grant := grantFor(intent, grantID)
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
		if domain != remote.TrustDomain {
			return FederationMaterial{}, errors.New("wrong remote domain")
		}
		return FederationMaterial{
			RemoteCACertificateDER: remoteCA,
			SourceGeneration:       generation,
		}, nil
	})
	manager := newSoftwareKeyManager(t, localPrivate)
	service, _, builder, _ := newTestService(
		t,
		local,
		manager,
		policy,
		material,
	)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	edge, err := service.Federate(
		context.Background(),
		state,
		remote.TrustDomain,
	)
	if err != nil {
		t.Fatal(err)
	}
	if edge.SourceDomain != local.TrustDomain ||
		edge.TargetDomain != remote.TrustDomain ||
		edge.LocalRole != FederationRoleHub ||
		edge.RemoteRole != FederationRoleSpoke ||
		len(edge.CrossCertificate) == 0 {
		t.Fatalf("federation edge = %#v", edge)
	}
	edges, err := service.GetFederations()
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].TargetDomain != remote.TrustDomain {
		t.Fatalf("federation edges = %#v", edges)
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, reverse := snapshot.Federations[local.TrustDomain]; reverse {
		t.Fatal("federation inferred a reverse edge")
	}
	if len(snapshot.Bundles[remote.TrustDomain].CACertificates) != 1 {
		t.Fatal("remote trust bundle was merged or omitted")
	}
	generation = 8
	replacement, err := service.Federate(
		context.Background(),
		state,
		remote.TrustDomain,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.SourceGeneration != 8 ||
		replacement.CrossCertificateID == edge.CrossCertificateID ||
		replacement.CrossCertificateSerial == edge.CrossCertificateSerial {
		t.Fatalf("replacement federation edge = %#v", replacement)
	}
	snapshot, err = service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	retired, exists := snapshot.Revocations[edge.CrossCertificateID]
	if !exists ||
		retired.Serial != edge.CrossCertificateSerial ||
		retired.Kind != RevocationKindCross ||
		!bytes.Equal(retired.CertificateDER, edge.CrossCertificate) {
		t.Fatalf("retired cross-certificate revocation = %#v", retired)
	}
	if active := snapshot.Federations[remote.TrustDomain]; active.CrossCertificateID !=
		replacement.CrossCertificateID {
		t.Fatalf("active replacement federation edge = %#v", active)
	}
	if _, reverse := snapshot.Federations[local.TrustDomain]; reverse {
		t.Fatal("replacement federation inferred a reverse edge")
	}
	for _, grantID := range []string{
		"federation_edge_0001",
		"federation_edge_0002",
	} {
		applied := snapshot.AppliedGrants[grantDigest(grantID)]
		if applied.Operation != OperationFederate {
			t.Fatalf("federation applied grant %q = %#v", grantID, applied)
		}
	}
	builder.mu.Lock()
	views := append([]PublicStateView(nil), builder.views...)
	builder.mu.Unlock()
	if len(views) == 0 {
		t.Fatal("replacement federation produced no public view")
	}
	lastView := views[len(views)-1]
	foundRetired := false
	for _, revocation := range lastView.Revocations {
		if revocation.CertificateID == edge.CrossCertificateID &&
			revocation.Serial == edge.CrossCertificateSerial &&
			revocation.Kind == RevocationKindCross &&
			bytes.Equal(revocation.CertificateDER, edge.CrossCertificate) {
			foundRetired = true
			break
		}
	}
	if !foundRetired {
		t.Fatalf("replacement public revocations = %#v", lastView.Revocations)
	}
	statusPath, err := OCSPPath(edge.CrossCertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if !publicationContainsPath(snapshot.Outbox, statusPath) {
		t.Fatalf("replacement publication omitted %q", statusPath)
	}
}

func TestCommitConflictResyncsAcrossMultipleSharedStoreRevisions(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	firstOwner, firstOwnerPrivate := testIdentity(t)
	secondPrincipal, secondPrincipalPrivate := testIdentity(t)
	store := newMemoryStore()
	firstPolicy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "shared_store_owner1")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	secondPolicy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grantID := "stale_writer_grant1"
		role := OwnershipRoleOwner
		if intent.CurrentRevision > 1 {
			grantID = "retry_writer_grant1"
			role = OwnershipRoleBackupAdmin
		}
		grant := grantFor(intent, grantID)
		grant.OwnershipRole = role
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	first, _, _ := newTestServiceOnStore(
		t,
		local,
		store,
		nil,
		firstPolicy,
		nil,
	)
	second, _, _ := newTestServiceOnStore(
		t,
		local,
		store,
		nil,
		secondPolicy,
		nil,
	)
	if _, err := first.AdoptDevice(
		context.Background(),
		testTLSState(t, firstOwner, firstOwnerPrivate),
		local.PeerID,
	); err != nil {
		t.Fatal(err)
	}
	if err := first.DrainOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := second.AdoptDevice(
		context.Background(),
		testTLSState(t, secondPrincipal, secondPrincipalPrivate),
		local.PeerID,
	); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale shared-store adoption error = %v, want %v", err, ErrRevisionConflict)
	}
	resynced, err := second.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if resynced.Revision != 3 || len(resynced.Relationships) != 1 {
		t.Fatalf("resynced shared-store state = %#v", resynced)
	}
	relationship, err := second.AdoptDevice(
		context.Background(),
		testTLSState(t, secondPrincipal, secondPrincipalPrivate),
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if relationship.Role != OwnershipRoleBackupAdmin {
		t.Fatalf("retried shared-store relationship = %#v", relationship)
	}
	durable, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if durable.Revision != 4 || len(durable.Relationships) != 2 {
		t.Fatalf("durable shared-store state = %#v", durable)
	}
}

func TestBackupAdminRequiresAuthorizedOwner(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	admin, adminPrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "backup_admin_no_owner")
		grant.OwnershipRole = OwnershipRoleBackupAdmin
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, admin, adminPrivate)
	if _, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	); err == nil {
		t.Fatal("backup-admin adoption succeeded without an authorized owner")
	}
}

func TestBackupAdminAdoptionWithAuthorizedOwner(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	admin, adminPrivate := testIdentity(t)
	callCount := 0
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		callCount++
		var id string
		if callCount == 1 {
			id = "backup_admin_owner_init1"
		} else {
			id = "backup_admin_admin_add1"
		}
		grant := grantFor(intent, id)
		if callCount == 1 {
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
		} else {
			grant.OwnershipRole = OwnershipRoleBackupAdmin
			grant.RelationshipPhase = RelationshipPhaseAuthorized
		}
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	ownerState := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(
		context.Background(),
		ownerState,
		local.PeerID,
	); err != nil {
		t.Fatal(err)
	}
	adminState := testTLSState(t, admin, adminPrivate)
	adminRelationship, err := service.AdoptDevice(
		context.Background(),
		adminState,
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if adminRelationship.Role != OwnershipRoleBackupAdmin ||
		adminRelationship.Phase != RelationshipPhaseAuthorized {
		t.Fatalf("backup-admin relationship = %#v", adminRelationship)
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Relationships) != 2 {
		t.Fatalf("relationships = %d, want 2", len(snapshot.Relationships))
	}
}

func TestRevokedRelationshipCannotAuthorizeOperations(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	var relationshipID string
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "revoke_then_use_adopt")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationRevokeRelationship:
			grant := grantFor(intent, "revoke_then_use_revoke")
			return grant, nil
		case OperationRevokeCertificate:
			return AuthorizationGrant{}, errors.New("no active certificate")
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, owner, ownerPrivate)
	relationship, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	relationshipID = relationship.ID
	if err := service.RevokeTrust(
		context.Background(),
		state,
		relationshipID,
	); err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	revoked := snapshot.Relationships[relationshipID]
	if revoked.Phase != RelationshipPhaseRevoked {
		t.Fatalf("relationship phase = %q, want revoked", revoked.Phase)
	}
	if _, err := requireAuthorizedPrincipal(snapshot, VerifiedMTLSPeer{}, true); err == nil {
		t.Fatal("requireAuthorizedPrincipal succeeded with no authorized peer")
	}
}

func TestAdoptDeviceRejectsUnknownTargetPeer(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	remote, remotePrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "unknown_target_grant1")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, remote, remotePrivate)
	if _, err := service.AdoptDevice(
		context.Background(),
		state,
		"12D3KooWNonExistentPeerIDThatDoesNotMatch",
	); err == nil {
		t.Fatal("AdoptDevice accepted unknown target peer ID")
	}
}

func TestStaleGenerationRejection(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "stale_generation_grant1")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		grant.ExpectedRevision = intent.CurrentRevision + 5
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale generation adoption error = %v, want %v", err, ErrStaleGeneration)
	}
}

func TestAdoptDeviceRejectsReplayedAdoptionRequest(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	remote, remotePrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "replay_adopt_00001")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, remote, remotePrivate)
	if _, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed adoption error = %v, want %v", err, ErrReplay)
	}
}

func TestConcurrentAdoptionConflictsAreDetected(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	first, firstPrivate := testIdentity(t)
	second, secondPrivate := testIdentity(t)
	store := newMemoryStore()
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "concurrent_adopt_grant")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	firstService, _, _ := newTestServiceOnStore(
		t, local, store, nil, policy, nil,
	)
	secondService, _, _ := newTestServiceOnStore(
		t, local, store, nil, policy, nil,
	)
	var wg sync.WaitGroup
	wg.Add(2)
	var firstErr, secondErr error
	go func() {
		defer wg.Done()
		_, firstErr = firstService.AdoptDevice(
			context.Background(),
			testTLSState(t, first, firstPrivate),
			local.PeerID,
		)
	}()
	go func() {
		defer wg.Done()
		_, secondErr = secondService.AdoptDevice(
			context.Background(),
			testTLSState(t, second, secondPrivate),
			local.PeerID,
		)
	}()
	wg.Wait()
	conflicts := 0
	if firstErr != nil && errors.Is(firstErr, ErrRevisionConflict) {
		conflicts++
	}
	if secondErr != nil && errors.Is(secondErr, ErrRevisionConflict) {
		conflicts++
	}
	if firstErr == nil && secondErr == nil {
		t.Fatal("concurrent adoptions both succeeded without conflict")
	}
	if conflicts == 0 {
		t.Fatalf(
			"expected at least one revision conflict, got first=%v second=%v",
			firstErr,
			secondErr,
		)
	}
}

func TestSnapshotVersionAndRevisionAreConsistent(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "version_revision_consistency")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, owner, ownerPrivate)
	if _, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	); err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != StateVersion {
		t.Fatalf("version = %d, want %d", snapshot.Version, StateVersion)
	}
	if snapshot.Revision < 2 {
		t.Fatalf("revision = %d, want >= 2 after adoption", snapshot.Revision)
	}
	if snapshot.NextSerial == 0 {
		t.Fatal("next serial must be positive")
	}
}

func TestGetTrustRelationshipsReturnsOnlyAuthorized(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	provisional, provisionalPrivate := testIdentity(t)
	var provisionalRelID string
	callCount := 0
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		callCount++
		switch {
		case intent.Operation == OperationAdopt && callCount == 1:
			grant := grantFor(intent, "get_auth_provisional_1")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseProvisional
			return grant, nil
		case intent.Operation == OperationAdopt && callCount == 2:
			grant := grantFor(intent, "get_auth_authorize_prov1")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			grant.RelatedRelationship = provisionalRelID
			return grant, nil
		case intent.Operation == OperationAdopt:
			grant := grantFor(intent, "get_auth_second_own_3")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	provisionalRel, err := service.AdoptDevice(
		context.Background(),
		testTLSState(t, provisional, provisionalPrivate),
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	provisionalRelID = provisionalRel.ID
	relationships, err := service.GetTrustRelationships()
	if err != nil {
		t.Fatal(err)
	}
	if len(relationships) != 0 {
		t.Fatalf("authorized relationships with provisional = %d, want 0", len(relationships))
	}
	_, err = service.AdoptDevice(
		context.Background(),
		testTLSState(t, provisional, provisionalPrivate),
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	relationships, err = service.GetTrustRelationships()
	if err != nil {
		t.Fatal(err)
	}
	if len(relationships) != 1 {
		t.Fatalf("authorized relationships after transition = %d, want 1", len(relationships))
	}
	if relationships[0].Phase != RelationshipPhaseAuthorized {
		t.Fatalf("relationship phase = %s, want authorized", relationships[0].Phase)
	}
}

func TestDrainOutboxWithEmptyOutboxIsNoOp(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	service, _, _, _ := newTestService(t, local, nil, nil, nil)
	if err := service.DrainOutbox(context.Background()); err != nil {
		t.Fatalf("DrainOutbox on empty outbox: %v", err)
	}
}

func TestFederateRejectsSelfEdge(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "federation_self_edge1")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	state := testTLSState(t, local, localPrivate)
	if _, err := service.Federate(
		context.Background(),
		state,
		local.TrustDomain,
	); err == nil {
		t.Fatal("federation accepted self-edge")
	}
}

func TestFederateRejectsStaleGeneration(t *testing.T) {
	t.Parallel()

	local, localPrivate := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	remote, _ := testIdentity(t)
	remoteCA := testCertificateAuthority(t, remote.TrustDomain)
	generation := uint64(5)
	callCount := 0
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "stale_fed_owner_001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "stale_fed_ca_grant1"), nil
		case OperationFederate:
			callCount++
			var id string
			if callCount == 1 {
				id = "stale_fed_edge_first01"
			} else {
				id = "stale_fed_edge_retry1"
			}
			grant := grantFor(intent, id)
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
	if _, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitializeLocalCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Federate(
		context.Background(),
		state,
		remote.TrustDomain,
	); err != nil {
		t.Fatal(err)
	}
	generation = 3
	if _, err := service.Federate(
		context.Background(),
		state,
		remote.TrustDomain,
	); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale federation generation error = %v, want %v", err, ErrStaleGeneration)
	}
}

func TestConcurrentRevokeAndAdoptConflict(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	admin, adminPrivate := testIdentity(t)
	store := newMemoryStore()
	callCount := 0
	var mu sync.Mutex
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		mu.Lock()
		callCount++
		count := callCount
		mu.Unlock()
		switch {
		case intent.Operation == OperationAdopt && count <= 1:
			grant := grantFor(intent, "concurrent_adopt_init")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case intent.Operation == OperationRevokeRelationship:
			grant := grantFor(intent, "concurrent_revoke_01")
			return grant, nil
		case intent.Operation == OperationAdopt:
			grant := grantFor(intent, "concurrent_adopt_retry")
			grant.OwnershipRole = OwnershipRoleBackupAdmin
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	service, _, _ := newTestServiceOnStore(t, local, store, nil, policy, nil)
	ownerState := testTLSState(t, owner, ownerPrivate)
	relationship, err := service.AdoptDevice(
		context.Background(),
		ownerState,
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = relationship
	if err := service.DrainOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	adminService, _, _ := newTestServiceOnStore(t, local, store, nil, policy, nil)
	adminState := testTLSState(t, admin, adminPrivate)
	_, err = adminService.AdoptDevice(
		context.Background(),
		adminState,
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsMismatchedIdentity(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	other, _ := testIdentity(t)
	store := newMemoryStore()
	store.snapshot = emptySnapshot()
	store.snapshot.Identity = other
	store.snapshot.Revision = 1
	var service *Service
	config := ServiceConfig{
		Identity:                   local,
		Store:                      store,
		Policy:                     AuthorizationPolicyFunc(nil),
		Clock:                      fixedClock{now: testNow},
		MaximumGrantLifetime:       time.Hour,
		MaximumCertificateLifetime: 24 * time.Hour,
	}
	var err error
	service, err = NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Open(context.Background()); err == nil {
		t.Fatal("Open accepted mismatched identity")
	}
}

func publicationContainsPath(
	outbox map[string]Publication,
	path string,
) bool {
	for _, publication := range outbox {
		for _, document := range publication.Documents {
			if document.Path() == path {
				return true
			}
		}
	}
	return false
}

func testCertificateAuthority(t *testing.T, commonName string) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(77),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	encoded, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		public,
		private,
	)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
