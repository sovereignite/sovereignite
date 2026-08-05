// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"
)

func TestGRPCAdoptDeviceSuccess(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	remote, remotePrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "grpc_adopt_success_01")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	server := NewTrustServer(service)
	state := testTLSState(t, remote, remotePrivate)
	ctx := peerContextWithTLS(state)
	resp, err := server.AdoptDevice(ctx, &pb.AdoptDeviceRequest{
		PeerId: local.PeerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.State != pb.AdoptionState_ADOPTION_STATE_ADOPTED {
		t.Fatalf("adoption state = %v, want ADOPTED", resp.State)
	}
	if resp.Relationship == nil {
		t.Fatal("adoption response missing relationship")
	}
}

func TestGRPCAdoptDeviceRejectsNilRequest(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	service, _, _, _ := newTestService(t, local, nil, nil, nil)
	server := NewTrustServer(service)
	_, err := server.AdoptDevice(context.Background(), nil)
	if err == nil {
		t.Fatal("AdoptDevice accepted nil request")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument", code)
	}
}

func TestGRPCAdoptDeviceRejectsMissingPeerID(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	service, _, _, _ := newTestService(t, local, nil, nil, nil)
	server := NewTrustServer(service)
	_, err := server.AdoptDevice(context.Background(), &pb.AdoptDeviceRequest{
		PeerId: "",
	})
	if err == nil {
		t.Fatal("AdoptDevice accepted empty peer_id")
	}
}

func TestGRPCAdoptDeviceRejectsPlaintext(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "grpc_adopt_plaintext1")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	server := NewTrustServer(service)
	_, err := server.AdoptDevice(
		context.Background(),
		&pb.AdoptDeviceRequest{PeerId: local.PeerID},
	)
	if err == nil {
		t.Fatal("AdoptDevice accepted plaintext context")
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Fatalf("error code = %v, want Unauthenticated", code)
	}
}

func TestGRPCGetTrustRelationshipsSuccess(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	remote, remotePrivate := testIdentity(t)
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		grant := grantFor(intent, "grpc_get_rels_0001")
		grant.OwnershipRole = OwnershipRoleOwner
		grant.RelationshipPhase = RelationshipPhaseAuthorized
		return grant, nil
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	server := NewTrustServer(service)
	_, err := service.AdoptDevice(
		context.Background(),
		testTLSState(t, remote, remotePrivate),
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.GetTrustRelationships(
		context.Background(),
		&emptypb.Empty{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Relationships) != 1 {
		t.Fatalf("relationships = %d, want 1", len(resp.Relationships))
	}
}

func TestGRPCGetTrustRelationshipsEmpty(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	service, _, _, _ := newTestService(t, local, nil, nil, nil)
	server := NewTrustServer(service)
	resp, err := server.GetTrustRelationships(
		context.Background(),
		&emptypb.Empty{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Relationships) != 0 {
		t.Fatalf("relationships = %d, want 0", len(resp.Relationships))
	}
}

func TestGRPCRevokeTrustSuccess(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	owner, ownerPrivate := testIdentity(t)
	var relID string
	policy := AuthorizationPolicyFunc(func(
		_ context.Context,
		intent AuthorizationIntent,
	) (AuthorizationGrant, error) {
		switch intent.Operation {
		case OperationAdopt:
			grant := grantFor(intent, "grpc_revoke_adopt1")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationRevokeRelationship:
			return grantFor(intent, "grpc_revoke_grant1"), nil
		default:
			return AuthorizationGrant{}, errors.New("unexpected operation")
		}
	})
	service, _, _, _ := newTestService(t, local, nil, policy, nil)
	server := NewTrustServer(service)
	state := testTLSState(t, owner, ownerPrivate)
	rel, err := service.AdoptDevice(
		context.Background(),
		state,
		local.PeerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	relID = rel.ID
	ctx := peerContextWithTLS(state)
	_, err = server.RevokeTrust(ctx, &pb.RevokeTrustRequest{
		RelationshipId: relID,
	})
	if err != nil {
		t.Fatal(err)
	}
	relationships, err := service.GetTrustRelationships()
	if err != nil {
		t.Fatal(err)
	}
	if len(relationships) != 0 {
		t.Fatalf("authorized relationships after revoke = %d, want 0", len(relationships))
	}
}

func TestGRPCRevokeTrustRejectsNilRequest(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	service, _, _, _ := newTestService(t, local, nil, nil, nil)
	server := NewTrustServer(service)
	_, err := server.RevokeTrust(context.Background(), nil)
	if err == nil {
		t.Fatal("RevokeTrust accepted nil request")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument", code)
	}
}

func TestGRPCRevokeTrustRejectsEmptyRelationshipID(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	service, _, _, _ := newTestService(t, local, nil, nil, nil)
	server := NewTrustServer(service)
	_, err := server.RevokeTrust(context.Background(), &pb.RevokeTrustRequest{
		RelationshipId: "",
	})
	if err == nil {
		t.Fatal("RevokeTrust accepted empty relationship_id")
	}
}

func TestGRPCFederateSuccess(t *testing.T) {
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
			grant := grantFor(intent, "grpc_fed_adopt_001")
			grant.OwnershipRole = OwnershipRoleOwner
			grant.RelationshipPhase = RelationshipPhaseAuthorized
			return grant, nil
		case OperationInitializeCA:
			return grantFor(intent, "grpc_fed_ca_00001"), nil
		case OperationFederate:
			grant := grantFor(intent, "grpc_fed_edge_001")
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
	server := NewTrustServer(service)
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
	ctx := peerContextWithTLS(state)
	resp, err := server.Federate(ctx, &pb.FederateRequest{
		RemoteTrustDomain: remote.TrustDomain,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Federation == nil {
		t.Fatal("federate response missing federation")
	}
}

func TestGRPCFederateRejectsNilRequest(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	service, _, _, _ := newTestService(t, local, nil, nil, nil)
	server := NewTrustServer(service)
	_, err := server.Federate(context.Background(), nil)
	if err == nil {
		t.Fatal("Federate accepted nil request")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument", code)
	}
}

func TestGRPCFederateRejectsEmptyDomain(t *testing.T) {
	t.Parallel()

	local, _ := testIdentity(t)
	service, _, _, _ := newTestService(t, local, nil, nil, nil)
	server := NewTrustServer(service)
	_, err := server.Federate(context.Background(), &pb.FederateRequest{
		RemoteTrustDomain: "",
	})
	if err == nil {
		t.Fatal("Federate accepted empty domain")
	}
}

func TestGRPCTranslateErrorMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{"nil", nil, codes.OK},
		{"not_authorized", ErrNotAuthorized, codes.PermissionDenied},
		{"auth_unavailable", ErrAuthorizationUnavailable, codes.PermissionDenied},
		{"revision_conflict", ErrRevisionConflict, codes.Aborted},
		{"replay", ErrReplay, codes.AlreadyExists},
		{"stale_generation", ErrStaleGeneration, codes.FailedPrecondition},
		{"pub_unavailable", ErrPublicationUnavailable, codes.Unavailable},
		{"schema_unavailable", ErrPublicationSchemaUnavailable, codes.Unavailable},
		{"unknown", errors.New("something"), codes.Internal},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := translateError(test.err)
			if test.wantCode == codes.OK {
				if result != nil {
					t.Fatalf("translateError(%v) = %v, want nil", test.err, result)
				}
				return
			}
			if result == nil {
				t.Fatalf("translateError(%v) = nil, want %v", test.err, test.wantCode)
			}
			if code := status.Code(result); code != test.wantCode {
				t.Fatalf("translateError(%v) code = %v, want %v", test.err, code, test.wantCode)
			}
		})
	}
}

func peerContextWithTLS(state tls.ConnectionState) context.Context {
	return peer.NewContext(
		context.Background(),
		&peer.Peer{
			AuthInfo: credentials.TLSInfo{State: state},
		},
	)
}
