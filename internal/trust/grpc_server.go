// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package trust

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"
)

// TrustServer implements the sovereignite.v1.Trust gRPC service by delegating
// to the trust domain Service. Every mutating RPC extracts the mTLS peer from
// the gRPC transport credentials and forwards it to the domain layer.
type TrustServer struct {
	pb.UnimplementedTrustServer
	service *Service
}

// NewTrustServer wraps a pre-configured trust Service for gRPC exposure.
func NewTrustServer(svc *Service) *TrustServer {
	return &TrustServer{service: svc}
}

// AdoptDevice accepts an mTLS-authenticated adoption request and creates or
// transitions a trust relationship.
func (s *TrustServer) AdoptDevice(
	ctx context.Context,
	req *pb.AdoptDeviceRequest,
) (*pb.AdoptDeviceResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	peerID := req.GetPeerId()
	if peerID == "" {
		return nil, status.Error(codes.InvalidArgument, "peer_id is required")
	}
	state, err := tlsConnectionState(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	record, err := s.service.AdoptDevice(ctx, state, peerID)
	if err != nil {
		return nil, translateError(err)
	}
	return &pb.AdoptDeviceResponse{
		State:        pb.AdoptionState_ADOPTION_STATE_ADOPTED,
		Relationship: relationshipToProto(record, s.service.config.Identity.TrustDomain),
	}, nil
}

// GetTrustRelationships returns every currently authorized relationship and
// federation edge.
func (s *TrustServer) GetTrustRelationships(
	ctx context.Context,
	_ *emptypb.Empty,
) (*pb.TrustRelationshipsResponse, error) {
	relationships, err := s.service.GetTrustRelationships()
	if err != nil {
		return nil, translateError(err)
	}
	federations, err := s.service.GetFederations()
	if err != nil {
		return nil, translateError(err)
	}
	protoRelationships := make([]*pb.TrustRelationship, 0, len(relationships))
	for _, r := range relationships {
		protoRelationships = append(
			protoRelationships,
			relationshipToProto(r, s.service.config.Identity.TrustDomain),
		)
	}
	protoFederations := make([]*pb.Federation, 0, len(federations))
	for _, f := range federations {
		protoFederations = append(protoFederations, federationToProto(f))
	}
	return &pb.TrustRelationshipsResponse{
		Relationships: protoRelationships,
		Federations:   protoFederations,
	}, nil
}

// RevokeTrust atomically revokes one relationship and every certificate bound
// to it.
func (s *TrustServer) RevokeTrust(
	ctx context.Context,
	req *pb.RevokeTrustRequest,
) (*emptypb.Empty, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	relationshipID := req.GetRelationshipId()
	if relationshipID == "" {
		return nil, status.Error(codes.InvalidArgument, "relationship_id is required")
	}
	state, err := tlsConnectionState(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.service.RevokeTrust(ctx, state, relationshipID); err != nil {
		return nil, translateError(err)
	}
	return &emptypb.Empty{}, nil
}

// Federate creates one directed local-to-remote hub/spoke federation edge.
func (s *TrustServer) Federate(
	ctx context.Context,
	req *pb.FederateRequest,
) (*pb.FederateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	remoteTrustDomain := req.GetRemoteTrustDomain()
	if remoteTrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "remote_trust_domain is required")
	}
	state, err := tlsConnectionState(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	record, err := s.service.Federate(ctx, state, remoteTrustDomain)
	if err != nil {
		return nil, translateError(err)
	}
	return &pb.FederateResponse{
		Federation: federationToProto(record),
	}, nil
}

// tlsConnectionState extracts the verified mTLS connection state from the
// gRPC peer credentials. The transport layer must have been configured with
// TLS client certificate verification.
func tlsConnectionState(ctx context.Context) (tls.ConnectionState, error) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok {
		return tls.ConnectionState{}, errors.New("peer information is unavailable")
	}
	tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return tls.ConnectionState{}, errors.New("mTLS transport credentials are required")
	}
	state := tlsInfo.State
	if !state.HandshakeComplete {
		return tls.ConnectionState{}, errors.New("mTLS handshake is incomplete")
	}
	if len(state.PeerCertificates) == 0 {
		return tls.ConnectionState{}, errors.New("mTLS client certificate is required")
	}
	return state, nil
}

func relationshipToProto(
	record RelationshipRecord,
	trustDomain string,
) *pb.TrustRelationship {
	return &pb.TrustRelationship{
		RelationshipId: record.ID,
		PeerId:         record.TargetPeerID,
		SpiffeId:       record.PrincipalSPIFFEID,
		TrustDomain:    trustDomain,
		EstablishedAt:  timeToProto(record.EstablishedAt),
	}
}

func federationToProto(record FederationRecord) *pb.Federation {
	return &pb.Federation{
		RemoteTrustDomain: record.TargetDomain,
		EstablishedAt:     timeToProto(record.EstablishedAt),
	}
}

func timeToProto(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// translateError maps domain errors to canonical gRPC status codes. The
// mapping is intentionally conservative: every unmapped error becomes
// Internal to avoid leaking implementation details.
func translateError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotAuthorized),
		errors.Is(err, ErrAuthorizationUnavailable):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, ErrRevisionConflict):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, ErrReplay):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ErrStaleGeneration):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrPublicationUnavailable),
		errors.Is(err, ErrPublicationSchemaUnavailable):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Error(codes.Internal, fmt.Sprintf("trust: %v", err))
	}
}
