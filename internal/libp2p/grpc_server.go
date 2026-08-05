// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	"encoding/base64"
	"fmt"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// IdentityServer implements the generated gRPC Identity service, bridging
// the local libp2p identity service to external RPC callers.
type IdentityServer struct {
	pb.UnimplementedIdentityServer
	service *Service
}

// NewIdentityServer returns a gRPC server backed by the given service.
func NewIdentityServer(svc *Service) *IdentityServer {
	return &IdentityServer{service: svc}
}

// GetIdentity returns the device identity for this peer.
func (s *IdentityServer) GetIdentity(
	ctx context.Context,
	_ *emptypb.Empty,
) (*pb.IdentityResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.Unavailable, "identity service is not initialized")
	}
	identity := s.service.Identity()
	if identity == nil {
		return nil, status.Error(codes.Unavailable, "identity is not available")
	}
	pubkeyBytes, err := libp2pcrypto.MarshalPublicKey(identity.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal public key: %v", err)
	}
	return &pb.IdentityResponse{
		Identity: &pb.DeviceIdentity{
			PeerId: identity.PeerID.String(),
			PublicKeys: []*pb.PublicKey{
				{
					Type:            mapKeyType(identity.PublicKey.Type()),
					PublicRawBase64: base64.StdEncoding.EncodeToString(pubkeyBytes),
					TpmHandle:       fmt.Sprintf("0x%08x", identity.TPMHandle),
				},
			},
			Phase: pb.IdentityPhase_IDENTITY_PHASE_ACTIVE,
		},
	}, nil
}

// GetTrustDomain returns the canonical IPNS trust domain for this peer.
func (s *IdentityServer) GetTrustDomain(
	ctx context.Context,
	_ *emptypb.Empty,
) (*pb.TrustDomainResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.Unavailable, "identity service is not initialized")
	}
	identity := s.service.Identity()
	if identity == nil {
		return nil, status.Error(codes.Unavailable, "identity is not available")
	}
	return &pb.TrustDomainResponse{
		TrustDomain: identity.Name,
	}, nil
}

func mapKeyType(kt cryptopb.KeyType) pb.PublicKeyType {
	switch kt {
	case cryptopb.KeyType_RSA:
		return pb.PublicKeyType_PUBLIC_KEY_TYPE_RSA
	case cryptopb.KeyType_Ed25519:
		return pb.PublicKeyType_PUBLIC_KEY_TYPE_ED25519
	case cryptopb.KeyType_ECDSA:
		return pb.PublicKeyType_PUBLIC_KEY_TYPE_ECDSA
	case cryptopb.KeyType_Secp256k1:
		return pb.PublicKeyType_PUBLIC_KEY_TYPE_SECP256K1
	default:
		return pb.PublicKeyType_PUBLIC_KEY_TYPE_UNSPECIFIED
	}
}
