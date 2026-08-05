// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package keyvalidation

import (
	"context"
	"errors"

	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"
)

// Service implements the KeyValidation gRPC service.
type Service struct {
	pb.UnimplementedKeyValidationServer
}

// NewService returns a fail-closed KeyValidation service.
func NewService() *Service { return &Service{} }

// ValidateKey denies all validation while D-007 remains unresolved (fail-closed).
func (s *Service) ValidateKey(_ context.Context, _ *pb.ValidateKeyRequest) (*pb.ValidateKeyResponse, error) {
	return &pb.ValidateKeyResponse{Valid: false}, nil
}

// IssueJWT refuses all token issuance while D-007 remains unresolved (fail-closed).
func (s *Service) IssueJWT(_ context.Context, _ *pb.IssueJWTRequest) (*pb.IssueJWTResponse, error) {
	return nil, errors.New("IssueJWT not authorized: D-007 unresolved")
}
