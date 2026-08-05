// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package bootstrap

import (
	"context"
	"errors"

	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server exposes only the two operations on the committed Bootstrap service.
type Server struct {
	pb.UnimplementedBootstrapServer
	coordinator *Coordinator
}

// NewServer binds the Bootstrap domain service.
func NewServer(coordinator *Coordinator) (*Server, error) {
	if coordinator == nil {
		return nil, errors.New("bootstrap coordinator is required")
	}
	return &Server{coordinator: coordinator}, nil
}

// GetStatus implements the committed Bootstrap.GetStatus domain operation.
func (s *Server) GetStatus(
	ctx context.Context,
	_ *emptypb.Empty,
) (*pb.BootstrapStatus, error) {
	if s == nil || s.coordinator == nil {
		return nil, errors.New("bootstrap server is not configured")
	}
	status, err := s.coordinator.GetStatus(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.BootstrapStatus{
		State:       domainStateToProto(status.State),
		CurrentStep: string(status.CurrentStep),
		Message:     status.Message,
		UpdatedAt:   timestamppb.New(status.UpdatedAt),
	}, nil
}

// StartBootstrap implements the committed parameterless
// Bootstrap.StartBootstrap domain operation.
func (s *Server) StartBootstrap(
	ctx context.Context,
	_ *pb.StartBootstrapRequest,
) (*emptypb.Empty, error) {
	if s == nil || s.coordinator == nil {
		return nil, errors.New("bootstrap server is not configured")
	}
	if err := s.coordinator.StartBootstrap(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// RegisterGrpcServer registers the Bootstrap service on the supplied gRPC
// server.
func (s *Server) RegisterGrpcServer(grpcServer *grpc.Server) {
	pb.RegisterBootstrapServer(grpcServer, s)
}

func domainStateToProto(state StatusState) pb.BootstrapState {
	switch state {
	case StatusNotStarted:
		return pb.BootstrapState_BOOTSTRAP_STATE_NOT_STARTED
	case StatusInProgress:
		return pb.BootstrapState_BOOTSTRAP_STATE_IN_PROGRESS
	case StatusComplete:
		return pb.BootstrapState_BOOTSTRAP_STATE_COMPLETE
	case StatusFailed:
		return pb.BootstrapState_BOOTSTRAP_STATE_FAILED
	default:
		return pb.BootstrapState_BOOTSTRAP_STATE_UNSPECIFIED
	}
}
