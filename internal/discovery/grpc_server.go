// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"context"
	"fmt"

	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// DiscoveryServer implements the sovereignite.v1.Discovery gRPC service.
type DiscoveryServer struct {
	pb.UnimplementedDiscoveryServer
	service *Service
}

// NewDiscoveryServer returns a gRPC server backed by the given discovery service.
func NewDiscoveryServer(svc *Service) *DiscoveryServer {
	return &DiscoveryServer{service: svc}
}

// StartBroadcast begins mDNS and BLE advertising. The request is intentionally
// empty; the service advertises its configured public identity.
func (s *DiscoveryServer) StartBroadcast(
	ctx context.Context,
	_ *pb.StartBroadcastRequest,
) (*emptypb.Empty, error) {
	if err := s.service.Start(ctx); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("start broadcast: %v", err))
	}
	return &emptypb.Empty{}, nil
}

// StopBroadcast removes both mDNS and BLE registrations.
func (s *DiscoveryServer) StopBroadcast(
	ctx context.Context,
	_ *emptypb.Empty,
) (*emptypb.Empty, error) {
	if err := s.service.Stop(ctx); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("stop broadcast: %v", err))
	}
	return &emptypb.Empty{}, nil
}

// ListDevices returns devices observed through active discovery.
func (s *DiscoveryServer) ListDevices(
	_ context.Context,
	_ *emptypb.Empty,
) (*pb.ListDevicesResponse, error) {
	s.service.stateMu.RLock()
	state := s.service.state
	record := s.service.config.Record
	s.service.stateMu.RUnlock()

	if state != StateRunning {
		return &pb.ListDevicesResponse{}, nil
	}

	adoptionState := pb.AdoptionState_ADOPTION_STATE_UNSPECIFIED
	switch record.AdoptionState {
	case AdoptionStateUnadopted:
		adoptionState = pb.AdoptionState_ADOPTION_STATE_UNADOPTED
	case AdoptionStateAdopted:
		adoptionState = pb.AdoptionState_ADOPTION_STATE_ADOPTED
	}

	return &pb.ListDevicesResponse{
		Devices: []*pb.DiscoveredDevice{
			{
				Identity: &pb.DeviceIdentity{
					PeerId: record.DeviceID,
				},
				AdoptionState: adoptionState,
			},
		},
	}, nil
}
