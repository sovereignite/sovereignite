// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"context"
	"errors"
	"testing"

	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestDiscoveryServerListDevicesReturnsDeviceData(t *testing.T) {
	t.Parallel()

	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: &fakeRegistration{}},
		&fakeBLEBroadcaster{handle: &fakeRegistration{}},
		&fakeAdoptionHandler{},
	)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	server := NewDiscoveryServer(service)
	resp, err := server.ListDevices(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("device count = %d, want 1", len(resp.Devices))
	}
	device := resp.Devices[0]
	if device.Identity.PeerId != "node-7" {
		t.Fatalf("peer ID = %q, want node-7", device.Identity.PeerId)
	}
	if device.AdoptionState != pb.AdoptionState_ADOPTION_STATE_UNADOPTED {
		t.Fatalf(
			"adoption state = %v, want ADOPTION_STATE_UNADOPTED",
			device.AdoptionState,
		)
	}
}

func TestDiscoveryServerListDevicesReturnsEmptyWhenStopped(t *testing.T) {
	t.Parallel()

	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: &fakeRegistration{}},
		&fakeBLEBroadcaster{handle: &fakeRegistration{}},
		&fakeAdoptionHandler{},
	)

	server := NewDiscoveryServer(service)
	resp, err := server.ListDevices(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Devices) != 0 {
		t.Fatalf("device count = %d, want 0 when stopped", len(resp.Devices))
	}
}

func TestDiscoveryServerListDevicesAdoptionStateMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		adoptionState    AdoptionState
		wantAdoptionState pb.AdoptionState
	}{
		{
			name:             "unadopted",
			adoptionState:    AdoptionStateUnadopted,
			wantAdoptionState: pb.AdoptionState_ADOPTION_STATE_UNADOPTED,
		},
		{
			name:             "adopted",
			adoptionState:    AdoptionStateAdopted,
			wantAdoptionState: pb.AdoptionState_ADOPTION_STATE_ADOPTED,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := ServiceConfig{
				Record: Record{
					DeviceID:      "test-device",
					TrustDomain:   "mesh.example",
					AdoptionState: test.adoptionState,
				},
				ServicePort:          8443,
				BluetoothServiceUUID: testBluetoothServiceUUID,
			}
			service, err := NewService(
				config,
				&fakeMDNSBroadcaster{handle: &fakeRegistration{}},
				&fakeBLEBroadcaster{handle: &fakeRegistration{}},
				&fakeAdoptionHandler{},
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := service.Start(context.Background()); err != nil {
				t.Fatal(err)
			}

			server := NewDiscoveryServer(service)
			resp, err := server.ListDevices(context.Background(), &emptypb.Empty{})
			if err != nil {
				t.Fatal(err)
			}
			if len(resp.Devices) != 1 {
				t.Fatalf("device count = %d, want 1", len(resp.Devices))
			}
			if resp.Devices[0].AdoptionState != test.wantAdoptionState {
				t.Fatalf(
					"adoption state = %v, want %v",
					resp.Devices[0].AdoptionState,
					test.wantAdoptionState,
				)
			}
		})
	}
}

func TestDiscoveryServerStartBroadcastDelegatesToService(t *testing.T) {
	t.Parallel()

	mdns := &fakeMDNSBroadcaster{handle: &fakeRegistration{}}
	ble := &fakeBLEBroadcaster{handle: &fakeRegistration{}}
	service := newTestService(t, mdns, ble, &fakeAdoptionHandler{})
	server := NewDiscoveryServer(service)

	_, err := server.StartBroadcast(context.Background(), &pb.StartBroadcastRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if service.State() != StateRunning {
		t.Fatalf("state after StartBroadcast = %s, want running", service.State())
	}
	if mdns.startCalls != 1 {
		t.Fatalf("mDNS start calls = %d, want 1", mdns.startCalls)
	}
	if ble.startCalls != 1 {
		t.Fatalf("BLE start calls = %d, want 1", ble.startCalls)
	}

	if err := service.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryServerStartBroadcastPropagatesErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("mDNS unavailable")
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{startErr: wantErr},
		&fakeBLEBroadcaster{handle: &fakeRegistration{}},
		&fakeAdoptionHandler{},
	)
	server := NewDiscoveryServer(service)

	_, err := server.StartBroadcast(context.Background(), &pb.StartBroadcastRequest{})
	if err == nil {
		t.Fatal("StartBroadcast() succeeded, want error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.Internal {
		t.Fatalf("gRPC code = %v, want Internal", st.Code())
	}
	if service.State() != StateStopped {
		t.Fatalf("state after failed StartBroadcast = %s, want stopped", service.State())
	}
}

func TestDiscoveryServerStopBroadcastDelegatesToService(t *testing.T) {
	t.Parallel()

	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: &fakeRegistration{}},
		&fakeBLEBroadcaster{handle: &fakeRegistration{}},
		&fakeAdoptionHandler{},
	)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := NewDiscoveryServer(service)

	_, err := server.StopBroadcast(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if service.State() != StateStopped {
		t.Fatalf("state after StopBroadcast = %s, want stopped", service.State())
	}
}

func TestDiscoveryServerStopBroadcastPropagatesErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("mDNS unregister failed")
	bleErr := errors.New("BLE unregister failed")
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: &fakeRegistration{stopErr: wantErr}},
		&fakeBLEBroadcaster{handle: &fakeRegistration{stopErr: bleErr}},
		&fakeAdoptionHandler{},
	)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := NewDiscoveryServer(service)

	_, err := server.StopBroadcast(context.Background(), &emptypb.Empty{})
	if err == nil {
		t.Fatal("StopBroadcast() succeeded, want error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.Internal {
		t.Fatalf("gRPC code = %v, want Internal", st.Code())
	}
	if service.State() != StateStopped {
		t.Fatalf("state after StopBroadcast errors = %s, want stopped", service.State())
	}
}

func TestDiscoveryServerListDevicesDoesNotMutateTrust(t *testing.T) {
	t.Parallel()

	config := ServiceConfig{
		Record: Record{
			DeviceID:      "test-device",
			TrustDomain:   "mesh.example",
			AdoptionState: AdoptionStateUnadopted,
		},
		ServicePort:          8443,
		BluetoothServiceUUID: testBluetoothServiceUUID,
	}
	service, err := NewService(
		config,
		&fakeMDNSBroadcaster{handle: &fakeRegistration{}},
		&fakeBLEBroadcaster{handle: &fakeRegistration{}},
		&fakeAdoptionHandler{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	server := NewDiscoveryServer(service)
	resp, err := server.ListDevices(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}

	originalState := service.config.Record.AdoptionState
	_ = resp

	if service.config.Record.AdoptionState != originalState {
		t.Fatalf(
			"ListDevices mutated adoption state from %q to %q",
			originalState,
			service.config.Record.AdoptionState,
		)
	}

	if err := service.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
