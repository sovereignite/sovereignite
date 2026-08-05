// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestZeroconfBroadcasterRegistersFixedService(t *testing.T) {
	t.Parallel()

	txt := []string{
		"device_id=node-7",
		"trust_domain=mesh.example",
		"adoption_state=unadopted",
	}
	server := &fakeZeroconfServer{}
	var got fakeZeroconfCall
	broadcaster := &ZeroconfBroadcaster{
		register: func(
			instance string,
			service string,
			domain string,
			port int,
			text []string,
			ifaces []net.Interface,
		) (zeroconfServer, error) {
			got = fakeZeroconfCall{
				instance: instance,
				service:  service,
				domain:   domain,
				port:     port,
				text:     text,
				ifaces:   ifaces,
			}
			return server, nil
		},
	}

	registration, err := broadcaster.Start(context.Background(), MDNSAdvertisement{
		Instance: "node-7",
		Port:     8443,
		TXT:      txt,
	})
	if err != nil {
		t.Fatal(err)
	}
	txt[0] = "device_id=changed-after-start"

	if got.instance != "node-7" {
		t.Fatalf("instance = %q, want node-7", got.instance)
	}
	if got.service != MDNSServiceType {
		t.Fatalf("service = %q, want %q", got.service, MDNSServiceType)
	}
	if got.domain != MDNSDomain {
		t.Fatalf("domain = %q, want %q", got.domain, MDNSDomain)
	}
	if got.port != 8443 {
		t.Fatalf("port = %d, want 8443", got.port)
	}
	wantTXT := []string{
		"device_id=node-7",
		"trust_domain=mesh.example",
		"adoption_state=unadopted",
	}
	if !reflect.DeepEqual(got.text, wantTXT) {
		t.Fatalf("TXT = %#v, want %#v", got.text, wantTXT)
	}
	if got.ifaces != nil {
		t.Fatalf("interfaces = %#v, want nil for all multicast interfaces", got.ifaces)
	}

	if err := registration.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := registration.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if server.shutdowns != 1 {
		t.Fatalf("Shutdown calls = %d, want 1", server.shutdowns)
	}
}

func TestZeroconfBroadcasterRejectsNoncanonicalOrUnplannedRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		advertisement MDNSAdvertisement
	}{
		{
			name: "wrong service instance",
			advertisement: MDNSAdvertisement{
				Instance: "node-8",
				Port:     8443,
				TXT:      validTestTXT(),
			},
		},
		{
			name: "noncanonical TXT order",
			advertisement: MDNSAdvertisement{
				Instance: "node-7",
				Port:     8443,
				TXT: []string{
					"adoption_state=unadopted",
					"device_id=node-7",
					"trust_domain=mesh.example",
				},
			},
		},
		{
			name: "extra TXT field",
			advertisement: MDNSAdvertisement{
				Instance: "node-7",
				Port:     8443,
				TXT: append(
					validTestTXT(),
					"endpoint=https://example.invalid",
				),
			},
		},
		{
			name: "zero port",
			advertisement: MDNSAdvertisement{
				Instance: "node-7",
				TXT:      validTestTXT(),
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			called := false
			broadcaster := &ZeroconfBroadcaster{
				register: func(
					string,
					string,
					string,
					int,
					[]string,
					[]net.Interface,
				) (zeroconfServer, error) {
					called = true
					return &fakeZeroconfServer{}, nil
				},
			}

			if _, err := broadcaster.Start(context.Background(), test.advertisement); err == nil {
				t.Fatal("Start() succeeded, want error")
			}
			if called {
				t.Fatal("zeroconf registrar called for invalid advertisement")
			}
		})
	}
}

func TestZeroconfBroadcasterPropagatesRegistrationError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("multicast unavailable")
	broadcaster := &ZeroconfBroadcaster{
		register: func(
			string,
			string,
			string,
			int,
			[]string,
			[]net.Interface,
		) (zeroconfServer, error) {
			return nil, wantErr
		},
	}

	_, err := broadcaster.Start(context.Background(), MDNSAdvertisement{
		Instance: "node-7",
		Port:     8443,
		TXT:      validTestTXT(),
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want wrapped %v", err, wantErr)
	}
}

func TestZeroconfBroadcasterCleansUpWhenContextCancelsDuringRegistration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	server := &fakeZeroconfServer{}
	broadcaster := &ZeroconfBroadcaster{
		register: func(
			string,
			string,
			string,
			int,
			[]string,
			[]net.Interface,
		) (zeroconfServer, error) {
			cancel()
			return server, nil
		},
	}

	_, err := broadcaster.Start(ctx, MDNSAdvertisement{
		Instance: "node-7",
		Port:     8443,
		TXT:      validTestTXT(),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context cancellation", err)
	}
	if server.shutdowns != 1 {
		t.Fatalf("Shutdown calls = %d, want 1", server.shutdowns)
	}
}

func TestZeroconfBroadcasterBoundsCancellationCleanup(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	releaseShutdown := make(chan struct{})
	defer close(releaseShutdown)
	server := &fakeZeroconfServer{
		shutdownHook: func() {
			<-releaseShutdown
		},
	}
	broadcaster := &ZeroconfBroadcaster{
		cleanupTimeout: 10 * time.Millisecond,
		register: func(
			string,
			string,
			string,
			int,
			[]string,
			[]net.Interface,
		) (zeroconfServer, error) {
			cancel()
			return server, nil
		},
	}

	result := make(chan error, 1)
	go func() {
		_, err := broadcaster.Start(ctx, MDNSAdvertisement{
			Instance: "node-7",
			Port:     8443,
			TXT:      validTestTXT(),
		})
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start() error = %v, want context cancellation", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Start() error = %v, want bounded cleanup deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not return after the cleanup deadline")
	}
}

type fakeZeroconfCall struct {
	instance string
	service  string
	domain   string
	port     int
	text     []string
	ifaces   []net.Interface
}

type fakeZeroconfServer struct {
	shutdowns    int
	shutdownHook func()
}

func (s *fakeZeroconfServer) Shutdown() {
	s.shutdowns++
	if s.shutdownHook != nil {
		s.shutdownHook()
	}
}

func validTestTXT() []string {
	return []string{
		"device_id=node-7",
		"trust_domain=mesh.example",
		"adoption_state=unadopted",
	}
}
