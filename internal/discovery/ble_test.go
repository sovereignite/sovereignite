// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

const testBluetoothServiceUUID = "7e57d004-2b97-0e7a-b45f-5387367791cd"

func TestNormalizeBluetoothServiceUUID(t *testing.T) {
	t.Parallel()

	got, err := NormalizeBluetoothServiceUUID("7E57D004-2B97-0E7A-B45F-5387367791CD")
	if err != nil {
		t.Fatal(err)
	}
	if got != testBluetoothServiceUUID {
		t.Fatalf("normalized UUID = %q, want %q", got, testBluetoothServiceUUID)
	}

	for _, value := range []string{
		"",
		"7e57d0042b970e7ab45f5387367791cd",
		"7e57d004-2b97-0e7a-b45f-5387367791cg",
		" 7e57d004-2b97-0e7a-b45f-5387367791cd",
	} {
		if _, err := NormalizeBluetoothServiceUUID(value); err == nil {
			t.Fatalf("NormalizeBluetoothServiceUUID(%q) succeeded, want error", value)
		}
	}
}

func TestBlueZBroadcasterRegistersMinimalAdvertisement(t *testing.T) {
	t.Parallel()

	session := &fakeBlueZSession{}
	broadcaster := &BlueZBroadcaster{
		adapterPath: dbus.ObjectPath("/org/bluez/hci7"),
		dial: func() (blueZSession, error) {
			return session, nil
		},
	}

	registration, err := broadcaster.Start(context.Background(), BLEAdvertisement{
		ServiceUUID: "7E57D004-2B97-0E7A-B45F-5387367791CD",
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.exportPath != blueZAdvertisementPath {
		t.Fatalf("export path = %q, want %q", session.exportPath, blueZAdvertisementPath)
	}
	if session.serviceUUID != testBluetoothServiceUUID {
		t.Fatalf("service UUID = %q, want %q", session.serviceUUID, testBluetoothServiceUUID)
	}
	if session.registerAdapter != broadcaster.adapterPath {
		t.Fatalf("register adapter = %q, want %q", session.registerAdapter, broadcaster.adapterPath)
	}
	if session.registerPath != blueZAdvertisementPath {
		t.Fatalf("register path = %q, want %q", session.registerPath, blueZAdvertisementPath)
	}

	if err := registration.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := registration.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if session.unregisterCalls != 1 {
		t.Fatalf("unregister calls = %d, want 1", session.unregisterCalls)
	}
	if session.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", session.closeCalls)
	}
}

func TestBlueZAdvertisementPropertiesContainOnlyASKMatchingFields(t *testing.T) {
	t.Parallel()

	properties := blueZAdvertisementProperties(testBluetoothServiceUUID)
	if len(properties) != 1 {
		t.Fatalf("interface count = %d, want 1", len(properties))
	}
	advertisementProperties, ok := properties[blueZAdvertisementInterface]
	if !ok {
		t.Fatalf("missing %s properties", blueZAdvertisementInterface)
	}
	if len(advertisementProperties) != 2 {
		t.Fatalf("property count = %d, want 2", len(advertisementProperties))
	}
	if got := advertisementProperties["Type"].Value; got != blueZAdvertisementType {
		t.Fatalf("Type = %#v, want %q", got, blueZAdvertisementType)
	}
	if got, want := advertisementProperties["ServiceUUIDs"].Value, []string{testBluetoothServiceUUID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ServiceUUIDs = %#v, want %#v", got, want)
	}
	for _, unplanned := range []string{
		"LocalName",
		"ManufacturerData",
		"ServiceData",
		"SolicitUUIDs",
		"Includes",
	} {
		if _, exists := advertisementProperties[unplanned]; exists {
			t.Fatalf("unplanned BLE property %q was emitted", unplanned)
		}
	}
}

func TestBlueZBroadcasterRejectsInvalidConfigurationBeforeDial(t *testing.T) {
	t.Parallel()

	if _, err := NewBlueZBroadcaster("not/an/object/path"); err == nil {
		t.Fatal("NewBlueZBroadcaster() succeeded for invalid object path")
	}

	dials := 0
	broadcaster := &BlueZBroadcaster{
		adapterPath: dbus.ObjectPath("/org/bluez/hci0"),
		dial: func() (blueZSession, error) {
			dials++
			return &fakeBlueZSession{}, nil
		},
	}
	if _, err := broadcaster.Start(context.Background(), BLEAdvertisement{
		ServiceUUID: "not-a-uuid",
	}); err == nil {
		t.Fatal("Start() succeeded for invalid service UUID")
	}
	if dials != 0 {
		t.Fatalf("D-Bus dials = %d, want 0", dials)
	}
}

func TestBlueZBroadcasterCleansUpFailures(t *testing.T) {
	t.Parallel()

	exportErr := errors.New("export failed")
	registerErr := errors.New("register failed")
	tests := []struct {
		name             string
		session          *fakeBlueZSession
		wantErr          error
		wantCloseCalls   int
		wantUnregistered int
	}{
		{
			name:           "export",
			session:        &fakeBlueZSession{exportErr: exportErr},
			wantErr:        exportErr,
			wantCloseCalls: 1,
		},
		{
			name:           "register",
			session:        &fakeBlueZSession{registerErr: registerErr},
			wantErr:        registerErr,
			wantCloseCalls: 1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			broadcaster := &BlueZBroadcaster{
				adapterPath: dbus.ObjectPath("/org/bluez/hci0"),
				dial: func() (blueZSession, error) {
					return test.session, nil
				},
			}
			_, err := broadcaster.Start(context.Background(), BLEAdvertisement{
				ServiceUUID: testBluetoothServiceUUID,
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Start() error = %v, want wrapped %v", err, test.wantErr)
			}
			if test.session.closeCalls != test.wantCloseCalls {
				t.Fatalf("close calls = %d, want %d", test.session.closeCalls, test.wantCloseCalls)
			}
			if test.session.unregisterCalls != test.wantUnregistered {
				t.Fatalf(
					"unregister calls = %d, want %d",
					test.session.unregisterCalls,
					test.wantUnregistered,
				)
			}
		})
	}
}

func TestBlueZBroadcasterCleansUpWhenContextCancelsAfterRegister(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	session := &fakeBlueZSession{registerHook: cancel}
	broadcaster := &BlueZBroadcaster{
		adapterPath: dbus.ObjectPath("/org/bluez/hci0"),
		dial: func() (blueZSession, error) {
			return session, nil
		},
	}

	_, err := broadcaster.Start(ctx, BLEAdvertisement{ServiceUUID: testBluetoothServiceUUID})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context cancellation", err)
	}
	if session.unregisterCalls != 1 {
		t.Fatalf("unregister calls = %d, want 1", session.unregisterCalls)
	}
	if session.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", session.closeCalls)
	}
}

func TestBlueZBroadcasterBoundsCancellationCleanup(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	session := &fakeBlueZSession{
		registerHook: cancel,
		unregisterFunc: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	broadcaster := &BlueZBroadcaster{
		adapterPath:    dbus.ObjectPath("/org/bluez/hci0"),
		cleanupTimeout: 10 * time.Millisecond,
		dial: func() (blueZSession, error) {
			return session, nil
		},
	}

	result := make(chan error, 1)
	go func() {
		_, err := broadcaster.Start(
			ctx,
			BLEAdvertisement{ServiceUUID: testBluetoothServiceUUID},
		)
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
	if session.unregisterCalls != 1 {
		t.Fatalf("unregister calls = %d, want 1", session.unregisterCalls)
	}
	if session.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", session.closeCalls)
	}
}

func TestBlueZSessionCloseIsBoundedOnEveryCleanupPath(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("BlueZ close incomplete")
	cancelErr := context.Canceled
	exportErr := errors.New("export failed")
	registerErr := errors.New("register failed")
	tests := []struct {
		name       string
		primaryErr error
		run        func(*BlueZBroadcaster, *fakeBlueZSession) error
	}{
		{
			name:       "cancellation after dial",
			primaryErr: cancelErr,
			run: func(broadcaster *BlueZBroadcaster, session *fakeBlueZSession) error {
				ctx, cancel := context.WithCancel(context.Background())
				broadcaster.dial = func() (blueZSession, error) {
					cancel()
					return session, nil
				}
				_, err := broadcaster.Start(
					ctx,
					BLEAdvertisement{ServiceUUID: testBluetoothServiceUUID},
				)
				return err
			},
		},
		{
			name:       "export failure",
			primaryErr: exportErr,
			run: func(broadcaster *BlueZBroadcaster, session *fakeBlueZSession) error {
				session.exportErr = exportErr
				_, err := broadcaster.Start(
					context.Background(),
					BLEAdvertisement{ServiceUUID: testBluetoothServiceUUID},
				)
				return err
			},
		},
		{
			name:       "register failure",
			primaryErr: registerErr,
			run: func(broadcaster *BlueZBroadcaster, session *fakeBlueZSession) error {
				session.registerErr = registerErr
				_, err := broadcaster.Start(
					context.Background(),
					BLEAdvertisement{ServiceUUID: testBluetoothServiceUUID},
				)
				return err
			},
		},
		{
			name: "unregister",
			run: func(broadcaster *BlueZBroadcaster, _ *fakeBlueZSession) error {
				registration, err := broadcaster.Start(
					context.Background(),
					BLEAdvertisement{ServiceUUID: testBluetoothServiceUUID},
				)
				if err != nil {
					return err
				}
				return registration.Stop(context.Background())
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			session := &fakeBlueZSession{
				closeFunc: func(ctx context.Context) error {
					<-ctx.Done()
					return errors.Join(closeErr, ctx.Err())
				},
			}
			broadcaster := &BlueZBroadcaster{
				adapterPath:    dbus.ObjectPath("/org/bluez/hci0"),
				cleanupTimeout: 10 * time.Millisecond,
				dial: func() (blueZSession, error) {
					return session, nil
				},
			}

			result := make(chan error, 1)
			go func() {
				result <- test.run(broadcaster, session)
			}()

			select {
			case err := <-result:
				if test.primaryErr != nil && !errors.Is(err, test.primaryErr) {
					t.Fatalf("cleanup error = %v, want primary error %v", err, test.primaryErr)
				}
				if !errors.Is(err, closeErr) {
					t.Fatalf("cleanup error = %v, want close error %v", err, closeErr)
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("cleanup error = %v, want cleanup deadline", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cleanup did not return after the close deadline")
			}
			if session.closeCalls != 1 {
				t.Fatalf("close calls = %d, want 1", session.closeCalls)
			}
		})
	}
}

func TestGodbusBlueZSessionCloseInterruptsOwnedUnixTransport(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("owned Unix transport close failed")
	tests := []struct {
		name       string
		newContext func() (context.Context, context.CancelFunc)
		wantErr    error
	}{
		{
			name: "canceled",
			newContext: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			wantErr: context.Canceled,
		},
		{
			name: "deadline",
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(
					context.Background(),
					time.Now().Add(-time.Second),
				)
			},
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.newContext()
			defer cancel()

			transport := &fakeOwnedUnixTransport{closeErr: transportErr}
			cancelCalls := 0
			var unexported []string
			session := &godbusBlueZSession{
				transport: transport,
				cancelConnection: func() {
					cancelCalls++
				},
				unexport: func(_ dbus.ObjectPath, iface string) error {
					unexported = append(unexported, iface)
					return nil
				},
				exported: true,
				path:     blueZAdvertisementPath,
			}

			err := session.Close(ctx)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Close() error = %v, want context error %v", err, test.wantErr)
			}
			if !errors.Is(err, transportErr) {
				t.Fatalf("Close() error = %v, want transport error %v", err, transportErr)
			}
			if transport.setDeadlineCalls != 1 || transport.deadline.IsZero() {
				t.Fatalf(
					"SetDeadline calls=%d deadline=%v, want one immediate deadline",
					transport.setDeadlineCalls,
					transport.deadline,
				)
			}
			if transport.closeCalls != 1 {
				t.Fatalf("transport close calls = %d, want 1", transport.closeCalls)
			}
			if cancelCalls != 1 {
				t.Fatalf("connection cancel calls = %d, want 1", cancelCalls)
			}
			wantUnexported := []string{
				blueZAdvertisementInterface,
				dbusPropertiesInterface,
			}
			if !reflect.DeepEqual(unexported, wantUnexported) {
				t.Fatalf("unexported interfaces = %#v, want %#v", unexported, wantUnexported)
			}

			if secondErr := session.Close(context.Background()); secondErr != err {
				t.Fatalf("second Close() error = %v, want saved error %v", secondErr, err)
			}
			if transport.setDeadlineCalls != 1 ||
				transport.closeCalls != 1 ||
				cancelCalls != 1 {
				t.Fatal("repeated Close() repeated owned transport teardown")
			}
		})
	}
}

func TestParseLinuxSystemBusUnixAddress(t *testing.T) {
	t.Parallel()

	valid := []struct {
		address string
		want    *net.UnixAddr
	}{
		{
			address: "unix:path=/run/dbus/system_bus_socket",
			want:    &net.UnixAddr{Name: "/run/dbus/system_bus_socket", Net: "unix"},
		},
		{
			address: "unix:abstract=sovereignite%2Fsystem-bus",
			want:    &net.UnixAddr{Name: "@sovereignite/system-bus", Net: "unix"},
		},
	}
	for _, test := range valid {
		got, err := parseLinuxSystemBusUnixAddress(test.address)
		if err != nil {
			t.Fatalf("parseLinuxSystemBusUnixAddress(%q): %v", test.address, err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf(
				"parseLinuxSystemBusUnixAddress(%q) = %#v, want %#v",
				test.address,
				got,
				test.want,
			)
		}
	}

	invalid := []string{
		"",
		"tcp:host=127.0.0.1",
		"unix:path=relative/socket",
		"unix:path=/run/dbus/../dbus/system_bus_socket",
		"unix:path=/run/dbus/system_bus_socket,abstract=system-bus",
		"unix:path=/run/dbus/system_bus_socket,guid=unplanned",
		"unix:path=/run/dbus/one;unix:path=/run/dbus/two",
		"unix:runtime=yes",
		"unix:abstract=%00",
		"unix:abstract=" + strings.Repeat("a", linuxUnixAddressMaxBytes+1),
	}
	for _, address := range invalid {
		if _, err := parseLinuxSystemBusUnixAddress(address); err == nil {
			t.Fatalf("parseLinuxSystemBusUnixAddress(%q) succeeded, want error", address)
		}
	}
}

func TestLinuxSystemBusUnixAddressUsesOnlyExplicitOrSafeDefaultAddress(t *testing.T) {
	t.Parallel()

	got, err := linuxSystemBusUnixAddress(func(string) (string, bool) {
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "/var/run/dbus/system_bus_socket" {
		t.Fatalf("default system bus socket = %q, want /var/run/dbus/system_bus_socket", got.Name)
	}

	if _, err := linuxSystemBusUnixAddress(func(key string) (string, bool) {
		if key != systemBusAddressEnvironment {
			t.Fatalf("environment key = %q, want %q", key, systemBusAddressEnvironment)
		}
		return "nonce-tcp:host=127.0.0.1", true
	}); err == nil {
		t.Fatal("linuxSystemBusUnixAddress() accepted unsupported configured transport")
	}
}

type fakeBlueZSession struct {
	exportPath        dbus.ObjectPath
	serviceUUID       string
	registerAdapter   dbus.ObjectPath
	registerPath      dbus.ObjectPath
	unregisterAdapter dbus.ObjectPath
	unregisterPath    dbus.ObjectPath
	unregisterCalls   int
	closeCalls        int
	exportErr         error
	registerErr       error
	unregisterErr     error
	closeErr          error
	registerHook      func()
	unregisterFunc    func(context.Context) error
	closeFunc         func(context.Context) error
}

func (s *fakeBlueZSession) ExportAdvertisement(path dbus.ObjectPath, serviceUUID string) error {
	s.exportPath = path
	s.serviceUUID = serviceUUID
	return s.exportErr
}

func (s *fakeBlueZSession) RegisterAdvertisement(
	_ context.Context,
	adapterPath dbus.ObjectPath,
	advertisementPath dbus.ObjectPath,
) error {
	s.registerAdapter = adapterPath
	s.registerPath = advertisementPath
	if s.registerHook != nil {
		s.registerHook()
	}
	return s.registerErr
}

func (s *fakeBlueZSession) UnregisterAdvertisement(
	ctx context.Context,
	adapterPath dbus.ObjectPath,
	advertisementPath dbus.ObjectPath,
) error {
	s.unregisterCalls++
	s.unregisterAdapter = adapterPath
	s.unregisterPath = advertisementPath
	if s.unregisterFunc != nil {
		return s.unregisterFunc(ctx)
	}
	return s.unregisterErr
}

func (s *fakeBlueZSession) Close(ctx context.Context) error {
	s.closeCalls++
	if s.closeFunc != nil {
		return s.closeFunc(ctx)
	}
	return s.closeErr
}

type fakeOwnedUnixTransport struct {
	deadline         time.Time
	setDeadlineCalls int
	closeCalls       int
	setDeadlineErr   error
	closeErr         error
}

func (t *fakeOwnedUnixTransport) SetDeadline(deadline time.Time) error {
	t.setDeadlineCalls++
	t.deadline = deadline
	return t.setDeadlineErr
}

func (t *fakeOwnedUnixTransport) Close() error {
	t.closeCalls++
	return t.closeErr
}
