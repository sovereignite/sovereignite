// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestServiceLifecycleStartsBothAndStopsBoth(t *testing.T) {
	t.Parallel()

	mdnsHandle := &fakeRegistration{}
	bleHandle := &fakeRegistration{}
	mdns := &fakeMDNSBroadcaster{handle: mdnsHandle}
	ble := &fakeBLEBroadcaster{handle: bleHandle}
	service := newTestService(t, mdns, ble, &fakeAdoptionHandler{})

	mdns.startHook = func() {
		if got := service.State(); got != StateStarting {
			t.Fatalf("state during mDNS start = %s, want starting", got)
		}
	}
	ble.startHook = func() {
		if got := service.State(); got != StateStarting {
			t.Fatalf("state during BLE start = %s, want starting", got)
		}
	}
	mdnsHandle.stopHook = func() {
		if got := service.State(); got != StateStopping {
			t.Fatalf("state during mDNS stop = %s, want stopping", got)
		}
	}
	bleHandle.stopHook = func() {
		if got := service.State(); got != StateStopping {
			t.Fatalf("state during BLE stop = %s, want stopping", got)
		}
	}

	if got := service.State(); got != StateStopped {
		t.Fatalf("initial state = %s, want stopped", got)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := service.State(); got != StateRunning {
		t.Fatalf("state after start = %s, want running", got)
	}
	if err := service.Start(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Start() error = %v, want %v", err, ErrAlreadyRunning)
	}

	wantMDNS := MDNSAdvertisement{
		Instance: "node-7",
		Port:     8443,
		TXT:      validTestTXT(),
	}
	if !reflect.DeepEqual(mdns.advertisement, wantMDNS) {
		t.Fatalf("mDNS advertisement = %#v, want %#v", mdns.advertisement, wantMDNS)
	}
	if ble.advertisement.ServiceUUID != testBluetoothServiceUUID {
		t.Fatalf(
			"BLE service UUID = %q, want %q",
			ble.advertisement.ServiceUUID,
			testBluetoothServiceUUID,
		)
	}

	if err := service.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := service.State(); got != StateStopped {
		t.Fatalf("state after stop = %s, want stopped", got)
	}
	if mdnsHandle.stopCalls != 1 {
		t.Fatalf("mDNS stop calls = %d, want 1", mdnsHandle.stopCalls)
	}
	if bleHandle.stopCalls != 1 {
		t.Fatalf("BLE stop calls = %d, want 1", bleHandle.stopCalls)
	}
	if err := service.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mdnsHandle.stopCalls != 1 || bleHandle.stopCalls != 1 {
		t.Fatal("repeated Stop() called registrations again")
	}
}

func TestServiceRollsBackMDNSWhenBLEStartFails(t *testing.T) {
	t.Parallel()

	bleErr := errors.New("Bluetooth unavailable")
	cleanupErr := errors.New("mDNS cleanup failed")
	mdnsHandle := &fakeRegistration{stopErr: cleanupErr}
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: mdnsHandle},
		&fakeBLEBroadcaster{startErr: bleErr},
		&fakeAdoptionHandler{},
	)

	err := service.Start(context.Background())
	if !errors.Is(err, bleErr) {
		t.Fatalf("Start() error = %v, want wrapped %v", err, bleErr)
	}
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("Start() error = %v, want wrapped cleanup error %v", err, cleanupErr)
	}
	if mdnsHandle.stopCalls != 1 {
		t.Fatalf("mDNS rollback calls = %d, want 1", mdnsHandle.stopCalls)
	}
	if got := service.State(); got != StateStopped {
		t.Fatalf("state after failed start = %s, want stopped", got)
	}
}

func TestServiceDoesNotStartBLEWhenMDNSFails(t *testing.T) {
	t.Parallel()

	mdnsErr := errors.New("mDNS unavailable")
	ble := &fakeBLEBroadcaster{handle: &fakeRegistration{}}
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{startErr: mdnsErr},
		ble,
		&fakeAdoptionHandler{},
	)

	err := service.Start(context.Background())
	if !errors.Is(err, mdnsErr) {
		t.Fatalf("Start() error = %v, want wrapped %v", err, mdnsErr)
	}
	if ble.startCalls != 0 {
		t.Fatalf("BLE start calls = %d, want 0", ble.startCalls)
	}
	if got := service.State(); got != StateStopped {
		t.Fatalf("state after failed start = %s, want stopped", got)
	}
}

func TestServiceStopAttemptsBothRegistrations(t *testing.T) {
	t.Parallel()

	bleErr := errors.New("BLE unregister failed")
	mdnsErr := errors.New("mDNS unregister failed")
	bleHandle := &fakeRegistration{stopErr: bleErr}
	mdnsHandle := &fakeRegistration{stopErr: mdnsErr}
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: mdnsHandle},
		&fakeBLEBroadcaster{handle: bleHandle},
		&fakeAdoptionHandler{},
	)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	err := service.Stop(context.Background())
	if !errors.Is(err, bleErr) || !errors.Is(err, mdnsErr) {
		t.Fatalf("Stop() error = %v, want both registration errors", err)
	}
	if bleHandle.stopCalls != 1 || mdnsHandle.stopCalls != 1 {
		t.Fatalf(
			"stop calls: BLE=%d mDNS=%d, want one each",
			bleHandle.stopCalls,
			mdnsHandle.stopCalls,
		)
	}
	if got := service.State(); got != StateStopped {
		t.Fatalf("state after stop errors = %s, want stopped", got)
	}
}

func TestServiceRollsBackBothWhenStartContextCancels(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	mdnsHandle := &fakeRegistration{}
	bleHandle := &fakeRegistration{}
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: mdnsHandle},
		&fakeBLEBroadcaster{
			handle: bleHandle,
			startHook: func() {
				cancel()
			},
		},
		&fakeAdoptionHandler{},
	)

	err := service.Start(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context cancellation", err)
	}
	if mdnsHandle.stopCalls != 1 || bleHandle.stopCalls != 1 {
		t.Fatalf(
			"rollback calls: mDNS=%d BLE=%d, want one each",
			mdnsHandle.stopCalls,
			bleHandle.stopCalls,
		)
	}
	if got := service.State(); got != StateStopped {
		t.Fatalf("state after canceled start = %s, want stopped", got)
	}
}

func TestServiceCancellationSurfacesOneOrTwoRollbackFailures(t *testing.T) {
	t.Parallel()

	mdnsErr := errors.New("mDNS unregister failed")
	bleErr := errors.New("BLE unregister failed")
	tests := []struct {
		name        string
		mdnsStopErr error
		bleStopErr  error
		wantErrs    []error
	}{
		{
			name:       "one unregister failure",
			bleStopErr: bleErr,
			wantErrs:   []error{bleErr},
		},
		{
			name:        "two unregister failures",
			mdnsStopErr: mdnsErr,
			bleStopErr:  bleErr,
			wantErrs:    []error{mdnsErr, bleErr},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			mdnsHandle := &fakeRegistration{stopErr: test.mdnsStopErr}
			bleHandle := &fakeRegistration{stopErr: test.bleStopErr}
			service := newTestService(
				t,
				&fakeMDNSBroadcaster{handle: mdnsHandle},
				&fakeBLEBroadcaster{
					handle: bleHandle,
					startHook: func() {
						cancel()
					},
				},
				&fakeAdoptionHandler{},
			)

			err := service.Start(ctx)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Start() error = %v, want context cancellation", err)
			}
			for _, wantErr := range test.wantErrs {
				if !errors.Is(err, wantErr) {
					t.Fatalf("Start() error = %v, want cleanup error %v", err, wantErr)
				}
			}
			if mdnsHandle.stopCalls != 1 || bleHandle.stopCalls != 1 {
				t.Fatalf(
					"rollback calls: mDNS=%d BLE=%d, want one each",
					mdnsHandle.stopCalls,
					bleHandle.stopCalls,
				)
			}
			if got := service.State(); got != StateStopped {
				t.Fatalf("state after canceled start = %s, want stopped", got)
			}
		})
	}
}

func TestServiceRollbackUsesBoundedCleanupContext(t *testing.T) {
	t.Parallel()

	startErr := errors.New("BLE start failed")
	mdnsHandle := &fakeRegistration{
		stopFunc: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: mdnsHandle},
		&fakeBLEBroadcaster{startErr: startErr},
		&fakeAdoptionHandler{},
	)
	service.cleanupTimeout = 10 * time.Millisecond

	result := make(chan error, 1)
	go func() {
		result <- service.Start(context.Background())
	}()

	select {
	case err := <-result:
		if !errors.Is(err, startErr) {
			t.Fatalf("Start() error = %v, want wrapped %v", err, startErr)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Start() error = %v, want bounded cleanup deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not return after the cleanup deadline")
	}
	if mdnsHandle.stopCalls != 1 {
		t.Fatalf("mDNS rollback calls = %d, want 1", mdnsHandle.stopCalls)
	}
	if got := service.State(); got != StateStopped {
		t.Fatalf("state after timed-out rollback = %s, want stopped", got)
	}
}

func TestServiceRejectsMissingRegistrationHandles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mdns MDNSBroadcaster
		ble  BLEBroadcaster
	}{
		{
			name: "mDNS",
			mdns: &fakeMDNSBroadcaster{},
			ble:  &fakeBLEBroadcaster{handle: &fakeRegistration{}},
		},
		{
			name: "BLE",
			mdns: &fakeMDNSBroadcaster{handle: &fakeRegistration{}},
			ble:  &fakeBLEBroadcaster{},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newTestService(t, test.mdns, test.ble, &fakeAdoptionHandler{})
			if err := service.Start(context.Background()); err == nil {
				t.Fatal("Start() succeeded without a registration handle")
			}
			if got := service.State(); got != StateStopped {
				t.Fatalf("state after invalid adapter response = %s, want stopped", got)
			}
		})
	}
}

func TestServiceForwardsAdoptionWithoutInterpretingRequest(t *testing.T) {
	t.Parallel()

	type transportRequest struct {
		opaque string
	}
	type transportResponse struct {
		opaque string
	}
	request := &transportRequest{opaque: "request-owned-by-transport"}
	response := &transportResponse{opaque: "response-owned-by-trust"}
	contextKey := struct{}{}
	ctx := context.WithValue(context.Background(), contextKey, "transport-context")
	handler := &fakeAdoptionHandler{response: response}
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: &fakeRegistration{}},
		&fakeBLEBroadcaster{handle: &fakeRegistration{}},
		handler,
	)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	got, err := service.ForwardAdoption(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if got != response {
		t.Fatalf("response = %#v, want exact handler response %#v", got, response)
	}
	if handler.request != request {
		t.Fatalf("handler request = %#v, want exact transport request %#v", handler.request, request)
	}
	if handler.ctx.Value(contextKey) != "transport-context" {
		t.Fatal("handler did not receive the transport context")
	}
	if handler.calls != 1 {
		t.Fatalf("handler calls = %d, want 1", handler.calls)
	}
}

func TestServiceReturnsAdoptionHandlerErrorUnchanged(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("Trust rejected adoption")
	handler := &fakeAdoptionHandler{err: wantErr}
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: &fakeRegistration{}},
		&fakeBLEBroadcaster{handle: &fakeRegistration{}},
		handler,
	)
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := service.ForwardAdoption(
		context.Background(),
		struct{}{},
	); !errors.Is(err, wantErr) {
		t.Fatalf("ForwardAdoption() error = %v, want %v", err, wantErr)
	}
}

func TestServiceAdoptionFailsClosedWithoutRunningOrInjectedHandler(t *testing.T) {
	t.Parallel()

	handler := &fakeAdoptionHandler{}
	service := newTestService(
		t,
		&fakeMDNSBroadcaster{handle: &fakeRegistration{}},
		&fakeBLEBroadcaster{handle: &fakeRegistration{}},
		handler,
	)
	if _, err := service.ForwardAdoption(context.Background(), struct{}{}); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("ForwardAdoption() error = %v, want %v", err, ErrNotRunning)
	}
	if handler.calls != 0 {
		t.Fatalf("handler calls = %d, want 0 while stopped", handler.calls)
	}

	_, err := NewService(
		testServiceConfig(),
		&fakeMDNSBroadcaster{handle: &fakeRegistration{}},
		&fakeBLEBroadcaster{handle: &fakeRegistration{}},
		nil,
	)
	if !errors.Is(err, ErrAdoptionHandlerUnavailable) {
		t.Fatalf("NewService() error = %v, want %v", err, ErrAdoptionHandlerUnavailable)
	}
}

func TestNewServiceRejectsInvalidConfigurationAndMissingAdapters(t *testing.T) {
	t.Parallel()

	validConfig := testServiceConfig()
	tests := []struct {
		name   string
		config ServiceConfig
		mdns   MDNSBroadcaster
		ble    BLEBroadcaster
	}{
		{
			name: "invalid record",
			config: ServiceConfig{
				Record: Record{
					DeviceID:      "Node-7",
					TrustDomain:   "mesh.example",
					AdoptionState: AdoptionStateUnadopted,
				},
				ServicePort:          8443,
				BluetoothServiceUUID: testBluetoothServiceUUID,
			},
			mdns: &fakeMDNSBroadcaster{},
			ble:  &fakeBLEBroadcaster{},
		},
		{
			name: "missing service port",
			config: ServiceConfig{
				Record:               validConfig.Record,
				BluetoothServiceUUID: testBluetoothServiceUUID,
			},
			mdns: &fakeMDNSBroadcaster{},
			ble:  &fakeBLEBroadcaster{},
		},
		{
			name: "missing Bluetooth UUID",
			config: ServiceConfig{
				Record:      validConfig.Record,
				ServicePort: 8443,
			},
			mdns: &fakeMDNSBroadcaster{},
			ble:  &fakeBLEBroadcaster{},
		},
		{
			name:   "missing mDNS adapter",
			config: validConfig,
			ble:    &fakeBLEBroadcaster{},
		},
		{
			name:   "missing BLE adapter",
			config: validConfig,
			mdns:   &fakeMDNSBroadcaster{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewService(test.config, test.mdns, test.ble, nil); err == nil {
				t.Fatal("NewService() succeeded, want error")
			}
		})
	}
}

func TestStateString(t *testing.T) {
	t.Parallel()

	tests := map[State]string{
		StateStopped:  "stopped",
		StateStarting: "starting",
		StateRunning:  "running",
		StateStopping: "stopping",
		State(255):    "unknown",
	}
	for state, want := range tests {
		if got := state.String(); got != want {
			t.Fatalf("State(%d).String() = %q, want %q", state, got, want)
		}
	}
}

type fakeMDNSBroadcaster struct {
	advertisement MDNSAdvertisement
	handle        Registration
	startErr      error
	startCalls    int
	startHook     func()
}

func (b *fakeMDNSBroadcaster) Start(
	_ context.Context,
	advertisement MDNSAdvertisement,
) (Registration, error) {
	b.startCalls++
	b.advertisement = advertisement
	if b.startHook != nil {
		b.startHook()
	}
	return b.handle, b.startErr
}

type fakeBLEBroadcaster struct {
	advertisement BLEAdvertisement
	handle        Registration
	startErr      error
	startCalls    int
	startHook     func()
}

func (b *fakeBLEBroadcaster) Start(
	_ context.Context,
	advertisement BLEAdvertisement,
) (Registration, error) {
	b.startCalls++
	b.advertisement = advertisement
	if b.startHook != nil {
		b.startHook()
	}
	return b.handle, b.startErr
}

type fakeRegistration struct {
	stopErr   error
	stopCalls int
	stopHook  func()
	stopFunc  func(context.Context) error
}

func (r *fakeRegistration) Stop(ctx context.Context) error {
	r.stopCalls++
	if r.stopHook != nil {
		r.stopHook()
	}
	if r.stopFunc != nil {
		return r.stopFunc(ctx)
	}
	return r.stopErr
}

type fakeAdoptionHandler struct {
	ctx      context.Context
	request  any
	response any
	err      error
	calls    int
}

func (h *fakeAdoptionHandler) HandleAdoption(ctx context.Context, request any) (any, error) {
	h.calls++
	h.ctx = ctx
	h.request = request
	return h.response, h.err
}

func newTestService(
	t *testing.T,
	mdns MDNSBroadcaster,
	ble BLEBroadcaster,
	handler AdoptionHandler,
) *Service {
	t.Helper()
	service, err := NewService(testServiceConfig(), mdns, ble, handler)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testServiceConfig() ServiceConfig {
	return ServiceConfig{
		Record: Record{
			DeviceID:      "node-7",
			TrustDomain:   "mesh.example",
			AdoptionState: AdoptionStateUnadopted,
		},
		ServicePort:          8443,
		BluetoothServiceUUID: testBluetoothServiceUUID,
	}
}
