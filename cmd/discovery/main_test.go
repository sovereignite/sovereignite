// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sovereignite/sovereignite/internal/discovery"
)

func TestParseOptionsAndServiceConfig(t *testing.T) {
	t.Parallel()

	opts, err := parseOptions([]string{
		"-device-id", "node-7",
		"-trust-domain", "mesh.example",
		"-adoption-state", "unadopted",
		"-service-port", "8443",
		"-ble-service-uuid", testCommandServiceUUID,
		"-bluez-adapter", "/org/bluez/hci7",
	}, &bytes.Buffer{}, emptyOptionSources())
	if err != nil {
		t.Fatal(err)
	}
	if opts.blueZAdapterPath != "/org/bluez/hci7" {
		t.Fatalf("BlueZ adapter = %q, want /org/bluez/hci7", opts.blueZAdapterPath)
	}

	config, err := serviceConfig(opts)
	if err != nil {
		t.Fatal(err)
	}
	want := discovery.ServiceConfig{
		Record: discovery.Record{
			DeviceID:      "node-7",
			TrustDomain:   "mesh.example",
			AdoptionState: discovery.AdoptionStateUnadopted,
		},
		ServicePort:          8443,
		BluetoothServiceUUID: testCommandServiceUUID,
	}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("service config = %#v, want %#v", config, want)
	}
}

func TestServiceConfigRejectsMissingAndUnplannedValues(t *testing.T) {
	t.Parallel()

	tests := []options{
		{
			trustDomain:         "mesh.example",
			adoptionState:       "unadopted",
			servicePort:         8443,
			bluetoothServiceUUID: testCommandServiceUUID,
		},
		{
			deviceID:            "node-7",
			trustDomain:         "mesh.example",
			adoptionState:       "pending",
			servicePort:         8443,
			bluetoothServiceUUID: testCommandServiceUUID,
		},
	}
	for _, opts := range tests {
		opts := opts
		if _, err := serviceConfig(opts); err == nil {
			t.Fatalf("serviceConfig(%#v) succeeded, want error", opts)
		}
	}
}

func TestParseOptionsRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	if _, err := parseOptions(
		[]string{"unexpected"},
		&bytes.Buffer{},
		emptyOptionSources(),
	); err == nil {
		t.Fatal("parseOptions() succeeded, want error")
	}
}

func TestParseOptionsLoadsNoArgRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	var gotPath string
	opts, err := parseOptions(nil, &bytes.Buffer{}, optionSources{
		lookupEnv: func(string) (string, bool) {
			return "", false
		},
		readConfig: func(path string) ([]byte, error) {
			gotPath = path
			return validConfigEnv(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != runtimeConfigPath {
		t.Fatalf("runtime configuration path = %q, want %q", gotPath, runtimeConfigPath)
	}
	want := options{
		deviceID:             "node-7",
		trustDomain:          "mesh.example",
		adoptionState:        "unadopted",
		servicePort:          8443,
		bluetoothServiceUUID: testCommandServiceUUID,
		blueZAdapterPath:     "/org/bluez/hci0",
	}
	if !reflect.DeepEqual(opts, want) {
		t.Fatalf("options = %#v, want %#v", opts, want)
	}
}

func TestParseOptionsPrecedenceIsFlagsThenEnvironmentThenRuntimeFile(t *testing.T) {
	t.Parallel()

	environment := map[string]string{
		envTrustDomain:   "environment.example",
		envAdoptionState: "adopted",
	}
	opts, err := parseOptions([]string{
		"-device-id", "flag-node",
	}, &bytes.Buffer{}, optionSources{
		lookupEnv: func(key string) (string, bool) {
			value, ok := environment[key]
			return value, ok
		},
		readConfig: func(string) ([]byte, error) {
			return validConfigEnv(), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.deviceID != "flag-node" {
		t.Fatalf("device ID = %q, want flag-node", opts.deviceID)
	}
	if opts.trustDomain != "environment.example" {
		t.Fatalf("trust domain = %q, want environment.example", opts.trustDomain)
	}
	if opts.adoptionState != "adopted" {
		t.Fatalf("adoption state = %q, want adopted", opts.adoptionState)
	}
	if opts.servicePort != 8443 {
		t.Fatalf("service port = %d, want 8443 from runtime file", opts.servicePort)
	}
}

func TestParseOptionsFailsClosedForInvalidRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "unknown key",
			content: string(validConfigEnv()) + "SOVEREIGNITE_ENDPOINT=http://example.invalid\n",
		},
		{
			name:    "duplicate key",
			content: string(validConfigEnv()) + envDeviceID + "=node-8\n",
		},
		{
			name: "empty value",
			content: envDeviceID + "=\n" +
				envTrustDomain + "=mesh.example\n",
		},
		{
			name:    "surrounding whitespace",
			content: " " + envDeviceID + "=node-7\n",
		},
		{
			name: "missing required key",
			content: envDeviceID + "=node-7\n" +
				envTrustDomain + "=mesh.example\n",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseOptions(nil, &bytes.Buffer{}, optionSources{
				lookupEnv: func(string) (string, bool) {
					return "", false
				},
				readConfig: func(string) ([]byte, error) {
					return []byte(test.content), nil
				},
			})
			if err == nil {
				t.Fatal("parseOptions() succeeded, want error")
			}
		})
	}
}

func TestParseOptionsFailsClosedWhenRequiredSourcesAreAbsent(t *testing.T) {
	t.Parallel()

	_, err := parseOptions(nil, &bytes.Buffer{}, emptyOptionSources())
	if err == nil {
		t.Fatal("parseOptions() succeeded without required configuration")
	}
}

func TestReadRuntimeConfigRequiresRegularNonWritableFile(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "config.env")
	content := validConfigEnv()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readRuntimeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("read content = %q, want %q", got, content)
	}

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuntimeConfig(path); err == nil {
		t.Fatal("readRuntimeConfig() accepted group/world-writable file")
	}

	target := filepath.Join(directory, "target.env")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.env")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuntimeConfig(link); err == nil {
		t.Fatal("readRuntimeConfig() accepted symbolic link")
	}
}

func TestRunStartsAndStopsInjectedBroadcasters(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	mdnsHandle := &fakeCommandRegistration{}
	bleHandle := &fakeCommandRegistration{}
	mdns := &fakeCommandMDNS{handle: mdnsHandle}
	ble := &fakeCommandBLE{
		handle: bleHandle,
		startHook: func() {
			cancel()
		},
	}
	var gotAdapter string
	deps := dependencies{
		newMDNS: func() discovery.MDNSBroadcaster {
			return mdns
		},
		newBLE: func(adapterPath string) (discovery.BLEBroadcaster, error) {
			gotAdapter = adapterPath
			return ble, nil
		},
		adoptionHandler: &fakeCommandAdoptionHandler{},
	}

	err := run(ctx, []string{
		"-device-id", "node-7",
		"-trust-domain", "mesh.example",
		"-adoption-state", "adopted",
		"-service-port", "8443",
		"-ble-service-uuid", testCommandServiceUUID,
		"-bluez-adapter", "/org/bluez/hci0",
	}, deps, &bytes.Buffer{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run() error = %v, want context cancellation", err)
	}
	if gotAdapter != "/org/bluez/hci0" {
		t.Fatalf("BlueZ adapter = %q, want /org/bluez/hci0", gotAdapter)
	}
	if mdns.startCalls != 1 || ble.startCalls != 1 {
		t.Fatalf("start calls: mDNS=%d BLE=%d, want one each", mdns.startCalls, ble.startCalls)
	}
	if mdnsHandle.stopCalls != 1 || bleHandle.stopCalls != 1 {
		t.Fatalf(
			"stop calls: mDNS=%d BLE=%d, want one each",
			mdnsHandle.stopCalls,
			bleHandle.stopCalls,
		)
	}
	wantTXT := []string{
		"device_id=node-7",
		"trust_domain=mesh.example",
		"adoption_state=adopted",
	}
	if !reflect.DeepEqual(mdns.advertisement.TXT, wantTXT) {
		t.Fatalf("mDNS TXT = %#v, want %#v", mdns.advertisement.TXT, wantTXT)
	}
	if ble.advertisement.ServiceUUID != testCommandServiceUUID {
		t.Fatalf(
			"BLE UUID = %q, want %q",
			ble.advertisement.ServiceUUID,
			testCommandServiceUUID,
		)
	}
}

func TestRunPropagatesBroadcasterFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("mDNS failed")
	deps := dependencies{
		newMDNS: func() discovery.MDNSBroadcaster {
			return &fakeCommandMDNS{startErr: wantErr}
		},
		newBLE: func(string) (discovery.BLEBroadcaster, error) {
			return &fakeCommandBLE{}, nil
		},
		adoptionHandler: &fakeCommandAdoptionHandler{},
	}
	err := run(context.Background(), []string{
		"-device-id", "node-7",
		"-trust-domain", "mesh.example",
		"-adoption-state", "unadopted",
		"-service-port", "8443",
		"-ble-service-uuid", testCommandServiceUUID,
		"-bluez-adapter", "/org/bluez/hci0",
	}, deps, &bytes.Buffer{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("run() error = %v, want wrapped %v", err, wantErr)
	}
}

func TestRunFailsClosedWithoutTrustAdoptionBinding(t *testing.T) {
	t.Parallel()

	mdnsFactoryCalls := 0
	bleFactoryCalls := 0
	deps := dependencies{
		newMDNS: func() discovery.MDNSBroadcaster {
			mdnsFactoryCalls++
			return &fakeCommandMDNS{}
		},
		newBLE: func(string) (discovery.BLEBroadcaster, error) {
			bleFactoryCalls++
			return &fakeCommandBLE{}, nil
		},
	}

	err := run(context.Background(), nil, deps, &bytes.Buffer{})
	if !errors.Is(err, discovery.ErrAdoptionHandlerUnavailable) {
		t.Fatalf(
			"run() error = %v, want %v",
			err,
			discovery.ErrAdoptionHandlerUnavailable,
		)
	}
	if !strings.Contains(err.Error(), "Trust.AdoptDevice") {
		t.Fatalf("run() error = %q, want Trust.AdoptDevice integration gate", err)
	}
	if mdnsFactoryCalls != 0 || bleFactoryCalls != 0 {
		t.Fatalf(
			"factory calls: mDNS=%d BLE=%d, want none before Trust binding",
			mdnsFactoryCalls,
			bleFactoryCalls,
		)
	}
}

func TestPureContextCancellationClassification(t *testing.T) {
	t.Parallel()

	cleanupErr := errors.New("unregister failed")
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", want: false},
		{name: "canceled", err: context.Canceled, want: true},
		{
			name: "wrapped canceled",
			err:  fmt.Errorf("start interrupted: %w", context.Canceled),
			want: true,
		},
		{
			name: "joined cancellations",
			err:  errors.Join(context.Canceled, context.Canceled),
			want: true,
		},
		{
			name: "cancellation and cleanup failure",
			err:  errors.Join(context.Canceled, cleanupErr),
			want: false,
		},
		{name: "deadline", err: context.DeadlineExceeded, want: false},
		{name: "cleanup failure", err: cleanupErr, want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := isPureContextCancellation(test.err); got != test.want {
				t.Fatalf(
					"isPureContextCancellation(%v) = %t, want %t",
					test.err,
					got,
					test.want,
				)
			}
		})
	}
}

const testCommandServiceUUID = "7e57d004-2b97-0e7a-b45f-5387367791cd"

type fakeCommandMDNS struct {
	advertisement discovery.MDNSAdvertisement
	handle        discovery.Registration
	startErr      error
	startCalls    int
}

func (b *fakeCommandMDNS) Start(
	_ context.Context,
	advertisement discovery.MDNSAdvertisement,
) (discovery.Registration, error) {
	b.startCalls++
	b.advertisement = advertisement
	return b.handle, b.startErr
}

type fakeCommandBLE struct {
	advertisement discovery.BLEAdvertisement
	handle        discovery.Registration
	startErr      error
	startCalls    int
	startHook     func()
}

func (b *fakeCommandBLE) Start(
	_ context.Context,
	advertisement discovery.BLEAdvertisement,
) (discovery.Registration, error) {
	b.startCalls++
	b.advertisement = advertisement
	if b.startHook != nil {
		b.startHook()
	}
	return b.handle, b.startErr
}

type fakeCommandRegistration struct {
	stopCalls int
}

func (r *fakeCommandRegistration) Stop(context.Context) error {
	r.stopCalls++
	return nil
}

type fakeCommandAdoptionHandler struct{}

func (*fakeCommandAdoptionHandler) HandleAdoption(context.Context, any) (any, error) {
	return nil, nil
}

func emptyOptionSources() optionSources {
	return optionSources{
		lookupEnv: func(string) (string, bool) {
			return "", false
		},
		readConfig: func(string) ([]byte, error) {
			return nil, fs.ErrNotExist
		},
	}
}

func validConfigEnv() []byte {
	return []byte(
		envDeviceID + "=node-7\n" +
			envTrustDomain + "=mesh.example\n" +
			envAdoptionState + "=unadopted\n" +
			envServicePort + "=8443\n" +
			envBluetoothServiceUUID + "=" + testCommandServiceUUID + "\n" +
			envBlueZAdapterPath + "=/org/bluez/hci0\n",
	)
}
