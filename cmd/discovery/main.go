// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sovereignite/sovereignite/internal/discovery"
	pb "github.com/sovereignite/sovereignite/pkg/api/proto/sovereignite/v1"

	"google.golang.org/grpc"
)

const (
	runtimeConfigPath = "/run/sovereignite/discovery/config.env"
	stopTimeout       = 5 * time.Second
	maxConfigBytes    = 64 * 1024

	envDeviceID             = "SOVEREIGNITE_DEVICE_ID"
	envTrustDomain          = "SOVEREIGNITE_TRUST_DOMAIN"
	envAdoptionState        = "SOVEREIGNITE_ADOPTION_STATE"
	envServicePort          = "SOVEREIGNITE_SERVICE_PORT"
	envBluetoothServiceUUID = "SOVEREIGNITE_BLE_SERVICE_UUID"
	envBlueZAdapterPath     = "SOVEREIGNITE_BLUEZ_ADAPTER"
)

type options struct {
	deviceID             string
	trustDomain          string
	adoptionState        string
	servicePort          int
	bluetoothServiceUUID string
	blueZAdapterPath     string
}

type dependencies struct {
	newMDNS         func() discovery.MDNSBroadcaster
	newBLE          func(string) (discovery.BLEBroadcaster, error)
	adoptionHandler discovery.AdoptionHandler
}

type optionSources struct {
	lookupEnv  func(string) (string, bool)
	readConfig func(string) ([]byte, error)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := run(ctx, os.Args[1:], productionDependencies(), os.Stderr)
	if err != nil && !isPureContextCancellation(err) {
		slog.Error("discovery service stopped", "error", err)
		os.Exit(1)
	}
}

func productionDependencies() dependencies {
	return dependencies{
		newMDNS: func() discovery.MDNSBroadcaster {
			return discovery.NewZeroconfBroadcaster()
		},
		newBLE: func(adapterPath string) (discovery.BLEBroadcaster, error) {
			return discovery.NewBlueZBroadcaster(adapterPath)
		},
		// Open integration gate: Phase 1.3 defines no adoption listener or wire
		// protocol. Until the committed Trust.AdoptDevice gRPC contract has a
		// generated mTLS binding, run fails closed instead of advertising.
		adoptionHandler: nil,
	}
}

func run(ctx context.Context, args []string, deps dependencies, errorOutput io.Writer) error {
	if ctx == nil {
		return errors.New("run context is required")
	}
	if deps.adoptionHandler == nil {
		return fmt.Errorf(
			"Trust.AdoptDevice mTLS binding is required: %w",
			discovery.ErrAdoptionHandlerUnavailable,
		)
	}
	opts, err := parseOptions(args, errorOutput, optionSources{
		lookupEnv:  os.LookupEnv,
		readConfig: readRuntimeConfig,
	})
	if err != nil {
		return err
	}
	if deps.newMDNS == nil {
		return errors.New("mDNS dependency factory is required")
	}
	if deps.newBLE == nil {
		return errors.New("BLE dependency factory is required")
	}

	config, err := serviceConfig(opts)
	if err != nil {
		return err
	}
	ble, err := deps.newBLE(opts.blueZAdapterPath)
	if err != nil {
		return fmt.Errorf("configure BlueZ broadcaster: %w", err)
	}
	service, err := discovery.NewService(
		config,
		deps.newMDNS(),
		ble,
		deps.adoptionHandler,
	)
	if err != nil {
		return fmt.Errorf("configure discovery service: %w", err)
	}
	if err := service.Start(ctx); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		defer cancel()
		_ = service.Stop(stopCtx)
		return fmt.Errorf("gRPC listener: %w", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterDiscoveryServer(grpcServer, discovery.NewDiscoveryServer(service))

	serveErr := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			serveErr <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil {
			grpcServer.GracefulStop()
			stopCtx, cancel := context.WithTimeout(context.Background(), stopTimeout)
			defer cancel()
			_ = service.Stop(stopCtx)
			return fmt.Errorf("gRPC serve: %w", err)
		}
	}

	grpcServer.GracefulStop()
	stopCtx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	return service.Stop(stopCtx)
}

func isPureContextCancellation(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		errs := joined.Unwrap()
		if len(errs) == 0 {
			return false
		}
		for _, child := range errs {
			if !isPureContextCancellation(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return isPureContextCancellation(wrapped.Unwrap())
	}
	return err == context.Canceled
}

func parseOptions(
	args []string,
	errorOutput io.Writer,
	sources optionSources,
) (options, error) {
	if sources.lookupEnv == nil {
		return options{}, errors.New("environment lookup is required")
	}
	if sources.readConfig == nil {
		return options{}, errors.New("runtime configuration reader is required")
	}

	flagValues := make(map[string]string, 6)
	var (
		deviceID             string
		trustDomain          string
		adoptionState        string
		servicePort          string
		bluetoothServiceUUID string
		blueZAdapterPath     string
	)
	flags := flag.NewFlagSet("sovereignite-discovery", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	flags.StringVar(&deviceID, "device-id", "", "canonical device identifier (required)")
	flags.StringVar(&trustDomain, "trust-domain", "", "canonical SPIFFE trust domain (required)")
	flags.StringVar(
		&adoptionState,
		"adoption-state",
		"",
		"adoption state: unadopted or adopted (required)",
	)
	flags.StringVar(
		&servicePort,
		"service-port",
		"",
		"existing secure service port advertised by mDNS (required)",
	)
	flags.StringVar(
		&bluetoothServiceUUID,
		"ble-service-uuid",
		"",
		"Bluetooth service UUID declared by the AccessorySetupKit client (required)",
	)
	flags.StringVar(
		&blueZAdapterPath,
		"bluez-adapter",
		"",
		"BlueZ adapter D-Bus object path (required)",
	)
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	flagKey := map[string]string{
		"device-id":         envDeviceID,
		"trust-domain":      envTrustDomain,
		"adoption-state":    envAdoptionState,
		"service-port":      envServicePort,
		"ble-service-uuid":  envBluetoothServiceUUID,
		"bluez-adapter":     envBlueZAdapterPath,
	}
	flags.Visit(func(flagValue *flag.Flag) {
		flagValues[flagKey[flagValue.Name]] = flagValue.Value.String()
	})

	values := make(map[string]string, len(flagKey))
	for _, key := range flagKey {
		if value, ok := flagValues[key]; ok {
			values[key] = value
			continue
		}
		if value, ok := sources.lookupEnv(key); ok {
			values[key] = value
		}
	}
	if len(values) != len(flagKey) {
		content, err := sources.readConfig(runtimeConfigPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return options{}, fmt.Errorf("read runtime discovery configuration: %w", err)
		}
		if err == nil {
			fileValues, parseErr := parseConfigEnv(content)
			if parseErr != nil {
				return options{}, fmt.Errorf("parse runtime discovery configuration: %w", parseErr)
			}
			for key, value := range fileValues {
				if _, configured := values[key]; !configured {
					values[key] = value
				}
			}
		}
	}

	requiredKeys := [...]string{
		envDeviceID,
		envTrustDomain,
		envAdoptionState,
		envServicePort,
		envBluetoothServiceUUID,
		envBlueZAdapterPath,
	}
	for _, key := range requiredKeys {
		if values[key] == "" {
			return options{}, fmt.Errorf("%s is required", key)
		}
	}
	for _, character := range values[envServicePort] {
		if character < '0' || character > '9' {
			return options{}, fmt.Errorf("%s must contain only decimal digits", envServicePort)
		}
	}
	portValue, err := strconv.ParseUint(values[envServicePort], 10, 16)
	if err != nil {
		return options{}, fmt.Errorf("%s must be a decimal port: %w", envServicePort, err)
	}
	if portValue == 0 {
		return options{}, fmt.Errorf("%s must be between 1 and 65535", envServicePort)
	}
	return options{
		deviceID:             values[envDeviceID],
		trustDomain:          values[envTrustDomain],
		adoptionState:        values[envAdoptionState],
		servicePort:          int(portValue),
		bluetoothServiceUUID: values[envBluetoothServiceUUID],
		blueZAdapterPath:     values[envBlueZAdapterPath],
	}, nil
}

func serviceConfig(opts options) (discovery.ServiceConfig, error) {
	record, err := discovery.NewRecord(
		opts.deviceID,
		opts.trustDomain,
		discovery.AdoptionState(opts.adoptionState),
	)
	if err != nil {
		return discovery.ServiceConfig{}, fmt.Errorf("configure discovery record: %w", err)
	}
	return discovery.ServiceConfig{
		Record:               record,
		ServicePort:          opts.servicePort,
		BluetoothServiceUUID: opts.bluetoothServiceUUID,
	}, nil
}

func readRuntimeConfig(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("runtime discovery configuration is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("runtime discovery configuration must not be group- or world-writable")
	}
	if info.Size() <= 0 || info.Size() > maxConfigBytes {
		return nil, errors.New("runtime discovery configuration has an invalid size")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, errors.New("runtime discovery configuration changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) == 0 || len(content) > maxConfigBytes {
		return nil, errors.New("runtime discovery configuration has an invalid size")
	}
	return content, nil
}

func parseConfigEnv(content []byte) (map[string]string, error) {
	if len(content) == 0 || len(content) > maxConfigBytes {
		return nil, errors.New("configuration must be nonempty and at most 64 KiB")
	}
	knownKeys := map[string]struct{}{
		envDeviceID:             {},
		envTrustDomain:          {},
		envAdoptionState:        {},
		envServicePort:          {},
		envBluetoothServiceUUID: {},
		envBlueZAdapterPath:     {},
	}
	values := make(map[string]string, len(knownKeys))
	for index, line := range strings.Split(string(content), "\n") {
		lineNumber := index + 1
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSpace(line) != line {
			return nil, fmt.Errorf("line %d has surrounding whitespace", lineNumber)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d has no value separator", lineNumber)
		}
		if _, known := knownKeys[key]; !known {
			return nil, fmt.Errorf("line %d contains unknown key %q", lineNumber, key)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("line %d duplicates key %q", lineNumber, key)
		}
		if value == "" {
			return nil, fmt.Errorf("line %d has an empty value", lineNumber)
		}
		values[key] = value
	}
	return values, nil
}
