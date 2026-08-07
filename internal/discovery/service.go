// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrAlreadyRunning is returned when broadcast start is requested twice.
	ErrAlreadyRunning = errors.New("discovery broadcast is already running")
	// ErrNotRunning is returned when an operation requires active discovery.
	ErrNotRunning = errors.New("discovery broadcast is not running")
	// ErrAdoptionHandlerUnavailable indicates that the transport has not yet
	// injected the Trust-owned adoption handler.
	ErrAdoptionHandlerUnavailable = errors.New("adoption handler is unavailable")
)

// State is the discovery broadcast lifecycle state.
type State uint8

const (
	// StateStopped means neither discovery mechanism is registered.
	StateStopped State = iota
	// StateStarting means registrations are being created.
	StateStarting
	// StateRunning means both discovery mechanisms are registered.
	StateRunning
	// StateStopping means registrations are being removed.
	StateStopping
)

func (s State) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	default:
		return "unknown"
	}
}

// AdoptionHandler owns adoption behavior. Discovery passes transport-owned
// request and response values through unchanged and never mutates trust state.
type AdoptionHandler interface {
	HandleAdoption(context.Context, any) (any, error)
}

// ServiceConfig contains the already-selected discovery identity and endpoint.
// ServicePort identifies an existing secure service; discovery does not open a
// listener or define an adoption wire protocol.
type ServiceConfig struct {
	Record               Record
	ServicePort          int
	BluetoothServiceUUID string
}

// Service coordinates mDNS and BLE discovery registrations.
type Service struct {
	config          ServiceConfig
	mdns            MDNSBroadcaster
	ble             BLEBroadcaster
	adoptionHandler AdoptionHandler

	operationMu sync.Mutex
	stateMu     sync.RWMutex
	state       State
	mdnsHandle  Registration
	bleHandle   Registration

	cleanupTimeout time.Duration
}

// NewService validates all broadcast data before any network or D-Bus work. A
// Trust-owned adoption handler is required so a running service never
// advertises an adoption endpoint that cannot accept secure requests.
func NewService(
	config ServiceConfig,
	mdns MDNSBroadcaster,
	ble BLEBroadcaster,
	adoptionHandler AdoptionHandler,
) (*Service, error) {
	if err := config.Record.Validate(); err != nil {
		return nil, fmt.Errorf("discovery record: %w", err)
	}
	if config.ServicePort < 1 || config.ServicePort > 65535 {
		return nil, errors.New("service port must be between 1 and 65535")
	}
	serviceUUID, err := NormalizeBluetoothServiceUUID(config.BluetoothServiceUUID)
	if err != nil {
		return nil, fmt.Errorf("bluetooth service UUID: %w", err)
	}
	if mdns == nil {
		return nil, errors.New("mDNS broadcaster is required")
	}
	if ble == nil {
		return nil, errors.New("BLE broadcaster is required")
	}
	if adoptionHandler == nil {
		return nil, ErrAdoptionHandlerUnavailable
	}
	config.BluetoothServiceUUID = serviceUUID
	return &Service{
		config:          config,
		mdns:            mdns,
		ble:             ble,
		adoptionHandler: adoptionHandler,
		state:           StateStopped,
		cleanupTimeout:  defaultCleanupTimeout,
	}, nil
}

// State returns the current broadcast lifecycle state.
func (s *Service) State() State {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state
}

// Start registers mDNS first and BLE second. Any partial start is rolled back.
func (s *Service) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("discovery start context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	if s.State() != StateStopped {
		return ErrAlreadyRunning
	}
	s.setState(StateStarting)

	txt, err := s.config.Record.Encode()
	if err != nil {
		s.setState(StateStopped)
		return fmt.Errorf("encode discovery record: %w", err)
	}
	mdnsHandle, err := s.mdns.Start(ctx, MDNSAdvertisement{
		Instance: s.config.Record.DeviceID,
		Port:     s.config.ServicePort,
		TXT:      txt,
	})
	if err != nil {
		s.setState(StateStopped)
		return fmt.Errorf("start mDNS broadcast: %w", err)
	}
	if mdnsHandle == nil {
		s.setState(StateStopped)
		return errors.New("start mDNS broadcast: broadcaster returned no registration")
	}
	if err := ctx.Err(); err != nil {
		cleanupErr := s.stopForRollback(mdnsHandle)
		s.setState(StateStopped)
		return errors.Join(
			err,
			wrapError("stop canceled mDNS broadcast", cleanupErr),
		)
	}

	bleHandle, err := s.ble.Start(ctx, BLEAdvertisement{
		ServiceUUID: s.config.BluetoothServiceUUID,
	})
	if err != nil {
		cleanupErr := s.stopForRollback(mdnsHandle)
		s.setState(StateStopped)
		return errors.Join(
			fmt.Errorf("start BLE broadcast: %w", err),
			wrapError("stop partial mDNS broadcast", cleanupErr),
		)
	}
	if bleHandle == nil {
		cleanupErr := s.stopForRollback(mdnsHandle)
		s.setState(StateStopped)
		return errors.Join(
			errors.New("start BLE broadcast: broadcaster returned no registration"),
			wrapError("stop partial mDNS broadcast", cleanupErr),
		)
	}
	if err := ctx.Err(); err != nil {
		bleCleanupErr, mdnsCleanupErr := s.stopBothForRollback(bleHandle, mdnsHandle)
		s.setState(StateStopped)
		return errors.Join(
			err,
			wrapError("stop canceled BLE broadcast", bleCleanupErr),
			wrapError("stop canceled mDNS broadcast", mdnsCleanupErr),
		)
	}

	s.stateMu.Lock()
	s.mdnsHandle = mdnsHandle
	s.bleHandle = bleHandle
	s.state = StateRunning
	s.stateMu.Unlock()
	return nil
}

// Stop removes both registrations. It is safe to call repeatedly.
func (s *Service) Stop(ctx context.Context) error {
	if ctx == nil {
		return errors.New("discovery stop context is required")
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()

	if s.State() == StateStopped {
		return nil
	}
	s.setState(StateStopping)

	s.stateMu.RLock()
	bleHandle := s.bleHandle
	mdnsHandle := s.mdnsHandle
	s.stateMu.RUnlock()

	var errs []error
	if bleHandle != nil {
		errs = append(errs, wrapError("stop BLE broadcast", bleHandle.Stop(ctx)))
	}
	if mdnsHandle != nil {
		errs = append(errs, wrapError("stop mDNS broadcast", mdnsHandle.Stop(ctx)))
	}

	s.stateMu.Lock()
	s.bleHandle = nil
	s.mdnsHandle = nil
	s.state = StateStopped
	s.stateMu.Unlock()
	return errors.Join(errs...)
}

// ForwardAdoption delegates an opaque transport request to the injected
// Trust-owned handler. Discovery performs no trust mutation and defines no wire
// representation.
func (s *Service) ForwardAdoption(ctx context.Context, request any) (any, error) {
	if ctx == nil {
		return nil, errors.New("adoption context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.stateMu.RLock()
	state := s.state
	handler := s.adoptionHandler
	s.stateMu.RUnlock()
	if state != StateRunning {
		return nil, ErrNotRunning
	}
	if handler == nil {
		return nil, ErrAdoptionHandlerUnavailable
	}
	return handler.HandleAdoption(ctx, request)
}

func (s *Service) setState(state State) {
	s.stateMu.Lock()
	s.state = state
	s.stateMu.Unlock()
}

func (s *Service) stopForRollback(registration Registration) error {
	ctx, cancel := cleanupContext(s.cleanupTimeout)
	defer cancel()
	return registration.Stop(ctx)
}

func (s *Service) stopBothForRollback(
	first Registration,
	second Registration,
) (error, error) {
	ctx, cancel := cleanupContext(s.cleanupTimeout)
	defer cancel()

	firstErr := first.Stop(ctx)
	secondErr := second.Stop(ctx)
	return firstErr, secondErr
}

func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
