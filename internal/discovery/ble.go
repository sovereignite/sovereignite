// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

const (
	blueZBusName                   = "org.bluez"
	blueZAdvertisementInterface    = "org.bluez.LEAdvertisement1"
	blueZAdvertisingManager        = "org.bluez.LEAdvertisingManager1"
	blueZRegisterAdvertisement     = blueZAdvertisingManager + ".RegisterAdvertisement"
	blueZUnregisterAdvertisement   = blueZAdvertisingManager + ".UnregisterAdvertisement"
	blueZAdvertisementType         = "peripheral"
	blueZAdvertisementPath         = dbus.ObjectPath("/net/sovereignite/discovery/advertisement0")
	dbusPropertiesInterface        = "org.freedesktop.DBus.Properties"
	bluetoothServiceUUIDStringSize = 36
)

type blueZSession interface {
	ExportAdvertisement(dbus.ObjectPath, string) error
	RegisterAdvertisement(context.Context, dbus.ObjectPath, dbus.ObjectPath) error
	UnregisterAdvertisement(context.Context, dbus.ObjectPath, dbus.ObjectPath) error
	Close(context.Context) error
}

type blueZDialFunc func() (blueZSession, error)

type ownedUnixTransport interface {
	SetDeadline(time.Time) error
	Close() error
}

type unexportBlueZFunc func(dbus.ObjectPath, string) error

// BlueZBroadcaster publishes an AccessorySetupKit-discoverable BLE service UUID
// through the BlueZ D-Bus advertising API.
type BlueZBroadcaster struct {
	adapterPath    dbus.ObjectPath
	dial           blueZDialFunc
	cleanupTimeout time.Duration
}

// NewBlueZBroadcaster returns a production broadcaster for the selected BlueZ
// adapter object. The service UUID is always supplied separately and is never
// guessed.
func NewBlueZBroadcaster(adapterPath string) (*BlueZBroadcaster, error) {
	path := dbus.ObjectPath(adapterPath)
	if !path.IsValid() {
		return nil, fmt.Errorf("invalid BlueZ adapter object path %q", adapterPath)
	}
	return &BlueZBroadcaster{
		adapterPath:    path,
		dial:           dialSystemBlueZ,
		cleanupTimeout: defaultCleanupTimeout,
	}, nil
}

// NormalizeBluetoothServiceUUID validates a full Bluetooth service UUID and
// returns its canonical lowercase representation.
func NormalizeBluetoothServiceUUID(value string) (string, error) {
	if len(value) != bluetoothServiceUUIDStringSize ||
		value[8] != '-' ||
		value[13] != '-' ||
		value[18] != '-' ||
		value[23] != '-' {
		return "", errors.New("bluetooth service UUID must use 8-4-4-4-12 form")
	}
	compact := strings.ReplaceAll(value, "-", "")
	if _, err := hex.DecodeString(compact); err != nil {
		return "", fmt.Errorf("bluetooth service UUID is not hexadecimal: %w", err)
	}
	return strings.ToLower(value), nil
}

// Start exports and registers the minimal BlueZ advertisement needed for
// AccessorySetupKit matching: a peripheral type and one injected service UUID.
// It deliberately omits manufacturer data, service data, names, and all other
// fields that are not part of the v5 discovery contract.
func (b *BlueZBroadcaster) Start(
	ctx context.Context,
	advertisement BLEAdvertisement,
) (Registration, error) {
	if ctx == nil {
		return nil, errors.New("BLE start context is required")
	}
	if b == nil || b.dial == nil {
		return nil, errors.New("BlueZ D-Bus dialer is required")
	}
	if !b.adapterPath.IsValid() {
		return nil, errors.New("valid BlueZ adapter object path is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	serviceUUID, err := NormalizeBluetoothServiceUUID(advertisement.ServiceUUID)
	if err != nil {
		return nil, err
	}

	session, err := b.dial()
	if err != nil {
		return nil, fmt.Errorf("connect to BlueZ system bus: %w", err)
	}
	if session == nil {
		return nil, errors.New("connect to BlueZ system bus: dialer returned no session")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(
			err,
			wrapError("close canceled BlueZ session", b.closeSession(session)),
		)
	}
	if err := session.ExportAdvertisement(blueZAdvertisementPath, serviceUUID); err != nil {
		return nil, errors.Join(
			fmt.Errorf("export BlueZ advertisement: %w", err),
			wrapError("close BlueZ session after export failure", b.closeSession(session)),
		)
	}
	if err := session.RegisterAdvertisement(ctx, b.adapterPath, blueZAdvertisementPath); err != nil {
		return nil, errors.Join(
			fmt.Errorf("register BlueZ advertisement: %w", err),
			wrapError("close BlueZ session after register failure", b.closeSession(session)),
		)
	}

	registration := &blueZRegistration{
		session:        session,
		adapterPath:    b.adapterPath,
		objectPath:     blueZAdvertisementPath,
		cleanupTimeout: b.cleanupTimeout,
	}
	if err := ctx.Err(); err != nil {
		cleanupCtx, cancel := cleanupContext(b.cleanupTimeout)
		cleanupErr := registration.Stop(cleanupCtx)
		cancel()
		return nil, errors.Join(
			err,
			wrapError("stop canceled BlueZ advertisement", cleanupErr),
		)
	}
	return registration, nil
}

func (b *BlueZBroadcaster) closeSession(session blueZSession) error {
	ctx, cancel := cleanupContext(b.cleanupTimeout)
	defer cancel()
	return session.Close(ctx)
}

type blueZRegistration struct {
	mu             sync.Mutex
	session        blueZSession
	adapterPath    dbus.ObjectPath
	objectPath     dbus.ObjectPath
	cleanupTimeout time.Duration
	stopped        bool
	stopErr        error
}

func (r *blueZRegistration) Stop(ctx context.Context) error {
	if ctx == nil {
		return errors.New("BlueZ stop context is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return r.stopErr
	}
	r.stopped = true
	cleanupCtx, cancel := cleanupContextFrom(ctx, r.cleanupTimeout)
	defer cancel()
	r.stopErr = errors.Join(
		wrapError(
			"unregister BlueZ advertisement",
			r.session.UnregisterAdvertisement(cleanupCtx, r.adapterPath, r.objectPath),
		),
		wrapError("close BlueZ session", r.session.Close(cleanupCtx)),
	)
	return r.stopErr
}

type godbusBlueZSession struct {
	conn             *dbus.Conn
	transport        ownedUnixTransport
	cancelConnection context.CancelFunc
	unexport         unexportBlueZFunc
	exported         bool
	path             dbus.ObjectPath
	closeOnce        sync.Once
	closeErr         error
}

func (s *godbusBlueZSession) ExportAdvertisement(path dbus.ObjectPath, serviceUUID string) error {
	advertisement := &blueZAdvertisement{}
	if err := s.conn.Export(advertisement, path, blueZAdvertisementInterface); err != nil {
		return err
	}
	if _, err := prop.Export(s.conn, path, blueZAdvertisementProperties(serviceUUID)); err != nil {
		_ = s.conn.Export(nil, path, blueZAdvertisementInterface)
		return err
	}
	s.path = path
	s.exported = true
	return nil
}

func (s *godbusBlueZSession) RegisterAdvertisement(
	ctx context.Context,
	adapterPath dbus.ObjectPath,
	advertisementPath dbus.ObjectPath,
) error {
	return s.conn.Object(blueZBusName, adapterPath).CallWithContext(
		ctx,
		blueZRegisterAdvertisement,
		0,
		advertisementPath,
		map[string]dbus.Variant{},
	).Err
}

func (s *godbusBlueZSession) UnregisterAdvertisement(
	ctx context.Context,
	adapterPath dbus.ObjectPath,
	advertisementPath dbus.ObjectPath,
) error {
	return s.conn.Object(blueZBusName, adapterPath).CallWithContext(
		ctx,
		blueZUnregisterAdvertisement,
		0,
		advertisementPath,
	).Err
}

func (s *godbusBlueZSession) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("BlueZ session close context is required")
	}
	s.closeOnce.Do(func() {
		var errs []error
		if s.exported {
			if s.unexport == nil {
				errs = append(errs, errors.New("BlueZ local unexport function is required"))
			} else {
				errs = append(errs,
					wrapError(
						"unexport BlueZ advertisement",
						s.unexport(s.path, blueZAdvertisementInterface),
					),
					wrapError(
						"unexport BlueZ properties",
						s.unexport(s.path, dbusPropertiesInterface),
					),
				)
			}
			s.exported = false
		}

		if s.transport == nil {
			errs = append(errs, errors.New("owned BlueZ Unix transport is required"))
		} else {
			errs = append(
				errs,
				wrapTransportError(
					"expire owned BlueZ Unix transport",
					s.transport.SetDeadline(time.Now()),
				),
			)
		}
		if s.cancelConnection == nil {
			errs = append(errs, errors.New("BlueZ connection cancel function is required"))
		} else {
			s.cancelConnection()
		}
		if s.transport != nil {
			errs = append(
				errs,
				wrapTransportError(
					"close owned BlueZ Unix transport",
					s.transport.Close(),
				),
			)
		}
		errs = append(errs, wrapError("BlueZ session close deadline", ctx.Err()))
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func wrapTransportError(operation string, err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return wrapError(operation, err)
}

func blueZAdvertisementProperties(serviceUUID string) map[string]map[string]*prop.Prop {
	return map[string]map[string]*prop.Prop{
		blueZAdvertisementInterface: {
			"Type": {
				Value:    blueZAdvertisementType,
				Writable: false,
				Emit:     prop.EmitFalse,
			},
			"ServiceUUIDs": {
				Value:    []string{serviceUUID},
				Writable: false,
				Emit:     prop.EmitFalse,
			},
		},
	}
}

type blueZAdvertisement struct{}

func (*blueZAdvertisement) Release() *dbus.Error {
	return nil
}
