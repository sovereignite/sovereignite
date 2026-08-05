// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package libp2p

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const hostnameBusName = "org.freedesktop.hostname1"
const hostnameObjectPath = dbus.ObjectPath("/org/freedesktop/hostname1")
const setStaticHostnameMethod = "org.freedesktop.hostname1.SetStaticHostname"
const setTransientHostnameMethod = "org.freedesktop.hostname1.SetHostname"
const defaultHostnameSetTimeout = 5 * time.Second

// HostnameSetter sets the persistent and current system hostname. Implementors
// must use a direct system API; spawning hostnamectl or any other process is
// prohibited.
type HostnameSetter interface {
	SetHostname(context.Context, string) error
}

type hostnameBus interface {
	Call(context.Context, string, ...any) error
	Close() error
}

type hostnameBusConnector func(context.Context) (hostnameBus, error)

// DBusHostnameSetter updates systemd-hostnamed through its fixed hostname1
// D-Bus API. The zero value uses the system bus and a bounded operation.
type DBusHostnameSetter struct {
	connect hostnameBusConnector
	timeout time.Duration
}

// SetHostname persists the canonical label and applies it to the running
// system. D-Bus connection setup and both calls share the same bounded context.
func (setter DBusHostnameSetter) SetHostname(
	ctx context.Context,
	name string,
) (returnErr error) {
	if isNil(ctx) {
		return errors.New("context is required")
	}
	if err := ValidateHostnameLabel(name); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := setter.timeout
	if timeout <= 0 {
		timeout = defaultHostnameSetTimeout
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connect := setter.connect
	if connect == nil {
		connect = connectSystemHostnameBus
	}
	connection, err := connect(bounded)
	if err != nil {
		return fmt.Errorf("connect system D-Bus for hostname1: %w", err)
	}
	if isNil(connection) {
		return errors.New("connect system D-Bus for hostname1: no connection")
	}
	defer func() {
		returnErr = errors.Join(
			returnErr,
			wrapCloseError("close hostname1 system D-Bus connection", connection.Close()),
		)
	}()

	if err := connection.Call(
		bounded,
		setStaticHostnameMethod,
		name,
		false,
	); err != nil {
		return fmt.Errorf("persist static hostname through hostname1: %w", err)
	}
	if err := connection.Call(
		bounded,
		setTransientHostnameMethod,
		name,
		false,
	); err != nil {
		return fmt.Errorf("apply transient hostname through hostname1: %w", err)
	}
	return nil
}

func connectSystemHostnameBus(ctx context.Context) (hostnameBus, error) {
	connection, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	return &systemHostnameBus{connection: connection}, nil
}

type systemHostnameBus struct {
	connection *dbus.Conn
}

func (bus *systemHostnameBus) Call(
	ctx context.Context,
	method string,
	args ...any,
) error {
	return bus.connection.Object(
		hostnameBusName,
		hostnameObjectPath,
	).CallWithContext(ctx, method, 0, args...).Err
}

func (bus *systemHostnameBus) Close() error {
	return bus.connection.Close()
}

func wrapCloseError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// ValidateHostnameLabel strictly validates a lowercase ASCII DNS label.
func ValidateHostnameLabel(name string) error {
	if len(name) == 0 {
		return errors.New("hostname is required")
	}
	if len(name) > 63 {
		return errors.New("hostname exceeds the 63-byte DNS label limit")
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		if character == '-' && index > 0 && index < len(name)-1 {
			continue
		}
		return fmt.Errorf("hostname contains an invalid byte at offset %d", index)
	}
	return nil
}

// SetValidatedHostname validates the complete label before invoking the direct
// system API. It never normalizes, truncates, or substitutes a name.
func SetValidatedHostname(
	ctx context.Context,
	setter HostnameSetter,
	name string,
) error {
	if isNil(ctx) {
		return errors.New("context is required")
	}
	if err := ValidateHostnameLabel(name); err != nil {
		return err
	}
	if isNil(setter) {
		return errors.New("hostname setter is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := setter.SetHostname(ctx, name); err != nil {
		return fmt.Errorf("set hostname: %w", err)
	}
	return nil
}
