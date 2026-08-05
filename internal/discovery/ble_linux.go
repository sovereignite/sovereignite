// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

//go:build linux

package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

func dialSystemBlueZ() (blueZSession, error) {
	address, err := linuxSystemBusUnixAddress(os.LookupEnv)
	if err != nil {
		return nil, fmt.Errorf("resolve private BlueZ system bus transport: %w", err)
	}
	socket, err := net.DialUnix("unix", nil, address)
	if err != nil {
		return nil, fmt.Errorf("dial private BlueZ system bus Unix transport: %w", err)
	}
	if err := socket.SetDeadline(time.Now().Add(defaultCleanupTimeout)); err != nil {
		_ = socket.Close()
		return nil, fmt.Errorf("bound private BlueZ system bus handshake: %w", err)
	}

	connectionContext, cancelConnection := context.WithCancel(context.Background())
	conn, err := dbus.DialUnix(socket, dbus.WithContext(connectionContext))
	if err != nil {
		cancelConnection()
		_ = socket.Close()
		return nil, fmt.Errorf("create private BlueZ D-Bus connection: %w", err)
	}
	session := &godbusBlueZSession{
		conn:             conn,
		transport:        socket,
		cancelConnection: cancelConnection,
		unexport: func(path dbus.ObjectPath, iface string) error {
			return conn.Export(nil, path, iface)
		},
	}
	if err := conn.Auth(nil); err != nil {
		return nil, closeFailedBlueZHandshake(
			session,
			fmt.Errorf("authenticate private BlueZ D-Bus connection: %w", err),
		)
	}
	if err := conn.Hello(); err != nil {
		return nil, closeFailedBlueZHandshake(
			session,
			fmt.Errorf("initialize private BlueZ D-Bus connection: %w", err),
		)
	}
	if err := socket.SetDeadline(time.Time{}); err != nil {
		return nil, closeFailedBlueZHandshake(
			session,
			fmt.Errorf("clear private BlueZ D-Bus handshake deadline: %w", err),
		)
	}
	return session, nil
}

func closeFailedBlueZHandshake(session blueZSession, handshakeErr error) error {
	ctx, cancel := cleanupContext(defaultCleanupTimeout)
	defer cancel()
	return errors.Join(
		handshakeErr,
		wrapError("close failed private BlueZ D-Bus connection", session.Close(ctx)),
	)
}
