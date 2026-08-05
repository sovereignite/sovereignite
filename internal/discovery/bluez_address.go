// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"errors"
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	systemBusAddressEnvironment = "DBUS_SYSTEM_BUS_ADDRESS"
	defaultSystemBusAddress     = "unix:path=/var/run/dbus/system_bus_socket"
	linuxUnixAddressMaxBytes    = 107
)

func linuxSystemBusUnixAddress(
	lookupEnv func(string) (string, bool),
) (*net.UnixAddr, error) {
	if lookupEnv == nil {
		return nil, errors.New("system bus environment lookup is required")
	}
	address := defaultSystemBusAddress
	if configured, ok := lookupEnv(systemBusAddressEnvironment); ok {
		address = configured
	}
	return parseLinuxSystemBusUnixAddress(address)
}

func parseLinuxSystemBusUnixAddress(address string) (*net.UnixAddr, error) {
	if address == "" {
		return nil, errors.New("system bus address is empty")
	}
	if strings.Contains(address, ";") {
		return nil, errors.New("multiple system bus addresses are not supported")
	}
	transport, options, ok := strings.Cut(address, ":")
	if !ok || transport == "" {
		return nil, errors.New("system bus address has no transport")
	}
	if transport != "unix" {
		return nil, fmt.Errorf("unsupported system bus transport %q", transport)
	}

	values := make(map[string]string, 2)
	for _, option := range strings.Split(options, ",") {
		key, escapedValue, ok := strings.Cut(option, "=")
		if !ok || key == "" || escapedValue == "" {
			return nil, errors.New("system bus Unix address contains an invalid option")
		}
		if key != "path" && key != "abstract" {
			return nil, fmt.Errorf("unsupported system bus Unix address option %q", key)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("duplicate system bus Unix address option %q", key)
		}
		value, err := dbus.UnescapeBusAddressValue(escapedValue)
		if err != nil {
			return nil, fmt.Errorf("decode system bus Unix address option %q: %w", key, err)
		}
		if value == "" || strings.ContainsRune(value, '\x00') {
			return nil, fmt.Errorf("system bus Unix address option %q is invalid", key)
		}
		values[key] = value
	}

	socketPath, hasPath := values["path"]
	abstractName, hasAbstract := values["abstract"]
	if hasPath == hasAbstract {
		return nil, errors.New(
			"system bus Unix address must contain exactly one of path or abstract",
		)
	}
	if hasPath {
		if !path.IsAbs(socketPath) || path.Clean(socketPath) != socketPath {
			return nil, errors.New("system bus Unix socket path must be clean and absolute")
		}
		if len(socketPath) > linuxUnixAddressMaxBytes {
			return nil, errors.New("system bus Unix socket path is too long")
		}
		return &net.UnixAddr{Name: socketPath, Net: "unix"}, nil
	}
	if len(abstractName) > linuxUnixAddressMaxBytes {
		return nil, errors.New("system bus abstract Unix socket name is too long")
	}
	return &net.UnixAddr{Name: "@" + abstractName, Net: "unix"}, nil
}
