// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package discovery

import (
	"context"
	"time"
)

const defaultCleanupTimeout = 5 * time.Second

func cleanupContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return cleanupContextFrom(context.Background(), timeout)
}

func cleanupContextFrom(
	parent context.Context,
	timeout time.Duration,
) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = defaultCleanupTimeout
	}
	return context.WithTimeout(parent, timeout)
}

// Registration is a running discovery advertisement.
type Registration interface {
	Stop(context.Context) error
}

// MDNSAdvertisement is the complete input to an mDNS broadcaster.
type MDNSAdvertisement struct {
	Instance string
	Port     int
	TXT      []string
}

// MDNSBroadcaster publishes the fixed Sovereignite DNS-SD service.
type MDNSBroadcaster interface {
	Start(context.Context, MDNSAdvertisement) (Registration, error)
}

// BLEAdvertisement is the complete input to a BLE broadcaster. The service
// UUID is injected configuration shared with the AccessorySetupKit client.
type BLEAdvertisement struct {
	ServiceUUID string
}

// BLEBroadcaster publishes the fixed-shape Sovereignite BLE advertisement.
type BLEBroadcaster interface {
	Start(context.Context, BLEAdvertisement) (Registration, error)
}
